"""Privacy aggregation engine.

Concurrency model
-----------------
Every externally visible operation runs inside one serialized SQLite
transaction guarded by :attr:`Storage.lock`. Budget deduction, folding of raw
events, revocation subtraction and aggregate recomputation therefore each
appear atomic: concurrent aggregation and revocation cannot interleave, so a
user's contribution is never counted twice and never left behind partially.

Restart semantics
-----------------
The queue of not-yet-aggregated ``raw_events`` plus the committed
``agg_checkpoint`` meta key are the recovery state. Aggregation deletes the
raw rows in the *same* transaction that updates partials/aggregates and
checkpoint, and budget charging happens in that transaction too. After a crash
either the whole run is visible (nothing to redo, no double charge / double
delete) or nothing is (the still-pending rows are reprocessed once).
"""
from __future__ import annotations

import json
import time
from typing import Any

from . import noise as noise_mod
from .audit import (
    AGG_READ_ROLES,
    RAW_READ_ROLES,
    AuditLog,
    parse_role,
)
from .budget import BudgetLedger
from .models import (
    AccessRole,
    AggregateResult,
    AggregationKind,
    AuthorizationError,
    BudgetExceededError,
    BudgetStatus,
    Event,
    TenantConfig,
)
from .storage import Storage, canonical_dims_key


class PrivacyEngine:
    def __init__(self, storage: Any, configs: Any, audit: Any) -> None:
        self._store: Storage = storage
        self._configs = configs
        self._audit: AuditLog = audit
        self._budgets = BudgetLedger(storage)

    # ------------------------------------------------------------------ utils
    def _cfg(self, tenant_id: str) -> TenantConfig:
        return self._configs.get(tenant_id)

    @staticmethod
    def _bucket_for(cfg: TenantConfig, ts_ms: int,
                    attrs: dict[str, str]) -> tuple[int, dict[str, str]]:
        window_ms = cfg.window_seconds * 1000
        start = (ts_ms // window_ms) * window_ms
        dims = {d: attrs.get(d, "") for d in cfg.dimensions}
        return start, dims

    # --------------------------------------------------------------- ingestion
    def ingest(self, events: list[Event]) -> int:
        """Accept events, de-duplicating by event id. Returns accepted count.

        Events are held as raw detail only until the next aggregation run,
        which folds them into per-user partial state and deletes the rows.
        """
        if not events:
            return 0
        tenants = {e.tenant_id for e in events}
        for t in tenants:
            self._cfg(t)  # reject unknown tenants up front
        with self._store.transaction() as cur:
            return Storage.insert_events(cur, events)

    # ------------------------------------------------------------- aggregation
    def aggregate_pending(self, tenant_id: str | None = None) -> int:
        """Fold all pending raw events into aggregates, one txn per tenant.

        Budget is charged *inside* the folding transaction. If a tenant's
        budget is exhausted the run is rejected with
        :class:`BudgetExceededError` and no state changes (no silent pass).
        Returns the number of raw events folded.
        """
        ids: list[str]
        if tenant_id is None:
            ids = self._configs.all_tenant_ids()
        else:
            self._cfg(tenant_id)
            ids = [tenant_id]

        total = 0
        for tid in ids:
            total += self._aggregate_one_tenant(tid)
        return total

    def _aggregate_one_tenant(self, tenant_id: str) -> int:
        cfg = self._cfg(tenant_id)
        with self._store.transaction() as cur:
            rows = Storage.fetch_pending(cur, tenant_id)
            if not rows:
                return 0
            # Reject (and leave untouched) if this release would exceed budget.
            consumed = Storage.budget_consumed(cur, tenant_id)
            if consumed + cfg.aggregation_cost > cfg.epsilon_budget + 1e-12:
                raise BudgetExceededError(
                    f"tenant {tenant_id}: privacy budget exhausted "
                    f"({consumed:.6f}/{cfg.epsilon_budget:.6f}); "
                    f"aggregation of {len(rows)} event(s) rejected"
                )
            cur.execute(
                "INSERT INTO budget_entries(tenant_id, amount, request_id, "
                "ts_ms) VALUES(?, ?, NULL, ?)",
                (tenant_id, cfg.aggregation_cost,
                 time.time_ns() // 1_000_000),
            )

            folded_ids: list[str] = []
            dropped_ids: list[str] = []
            touched: dict[tuple[int, str], str] = {}
            max_seq = 0
            for r in rows:
                max_seq = max(max_seq, r["seq"])
                uid = r["user_id"]
                if Storage.is_revoked(cur, tenant_id, uid):
                    dropped_ids.append(r["event_id"])
                    continue
                attrs = json.loads(r["attrs_json"])
                start, dims = self._bucket_for(cfg, r["ts_ms"], attrs)
                key = canonical_dims_key(dims)
                touched[(start, key)] = json.dumps(
                    sorted(dims.items()), ensure_ascii=False)
                contrib = float(r["value"]) if cfg.aggregation is \
                    AggregationKind.SUM else 1.0
                Storage.upsert_partial(cur, tenant_id, uid, start, key,
                                       json.dumps(sorted(dims.items()),
                                                  ensure_ascii=False),
                                       contrib)
                folded_ids.append(r["event_id"])
            for eid in dropped_ids:
                cur.execute(
                    "DELETE FROM raw_events WHERE tenant_id=? AND event_id=?",
                    (tenant_id, eid))
                cur.execute(
                    "DELETE FROM processed_ids WHERE tenant_id=? AND event_id=?",
                    (tenant_id, eid))
            Storage.delete_raw(cur, tenant_id, folded_ids)
            for (start, key), dims_json in touched.items():
                self._recompute(cur, cfg, start, key, dims_json, max_seq)
            Storage.meta_set(cur, f"agg_checkpoint:{tenant_id}",
                             json.dumps({"seq": max_seq,
                                         "ts_ms": time.time_ns() // 1_000_000}))
            return len(folded_ids) + len(dropped_ids)

    @staticmethod
    def _recompute(cur: Any, cfg: TenantConfig, start: int, key: str,
                   dims_json: str, update_seq: int) -> None:
        row = cur.execute(
            "SELECT COALESCE(SUM(contrib), 0.0) AS v, COUNT(*) AS n "
            "FROM partials WHERE tenant_id=? AND window_start_ms=? "
            "AND dims_key=?",
            (cfg.tenant_id, start, key),
        ).fetchone()
        total = float(row["v"])
        users = int(row["n"])
        if users == 0:
            cur.execute(
                "DELETE FROM aggregates WHERE tenant_id=? AND window_start_ms=? "
                "AND dims_key=?", (cfg.tenant_id, start, key))
            return
        cur.execute(
            "INSERT INTO aggregates(tenant_id, window_start_ms, dims_key, "
            "dims_json, value, users, updated_seq) VALUES(?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, window_start_ms, dims_key) DO UPDATE SET "
            "value=excluded.value, users=excluded.users, "
            "updated_seq=CASE WHEN excluded.updated_seq > aggregates.updated_seq "
            "THEN excluded.updated_seq ELSE aggregates.updated_seq END, "
            "dims_json=excluded.dims_json",
            (cfg.tenant_id, start, key, dims_json, total, users, update_seq),
        )

    # --------------------------------------------------------------- revocation
    def revoke(self, tenant_id: str, user_id: str, *, actor: str = "system",
               role: str = "admin") -> int:
        """Withdraw authorization: atomically purge the user and re-derive
        every affected bucket. Idempotent; returns number of buckets changed.
        """
        cfg = self._cfg(tenant_id)
        actor_role = parse_role(role)
        if actor_role is not AccessRole.ADMIN:
            self._audit.record(tenant_id, actor, actor_role, "revoke",
                               False, subject=user_id)
            raise AuthorizationError(
                f"role {actor_role.value} may not revoke authorization")
        with self._store.transaction() as cur:
            first_time = Storage.mark_revoked(cur, tenant_id, user_id)
            buckets = Storage.delete_user_data(cur, tenant_id, user_id)
            changed = 0
            for start, key, dims_json in buckets:
                before = cur.execute(
                    "SELECT value, users FROM aggregates WHERE tenant_id=? "
                    "AND window_start_ms=? AND dims_key=?",
                    (tenant_id, start, key),
                ).fetchone()
                self._recompute(cur, cfg, start, key, dims_json, 0)
                after = cur.execute(
                    "SELECT value, users FROM aggregates WHERE tenant_id=? "
                    "AND window_start_ms=? AND dims_key=?",
                    (tenant_id, start, key),
                ).fetchone()
                b = None if before is None else (before["value"], before["users"])
                a = None if after is None else (after["value"], after["users"])
                if a != b:
                    changed += 1
        # Audit outside the revoked user's identity: store only a hash.
        self._audit.record(tenant_id, actor, actor_role, "revoke", True,
                           subject=user_id if first_time else None)
        return changed

    # ------------------------------------------------------------------ queries
    def query_aggregates(self, tenant_id: str, actor: str, role: str,
                         window_start_ms: int | None = None,
                         request_id: str | None = None
                         ) -> list[AggregateResult]:
        """Return noisy aggregates, charged against budget, role-checked.

        Denials (budget or permission) return no data and are audited.
        """
        actor_role = parse_role(role)
        cfg = self._cfg(tenant_id)
        allowed = actor_role in AGG_READ_ROLES
        if not allowed:
            self._audit.record(tenant_id, actor, actor_role,
                               "aggregate_read", False)
            raise AuthorizationError(
                f"role {actor_role.value} may not read aggregates")
        charged = self._budgets.try_charge(tenant_id, cfg.query_cost,
                                           cfg.epsilon_budget, request_id)
        if not charged:
            self._audit.record(tenant_id, actor, actor_role,
                               "aggregate_read", False)
            raise BudgetExceededError(
                f"tenant {tenant_id}: query rejected, privacy budget "
                f"exhausted ({cfg.epsilon_budget:.6f})")
        with self._store.transaction() as cur:
            rows = Storage.list_aggregates(cur, tenant_id, window_start_ms)
            consumed = Storage.budget_consumed(cur, tenant_id)
            out: list[AggregateResult] = []
            for r in rows:
                dims = dict(json.loads(r["dims_json"]))
                dims_tuple = tuple(sorted(dims.items()))
                digest = self._content_digest(r["value"], r["users"])
                z = noise_mod.bucket_noise(
                    cfg.master_seed, tenant_id, r["window_start_ms"],
                    dims_tuple + (("__content__", digest),),
                    sensitivity=1.0, epsilon=cfg.noise_epsilon,
                )
                out.append(AggregateResult(
                    tenant_id=tenant_id,
                    window_start_ms=r["window_start_ms"],
                    dimensions=dims,
                    contributing_users=int(r["users"]),
                    value=float(r["value"]),
                    noise=z,
                    noisy_value=float(r["value"]) + z,
                    budget_consumed=consumed,
                ))
        self._audit.record(tenant_id, actor, actor_role, "aggregate_read",
                           True)
        return out

    @staticmethod
    def _content_digest(value: float, users: int) -> str:
        import hashlib
        h = hashlib.sha256()
        h.update(f"{users}:{value!r}".encode())
        return h.hexdigest()[:16]

    def read_raw_events(self, tenant_id: str, actor: str, role: str
                        ) -> list[Event]:
        """Read retained (not-yet-aggregated) raw detail. Support/admin only.

        Denied attempts return nothing and are audited; the denied caller
        never receives a single event.
        """
        actor_role = parse_role(role)
        if actor_role not in RAW_READ_ROLES:
            self._audit.record(tenant_id, actor, actor_role, "raw_read",
                               False)
            raise AuthorizationError(
                f"role {actor_role.value} may not read raw detail")
        with self._store.transaction() as cur:
            rows = Storage.fetch_pending(cur, tenant_id)
            events = [Event(
                event_id=r["event_id"], tenant_id=r["tenant_id"],
                user_id=r["user_id"], ts_ms=r["ts_ms"], value=r["value"],
                attrs=json.loads(r["attrs_json"]),
            ) for r in rows]
        self._audit.record(tenant_id, actor, actor_role, "raw_read", True)
        return events

    # ------------------------------------------------------------------- status
    def budget_status(self, tenant_id: str) -> BudgetStatus:
        cfg = self._cfg(tenant_id)
        return self._budgets.status(tenant_id, cfg.epsilon_budget)

    def pending_count(self, tenant_id: str | None = None) -> int:
        with self._store.transaction() as cur:
            return Storage.pending_event_count(cur, tenant_id)

    def close(self) -> None:
        self._store.close()
