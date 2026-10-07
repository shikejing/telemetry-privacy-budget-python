"""Privacy aggregation engine.

Guarantees:
* Events are grouped into per-user contribution vectors and then *deleted*
  once the aggregation commits; raw detail is never retained.
* Aggregate noise is fixed per output cell (see :mod:`noise`), so removing a
  user reproduces exactly the result that would have existed had that user
  never contributed.
* Budget charging, contribution storage and event deletion happen in one
  lock-protected atomic transition. Concurrent aggregations/revocations
  therefore always converge with neither double counting nor leftovers.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict
from typing import Callable

from . import noise
from .budget import BudgetManager
from .errors import AggregationNotFoundError, BudgetExceededError
from .models import AggregationConfig, AggregationResult, ConsentState, Event
from .storage import Storage

_EPSILON_COST_SCALE = 1.0


def _bin_key(dimensions: tuple[str, ...], event: dict | Event) -> str:
    values = event["dimensions"] if isinstance(event, dict) else event.dimensions
    return "|".join(values.get(d, "") for d in dimensions) or "_"


def config_fingerprint(tenant_id: str, config: AggregationConfig) -> str:
    payload = json.dumps(
        {
            "tenant": tenant_id,
            "dimensions": list(config.dimensions),
            "window": [config.window_start, config.window_end],
            "event_type": config.event_type,
            "epsilon": config.epsilon,
            "seed": config.noise_seed,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _serialize_result(result: AggregationResult) -> dict:
    data = asdict(result)
    cfg = data["config"]
    cfg["dimensions"] = list(cfg["dimensions"])
    data["config"] = cfg
    data["excluded_users"] = sorted(result.excluded_users)
    return data


def _deserialize_result(data: dict) -> AggregationResult:
    cfg = data["config"]
    config = AggregationConfig(
        dimensions=tuple(cfg["dimensions"]),
        window_start=cfg["window_start"],
        window_end=cfg["window_end"],
        event_type=cfg["event_type"],
        epsilon=cfg["epsilon"],
        noise_seed=cfg["noise_seed"],
        query_cost=cfg.get("query_cost", 0.0),
    )
    return AggregationResult(
        aggregation_id=data["aggregation_id"],
        tenant_id=data["tenant_id"],
        config=config,
        bins=data["bins"],
        cost=data["cost"],
        created_at=data["created_at"],
        excluded_users=frozenset(data.get("excluded_users", ())),
    )


class Aggregator:
    def __init__(
        self,
        storage: Storage,
        budgets: BudgetManager,
        time_func: Callable[[], float] = time.time,
    ) -> None:
        self.storage = storage
        self.budgets = budgets
        self.time = time_func
        # Serializes aggregation vs. revocation for one tenant; storage lock
        # guards state correctness while this prevents interleaved logical ops.
        self._tenant_locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()

    def _tenant_lock(self, tenant_id: str) -> threading.RLock:
        with self._locks_guard:
            lock = self._tenant_locks.get(tenant_id)
            if lock is None:
                lock = threading.RLock()
                self._tenant_locks[tenant_id] = lock
            return lock

    # ------------------------------------------------------------------ #
    # aggregation
    # ------------------------------------------------------------------ #
    def run_aggregation(
        self,
        tenant_id: str,
        config: AggregationConfig,
        idem_key: str | None = None,
    ) -> AggregationResult:
        cost = _EPSILON_COST_SCALE / config.epsilon
        with self._tenant_lock(tenant_id):
            # Same input under the same configuration must be reproducible:
            # the configuration fingerprint identifies the logical aggregate.
            # If it already exists, replay it without charging again. An
            # explicit idempotency key is accepted as an alias for the same
            # aggregate (and rejected if it resolves to a different one).
            fingerprint = config_fingerprint(tenant_id, config)
            aggregation_id = f"agg_{fingerprint}"
            existing = self.storage.get_aggregate(tenant_id, aggregation_id)
            if existing is not None:
                if idem_key is not None:
                    self.storage.save_idem_key(tenant_id, idem_key, aggregation_id)
                    self.storage.commit()
                return _deserialize_result(existing)
            if idem_key is not None:
                aliased = self.storage.find_aggregate(tenant_id, idem_key)
                if aliased is not None:
                    return _deserialize_result(aliased)

            self.budgets.charge(tenant_id, cost, reason="aggregate")
            try:
                result = self._build_and_commit(
                    tenant_id,
                    config,
                    cost,
                    idem_key=idem_key,
                    aggregation_id=aggregation_id,
                )
            except BaseException:
                # The charge was committed before the build; if the build
                # cannot commit, roll it back so we never leave "charged but
                # no output".
                self.budgets.refund(tenant_id, cost)
                raise
            return result

    def _collect_events(self, tenant_id: str, config: AggregationConfig) -> list[dict]:
        events = self.storage.events_for_window(
            tenant_id, config.event_type, config.window_start, config.window_end
        )
        granted: list[dict] = []
        for event in events:
            consent = self.storage.get_consent(tenant_id, event["user_id"])
            if consent and consent["state"] == ConsentState.GRANTED.value:
                granted.append(event)
        return granted

    def _build_and_commit(
        self,
        tenant_id: str,
        config: AggregationConfig,
        cost: float,
        idem_key: str | None,
        excluded: frozenset[str] = frozenset(),
        aggregation_id: str | None = None,
    ) -> AggregationResult:
        with self.storage.lock:
            events = self._collect_events(tenant_id, config)
            contributions: dict[str, dict[str, float]] = {}
            true_bins: dict[str, float] = {}
            event_ids: set[str] = set()
            for event in events:
                key = _bin_key(config.dimensions, event)
                per_user = contributions.setdefault(event["user_id"], {})
                per_user[key] = per_user.get(key, 0.0) + float(event.get("value", 1.0))
                true_bins[key] = true_bins.get(key, 0.0) + float(
                    event.get("value", 1.0)
                )
                if event.get("event_id"):
                    event_ids.add(event["event_id"])

            if aggregation_id is None:
                fingerprint = config_fingerprint(tenant_id, config)
                aggregation_id = f"agg_{fingerprint}"

            bins = {
                key: noise.clip_nonneg(
                    noise.noisy_value(
                        total, config.noise_seed, aggregation_id, key, config.epsilon
                    )
                )
                for key, total in true_bins.items()
            }
            result = AggregationResult(
                aggregation_id=aggregation_id,
                tenant_id=tenant_id,
                config=config,
                bins=bins,
                cost=cost,
                created_at=self.time(),
                excluded_users=frozenset(excluded),
            )

            serialized = _serialize_result(result)
            self.storage.put_aggregate(serialized)
            self.storage.put_contributions(
                tenant_id, aggregation_id, {u: {"bins": c} for u, c in contributions.items()}
            )
            # Raw detail is removed together with the committed aggregate.
            self.storage.delete_events(tenant_id, event_ids)
            if idem_key is not None:
                self.storage.save_idem_key(tenant_id, idem_key, aggregation_id)
            self.storage.commit()
            return result

    # ------------------------------------------------------------------ #
    # queries over an existing aggregate (also budget charged)
    # ------------------------------------------------------------------ #
    def query(
        self,
        tenant_id: str,
        aggregation_id: str,
        bin_key: str | None = None,
        idem_key: str | None = None,
    ) -> dict[str, float]:
        record = self.storage.get_aggregate(tenant_id, aggregation_id)
        if record is None:
            raise AggregationNotFoundError(aggregation_id)
        cost = float(record["config"].get("query_cost", 0.0))
        if cost > 0 and idem_key is not None:
            already = self.storage.get_idem_op(tenant_id, idem_key)
            if already is not None:
                # Replay a previously charged query: never charge twice.
                bins = record["bins"]
                return (
                    {bin_key: bins.get(bin_key, 0.0)}
                    if bin_key is not None
                    else dict(bins)
                )
        if cost > 0:
            # Charge and ledger under one lock/transaction: a restart after
            # commit replays instead of re-charging.
            with self.storage.lock:
                self.budgets.charge(tenant_id, cost, reason="query")
                if idem_key is not None:
                    self.storage.save_idem_op(
                        tenant_id, idem_key, "query", aggregation_id
                    )
                self.storage.commit()
        bins = record["bins"]
        if bin_key is not None:
            return {bin_key: bins.get(bin_key, 0.0)}
        return dict(bins)

    # ------------------------------------------------------------------ #
    # revocation
    # ------------------------------------------------------------------ #
    def apply_revocations(self, tenant_id: str, aggregation_id: str) -> AggregationResult:
        """Rebuild an aggregate excluding ledgered revoked users.

        Noise for retained cells is identical to a run where revoked users
        never existed. Cells that only held revoked contributions disappear.
        Budget is *not* charged again: users exercising their right to opt out
        must not consume further budget.
        """
        with self._tenant_lock(tenant_id):
            record = self.storage.get_aggregate(tenant_id, aggregation_id)
            if record is None:
                raise AggregationNotFoundError(aggregation_id)
            with self.storage.lock:
                revoked = set(
                    self.storage.revocations_for(tenant_id, aggregation_id).keys()
                )
                already_excluded = set(record.get("excluded_users", ()))
                new_excluded = revoked - already_excluded
                if not new_excluded:
                    return _deserialize_result(record)

                contributions = self.storage.all_contributions(
                    tenant_id, aggregation_id
                )
                true_bins: dict[str, float] = {}
                for user_id, payload in contributions.items():
                    if user_id in revoked:
                        continue
                    for key, value in payload["bins"].items():
                        true_bins[key] = true_bins.get(key, 0.0) + value

                config = _deserialize_result(record).config
                bins = {
                    key: noise.clip_nonneg(
                        noise.noisy_value(
                            total,
                            config.noise_seed,
                            aggregation_id,
                            key,
                            config.epsilon,
                        )
                    )
                    for key, total in true_bins.items()
                }
                result = AggregationResult(
                    aggregation_id=aggregation_id,
                    tenant_id=tenant_id,
                    config=config,
                    bins=bins,
                    cost=record["cost"],
                    created_at=record["created_at"],
                    excluded_users=frozenset(revoked),
                )
                for user_id in new_excluded:
                    self.storage.delete_contribution(
                        tenant_id, aggregation_id, user_id
                    )
                self.storage.put_aggregate(_serialize_result(result))
                self.storage.commit()
                return result

    def get(self, tenant_id: str, aggregation_id: str) -> AggregationResult:
        record = self.storage.get_aggregate(tenant_id, aggregation_id)
        if record is None:
            raise AggregationNotFoundError(aggregation_id)
        return _deserialize_result(record)

    def list(self, tenant_id: str) -> list[AggregationResult]:
        return [
            _deserialize_result(r)
            for r in self.storage.list_aggregates(tenant_id)
        ]

    def individual_contribution(
        self, tenant_id: str, aggregation_id: str, user_id: str
    ) -> dict[str, float] | None:
        """Access-controlled per-user vector (requires detail:read)."""
        payload = self.storage.get_contribution(
            tenant_id, aggregation_id, user_id
        )
        return None if payload is None else dict(payload["bins"])
