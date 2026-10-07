"""Durable, transactional storage for pipeline state.

All pipeline state lives in a single JSON snapshot. Every state transition is
persisted by an atomic *temp-file + fsync + rename* commit, so a process
restart always observes a fully committed snapshot and resumes from the last
committed position: budget charges and revocation deletions are therefore
never re-applied after a crash.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any

# Snapshot schema version, stored under "_version".
_SCHEMA_VERSION = 1


def _empty_state() -> dict[str, Any]:
    return {
        "_version": _SCHEMA_VERSION,
        # tenant -> list of event records
        "events": {},
        # tenant -> aggregation_id -> {user_id: {"bins": {...}, "total": float}}
        "contributions": {},
        # tenant -> aggregation_id -> serialized AggregationResult
        "aggregates": {},
        # tenant -> idempotency_key -> aggregation_id
        "idem": {},
        # tenant -> idempotency_key -> {"kind": ..., "ref": resource}
        "idem_ops": {},
        # tenant -> {"limit": float, "consumed": float}
        "budget": {},
        # tenant -> user_id -> {"state": "granted|revoked", "updated_at": float}
        "consent": {},
        # tenant -> aggregation_id -> {user_id: timestamp}
        "revocations": {},
        # tenant -> list of serialized audit entries
        "audit": {},
        # global monotonically increasing audit sequence
        "audit_seq": 0,
    }


class Storage:
    """File-backed durable store with a process-wide reentrant lock."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._state: dict[str, Any] = self._load()

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def _load(self) -> dict[str, Any]:
        if not os.path.exists(self.path):
            parent = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(parent, exist_ok=True)
            return _empty_state()
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Basic migration hook for future schema versions.
        if data.get("_version") != _SCHEMA_VERSION:
            raise ValueError(f"unsupported storage schema: {data.get('_version')}")
        return data

    def _persist_locked(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh, sort_keys=True, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _tenant_bucket(self, top: str, tenant_id: str) -> dict[str, Any]:
        root = self._state[top]
        return root.setdefault(tenant_id, {})

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def snapshot(self) -> dict[str, Any]:
        """Return the live state (callers must hold ``lock`` while mutating)."""
        return self._state

    def commit(self, mutations=None) -> None:
        """Persist current state. ``mutations`` is an optional no-op callback.

        Callers perform their in-memory mutations while holding ``self.lock``
        and then call :meth:`commit`; the fsynced rename makes the whole
        transition crash-atomic.
        """
        with self._lock:
            if callable(mutations):
                mutations()
            self._persist_locked()

    # ------------------------------------------------------------------ #
    # events
    # ------------------------------------------------------------------ #
    def append_event(self, event: dict[str, Any]) -> None:
        bucket = self._tenant_bucket("events", event["tenant_id"])
        records = bucket.setdefault("_records", [])
        records.append(event)

    def events_for_window(
        self, tenant_id: str, event_type: str, start: float, end: float
    ) -> list[dict[str, Any]]:
        bucket = self._state["events"].get(tenant_id)
        if not bucket:
            return []
        return [
            e
            for e in bucket.get("_records", ())
            if e["event_type"] == event_type and start <= e["timestamp"] < end
        ]

    def delete_events(self, tenant_id: str, ids: set[str]) -> None:
        bucket = self._state["events"].get(tenant_id)
        if not bucket:
            return
        bucket["_records"] = [
            e for e in bucket.get("_records", ()) if e["event_id"] not in ids
        ]

    # ------------------------------------------------------------------ #
    # contributions (individual, access-controlled)
    # ------------------------------------------------------------------ #
    def get_contribution(
        self, tenant_id: str, aggregation_id: str, user_id: str
    ) -> dict[str, Any] | None:
        agg = self._state["contributions"].get(tenant_id, {}).get(aggregation_id)
        if not agg:
            return None
        return agg.get(user_id)

    def put_contributions(
        self, tenant_id: str, aggregation_id: str, contributions: dict[str, dict]
    ) -> None:
        tenant = self._state["contributions"].setdefault(tenant_id, {})
        tenant[aggregation_id] = dict(contributions)

    def all_contributions(
        self, tenant_id: str, aggregation_id: str
    ) -> dict[str, dict[str, Any]]:
        return dict(
            self._state["contributions"].get(tenant_id, {}).get(aggregation_id, {})
        )

    def delete_contribution(
        self, tenant_id: str, aggregation_id: str, user_id: str
    ) -> None:
        agg = self._state["contributions"].get(tenant_id, {}).get(aggregation_id)
        if agg and user_id in agg:
            del agg[user_id]

    # ------------------------------------------------------------------ #
    # aggregates
    # ------------------------------------------------------------------ #
    def put_aggregate(self, result: dict[str, Any]) -> None:
        tenant = self._state["aggregates"].setdefault(result["tenant_id"], {})
        tenant[result["aggregation_id"]] = result

    def get_aggregate(self, tenant_id: str, aggregation_id: str) -> dict[str, Any] | None:
        return self._state["aggregates"].get(tenant_id, {}).get(aggregation_id)

    def list_aggregates(self, tenant_id: str) -> list[dict[str, Any]]:
        return list(self._state["aggregates"].get(tenant_id, {}).values())

    def find_aggregate(self, tenant_id: str, idem_key: str) -> dict[str, Any] | None:
        aggregation_id = self._state["idem"].get(tenant_id, {}).get(idem_key)
        if aggregation_id is None:
            return None
        return self.get_aggregate(tenant_id, aggregation_id)

    def save_idem_key(self, tenant_id: str, idem_key: str, aggregation_id: str) -> None:
        self._state["idem"].setdefault(tenant_id, {})[idem_key] = aggregation_id

    # generic idempotent-operation ledger (e.g. charged queries)
    def get_idem_op(self, tenant_id: str, idem_key: str) -> dict[str, str] | None:
        return self._state.get("idem_ops", {}).get(tenant_id, {}).get(idem_key)

    def save_idem_op(
        self, tenant_id: str, idem_key: str, kind: str, ref: str
    ) -> None:
        self._state.setdefault("idem_ops", {}).setdefault(tenant_id, {})[idem_key] = {
            "kind": kind,
            "ref": ref,
        }

    # ------------------------------------------------------------------ #
    # budget
    # ------------------------------------------------------------------ #
    def get_budget(self, tenant_id: str, default_limit: float) -> dict[str, float]:
        record = self._state["budget"].get(tenant_id)
        if record is None:
            record = {"limit": float(default_limit), "consumed": 0.0}
            self._state["budget"][tenant_id] = record
        return record

    def set_budget_limit(self, tenant_id: str, limit: float) -> None:
        record = self.get_budget(tenant_id, limit)
        record["limit"] = float(limit)

    def charge_budget(self, tenant_id: str, amount: float) -> None:
        record = self._state["budget"][tenant_id]
        record["consumed"] = round(record["consumed"] + amount, 12)

    # ------------------------------------------------------------------ #
    # consent
    # ------------------------------------------------------------------ #
    def get_consent(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        return self._state["consent"].get(tenant_id, {}).get(user_id)

    def put_consent(
        self, tenant_id: str, user_id: str, state: str, updated_at: float
    ) -> None:
        self._state["consent"].setdefault(tenant_id, {})[user_id] = {
            "state": state,
            "updated_at": updated_at,
        }

    def list_consent(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        return dict(self._state["consent"].get(tenant_id, {}))

    # ------------------------------------------------------------------ #
    # revocation ledger (deduplicates removal across restarts)
    # ------------------------------------------------------------------ #
    def has_revocation(
        self, tenant_id: str, aggregation_id: str, user_id: str
    ) -> bool:
        return (
            user_id
            in self._state["revocations"].get(tenant_id, {}).get(aggregation_id, {})
        )

    def record_revocation(
        self, tenant_id: str, aggregation_id: str, user_id: str, at: float
    ) -> None:
        tenant = self._state["revocations"].setdefault(tenant_id, {})
        tenant.setdefault(aggregation_id, {})[user_id] = at

    def revocations_for(
        self, tenant_id: str, aggregation_id: str
    ) -> dict[str, float]:
        return dict(
            self._state["revocations"].get(tenant_id, {}).get(aggregation_id, {})
        )

    # ------------------------------------------------------------------ #
    # audit
    # ------------------------------------------------------------------ #
    def next_audit_seq(self) -> int:
        self._state["audit_seq"] += 1
        return self._state["audit_seq"]

    def append_audit(self, tenant_id: str, entry: dict[str, Any]) -> None:
        self._state["audit"].setdefault(tenant_id, []).append(entry)

    def list_audit(self, tenant_id: str) -> list[dict[str, Any]]:
        return list(self._state["audit"].get(tenant_id, ()))
