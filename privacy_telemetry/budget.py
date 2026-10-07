"""Per-tenant privacy-budget ledger.

The ledger is append-only: budget consumption never decreases (monotonic),
every charge is durable, and a client-supplied ``request_id`` makes retries
idempotent so a network retry can never deduct budget twice. Whether a charge
is allowed is decided *inside* the same transaction as the charge itself, so
the answer cannot go stale under concurrency.
"""
from __future__ import annotations

import time
from typing import Any

from .models import BudgetStatus
from .storage import Storage


class BudgetLedger:
    def __init__(self, storage: Any) -> None:
        self._store: Storage = storage

    def status(self, tenant_id: str, limit: float) -> BudgetStatus:
        with self._store.transaction() as cur:
            consumed = Storage.budget_consumed(cur, tenant_id)
        return BudgetStatus(tenant_id=tenant_id, consumed=consumed, limit=limit)

    def try_charge(self, tenant_id: str, amount: float, limit: float,
                   request_id: str | None = None) -> bool:
        """Atomically check-and-charge.

        Returns True if the charge was applied (or was already applied under
        the same ``request_id``); returns False if it would exceed the limit.
        Never partially charges.
        """
        if amount < 0:
            raise ValueError("charge amount must be non-negative")
        with self._store.transaction() as cur:
            if request_id is not None:
                dup = cur.execute(
                    "SELECT 1 FROM budget_entries WHERE tenant_id=? "
                    "AND request_id=?",
                    (tenant_id, request_id),
                ).fetchone()
                if dup is not None:
                    return True
            consumed = Storage.budget_consumed(cur, tenant_id)
            if consumed + amount > limit + 1e-12:
                return False
            cur.execute(
                "INSERT INTO budget_entries(tenant_id, amount, request_id, "
                "ts_ms) VALUES(?, ?, ?, ?)",
                (tenant_id, amount, request_id, time.time_ns() // 1_000_000),
            )
            return True
