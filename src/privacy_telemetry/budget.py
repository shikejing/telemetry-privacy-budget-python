"""Per-tenant privacy budget accounting."""

from __future__ import annotations

from .errors import BudgetExceededError
from .models import BudgetState
from .storage import Storage

DEFAULT_BUDGET_LIMIT = 10.0


class BudgetManager:
    def __init__(self, storage: Storage, default_limit: float = DEFAULT_BUDGET_LIMIT) -> None:
        self.storage = storage
        self.default_limit = default_limit

    def state(self, tenant_id: str) -> BudgetState:
        record = self.storage.get_budget(tenant_id, self.default_limit)
        return BudgetState(
            tenant_id=tenant_id, limit=record["limit"], consumed=record["consumed"]
        )

    def set_limit(self, tenant_id: str, limit: float) -> None:
        if limit < 0:
            raise ValueError("budget limit must be non-negative")
        with self.storage.lock:
            self.storage.set_budget_limit(tenant_id, limit)
            self.storage.commit()

    def can_charge(self, tenant_id: str, amount: float) -> bool:
        state = self.state(tenant_id)
        return state.consumed + amount <= state.limit + 1e-12

    def refund(self, tenant_id: str, amount: float) -> None:
        """Compensating rollback when a charged operation fails to commit."""
        with self.storage.lock:
            record = self.storage.get_budget(tenant_id, self.default_limit)
            record["consumed"] = max(
                0.0, round(record["consumed"] - amount, 12)
            )
            self.storage.commit()

    def charge(self, tenant_id: str, amount: float, reason: str) -> None:
        """Atomically check and deduct; persisted before the caller proceeds.

        The check and deduction happen under the storage lock and are committed
        immediately, so concurrent aggregations cannot oversubscribe and a
        restart never re-deducts.
        """
        if amount < 0:
            raise ValueError("charge must be non-negative")
        with self.storage.lock:
            state = self.state(tenant_id)
            if state.consumed + amount > state.limit + 1e-12:
                raise BudgetExceededError(
                    f"tenant {tenant_id}: budget exhausted "
                    f"(consumed={state.consumed}, limit={state.limit}, "
                    f"requested={amount}, op={reason})"
                )
            self.storage.charge_budget(tenant_id, amount)
            self.storage.commit()
