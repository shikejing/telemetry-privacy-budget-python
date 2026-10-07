"""User consent state and revocation propagation."""

from __future__ import annotations

import time

from .models import ConsentState
from .storage import Storage


class ConsentManager:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def state_of(self, tenant_id: str, user_id: str) -> ConsentState:
        record = self.storage.get_consent(tenant_id, user_id)
        if record is None:
            # Default posture: telemetry requires explicit grant.
            return ConsentState.REVOKED
        return ConsentState(record["state"])

    def is_granted(self, tenant_id: str, user_id: str) -> bool:
        return self.state_of(tenant_id, user_id) is ConsentState.GRANTED

    def grant(self, tenant_id: str, user_id: str) -> None:
        with self.storage.lock:
            self.storage.put_consent(
                tenant_id, user_id, ConsentState.GRANTED.value, time.time()
            )
            self.storage.commit()

    def revoke(self, tenant_id: str, user_id: str) -> list[str]:
        """Mark consent revoked and remove the user from every affected
        aggregate atomically.

        Returns the list of adjusted aggregation ids. The actual contribution
        subtraction is performed by the aggregation engine; here we persist
        the revocation intent plus idempotent ledger entries inside the same
        transaction so a crash/restart never double-deletes.
        """
        with self.storage.lock:
            self.storage.put_consent(
                tenant_id, user_id, ConsentState.REVOKED.value, time.time()
            )
            affected: list[str] = []
            for result in self.storage.list_aggregates(tenant_id):
                aggregation_id = result["aggregation_id"]
                contrib = self.storage.get_contribution(
                    tenant_id, aggregation_id, user_id
                )
                if contrib is None:
                    continue
                if not self.storage.has_revocation(
                    tenant_id, aggregation_id, user_id
                ):
                    self.storage.record_revocation(
                        tenant_id, aggregation_id, user_id, time.time()
                    )
                affected.append(aggregation_id)
            self.storage.commit()
            return affected
