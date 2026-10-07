"""Audit logging without re-identifiable individual data.

Audit records never store raw user identifiers or event payloads. A user is
referenced only by ``HMAC(tenant_secret, tenant_id|user_id)``: the same user
produces a stable reference within a tenant (useful for correlating consent
actions) but it cannot be reversed into the original identifier without the
per-deployment secret.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from .models import AuditEntry
from .storage import Storage


class Auditor:
    def __init__(self, storage: Storage, tenant_secret: str = "default-secret") -> None:
        self.storage = storage
        self._secret = tenant_secret.encode("utf-8")

    def user_ref(self, tenant_id: str, user_id: str) -> str:
        digest = hmac.new(
            self._secret, f"{tenant_id}|{user_id}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"u_{digest[:16]}"

    def record(
        self,
        tenant_id: str,
        action: str,
        resource: str,
        outcome: str,
        actor_role: str,
        user_id: str | None = None,
        detail: str = "",
    ) -> AuditEntry:
        """Append an audit entry; caller controls locking/transaction boundaries."""
        entry = AuditEntry(
            seq=self.storage.next_audit_seq(),
            timestamp=time.time(),
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            outcome=outcome,
            actor_role=actor_role,
            user_ref=self.user_ref(tenant_id, user_id) if user_id is not None else "",
            # ``detail`` is restricted to non-personal metadata by callers.
            detail=detail,
        )
        self.storage.append_audit(tenant_id, entry.__dict__)
        return entry

    def list(self, tenant_id: str) -> list[AuditEntry]:
        return [AuditEntry(**row) for row in self.storage.list_audit(tenant_id)]

    # convenience helper used in tests
    @staticmethod
    def assert_no_pii(entries: list[AuditEntry], known_user_ids: Any) -> None:
        banned = set(known_user_ids)
        for e in entries:
            blob = f"{e.user_ref}|{e.detail}"
            assert not (blob and blob in banned or any(u and u in blob for u in banned))
