"""Access roles and redacted audit logging.

Audit records never carry values, user ids or event payloads. When a record
must refer to an individual subject (e.g. a revoked user), only a keyed hash
of the tenant-qualified identifier is stored, which is not reversible and is
specific to this deployment's audit secret.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
import time
from typing import Any

from .models import AccessRole, AuditEntry
from .storage import Storage

# Who may reach individual-level detail.
RAW_READ_ROLES = frozenset({AccessRole.SUPPORT, AccessRole.ADMIN})
# Who may read published (noisy) aggregate statistics.
AGG_READ_ROLES = frozenset(
    {AccessRole.ANALYST, AccessRole.SUPPORT, AccessRole.ADMIN}
)


def parse_role(role: str | AccessRole) -> AccessRole:
    if isinstance(role, AccessRole):
        return role
    try:
        return AccessRole(role)
    except ValueError:
        raise ValueError(f"unknown role: {role!r}") from None


class AuditLog:
    def __init__(self, storage: Any, secret: bytes = b"audit-secret") -> None:
        self._store: Storage = storage
        self._secret = secret

    def subject_hash(self, tenant_id: str, user_id: str) -> str:
        mac = hmac.new(self._secret,
                       f"{tenant_id}\x00{user_id}".encode(),
                       hashlib.sha256)
        return "u_" + mac.hexdigest()[:16]

    def record(self, tenant_id: str, actor: str, role: AccessRole,
               action: str, allowed: bool, subject: str | None = None
               ) -> AuditEntry:
        """Persist one audit entry; ``subject`` is always stored hashed."""
        ts_ms = time.time_ns() // 1_000_000
        ref = "" if subject is None else self.subject_hash(tenant_id, subject)
        with self._store.transaction() as cur:
            cur = self._insert(cur, ts_ms, tenant_id, actor,
                               role.value if isinstance(role, AccessRole)
                               else str(role), action, 1 if allowed else 0, ref)
            seq = cur.lastrowid
        return AuditEntry(seq=seq, ts_ms=ts_ms, tenant_id=tenant_id,
                          actor=actor, role=role.value
                          if isinstance(role, AccessRole) else str(role),
                          action=action, allowed=allowed, subject_ref=ref)

    @staticmethod
    def _insert(cur: sqlite3.Cursor, ts_ms: int, tenant_id: str, actor: str,
                role: str, action: str, allowed: int, ref: str
                ) -> sqlite3.Cursor:
        cur.execute(
            "INSERT INTO audit(ts_ms, tenant_id, actor, role, action, "
            "allowed, subject_ref) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (ts_ms, tenant_id, actor, role, action, allowed, ref),
        )
        return cur

    def entries(self, tenant_id: str | None = None) -> list[AuditEntry]:
        with self._store.transaction() as cur:
            if tenant_id is None:
                rows = cur.execute(
                    "SELECT seq, ts_ms, tenant_id, actor, role, action, "
                    "allowed, subject_ref FROM audit ORDER BY seq"
                ).fetchall()
            else:
                rows = cur.execute(
                    "SELECT seq, ts_ms, tenant_id, actor, role, action, "
                    "allowed, subject_ref FROM audit WHERE tenant_id=? "
                    "ORDER BY seq",
                    (tenant_id,),
                ).fetchall()
        return [AuditEntry(seq=r["seq"], ts_ms=r["ts_ms"],
                           tenant_id=r["tenant_id"], actor=r["actor"],
                           role=r["role"], action=r["action"],
                           allowed=bool(r["allowed"]),
                           subject_ref=r["subject_ref"]) for r in rows]
