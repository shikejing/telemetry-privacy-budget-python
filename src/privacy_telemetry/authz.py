"""Capability-based access control.

Capabilities:
- ``aggregate:read``  noisy aggregate results (viewer/analyst)
- ``query:run``       budget-charged queries (analyst)
- ``aggregate:write`` run aggregations, manage budgets (analyst/admin)
- ``detail:read``     per-user contribution vectors (admin only)
- ``consent:write``   grant/revoke consent (admin; a user-scoped token may
                      only manage its own user id)
- ``audit:read``      read the audit trail (auditor/admin)

Every authorization failure is recorded by the caller through the auditor;
this module performs the decision only and never returns individual data.
"""

from __future__ import annotations

from .errors import AccessDeniedError
from .models import Principal, Role

CAPABILITIES: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset({"aggregate:read"}),
    Role.ANALYST: frozenset(
        {"aggregate:read", "aggregate:write", "query:run"}
    ),
    Role.AUDITOR: frozenset({"audit:read"}),
    Role.ADMIN: frozenset(
        {
            "aggregate:read",
            "aggregate:write",
            "query:run",
            "detail:read",
            "consent:write",
            "audit:read",
        }
    ),
}


class Authorizer:
    def permit(self, principal: Principal, capability: str) -> bool:
        return capability in CAPABILITIES[principal.role]

    def require(
        self,
        principal: Principal,
        capability: str,
        resource_tenant: str | None = None,
    ) -> None:
        """Raise :class:`AccessDeniedError` unless access is permitted.

        Principals are always scoped to a single tenant: cross-tenant access
        is refused even when the role itself carries the capability.
        """
        if resource_tenant is not None and principal.tenant_id != resource_tenant:
            raise AccessDeniedError(
                f"tenant mismatch: principal of {principal.tenant_id!r} "
                f"cannot access resource of {resource_tenant!r}"
            )
        if not self.permit(principal, capability):
            raise AccessDeniedError(
                f"role {principal.role.value!r} lacks capability {capability!r}"
            )

    def require_self_or_admin(
        self, principal: Principal, target_user_id: str, self_user_id: str | None
    ) -> None:
        """Consent self-service: a user token may act on its own record."""
        if principal.role is Role.ADMIN:
            return
        if principal.role is not Role.VIEWER or self_user_id != target_user_id:
            raise AccessDeniedError(
                "only the user themself or an admin may change consent"
            )
