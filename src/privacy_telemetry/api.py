"""HTTP API for the privacy telemetry pipeline."""

from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .aggregation import Aggregator
from .audit import Auditor
from .authz import Authorizer
from .budget import DEFAULT_BUDGET_LIMIT, BudgetManager
from .consent import ConsentManager
from .errors import (
    AccessDeniedError,
    AggregationNotFoundError,
    BudgetExceededError,
    NotFoundError,
)
from .models import AggregationConfig, ConsentState, Principal, Role
from .storage import Storage


# --------------------------------------------------------------------- #
# request / response schemas
# --------------------------------------------------------------------- #
class EventIn(BaseModel):
    user_id: str
    event_type: str
    timestamp: float
    dimensions: dict[str, str] = Field(default_factory=dict)
    value: float = 1.0


class ConsentIn(BaseModel):
    user_id: str


class AggregationIn(BaseModel):
    dimensions: list[str]
    window_start: float
    window_end: float
    event_type: str
    epsilon: float = 1.0
    noise_seed: int = 0
    query_cost: float = 0.0
    idem_key: str | None = None


class QueryIn(BaseModel):
    bin_key: str | None = None
    idem_key: str | None = None


class BudgetIn(BaseModel):
    limit: float


class Services:
    def __init__(
        self,
        state_path: str,
        audit_secret: str = "default-secret",
        default_budget: float = DEFAULT_BUDGET_LIMIT,
    ) -> None:
        self.storage = Storage(state_path)
        self.budgets = BudgetManager(self.storage, default_budget)
        self.consent = ConsentManager(self.storage)
        self.audit = Auditor(self.storage, audit_secret)
        self.authz = Authorizer()
        self.aggregator = Aggregator(self.storage, self.budgets)
        self.recover()

    def recover(self) -> None:
        """Resume from the committed position after restart.

        Re-apply any revocation that was durably ledgered but whose aggregate
        update had not yet committed. The operation is idempotent: already
        excluded users and already charged budgets are never touched twice.
        """
        for tenant_id in list(self.storage.snapshot()["aggregates"].keys()):
            for record in self.storage.list_aggregates(tenant_id):
                self.aggregator.apply_revocations(
                    tenant_id, record["aggregation_id"]
                )


def _principal(
    tenant_id: str | None, role: str | None, user_id: str | None
) -> Principal:
    if not tenant_id or not role:
        raise HTTPException(status_code=401, detail="missing X-Tenant-Id/X-Role")
    try:
        return Principal(tenant_id=tenant_id, role=Role(role))
    except ValueError:
        raise HTTPException(status_code=401, detail=f"unknown role {role!r}")


def create_app(services: Services | None = None) -> FastAPI:
    if services is None:
        services = Services(
            state_path=os.environ.get(
                "PRIVACY_TELEMETRY_STATE", "data/state.json"
            ),
            audit_secret=os.environ.get("PRIVACY_TELEMETRY_AUDIT_SECRET", "default-secret"),
            default_budget=float(
                os.environ.get("PRIVACY_TELEMETRY_DEFAULT_BUDGET", DEFAULT_BUDGET_LIMIT)
            ),
        )

    app = FastAPI(title="Privacy Telemetry Aggregation", version="0.1.0")
    app.state.services = services

    def guarded(
        principal: Principal,
        capability: str,
        action: str,
        resource: str,
        tenant_id: str,
        user_id: str | None = None,
        detail: str = "",
    ) -> None:
        """Authorize and audit; deny without leaking data."""
        s = services
        try:
            s.authz.require(principal, capability, tenant_id)
        except AccessDeniedError as exc:
            with s.storage.lock:
                s.audit.record(
                    tenant_id, action, resource, "denied",
                    principal.role.value, user_id=user_id, detail=str(exc),
                )
                s.storage.commit()
            raise HTTPException(status_code=403, detail="access denied")
        return None

    def audit_ok(
        principal: Principal,
        action: str,
        resource: str,
        user_id: str | None = None,
        detail: str = "",
    ) -> None:
        s = services
        with s.storage.lock:
            s.audit.record(
                principal.tenant_id, action, resource, "allowed",
                principal.role.value, user_id=user_id, detail=detail,
            )
            s.storage.commit()

    def result_payload(result) -> dict[str, Any]:
        return {
            "aggregation_id": result.aggregation_id,
            "tenant_id": result.tenant_id,
            "config": {
                "dimensions": list(result.config.dimensions),
                "window_start": result.config.window_start,
                "window_end": result.config.window_end,
                "event_type": result.config.event_type,
                "epsilon": result.config.epsilon,
                "noise_seed": result.config.noise_seed,
                "query_cost": result.config.query_cost,
            },
            "bins": result.bins,
            "cost": result.cost,
            "created_at": result.created_at,
            "excluded_users": sorted(result.excluded_users),
        }

    # ------------------------------------------------------------------ #
    @app.post("/events", status_code=202)
    def ingest(
        body: EventIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "aggregate:write", "event.ingest", "/events",
                principal.tenant_id, user_id=body.user_id)
        s = services
        event_id = str(uuid.uuid4())
        with s.storage.lock:
            s.storage.append_event(
                {
                    "tenant_id": principal.tenant_id,
                    "user_id": body.user_id,
                    "event_type": body.event_type,
                    "timestamp": body.timestamp,
                    "dimensions": body.dimensions,
                    "value": body.value,
                    "event_id": event_id,
                }
            )
            s.audit.record(
                principal.tenant_id, "event.ingest", "/events", "allowed",
                principal.role.value, user_id=body.user_id,
                detail=f"event_type={body.event_type}",
            )
            s.storage.commit()
        return {"status": "accepted", "event_id": event_id}

    # ------------------------------------------------------------------ #
    @app.post("/consent/grant")
    def grant_consent(
        body: ConsentIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        s = services
        try:
            s.authz.require(principal, "consent:write", principal.tenant_id)
        except AccessDeniedError:
            s.authz.require_self_or_admin(principal, body.user_id, x_user_id)
        s.consent.grant(principal.tenant_id, body.user_id)
        audit_ok(principal, "consent.grant",
                 f"consent:{s.audit.user_ref(principal.tenant_id, body.user_id)}",
                 user_id=body.user_id)
        return {"user_id": body.user_id, "state": ConsentState.GRANTED.value}

    @app.post("/consent/revoke")
    def revoke_consent(
        body: ConsentIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        s = services
        try:
            s.authz.require(principal, "consent:write", principal.tenant_id)
        except AccessDeniedError:
            s.authz.require_self_or_admin(principal, body.user_id, x_user_id)
        affected = s.consent.revoke(principal.tenant_id, body.user_id)
        # Propagate immediately; each call is idempotent and budget-free.
        for aggregation_id in affected:
            s.aggregator.apply_revocations(principal.tenant_id, aggregation_id)
        audit_ok(
            principal, "consent.revoke",
            f"consent:{s.audit.user_ref(principal.tenant_id, body.user_id)}",
            user_id=body.user_id, detail=f"aggregates={len(affected)}",
        )
        return {
            "user_id": body.user_id,
            "state": ConsentState.REVOKED.value,
            "affected_aggregations": affected,
        }

    # ------------------------------------------------------------------ #
    @app.post("/aggregations", status_code=201)
    def create_aggregation(
        body: AggregationIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "aggregate:write", "aggregate.run", "/aggregations",
                principal.tenant_id)
        s = services
        config = AggregationConfig(
            dimensions=tuple(body.dimensions),
            window_start=body.window_start,
            window_end=body.window_end,
            event_type=body.event_type,
            epsilon=body.epsilon,
            noise_seed=body.noise_seed,
            query_cost=body.query_cost,
        )
        try:
            result = s.aggregator.run_aggregation(
                principal.tenant_id, config, idem_key=body.idem_key
            )
        except BudgetExceededError as exc:
            with s.storage.lock:
                s.audit.record(
                    principal.tenant_id, "aggregate.run", "/aggregations",
                    "denied_budget", principal.role.value, detail="budget_exceeded",
                )
                s.storage.commit()
            raise HTTPException(status_code=402, detail=str(exc))
        audit_ok(
            principal, "aggregate.run", result.aggregation_id,
            detail=f"epsilon={body.epsilon};bins={len(result.bins)}",
        )
        return result_payload(result)

    @app.get("/aggregations")
    def list_aggregations(
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "aggregate:read", "aggregate.list",
                "/aggregations", principal.tenant_id)
        results = services.aggregator.list(principal.tenant_id)
        audit_ok(principal, "aggregate.list", "/aggregations")
        return [result_payload(r) for r in results]

    @app.get("/aggregations/{aggregation_id}")
    def read_aggregation(
        aggregation_id: str,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "aggregate:read", "aggregate.read",
                aggregation_id, principal.tenant_id)
        try:
            result = services.aggregator.get(principal.tenant_id, aggregation_id)
        except AggregationNotFoundError:
            raise HTTPException(status_code=404, detail="aggregation not found")
        audit_ok(principal, "aggregate.read", aggregation_id)
        return result_payload(result)

    @app.post("/aggregations/{aggregation_id}/query")
    def query_aggregation(
        aggregation_id: str,
        body: QueryIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "query:run", "aggregate.query",
                aggregation_id, principal.tenant_id)
        s = services
        try:
            bins = s.aggregator.query(
                principal.tenant_id, aggregation_id,
                bin_key=body.bin_key, idem_key=body.idem_key,
            )
        except AggregationNotFoundError:
            raise HTTPException(status_code=404, detail="aggregation not found")
        except BudgetExceededError as exc:
            with s.storage.lock:
                s.audit.record(
                    principal.tenant_id, "aggregate.query", aggregation_id,
                    "denied_budget", principal.role.value, detail="budget_exceeded",
                )
                s.storage.commit()
            raise HTTPException(status_code=402, detail=str(exc))
        audit_ok(
            principal, "aggregate.query", aggregation_id,
            detail=f"cell={'single' if body.bin_key else 'all'}",
        )
        return {"aggregation_id": aggregation_id, "bins": bins}

    @app.get("/aggregations/{aggregation_id}/contributions/{user_id}")
    def read_contribution(
        aggregation_id: str,
        user_id: str,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        # Individual vectors require the privileged detail capability;
        # denied attempts are audited and never return data.
        guarded(principal, "detail:read", "detail.read",
                aggregation_id, principal.tenant_id, user_id=user_id)
        payload = services.aggregator.individual_contribution(
            principal.tenant_id, aggregation_id, user_id
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="contribution not found")
        audit_ok(principal, "detail.read", aggregation_id, user_id=user_id)
        return {"user_ref": services.audit.user_ref(principal.tenant_id, user_id),
                "bins": payload}

    # ------------------------------------------------------------------ #
    @app.get("/budget")
    def read_budget(
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "aggregate:read", "budget.read",
                "/budget", principal.tenant_id)
        state = services.budgets.state(principal.tenant_id)
        return {"tenant_id": state.tenant_id, "limit": state.limit,
                "consumed": state.consumed, "remaining": state.remaining}

    @app.put("/budget")
    def update_budget(
        body: BudgetIn,
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "consent:write", "budget.update",
                "/budget", principal.tenant_id)
        services.budgets.set_limit(principal.tenant_id, body.limit)
        audit_ok(principal, "budget.update", "/budget", detail=f"limit={body.limit}")
        state = services.budgets.state(principal.tenant_id)
        return {"tenant_id": state.tenant_id, "limit": state.limit,
                "consumed": state.consumed, "remaining": state.remaining}

    # ------------------------------------------------------------------ #
    @app.get("/audit")
    def read_audit(
        x_tenant_id: str = Header(...),
        x_role: str = Header(...),
        x_user_id: str | None = Header(default=None),
    ):
        principal = _principal(x_tenant_id, x_role, x_user_id)
        guarded(principal, "audit:read", "audit.read",
                "/audit", principal.tenant_id)
        entries = services.audit.list(principal.tenant_id)
        return [e.__dict__ for e in entries]

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app
