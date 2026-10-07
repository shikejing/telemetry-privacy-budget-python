"""FastAPI HTTP surface for the privacy aggregation pipeline.

Authentication is deliberately simple: callers present ``X-Actor`` and
``X-Role`` headers (in production these would be replaced by verified
identity tokens). Authorization is enforced inside the engine; the API only
translates policy errors into status codes and *never* returns individual
data on a denied request.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .models import (
    AuthorizationError,
    BudgetExceededError,
    Event,
    PrivacyError,
    UnknownTenantError,
)


class EventIn(BaseModel):
    event_id: str
    tenant_id: str
    user_id: str
    ts_ms: int = Field(ge=0)
    value: float = 0.0
    attrs: dict[str, str] = Field(default_factory=dict)


class EventsIn(BaseModel):
    events: list[EventIn]


class RevokeIn(BaseModel):
    tenant_id: str
    user_id: str
    request_id: str | None = None


class AggregateOut(BaseModel):
    tenant_id: str
    window_start_ms: int
    dimensions: dict[str, str]
    contributing_users: int
    value: float
    noise: float
    noisy_value: float
    budget_consumed: float


def _raise_privacy(exc: PrivacyError) -> HTTPException:
    if isinstance(exc, BudgetExceededError):
        return HTTPException(status_code=402, detail=str(exc))
    if isinstance(exc, AuthorizationError):
        return HTTPException(status_code=403, detail="access denied")
    if isinstance(exc, UnknownTenantError):
        return HTTPException(status_code=404, detail="unknown tenant")
    return HTTPException(status_code=400, detail=str(exc))


def create_app(engine: Any) -> FastAPI:
    app = FastAPI(title="Privacy Telemetry Aggregation", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/events", status_code=202)
    def post_events(body: EventsIn) -> dict[str, Any]:
        events = [Event(event_id=e.event_id, tenant_id=e.tenant_id,
                        user_id=e.user_id, ts_ms=e.ts_ms, value=e.value,
                        attrs=e.attrs) for e in body.events]
        try:
            accepted = engine.ingest(events)
        except PrivacyError as ex:  # unknown tenant
            raise _raise_privacy(ex) from ex
        return {"accepted": accepted, "submitted": len(events)}

    @app.post("/aggregate")
    def run_aggregate(tenant_id: str | None = Query(default=None)) -> dict[str, Any]:
        try:
            folded = engine.aggregate_pending(tenant_id)
        except PrivacyError as ex:
            raise _raise_privacy(ex) from ex
        return {"folded": folded}

    @app.post("/revoke", status_code=200)
    def revoke(body: RevokeIn, x_actor: str = Header(default="system"),
               x_role: str = Header(default="admin")) -> dict[str, Any]:
        try:
            changed = engine.revoke(body.tenant_id, body.user_id,
                                    actor=x_actor, role=x_role)
        except (PrivacyError, ValueError) as ex:
            raise _raise_privacy(ex if isinstance(ex, PrivacyError)
                                 else AuthorizationError("bad role")) from ex
        return {"revoked": True, "buckets_changed": changed}

    @app.get("/aggregates", response_model=list[AggregateOut])
    def get_aggregates(
        tenant_id: str = Query(...),
        window_start_ms: int | None = Query(default=None),
        request_id: str | None = Query(default=None),
        x_actor: str = Header(default="anonymous"),
        x_role: str = Header(default="analyst"),
    ) -> list[AggregateOut]:
        try:
            results = engine.query_aggregates(
                tenant_id, x_actor, x_role,
                window_start_ms=window_start_ms, request_id=request_id)
        except (PrivacyError, ValueError) as ex:
            raise _raise_privacy(ex if isinstance(ex, PrivacyError)
                                 else AuthorizationError("bad role")) from ex
        return [AggregateOut(
            tenant_id=r.tenant_id, window_start_ms=r.window_start_ms,
            dimensions=r.dimensions, contributing_users=r.contributing_users,
            value=r.value, noise=r.noise, noisy_value=r.noisy_value,
            budget_consumed=r.budget_consumed) for r in results]

    @app.get("/raw-events")
    def get_raw(
        tenant_id: str = Query(...),
        x_actor: str = Header(default="anonymous"),
        x_role: str = Header(default="analyst"),
    ) -> list[dict[str, Any]]:
        try:
            events = engine.read_raw_events(tenant_id, x_actor, x_role)
        except (PrivacyError, ValueError) as ex:
            raise _raise_privacy(ex if isinstance(ex, PrivacyError)
                                 else AuthorizationError("bad role")) from ex
        return [e.__dict__ for e in events]

    @app.get("/budget")
    def get_budget(tenant_id: str = Query(...)) -> dict[str, Any]:
        try:
            st = engine.budget_status(tenant_id)
        except UnknownTenantError as ex:
            raise _raise_privacy(ex) from ex
        return {"tenant_id": st.tenant_id, "consumed": st.consumed,
                "limit": st.limit, "remaining": st.remaining}

    @app.get("/audit")
    def get_audit(
        tenant_id: str | None = Query(default=None),
        x_actor: str = Header(default="anonymous"),
        x_role: str = Header(default="analyst"),
    ) -> list[dict[str, Any]]:
        # Only admin may inspect the audit trail itself.
        if x_role != "admin":
            engine._audit.record(tenant_id or "-", x_actor,
                                 _safe_role(x_role), "audit_read", False)
            raise HTTPException(status_code=403, detail="access denied")
        entries = engine._audit.entries(tenant_id)
        return [{"seq": e.seq, "ts_ms": e.ts_ms, "tenant_id": e.tenant_id,
                 "actor": e.actor, "role": e.role, "action": e.action,
                 "allowed": e.allowed, "subject_ref": e.subject_ref}
                for e in entries]

    return app


def _safe_role(role: str):
    try:
        from .audit import parse_role
        return parse_role(role)
    except ValueError:
        from .models import AccessRole
        return AccessRole.ANALYST
