"""End-to-end HTTP coverage through the FastAPI app."""
from __future__ import annotations

import pytest

from privacy_telemetry.api import create_app

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient


@pytest.fixture
def client(engine):
    return TestClient(create_app(engine))


def _events(tenant="tenant-a"):
    return {"events": [
        {"event_id": "h1", "tenant_id": tenant, "user_id": "u1",
         "ts_ms": 100, "attrs": {"event": "click"}},
        {"event_id": "h2", "tenant_id": tenant, "user_id": "u2",
         "ts_ms": 200, "attrs": {"event": "click"}},
    ]}


def test_full_lifecycle_over_http(client):
    assert client.get("/health").json() == {"status": "ok"}
    r = client.post("/events", json=_events())
    assert r.status_code == 202 and r.json()["accepted"] == 2

    assert client.post("/aggregate", params={"tenant_id": "tenant-a"}
                       ).json() == {"folded": 2}

    r = client.get("/aggregates", params={"tenant_id": "tenant-a"},
                   headers={"X-Actor": "a", "X-Role": "analyst"})
    assert r.status_code == 200
    body = r.json()
    assert body[0]["value"] == 2.0
    assert "noise" in body[0] and "noisy_value" in body[0]

    budget = client.get("/budget", params={"tenant_id": "tenant-a"}).json()
    assert budget["limit"] == 1.0 and budget["consumed"] > 0


def test_http_budget_rejection_status(client):
    client.post("/events", json=_events())
    client.post("/aggregate", params={"tenant_id": "tenant-a"})  # 0.3
    for _ in range(14):  # to 1.0
        r = client.get("/aggregates", params={"tenant_id": "tenant-a"})
        assert r.status_code == 200
    r = client.get("/aggregates", params={"tenant_id": "tenant-a"})
    assert r.status_code == 402
    assert r.json() == {"detail": r.json()["detail"]}  # generic message only


def test_http_permission_denied(client):
    client.post("/events", json=_events())
    r = client.get("/raw-events", params={"tenant_id": "tenant-a"},
                   headers={"X-Role": "analyst"})
    assert r.status_code == 403
    assert r.json() == {"detail": "access denied"}


def test_http_revoke_and_audit(client):
    client.post("/events", json=_events())
    client.post("/aggregate", params={"tenant_id": "tenant-a"})
    r = client.post("/revoke", json={"tenant_id": "tenant-a", "user_id": "u1"},
                    headers={"X-Role": "admin"})
    assert r.status_code == 200 and r.json()["buckets_changed"] == 1

    # analyst cannot read audit; admin can and sees no raw identity
    assert client.get("/audit", headers={"X-Role": "analyst"}
                      ).status_code == 403
    audit = client.get("/audit", headers={"X-Role": "admin"}).json()
    assert any(a["action"] == "revoke" for a in audit)
    for a in audit:
        assert "u1" not in (a["subject_ref"] or "")


def test_http_idempotent_aggregate_query(client):
    client.post("/events", json=_events())
    # query retried with the same request id deducts only once
    a = client.get("/aggregates",
                   params={"tenant_id": "tenant-a", "request_id": "r-9"})
    b = client.get("/aggregates",
                   params={"tenant_id": "tenant-a", "request_id": "r-9"})
    assert a.json() == b.json()
    consumed = client.get("/budget",
                          params={"tenant_id": "tenant-a"}).json()["consumed"]
    assert consumed == 0.05


def test_unknown_tenant_rejected(client):
    r = client.get("/budget", params={"tenant_id": "nope"})
    assert r.status_code == 404
