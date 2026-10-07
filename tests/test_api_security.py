from fastapi.testclient import TestClient

from privacy_telemetry.api import create_app


ADMIN = {"X-Tenant-Id": "t", "X-Role": "admin"}
ANALYST = {"X-Tenant-Id": "t", "X-Role": "analyst"}
VIEWER = {"X-Tenant-Id": "t", "X-Role": "viewer"}
AUDITOR = {"X-Tenant-Id": "t", "X-Role": "auditor"}


def _setup(client):
    client.post("/consent/grant", json={"user_id": "alice"}, headers=ADMIN)
    client.post(
        "/events",
        json={
            "user_id": "alice",
            "event_type": "run",
            "timestamp": 1.0,
            "dimensions": {"os": "linux"},
        },
        headers=ADMIN,
    )
    r = client.post(
        "/aggregations",
        json={
            "dimensions": ["os"],
            "window_start": 0,
            "window_end": 10,
            "event_type": "run",
            "epsilon": 1.0,
            "noise_seed": 4,
            "idem_key": "agg1",
        },
        headers=ANALYST,
    )
    return r.json()["aggregation_id"]


def test_viewer_may_read_aggregate_but_not_detail(client):
    aid = _setup(client)
    assert client.get(f"/aggregations/{aid}", headers=VIEWER).status_code == 200
    denied = client.get(
        f"/aggregations/{aid}/contributions/alice", headers=VIEWER
    )
    assert denied.status_code == 403
    assert "alice" not in denied.text


def test_analyst_cannot_read_detail_or_audit(client):
    aid = _setup(client)
    assert client.get(
        f"/aggregations/{aid}/contributions/alice", headers=ANALYST
    ).status_code == 403
    assert client.get("/audit", headers=ANALYST).status_code == 403


def test_auditor_cannot_read_aggregates(client):
    _setup(client)
    assert client.get("/aggregations", headers=AUDITOR).status_code == 403
    assert client.get("/audit", headers=AUDITOR).status_code == 200


def test_admin_detail_returns_hashed_reference_only(client):
    aid = _setup(client)
    r = client.get(
        f"/aggregations/{aid}/contributions/alice", headers=ADMIN
    )
    assert r.status_code == 200
    body = r.text
    assert "alice" not in body
    assert body.startswith('{"user_ref":"u_')


def test_denied_access_is_audited(client):
    _setup(client)
    client.get("/aggregations", headers=AUDITOR)  # denied
    client.get("/budget", headers=VIEWER)
    audit = client.get("/audit", headers=AUDITOR).json()
    assert any(e["action"] == "aggregate.list" and e["outcome"] == "denied"
               for e in audit)


def test_audit_contains_no_raw_identifiers(client):
    aid = _setup(client)
    # trigger all code paths that mention the user
    client.post("/consent/revoke", json={"user_id": "alice"}, headers=ADMIN)
    client.get(f"/aggregations/{aid}/contributions/alice", headers=ADMIN)
    client.get(
        f"/aggregations/{aid}/contributions/alice", headers=VIEWER
    )
    audit = client.get("/audit", headers=AUDITOR).text
    assert "alice" not in audit


def test_budget_exceeded_returns_402_and_is_audited(services):
    client = TestClient(create_app(services))
    services.budgets.set_limit("t", 0.5)
    client.post("/consent/grant", json={"user_id": "alice"}, headers=ADMIN)
    client.post(
        "/events",
        json={"user_id": "alice", "event_type": "run", "timestamp": 1.0,
              "dimensions": {"os": "linux"}},
        headers=ADMIN,
    )
    r = client.post(
        "/aggregations",
        json={"dimensions": ["os"], "window_start": 0, "window_end": 10,
              "event_type": "run", "epsilon": 1.0, "noise_seed": 1},
        headers=ANALYST,
    )
    assert r.status_code == 402
    audit = client.get("/audit", headers=AUDITOR).json()
    assert any(e["outcome"] == "denied_budget" for e in audit)


def test_authentication_required(client):
    r = client.get("/aggregations")
    assert r.status_code == 422  # missing required headers


def test_tenant_isolation_of_state(services, state_path):
    from privacy_telemetry.storage import Storage
    from privacy_telemetry.budget import BudgetManager

    client = TestClient(create_app(services))
    _setup(client)
    # another tenant header sees nothing
    other = {"X-Tenant-Id": "other", "X-Role": "admin"}
    assert client.get("/aggregations", headers=other).json() == []
    assert client.get("/budget", headers=other).json()["consumed"] == 0.0
