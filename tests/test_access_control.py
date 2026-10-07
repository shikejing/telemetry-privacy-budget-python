"""Role separation, denial without disclosure, and redacted audit trail."""
from __future__ import annotations

import pytest

from privacy_telemetry.models import AuthorizationError
from tests.conftest import click_events


def test_analyst_may_read_aggregates_but_not_raw(engine):
    engine.ingest(click_events("a", ["u1"]))
    engine.aggregate_pending("tenant-a")
    res = engine.query_aggregates("tenant-a", "an", "analyst")
    assert res[0].noisy_value is not None
    with pytest.raises(AuthorizationError):
        engine.read_raw_events("tenant-a", "an", "analyst")


def test_support_may_read_retained_raw(engine):
    engine.ingest(click_events("a", ["u1"]))
    # before aggregation, support can see the retained raw detail
    raw = engine.read_raw_events("tenant-a", "sup", "support")
    assert len(raw) == 1 and raw[0].user_id == "u1"


def test_admin_denied_nothing_but_unknown_role_rejected(engine):
    engine.ingest(click_events("a", ["u1"]))
    engine.aggregate_pending("tenant-a")
    assert engine.read_raw_events("tenant-a", "root", "admin") == []
    with pytest.raises(ValueError):
        engine.query_aggregates("tenant-a", "x", "superuser")


def test_denial_returns_no_individual_data(engine):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    with pytest.raises(AuthorizationError) as ei:
        engine.read_raw_events("tenant-a", "an", "analyst")
    message = str(ei.value)
    assert "u1" not in message and "u2" not in message


def test_audit_records_allow_and_deny_without_identity(engine):
    engine.ingest(click_events("a", ["u1"]))
    engine.aggregate_pending("tenant-a")
    engine.query_aggregates("tenant-a", "an", "analyst")  # allowed
    with pytest.raises(AuthorizationError):
        engine.read_raw_events("tenant-a", "an", "analyst")  # denied
    engine.revoke("tenant-a", "u1", actor="root", role="admin")

    entries = engine._audit.entries("tenant-a")
    actions = {(e.action, e.allowed) for e in entries}
    assert ("aggregate_read", True) in actions
    assert ("raw_read", False) in actions
    assert ("revoke", True) in actions

    # Audit payload must never embed a restorable user id or raw values.
    for e in entries:
        assert "u1" not in (e.subject_ref or "")
    revoke_entries = [e for e in entries if e.action == "revoke"]
    assert all(e.subject_ref.startswith("u_") for e in revoke_entries)

    # The subject hash is deterministic (same user -> same ref) but opaque.
    refs = {e.subject_ref for e in revoke_entries}
    assert len(refs) == 1


def test_audit_scoped_per_tenant(engine, make_engine_factory):
    from privacy_telemetry.config import default_config
    engine._configs.put(default_config("tenant-b"))
    engine.query_aggregates("tenant-a", "an", "analyst")
    # tenant-b has no data, so reading it simply yields no entries, but the
    # access must still be audited under tenant-b.
    assert engine.query_aggregates("tenant-b", "an", "analyst") == []
    a_entries = engine._audit.entries("tenant-a")
    b_entries = engine._audit.entries("tenant-b")
    assert all(e.tenant_id == "tenant-a" for e in a_entries)
    assert all(e.tenant_id == "tenant-b" for e in b_entries)


def test_revoke_requires_admin(engine):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    with pytest.raises(AuthorizationError):
        engine.revoke("tenant-a", "u1", actor="sup", role="support")
    with pytest.raises(AuthorizationError):
        engine.revoke("tenant-a", "u1", actor="an", role="analyst")
    # nothing was removed
    res = engine.query_aggregates("tenant-a", "an", "analyst",
                                  request_id="still-there")
    assert res[0].value == 2.0
    denied = [e for e in engine._audit.entries("tenant-a")
              if e.action == "revoke" and not e.allowed]
    assert len(denied) == 2
    # denial audit must still not contain the raw id
    assert all("u1" not in (e.subject_ref or "") for e in denied)
