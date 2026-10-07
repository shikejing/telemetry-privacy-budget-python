"""Tenant isolation: ids, budgets, revocation and audit are per-tenant."""
from __future__ import annotations

from privacy_telemetry.config import StaticConfigRegistry, default_config
from privacy_telemetry.models import Event


def _engine_two_tenants(engine):
    engine._configs = StaticConfigRegistry({
        "tenant-a": default_config(
            "tenant-a", epsilon_budget=1.0, aggregation_cost=0.2,
            query_cost=0.05, master_seed=1),
        "tenant-b": default_config(
            "tenant-b", epsilon_budget=0.3, aggregation_cost=0.2,
            query_cost=0.05, master_seed=2),
    })
    return engine


def test_same_event_id_in_two_tenants_both_accepted(engine):
    _engine_two_tenants(engine)
    assert engine.ingest([Event("dup-1", "tenant-a", "u1", 0,
                                attrs={"event": "click"})]) == 1
    assert engine.ingest([Event("dup-1", "tenant-b", "v1", 0,
                                attrs={"event": "click"})]) == 1
    assert engine.pending_count("tenant-a") == 1
    assert engine.pending_count("tenant-b") == 1


def test_budgets_are_independent(engine):
    _engine_two_tenants(engine)
    engine.ingest([Event("a1", "tenant-a", "u1", 0,
                         attrs={"event": "click"})])
    engine.ingest([Event("b1", "tenant-b", "v1", 0,
                         attrs={"event": "click"})])
    engine.aggregate_pending("tenant-a")  # a: 0.2/1.0
    engine.aggregate_pending("tenant-b")  # b: 0.2/0.3
    assert engine.budget_status("tenant-a").consumed == 0.2
    assert engine.budget_status("tenant-b").consumed == 0.2

    # b is nearly exhausted while a is not: the other tenant is unaffected.
    engine.query_aggregates("tenant-b", "an", "analyst")  # b -> 0.25
    engine.query_aggregates("tenant-b", "an", "analyst")  # b -> 0.30
    assert engine.query_aggregates("tenant-a", "an", "analyst",
                                   request_id="a-ok")  # still allowed


def test_revocation_scoped_to_tenant(engine):
    _engine_two_tenants(engine)
    # same user id present in both tenants
    engine.ingest([Event("s1", "tenant-a", "shared", 0,
                         attrs={"event": "click"}),
                   Event("s2", "tenant-a", "other", 0,
                         attrs={"event": "click"})])
    engine.ingest([Event("s3", "tenant-b", "shared", 0,
                         attrs={"event": "click"})])
    engine.aggregate_pending("tenant-a")
    engine.aggregate_pending("tenant-b")
    engine.revoke("tenant-a", "shared", actor="root", role="admin")

    a = engine.query_aggregates("tenant-a", "an", "analyst",
                                request_id="a")
    b = engine.query_aggregates("tenant-b", "an", "analyst",
                                request_id="b")
    assert a[0].value == 1.0 and a[0].contributing_users == 1
    assert b[0].value == 1.0  # tenant-b's "shared" untouched
