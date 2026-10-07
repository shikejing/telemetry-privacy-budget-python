"""Privacy-budget enforcement: queryable, monotonic, never silently passed."""
from __future__ import annotations

import pytest

from privacy_telemetry.models import BudgetExceededError
from tests.conftest import click_events


def test_budget_queryable_and_monotonic(engine):
    statuses = [engine.budget_status("tenant-a").consumed]
    engine.ingest(click_events("b1", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    statuses.append(engine.budget_status("tenant-a").consumed)
    engine.query_aggregates("tenant-a", "an", "analyst")
    statuses.append(engine.budget_status("tenant-a").consumed)
    assert statuses == sorted(statuses)
    assert statuses == [0.0, pytest.approx(0.3), pytest.approx(0.35)]
    assert engine.budget_status("tenant-a").remaining == pytest.approx(0.65)


def test_aggregation_rejected_when_budget_exhausted(engine):
    # aggregation costs 0.3; three runs would exceed 1.0 -> third rejected.
    for batch in range(3):
        engine.ingest(click_events(f"b{batch}", ["u1"]))
        if batch < 3:
            engine.aggregate_pending("tenant-a")
    engine.ingest(click_events("b3", ["u1"]))
    before = engine.budget_status("tenant-a").consumed
    with pytest.raises(BudgetExceededError):
        engine.aggregate_pending("tenant-a")
    # Rejected run leaves state untouched: events still pending, no charge.
    assert engine.budget_status("tenant-a").consumed == pytest.approx(before)
    assert engine.pending_count("tenant-a") == 1


def test_query_rejected_when_budget_exhausted(engine):
    engine.ingest(click_events("b", ["u1"]))
    engine.aggregate_pending("tenant-a")  # 0.3
    for _ in range(14):  # 14 * 0.05 = 0.7 -> total 1.0
        engine.query_aggregates("tenant-a", "an", "analyst")
    with pytest.raises(BudgetExceededError):
        engine.query_aggregates("tenant-a", "an", "analyst")
    # Exactly at the limit boundary the monotonic total is unchanged.
    assert engine.budget_status("tenant-a").consumed == pytest.approx(1.0)


def test_query_request_id_is_idempotent(engine):
    engine.ingest(click_events("b", ["u1"]))
    engine.aggregate_pending("tenant-a")
    r1 = engine.query_aggregates("tenant-a", "an", "analyst",
                                 request_id="read-1")
    r2 = engine.query_aggregates("tenant-a", "an", "analyst",
                                 request_id="read-1")
    assert r1 == r2
    # Retried request deducts only once.
    assert engine.budget_status("tenant-a").consumed == pytest.approx(0.35)


def test_rejection_audited(engine):
    engine.ingest(click_events("b", ["u1"]))
    engine.aggregate_pending("tenant-a")
    for _ in range(14):
        engine.query_aggregates("tenant-a", "an", "analyst")
    with pytest.raises(BudgetExceededError):
        engine.query_aggregates("tenant-a", "an", "analyst")
    denied = [e for e in engine._audit.entries("tenant-a")
              if e.action == "aggregate_read" and not e.allowed]
    assert len(denied) == 1
