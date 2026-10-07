"""End-to-end scenario chaining budget overrun, revocation and restart."""
from __future__ import annotations

import pytest

from privacy_telemetry.models import BudgetExceededError, Event
from tests.conftest import make_engine


def test_privacy_lifecycle_scenario(db_path):
    eng = make_engine(db_path, epsilon_budget=1.0, aggregation_cost=0.4,
                      query_cost=0.1)
    # 1) ingest and aggregate two windows of events
    eng.ingest([
        Event("s1", "tenant-a", "u1", 0, attrs={"event": "click"}),
        Event("s2", "tenant-a", "u2", 0, attrs={"event": "click"}),
        Event("s3", "tenant-a", "u3", 0, attrs={"event": "click"}),
    ])
    assert eng.aggregate_pending("tenant-a") == 3            # 0.4 charged
    published = eng.query_aggregates("tenant-a", "an", "analyst")  # 0.1
    assert published[0].value == 3.0

    # 2) budget overrun: aggregation and queries are refused, not passed
    #    consumed is 0.5 (0.4 aggregation + 0.1 query).
    eng.ingest([Event("s4", "tenant-a", "u1", 60_000,
                      attrs={"event": "click"})])
    assert eng.aggregate_pending("tenant-a") == 1            # -> 0.9
    eng.ingest([Event("s5", "tenant-a", "u2", 120_000,
                      attrs={"event": "click"})])
    with pytest.raises(BudgetExceededError):
        eng.aggregate_pending("tenant-a")                    # would be 1.3
    # queries over the remaining 0.1: exactly one succeeds, next refused
    eng.query_aggregates("tenant-a", "an", "analyst")        # -> 1.0
    with pytest.raises(BudgetExceededError):
        eng.query_aggregates("tenant-a", "an", "analyst")
    assert eng.pending_count("tenant-a") == 1  # rejected input untouched

    # 3) restart: budget ledger and checkpoint survive, no double deduction
    eng.close()
    restarted = make_engine(db_path, epsilon_budget=1.0,
                            aggregation_cost=0.4, query_cost=0.1)
    assert restarted.budget_status("tenant-a").consumed == pytest.approx(1.0)
    # Already-folded windows are not reprocessed: only the one previously
    # rejected event is still pending, and at the budget cap it is rejected
    # again rather than silently passing or double-charging.
    assert restarted.pending_count("tenant-a") == 1
    with pytest.raises(BudgetExceededError):
        restarted.aggregate_pending("tenant-a")
    assert restarted.budget_status("tenant-a").consumed == pytest.approx(1.0)
    assert restarted.pending_count("tenant-a") == 1

    # 4) revocation still works on the restarted process and is idempotent
    changed = restarted.revoke("tenant-a", "u3", actor="root", role="admin")
    assert changed == 1
    assert restarted.revoke("tenant-a", "u3", actor="root",
                            role="admin") == 0
    with restarted._store.transaction() as cur:
        survivors = cur.execute(
            "SELECT value, users FROM aggregates "
            "ORDER BY window_start_ms").fetchall()
    first = survivors[0]
    # window 0 had u1,u2,u3 counts 1 each; after revoking u3 -> 2 users/2
    assert first["value"] == 2.0 and first["users"] == 2
    restarted.close()
