"""Durability: restart resumes from the committed position exactly once."""
from __future__ import annotations

from tests.conftest import click_events, make_engine


def test_restart_resumes_without_reprocessing(engine, db_path):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    consumed_before = engine.budget_status("tenant-a").consumed
    pending_before = engine.pending_count("tenant-a")
    engine.close()

    restarted = make_engine(db_path)
    # No folded events remain, and an extra run charges nothing / changes
    # nothing: the committed checkpoint means nothing is reprocessed.
    assert restarted.aggregate_pending("tenant-a") == 0
    assert restarted.pending_count("tenant-a") == pending_before == 0
    assert restarted.budget_status("tenant-a").consumed == consumed_before
    restarted.close()


def test_restart_recovers_pending_events(engine, db_path):
    # Events ingested but never aggregated survive a restart and are folded
    # afterward, charging exactly once.
    engine.ingest(click_events("a", ["u1", "u2", "u3"]))
    engine.close()

    restarted = make_engine(db_path)
    assert restarted.pending_count("tenant-a") == 3
    assert restarted.aggregate_pending("tenant-a") == 3
    assert restarted.budget_status("tenant-a").consumed == 0.3
    assert restarted.aggregate_pending("tenant-a") == 0
    assert restarted.budget_status("tenant-a").consumed == 0.3
    restarted.close()


def test_revocation_state_survives_restart(engine, db_path):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    engine.revoke("tenant-a", "u1", actor="admin", role="admin")
    engine.close()

    restarted = make_engine(db_path)
    # A late event from the revoked user must still be rejected post-restart.
    restarted.ingest(click_events("late", ["u1", "u2"]))
    restarted.aggregate_pending("tenant-a")
    res = restarted.query_aggregates("tenant-a", "an", "analyst",
                                     request_id="post-restart")
    assert len(res) == 1
    # only u2 survives: one from the first batch + one late = 2
    assert res[0].value == 2.0
    assert res[0].contributing_users == 1
    restarted.close()


def test_revoked_deletion_not_repeated_after_restart(engine, db_path):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    engine.revoke("tenant-a", "u1", actor="admin", role="admin")
    engine.close()

    restarted = make_engine(db_path)
    # Second revoke is an idempotent no-op (0 buckets) and does not resurface
    # any data or double-delete.
    assert restarted.revoke("tenant-a", "u1", actor="admin",
                            role="admin") == 0
    res = restarted.query_aggregates("tenant-a", "an", "analyst",
                                     request_id="idempotent")
    assert res[0].value == 1.0 and res[0].contributing_users == 1
    restarted.close()


def test_budget_ledger_survives_restart(engine, db_path):
    engine.ingest(click_events("a", ["u1"]))
    engine.aggregate_pending("tenant-a")
    engine.query_aggregates("tenant-a", "an", "analyst", request_id="q1")
    engine.close()
    restarted = make_engine(db_path)
    st = restarted.budget_status("tenant-a")
    assert st.consumed == 0.35 and st.remaining == 0.65
    # retrying the same idempotent request after restart charges nothing more
    restarted.query_aggregates("tenant-a", "an", "analyst", request_id="q1")
    assert restarted.budget_status("tenant-a").consumed == 0.35
    restarted.close()
