"""Consent withdrawal: contributions removed as if never included."""
from __future__ import annotations

from tests.conftest import click_events, make_engine


def _totals(engine, request_id):
    res = engine.query_aggregates("tenant-a", "an", "analyst",
                                  request_id=request_id)
    return {(r.window_start_ms, tuple(sorted(r.dimensions.items()))):
            (r.value, r.contributing_users) for r in res}


def test_revocation_equivalent_to_never_included(engine, tmp_path):
    # Engine A: everyone included, then u1 revoked.
    engine.ingest(click_events("inc", ["u1", "u2", "u3", "u1"]))
    engine.aggregate_pending("tenant-a")
    engine.revoke("tenant-a", "u1", actor="admin", role="admin")

    # Reference engine on a *separate* database: u1 never present.
    ref = make_engine(str(tmp_path / "ref.db"), epsilon_budget=5.0)
    ref.ingest(click_events("ref", ["u2", "u3"]))
    ref.aggregate_pending("tenant-a")
    got = _totals(engine, "a")
    expected = _totals(ref, "b")
    assert got == expected
    assert got == {(0, (("event", "click"),)): (2.0, 2)}
    ref.close()


def test_revocation_removes_all_traces(engine):
    engine.ingest(click_events("inc", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    engine.revoke("tenant-a", "u1", actor="admin", role="admin")
    with engine._store.transaction() as cur:
        n_raw = cur.execute(
            "SELECT COUNT(*) n FROM raw_events WHERE user_id='u1'").fetchone()["n"]
        n_part = cur.execute(
            "SELECT COUNT(*) n FROM partials WHERE user_id='u1'").fetchone()["n"]
        n_tomb = cur.execute(
            "SELECT COUNT(*) n FROM processed_ids WHERE user_id='u1'").fetchone()["n"]
        revoked = cur.execute(
            "SELECT COUNT(*) n FROM revoked WHERE user_id='u1'").fetchone()["n"]
    assert (n_raw, n_part, n_tomb) == (0, 0, 0)
    assert revoked == 1  # only the revocation marker remains


def test_revocation_idempotent(engine):
    engine.ingest(click_events("inc", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    first = engine.revoke("tenant-a", "u2", actor="admin", role="admin")
    second = engine.revoke("tenant-a", "u2", actor="admin", role="admin")
    assert first == 1 and second == 0
    totals = _totals(engine, "r")
    assert totals == {(0, (("event", "click"),)): (1.0, 1)}


def test_events_from_revoked_user_are_not_aggregated(engine):
    engine.revoke("tenant-a", "gone", actor="admin", role="admin")
    engine.ingest(click_events("late", ["gone", "kept"]))
    folded = engine.aggregate_pending("tenant-a")
    # revoked user's late event is dropped, not folded
    assert folded == 2
    totals = _totals(engine, "x")
    assert totals == {(0, (("event", "click"),)): (1.0, 1)}


def test_revocation_before_aggregation(engine, make_engine_factory):
    engine.ingest(click_events("pre", ["u1", "u2"]))
    engine.revoke("tenant-a", "u1", actor="admin", role="admin")
    engine.aggregate_pending("tenant-a")
    totals = _totals(engine, "p")
    assert totals == {(0, (("event", "click"),)): (1.0, 1)}
