"""Crash atomicity: a failure mid-aggregation rolls the whole txn back."""
from __future__ import annotations

import pytest

from privacy_telemetry import storage as storage_mod
from tests.conftest import click_events


class InjectedFailure(RuntimeError):
    pass


def test_failure_after_budget_insert_charges_nothing(engine, monkeypatch):
    engine.ingest(click_events("a", ["u1", "u2"]))
    consumed0 = engine.budget_status("tenant-a").consumed

    calls = {"n": 0}
    real_upsert = storage_mod.Storage.upsert_partial

    def boom(cur, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise InjectedFailure("disk goes away mid-fold")
        return real_upsert(cur, *args, **kwargs)

    monkeypatch.setattr(storage_mod.Storage, "upsert_partial", boom)
    with pytest.raises(InjectedFailure):
        engine.aggregate_pending("tenant-a")
    monkeypatch.undo()

    # Whole transaction rolled back: no charge, no lost raw events, no
    # half-written partial state.
    assert engine.budget_status("tenant-a").consumed == consumed0
    assert engine.pending_count("tenant-a") == 2
    with engine._store.transaction() as cur:
        n_partials = cur.execute("SELECT COUNT(*) n FROM partials").fetchone()["n"]
    assert n_partials == 0

    # Retrying the failed run succeeds exactly once.
    assert engine.aggregate_pending("tenant-a") == 2
    assert engine.budget_status("tenant-a").consumed == pytest.approx(0.3)
    assert engine.pending_count("tenant-a") == 0


def test_failure_during_revoke_leaves_consistent_state(engine, monkeypatch):
    engine.ingest(click_events("a", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")

    def boom(cur, cfg, start, key, dims_json, update_seq):
        raise InjectedFailure("crash while re-deriving bucket")

    monkeypatch.setattr(engine, "_recompute", boom)
    with pytest.raises(InjectedFailure):
        engine.revoke("tenant-a", "u1", actor="root", role="admin")
    monkeypatch.undo()

    # Rollback: user is NOT marked revoked, contribution still present,
    # aggregate unchanged - the operation can be retried cleanly.
    with engine._store.transaction() as cur:
        revoked = cur.execute(
            "SELECT COUNT(*) n FROM revoked WHERE user_id='u1'").fetchone()["n"]
        partials_u1 = cur.execute(
            "SELECT COUNT(*) n FROM partials WHERE user_id='u1'").fetchone()["n"]
        agg = cur.execute("SELECT value, users FROM aggregates").fetchone()
    assert revoked == 0 and partials_u1 == 1
    assert agg["value"] == 2 and agg["users"] == 2

    # The user is not revoked, so audit should not show a successful revoke.
    success = [e for e in engine._audit.entries("tenant-a")
               if e.action == "revoke" and e.allowed]
    assert success == []

    # Retry now converges to the revoked state.
    assert engine.revoke("tenant-a", "u1", actor="root", role="admin") == 1
    with engine._store.transaction() as cur:
        agg = cur.execute("SELECT value, users FROM aggregates").fetchone()
    assert agg["value"] == 1 and agg["users"] == 1
