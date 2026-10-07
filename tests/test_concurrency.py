"""Concurrent aggregation and revocation must converge.

Producer threads ingest, aggregator threads fold, a revoker thread withdraws
users, all against the same engine. Interim snapshots must never show a
revoked user's residual contribution or double-counted totals, and after a
final drain the stored aggregate total exactly equals the surviving
per-user contributions.
"""
from __future__ import annotations

import threading

from privacy_telemetry.config import StaticConfigRegistry, default_config
from privacy_telemetry.models import BudgetExceededError, Event, PrivacyError


def _bucket_state(engine):
    with engine._store.transaction() as cur:
        agg = cur.execute("SELECT value, users FROM aggregates").fetchall()
        partial = cur.execute(
            "SELECT user_id, SUM(contrib) c FROM partials GROUP BY user_id"
        ).fetchall()
        revoked = {r["user_id"] for r in
                   cur.execute("SELECT user_id FROM revoked").fetchall()}
    return agg, partial, revoked


def test_concurrent_ingest_aggregate_revoke_converges(engine):
    cfg = engine._configs.get("tenant-a")
    engine._configs = StaticConfigRegistry({"tenant-a": default_config(
        "tenant-a", dimensions=("event",), window_seconds=3600,
        epsilon_budget=1_000_000.0, aggregation_cost=0.0001,
        query_cost=0.0, noise_epsilon=2.0, master_seed=cfg.master_seed)})

    n_producers = 4
    n_aggregators = 3
    start = threading.Event()
    seq_lock = threading.Lock()
    state = {"seq": 0, "errors": []}

    def producer(pid):
        start.wait()
        for i in range(40):
            uid = f"u{pid}-{i % 6}"
            with seq_lock:
                state["seq"] += 1
                eid = f"evt-{state['seq']}"
            try:
                engine.ingest([Event(
                    event_id=eid, tenant_id="tenant-a", user_id=uid,
                    ts_ms=pid * 1000 + i, attrs={"event": "click"})])
            except PrivacyError as ex:
                with seq_lock:
                    state["errors"].append(repr(ex))

    def aggregator(stop_event):
        start.wait()
        while not stop_event.is_set():
            try:
                engine.aggregate_pending("tenant-a")
            except BudgetExceededError:
                pass

    users_to_revoke = [f"u{p}-{u}" for p in range(n_producers) for u in (0, 2)]

    def revoker():
        start.wait()
        for uid in users_to_revoke:
            engine.revoke("tenant-a", uid, actor="admin", role="admin")

    producers = [threading.Thread(target=producer, args=(p,))
                 for p in range(n_producers)]
    rev = threading.Thread(target=revoker)
    work = producers + [rev]
    agg_stop = threading.Event()
    aggregators = [threading.Thread(target=aggregator, args=(agg_stop,))
                   for _ in range(n_aggregators)]

    threads = work + aggregators
    for t in threads:
        t.start()
    start.set()

    # Monitor interim snapshots while work is still ongoing.
    samples = 0
    while any(t.is_alive() for t in work):
        agg, partial, revoked = _bucket_state(engine)
        for r in partial:
            assert r["user_id"] not in revoked          # no residue
        for r in agg:
            assert float(r["value"]).is_integer()       # no double weights
            assert r["users"] >= 0
        samples += 1

    # Producers and the revoker are done: stop aggregators and do one final,
    # deterministic drain on the main thread.
    agg_stop.set()
    for t in aggregators:
        t.join(timeout=5)
        assert not t.is_alive()
    for t in work:
        t.join(timeout=5)
        assert not t.is_alive()
    assert state["errors"] == []
    assert samples > 0

    engine.aggregate_pending("tenant-a")
    assert engine.pending_count("tenant-a") == 0

    with engine._store.transaction() as cur:
        rev_rows = [r["user_id"] for r in
                    cur.execute("SELECT DISTINCT user_id FROM revoked")]
        placeholders = ",".join("?" * len(rev_rows))
        left = cur.execute(
            f"SELECT COUNT(*) n FROM partials WHERE user_id IN ({placeholders})",
            rev_rows).fetchone()["n"]
        assert left == 0
        raw_left = cur.execute(
            f"SELECT COUNT(*) n FROM raw_events WHERE user_id IN ({placeholders})",
            rev_rows).fetchone()["n"]
        assert raw_left == 0
        total_events = cur.execute(
            "SELECT COUNT(*) n FROM processed_ids").fetchone()["n"]

    agg, partial, revoked = _bucket_state(engine)
    partial_users = {r["user_id"] for r in partial}
    assert not (partial_users & revoked)
    assert sum(r["value"] for r in agg) == sum(r["c"] for r in partial)
    assert sum(r["value"] for r in agg) <= total_events
    assert set(users_to_revoke) <= revoked
