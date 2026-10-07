"""Aggregation, raw-detail disposal and deterministic randomization."""
from __future__ import annotations

from privacy_telemetry.models import AggregationKind, Event
from tests.conftest import click_events


def test_raw_events_deleted_after_aggregation(engine):
    engine.ingest(click_events("e", ["u1", "u2", "u3"]))
    assert engine.pending_count("tenant-a") == 3
    assert engine.aggregate_pending("tenant-a") == 3
    # The folded raw detail must not be retained.
    assert engine.pending_count("tenant-a") == 0
    kept = engine.read_raw_events("tenant-a", "sup", "support")
    assert kept == []


def test_aggregation_counts_by_dimension_and_window(engine):
    events = click_events("e", ["u1", "u1", "u2"])
    engine.ingest(events)
    engine.aggregate_pending("tenant-a")
    res = engine.query_aggregates("tenant-a", "an", "analyst")
    assert len(res) == 1
    r = res[0]
    assert r.value == 3.0
    assert r.contributing_users == 2
    assert r.window_start_ms == 0
    assert r.dimensions == {"event": "click"}


def test_window_splitting(engine, db_path):
    from privacy_telemetry.config import StaticConfigRegistry
    from privacy_telemetry.models import TenantConfig
    cfg = TenantConfig(
        tenant_id="tenant-a", dimensions=("event",), window_seconds=60,
        aggregation=AggregationKind.COUNT, epsilon_budget=5.0,
        aggregation_cost=0.1, query_cost=0.01, master_seed=1,
        noise_epsilon=2.0)
    engine._configs = StaticConfigRegistry({"tenant-a": cfg})
    engine.ingest([
        Event("a", "tenant-a", "u1", 0, attrs={"event": "click"}),
        Event("b", "tenant-a", "u1", 60_000, attrs={"event": "click"}),
    ])
    engine.aggregate_pending("tenant-a")
    res = engine.query_aggregates("tenant-a", "an", "analyst")
    windows = sorted(r.window_start_ms for r in res)
    assert windows == [0, 60_000]


def test_noise_is_seeded_and_reproducible(engine):
    engine.ingest(click_events("e", ["u1", "u2"]))
    engine.aggregate_pending("tenant-a")
    first = engine.query_aggregates("tenant-a", "an", "analyst")
    second = engine.query_aggregates("tenant-a", "an", "analyst")
    assert [r.noise for r in first] == [r.noise for r in second]
    assert [r.noisy_value for r in first] == [r.noisy_value for r in second]
    # Noise genuinely perturbs the result (with overwhelming probability).
    assert all(r.noise != 0.0 for r in first)


def test_same_input_same_result_across_reprocessing(engine, make_engine_factory):
    events = click_events("e", ["u1", "u2", "u3"])
    engine.ingest(events)
    engine.aggregate_pending("tenant-a")
    a = engine.query_aggregates("tenant-a", "an", "analyst")

    # A fresh process on the same database must publish identical numbers.
    restarted = make_engine_factory()
    b = restarted.query_aggregates("tenant-a", "an", "analyst")
    assert [r.noisy_value for r in a] == [r.noisy_value for r in b]
    restarted.close()


def test_sum_aggregation(engine):
    from privacy_telemetry.config import StaticConfigRegistry
    from privacy_telemetry.models import TenantConfig
    cfg = TenantConfig(
        tenant_id="tenant-a", dimensions=("event",), window_seconds=60,
        aggregation=AggregationKind.SUM, epsilon_budget=5.0,
        aggregation_cost=0.1, query_cost=0.01, master_seed=1,
        noise_epsilon=2.0)
    engine._configs = StaticConfigRegistry({"tenant-a": cfg})
    engine.ingest([
        Event("a", "tenant-a", "u1", 0, value=4.0, attrs={"event": "ms"}),
        Event("b", "tenant-a", "u2", 0, value=6.0, attrs={"event": "ms"}),
    ])
    engine.aggregate_pending("tenant-a")
    r = engine.query_aggregates("tenant-a", "an", "analyst")[0]
    assert r.value == 10.0
    assert r.contributing_users == 2
