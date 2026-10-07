"""Shared fixtures: an isolated engine backed by a temporary database."""
from __future__ import annotations

import pytest

from privacy_telemetry.audit import AuditLog
from privacy_telemetry.config import StaticConfigRegistry, default_config
from privacy_telemetry.engine import PrivacyEngine
from privacy_telemetry.models import Event
from privacy_telemetry.storage import Storage


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "privacy.db")


def make_engine(db_path: str, **cfg_over) -> PrivacyEngine:
    store = Storage(db_path)
    defaults = {
        "dimensions": ("event",),
        "window_seconds": 60,
        "epsilon_budget": 1.0,
        "aggregation_cost": 0.3,
        "query_cost": 0.05,
        "noise_epsilon": 2.0,
        "master_seed": 99,
    }
    defaults.update(cfg_over)
    cfg = default_config("tenant-a", **defaults)
    registry = StaticConfigRegistry({"tenant-a": cfg})
    return PrivacyEngine(store, registry, AuditLog(store))


@pytest.fixture
def engine(db_path):
    eng = make_engine(
        db_path,
        dimensions=("event",),
        window_seconds=60,
        epsilon_budget=1.0,
        aggregation_cost=0.3,
        query_cost=0.05,
        noise_epsilon=2.0,
        master_seed=99,
    )
    yield eng
    eng.close()


def click_events(prefix: str, users, ts_base: int = 0) -> list[Event]:
    out: list[Event] = []
    for i, u in enumerate(users):
        out.append(Event(
            event_id=f"{prefix}-{i}", tenant_id="tenant-a", user_id=u,
            ts_ms=ts_base + i * 1000, attrs={"event": "click"},
        ))
    return out


@pytest.fixture
def make_engine_factory(db_path):
    """Return a factory that re-opens the same database (restart tests)."""
    def factory(**over):
        return make_engine(db_path, dimensions=("event",), window_seconds=60,
                           epsilon_budget=over.pop("epsilon_budget", 1.0),
                           aggregation_cost=over.pop("aggregation_cost", 0.3),
                           query_cost=over.pop("query_cost", 0.05),
                           noise_epsilon=over.pop("noise_epsilon", 2.0),
                           master_seed=over.pop("master_seed", 99), **over)
    return factory
