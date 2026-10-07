import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from privacy_telemetry.aggregation import Aggregator
from privacy_telemetry.api import Services, create_app
from privacy_telemetry.audit import Auditor
from privacy_telemetry.authz import Authorizer
from privacy_telemetry.budget import BudgetManager
from privacy_telemetry.consent import ConsentManager
from privacy_telemetry.models import AggregationConfig, Event
from privacy_telemetry.storage import Storage
from fastapi.testclient import TestClient


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "state.json")


@pytest.fixture
def storage(state_path):
    return Storage(state_path)


@pytest.fixture
def budget(storage):
    return BudgetManager(storage, default_limit=3.0)


@pytest.fixture
def consent(storage):
    return ConsentManager(storage)


@pytest.fixture
def aggregator(storage, budget):
    import itertools

    clock = itertools.count(100.0)
    return Aggregator(storage, budget, time_func=lambda: next(clock))


@pytest.fixture
def services(state_path):
    return Services(state_path, audit_secret="test-secret", default_budget=3.0)


@pytest.fixture
def client(services):
    return TestClient(create_app(services))


def seed_events(storage, tenant, rows):
    """rows: list of (user_id, event_type, ts, dimensions, value)."""
    with storage.lock:
        for i, (uid, etype, ts, dims, value) in enumerate(rows):
            storage.append_event(
                {
                    "tenant_id": tenant,
                    "user_id": uid,
                    "event_type": etype,
                    "timestamp": ts,
                    "dimensions": dims,
                    "value": value,
                    "event_id": f"e{i}",
                }
            )
        storage.commit()


def grant_all(consent, tenant, users):
    for u in users:
        consent.grant(tenant, u)


def config(epsilon=1.0, seed=42, dims=("os",)):
    return AggregationConfig(
        dimensions=dims,
        window_start=0.0,
        window_end=10.0,
        event_type="run",
        epsilon=epsilon,
        noise_seed=seed,
    )
