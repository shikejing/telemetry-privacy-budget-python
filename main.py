"""Service entry point: wires the privacy pipeline to the FastAPI app.

Configuration via environment variables:
    PRIVACY_DB_PATH       SQLite file (default: ./data/privacy.db)
    PRIVACY_TENANT_ID     single default tenant id (default: default)
    PRIVACY_DIMENSIONS    comma-separated dimension attribute names
    PRIVACY_WINDOW_SECONDS, PRIVACY_EPSILON_BUDGET,
    PRIVACY_AGG_COST, PRIVACY_QUERY_COST, PRIVACY_NOISE_EPSILON,
    PRIVACY_MASTER_SEED
"""
from __future__ import annotations

import os

import uvicorn

from privacy_telemetry.api import create_app
from privacy_telemetry.audit import AuditLog
from privacy_telemetry.config import StaticConfigRegistry, default_config
from privacy_telemetry.engine import PrivacyEngine
from privacy_telemetry.models import AggregationKind
from privacy_telemetry.storage import Storage


def build_engine(db_path: str | None = None) -> PrivacyEngine:
    db_path = db_path or os.environ.get(
        "PRIVACY_DB_PATH", os.path.join("data", "privacy.db"))
    directory = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(directory, exist_ok=True)
    store = Storage(db_path)
    tenant_id = os.environ.get("PRIVACY_TENANT_ID", "default")
    dims = tuple(d.strip() for d in os.environ.get(
        "PRIVACY_DIMENSIONS", "event").split(",") if d.strip())
    cfg = default_config(
        tenant_id,
        dimensions=dims,
        window_seconds=int(os.environ.get("PRIVACY_WINDOW_SECONDS", "60")),
        aggregation=AggregationKind.COUNT,
        epsilon_budget=float(os.environ.get("PRIVACY_EPSILON_BUDGET", "2.0")),
        aggregation_cost=float(os.environ.get("PRIVACY_AGG_COST", "0.5")),
        query_cost=float(os.environ.get("PRIVACY_QUERY_COST", "0.05")),
        noise_epsilon=float(os.environ.get("PRIVACY_NOISE_EPSILON", "1.0")),
        master_seed=int(os.environ.get("PRIVACY_MASTER_SEED", "0")),
    )
    registry = StaticConfigRegistry({tenant_id: cfg})
    return PrivacyEngine(store, registry, AuditLog(store))


app = create_app(build_engine())


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
