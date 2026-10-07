"""Privacy-preserving telemetry aggregation pipeline.

Modules:
    config   - tenant configuration (dimensions, windows, budgets)
    models   - domain types and dataclasses
    storage  - durable SQLite-backed storage
    budget   - per-tenant monotonic privacy-budget ledger
    noise    - seeded, reproducible randomization
    engine   - aggregation / revocation / query service
    audit    - redacted audit logging and access roles
    api      - FastAPI HTTP surface
"""

__all__ = [
    "api",
    "audit",
    "budget",
    "config",
    "engine",
    "models",
    "noise",
    "storage",
]
