"""Core data types shared across the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ConsentState(str, Enum):
    GRANTED = "granted"
    REVOKED = "revoked"


class Role(str, Enum):
    """Access-control principals.

    - VIEWER: reads noisy aggregates only.
    - ANALYST: reads aggregates and triggers charged queries.
    - AUDITOR: reads the audit trail.
    - ADMIN: manages consent / budgets; may access protected detail
      (individual contribution vectors), never raw events.
    """

    VIEWER = "viewer"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    ADMIN = "admin"


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    role: Role


@dataclass
class Event:
    tenant_id: str
    user_id: str
    event_type: str
    timestamp: float
    dimensions: dict[str, str] = field(default_factory=dict)
    value: float = 1.0
    event_id: str = ""


@dataclass
class AggregationConfig:
    dimensions: tuple[str, ...]
    window_start: float
    window_end: float
    event_type: str
    epsilon: float = 1.0
    noise_seed: int = 0
    query_cost: float = 0.0


@dataclass
class AggregationResult:
    aggregation_id: str
    tenant_id: str
    config: AggregationConfig
    bins: dict[str, float]
    cost: float
    created_at: float
    excluded_users: frozenset[str] = frozenset()


@dataclass
class BudgetState:
    tenant_id: str
    limit: float
    consumed: float

    @property
    def remaining(self) -> float:
        return self.limit - self.consumed


@dataclass
class AuditEntry:
    seq: int
    timestamp: float
    tenant_id: str
    action: str
    resource: str
    outcome: str
    actor_role: str
    user_ref: str = ""
    detail: str = ""
