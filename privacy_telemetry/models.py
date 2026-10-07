"""Domain types for the privacy aggregation pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AggregationKind(str, Enum):
    COUNT = "count"
    SUM = "sum"


class AccessRole(str, Enum):
    ANALYST = "analyst"        # may read noisy aggregates
    SUPPORT = "support"        # may read raw detail within own tenant
    ADMIN = "admin"            # may manage budgets/config, read aggregates


@dataclass(frozen=True)
class Dimension:
    name: str


@dataclass(frozen=True)
class TenantConfig:
    tenant_id: str
    dimensions: tuple[str, ...]
    window_seconds: int
    aggregation: AggregationKind
    epsilon_budget: float
    aggregation_cost: float
    query_cost: float
    master_seed: int
    noise_epsilon: float = 1.0


@dataclass(frozen=True)
class Event:
    event_id: str
    tenant_id: str
    user_id: str
    ts_ms: int
    value: float = 0.0
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BucketKey:
    tenant_id: str
    window_start_ms: int
    dimensions: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class AggregateResult:
    tenant_id: str
    window_start_ms: int
    dimensions: dict[str, str]
    contributing_users: int
    value: float
    noise: float
    noisy_value: float
    budget_consumed: float


@dataclass(frozen=True)
class BudgetStatus:
    tenant_id: str
    consumed: float
    limit: float

    @property
    def remaining(self) -> float:
        return self.limit - self.consumed


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts_ms: int
    tenant_id: str
    actor: str
    role: str
    action: str
    allowed: bool
    subject_ref: str


class PrivacyError(Exception):
    """Base error for pipeline policy failures."""


class BudgetExceededError(PrivacyError):
    pass


class AuthorizationError(PrivacyError):
    pass


class UnknownTenantError(PrivacyError):
    pass
