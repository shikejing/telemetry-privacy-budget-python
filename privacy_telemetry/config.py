"""Tenant configuration registry.

A :class:`TenantConfig` describes, per tenant, which event attributes are
aggregated as dimensions, the tumbling time window, the aggregation kind,
the total privacy budget (epsilon) and the per-action cost, plus the master
seed that drives all deterministic randomization.
"""
from __future__ import annotations

import threading

from .models import AggregationKind, TenantConfig, UnknownTenantError


class ConfigRegistry:
    def get(self, tenant_id: str) -> TenantConfig:
        raise NotImplementedError

    def put(self, cfg: TenantConfig) -> None:
        raise NotImplementedError


class StaticConfigRegistry(ConfigRegistry):
    """In-memory registry. Put is thread-safe; configs are append/replace."""

    def __init__(self, configs: dict[str, TenantConfig] | None = None) -> None:
        self._configs: dict[str, TenantConfig] = dict(configs or {})
        self._lock = threading.RLock()

    def get(self, tenant_id: str) -> TenantConfig:
        with self._lock:
            try:
                return self._configs[tenant_id]
            except KeyError:
                raise UnknownTenantError(f"unknown tenant: {tenant_id}") from None

    def put(self, cfg: TenantConfig) -> None:
        if cfg.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if cfg.epsilon_budget < 0 or cfg.aggregation_cost < 0 or cfg.query_cost < 0:
            raise ValueError("budgets and costs must be non-negative")
        with self._lock:
            self._configs[cfg.tenant_id] = cfg

    def all_tenant_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._configs)


def default_config(
    tenant_id: str,
    *,
    dimensions: tuple[str, ...] = ("event",),
    window_seconds: int = 60,
    aggregation: AggregationKind = AggregationKind.COUNT,
    epsilon_budget: float = 2.0,
    aggregation_cost: float = 0.5,
    query_cost: float = 0.1,
    master_seed: int = 0,
    noise_epsilon: float = 1.0,
) -> TenantConfig:
    return TenantConfig(
        tenant_id=tenant_id,
        dimensions=tuple(dimensions),
        window_seconds=window_seconds,
        aggregation=aggregation,
        epsilon_budget=epsilon_budget,
        aggregation_cost=aggregation_cost,
        query_cost=query_cost,
        master_seed=master_seed,
        noise_epsilon=noise_epsilon,
    )
