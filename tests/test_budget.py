import pytest

from privacy_telemetry.errors import BudgetExceededError
from privacy_telemetry.models import AggregationConfig
from conftest import config, grant_all, seed_events


def test_budget_charged_monotonic_and_queryable(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    aggregator.run_aggregation("t", config(epsilon=1.0))
    assert budget.state("t").consumed == 1.0
    aggregator.run_aggregation("t", config(epsilon=2.0, seed=7))
    assert budget.state("t").consumed == 1.5
    assert budget.state("t").remaining == 1.5


def test_over_budget_aggregation_rejected(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    with pytest.raises(BudgetExceededError):
        aggregator.run_aggregation("t", config(epsilon=0.2))  # cost 5.0 > 3.0
    # rejection must not consume budget
    assert budget.state("t").consumed == 0.0


def test_over_budget_query_rejected(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    cfg = AggregationConfig(
        dimensions=("os",), window_start=0, window_end=10, event_type="run",
        epsilon=1.0, noise_seed=1, query_cost=5.0,
    )
    aggregator.run_aggregation("t", cfg)
    with pytest.raises(BudgetExceededError):
        aggregator.query("t", None) if False else aggregator.query(
            "t", aggregator.list("t")[0].aggregation_id
        )
    assert budget.state("t").consumed == 1.0


def test_query_idempotent_charges_once(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    cfg = AggregationConfig(
        dimensions=("os",), window_start=0, window_end=10, event_type="run",
        epsilon=1.0, noise_seed=1, query_cost=0.5,
    )
    aggregator.run_aggregation("t", cfg)
    aid = aggregator.list("t")[0].aggregation_id
    aggregator.query("t", aid, idem_key="q1")
    aggregator.query("t", aid, idem_key="q1")
    assert budget.state("t").consumed == 1.5


def test_tenants_have_independent_budgets(storage, consent, aggregator, budget):
    grant_all(consent, "tA", ["u1"])
    grant_all(consent, "tB", ["u1"])
    seed_events(storage, "tA", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    seed_events(storage, "tB", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    aggregator.run_aggregation("tA", config(seed=1))
    assert budget.state("tA").consumed == 1.0
    assert budget.state("tB").consumed == 0.0


def test_revocation_does_not_charge(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", [("u1", "run", 1.0, {"os": "linux"}, 1.0)])
    result = aggregator.run_aggregation("t", config())
    consent.revoke("t", "u1")
    aggregator.apply_revocations("t", result.aggregation_id)
    assert budget.state("t").consumed == 1.0
