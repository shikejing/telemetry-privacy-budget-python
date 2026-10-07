from privacy_telemetry.aggregation import Aggregator
from privacy_telemetry.api import Services, create_app
from privacy_telemetry.budget import BudgetManager
from privacy_telemetry.consent import ConsentManager
from privacy_telemetry.storage import Storage
from conftest import config, grant_all, seed_events


def _rows(users):
    return [(u, "run", 1.0, {"os": "linux"}, 1.0) for u in users]


def test_state_survives_restart(state_path):
    s1 = Storage(state_path)
    bm1 = BudgetManager(s1, default_limit=5.0)
    cm1 = ConsentManager(s1)
    ag1 = Aggregator(s1, bm1)
    grant_all(cm1, "t", ["u1", "u2"])
    seed_events(s1, "t", _rows(["u1", "u2"]))
    result = ag1.run_aggregation("t", config(seed=5))
    bins_before = result.bins
    consumed_before = bm1.state("t").consumed

    # simulate process restart: new objects over the same file
    s2 = Storage(state_path)
    bm2 = BudgetManager(s2, default_limit=5.0)
    cm2 = ConsentManager(s2)
    ag2 = Aggregator(s2, bm2)

    assert bm2.state("t").consumed == consumed_before
    restarted = ag2.get("t", result.aggregation_id)
    assert restarted.bins == bins_before
    # raw events remain deleted after restart
    assert s2.events_for_window("t", "run", 0, 10) == []
    # rerunning the same config replays and does not recharge
    again = ag2.run_aggregation("t", config(seed=5))
    assert again.bins == bins_before
    assert bm2.state("t").consumed == consumed_before
    assert cm2.is_granted("t", "u1")


def test_revocation_resumes_after_restart(state_path):
    s1 = Storage(state_path)
    bm1 = BudgetManager(s1, default_limit=10.0)
    cm1 = ConsentManager(s1)
    ag1 = Aggregator(s1, bm1)
    grant_all(cm1, "t", ["u1", "u2", "u3"])
    seed_events(s1, "t", _rows(["u1", "u2", "u3"]))
    result = ag1.run_aggregation("t", config(seed=8))

    # revoke + ledger persisted, but imagine apply_revocations had not run;
    # the Services recovery hook must finish the propagation.
    cm1.revoke("t", "u3")
    consumed = bm1.state("t").consumed

    services = Services(state_path, default_budget=10.0)  # runs recovery
    adjusted = services.aggregator.get("t", result.aggregation_id)
    assert "u3" in adjusted.excluded_users

    # explicit re-application is a no-op: no double subtraction, no charge
    again = services.aggregator.apply_revocations("t", result.aggregation_id)
    assert again.bins == adjusted.bins
    assert services.budgets.state("t").consumed == consumed
    assert (
        services.storage.get_contribution("t", result.aggregation_id, "u3")
        is None
    )


def test_revoked_then_restart_matches_never_included(tmp_path, state_path):
    s1 = Storage(state_path)
    bm1 = BudgetManager(s1, default_limit=10.0)
    cm1 = ConsentManager(s1)
    ag1 = Aggregator(s1, bm1, time_func=lambda: 100.0)
    grant_all(cm1, "t", ["u1", "u2", "u3"])
    seed_events(s1, "t", _rows(["u1", "u2", "u3"]))
    result = ag1.run_aggregation("t", config(seed=13))
    cm1.revoke("t", "u3")
    ag1.apply_revocations("t", result.aggregation_id)

    # restart
    services = Services(state_path, default_budget=10.0)
    restarted = services.aggregator.get("t", result.aggregation_id)

    # never-included baseline
    base_path = str(tmp_path / "base.json")
    sb = Storage(base_path)
    bmb = BudgetManager(sb, default_limit=10.0)
    cmb = ConsentManager(sb)
    agb = Aggregator(sb, bmb, time_func=lambda: 100.0)
    grant_all(cmb, "t", ["u1", "u2"])
    seed_events(sb, "t", _rows(["u1", "u2"]))
    baseline = agb.run_aggregation("t", config(seed=13))

    assert restarted.bins == baseline.bins
