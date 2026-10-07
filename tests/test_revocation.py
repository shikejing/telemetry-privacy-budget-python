from conftest import config, grant_all, seed_events


def _rows(users, os_name="linux"):
    return [(u, "run", 1.0, {"os": os_name}, 1.0) for u in users]


def _fresh(tmp_path, users, seed):
    from privacy_telemetry.storage import Storage
    from privacy_telemetry.budget import BudgetManager
    from privacy_telemetry.consent import ConsentManager
    from privacy_telemetry.aggregation import Aggregator

    storage = Storage(str(tmp_path / f"s{seed}.json"))
    budgets = BudgetManager(storage, default_limit=100.0)
    consent = ConsentManager(storage)
    aggregator = Aggregator(storage, budgets, time_func=lambda: 100.0)
    grant_all(consent, "t", users)
    seed_events(storage, "t", _rows(users))
    return storage, consent, aggregator, aggregator.run_aggregation(
        "t", config(seed=seed)
    )


def test_revoked_result_equals_never_included(tmp_path, storage, consent, aggregator):
    users = ["u1", "u2", "u3"]
    grant_all(consent, "t", users)
    seed_events(storage, "t", _rows(users))
    result = aggregator.run_aggregation("t", config(seed=5))

    consent.revoke("t", "u3")
    adjusted = aggregator.apply_revocations("t", result.aggregation_id)

    _, _, _, baseline = _fresh(tmp_path, ["u1", "u2"], seed=5)
    assert adjusted.bins == baseline.bins
    assert "u3" in adjusted.excluded_users
    # individual vector removed
    assert storage.get_contribution("t", result.aggregation_id, "u3") is None


def test_revocation_idempotent(storage, consent, aggregator):
    grant_all(consent, "t", ["u1", "u2"])
    seed_events(storage, "t", _rows(["u1", "u2"]))
    result = aggregator.run_aggregation("t", config(seed=9))
    consent.revoke("t", "u2")
    once = aggregator.apply_revocations("t", result.aggregation_id)
    twice = aggregator.apply_revocations("t", result.aggregation_id)
    assert once.bins == twice.bins
    assert sorted(twice.excluded_users) == ["u2"]


def test_revoke_before_aggregation_excludes_user(storage, consent, aggregator):
    consent.grant("t", "u1")
    consent.grant("t", "u2")
    seed_events(storage, "t", _rows(["u1", "u2"]))
    consent.revoke("t", "u2")
    result = aggregator.run_aggregation("t", config(seed=11))
    assert storage.get_contribution("t", result.aggregation_id, "u2") is None


def test_multi_user_revocation(tmp_path, storage, consent, aggregator):
    users = ["a", "b", "c", "d"]
    grant_all(consent, "t", users)
    seed_events(
        storage,
        "t",
        [
            ("a", "run", 1.0, {"os": "linux"}, 1.0),
            ("b", "run", 1.0, {"os": "mac"}, 1.0),
            ("c", "run", 1.0, {"os": "linux"}, 1.0),
            ("d", "run", 1.0, {"os": "mac"}, 1.0),
        ],
    )
    result = aggregator.run_aggregation("t", config(seed=3))
    consent.revoke("t", "a")
    consent.revoke("t", "b")
    adjusted = aggregator.apply_revocations("t", result.aggregation_id)

    from privacy_telemetry.storage import Storage
    from privacy_telemetry.budget import BudgetManager
    from privacy_telemetry.consent import ConsentManager as CM
    from privacy_telemetry.aggregation import Aggregator as AG

    s2 = Storage(str(tmp_path / "base.json"))
    bm2 = BudgetManager(s2, default_limit=100.0)
    cm2 = CM(s2)
    grant_all(cm2, "t", ["c", "d"])
    seed_events(
        s2,
        "t",
        [
            ("c", "run", 1.0, {"os": "linux"}, 1.0),
            ("d", "run", 1.0, {"os": "mac"}, 1.0),
        ],
    )
    baseline = AG(s2, bm2, time_func=lambda: 100.0).run_aggregation(
        "t", config(seed=3)
    )
    assert adjusted.bins == baseline.bins


def test_regrant_does_not_resurrect_deleted_detail(storage, consent, aggregator):
    consent.grant("t", "u1")
    seed_events(storage, "t", _rows(["u1"]))
    result = aggregator.run_aggregation("t", config(seed=4))
    consent.revoke("t", "u1")
    aggregator.apply_revocations("t", result.aggregation_id)
    consent.grant("t", "u1")
    # no new events -> aggregate stays empty for that user
    again = aggregator.apply_revocations("t", result.aggregation_id)
    assert storage.get_contribution("t", result.aggregation_id, "u1") is None
    assert "u1" in again.excluded_users
