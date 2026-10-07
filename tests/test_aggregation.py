from conftest import config, grant_all, seed_events


def _rows(users):
    return [
        (u, "run", 1.0, {"os": "linux"}, 1.0) for u in users
    ]


def test_raw_events_deleted_after_aggregation(storage, consent, aggregator):
    grant_all(consent, "t", ["u1", "u2"])
    seed_events(storage, "t", _rows(["u1", "u2"]))
    aggregator.run_aggregation("t", config())
    assert storage.events_for_window("t", "run", 0, 10) == []


def test_same_config_replays_without_recharge(storage, consent, aggregator, budget):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", _rows(["u1"]))
    first = aggregator.run_aggregation("t", config(), idem_key="k1")
    second = aggregator.run_aggregation("t", config(), idem_key="k2")
    assert first.aggregation_id == second.aggregation_id
    assert first.bins == second.bins
    assert budget.state("t").consumed == 1.0  # charged once


def test_idempotency_key_returns_same_result(storage, consent, aggregator):
    grant_all(consent, "t", ["u1"])
    seed_events(storage, "t", _rows(["u1"]))
    a = aggregator.run_aggregation("t", config(), idem_key="client-abc")
    b = aggregator.run_aggregation("t", config(), idem_key="client-abc")
    assert a.bins == b.bins and a.aggregation_id == b.aggregation_id


def test_seed_drives_randomization(storage, consent, aggregator):
    many = [f"u{i}" for i in range(40)]
    grant_all(consent, "t", many)
    seed_events(storage, "t", _rows(many))
    a = aggregator.run_aggregation("t", config(seed=1))
    from privacy_telemetry.storage import Storage
    from privacy_telemetry.budget import BudgetManager
    from privacy_telemetry.aggregation import Aggregator
    import tempfile

    s2 = Storage(tempfile.mktemp(suffix=".json"))
    cm2 = ConsentManager(s2)
    grant_all(cm2, "t", many)
    seed_events(s2, "t", _rows(many))
    b = Aggregator(s2, BudgetManager(s2)).run_aggregation("t", config(seed=2))
    assert a.bins != b.bins


def test_unconsented_events_excluded(storage, consent, aggregator):
    consent.grant("t", "u1")
    # u2 never grants consent
    seed_events(storage, "t", _rows(["u1", "u2"]))
    result = aggregator.run_aggregation("t", config())
    # no individual vector retained for u2 and its contribution absent
    assert storage.get_contribution("t", result.aggregation_id, "u2") is None


def test_windows_and_dimensions_partition(storage, consent, aggregator):
    grant_all(consent, "t", ["u1", "u2"])
    seed_events(
        storage,
        "t",
        [
            ("u1", "run", 1.0, {"os": "linux"}, 1.0),
            ("u2", "run", 5.0, {"os": "mac"}, 1.0),
            ("u1", "other", 1.0, {"os": "linux"}, 1.0),
            ("u1", "run", 50.0, {"os": "linux"}, 1.0),
        ],
    )
    result = aggregator.run_aggregation("t", config(dims=("os",)))
    assert set(result.bins) == {"linux", "mac"}
    assert storage.events_for_window("t", "run", 0, 10) == []
    # out-of-window event stays
    assert len(storage.events_for_window("t", "run", 0, 100)) == 1


from privacy_telemetry.consent import ConsentManager  # noqa: E402
