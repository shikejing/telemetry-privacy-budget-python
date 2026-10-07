import threading

from conftest import config, grant_all, seed_events


def test_concurrent_aggregations_charge_once_per_config(
    storage, consent, aggregator, budget
):
    budget.set_limit("t", 100.0)
    users = [f"u{i}" for i in range(20)]
    grant_all(consent, "t", users)
    seed_events(storage, "t", [(u, "run", 1.0, {"os": "linux"}, 1.0) for u in users])

    results = []
    errors = []

    def worker(seed):
        try:
            results.append(
                aggregator.run_aggregation("t", config(seed=seed), idem_key=f"k{seed}")
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(s,)) for s in range(1, 6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # five distinct configurations => exactly five charges, no oversubscription
    assert errors == []
    assert budget.state("t").consumed == 5.0
    ids = {r.aggregation_id for r in results}
    assert len(ids) == 5


def test_concurrent_same_config_charges_once(
    storage, consent, aggregator, budget
):
    grant_all(consent, "t", ["u1", "u2"])
    seed_events(
        storage,
        "t",
        [(u, "run", 1.0, {"os": "linux"}, 1.0) for u in ["u1", "u2"]],
    )
    results = []
    errors = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        try:
            results.append(aggregator.run_aggregation("t", config(seed=42)))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [], errors
    assert {r.aggregation_id for r in results} == {results[0].aggregation_id}
    assert budget.state("t").consumed == 1.0


def test_concurrent_revocation_runs_once(storage, consent, aggregator, budget):
    users = [f"u{i}" for i in range(10)]
    grant_all(consent, "t", users)
    seed_events(storage, "t", [(u, "run", 1.0, {"os": "linux"}, 1.0) for u in users])
    result = aggregator.run_aggregation("t", config(seed=77))
    aid = result.aggregation_id

    barrier = threading.Barrier(6)

    def revoke_and_apply():
        barrier.wait()
        consent.revoke("t", "u0")
        aggregator.apply_revocations("t", aid)

    threads = [threading.Thread(target=revoke_and_apply) for _ in range(5)]
    # extra thread re-running aggregation concurrently
    def rerun():
        barrier.wait()
        aggregator.run_aggregation("t", config(seed=77), idem_key="dup")

    threads.append(threading.Thread(target=rerun))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = aggregator.get("t", aid)
    assert "u0" in final.excluded_users
    assert storage.get_contribution("t", aid, "u0") is None
    # budget: single aggregate, no extra charge
    assert budget.state("t").consumed == 1.0


def test_concurrent_revokes_of_different_users_converge(
    tmp_path, storage, consent, aggregator
):
    users = [f"u{i}" for i in range(6)]
    grant_all(consent, "t", users)
    seed_events(
        storage,
        "t",
        [(u, "run", 1.0, {"os": "linux" if int(u[1]) % 2 else "mac"}, 1.0)
         for u in users],
    )
    result = aggregator.run_aggregation("t", config(seed=21))
    aid = result.aggregation_id

    def revoke(u):
        consent.revoke("t", u)
        aggregator.apply_revocations("t", aid)

    threads = [threading.Thread(target=revoke, args=(u,)) for u in ["u1", "u3", "u5"]]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = aggregator.get("t", aid)
    assert final.excluded_users == frozenset({"u1", "u3", "u5"})
    for u in ["u1", "u3", "u5"]:
        assert storage.get_contribution("t", aid, u) is None
    # retained users still present
    for u in ["u0", "u2", "u4"]:
        assert storage.get_contribution("t", aid, u) is not None
