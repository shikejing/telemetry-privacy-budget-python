"""Durable, transactional storage for the privacy pipeline.

A single SQLite database holds all state that must survive a restart:

* ``processed_ids``  - idempotency tombstones for ingested event ids;
* ``raw_events``     - not-yet-aggregated raw detail (deleted once folded
  into per-user partial aggregates within the same transaction);
* ``partials``       - per-user / per-bucket contributions, the only
  individual-level state retained after aggregation, and only so that a
  later revocation can subtract exactly that user's contribution;
* ``revoked``        - users whose authorization has been withdrawn;
* ``aggregates``     - current per-bucket aggregate totals (no user ids);
* ``budget_entries`` - append-only, monotonic per-tenant ledger;
* ``audit``          - redacted audit trail;
* ``meta``           - checkpoints and other scalar state.

Every compound operation (aggregation, revocation, budget charge) runs in a
single ``BEGIN IMMEDIATE`` transaction: an outside observer can only ever see
the state before or after, never a half-applied mix.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .models import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS processed_ids (
    event_id  TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    PRIMARY KEY (event_id, tenant_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS raw_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    ts_ms      INTEGER NOT NULL,
    value      REAL NOT NULL,
    attrs_json TEXT NOT NULL,
    UNIQUE(event_id, tenant_id)
);
CREATE TABLE IF NOT EXISTS revoked (
    tenant_id TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS partials (
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    window_start_ms INTEGER NOT NULL,
    dims_key        TEXT NOT NULL,
    dims_json       TEXT NOT NULL,
    contrib         REAL NOT NULL,
    PRIMARY KEY (tenant_id, user_id, window_start_ms, dims_key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS aggregates (
    tenant_id       TEXT NOT NULL,
    window_start_ms INTEGER NOT NULL,
    dims_key        TEXT NOT NULL,
    dims_json       TEXT NOT NULL,
    value           REAL NOT NULL,
    users           INTEGER NOT NULL,
    updated_seq     INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, window_start_ms, dims_key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS budget_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    amount     REAL NOT NULL,
    request_id TEXT,
    ts_ms      INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS budget_request
    ON budget_entries(tenant_id, request_id)
    WHERE request_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms       INTEGER NOT NULL,
    tenant_id   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    role        TEXT NOT NULL,
    action      TEXT NOT NULL,
    allowed     INTEGER NOT NULL,
    subject_ref TEXT NOT NULL
);
"""


def canonical_dims_key(dims: dict[str, str]) -> str:
    return json.dumps(sorted(dims.items()), separators=(",", ":"),
                      ensure_ascii=False)


class Storage:
    def __init__(self, path: str) -> None:
        self._path = path
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Serialize writers and expose a single committed transaction."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                yield cur
            except Exception:
                cur.execute("ROLLBACK")
                raise
            else:
                cur.execute("COMMIT")
            finally:
                cur.close()

    # ---------------- meta / checkpoints -----------------
    @staticmethod
    def meta_get(cur: sqlite3.Cursor, key: str) -> str | None:
        row = cur.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return None if row is None else row["value"]

    @staticmethod
    def meta_set(cur: sqlite3.Cursor, key: str, value: str) -> None:
        cur.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---------------- ingestion --------------------------
    @staticmethod
    def insert_events(cur: sqlite3.Cursor, events: list[Event]) -> int:
        """Insert events; duplicate event ids are ignored. Returns accepted."""
        accepted = 0
        for ev in events:
            cur.execute(
                "INSERT OR IGNORE INTO processed_ids"
                "(event_id, tenant_id, user_id) VALUES(?, ?, ?)",
                (ev.event_id, ev.tenant_id, ev.user_id),
            )
            if cur.rowcount == 1:
                cur.execute(
                    "INSERT OR IGNORE INTO raw_events"
                    "(event_id, tenant_id, user_id, ts_ms, value, attrs_json) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (ev.event_id, ev.tenant_id, ev.user_id, ev.ts_ms, ev.value,
                     json.dumps(ev.attrs, ensure_ascii=False, sort_keys=True)),
                )
                accepted += cur.rowcount
        return accepted

    @staticmethod
    def pending_event_count(cur: sqlite3.Cursor, tenant_id: str | None) -> int:
        if tenant_id is None:
            row = cur.execute("SELECT COUNT(*) AS n FROM raw_events").fetchone()
        else:
            row = cur.execute(
                "SELECT COUNT(*) AS n FROM raw_events WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        return int(row["n"])

    @staticmethod
    def fetch_pending(cur: sqlite3.Cursor, tenant_id: str | None
                      ) -> list[sqlite3.Row]:
        if tenant_id is None:
            return cur.execute(
                "SELECT seq, event_id, tenant_id, user_id, ts_ms, value, "
                "attrs_json FROM raw_events ORDER BY seq"
            ).fetchall()
        return cur.execute(
            "SELECT seq, event_id, tenant_id, user_id, ts_ms, value, "
            "attrs_json FROM raw_events WHERE tenant_id=? ORDER BY seq",
            (tenant_id,),
        ).fetchall()

    # ---------------- revocation -------------------------
    @staticmethod
    def is_revoked(cur: sqlite3.Cursor, tenant_id: str, user_id: str) -> bool:
        row = cur.execute(
            "SELECT 1 FROM revoked WHERE tenant_id=? AND user_id=?",
            (tenant_id, user_id),
        ).fetchone()
        return row is not None

    @staticmethod
    def mark_revoked(cur: sqlite3.Cursor, tenant_id: str, user_id: str) -> bool:
        cur.execute(
            "INSERT OR IGNORE INTO revoked(tenant_id, user_id) VALUES(?, ?)",
            (tenant_id, user_id),
        )
        return cur.rowcount == 1

    @staticmethod
    def delete_user_data(cur: sqlite3.Cursor, tenant_id: str, user_id: str
                         ) -> list[tuple[int, str, str]]:
        """Remove a user's raw events, tombstones and partial contributions.

        Returns the distinct buckets (window_start_ms, dims_key, dims_json)
        whose totals must be recomputed.
        """
        cur.execute(
            "DELETE FROM raw_events WHERE tenant_id=? AND user_id=?",
            (tenant_id, user_id),
        )
        cur.execute(
            "DELETE FROM processed_ids WHERE tenant_id=? AND user_id=?",
            (tenant_id, user_id),
        )
        rows = cur.execute(
            "SELECT DISTINCT window_start_ms, dims_key, dims_json FROM partials "
            "WHERE tenant_id=? AND user_id=?",
            (tenant_id, user_id),
        ).fetchall()
        buckets = [(r["window_start_ms"], r["dims_key"], r["dims_json"])
                   for r in rows]
        cur.execute(
            "DELETE FROM partials WHERE tenant_id=? AND user_id=?",
            (tenant_id, user_id),
        )
        return buckets

    # ---------------- partials & aggregates --------------
    @staticmethod
    def upsert_partial(cur: sqlite3.Cursor, tenant_id: str, user_id: str,
                       window_start_ms: int, dims_key: str, dims_json: str,
                       delta: float) -> None:
        cur.execute(
            "INSERT INTO partials(tenant_id, user_id, window_start_ms, "
            "dims_key, dims_json, contrib) VALUES(?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, user_id, window_start_ms, dims_key) "
            "DO UPDATE SET contrib = contrib + excluded.contrib",
            (tenant_id, user_id, window_start_ms, dims_key, dims_json, delta),
        )

    @staticmethod
    def delete_raw(cur: sqlite3.Cursor, tenant_id: str,
                   event_ids: list[str]) -> None:
        if not event_ids:
            return
        cur.executemany(
            "DELETE FROM raw_events WHERE tenant_id=? AND event_id=?",
            [(tenant_id, eid) for eid in event_ids])

    @staticmethod
    def list_aggregates(cur: sqlite3.Cursor, tenant_id: str,
                        window_start_ms: int | None) -> list[sqlite3.Row]:
        if window_start_ms is None:
            return cur.execute(
                "SELECT window_start_ms, dims_key, dims_json, value, users "
                "FROM aggregates WHERE tenant_id=? "
                "ORDER BY window_start_ms, dims_key",
                (tenant_id,),
            ).fetchall()
        return cur.execute(
            "SELECT window_start_ms, dims_key, dims_json, value, users "
            "FROM aggregates WHERE tenant_id=? AND window_start_ms=? "
            "ORDER BY dims_key",
            (tenant_id, window_start_ms),
        ).fetchall()

    # ---------------- budget -----------------------------
    @staticmethod
    def budget_consumed(cur: sqlite3.Cursor, tenant_id: str) -> float:
        row = cur.execute(
            "SELECT COALESCE(SUM(amount), 0) AS s FROM budget_entries "
            "WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        return float(row["s"])
