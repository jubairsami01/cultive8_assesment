"""SQLite persistence. Every model call's result is committed immediately, so a crash or
restart never loses completed work (resume picks up the remaining parts)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL,               -- uploaded|queued|planning|running|done|failed|cancelled
    stage TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    total_lines INTEGER,
    total_entries INTEGER,
    collapsed_entries INTEGER,
    raw_tokens INTEGER,
    compact_tokens INTEGER,
    n_chunks INTEGER,
    budget_json TEXT,
    error TEXT,
    model TEXT,
    prompt_version TEXT,
    report_json TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
    job_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    n_entries INTEGER NOT NULL,
    token_count INTEGER NOT NULL,
    text TEXT NOT NULL,                 -- compact form (not a raw copy of the log)
    line_ips TEXT NOT NULL,             -- {line: ip} for evidence validation
    state_json TEXT NOT NULL,           -- code-side facts known before this part
    status TEXT NOT NULL DEFAULT 'pending',  -- pending|running|done|failed
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    latency_ms INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    parse_mode TEXT,
    raw_response TEXT,
    findings_json TEXT,
    watch_json TEXT,
    updated_at REAL,
    PRIMARY KEY (job_id, idx)
);
"""


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._lock = threading.Lock()

    @contextmanager
    def tx(self):
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def q(self, sql: str, *args) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def one(self, sql: str, *args) -> sqlite3.Row | None:
        rows = self.q(sql, *args)
        return rows[0] if rows else None

    def x(self, sql: str, *args) -> None:
        with self._lock:
            self._conn.execute(sql, args)

    # --- jobs ---
    def create_job(self, job_id: str, filename: str, path: str, size: int, model: str, pv: str) -> None:
        self.x("INSERT INTO jobs (id, filename, path, size_bytes, status, created_at, model, prompt_version)"
               " VALUES (?,?,?,?,?,?,?,?)", job_id, filename, path, size, "uploaded", time.time(), model, pv)

    def update_job(self, job_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in fields.values()]
        self.x(f"UPDATE jobs SET {cols} WHERE id=?", *vals, job_id)

    def job(self, job_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM jobs WHERE id=?", job_id)

    def chunk_rows(self, job_id: str, full: bool = False) -> list[sqlite3.Row]:
        cols = "*" if full else ("idx, line_start, line_end, n_entries, token_count, status, attempts, error, "
                                 "latency_ms, prompt_tokens, completion_tokens, parse_mode, findings_json")
        return self.q(f"SELECT {cols} FROM chunks WHERE job_id=? ORDER BY idx", job_id)

    def update_chunk(self, job_id: str, idx: int, **fields) -> None:
        fields["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in fields.values()]
        self.x(f"UPDATE chunks SET {cols} WHERE job_id=? AND idx=?", *vals, job_id, idx)
