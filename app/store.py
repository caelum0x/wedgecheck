"""Lightweight SQLite persistence for generated market briefs.

Wedgecheck previously generated a brief and handed it straight back in the
HTTP response -- nothing was kept, so closing the tab (or losing the API
response) lost the report for good, and there was no way to send someone
else a link to a result. This module adds exactly two real things on top
of the existing generate_market_brief() flow, no new infra, no new paid
dependency (sqlite3 is stdlib):

1. A shareable permalink for any completed report (`GET /b/{id}`).
2. A "my past briefs" history scoped to an anonymous session cookie
   (`GET /history`) so a browser doesn't lose its own briefs after one
   session.

There is still no user-account system in Wedgecheck. "Session" here is
just an opaque random id issued as a cookie, used only to group a single
browser's own past briefs for the /history view -- it is not an auth
token and grants no extra access. Permalinks are deliberately public by
id (like a paste link): the content is market research grounded in
already-public, cited source URLs, not private data, and that's already
how a generated brief is shared today (markdown printed to stdout by
cli.py, or handed back raw by /api/brief).
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from .schema import MarketBrief

DB_PATH = Path(os.getenv("WEDGECHECK_DB_PATH", "./data/wedgecheck.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS briefs (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    url TEXT,
    description TEXT,
    resolved_title TEXT,
    report_markdown TEXT NOT NULL,
    source_urls TEXT NOT NULL,
    research_cost_usd REAL NOT NULL,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_briefs_session
    ON briefs (session_id, generated_at DESC);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _connection():
    """Same commit-on-success/rollback-on-exception semantics as using a
    raw sqlite3.Connection as a context manager (`with conn:`), but also
    actually closes the connection on the way out.

    Every function below used to do `with _connect() as conn:` directly.
    That commits or rolls back correctly, but a bare sqlite3.Connection's
    own `__exit__` never calls `close()` -- and, confirmed live, Python's
    refcounting alone does not reclaim it either: sqlite3.Connection
    objects hold an internal reference back to their own cached
    Cursor/Statement objects, a real reference cycle, so the connection
    (and the one real OS file descriptor + SQLite-level handle it holds
    open on `DB_PATH`) is only ever reclaimed whenever the generational
    cyclic GC next happens to run -- not deterministically when the
    `with` block exits, which is what every caller's own code shape
    implied. Reproduced with `gc.disable()`: 500 real save_brief()+
    get_brief() calls through the unfixed code left exactly 1000 real
    open file descriptors on the db file (confirmed via `lsof`), never
    freed by refcounting alone, until `gc.collect()` ran and dropped it
    back to 0. Reproduced again with gc left enabled (the real default):
    the open-FD count for the db file churned between 2 and 75+ across
    2000 real save_brief() calls instead of staying pinned at 1 or 2,
    because collection only happens whenever the next GC generation
    threshold is hit, not per request. On this single long-running
    process (no restarts between requests -- every GET /b/{id}, GET
    /history, POST /, and POST /api/brief opens one of these), that is a
    real, unbounded-until-GC file-descriptor leak scaling with request
    volume, not a one-time cost -- under enough real concurrent/bursty
    traffic it can run the process into its own `ulimit -n` and start
    failing brand new sqlite3.connect() calls with a real OSError, with
    no try/except anywhere in main.py around the save_brief() call on
    POST / to catch it -- discarding an already-completed, already-paid-
    for real research result for no reason other than this leak.
    """
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create the briefs table if it doesn't exist yet. Safe to call every
    process start -- CREATE TABLE/INDEX IF NOT EXISTS, no destructive op."""
    with _connection() as conn:
        conn.executescript(_SCHEMA)


def save_brief(brief: MarketBrief, *, session_id: str | None) -> str:
    """Persist a completed MarketBrief and return its new permalink id.

    Never mutates the MarketBrief passed in -- this is a pure storage-layer
    concern, the dataclass itself stays exactly as generate_market_brief()
    built it.
    """
    brief_id = uuid.uuid4().hex
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO briefs
                (id, session_id, url, description, resolved_title,
                 report_markdown, source_urls, research_cost_usd, generated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                brief_id,
                session_id,
                brief.input.raw_url,
                brief.input.raw_description,
                brief.input.resolved_title,
                brief.report_markdown,
                json.dumps(brief.source_urls),
                brief.research_cost_usd,
                brief.generated_at,
            ),
        )
    return brief_id


def get_brief(brief_id: str) -> dict | None:
    """Look up one stored brief by its permalink id, or None if it never
    existed / was never saved (e.g. generated before this feature shipped)."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM briefs WHERE id = ?", (brief_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["source_urls"] = json.loads(result["source_urls"])
    return result


def list_briefs_for_session(session_id: str, *, limit: int = 20) -> list[dict]:
    """Most-recent-first briefs generated by this browser's session cookie.
    Returns [] for a brand-new session -- that's a real empty state, not
    an error."""
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT id, url, description, resolved_title,
                   research_cost_usd, generated_at
            FROM briefs
            WHERE session_id = ?
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]
