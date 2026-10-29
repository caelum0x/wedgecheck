"""In-process rate limiting for Wedgecheck's two compute-heavy endpoints.

Every POST / or POST /api/brief triggers a real 60-120s gpt-researcher
research pass against this portfolio's shared free LLM relay
(ai-relay-worker, also used by Huddle) -- and, until this module, there was
no limit anywhere in the app on how many of those a single client could
fire concurrently or back-to-back. One abusive client (or a broken retry
loop in someone's own script hitting the public API) could pin the box's
single uvicorn worker and degrade the shared relay for every other product
using it, with zero cost to the caller. This closes that gap with a basic
per-IP sliding-window limiter -- no new dependency, no new infra, matches
the existing single-process in-memory pattern the app already uses
elsewhere (e.g. no --workers, no external cache).

Deliberately NOT applied to the cheap endpoints (/, GET; /history; /b/{id};
/healthz) -- those are DB reads or static renders, not the resource this
guards.

This is process-local state: restarting the container resets everyone's
window (acceptable -- the goal is bounding sustained abuse, not perfect
enforcement), and it only works correctly behind a proxy that sets
X-Forwarded-For (Caddy does this by default for every stacks/*.caddy site
in infra-box) -- _client_ip() falls back to the raw socket peer if that
header is absent.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import Request

_WINDOW_SECONDS = float(os.getenv("WEDGECHECK_RATE_LIMIT_WINDOW_SECONDS", "600"))
_MAX_REQUESTS = int(os.getenv("WEDGECHECK_RATE_LIMIT_MAX_REQUESTS", "3"))
# Sweep stale IPs once the tracked set crosses this size, so a botnet of
# unique source IPs can't grow this dict unbounded in a long-lived process.
_MAX_TRACKED_IPS = 5000

# ip -> list of monotonic timestamps of its requests still inside the
# current window. Mutation here is plain sync code with no `await` in
# between read and write, so it stays atomic on uvicorn's single-worker,
# single-event-loop process without needing an explicit lock.
_hits: dict[str, list[float]] = defaultdict(list)


class RateLimitExceeded(Exception):
    """Raised when an IP has used up its requests for the current window."""

    def __init__(self, retry_after_seconds: float):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Rate limit exceeded, retry after {retry_after_seconds:.0f}s"
        )


def client_ip(request: Request) -> str:
    """Real client IP behind Caddy's reverse proxy, or the raw socket peer
    if no X-Forwarded-For is present (e.g. a direct localhost request)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check(ip: str) -> None:
    """Record one request from `ip`, raising RateLimitExceeded if it has
    already made _MAX_REQUESTS within the trailing _WINDOW_SECONDS."""
    now = time.monotonic()
    window_start = now - _WINDOW_SECONDS
    fresh = [t for t in _hits[ip] if t > window_start]
    if len(fresh) >= _MAX_REQUESTS:
        _hits[ip] = fresh
        retry_after = fresh[0] + _WINDOW_SECONDS - now
        raise RateLimitExceeded(max(retry_after, 1.0))
    fresh.append(now)
    _hits[ip] = fresh
    if len(_hits) > _MAX_TRACKED_IPS:
        _evict_stale(window_start)


def _evict_stale(window_start: float) -> None:
    stale = [ip for ip, timestamps in _hits.items() if not timestamps or max(timestamps) <= window_start]
    for ip in stale:
        del _hits[ip]
