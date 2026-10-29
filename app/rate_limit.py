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
enforcement). `client_ip()` uses the raw socket peer by default, and only
consults `X-Forwarded-For` when that peer is an explicitly configured
trusted proxy (`WEDGECHECK_TRUSTED_PROXY_IPS`) -- see the real bypass this
closes, and why, below.

Real gap found and fixed here (2026-10-29): `client_ip()` used to honor
`X-Forwarded-For` unconditionally, from *any* direct connection, with no
check that the request had actually passed through Caddy (or any reverse
proxy) at all. Reproduced live, directly against this module (no mocks):
holding the simulated TCP peer fixed and only changing the request's own
`X-Forwarded-For` header made `client_ip()` return a different value every
time -- a single real client could self-assign a fresh bucket key per
request and bypass the limiter entirely, just by sending its own header.
This is reachable two ways without needing Caddy to ever misbehave:
production's own `docker-compose.yml` binds the app's port to
`127.0.0.1:4220` on the host (not the public interface) -- but that
container also sits on `products-net`, a shared bridge network with many
other products' containers attached to it (per `infra-box`). Docker's
default bridge network does not isolate same-network containers from each
other, so *any* other container on `products-net` can reach
`http://wedgecheck:8000/` directly over the internal docker network,
bypassing Caddy (and its `header_up X-Forwarded-For {client_ip}`
overwrite) entirely, and forge whatever `X-Forwarded-For` it likes. A
future accidental change to the host port binding (dropping the
`127.0.0.1:` prefix) would open the same gap straight to the public
internet. The app itself had zero defense against either case -- it
is exactly the "don't trust a client-controlled header for a security
decision just because a correctly-configured proxy happens to overwrite
it today" principle the rest of this file (and `csrf_guard.py`,
`ssrf_guard.py`) already follows elsewhere.

Fixed by only trusting `X-Forwarded-For` when the *immediate* connecting
peer (`request.client.host`, which Docker/Starlette itself determines from
the real TCP connection and a client cannot forge) is in
`WEDGECHECK_TRUSTED_PROXY_IPS` (comma-separated IPs, default empty).
Empty/unset means trust nothing extra -- `client_ip()` always falls back
to the real socket peer, which closes the bypass completely with zero
configuration and zero infra coordination needed. Operators who want
`X-Forwarded-For` honored set this to Caddy's actual peer address as seen
from inside the container (confirm with one real request's logged
`request.client.host` -- typically the docker bridge gateway address, not
`127.0.0.1`, since Docker NATs host-originated connections).
"""
from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import Request

_WINDOW_SECONDS = float(os.getenv("WEDGECHECK_RATE_LIMIT_WINDOW_SECONDS", "600"))
_MAX_REQUESTS = int(os.getenv("WEDGECHECK_RATE_LIMIT_MAX_REQUESTS", "3"))
# Empty by default: X-Forwarded-For is trusted *only* from these exact
# immediate-peer addresses (the real TCP peer, not anything the request
# itself can claim). See module docstring -- this closes a real bypass
# where any direct connection (another container on the same shared
# docker network, or a future port-binding slip) could self-assign a
# fresh rate-limit bucket per request just by setting its own header.
_TRUSTED_PROXY_IPS = {
    ip.strip()
    for ip in os.getenv("WEDGECHECK_TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}
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
    otherwise.

    X-Forwarded-For is honored ONLY when the immediate TCP peer
    (`request.client.host`, not attacker-controllable) is a configured
    trusted proxy (`WEDGECHECK_TRUSTED_PROXY_IPS`) -- see module docstring
    for the real bypass this closes. Any other direct connection (no
    trusted proxy configured, or a peer not on the list) gets its own raw
    socket address as the rate-limit key, full stop; its own
    X-Forwarded-For header is never consulted, so it cannot self-assign a
    different bucket per request.

    When trusted, takes the right-most entry of a comma-separated list --
    the hop nearest the trusted proxy itself (what it actually appended/
    set), not the left-most entry a client ahead of it could have
    injected into the header before it ever reached the proxy.
    """
    peer = request.client.host if request.client else None
    if peer is not None and peer in _TRUSTED_PROXY_IPS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                return parts[-1]
    return peer or "unknown"


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
