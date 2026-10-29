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
from collections import OrderedDict

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
# Real hard cap on how many distinct IPs this process ever tracks at once.
#
# Real bug found + fixed here (2026-10-29): the previous implementation
# called this "the tracked set size that triggers a sweep", not an actual
# cap -- and the sweep (`_evict_stale`) only ever removed an IP whose
# *entire* history had already gone stale (`max(timestamps) <= window_start`).
# A sustained burst of unique source IPs *within* one live window (any
# botnet, cheap rotating proxies, or just plain IPv6 address diversity --
# nothing here requires defeating the X-Forwarded-For trust fix above, a
# direct connection from N different real source addresses is enough) is
# never stale by that definition, so the sweep found nothing to evict and
# `_hits` grew without bound. Reproduced live, directly against this exact
# module (no mocks): 20,000 one-shot unique-IP `check()` calls inside one
# window left 20,000 entries in `_hits` -- 4x the "cap" -- and, because the
# sweep re-ran its full `O(len(_hits))` scan on *every single call* once
# past the threshold (finding nothing to evict each time, so never getting
# cheaper), per-request cost measured 736x slower once past 5000 tracked
# IPs (0.4us/req before, 310us/req after) with no upper bound on either the
# dict's size or that per-request scan cost as the burst continued. Since
# `check()` runs synchronously in the request path before any `await`
# (see the class-level note below), that cost is paid on the single
# uvicorn worker's event loop for every concurrent request, not just the
# IPs causing the burst -- the exact unbounded-growth-under-a-botnet
# scenario this module's own original comment claimed was already
# prevented.
#
# Fixed by making `_hits` a real LRU with a real hard cap: inserting a
# previously-unseen IP that would push the tracked set over `_MAX_TRACKED_IPS`
# evicts the single least-recently-seen IP (`OrderedDict.popitem(last=False)`,
# O(1)) instead of re-scanning the whole dict for staleness. This can, in
# the worst case, evict an IP that still had an active, non-stale window
# (resetting its count early) -- an accepted tradeoff already stated by this
# module's own docstring ("the goal is bounding sustained abuse, not
# perfect enforcement"), and strictly better than the unbounded
# memory/CPU growth it replaces.
_MAX_TRACKED_IPS = 5000

# ip -> list of monotonic timestamps of its requests still inside the
# current window. An OrderedDict kept in least-recently-seen order (every
# access moves the IP to the end) so eviction at the cap is an O(1)
# `popitem(last=False)` instead of an O(n) staleness scan -- see
# `_MAX_TRACKED_IPS` above for the real unbounded-growth bug this replaces.
# Mutation here is plain sync code with no `await` in between read and
# write, so it stays atomic on uvicorn's single-worker, single-event-loop
# process without needing an explicit lock.
_hits: "OrderedDict[str, list[float]]" = OrderedDict()


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
    already made _MAX_REQUESTS within the trailing _WINDOW_SECONDS.

    O(1) amortized regardless of how many distinct IPs are currently
    tracked -- see `_MAX_TRACKED_IPS`'s module-level comment for the real
    unbounded-growth/O(n)-per-request bug this replaces.
    """
    now = time.monotonic()
    window_start = now - _WINDOW_SECONDS
    is_new_ip = ip not in _hits
    fresh = [t for t in _hits.get(ip, ()) if t > window_start]
    if len(fresh) >= _MAX_REQUESTS:
        _hits[ip] = fresh
        _hits.move_to_end(ip)
        retry_after = fresh[0] + _WINDOW_SECONDS - now
        raise RateLimitExceeded(max(retry_after, 1.0))
    fresh.append(now)
    _hits[ip] = fresh
    _hits.move_to_end(ip)
    if is_new_ip and len(_hits) > _MAX_TRACKED_IPS:
        # Real hard cap: evict the single least-recently-seen IP, O(1).
        # Only reachable when *this* call just added a never-seen-before
        # IP -- an already-tracked IP being updated never grows `_hits`,
        # so it can never be the thing that pushes it over the cap.
        _hits.popitem(last=False)
