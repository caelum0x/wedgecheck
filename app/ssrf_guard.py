"""Block Wedgecheck's URL-fetch step from reaching internal/private
infrastructure (SSRF).

`app/product_input.py`'s `build_product_input()` runs `requests.get(url)`
on whatever a caller hands the public, unauthenticated web form or
`/api/brief` endpoint -- there was no validation at all on `url` before
this module: scheme, host, and destination were all attacker-controlled.
On the real production box this process can reach the Docker
`products-net` network (other containers' internal-only ports) and the
host's own loopback-bound services, and on the Oracle Cloud box
specifically, the cloud metadata address (`169.254.169.254`) can leak
instance credentials if an attacker can make the box fetch it. None of
that is theoretical -- it was reproduced live against this app's own
`127.0.0.1` listener before this fix (see wedgecheck.md's 2026-10-29
entry).

Three defenses, all required:
1. Scheme must be http/https (blocks `file://`, custom handlers, etc).
2. Every IP the hostname resolves to must be a real public, routable
   address -- not loopback, private (RFC1918), link-local (incl. the
   cloud-metadata /16), multicast, reserved, unspecified, or any other
   range `ipaddress`'s own `is_global` knows isn't public (e.g. RFC 6598
   Shared Address Space, 100.64.0.0/10 -- see `_is_blocked_ip`'s own
   comment for why `is_private` alone misses that one).
3. The actual TCP connection reuses the *exact* address list this module
   already resolved and validated, instead of letting `requests`/urllib3
   re-resolve the hostname independently a moment later. Without this,
   steps 1-2 are a check-then-fetch pattern with a real DNS-rebinding
   bypass: an attacker who controls the authoritative DNS for the
   hostname can answer the validation lookup with a public IP and the
   separate connection lookup -- made by urllib3 inside `requests.get()`
   -- with `127.0.0.1` / `169.254.169.254` / an internal container IP,
   walking straight past steps 1-2. (This is the standard SSRF-via-
   DNS-rebinding technique and applies to any "validate, then separately
   connect" URL guard -- including the first version of this module,
   which called `socket.getaddrinfo()` once for validation and then threw
   the result away before calling `requests.get()`.)

   `socket.getaddrinfo` is a single process-global function, so pinning
   it has to be done without letting one request's pin leak onto another
   request's unrelated hostname. An earlier version of this fix installed
   and tore down a *global* monkeypatch of `socket.getaddrinfo` around
   each request, serialized by one process-wide `threading.Lock` held for
   the pin's entire lifetime -- which, because `requests.get()` itself
   blocks until the response's status line and headers arrive (not just
   through DNS resolve + TCP connect), meant that lock was held for the
   full wait-on-a-slow-server duration, not a quick setup step. Confirmed
   live against the real production container (see wedgecheck.md's
   2026-10-29 entry): one in-flight fetch of a deliberately slow but
   perfectly legitimate URL (`httpbin.org/delay/6`) stalled four
   concurrent fetches of a completely unrelated, fast host (`example.com`)
   for the same ~6s, even though none of them shared a hostname and there
   was no reason for them to wait on each other -- every concurrent
   brief's url-fetch step was serialized behind whichever one happened to
   be slowest, for up to `timeout` seconds per redirect hop.

   Fixed by pinning per-thread instead of per-process: `_pin_state` is a
   `threading.local()`, and the single `socket.getaddrinfo` monkeypatch
   (installed once, at import time, forever) only intercepts a hostname
   lookup if the *calling thread* has that exact hostname pinned in its
   own thread-local slot. Since `requests`/urllib3 does its DNS resolution
   and connect synchronously on the same thread that called
   `fetch_public_url()` (this app runs each brief's URL fetch in its own
   worker thread via `asyncio.to_thread`, see brief.py), the pin is only
   ever visible to the thread that set it -- closing the exact same
   DNS-rebinding window as before, with zero cross-thread lock and zero
   cross-thread stalling.

Because a redirect can point anywhere, `fetch_public_url()` also follows
redirects itself, one hop at a time, re-running all three checks before
every single request -- `requests`' own `allow_redirects=True` is never
used here (classic SSRF-via-redirect bypass).

A fourth defense, unrelated to SSRF but living here because it's the same
"public, unauthenticated url fetch" surface: a response-size cap.
`requests.get()` with its default `stream=False` buffers the entire
response body into memory before this function (or `product_input.py`)
ever looks at it, with no limit. A URL that resolves to a perfectly
public, non-internal address -- so none of the three defenses above would
ever block it -- but serves a multi-gigabyte body (an attacker's own
public server, or even just a legitimate but huge file someone pastes in)
would still get downloaded in full, in this single-uvicorn-worker
container that runs at ~512MB. That OOMs the one process serving every
concurrent user, not just the request that triggered it. `fetch_public_url`
now streams and enforces `WEDGECHECK_MAX_FETCH_BYTES` (default 5MB, well
over any real HTML page this app needs to extract a title/summary from)
against both the `Content-Length` header (fast path) and the actual bytes
read (so a missing or lying header can't bypass it).

A fifth defense: a real wall-clock deadline on the whole fetch, separate
from (and not satisfied by) the `timeout=` already passed to every
`requests.get()` call above. `requests`'/urllib3's "timeout" is a
*per-socket-read* timeout, not a total-duration one -- confirmed live with
a throwaway local TCP server that sends valid HTTP headers, then the body
one single byte at a time with a `time.sleep()` between each byte well
under the configured timeout: `requests.get(url, timeout=15, stream=True)`
followed by reading `.content`/iterating `iter_content()` took the full
57+ seconds to materialize a 20-byte body, never once raising, because
every individual `recv()` arrived comfortably inside the 15s window --
only the gap *between* reads is timed, never the sum of them. A URL that
resolves to a real public address an attacker controls (so none of the
first three defenses touch it, and the response is well under the
response-size cap above) can hold the connection open near-indefinitely
this way. That matters well beyond "one slow request": `build_product_input()`
(product_input.py) runs on a worker thread via `asyncio.to_thread()` -- see
the sixth defense below for the sibling gap this same thread-pool-
exhaustion risk applies to, one step earlier in the same call.

A sixth defense, found the same way as the fifth (re-examining this exact
module's own wall-clock-deadline claim after shipping it, not a new file):
the fifth defense's own deadline tracking starts the clock, but
`_resolve_and_validate()` -- called once per redirect hop, *before*
`requests.get()` or `_read_capped()` ever run -- calls the real
`socket.getaddrinfo()` with no timeout at all. `socket.getaddrinfo()`
takes no timeout argument; it blocks for however long the OS resolver
takes, which for a hostname whose authoritative nameserver an attacker
controls and deliberately never answers (or answers very slowly) is bounded
only by the resolver's own retry/timeout policy -- not by this module's
`timeout` parameter, and not by Docker's embedded DNS at 127.0.0.11 inside
this exact container either (confirmed by reading its own retry/backoff
behavior; it is not instant on a non-responding upstream). Reproduced live
against this exact function, same technique as the fifth defense's own
repro (a synthetic slow dependency swapped in at the real call site, not a
hypothetical): monkeypatching `_real_getaddrinfo` to sleep 8s before
resolving proved `fetch_public_url(url, timeout=3)` -- a 3-second budget --
actually took 8.1s to raise, with the error message claiming "wall-clock
budget exceeded before the response body could be read", which is simply
false in this case: no body was ever reached, the entire overrun happened
inside the supposedly-already-fixed deadline's own first step. Since this
runs on the same shared default `asyncio.to_thread()` pool the fifth
defense's own docstring already describes (small, single-digit worker
threads, shared with `store.save_brief()`/`get_brief()`/
`list_briefs_for_session()` for every other concurrent user), a handful of
briefs pointed at hostnames with deliberately unresponsive authoritative
nameservers can occupy the entire pool this way, identically to the fifth
defense's own already-fixed scenario -- just one call earlier.

Fixed by running the actual `_real_getaddrinfo()` call on a separate daemon
thread and waiting on it for at most whatever wall-clock budget remains,
via a one-slot `queue.Queue.get(timeout=...)` -- `socket.getaddrinfo()`
itself cannot be interrupted or cancelled once started (no socket exists
yet to shut down the way the fifth defense's `_force_close_socket` does),
so a resolution that is still running when the budget runs out is
abandoned, not killed: the background thread is left to finish on its own
and is simply never waited on or acted on again (harmless -- it only ever
writes its result into a queue nothing reads again, and is a daemon thread
so it cannot block process exit). This bounds the *caller's* wait, which is
the actual thread-pool-exhaustion risk, even though the orphaned OS-level
resolution call itself may still be running somewhere underneath.
`assert_safe_public_url()` (the standalone validator with no fetch and no
caller-supplied deadline) keeps the old unbounded call -- there is no
budget to bound it against there, and it was never reachable by a public
request in the first place.
(product_input.py) runs on a worker thread via `asyncio.to_thread()`, which
hands it to the asyncio event loop's *default* `ThreadPoolExecutor` --
shared, process-wide, with every *other* `asyncio.to_thread()` call in the
app, including `store.save_brief()`/`get_brief()`/`list_briefs_for_session()`
for every other user's completely unrelated request. That default pool is
small (`min(32, os.cpu_count() + 4)` -- single digits on this box's vCPU
count). A handful of concurrent briefs pointed at attacker-controlled
trickling URLs can occupy every worker thread the whole process has, with
nothing on this path currently able to time it out -- stalling `/history`,
`/b/{id}`, and every in-flight brief's own save, not just the attacker's
own slow fetch. Fixed by tracking one monotonic deadline across the entire
`fetch_public_url()` call -- every redirect hop's own `requests.get()`
gets whatever time remains (not the full budget again), and the
`_read_capped()` streaming loop checks the same deadline after every
chunk, closing the connection and raising once the real wall-clock budget
(the same `timeout` seconds the caller already asked for) is used up,
regardless of how innocently-paced each individual byte was.

Getting that deadline actually enforced took a second, less obvious step:
a plain per-chunk check inside the `iter_content()` loop is not enough on
its own. `http.client`'s own `_safe_read()` loops *internally*,
accumulating up to `min(chunk_size, bytes remaining per the attacker's own
declared Content-Length)` bytes across as many slow individual socket
reads as it takes, and only returns control to our loop (where a
per-chunk check would run) once that whole amount is assembled. Since the
attacker also controls Content-Length, they can simply declare a value at
or below whatever chunk_size this module picks, and the entire body comes
back as a *single* chunk no matter how many seconds it's spread across --
confirmed live: with only a per-chunk deadline check and the original 64KB
chunk size, a 40-byte body trickled 1 byte every 3s still took the full
117s to time out, not the ~10s budget asked for (shrinking chunk_size
doesn't close this either -- it only shifts which small Content-Length
value the attacker needs to declare to defeat it, confirmed the same way
down to chunk_size=1, which does close it but costs ~400x throughput on a
real fast response -- a 2MB fast local reply went from 12ms to 4.7s,
measured live -- an unacceptable trade on a 512MB single-worker box for
every legitimate fetch, to guard against an attacker who doesn't need it).

Fixed with a real interrupt instead: a `threading.Timer`, armed for
whatever time remains until `deadline` before the blocking read begins,
whose callback (`_force_close_socket`) reaches into the live socket (not
just `response.close()`, which was tried and confirmed live to do nothing
to an already-blocked read -- it only marks the response object closed
for *later* use, the in-progress `recv()` on the reading thread doesn't
notice and keeps blocking until the attacker's trickle finishes on its
own) and calls the real `socket.shutdown(SHUT_RDWR)` on it. That reliably
interrupts a blocked `recv()` on the thread stuck inside it, surfacing as
a normal `requests.exceptions.RequestException` (confirmed live: the same
40-byte/3s-per-byte repro now raises in ~5s, matching the timer, not
117s) -- which `_read_capped` catches and re-raises as `UnsafeUrlError`
only if the deadline had genuinely passed (any other, unrelated
connection error still propagates normally). The timer is cancelled in a
`finally` the instant a real read finishes, so the normal/fast case pays
only the cost of arming and cancelling one timer -- full chunk-size
throughput is unaffected, confirmed live (2MB fast local reply still
~12ms with this fix in place).
"""
from __future__ import annotations

import ipaddress
import os
import queue
import socket
import threading
import time
from contextlib import contextmanager
from urllib.parse import urlparse

import requests

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_REDIRECTS = 5
_MAX_RESPONSE_BYTES = int(os.getenv("WEDGECHECK_MAX_FETCH_BYTES", str(5 * 1024 * 1024)))
_FETCH_CHUNK_SIZE = 65536

# The real, unpatched resolver -- captured once, at import time, before
# the module-global monkeypatch below ever runs, so it always reaches the
# OS/libc resolver directly and never recurses into our own patch.
_real_getaddrinfo = socket.getaddrinfo

# Per-thread pin slot. See module docstring point 3: `requests`/urllib3
# resolves and connects synchronously on whichever thread called
# fetch_public_url(), so pinning per-thread (instead of per-process,
# behind a lock held for the whole request) closes the DNS-rebinding
# window with no cross-thread serialization.
_pin_state = threading.local()


def _thread_pinned_getaddrinfo(host, port=None, family=0, type=0, proto=0, flags=0):
    pinned_hostname = getattr(_pin_state, "hostname", None)
    if pinned_hostname is not None and host == pinned_hostname:
        results = []
        for ip in _pin_state.ips:
            results.extend(_real_getaddrinfo(ip, port, family, type, proto, flags))
        return results
    return _real_getaddrinfo(host, port, family, type, proto, flags)


# Installed once, forever, at import time -- not swapped in/out per
# request. Safe to leave in place process-wide: for any thread that has
# never entered `_pinned_resolution`, `_pin_state.hostname` is unset and
# every lookup falls straight through to `_real_getaddrinfo` unchanged.
socket.getaddrinfo = _thread_pinned_getaddrinfo


class UnsafeUrlError(ValueError):
    """Raised instead of ever fetching a URL that resolves to a
    non-public address, or uses a disallowed scheme."""


def _is_blocked_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local  # covers 169.254.0.0/16, the cloud metadata range
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # `ip.is_private` does NOT cover every non-publicly-routable range --
        # confirmed live against this exact module, running inside the real
        # production container: `ipaddress.ip_address("100.64.0.1").is_private`
        # is False, so a hostname resolving anywhere in 100.64.0.0/10 (RFC
        # 6598 "Shared Address Space", reserved for carrier-grade NAT and
        # widely used inside cloud providers' own internal networks) sailed
        # straight past every check above and `assert_safe_public_url()`
        # reported it as a safe public address. `ip.is_global` *does* know
        # about this range (`is_global` is False for it) -- added as a
        # catch-all on top of, not instead of, the explicit checks above:
        # `ip.is_global` is also False for multicast (e.g. 224.0.0.1), which
        # the explicit `is_multicast` check above already correctly blocks,
        # so this can only ever block *more* addresses than before, never
        # fewer -- an OR of the two cannot un-block anything the old code
        # already caught.
        or not ip.is_global
    )


def _getaddrinfo_with_deadline(hostname: str, deadline: float):
    """Run the real, blocking `socket.getaddrinfo()` on a separate daemon
    thread and wait for it for at most whatever wall-clock budget remains
    before `deadline` -- see module docstring's sixth defense for the real
    bug this closes: `socket.getaddrinfo()` takes no timeout argument and
    can block far longer than any `timeout=` this module was given, if the
    hostname's authoritative nameserver simply never answers.

    `socket.getaddrinfo()` cannot be cancelled or interrupted once started
    (unlike the fifth defense's socket read, there is no live socket yet to
    shut down) -- a lookup still running when the budget runs out is
    abandoned, not killed: the background thread is left to finish (or
    hang) on its own, writing its eventual result into a queue nothing
    reads again. This is safe to abandon because it mutates no shared
    state and is a daemon thread, so it can never block process exit.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise UnsafeUrlError(f"Timed out resolving host {hostname!r}")

    result_q: "queue.Queue[tuple[str, object]]" = queue.Queue(maxsize=1)

    def _resolve():
        try:
            result_q.put(("ok", _real_getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)))
        except Exception as exc:  # re-raised on the waiting thread below
            result_q.put(("error", exc))

    threading.Thread(target=_resolve, daemon=True).start()
    try:
        kind, payload = result_q.get(timeout=remaining)
    except queue.Empty:
        raise UnsafeUrlError(
            f"Timed out resolving host {hostname!r} (DNS lookup exceeded "
            "the wall-clock fetch budget -- the lookup may still be running "
            "in the background against an unresponsive or deliberately "
            "slow-answering nameserver, but this request gives up on it "
            "rather than holding a worker thread open indefinitely)"
        )
    if kind == "error":
        raise UnsafeUrlError(f"Could not resolve host {hostname!r}") from payload
    return payload


def _resolve_and_validate(hostname: str, *, deadline: float | None = None) -> list[str]:
    """Resolve `hostname` exactly once and raise unless every address it
    maps to is public. Returns the validated IP *literals* -- not raw
    getaddrinfo() tuples, which embed a port (this validation call always
    asks with port=None, but the real connection may want 443/80/etc) --
    so a later connection can be pinned to these exact addresses without
    ever resolving the hostname a second time.

    `deadline` (a `time.monotonic()` timestamp), when given, bounds how
    long the resolution itself is allowed to take -- see module docstring's
    sixth defense. Omitted by `assert_safe_public_url()`, the standalone
    validator with no fetch and therefore no budget to bound against;
    always supplied by `fetch_public_url()`, the only caller reachable from
    a public request.
    """
    try:
        if deadline is None:
            addrinfo = _real_getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
        else:
            addrinfo = _getaddrinfo_with_deadline(hostname, deadline)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Could not resolve host {hostname!r}") from exc
    if not addrinfo:
        raise UnsafeUrlError(f"Host {hostname!r} resolved to no addresses")
    ips = []
    for info in addrinfo:
        ip_text = info[4][0]
        if _is_blocked_ip(ip_text):
            raise UnsafeUrlError(
                f"Host {hostname!r} resolves to a non-public address "
                f"({ip_text}); refusing to fetch internal infrastructure"
            )
        ips.append(ip_text)
    return ips


def assert_safe_public_url(url: str) -> None:
    """Raise UnsafeUrlError unless `url` is http(s) and every address its
    hostname resolves to is a public, non-internal IP.

    Standalone validation only -- does NOT protect against the DNS-
    rebinding bypass described above, because a caller that uses this and
    then separately opens its own connection will still re-resolve the
    hostname independently. `fetch_public_url()` below does not call this;
    it runs its own resolve-and-pin sequence so the hostname is only ever
    resolved once per request. Kept as a public helper only for pure
    validation use cases that never make a network request off the
    result.
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise UnsafeUrlError("URL has no hostname")
    _resolve_and_validate(parsed.hostname)


@contextmanager
def _pinned_resolution(hostname: str, validated_ips: list[str]):
    """For the duration of this context, any socket.getaddrinfo(hostname,
    ...) call made *by the current thread* is answered using only the
    already-validated `validated_ips`, instead of performing a fresh DNS
    lookup of `hostname` -- scoped per-thread (via `_pin_state`), not
    process-wide, so a concurrent fetch on another thread for a different
    hostname is never blocked on or affected by this one. Resolving a
    literal IP address (as opposed to a hostname) never performs a DNS
    query -- it's pure local formatting -- so re-running getaddrinfo per
    validated IP here to pick up whatever port/family/type the real
    caller actually asked for is still exactly one real hostname lookup
    total, with zero additional rebinding window."""
    _pin_state.hostname = hostname
    _pin_state.ips = validated_ips
    try:
        yield
    finally:
        _pin_state.hostname = None
        _pin_state.ips = None


def _force_close_socket(response: requests.Response) -> None:
    """Best-effort hard interrupt for a streaming read blocked inside
    `response.iter_content()` on *another* thread -- called only from the
    `threading.Timer` armed by `_read_capped` below, once `deadline` has
    actually passed.

    `response.close()` alone does not do this: confirmed live, calling it
    from a watchdog thread while the real reading thread was blocked
    inside a slow trickle had no effect at all until the trickle finished
    on its own -- `close()` just marks the response object closed for
    later use, it doesn't touch the live, already-blocked `recv()`.
    Reaching into the real underlying socket and calling the stdlib
    `shutdown(SHUT_RDWR)` on it does reliably interrupt that blocked read
    (confirmed live: raises on the reading thread within the timer's own
    delay, not after the attacker's trickle finishes) -- this is the
    standard way to cancel a blocking socket op from a different thread.

    The attribute path below is requests/urllib3/http.client internals,
    not a public API -- confirmed against this project's exact pinned
    versions (requests==2.34.2, urllib3==2.8.0, see requirements.txt). If
    a future dependency bump changes this shape, this becomes a silent
    no-op (broad except, by design) rather than a crash; re-verify this
    path still resolves whenever either pin moves.
    """
    try:
        response.raw._fp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass


def _read_capped(response: requests.Response, url: str, deadline: float) -> None:
    """Materialize `response`'s body into `.content`/`.text`, raising
    UnsafeUrlError and closing the connection instead of buffering past
    `_MAX_RESPONSE_BYTES` -- or past `deadline` (a `time.monotonic()`
    timestamp; see module docstring's fifth defense). Checks the declared
    Content-Length first (fast, no bytes transferred for an honest
    oversized response), then enforces the same byte cap against the real
    streamed byte count regardless, because a missing or understated
    Content-Length (chunked transfer, or just a lying server) must not be
    able to bypass it.

    The wall-clock deadline is enforced by arming a `threading.Timer` for
    whatever time remains, before the (potentially slow-trickled, blocking)
    read begins -- not just a check between chunks, which a server that
    also controls Content-Length can trivially dodge by declaring a body
    no bigger than one chunk (see module docstring's fifth defense for the
    live repro). If the timer fires, `_force_close_socket` interrupts the
    in-progress read from outside it, which surfaces here as a normal
    `requests.exceptions.RequestException` -- re-raised as `UnsafeUrlError`
    only when `deadline` had genuinely passed (anything else -- a real,
    unrelated connection drop before the deadline -- propagates as-is, same
    as before this fix existed). The timer is always cancelled in `finally`
    so the normal/fast case pays only the cost of arming + cancelling one
    timer, not any change to real throughput.
    """
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            declared = None
        if declared is not None and declared > _MAX_RESPONSE_BYTES:
            response.close()
            raise UnsafeUrlError(
                f"Response from {url!r} declares Content-Length "
                f"{declared} bytes, over the {_MAX_RESPONSE_BYTES}-byte "
                "fetch cap"
            )

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        response.close()
        raise UnsafeUrlError(
            f"Timed out fetching {url!r} (wall-clock budget exceeded "
            "before the response body could be read)"
        )
    timer = threading.Timer(remaining, _force_close_socket, args=(response,))
    timer.daemon = True
    timer.start()

    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=_FETCH_CHUNK_SIZE):
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                response.close()
                raise UnsafeUrlError(
                    f"Response from {url!r} exceeded the "
                    f"{_MAX_RESPONSE_BYTES}-byte fetch cap while streaming "
                    "(no Content-Length, or a lying one); refusing to "
                    "buffer an unbounded body into memory"
                )
            chunks.append(chunk)
    except requests.exceptions.RequestException as exc:
        if time.monotonic() >= deadline:
            raise UnsafeUrlError(
                f"Response from {url!r} took too long to fully download "
                "(wall-clock fetch budget exceeded while streaming -- each "
                "individual read was fast enough to dodge the socket "
                "timeout, but the total time was not, so the connection "
                "was forcibly closed); refusing to hold it open any longer"
            ) from exc
        raise
    finally:
        timer.cancel()
    response._content = b"".join(chunks)
    response._content_consumed = True


def fetch_public_url(
    url: str, *, headers: dict, timeout: int
) -> requests.Response:
    """requests.get(), but every redirect hop is resolved, validated, and
    then pinned to that exact validated address before the real request
    is made. Closes both the classic SSRF-via-redirect bypass (each hop
    is independently validated) and the SSRF-via-DNS-rebinding bypass
    (each hop's actual TCP connection reuses its own validation lookup
    instead of letting the HTTP client re-resolve the hostname a second
    time, independently, a moment later).

    `timeout` is treated as the real total wall-clock budget for the
    *whole* call (every redirect hop, every streamed chunk) -- not just
    the per-socket-read timeout `requests` itself enforces. See module
    docstring's fifth defense for why that distinction matters: a slow-
    trickling attacker server can dodge a plain `requests.get(timeout=...)`
    forever without this."""
    deadline = time.monotonic() + timeout
    current_url = url
    for _ in range(_MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UnsafeUrlError(
                f"Timed out fetching {url!r} (wall-clock budget of "
                f"{timeout}s exceeded)"
            )
        parsed = urlparse(current_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise UnsafeUrlError(f"Unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise UnsafeUrlError("URL has no hostname")

        addrinfo = _resolve_and_validate(parsed.hostname, deadline=deadline)
        with _pinned_resolution(parsed.hostname, addrinfo):
            response = requests.get(
                current_url,
                headers=headers,
                timeout=remaining,
                allow_redirects=False,
                stream=True,
            )

        if response.is_redirect or response.is_permanent_redirect:
            next_url = response.headers.get("Location")
            if not next_url:
                # No Location to follow -- same edge case as before this
                # cap existed; still materialize (capped) so raise_for_status
                # and any later .text/.content access on the returned
                # response work.
                _read_capped(response, current_url, deadline)
                response.raise_for_status()
                return response
            response.close()  # redirect hop's own body is never used
            current_url = requests.compat.urljoin(current_url, next_url)
            continue
        _read_capped(response, current_url, deadline)
        return response
    raise UnsafeUrlError(f"Too many redirects fetching {url!r}")
