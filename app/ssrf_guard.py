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
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
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


def _resolve_and_validate(hostname: str) -> list[str]:
    """Resolve `hostname` exactly once and raise unless every address it
    maps to is public. Returns the validated IP *literals* -- not raw
    getaddrinfo() tuples, which embed a port (this validation call always
    asks with port=None, but the real connection may want 443/80/etc) --
    so a later connection can be pinned to these exact addresses without
    ever resolving the hostname a second time."""
    try:
        addrinfo = _real_getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
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


def _read_capped(response: requests.Response, url: str) -> None:
    """Materialize `response`'s body into `.content`/`.text`, raising
    UnsafeUrlError and closing the connection instead of buffering past
    `_MAX_RESPONSE_BYTES`. Checks the declared Content-Length first (fast,
    no bytes transferred for an honest oversized response), then enforces
    the same cap against the real streamed byte count regardless, because
    a missing or understated Content-Length (chunked transfer, or just a
    lying server) must not be able to bypass it."""
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

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=_FETCH_CHUNK_SIZE):
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            response.close()
            raise UnsafeUrlError(
                f"Response from {url!r} exceeded the {_MAX_RESPONSE_BYTES}-"
                "byte fetch cap while streaming (no Content-Length, or a "
                "lying one); refusing to buffer an unbounded body into "
                "memory"
            )
        chunks.append(chunk)
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
    time, independently, a moment later)."""
    current_url = url
    for _ in range(_MAX_REDIRECTS + 1):
        parsed = urlparse(current_url)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise UnsafeUrlError(f"Unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise UnsafeUrlError("URL has no hostname")

        addrinfo = _resolve_and_validate(parsed.hostname)
        with _pinned_resolution(parsed.hostname, addrinfo):
            response = requests.get(
                current_url,
                headers=headers,
                timeout=timeout,
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
                _read_capped(response, current_url)
                response.raise_for_status()
                return response
            response.close()  # redirect hop's own body is never used
            current_url = requests.compat.urljoin(current_url, next_url)
            continue
        _read_capped(response, current_url)
        return response
    raise UnsafeUrlError(f"Too many redirects fetching {url!r}")
