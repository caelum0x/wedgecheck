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
   cloud-metadata /16), multicast, reserved, or unspecified.
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

# socket.getaddrinfo is a single process-global function (urllib3's own
# create_connection() calls the module-qualified `socket.getaddrinfo`, not
# a name bound at its own import time, which is exactly what makes
# pinning it from here effective). This app runs each brief's synchronous
# URL fetch in its own worker thread (asyncio.to_thread, see brief.py), so
# two concurrent fetch_public_url() calls could otherwise install and tear
# down competing monkeypatches on that shared global mid-flight -- this
# lock serializes just the resolve-pin-request sequence (bounded by
# `timeout` per redirect hop, _MAX_REDIRECTS hops max) across threads, not
# the rest of the 60-120s research pass.
_dns_pin_lock = threading.Lock()


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
    )


def _resolve_and_validate(hostname: str) -> list[str]:
    """Resolve `hostname` exactly once and raise unless every address it
    maps to is public. Returns the validated IP *literals* -- not raw
    getaddrinfo() tuples, which embed a port (this validation call always
    asks with port=None, but the real connection may want 443/80/etc) --
    so a later connection can be pinned to these exact addresses without
    ever resolving the hostname a second time."""
    try:
        addrinfo = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
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
    ...) call anywhere in this process is answered using only the
    already-validated `validated_ips`, instead of performing a fresh DNS
    lookup of `hostname`. Resolving a literal IP address (as opposed to a
    hostname) never performs a DNS query -- it's pure local formatting --
    so re-running getaddrinfo per validated IP here to pick up whatever
    port/family/type the real caller actually asked for is still exactly
    one real hostname lookup total, with zero additional rebinding
    window. Caller must hold _dns_pin_lock -- see module docstring."""
    real_getaddrinfo = socket.getaddrinfo

    def _patched(host, port=None, family=0, type=0, proto=0, flags=0):
        if host != hostname:
            return real_getaddrinfo(host, port, family, type, proto, flags)
        results = []
        for ip in validated_ips:
            results.extend(real_getaddrinfo(ip, port, family, type, proto, flags))
        return results

    socket.getaddrinfo = _patched
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo


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

        with _dns_pin_lock:
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
