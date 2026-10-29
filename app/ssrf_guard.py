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

Two defenses, both required:
1. Scheme must be http/https (blocks `file://`, custom handlers, etc).
2. Every IP the hostname resolves to must be a real public, routable
   address -- not loopback, private (RFC1918), link-local (incl. the
   cloud-metadata /16), multicast, reserved, or unspecified.

Because step 2 only validates the *first* request, a 3xx redirect to a
blocked address would otherwise bypass it (classic SSRF-via-redirect).
`fetch_public_url()` therefore follows redirects itself, one hop at a
time, re-validating the new target before every single request --
`requests`' own `allow_redirects=True` is never used here.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_REDIRECTS = 5


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


def assert_safe_public_url(url: str) -> None:
    """Raise UnsafeUrlError unless `url` is http(s) and every address its
    hostname resolves to is a public, non-internal IP. Call this again
    before *each* request in a redirect chain -- never trust a prior
    check for a new URL."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise UnsafeUrlError("URL has no hostname")

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Could not resolve host {parsed.hostname!r}") from exc

    resolved_ips = {info[4][0] for info in addrinfo}
    if not resolved_ips:
        raise UnsafeUrlError(f"Host {parsed.hostname!r} resolved to no addresses")
    for ip_text in resolved_ips:
        if _is_blocked_ip(ip_text):
            raise UnsafeUrlError(
                f"Host {parsed.hostname!r} resolves to a non-public address "
                f"({ip_text}); refusing to fetch internal infrastructure"
            )


def fetch_public_url(
    url: str, *, headers: dict, timeout: int
) -> requests.Response:
    """requests.get(), but re-validated before every redirect hop so a
    public-looking URL can't 3xx its way into an internal address."""
    current_url = url
    for _ in range(_MAX_REDIRECTS + 1):
        assert_safe_public_url(current_url)
        response = requests.get(
            current_url, headers=headers, timeout=timeout, allow_redirects=False
        )
        if response.is_redirect or response.is_permanent_redirect:
            next_url = response.headers.get("Location")
            if not next_url:
                response.raise_for_status()
                return response
            current_url = requests.compat.urljoin(current_url, next_url)
            continue
        return response
    raise UnsafeUrlError(f"Too many redirects fetching {url!r}")
