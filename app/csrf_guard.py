"""Lightweight CSRF defense for `POST /`, the one cookie-backed,
state-changing, compute-costing endpoint in this app.

Confirmed live against the real production site (2026-10-29): a plain
cross-site `POST /` with a forged `Origin`/`Referer` (e.g.
`Origin: https://evil.example`) is processed exactly like a same-site
submission -- it reaches `rate_limit.check()` and, had quota been
available, would have gone on to trigger a real 60-120s gpt-researcher
pass (real spend on the shared `ai-relay-worker` relay, also used by
Huddle) and a real `store.save_brief()` write, all tied to whichever
browser's session cookie and client IP happened to submit it. Nothing
anywhere in `main.py` or `rate_limit.py` ever inspects `Origin`/`Referer`
-- grepped for both, confirmed absent.

This is a real, exploitable CSRF gap, not a theoretical one: a page an
attacker controls can embed

    <form action="https://wedgecheck.ereboslab.com/" method="POST">
      <input name="description" value="...">
    </form>
    <script>document.forms[0].submit()</script>

and any visitor's browser will silently fire a real, compute-costing
`POST /` the instant they load that page -- burning *that visitor's* own
per-IP rate-limit budget (`rate_limit.py`, 3 requests / 10 minutes) and
real shared-relay spend, with zero user intent or awareness. `SameSite=
lax` on the session cookie (`main.py`) stops the *cookie* from riding
along (so the forged submission lands in a brand-new anonymous session,
not the victim's real one) but does nothing to stop the POST itself from
being accepted and processed -- `SameSite` and CSRF-via-Origin-check are
complementary defenses, not substitutes for each other, and this app had
neither of the latter.

Deliberately scoped to `POST /` only, not `/api/brief`: the JSON API is
intentionally a public endpoint meant to be called by arbitrary non-
browser HTTP clients (curl, scripts, this product's own `cli.py`-adjacent
callers) with no `Origin` header at all, and it never ties a request to
an existing session cookie (`save_brief(..., session_id=None)`), so there
is no cross-site *browser* privilege to forge in the first place.

Modern browsers send a real `Origin` header on every cross-site request
and, since Chrome 76 / Firefox 92+ (`sec-fetch-*`/Origin-on-POST
behavior), on same-site POSTs too -- so checking it when present is a
reliable, zero-new-dependency CSRF defense (the same "verify Origin with
standard headers" technique OWASP documents as the lightweight
alternative to a synchronizer token when there's no per-session secret to
embed in the form). Only *rejects* when `Origin`/`Referer` is present and
names a different host; a request with neither header (a non-browser
client, or an old browser) is let through unchanged -- this app has no
authenticated/privileged state to protect beyond "which anonymous
session/IP pays for this compute", so failing open on a *missing* header
is the right tradeoff, not a silent downgrade of a real protection.
"""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import HTTPException, Request


def assert_same_site(request: Request) -> None:
    """Raise HTTPException(403) if `Origin` or `Referer` is present and
    names a host other than the one that served this request.

    Checked by `main.py`'s `submit()` *before* `rate_limit.check()` --
    a forged cross-site submission must not spend the real client's rate-
    limit quota before being rejected.
    """
    expected_host = request.url.hostname
    for header_name in ("origin", "referer"):
        value = request.headers.get(header_name)
        if not value:
            continue
        stripped = value.strip()
        if stripped.lower() == "null":
            # A real browser sends the literal string "null" as Origin
            # from a sandboxed iframe/opaque-origin context -- never a
            # legitimate same-site form submission, and exactly the kind
            # of context an attacker can trivially construct
            # (`<iframe sandbox="allow-scripts allow-forms">`) specifically
            # to dodge a naive "does the host match" check. Treat it as a
            # mismatch, not a pass-through.
            raise HTTPException(
                403,
                "Cross-site form submission blocked (opaque Origin) -- "
                "POST / only accepts same-site submissions.",
            )
        candidate_host = urlparse(stripped).hostname
        if candidate_host and candidate_host != expected_host:
            raise HTTPException(
                403,
                "Cross-site form submission blocked (Origin/Referer did "
                "not match this site) -- POST / only accepts same-site "
                "submissions.",
            )
