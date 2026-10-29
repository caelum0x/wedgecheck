"""Turn a raw URL or free-text description into a real research subject.

No LLM is used here on purpose -- this is plain HTTP + HTML parsing so the
"what is this product" step never hallucinates. If the page can't be
fetched *and the caller gave no description either*, we fail loudly rather
than inventing a description. But if the caller gave both (the web form's
own label reads "Product URL (optional if you give a description)", and
`ProductInput.research_subject()` already treats `raw_description` as the
designed fallback for an empty `resolved_summary`), a url that is
unreachable, blocked by the SSRF guard, or returns a non-2xx status must
fall back to the real description instead of discarding it and failing the
whole request -- confirmed live this was NOT happening before: a DNS
failure, a 404, and an SSRF block each raised immediately even with a
perfectly good `description` already in hand.

The URL fetch goes through ssrf_guard.fetch_public_url(), not a bare
requests.get() -- this is a public, unauthenticated endpoint (the web
form and /api/brief both take an arbitrary `url`), so without that guard
anyone could make this box fetch its own internal infrastructure (other
containers, loopback services, the cloud metadata address). See
ssrf_guard.py's docstring for the real, reproduced-live vulnerability
this closes.

Both `url` and `description` are also length-capped here, before either
one is used for anything. Neither had any limit anywhere in the app:
`description` goes straight into the research query handed to
gpt-researcher (`brief.py`'s `_QUERY_TEMPLATE`), which fans it out across
several concurrent sub-queries to this portfolio's shared free LLM relay
(ai-relay-worker, also used by Huddle) and then persists the result in
sqlite (`store.py`) forever. The existing rate limiter (`rate_limit.py`)
only bounds *how many* requests a client can make, not how large any one
of them is -- a single request, well within the 3-per-10-minute budget,
with a multi-megabyte `description` would still blow up real compute
and token spend on the shared relay, bloat the sqlite store, and hold
that whole string in memory on the single 512MB uvicorn worker for the
length of a 60-120s research pass. `url` is capped too, matching the
standard real-world max URL length browsers/servers already enforce
(RFC 7230 gives no hard limit, but no legitimate product URL needs more
than a couple thousand characters) so a garbage multi-megabyte "url"
can't reach even the SSRF guard's own DNS resolution step.
"""
from __future__ import annotations

import os

import requests
from bs4 import BeautifulSoup

from .schema import ProductInput
from .ssrf_guard import UnsafeUrlError, fetch_public_url

_USER_AGENT = "Wedgecheck/0.1 (+https://github.com/caelum0x/wedgecheck)"
_TIMEOUT_SECONDS = 15
_MAX_SUMMARY_CHARS = 1200
# No real <title> needs more than this -- browsers themselves truncate tab
# titles well under 100 chars, and nothing legitimate on the web ships a
# multi-KB <title>. Reproduced live (2026-10-29): resolved_title is the one
# extracted field that skips the summary join's own [:_MAX_SUMMARY_CHARS]
# truncation below -- it's assigned straight from `title_tag.get_text()`
# and stored/rendered completely separately (ProductInput.resolved_title,
# store.py's own `resolved_title` column, and the bare `{{ result.
# resolved_title }}`/`{{ b.resolved_title }}` in index.html/history.html).
# A page whose <title> is a few MB of garbage -- well under the *response*
# fetch cap (ssrf_guard.py's `_MAX_RESPONSE_BYTES`, 5MB, which has no
# reason to block a request like this at all) -- gets extracted in full,
# persisted forever in sqlite (store.save_brief has no length check either),
# and re-rendered on every future view of that permalink, which is public
# by design and never expires. Confirmed with a real ~4.8MB <title>: the
# sqlite row it created was ~4.8MB on disk, and the real index.html
# template (same Jinja2Templates instance /b/{id} uses) rendered a ~4.8MB
# HTML page from it -- on a box already noted elsewhere as 91% disk used /
# 9.1GB free, and within the existing 3-requests/10-min rate limit, that's
# a few hundred MB/day of real, permanent, publicly-served bloat from one
# attacker, for a field no legitimate page ever needs more than ~100
# visible characters of.
_MAX_TITLE_CHARS = 300
_MAX_URL_CHARS = int(os.getenv("WEDGECHECK_MAX_URL_CHARS", "2048"))
_MAX_DESCRIPTION_CHARS = int(os.getenv("WEDGECHECK_MAX_DESCRIPTION_CHARS", "4000"))


def _first_meaningful_paragraph(soup: BeautifulSoup) -> str | None:
    for p in soup.find_all(["p", "h1", "h2"]):
        text = p.get_text(strip=True)
        if text and len(text) > 40:
            return text
    return None


def build_product_input(
    *, url: str | None, description: str | None
) -> ProductInput:
    if not url and not description:
        raise ValueError("Provide either a product url or a description")

    if url and len(url) > _MAX_URL_CHARS:
        raise ValueError(
            f"url is too long ({len(url)} chars, max {_MAX_URL_CHARS})"
        )
    if description and len(description) > _MAX_DESCRIPTION_CHARS:
        raise ValueError(
            f"description is too long ({len(description)} chars, max "
            f"{_MAX_DESCRIPTION_CHARS}) -- summarize it instead"
        )

    title: str | None = None
    summary: str | None = None

    if url:
        try:
            response = fetch_public_url(
                url, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT_SECONDS
            )
            response.raise_for_status()
        except (UnsafeUrlError, requests.RequestException) as exc:
            # The URL itself couldn't be fetched or extracted (SSRF block,
            # DNS failure, timeout, non-2xx status, ...) -- NOT the same as
            # "fetched fine but had no extractable text" below, but it must
            # be handled the same way: if the caller also gave a real
            # description, that's a genuine, usable fallback (exactly what
            # ProductInput.research_subject() already falls back to, and
            # exactly what the web form's own "Product URL (optional if you
            # give a description)" label promises) rather than discarding a
            # perfectly good description just because the url happened to be
            # unreachable/blocked/stale. Only raise -- and only with this
            # url-specific error, not a generic one -- when there's truly
            # nothing else to fall back to.
            if description:
                return ProductInput(
                    raw_url=url,
                    raw_description=description,
                    resolved_title=None,
                    resolved_summary=description,
                )
            raise ValueError(str(exc)) from exc

        soup = BeautifulSoup(response.text, "html.parser")

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True)[:_MAX_TITLE_CHARS] if title_tag else None

        meta_description = soup.find("meta", attrs={"name": "description"})
        og_description = soup.find("meta", attrs={"property": "og:description"})
        description_text = None
        if meta_description and meta_description.get("content"):
            description_text = meta_description["content"].strip()
        elif og_description and og_description.get("content"):
            description_text = og_description["content"].strip()

        body_text = _first_meaningful_paragraph(soup)

        parts = [p for p in [title, description_text, body_text] if p]
        summary = " -- ".join(parts)[:_MAX_SUMMARY_CHARS] if parts else None

        if not summary and description:
            summary = description
        if not summary:
            raise ValueError(
                f"Could not extract any usable text from {url}; "
                "pass --description instead"
            )

    return ProductInput(
        raw_url=url,
        raw_description=description,
        resolved_title=title,
        resolved_summary=summary,
    )
