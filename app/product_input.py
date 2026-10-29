"""Turn a raw URL or free-text description into a real research subject.

No LLM is used here on purpose -- this is plain HTTP + HTML parsing so the
"what is this product" step never hallucinates. If the page can't be
fetched, we fail loudly rather than inventing a description.

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

from bs4 import BeautifulSoup

from .schema import ProductInput
from .ssrf_guard import UnsafeUrlError, fetch_public_url

_USER_AGENT = "Wedgecheck/0.1 (+https://github.com/caelum0x/wedgecheck)"
_TIMEOUT_SECONDS = 15
_MAX_SUMMARY_CHARS = 1200
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
        except UnsafeUrlError as exc:
            raise ValueError(str(exc)) from exc
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else None

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
