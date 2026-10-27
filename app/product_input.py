"""Turn a raw URL or free-text description into a real research subject.

No LLM is used here on purpose -- this is plain HTTP + HTML parsing so the
"what is this product" step never hallucinates. If the page can't be
fetched, we fail loudly rather than inventing a description.
"""
from __future__ import annotations

import requests
from bs4 import BeautifulSoup

from .schema import ProductInput

_USER_AGENT = "Wedgecheck/0.1 (+https://github.com/caelum0x/wedgecheck)"
_TIMEOUT_SECONDS = 15
_MAX_SUMMARY_CHARS = 1200


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

    title: str | None = None
    summary: str | None = None

    if url:
        response = requests.get(
            url, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT_SECONDS
        )
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
