#!/usr/bin/env python3
"""Wedgecheck CLI: generate a sourced market brief from a URL or description.

Usage:
    python cli.py --url https://example.com
    python cli.py --description "A hosted Postgres backend for indie SaaS teams"

Writes <slug>.md and <slug>.json under ./output/.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

from app.brief import generate_market_brief

OUTPUT_DIR = Path(__file__).parent / "output"


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:60] or "brief"


async def _run(url: str | None, description: str | None) -> None:
    brief = await generate_market_brief(url=url, description=description)

    OUTPUT_DIR.mkdir(exist_ok=True)
    slug = _slugify(url or description or "brief")

    md_path = OUTPUT_DIR / f"{slug}.md"
    json_path = OUTPUT_DIR / f"{slug}.json"

    md_path.write_text(brief.report_markdown, encoding="utf-8")
    json_path.write_text(json.dumps(brief.to_dict(), indent=2), encoding="utf-8")

    print(f"\nWrote {md_path}")
    print(f"Wrote {json_path}")
    print(f"\nSources cited ({len(brief.source_urls)}):")
    for s in brief.source_urls:
        print(f"  - {s}")
    print(f"\nResearch cost: ${brief.research_cost_usd:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", help="Product/landing-page URL to research")
    parser.add_argument("--description", help="Plain-text product description")
    args = parser.parse_args()

    if not args.url and not args.description:
        parser.error("pass --url or --description")

    try:
        asyncio.run(_run(args.url, args.description))
    except Exception as exc:  # surface real errors, never swallow them
        print(f"Wedgecheck failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
