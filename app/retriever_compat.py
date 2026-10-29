"""Workaround for a real upstream bug: gpt-researcher's vendored DuckDuckGo
retriever hardcodes `region="wt-wt"` (ddgs/duckduckgo-search's own sentinel
for "no region"). In `ddgs==9.16.1`, passing that region triggers a spurious
DNS lookup of a hostname that does not exist anywhere
(`wt.wikipedia.org` -- NXDOMAIN against public resolvers; confirmed with
`dig`), apparently an internal spell-check/suggestion step. The failure mode
depends on the resolver: on a resolver with a configured search domain
(this portfolio's Docker containers on the Oracle box have
`search vcn12041922.oraclevcn.com`; a sandboxed Mac dev shell had its own
`.local` search domain), the NXDOMAIN gets re-tried against
`wt.wikipedia.org.<search-domain>` and raises a DNSError that aborts the
*entire* ddgs call -- not a rate limit, not a credits problem, not a "the
query had zero real results" case.

gpt_researcher.retrievers.duckduckgo.duckduckgo.Duckduckgo.search() already
swallows that exception into an empty list (its own bug: silent, no
logging beyond a print), which is exactly what made this look like "the
free retriever is flaky" throughout this product's development -- it
reproduced on every single live run, every environment, 100% of the time
`region="wt-wt"` was passed, and 0% of the time when omitted (verified live
both on a dev Mac and on the production Oracle box, 2026-10-29).

Confirmed fix: omit `region` entirely (ddgs defaults to its own unregioned
behavior, which returns normal results). This module monkeypatches
Duckduckgo.search to do exactly that. Applied unconditionally -- this is a
straight bug fix, not an environment-specific opt-in like llm_compat.py.
"""
from __future__ import annotations


def apply() -> None:
    from gpt_researcher.retrievers.duckduckgo import duckduckgo as dd_module

    if getattr(dd_module.Duckduckgo, "_wedgecheck_no_region_patch", False):
        return

    def _search(self, max_results: int = 5):
        try:
            return self.ddg.text(self.query, max_results=max_results)
        except Exception as exc:  # pragma: no cover - mirrors upstream's own fallback
            print(f"Error: {exc}. Failed fetching sources. Resulting in empty response.")
            return []

    dd_module.Duckduckgo.search = _search
    dd_module.Duckduckgo._wedgecheck_no_region_patch = True
