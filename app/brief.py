"""Core Wedgecheck flow: product input -> sourced market brief.

The research/citation step is entirely gpt-researcher (Apache-2.0,
https://github.com/assafelovic/gpt-researcher). This file only builds the
query we hand it and reshapes its output into MarketBrief. No fact in the
output is written by Wedgecheck's own code -- every claim comes from
gpt-researcher's web-grounded report, cited to real source URLs.

gpt-researcher fires several sub-queries concurrently against the retriever
(see gpt_researcher/skills/researcher.py's asyncio.gather fan-out). The free
"duckduckgo" retriever (ddgs) has no retry of its own and silently swallows
any error into an empty result list (see
gpt_researcher/retrievers/duckduckgo/duckduckgo.py), so zero sources can come
back for the *whole* report with no exception raised anywhere. Left
unchecked, that produces a confident-looking but entirely unsourced report --
the exact failure this product exists to prevent. generate_market_brief()
below retries the full research pass (a fresh GPTResearcher -> fresh
retriever session) with a backoff on an empty source list, and raises
WedgecheckResearchError instead of returning an unsourced MarketBrief if
every attempt still comes back empty.

Retrying does NOT reliably fix this, and the error message below must not
claim otherwise. An earlier version of this module (and this comment)
assumed the cause was "a transient rate limit," written before
retriever_compat.py's real root-cause fix (the ddgs `region="wt-wt"` DNS bug,
which *was* a 100%-reproducible hard failure, now patched out). Once that bug
was fixed, "0 sources after N attempts" kept happening anyway on certain
phrasings -- confirmed live, twice, in two separate sessions, against the
identical description ("a simple habit tracker app for iOS") returning 0
sources on every one of 3 attempts both times. A rate limit would not fail
the exact same query deterministically across separate sessions; this is the
free DuckDuckGo HTML retriever's own low recall on some phrasings, which
retrying the identical query does not fix. Rephrasing the query or setting
RETRIEVER=tavily are the two things that actually help.
"""
from __future__ import annotations

import asyncio
import logging

from gpt_researcher import GPTResearcher

from .config import WedgecheckConfig
from .errors import WedgecheckResearchError
from .product_input import build_product_input
from .schema import MarketBrief

logger = logging.getLogger("wedgecheck.brief")

_QUERY_TEMPLATE = """\
Market and competitive brief for the following product/business:

{subject}

Research and report, with every factual claim grounded in a cited source:
1. Market signal: what real people search for or complain about in this
   space (forums, review sites, search trends) -- evidence that the pain
   point is real, not assumed.
2. Named, real competitors or alternatives, with their pricing if findable.
3. Common complaints/gaps in those competitors' own reviews or docs.
4. A specific, underserved positioning gap this product could own.

Do not invent competitors, numbers, or quotes. If a figure cannot be
sourced, say so explicitly instead of estimating silently.
"""


async def _run_one_research_attempt(
    query: str,
) -> tuple[str, list[str], float]:
    """One full gpt-researcher pass. A fresh GPTResearcher per attempt means
    a fresh retriever session, so a rate-limited DuckDuckGo burst on one
    attempt doesn't carry over into the retry."""
    researcher = GPTResearcher(query=query, report_type="research_report")
    await researcher.conduct_research()
    report_markdown = await researcher.write_report()

    costs = researcher.get_costs()
    cost_usd = float(costs) if isinstance(costs, (int, float)) else 0.0
    source_urls = researcher.get_source_urls()
    return report_markdown, source_urls, cost_usd


async def generate_market_brief(
    *,
    url: str | None,
    description: str | None,
    config: WedgecheckConfig | None = None,
) -> MarketBrief:
    cfg = config or WedgecheckConfig.from_env()
    cfg.apply_to_environ()

    # build_product_input() does a synchronous `requests.get()` (see
    # product_input.py) -- called directly from this async function it would
    # block the entire single-worker event loop (and therefore every other
    # concurrent request, including /healthz) for up to its own 15s timeout.
    # Confirmed live: a URL pointed at a slow-responding page froze a
    # concurrent /healthz call for ~7.6s. Run it in a thread instead.
    product_input = await asyncio.to_thread(
        build_product_input, url=url, description=description
    )
    query = _QUERY_TEMPLATE.format(subject=product_input.research_subject())

    last_report_markdown = ""
    last_cost_usd = 0.0
    attempts = max(1, cfg.research_max_attempts)

    for attempt in range(1, attempts + 1):
        report_markdown, source_urls, cost_usd = await _run_one_research_attempt(query)
        last_report_markdown, last_cost_usd = report_markdown, cost_usd

        if source_urls:
            if attempt > 1:
                logger.info(
                    "wedgecheck: research recovered %d source(s) on attempt %d/%d",
                    len(source_urls),
                    attempt,
                    attempts,
                )
            return MarketBrief(
                input=product_input,
                report_markdown=report_markdown,
                source_urls=source_urls,
                research_cost_usd=cost_usd,
            )

        logger.warning(
            "wedgecheck: research attempt %d/%d returned 0 source URLs "
            "(retriever=%s) -- usually the free retriever's own low recall "
            "on this phrasing, not a rate limit; retrying the identical "
            "query rarely recovers it",
            attempt,
            attempts,
            cfg.retriever,
        )
        if attempt < attempts:
            await asyncio.sleep(cfg.research_retry_backoff_seconds * attempt)

    raise WedgecheckResearchError(
        f"gpt-researcher returned 0 source URLs after {attempts} attempt(s) "
        f"using retriever={cfg.retriever!r}. Refusing to return an unsourced "
        "report -- every Wedgecheck claim must be grounded in a real source. "
        "This is usually the free retriever's own low recall on this exact "
        "phrasing (not a rate limit -- retrying the same wording rarely "
        "helps); try rephrasing the description, or set RETRIEVER to a "
        "different gpt-researcher retriever (e.g. tavily, with "
        "TAVILY_API_KEY set) for more reliable results. (Research cost so "
        f"far: ${last_cost_usd:.4f}; last report was "
        f"{len(last_report_markdown)} chars, discarded.)"
    )
