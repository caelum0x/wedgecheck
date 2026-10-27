# Wedgecheck

Wedgecheck turns a product URL or a one-line description into a **sourced**
market/competitive brief: real search-volume/complaint signal, named real
competitors with pricing where findable, their common gaps, and a specific
positioning gap — every claim cited to a real source URL, never invented.

The research and citation engine is entirely
[gpt-researcher](https://github.com/assafelovic/gpt-researcher) (Apache-2.0).
Wedgecheck's own code only does two things:

1. `app/product_input.py` — turns a URL into real extracted text (plain HTTP
   + HTML parsing, no LLM) so "what is this product" never hallucinates.
2. `app/brief.py` — builds the research query, retries the research pass if
   the retriever comes back with zero sources (see below), and refuses to
   hand back an unsourced report.

## Why the retry logic exists

gpt-researcher fires several sub-queries concurrently. The free
`duckduckgo` retriever (`ddgs`) has no retry of its own and silently turns
any error into an empty result list — a transient rate limit on that
concurrent burst can come back as **zero sources for the whole report, with
no exception raised anywhere**. Left unchecked this produces a confident,
detailed, fully invented report with "Sources (0)" quietly sitting at the
bottom — the exact failure this product exists to prevent.

`generate_market_brief()` retries the full research pass (a fresh
`GPTResearcher`, so a fresh retriever session) with backoff whenever a pass
comes back with zero source URLs, and raises `WedgecheckResearchError`
instead of returning an unsourced `MarketBrief` if every attempt still comes
back empty. Tunable via env: `WEDGECHECK_RESEARCH_MAX_ATTEMPTS` (default 3),
`WEDGECHECK_RESEARCH_RETRY_BACKOFF_SECONDS` (default 4).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set at minimum an OpenAI-compatible chat-completions endpoint:

```bash
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://openrouter.ai/api/v1   # or any OpenAI-compatible gateway
```

No paid retriever key is required — `RETRIEVER` defaults to `duckduckgo`
(free, no key). For more reliable results than the free retriever, set
`RETRIEVER=tavily` and `TAVILY_API_KEY=...`.

## Usage

CLI:

```bash
python cli.py --url https://example.com
python cli.py --description "A hosted Postgres backend for indie SaaS teams"
```

Writes `<slug>.md` and `<slug>.json` under `./output/`.

Web app:

```bash
uvicorn app.main:app --reload
```

`GET /` — single-form UI. `POST /api/brief` — JSON API
(`{"url": "..."}` or `{"description": "..."}`). `GET /healthz` — health check.

## Status

Early-stage, self-hosted, no deploy yet. Known current blocker: the
OpenRouter key used in dev has exhausted credits (owner billing step, not a
code issue) — the retry/fail-loud logic above is verified against a mocked
research engine (both the "recovers on retry" and "fails loud after
exhausting retries" paths), not yet against a full live run end-to-end,
pending that credit top-up.
