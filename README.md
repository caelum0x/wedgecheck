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

### Fully free self-host (no paid key at all)

Production (`wedgecheck.ereboslab.com`) runs with **no paid LLM key** —
`OPENAI_BASE_URL` points at this portfolio's own free Cloudflare Workers AI
relay instead of OpenRouter/OpenAI:

```bash
export OPENAI_API_KEY=<the relay's low-value AI_RELAY_KEY>
export OPENAI_BASE_URL=https://ai-relay.subasiarhan3.workers.dev/v1
export EMBEDDING=custom:bge          # relay's /v1/embeddings route (Workers AI bge-base-en-v1.5)
export WEDGECHECK_NON_STREAMING_LLM=1
```

Two things make this work that are easy to miss if you swap in a different
minimal relay:

- The relay always answers a flat JSON body even when the request says
  `"stream": true` (no real SSE). gpt-researcher's report writer always
  requests streaming, so without `WEDGECHECK_NON_STREAMING_LLM=1`
  (`app/llm_compat.py`) you'll see `No generation chunks were returned`.
- gpt-researcher's embedding step defaults to a paid
  `openai:text-embedding-3-small`. `EMBEDDING=custom:bge` routes it at the
  relay's `/v1/embeddings` route instead, so the image never needs
  torch/sentence-transformers.

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

Every completed brief (web form or `/api/brief`) is persisted to a local
SQLite DB (`app/store.py`, path via `WEDGECHECK_DB_PATH`, default
`./data/wedgecheck.db`) so it isn't lost after one request/session:

- `GET /b/{id}` — a shareable permalink for one completed report. The
  `/api/brief` JSON response now includes `id` and `permalink_url`.
  Permalinks are public by id (no auth) — see `app/store.py`'s docstring
  for why that's the right tradeoff here.
- `GET /history` — a browser's own past briefs, scoped to an anonymous
  session cookie (`wedgecheck_session`, no account system). Linked from
  every page's nav.

In Docker, mount a volume at `/app/data` or these survive only until the
next container recreate.

`POST /` and `POST /api/brief` are rate-limited per client IP (read from
`X-Forwarded-For`, falling back to the raw socket peer) — each one is a real
60–120s research pass against the shared LLM relay, so an unlimited public
endpoint is a real abuse/cost vector, not a hypothetical one. Default: 3
requests per 10 minutes per IP, both tunable
(`WEDGECHECK_RATE_LIMIT_MAX_REQUESTS`, `WEDGECHECK_RATE_LIMIT_WINDOW_SECONDS`).
Exceeding it returns `429` with a `Retry-After` header (JSON for the API, a
friendly banner for the form). See `app/rate_limit.py`.

The `url` fetch (web form or `/api/brief`) also enforces a response-size
cap, independent of the SSRF checks: a URL can resolve to a perfectly
public address and still serve an unbounded body, which would otherwise be
buffered in full into this single-worker container's memory. Default 5MB,
tunable via `WEDGECHECK_MAX_FETCH_BYTES`; enforced against both the
declared `Content-Length` and the real streamed byte count, so a missing
or lying header can't bypass it. See `app/ssrf_guard.py`.

Both `url` and `description` (web form or `/api/brief`) are length-capped
before either is used for anything — the rate limiter above only bounds
*how many* requests a client can make, not how large one is, and an
oversized `description` would still be handed straight to gpt-researcher
(real compute/token spend on the shared LLM relay) and persisted to
sqlite forever. Defaults: 2048 chars for `url`, 4000 chars for
`description`, tunable via `WEDGECHECK_MAX_URL_CHARS` /
`WEDGECHECK_MAX_DESCRIPTION_CHARS`. See `app/product_input.py`.

## Status

Live at `https://wedgecheck.ereboslab.com` (Docker on the Oracle box,
`/opt/infra-box/stacks/wedgecheck`). Verified end-to-end against the real
code path, not a mock: the retry/fail-loud logic in `app/brief.py` has been
exercised live, repeatedly, and correctly discards an LLM-written report
whenever the free `duckduckgo` retriever comes back with zero real sources
on every attempt (raising `WedgecheckResearchError`) rather than ever
serving a confidently-written but unsourced brief.

A full success case (non-zero `source_urls`, no exception) depends on the
free `duckduckgo`/`ddgs` retriever actually returning results for the given
query at request time, which it does not always do. See
`~/products/plans/wedgecheck.md` for the live evidence and what's still
worth doing about retriever reliability (e.g. `RETRIEVER=tavily`).
