"""Compatibility shim for OpenAI-compatible LLM endpoints that don't support
real SSE streaming.

gpt-researcher's report-writing step (gpt_researcher/actions/report_generation.py)
always calls the chat model with stream=True and consumes the response via
langchain's `ChatOpenAI.astream()`, which expects real `text/event-stream`
chunks. Pointed at a minimal relay that always returns one flat JSON body
regardless of the `stream` flag in the request (e.g. this portfolio's free
Cloudflare Workers AI relay, which forwards to Workers AI / Groq and shapes
a single `{choices: [...]}` response), `astream()` raises:

    No generation chunks were returned

This is not a credits/auth problem -- it is a transport mismatch between
"client asked for SSE" and "server always answers with one JSON blob".

Enable with WEDGECHECK_NON_STREAMING_LLM=1 when pointing Wedgecheck's
OPENAI_BASE_URL at such an endpoint. This monkeypatches
`ChatOpenAI.astream` to fall back to a single `ainvoke()` call wrapped in a
one-chunk async generator, so gpt-researcher's streaming consumer still
gets a valid (if non-incremental) stream. Leave this unset for any real
streaming-capable provider (OpenAI, OpenRouter, Anthropic, etc) -- it is
strictly a workaround for non-streaming relays, not a general improvement.
"""
from __future__ import annotations

import os


def apply_if_enabled() -> None:
    """Patch ChatOpenAI.astream iff WEDGECHECK_NON_STREAMING_LLM is truthy.

    Idempotent and safe to call multiple times (e.g. once per research
    attempt) -- the patch is only ever installed once per process.
    """
    if os.getenv("WEDGECHECK_NON_STREAMING_LLM", "").strip().lower() not in (
        "1",
        "true",
        "yes",
    ):
        return

    from langchain_openai import ChatOpenAI
    from langchain_core.messages import AIMessageChunk

    if getattr(ChatOpenAI, "_wedgecheck_nonstreaming_patch", False):
        return

    original_ainvoke = ChatOpenAI.ainvoke

    async def _astream_via_ainvoke(self, input, config=None, *, stop=None, **kwargs):
        result = await original_ainvoke(self, input, config, stop=stop, **kwargs)
        yield AIMessageChunk(content=result.content)

    ChatOpenAI.astream = _astream_via_ainvoke
    ChatOpenAI._wedgecheck_nonstreaming_patch = True
