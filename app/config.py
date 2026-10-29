"""Runtime configuration for Wedgecheck.

Wedgecheck is built on top of gpt-researcher (Apache-2.0,
https://github.com/assafelovic/gpt-researcher) for the actual web retrieval +
citation engine. This module only configures *which* retriever and LLM
gpt-researcher uses -- it does not re-implement any research logic itself.

Self-host default: no paid API key is required to run Wedgecheck at all.
RETRIEVER defaults to "duckduckgo" (free, no key). You still need to point it
at *some* chat-completions endpoint (OPENAI_API_KEY + OPENAI_BASE_URL, or any
OpenAI-compatible gateway -- Ollama, OpenRouter, Railyard Relay, etc).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from . import llm_compat, retriever_compat

load_dotenv()


@dataclass(frozen=True)
class WedgecheckConfig:
    retriever: str
    fast_llm: str
    smart_llm: str
    strategic_llm: str
    max_subtopics: int
    report_language: str
    research_max_attempts: int
    research_retry_backoff_seconds: float

    @staticmethod
    def from_env() -> "WedgecheckConfig":
        return WedgecheckConfig(
            retriever=os.getenv("RETRIEVER", "duckduckgo"),
            fast_llm=os.getenv("FAST_LLM", "openai:gpt-4o-mini"),
            smart_llm=os.getenv("SMART_LLM", "openai:gpt-4o-mini"),
            strategic_llm=os.getenv("STRATEGIC_LLM", "openai:gpt-4o-mini"),
            max_subtopics=int(os.getenv("WEDGECHECK_MAX_SUBTOPICS", "3")),
            report_language=os.getenv("WEDGECHECK_REPORT_LANGUAGE", "english"),
            research_max_attempts=int(
                os.getenv("WEDGECHECK_RESEARCH_MAX_ATTEMPTS", "3")
            ),
            research_retry_backoff_seconds=float(
                os.getenv("WEDGECHECK_RESEARCH_RETRY_BACKOFF_SECONDS", "4")
            ),
        )

    def apply_to_environ(self) -> None:
        """gpt-researcher reads its own config straight from os.environ."""
        os.environ.setdefault("RETRIEVER", self.retriever)
        os.environ.setdefault("FAST_LLM", self.fast_llm)
        os.environ.setdefault("SMART_LLM", self.smart_llm)
        os.environ.setdefault("STRATEGIC_LLM", self.strategic_llm)
        # No-op unless WEDGECHECK_NON_STREAMING_LLM=1 -- see llm_compat.py.
        llm_compat.apply_if_enabled()
        # Real upstream bug fix, always applied -- see retriever_compat.py.
        retriever_compat.apply()
