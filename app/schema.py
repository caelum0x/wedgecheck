"""Output shape for a Wedgecheck market brief."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ProductInput:
    """What the user gave us, after real (not mocked) extraction."""

    raw_url: str | None
    raw_description: str | None
    resolved_title: str | None
    resolved_summary: str | None

    def research_subject(self) -> str:
        """The text actually handed to the research engine."""
        if self.resolved_summary:
            return self.resolved_summary
        if self.raw_description:
            return self.raw_description
        raise ValueError("No usable product input: give a URL or a description")


@dataclass
class MarketBrief:
    """A sourced market/competitive brief. Every fact in `report_markdown`
    traces back to one of `source_urls` -- gpt-researcher cites inline as it
    writes, we never add unsourced numbers ourselves."""

    input: ProductInput
    report_markdown: str
    source_urls: list[str]
    research_cost_usd: float
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "input": {
                "url": self.input.raw_url,
                "description": self.input.raw_description,
                "resolved_title": self.input.resolved_title,
            },
            "generated_at": self.generated_at,
            "research_cost_usd": self.research_cost_usd,
            "source_urls": self.source_urls,
            "report_markdown": self.report_markdown,
        }
