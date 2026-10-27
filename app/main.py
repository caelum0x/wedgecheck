"""Wedgecheck web app: a single form, a single real result.

POST /api/brief and the HTML form both call the same generate_market_brief
flow as cli.py -- there is no separate "demo" code path with fake data.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from .brief import generate_market_brief

app = FastAPI(title="Wedgecheck", version="0.1.0")
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "web" / "templates"))


class BriefRequest(BaseModel):
    url: str | None = None
    description: str | None = None


class BriefResponse(BaseModel):
    report_markdown: str
    source_urls: list[str]
    research_cost_usd: float
    resolved_title: str | None


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"result": None})


@app.post("/", response_class=HTMLResponse)
async def submit(request: Request, url: str = Form(""), description: str = Form("")):
    try:
        brief = await generate_market_brief(
            url=url.strip() or None, description=description.strip() or None
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request, "index.html", {"result": None, "error": str(exc)}
        )
    return templates.TemplateResponse(request, "index.html", {"result": brief, "error": None})


@app.post("/api/brief", response_model=BriefResponse)
async def api_brief(payload: BriefRequest):
    if not payload.url and not payload.description:
        raise HTTPException(400, "Provide url or description")
    try:
        brief = await generate_market_brief(
            url=payload.url, description=payload.description
        )
    except Exception as exc:
        raise HTTPException(502, f"Research failed: {exc}") from exc
    return BriefResponse(
        report_markdown=brief.report_markdown,
        source_urls=brief.source_urls,
        research_cost_usd=brief.research_cost_usd,
        resolved_title=brief.input.resolved_title,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "wedgecheck"}
