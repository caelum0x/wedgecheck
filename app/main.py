"""Wedgecheck web app: a single form, a single real result.

POST /api/brief and the HTML form both call the same generate_market_brief
flow as cli.py -- there is no separate "demo" code path with fake data.

Every completed brief is also persisted (see .store) so it can be reopened
later: GET /b/{id} is a shareable permalink for one report, and GET
/history lists a browser's own past briefs via an anonymous session
cookie. See store.py's module docstring for why permalinks are public by
id with no auth.
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import rate_limit, store
from .body_limit import RequestBodyLimitMiddleware
from .brief import generate_market_brief

app = FastAPI(title="Wedgecheck", version="0.1.0")
# Caps raw request-body bytes before Starlette/Pydantic ever buffers or
# parses them -- see body_limit.py's module docstring for the real OOM
# class this closes that the field-length cap (da61f0b) doesn't.
app.add_middleware(RequestBodyLimitMiddleware)
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "web" / "templates"))

# Fast, one-time (CREATE TABLE/INDEX IF NOT EXISTS) -- safe to run at import
# time, before the app accepts its first request.
store.init_db()

_SESSION_COOKIE = "wedgecheck_session"
_SESSION_MAX_AGE_SECONDS = 365 * 24 * 60 * 60  # 1 year


def _session_id(request: Request) -> str:
    """Existing anonymous session cookie, or a fresh one. Never an auth
    token -- just a grouping key for this browser's own /history list."""
    return request.cookies.get(_SESSION_COOKIE) or uuid.uuid4().hex


def _with_session_cookie(request: Request, response, session_id: str | None = None):
    """Set the session cookie on `response` if the browser doesn't already
    have it. `session_id` must be the *same* id the caller already used for
    any store.* call this request made (e.g. submit()'s store.save_brief) --
    resolving a second, independent `_session_id(request)` here would mint a
    fresh random uuid distinct from the one just written to the DB, since a
    cookie set on a response is never visible in request.cookies within that
    same request/response cycle. Callers with no prior session_id of their
    own (index(), history()) can omit it and let this resolve one itself."""
    if session_id is None:
        session_id = _session_id(request)
    if request.cookies.get(_SESSION_COOKIE) != session_id:
        response.set_cookie(
            _SESSION_COOKIE,
            session_id,
            max_age=_SESSION_MAX_AGE_SECONDS,
            httponly=True,
            samesite="lax",
        )
    return session_id, response


@app.exception_handler(HTTPException)
async def _html_aware_http_exception_handler(request: Request, exc: HTTPException):
    """Every *other* error path on `POST /` (rate limit, SSRF, length cap,
    a failed research pass) is handled inside `submit()` itself and renders
    the real `index.html` template with a friendly in-page banner -- never
    raw JSON. But `RequestBodyLimitMiddleware` (body_limit.py) necessarily
    raises its 413 `HTTPException` from *inside* Starlette's own body
    parsing, which runs before `submit()`'s own code (and therefore its
    try/except) ever gets to execute -- so without this handler, FastAPI's
    default behavior (a bare `{"detail": ...}` JSON body, confirmed live via
    a real oversized form POST) is the one error response on this exact
    route that breaks the page instead of rendering the app's own HTML, for
    no reason other than which layer happened to raise it. `POST /` is the
    only route this can reach (`/api/brief` and everything else correctly
    keep the default JSON handling, unchanged)."""
    if request.method == "POST" and request.url.path == "/":
        response = templates.TemplateResponse(
            request,
            "index.html",
            {"result": None, "error": str(exc.detail)},
            status_code=exc.status_code,
            headers=exc.headers,
        )
        _, response = _with_session_cookie(request, response)
        return response
    return await http_exception_handler(request, exc)


def _brief_view(brief) -> dict:
    """Flatten either a freshly generated MarketBrief (nested .input) or a
    stored-briefs dict (already flat, from store.get_brief) into the same
    shape index.html expects, so the template doesn't need to care which
    one it got."""
    if isinstance(brief, dict):
        return {
            "resolved_title": brief["resolved_title"],
            "research_cost_usd": brief["research_cost_usd"],
            "report_markdown": brief["report_markdown"],
            "source_urls": brief["source_urls"],
        }
    return {
        "resolved_title": brief.input.resolved_title,
        "research_cost_usd": brief.research_cost_usd,
        "report_markdown": brief.report_markdown,
        "source_urls": brief.source_urls,
    }


class BriefRequest(BaseModel):
    url: str | None = None
    description: str | None = None


class BriefResponse(BaseModel):
    id: str
    permalink_url: str
    report_markdown: str
    source_urls: list[str]
    research_cost_usd: float
    resolved_title: str | None


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    response = templates.TemplateResponse(request, "index.html", {"result": None})
    _, response = _with_session_cookie(request, response)
    return response


@app.post("/", response_class=HTMLResponse)
async def submit(request: Request, url: str = Form(""), description: str = Form("")):
    session_id = _session_id(request)
    try:
        rate_limit.check(rate_limit.client_ip(request))
    except rate_limit.RateLimitExceeded as exc:
        response = templates.TemplateResponse(
            request,
            "index.html",
            {
                "result": None,
                "error": (
                    "Too many briefs from this connection -- each one runs a "
                    f"real research pass. Try again in about {exc.retry_after_seconds:.0f}s."
                ),
            },
            status_code=429,
        )
        response.headers["Retry-After"] = str(int(exc.retry_after_seconds))
        _, response = _with_session_cookie(request, response, session_id)
        return response
    try:
        brief = await generate_market_brief(
            url=url.strip() or None, description=description.strip() or None
        )
    except Exception as exc:
        response = templates.TemplateResponse(
            request, "index.html", {"result": None, "error": str(exc)}
        )
        _, response = _with_session_cookie(request, response, session_id)
        return response

    brief_id = await asyncio.to_thread(store.save_brief, brief, session_id=session_id)
    permalink = str(request.url_for("view_permalink", brief_id=brief_id))
    response = templates.TemplateResponse(
        request,
        "index.html",
        {"result": _brief_view(brief), "error": None, "permalink": permalink},
    )
    # Must reuse the exact session_id resolved above (and already passed to
    # store.save_brief) -- see _with_session_cookie's docstring for why
    # calling _session_id(request) again here would silently orphan the
    # just-saved brief under a cookie value nobody has.
    _, response = _with_session_cookie(request, response, session_id)
    return response


@app.get("/b/{brief_id}", response_class=HTMLResponse, name="view_permalink")
async def view_permalink(request: Request, brief_id: str):
    stored = await asyncio.to_thread(store.get_brief, brief_id)
    if stored is None:
        raise HTTPException(404, "No brief found at this link")
    permalink = str(request.url_for("view_permalink", brief_id=brief_id))
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "result": _brief_view(stored),
            "error": None,
            "permalink": permalink,
            "readonly": True,
        },
    )


@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    session_id = _session_id(request)
    briefs = await asyncio.to_thread(
        store.list_briefs_for_session, session_id, limit=20
    )
    response = templates.TemplateResponse(
        request, "history.html", {"briefs": briefs}
    )
    _, response = _with_session_cookie(request, response, session_id)
    return response


@app.post("/api/brief", response_model=BriefResponse)
async def api_brief(request: Request, payload: BriefRequest):
    if not payload.url and not payload.description:
        raise HTTPException(400, "Provide url or description")
    try:
        rate_limit.check(rate_limit.client_ip(request))
    except rate_limit.RateLimitExceeded as exc:
        raise HTTPException(
            429,
            f"Rate limit exceeded -- retry after {exc.retry_after_seconds:.0f}s",
            headers={"Retry-After": str(int(exc.retry_after_seconds))},
        ) from exc
    try:
        brief = await generate_market_brief(
            url=payload.url, description=payload.description
        )
    except Exception as exc:
        raise HTTPException(502, f"Research failed: {exc}") from exc
    # API callers have no session cookie of their own -- still persisted
    # (session_id=None) so the permalink in the response works for anyone.
    brief_id = await asyncio.to_thread(store.save_brief, brief, session_id=None)
    permalink = str(request.url_for("view_permalink", brief_id=brief_id))
    return BriefResponse(
        id=brief_id,
        permalink_url=permalink,
        report_markdown=brief.report_markdown,
        source_urls=brief.source_urls,
        research_cost_usd=brief.research_cost_usd,
        resolved_title=brief.input.resolved_title,
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "wedgecheck"}
