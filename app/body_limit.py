"""Caps the raw size of any HTTP request body before Starlette/FastAPI ever
buffers or parses it.

`app/product_input.py` already caps `url`/`description` to 2048/4000 chars
(commit `da61f0b`) -- but that check only runs *after* FastAPI has already
read the entire raw request body off the socket and parsed it (into a
`BriefRequest` for `/api/brief`, or form fields for `POST /`). Starlette has
no default limit on request body size: a client can send
`{"description": "short", "junk": "<500MB of garbage>"}` to `/api/brief` --
`description` itself passes the field-length check fine, but Starlette
still buffers the whole 500MB body into memory to parse the JSON *before*
Pydantic or `build_product_input()` ever sees a single field. Same story for
a request with no `Content-Length` at all (chunked transfer) streaming an
unbounded body. This is the exact same single-512MB-uvicorn-worker OOM class
the response-fetch cap (`bef522d`) already closed on the *outbound* side of
this app (the url fetch) -- this closes the mirror-image hole on the
*inbound* side (the request itself), which nothing before this touched.

Pure ASGI middleware, not `BaseHTTPMiddleware` -- `BaseHTTPMiddleware` calls
`await request.body()` internally before your code ever runs, which is
exactly the unbounded buffering this exists to prevent. Two layers, same
precedent already used by `ssrf_guard.py`'s `_read_capped()`: an honestly
declared oversized `Content-Length` is rejected immediately with zero bytes
read off the socket (fast path, direct ASGI response, no app code runs at
all), and the real streamed byte count is enforced regardless (so a missing
or lying `Content-Length` -- chunked transfer -- can't bypass it either).

The streaming check raises a real `fastapi.HTTPException(413, ...)` from
inside the patched `receive()` rather than a custom exception type. This
is deliberate, not an accident: FastAPI's own body-parsing code
(`fastapi/routing.py`'s request handler, which calls `await request.json()`
/ `await request.form()` deep inside the app, below this middleware) wraps
that call in `except HTTPException: raise` / `except Exception: raise
HTTPException(400, "There was an error parsing the body")` -- a plain
custom exception gets silently swallowed into that generic 400 (confirmed
live: that's exactly what happened before this was changed to raise
`HTTPException` directly), while a real `HTTPException` passes through
unchanged and is handled correctly by Starlette's own `ExceptionMiddleware`
into the clean `413` this module intends.

The declared-`Content-Length` fast path (zero bytes read off the socket)
also raises that same `HTTPException` from inside `capped_receive()` now,
rather than sending a hand-built `JSONResponse` directly from this
middleware (the original design, which bypassed `self.app()` -- and
therefore the real FastAPI app, including its exception-handler registry
-- entirely). That original design meant the one route this app renders as
a styled HTML page on every other error (`POST /` -- rate limit, SSRF,
length cap, a failed research pass all render `index.html`'s error banner,
see `main.py`'s `submit()`) got a bare `{"detail": ...}` JSON body instead
on exactly this one error path, because it was the only one raised by a
layer that ran before `submit()`'s own code -- and therefore its own
try/except -- ever got to execute. Confirmed live: a real oversized `POST
/` form submission came back `content-type: application/json`, not the
app's own HTML. Routing *both* checks through `self.app()` means both now
reach `main.py`'s `_html_aware_http_exception_handler`, which renders the
real `index.html` error banner for `POST /` specifically and leaves every
other route's (`/api/brief` included) default JSON `413` untouched. This
costs nothing in the zero-bytes-transferred guarantee: `capped_receive()`
still never calls the real `receive()` before raising when `declared` is
already over the cap, for every request this app actually reads a body on
(every `POST /` and `POST /api/brief` -- the only two routes with a
Form/Body parameter at all, so the only two that ever trigger a real
`receive()` call in the first place).
"""
from __future__ import annotations

import os

from fastapi import HTTPException

# Comfortably above the largest legitimate payload this app accepts (a
# ~4000-char description plus a ~2048-char url plus JSON/multipart
# overhead, well under 10KB in practice) while still bounding worst-case
# memory from an abusive or buggy client to a small, fixed amount.
_MAX_REQUEST_BYTES = int(os.getenv("WEDGECHECK_MAX_REQUEST_BYTES", str(64 * 1024)))


def _declared_content_length(scope) -> int | None:
    for key, value in scope.get("headers", []):
        if key == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


class RequestBodyLimitMiddleware:
    """Rejects any HTTP request whose body exceeds
    `WEDGECHECK_MAX_REQUEST_BYTES` (default 64KiB) with a real `413`,
    before the rest of the app -- and therefore Starlette/Pydantic's own
    body buffering -- ever runs.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _declared_content_length(scope)
        total = 0
        declared_checked = False

        async def capped_receive():
            nonlocal total, declared_checked
            if not declared_checked:
                declared_checked = True
                if declared is not None and declared > _MAX_REQUEST_BYTES:
                    # Zero bytes read off the socket: reject on the
                    # declared Content-Length alone, before the real
                    # receive() is ever called. Only reachable on a route
                    # that actually reads a body at all (POST / and
                    # POST /api/brief in this app) -- see module docstring.
                    raise HTTPException(
                        413,
                        f"Request body too large ({declared} declared, max "
                        f"{_MAX_REQUEST_BYTES})",
                    )
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body") or b"")
                if total > _MAX_REQUEST_BYTES:
                    raise HTTPException(
                        413,
                        f"Request body too large ({total}+ bytes read, max "
                        f"{_MAX_REQUEST_BYTES})",
                    )
            return message

        await self.app(scope, capped_receive, send)
