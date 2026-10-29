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
"""
from __future__ import annotations

import os

from fastapi import HTTPException
from starlette.responses import JSONResponse

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
        if declared is not None and declared > _MAX_REQUEST_BYTES:
            await self._reject(scope, send, declared)
            return

        total = 0

        async def capped_receive():
            nonlocal total
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

    @staticmethod
    async def _reject(scope, send, declared_bytes: int) -> None:
        detail = (
            f"Request body too large ({declared_bytes} declared, max "
            f"{_MAX_REQUEST_BYTES})"
        )
        response = JSONResponse({"detail": detail}, status_code=413)
        await response(scope, receive=None, send=send)
