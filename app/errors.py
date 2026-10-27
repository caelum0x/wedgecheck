"""Errors Wedgecheck raises on purpose, instead of silently degrading.

Wedgecheck's one promise is "every claim is cited to a real source." If the
research engine cannot ground a single source URL, the product must say so
loudly -- never hand back an unsourced report as if it were sourced.
"""
from __future__ import annotations


class WedgecheckResearchError(RuntimeError):
    """Raised when gpt-researcher cannot produce any grounded source URLs.

    This is a real, user-facing failure (HTTP 502 from the API, a visible
    error banner from the form) -- not an internal bug to hide.
    """
