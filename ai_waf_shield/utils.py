"""ai_waf_shield/utils.py

Utility helpers used by the middleware and protection layers.
"""
import urllib.parse

def canonicalize_payload(payload: str) -> str:
    """Recursively URL‑decode the payload until it no longer changes.
    This mirrors the behaviour of the original WAF's ``canonicalize_payload``.
    """
    previous = None
    current = payload
    while previous != current:
        previous = current
        current = urllib.parse.unquote_plus(current)
    return current

def flatten_payloads(request) -> str:
    """Combine query string, JSON body, headers and cookies into a single string.
    The AI model expects a plain‑text representation of the whole request.
    """
    parts = []
    # Query parameters
    for key, value in request.args.items():
        parts.append(f"{key}={value}")
    # Form data / JSON body (if any)
    if request.is_json:
        parts.append(str(request.get_json()))
    else:
        for key, value in request.form.items():
            parts.append(f"{key}={value}")
    # Headers of interest
    for hdr in ["User-Agent", "Referer", "X-Forwarded-For"]:
        if hdr in request.headers:
            parts.append(f"{hdr}:{request.headers[hdr]}")
    # Cookies
    for key, val in request.cookies.items():
        parts.append(f"cookie_{key}={val}")
    return " ".join(parts)
