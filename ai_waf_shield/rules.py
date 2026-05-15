"""ai_waf_shield/rules.py

Simple rule‑based scanner – mirrors the blacklist / regex checks from the original ``modul2_waf``.
The rule list can be extended by the end‑user via configuration.
"""

import re

# Example hard‑coded regex patterns (could be loaded from a file in a real product)
HARD_BLOCK_PATTERNS = [
    r"(?i)union.*select",   # SQL injection pattern
    r'<script[^"]*>',      # Basic XSS detection
    r"\.\./",             # Path traversal
    r"\{\s*['\"]?\$gt['\"]?\s*:\s*.*\}",  # NoSQL injection hint
    r"{{.*}}",              # SSTI pattern
]

def rule_scan(payload: str):
    """Return ``(label, confidence)`` if any hard rule matches.
    ``label`` is ``"malicious"`` and confidence is fixed at ``99.0``.
    If no rule matches ``None`` is returned.
    """
    for pattern in HARD_BLOCK_PATTERNS:
        if re.search(pattern, payload):
            return "malicious", 99.0
    return None
