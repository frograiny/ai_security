"""ai_waf_shield/config.py

Default configuration values for the AI WAF SDK. Users can override any of these by passing a ``config`` dict to ``AIWafShield``.
"""

DEFAULT_CONFIG = {
    # Thresholds (percentage) for blocking / alerting
    "threshold_block": 90.0,
    "threshold_alert": 75.0,
    # Rate limiting (requests per minute)
    "rate_limit_normal": 100,
    "rate_limit_flagged": 10,
    # Blacklist settings
    "blacklist_threshold": 5,  # number of blocks before IP is blacklisted
    "blacklist_duration": 600,  # seconds the IP stays banned
    # Cache for AI inference results (to avoid re‑scanning identical payloads)
    "cache_size": 1024,
    "cache_ttl": 300,  # seconds
    # Path to the bundled model directory (None => auto‑detect inside package)
    "model_dir": None,
    # Dashboard options
    "dashboard_enabled": True,
    "dashboard_path": "/ai-waf/dashboard",
    # Logging verbosity
    "log_level": "WARNING",
}
