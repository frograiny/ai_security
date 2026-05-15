"""ai_waf_shield/shield.py

High‑level façade for the WAF SDK.
The user only needs to instantiate the class and call ``protect(app)`` where ``app`` is a Flask instance.
"""

from .config import DEFAULT_CONFIG
from .engine import AIEngine
from .middleware import waf_middleware
from .protection import RateLimiter, IPBlacklist, AlertSystem
from .dashboard import register_dashboard

class AIWafShield:
    def __init__(self, config: dict | None = None):
        """Merge user config with defaults and initialise sub‑components.

        Parameters
        ----------
        config: dict | None
            Optional configuration dictionary. Missing keys are filled from ``DEFAULT_CONFIG``.
        """
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        # Initialise core AI engine (model loading is lazy inside AIEngine)
        self.engine = AIEngine(self.config.get("model_dir"))
        # Initialise auxiliary services
        self.rate_limiter = RateLimiter(self.config)
        self.blacklist = IPBlacklist(self.config)
        self.alerts = AlertSystem(self.config)
        # Stats dictionary that will be exposed to the dashboard
        self.stats = {
            "traffic": {"total_requests": 0, "total_blocked": 0, "block_rate": "0%", "blocks_by_type": {}},
            "backend": "healthy",
            "cache": {"hit_rate": "0%"},
        }

    def protect(self, app):
        """Register the WAF middleware on the given Flask ``app``.

        The middleware will be executed before every request, performing:
        * Canonicalisation
        * Rule‑based checks
        * Rate‑limiting / IP blacklist
        * AI inference via ``self.engine``
        * Alert / logging
        * Statistics update for the dashboard
        """
        # Attach the stats dict so the dashboard can read it
        app.waf_stats = self.stats
        # Register Flask ``before_request`` hook
        app.before_request(waf_middleware(self))
        # Optional built‑in dashboard
        if self.config.get("dashboard_enabled"):
            register_dashboard(app)
        return app
