"""ai_waf_shield/protection.py

Provides rate limiting, IP blacklisting and alerting components.
"""
import time

class RateLimiter:
    def __init__(self, config):
        self.limit_normal = config.get("rate_limit_normal", 100)
        self.limit_flagged = config.get("rate_limit_flagged", 10)
        self.requests = {}  # {ip: [timestamp1, timestamp2, ...]}
        self.flagged_ips = set()

    def flag_ip(self, ip: str):
        self.flagged_ips.add(ip)

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        now = time.time()
        limit = self.limit_flagged if ip in self.flagged_ips else self.limit_normal
        
        if ip not in self.requests:
            self.requests[ip] = []
        
        # Clean up requests older than 60 seconds
        self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]
        
        if len(self.requests[ip]) >= limit:
            return False, 0
            
        self.requests[ip].append(now)
        return True, limit - len(self.requests[ip])


class IPBlacklist:
    def __init__(self, config):
        self.threshold = config.get("blacklist_threshold", 5)
        self.duration = config.get("blacklist_duration", 600)
        self.blocks = {} # {ip: [timestamp1, timestamp2, ...]}
        self.blacklisted_ips = {} # {ip: unban_time}

    def record_block(self, ip: str) -> bool:
        """Record a block and return True if it just crossed the threshold."""
        now = time.time()
        
        if ip not in self.blocks:
            self.blocks[ip] = []
            
        # Clean up blocks older than 60 seconds (window)
        self.blocks[ip] = [t for t in self.blocks[ip] if now - t < 60]
        self.blocks[ip].append(now)
        
        if len(self.blocks[ip]) >= self.threshold and ip not in self.blacklisted_ips:
            self.blacklisted_ips[ip] = now + self.duration
            return True
        return False

    def is_blacklisted(self, ip: str) -> bool:
        now = time.time()
        if ip in self.blacklisted_ips:
            if now > self.blacklisted_ips[ip]:
                del self.blacklisted_ips[ip]
                # Also reset blocks and flags if unbanned? Keep it simple.
                return False
            return True
        return False


class AlertSystem:
    def __init__(self, config):
        self.config = config

    def record(self, ip: str, label: str, confidence: float):
        # In a real product, this could send an email, webhook, or push notification
        # For SDK we just print/log
        print(f"[ALERT] High confidence threat ({label}: {confidence:.1f}%) from {ip}")
