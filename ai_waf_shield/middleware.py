"""ai_waf_shield/middleware.py

Flask middleware integration.
"""
from flask import request, jsonify
from .utils import canonicalize_payload, flatten_payloads
from .rules import rule_scan

def waf_middleware(shield_instance):
    """Factory for the before_request hook."""
    
    def security_filter():
        ip = request.remote_addr
        stats = shield_instance.stats
        
        # 0. Bypass internal endpoints
        if request.path.startswith('/ai-waf/'):
            return None

        # 1. IP Blacklist
        if shield_instance.blacklist.is_blacklisted(ip):
            return jsonify({
                "status": "blocked",
                "reason": "IP blacklisted",
                "engine": "blacklist"
            }), 403

        # 2. Rate Limiting
        allowed, remaining = shield_instance.rate_limiter.is_allowed(ip)
        if not allowed:
            return jsonify({
                "status": "rate_limited",
                "reason": "Too many requests"
            }), 429

        # 3. Payload Collection
        stats["traffic"]["total_requests"] += 1
        raw_payload = flatten_payloads(request)
        if request.path and request.path != '/':
            raw_payload += " " + request.path
            
        if not raw_payload.strip():
            return None # nothing to scan

        # Canonicalize
        canonical = canonicalize_payload(raw_payload)
        
        payloads_to_check = [raw_payload]
        if canonical != raw_payload:
            payloads_to_check.append(canonical)
            
        # 4. Scanning
        for check_payload in payloads_to_check:
            # 4a. Rule based
            rule_result = rule_scan(check_payload)
            if rule_result:
                label, conf = rule_result
                return _handle_block(shield_instance, ip, label, conf, "rule-based")
                
            # 4b. AI based
            label, conf = shield_instance.engine.scan(check_payload)
            if label != "benign" and conf >= shield_instance.config["threshold_block"]:
                return _handle_block(shield_instance, ip, label, conf, "ai-bilstm")
            elif label != "benign" and conf >= shield_instance.config["threshold_alert"]:
                shield_instance.rate_limiter.flag_ip(ip)
                shield_instance.alerts.record(ip, label, conf)
                # Monitor only, let it pass
                
        # Benign
        return None
        
    return security_filter

def _handle_block(shield, ip, label, conf, engine_name):
    stats = shield.stats
    stats["traffic"]["total_blocked"] += 1
    stats["traffic"]["blocks_by_type"][label] = stats["traffic"]["blocks_by_type"].get(label, 0) + 1
    
    total_req = stats["traffic"]["total_requests"]
    total_block = stats["traffic"]["total_blocked"]
    stats["traffic"]["block_rate"] = f"{(total_block / total_req * 100):.1f}%" if total_req > 0 else "0%"
    
    shield.rate_limiter.flag_ip(ip)
    just_blacklisted = shield.blacklist.record_block(ip)
    
    if just_blacklisted:
        shield.alerts.record(ip, "AUTO-BLACKLIST", 100.0)
    else:
        shield.alerts.record(ip, label, conf)
        
    return jsonify({
        "status": "blocked",
        "reason": f"WAF detected {label}",
        "confidence": f"{conf:.1f}%",
        "engine": engine_name
    }), 403
