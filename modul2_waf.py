"""
MODULE 2 — AI WAF SHIELD (Enhanced)
=====================================
Thêm mới so với v1:
  - Rate Limiting: 100 req/phút/IP, 10 req/phút sau khi bị block
  - IP Blacklist tự động: 5 lần BLOCKED trong 60s → blacklist 10 phút
  - Alert System: terminal alert + webhook (Discord/Telegram tuỳ chọn)
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import os
import requests as req_lib
import logging
import hashlib
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
import time
import threading

# ===== LOGGING =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [AI-WAF-SHIELD] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("shield_protection.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Alert logger riêng — chỉ ghi các sự kiện nghiêm trọng
alert_logger = logging.getLogger("ALERT")
alert_handler = logging.FileHandler("shield_alerts.log", encoding='utf-8')
alert_handler.setFormatter(logging.Formatter('%(asctime)s - [ALERT] - %(message)s'))
alert_logger.addHandler(alert_handler)
alert_logger.setLevel(logging.WARNING)

app = Flask(__name__)
CORS(app)

# ===== CONFIGURATION =====
MODEL_DIR        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
MAX_LEN          = 150
REAL_WEB_URL     = "http://localhost:5170"
THRESHOLD        = 75.0
CACHE_TTL        = 300
MAX_CACHE_SIZE   = 1000
REQUEST_TIMEOUT  = 10
MAX_RETRIES      = 3

# Rate limiting
RATE_LIMIT_NORMAL   = 100   # req/phút cho IP bình thường
RATE_LIMIT_FLAGGED  = 10    # req/phút cho IP đã từng bị block

# IP Blacklist
BLACKLIST_THRESHOLD = 5     # số lần BLOCKED trong cửa sổ thời gian
BLACKLIST_WINDOW    = 60    # giây — cửa sổ đếm
BLACKLIST_DURATION  = 600   # giây — thời gian blacklist (10 phút)

# Alert webhook (tuỳ chọn — để trống nếu không dùng)
WEBHOOK_URL = ""  # VD: "https://discord.com/api/webhooks/..." hoặc Telegram bot URL
ALERT_THRESHOLD = 50  # Số lần BLOCKED trong 1 phút trước khi gửi alert


# ══════════════════════════════════════════════════════════
# LRU CACHE WITH TTL
# ══════════════════════════════════════════════════════════
class PayloadCache:
    def __init__(self, max_size=1000, ttl=300):
        self.cache   = OrderedDict()
        self.ttl_map = {}
        self.max_size = max_size
        self.ttl      = ttl
        self.hits     = 0
        self.misses   = 0

    def _make_key(self, payload):
        return hashlib.md5(str(payload).encode()).hexdigest()

    def get(self, payload):
        key = self._make_key(payload)
        if key not in self.cache:
            self.misses += 1
            return None
        label, conf, ts = self.cache[key]
        if datetime.now() - ts > timedelta(seconds=self.ttl):
            del self.cache[key]
            del self.ttl_map[key]
            self.misses += 1
            return None
        self.cache.move_to_end(key)
        self.hits += 1
        return label, conf

    def set(self, payload, label, conf):
        key = self._make_key(payload)
        if len(self.cache) >= self.max_size:
            oldest = next(iter(self.cache))
            del self.cache[oldest]
            del self.ttl_map[oldest]
        self.cache[key] = (label, conf, datetime.now())
        self.ttl_map[key] = datetime.now()

    def stats(self):
        total    = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'size': len(self.cache), 'hits': self.hits,
            'misses': self.misses, 'hit_rate': f"{hit_rate:.1f}%"
        }

cache = PayloadCache(max_size=MAX_CACHE_SIZE, ttl=CACHE_TTL)


# ══════════════════════════════════════════════════════════
# RATE LIMITER
# ══════════════════════════════════════════════════════════
class RateLimiter:
    """
    Sliding window rate limiter theo IP.
    - IP bình thường: RATE_LIMIT_NORMAL req/phút
    - IP đã từng bị block: RATE_LIMIT_FLAGGED req/phút
    """
    def __init__(self):
        self.windows  = defaultdict(list)   # ip → [timestamp, ...]
        self.flagged  = set()               # IP đã từng bị block ít nhất 1 lần
        self._lock    = threading.Lock()

    def is_allowed(self, ip):
        """Trả về (allowed: bool, remaining: int)"""
        with self._lock:
            now   = datetime.now()
            limit = RATE_LIMIT_FLAGGED if ip in self.flagged else RATE_LIMIT_NORMAL
            # Xoá các timestamp cũ hơn 60 giây
            self.windows[ip] = [t for t in self.windows[ip]
                                 if now - t < timedelta(seconds=60)]
            count = len(self.windows[ip])
            if count >= limit:
                return False, 0
            self.windows[ip].append(now)
            return True, limit - count - 1

    def flag_ip(self, ip):
        """Đánh dấu IP này là flagged (đã từng bị block)"""
        with self._lock:
            self.flagged.add(ip)

    def stats(self):
        with self._lock:
            return {
                'tracked_ips': len(self.windows),
                'flagged_ips': len(self.flagged),
                'flagged_list': list(self.flagged)[:20]  # Top 20
            }

rate_limiter = RateLimiter()


# ══════════════════════════════════════════════════════════
# IP BLACKLIST
# ══════════════════════════════════════════════════════════
class IPBlacklist:
    """
    Tự động blacklist IP nếu bị BLOCKED >= BLACKLIST_THRESHOLD lần
    trong BLACKLIST_WINDOW giây.
    Blacklist kéo dài BLACKLIST_DURATION giây.
    """
    def __init__(self):
        self.blacklist      = {}    # ip → expiry datetime
        self.block_history  = defaultdict(list)  # ip → [timestamp, ...]
        self._lock          = threading.Lock()

    def record_block(self, ip):
        """Ghi nhận 1 lần block. Trả về True nếu IP vừa bị blacklist."""
        with self._lock:
            now = datetime.now()
            window_start = now - timedelta(seconds=BLACKLIST_WINDOW)
            # Xoá history cũ
            self.block_history[ip] = [t for t in self.block_history[ip]
                                       if t > window_start]
            self.block_history[ip].append(now)

            if len(self.block_history[ip]) >= BLACKLIST_THRESHOLD:
                expiry = now + timedelta(seconds=BLACKLIST_DURATION)
                self.blacklist[ip] = expiry
                self.block_history[ip] = []  # Reset sau khi blacklist
                return True
            return False

    def is_blacklisted(self, ip):
        """Trả về True nếu IP đang trong blacklist còn hiệu lực."""
        with self._lock:
            if ip not in self.blacklist:
                return False
            if datetime.now() > self.blacklist[ip]:
                del self.blacklist[ip]
                return False
            return True

    def remove(self, ip):
        """Xoá IP khỏi blacklist thủ công."""
        with self._lock:
            self.blacklist.pop(ip, None)

    def stats(self):
        with self._lock:
            now = datetime.now()
            active = {ip: str(exp) for ip, exp in self.blacklist.items()
                      if exp > now}
            return {
                'active_blacklisted': len(active),
                'blacklisted_ips': active
            }

ip_blacklist = IPBlacklist()


# ══════════════════════════════════════════════════════════
# ALERT SYSTEM
# ══════════════════════════════════════════════════════════
class AlertSystem:
    """
    Theo dõi số lần BLOCKED trong cửa sổ 1 phút.
    Khi vượt ALERT_THRESHOLD → in terminal alert + gửi webhook.
    """
    def __init__(self):
        self.block_times   = []      # timestamps của các lần block
        self.alert_sent_at = None    # Tránh spam alert
        self._lock         = threading.Lock()

    def record(self, ip, attack_type, confidence):
        """Ghi nhận 1 lần block và kiểm tra ngưỡng alert."""
        with self._lock:
            now = datetime.now()
            self.block_times = [t for t in self.block_times
                                 if now - t < timedelta(seconds=60)]
            self.block_times.append(now)
            count = len(self.block_times)

        if count >= ALERT_THRESHOLD:
            # Tránh gửi alert liên tục — chờ ít nhất 5 phút giữa 2 alert
            with self._lock:
                if (self.alert_sent_at is None or
                        now - self.alert_sent_at > timedelta(minutes=5)):
                    self.alert_sent_at = now
                    self._fire_alert(count, ip, attack_type, confidence)

    def _fire_alert(self, count, ip, attack_type, confidence):
        """Gửi alert ra terminal và webhook."""
        msg = (
            f"🚨 SECURITY ALERT — {count} lần BLOCKED trong 60 giây!\n"
            f"   Lần cuối: IP={ip} | {attack_type} | {confidence:.1f}%\n"
            f"   Thời điểm: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        # Terminal alert (màu đỏ)
        RED, RESET = '\033[91m', '\033[0m'
        print(f"\n{RED}{'='*60}")
        print(msg)
        print(f"{'='*60}{RESET}\n")

        # File alert
        alert_logger.warning(msg)

        # Webhook (Discord / Telegram / bất kỳ)
        if WEBHOOK_URL:
            threading.Thread(
                target=self._send_webhook,
                args=(msg,),
                daemon=True
            ).start()

    def _send_webhook(self, msg):
        """Gửi webhook không block main thread."""
        try:
            # Format cho Discord
            payload = {"content": f"```\n{msg}\n```"}
            req_lib.post(WEBHOOK_URL, json=payload, timeout=5)
            logger.info("📡 Webhook alert đã gửi")
        except Exception as e:
            logger.warning(f"⚠️ Webhook thất bại: {e}")

    def stats(self):
        with self._lock:
            now = datetime.now()
            recent = [t for t in self.block_times
                      if now - t < timedelta(seconds=60)]
            return {
                'blocks_last_60s': len(recent),
                'alert_threshold': ALERT_THRESHOLD,
                'last_alert': str(self.alert_sent_at) if self.alert_sent_at else None
            }

alert_system = AlertSystem()


# ══════════════════════════════════════════════════════════
# LOAD AI MODEL
# ══════════════════════════════════════════════════════════
try:
    model = tf.keras.models.load_model(
        os.path.join(MODEL_DIR, 'deep_learning_agent_core.keras')
    )
    with open(os.path.join(MODEL_DIR, 'tokenizer.pkl'), 'rb') as f:
        tokenizer = pickle.load(f)
    with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'rb') as f:
        le = pickle.load(f)
    logger.info("✅ SHIELD AGENT: Bi-LSTM sẵn sàng")
    logger.info(f"🛡️  Threshold={THRESHOLD}% | Cache={MAX_CACHE_SIZE} | "
                f"RateLimit={RATE_LIMIT_NORMAL}/min | "
                f"Blacklist={BLACKLIST_THRESHOLD}hits/{BLACKLIST_WINDOW}s")
except Exception as e:
    logger.error(f"❌ CRITICAL: Lỗi tải model: {e}")
    exit(1)


# ══════════════════════════════════════════════════════════
# SCAN ENGINE
# ══════════════════════════════════════════════════════════
def scan_payload(payload):
    if not payload or (isinstance(payload, str) and payload.strip() == ""):
        return "Normal", 100.0

    cached = cache.get(payload)
    if cached:
        return cached

    try:
        seq  = tokenizer.texts_to_sequences([str(payload)])
        pad  = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
        pred = model.predict(pad, verbose=0)[0]
        idx  = np.argmax(pred)
        label      = le.inverse_transform([idx])[0]
        confidence = float(pred[idx]) * 100
        cache.set(payload, label, confidence)
        return label, confidence
    except Exception as e:
        logger.error(f"❌ Scan error: {e}")
        return "Unknown", 0.0


# ══════════════════════════════════════════════════════════
# HEALTH CHECK BACKEND
# ══════════════════════════════════════════════════════════
backend_health = {"status": "unknown", "last_check": None, "consecutive_failures": 0}

def check_backend_health():
    global backend_health
    try:
        resp = req_lib.get(f"{REAL_WEB_URL}/", timeout=2)
        backend_health["status"] = "healthy" if resp.status_code < 500 else "degraded"
        backend_health["consecutive_failures"] = 0
    except Exception as e:
        backend_health["status"] = "unavailable"
        backend_health["consecutive_failures"] += 1
        logger.warning(f"⚠️ Backend unreachable: {e}")
    backend_health["last_check"] = datetime.now()


# ══════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE
# ══════════════════════════════════════════════════════════
@app.before_request
def security_filter():
    ip = request.remote_addr

    # ── 0. Bỏ qua static files ────────────────────────────
    if any(request.path.endswith(ext)
           for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2']):
        return None

    # ── 1. Kiểm tra IP Blacklist ──────────────────────────
    if ip_blacklist.is_blacklisted(ip):
        logger.warning(f"🚫 [BLACKLISTED] IP={ip} | Path={request.path}")
        return jsonify({
            "status": "blocked",
            "reason": "IP blacklisted due to repeated attacks",
            "retry_after": f"{BLACKLIST_DURATION // 60} minutes"
        }), 403

    # ── 2. Rate Limiting ──────────────────────────────────
    allowed, remaining = rate_limiter.is_allowed(ip)
    if not allowed:
        logger.warning(f"⏱️ [RATE LIMITED] IP={ip} | Path={request.path}")
        return jsonify({
            "status": "rate_limited",
            "reason": "Too many requests",
            "retry_after": "60 seconds"
        }), 429

    # ── 3. Thu thập payload để scan ───────────────────────
    data_to_scan = list(request.args.values())
    if request.is_json:
        try:
            data_to_scan.extend(
                str(v) for v in request.get_json(silent=True).values() if v
            )
        except Exception:
            pass
    elif request.form:
        data_to_scan.extend(request.form.values())

    # ── 4. Scan từng payload ──────────────────────────────
    for payload in data_to_scan:
        if not payload or len(str(payload)) < 2:
            continue

        label, confidence = scan_payload(payload)
        payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()[:8]

        if label != "Normal" and confidence >= THRESHOLD:
            # Ghi nhận block
            rate_limiter.flag_ip(ip)
            just_blacklisted = ip_blacklist.record_block(ip)
            alert_system.record(ip, label, confidence)

            logger.warning(
                f"🛡️ [BLOCKED] {label} | {confidence:.1f}% | "
                f"Hash={payload_hash} | IP={ip}"
            )

            # Thông báo nếu IP vừa bị blacklist
            if just_blacklisted:
                logger.warning(
                    f"🚫 [AUTO-BLACKLIST] IP={ip} đã bị blacklist "
                    f"{BLACKLIST_DURATION//60} phút do tấn công liên tục"
                )
                alert_logger.warning(
                    f"AUTO-BLACKLIST | IP={ip} | "
                    f"Triggered by {BLACKLIST_THRESHOLD} blocks in {BLACKLIST_WINDOW}s"
                )

            return jsonify({
                "status": "blocked",
                "reason": f"AI WAF detected {label}",
                "confidence": f"{confidence:.1f}%"
            }), 403

        elif label != "Normal" and confidence >= 50:
            logger.info(
                f"⚠️ [SUSPICIOUS] {label} ({confidence:.1f}%) | "
                f"Hash={payload_hash} | ALLOWED | IP={ip}"
            )

    return None


# ══════════════════════════════════════════════════════════
# MONITORING ENDPOINTS
# ══════════════════════════════════════════════════════════
@app.route('/ai-waf/health', methods=['GET'])
def health_check():
    check_backend_health()
    return jsonify({
        "status": "operational",
        "backend": backend_health["status"],
        "cache": cache.stats(),
        "model": "Bi-LSTM",
        "threshold": THRESHOLD,
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/ai-waf/stats', methods=['GET'])
def get_stats():
    """Dashboard tổng hợp toàn bộ thống kê."""
    return jsonify({
        "model": {
            "accuracy": "93.42%",
            "threshold": THRESHOLD,
            "supported_attacks": [
                "SQLi", "XSS", "Command Injection",
                "Path Traversal", "SSRF", "CSRF"
            ]
        },
        "cache":       cache.stats(),
        "rate_limiter": rate_limiter.stats(),
        "blacklist":   ip_blacklist.stats(),
        "alerts":      alert_system.stats(),
        "backend":     backend_health["status"],
        "timestamp":   datetime.now().isoformat()
    }), 200


@app.route('/ai-waf/blacklist/<ip>', methods=['DELETE'])
def remove_blacklist(ip):
    """Xoá IP khỏi blacklist thủ công (dành cho admin)."""
    ip_blacklist.remove(ip)
    logger.info(f"🔓 [MANUAL] IP={ip} đã được xoá khỏi blacklist")
    return jsonify({"status": "ok", "message": f"{ip} removed from blacklist"}), 200


# ══════════════════════════════════════════════════════════
# REVERSE PROXY WITH RETRY
# ══════════════════════════════════════════════════════════
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    url = f"{REAL_WEB_URL}/{path}"
    if request.query_string:
        url += f"?{request.query_string.decode()}"

    headers = {k: v for k, v in request.headers
               if k.lower() not in ['host', 'connection']}

    for attempt in range(MAX_RETRIES):
        try:
            resp = req_lib.request(
                method=request.method,
                url=url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT
            )
            logger.info(
                f"✅ [{request.method} /{path}] "
                f"Status={resp.status_code} | Attempt={attempt+1}"
            )
            return Response(resp.content, resp.status_code, resp.headers.items())

        except req_lib.Timeout:
            logger.warning(f"⏱️ Timeout attempt {attempt+1}/{MAX_RETRIES}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)

        except Exception as e:
            logger.error(f"❌ Proxy error attempt {attempt+1}: {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
            else:
                return jsonify({
                    "status": "error",
                    "message": "Backend unavailable",
                    "detail": str(e)
                }), 503

    return jsonify({"status": "error", "message": "Max retries exceeded"}), 504


# ══════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════
# @app.before_first_request
def startup():
    logger.info("=" * 60)
    logger.info("🚀 AI WAF SHIELD — STARTUP")
    logger.info("=" * 60)
    logger.info(f"🌐 Public   : 0.0.0.0:5000")
    logger.info(f"🔒 Backend  : {REAL_WEB_URL} (internal)")
    logger.info(f"🧠 Model    : Bi-LSTM | Accuracy: 93.42%")
    logger.info(f"🛡️  Threshold: {THRESHOLD}%")
    logger.info(f"⏱️  RateLimit: {RATE_LIMIT_NORMAL}/min normal | "
                f"{RATE_LIMIT_FLAGGED}/min flagged")
    logger.info(f"🚫 Blacklist: {BLACKLIST_THRESHOLD} blocks/{BLACKLIST_WINDOW}s "
                f"→ ban {BLACKLIST_DURATION//60}min")
    logger.info(f"🔔 Alert    : threshold={ALERT_THRESHOLD} blocks/min | "
                f"webhook={'ON' if WEBHOOK_URL else 'OFF'}")
    logger.info(f"💾 Cache    : {MAX_CACHE_SIZE} entries | TTL={CACHE_TTL}s")
    check_backend_health()
    logger.info(f"📡 Backend  : {backend_health['status']}")
    logger.info("=" * 60)


if __name__ == '__main__':
    startup()
    logger.info("⚡ Starting Shield Agent on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)