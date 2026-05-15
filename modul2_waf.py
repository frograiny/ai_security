"""
MODULE 2 — AI WAF SHIELD (Reverse Proxy Wrapper)
================================================
This script acts as a backward-compatible reverse proxy that wraps the 
vulnerable backend application using the new `ai_waf_shield` SDK.
"""

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import argparse
import requests as req_lib
import logging
import time
from datetime import datetime
from ai_waf_shield import AIWafShield

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [PROXY] - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Default Config
REAL_WEB_URL = "http://localhost:5170"
WAF_PORT = 5000
MAX_RETRIES = 3
REQUEST_TIMEOUT = 10

# Initialize WAF SDK
waf = AIWafShield()
waf.protect(app)

# ══════════════════════════════════════════════════════════
# REVERSE PROXY LOGIC (Catch-all route)
# ══════════════════════════════════════════════════════════
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    url = f"{REAL_WEB_URL}/{path}"
    if request.query_string:
        url = f"{url}?{request.query_string.decode('utf-8')}"

    headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'connection']}

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
            logger.info(f"✅ [{request.method} /{path}] Status={resp.status_code}")
            
            hop_by_hop = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade'}
            headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in hop_by_hop]
            
            return Response(resp.content, resp.status_code, headers)

        except req_lib.Timeout:
            logger.warning(f"⏱️ Timeout attempt {attempt+1}")
            time.sleep(1)
        except Exception as e:
            logger.error(f"❌ Proxy error: {e}")
            time.sleep(1)

    return jsonify({"status": "error", "message": "Backend unavailable"}), 503

# ══════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="🛡️ AI WAF Shield — Proxy Mode")
    parser.add_argument('--target', '-t', type=str, help='URL của website cần bảo vệ')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port lắng nghe')
    args = parser.parse_args()

    if args.target:
        REAL_WEB_URL = args.target if args.target.startswith('http') else 'http://' + args.target

    WAF_PORT = args.port

    logger.info("=" * 60)
    logger.info("🚀 AI WAF SHIELD v3 — PROXY MODE (SDK INTEGRATED)")
    logger.info("=" * 60)
    logger.info(f"🌐 WAF      : 127.0.0.1:{WAF_PORT}")
    logger.info(f"🔒 Backend  : {REAL_WEB_URL}")
    logger.info("=" * 60)

    try:
        from waitress import serve
        logger.info(f"🚀 Production mode: Waitress WSGI (threads=8)")
        serve(app, host='0.0.0.0', port=WAF_PORT, threads=8)
    except ImportError:
        app.run(host='0.0.0.0', port=WAF_PORT, debug=False, threaded=True)
