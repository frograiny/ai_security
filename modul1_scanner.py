"""
MODULE 1 — AI VULNERABILITY SCANNER (Active Attacker)
=========================================================
Mục đích: Chủ động quét + giả lập tấn công vào web mục tiêu,
phân tích response để phát hiện lỗ hổng, tạo báo cáo.

Sử dụng:
    python modul1_scanner.py --target http://localhost:5173
    python modul1_scanner.py --target http://localhost:5173 --report
"""

import requests
import re
import json
import time
import argparse
import html
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import os
import logging
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlencode
from groq import Groq
from dotenv import load_dotenv

# ===== BỘ SINH PAYLOAD AI (ĐỘC LẬP) =====
class AIPayloadGenerator:
    """Module tự sinh payload thông minh theo ngữ cảnh, dùng Groq"""
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=self.api_key) if self.api_key else None
        
    def generate_context_payloads(self, attack_type, endpoint_url, param_name, count=3):
        if not self.client:
            return []
        prompt = f'''Bạn là pentester đang kiểm tra endpoint:
URL: {endpoint_url}
Tham số: {param_name}
Loại tấn công: {attack_type}

Tạo {count} payload đặc thù cho ĐÚNG tham số "{param_name}".
CHỈ TRẢ VỀ MỘT MẢNG JSON (ARRAY) DẠNG CHUỖI, KHÔNG GIẢI THÍCH, KHÔNG MARKDOWN. TRÁNH DÙNG DẤU NHÁY ĐƠN TRONG CHUỖI NẾU KHÔNG THỰC SỰ CẦN, HÃY ESCAPE CHÚNG.
Ví dụ: ["payload1", "payload2"]
'''
        try:
            resp = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Return a raw JSON array of strings only."},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.1-8b-instant",
                temperature=0.8,
            )
            text = resp.choices[0].message.content.strip()
            if "[" in text and "]" in text:
                raw = text[text.find("["):text.rfind("]")+1]
                return json.loads(raw)
        except Exception as e:
            logger.warning(f"  [AI Payload Gen] Lỗi gọi Groq cho {attack_type}: {e}")
        return []
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
# ===== LOGGING =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [SCANNER] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===== CONFIG =====
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
MAX_LEN = 150

# ===== COLOR OUTPUT =====
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


# ===== HTML FORM PARSER =====
class FormParser(HTMLParser):
    """Phân tích HTML tìm các form và input để tấn công"""
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'inputs': []
            }
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append({
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', '')
            })
        elif tag == 'a':
            href = attrs_dict.get('href', '')
            if href and '?' in href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


# ===== BỘ PAYLOAD TẤN CÔNG =====
ATTACK_PAYLOADS = {
    "SQLi": [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "admin' --",
        "1 UNION SELECT username,password FROM users--",
        "1' AND 1=1--",
        "1; DROP TABLE users--",
        "' OR 1=1#",
        "1' UNION SELECT null,null,null,null--",
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>",
        "\"><script>alert(document.cookie)</script>",
        "javascript:alert(1)",
        "<body onload=alert('XSS')>",
    ],
    "Command Injection": [
        "127.0.0.1; whoami",
        "127.0.0.1 && id",
        "127.0.0.1 | cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "127.0.0.1; ls -la /",
    ],
    "Path Traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/shadow",
        "..%252f..%252f..%252fetc%252fpasswd",
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:3306",
        "http://0.0.0.0:8080",
        "http://[::1]:80",
    ],
    "CSRF": [
        "http://attacker.com/csrf/transfer",
        "<form action='/transfer' method='POST' id='csrf'><input type='hidden' name='to' value='hack' /><input type='hidden' name='amount' value='9999' /></form><script>document.getElementById('csrf').submit();</script>",
        "<img src='http://localhost:5170/transfer?to=hacker&amount=9000'>",
        "<html><body><script>fetch('/transfer?to=hacker&amount=9999');</script></body></html>",
    ],
}

# Dấu hiệu tấn công thành công trong response
VULN_SIGNATURES = {
    "SQLi": [
        r"\(\d+,\s*'[^']+',\s*'[^']+'",  # (1, 'admin', 'pass')
        r"root:x:0:0",                   # /etc/passwd qua SQLi
        r"syntax error.*SQL",            # SQL error rõ ràng
        r"mysql_fetch_array\(\)",        # PHP MySQL error
        r"ORA-\d{5}:",                   # Oracle error với mã lỗi
        r"Microsoft OLE DB.*error",      # MSSQL error
        r"pg_query\(\).*failed",         # PostgreSQL error
        r"SQLite3::query\(\)",           # SQLite error
    ],
    "XSS": [
        r"<script[^>]*>alert\(",
        r"<img[^>]+onerror\s*=\s*alert",
        r"<svg[^>]+onload\s*=\s*alert",
    ],
    "Command Injection": [
        r"uid=\d+\(\w+\)\s+gid=\d+",
        r"root:x:0:0:root:/root:",
        r"(?m)^total \d+$\ndrwx",
        r"Windows IP Configuration",
    ],
    "Path Traversal": [
        r"root:x:0:0:root:/root:/bin/",
        r"\[extensions\]\s*\n.*MAPI=",
        r"daemon:x:\d+:\d+:daemon",
    ],
    "SSRF": [
        r"ami-id\s*:\s*ami-[a-f0-9]+",
        r"instance-id\s*:\s*i-[a-f0-9]+",
        r"local-ipv4\s*:\s*\d+\.\d+\.\d+",
        r"SSH-2.0-OpenSSH",
        r"mysql_native_password",
        r"Kết quả fetch URL",
    ],
    "CSRF": [
        r"Chuyển khoản thành công",
        r"Invalid CSRF",
    ],
}


def _infer_endpoint_params(url, method, source_label):
    """Suy luận endpoint params cho API không có query string.

    Tránh bắn param giả vào trang non-API (ví dụ /about, /tuyensinh).
    Returns list of endpoint dicts.
    """
    parsed_path = urlparse(url).path.rstrip('/')
    last_seg = parsed_path.split('/')[-1] if parsed_path else ''
    is_api = bool(re.search(r'/(?:api|v\d+)/', parsed_path))

    results = []
    if method in ('POST', 'PUT', 'PATCH'):
        # POST/PUT thường nhận body → thử các param phổ biến
        for pname in ['id', 'query', 'input', 'data']:
            results.append({
                'url': url, 'param': pname,
                'method': method, 'source': f'{source_label}-body'
            })
    elif is_api or (last_seg and last_seg.isdigit()):
        # GET trên API path hoặc path kết thúc bằng số → thử 'id'
        results.append({
            'url': url, 'param': 'id',
            'method': method, 'source': f'{source_label}-path'
        })
    # else: bỏ qua — page thường không có query param để inject
    return results


# ===== AI ENGINE =====
class AIEngine:
    """Lõi AI — Load model Bi-LSTM để phân loại payload"""
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.label_encoder = None
        self.loaded = False

    def load(self):
        try:
            self.model = tf.keras.models.load_model(
                os.path.join(MODEL_DIR, 'deep_learning_agent_core.keras')
            )
            with open(os.path.join(MODEL_DIR, 'tokenizer.pkl'), 'rb') as f:
                self.tokenizer = pickle.load(f)
            with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'rb') as f:
                self.label_encoder = pickle.load(f)
            self.loaded = True
            logger.info("✅ AI Engine (Bi-LSTM) đã sẵn sàng")
        except Exception as e:
            logger.warning(f"⚠️ Không load được AI model: {e}")
            logger.warning("   Scanner vẫn chạy được (chế độ rule-based)")
            self.loaded = False

    def classify(self, payload):
        """Phân loại payload bằng AI model"""
        if not self.loaded:
            return "Unknown", 0.0
        try:
            seq = self.tokenizer.texts_to_sequences([str(payload)])
            pad = pad_sequences(seq, maxlen=MAX_LEN, padding='post', truncating='post')
            pred = self.model.predict(pad, verbose=0)[0]
            idx = np.argmax(pred)
            label = self.label_encoder.inverse_transform([idx])[0]
            confidence = float(pred[idx]) * 100
            return label, confidence
        except:
            return "Unknown", 0.0


# ===== SCANNER CHÍNH =====
class VulnerabilityScanner:
    """
    Module 1 — Active Vulnerability Scanner
    Chủ động tấn công thử vào web mục tiêu, phân tích response.
    """

    def __init__(self, target_url, ai_brain=False):
        self.target_url = target_url.rstrip('/')
        self.ai_brain_enabled = ai_brain
        self.ai_generator = AIPayloadGenerator() if self.ai_brain_enabled else None
        self.ai = AIEngine()
        self.ai.load()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AI-SecurityScanner/1.0 (Module1-PenTest)'
        })
        self.vulnerabilities = []    # Danh sách lỗ hổng phát hiện
        self.scan_results = []       # Tất cả kết quả scan
        self.endpoints = []          # Các endpoint tìm được
        self.start_time = None
        self.end_time = None
        self._attack_payloads = ATTACK_PAYLOADS  # Bản tham chiếu mặc định (không mutate)

    def banner(self):
        print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════╗
║   AI VULNERABILITY SCANNER — MODULE 1            ║
║  Active Attack Simulation & Vulnerability Detection  ║
╠══════════════════════════════════════════════════════╣
║  Target : {self.target_url:<41s}║
║  Engine : Bi-LSTM Deep Learning + Rule-Based         ║
║  Mode   : Giả lập tấn công (Pentest Simulation)     ║
╚══════════════════════════════════════════════════════╝
{Color.END}""")

    # ----- Phase 1: Crawl tìm endpoint -----
    def crawl_target(self):
        """Crawl trang chủ, tìm tất cả form và link có parameter"""
        print(f"\n{Color.BLUE}[Phase 1] 🔍 Crawling target...{Color.END}")

        try:
            resp = self.session.get(self.target_url, timeout=10)
            if resp.status_code != 200:
                print(f"  {Color.RED}❌ Target trả về HTTP {resp.status_code}{Color.END}")
                return False
        except requests.ConnectionError:
            print(f"  {Color.RED}❌ Không kết nối được tới {self.target_url}{Color.END}")
            print(f"  {Color.YELLOW}💡 Hãy chạy: python webtest.py (port 5173){Color.END}")
            return False

        # Parse forms
        parser = FormParser()
        parser.feed(resp.text)

        # Thêm các form tìm được
        for form in parser.forms:
            action = urljoin(self.target_url, form['action'])
            for inp in form['inputs']:
                if inp['name'] and inp['type'] not in ['submit', 'button', 'hidden']:
                    self.endpoints.append({
                        'url': action,
                        'param': inp['name'],
                        'method': form['method'],
                        'source': 'form'
                    })

        # Thêm các link có query params
        for link in parser.links:
            full_url = urljoin(self.target_url, link)
            parsed = urlparse(full_url)
            if parsed.query:
                for part in parsed.query.split('&'):
                    if '=' in part:
                        param = part.split('=')[0]
                        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        self.endpoints.append({
                            'url': base_url,
                            'param': param,
                            'method': 'GET',
                            'source': 'link'
                        })
        if not self.endpoints:
            print(f"  {Color.YELLOW}⚠️  Không tìm thấy form tĩnh → thử quét JS động...{Color.END}")
            dynamic = self.extract_dynamic_endpoints(self.target_url)
            self.endpoints.extend(dynamic)
            bundle_endpoints = self.scan_js_bundles(self.target_url)
            self.endpoints.extend(bundle_endpoints)

        # Loại bỏ trùng lặp
        seen = set()
        unique = []
        for ep in self.endpoints:
            key = f"{ep['url']}|{ep['param']}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        self.endpoints = unique

        print(f"  ✅ Tìm thấy {Color.BOLD}{len(self.endpoints)}{Color.END} điểm đầu vào:")
        for ep in self.endpoints:
            print(f"     • {ep['method']} {ep['url']}  →  param: {Color.YELLOW}{ep['param']}{Color.END}")

        return len(self.endpoints) > 0

    def extract_dynamic_endpoints(self, url):
        """Dùng Selenium để bắt network requests và quét endpoint động của SPA."""
        if not SELENIUM_AVAILABLE:
            print(f"  {Color.YELLOW}⚠️  Selenium chưa cài.{Color.END}")
            return []

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        endpoints = []
        try:
            print(f"  {Color.CYAN}🌐 Đang render + bắt API calls: {url}{Color.END}")
            driver.get(url)
            time.sleep(4)

            # DEBUG: dump HTML ra file để kiểm tra
            with open("debug_selenium.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            print("  🔍 DEBUG: Đã lưu HTML render vào debug_selenium.html")
            print(f"  🔍 DEBUG: Title trang = '{driver.title}'")
            print(
                f"  🔍 DEBUG: Số thẻ <input> tìm thấy = "
                f"{len(driver.find_elements(By.TAG_NAME, 'input'))}"
            )
            print(
                f"  🔍 DEBUG: Số thẻ <form> tìm thấy = "
                f"{len(driver.find_elements(By.TAG_NAME, 'form'))}"
            )

            driver.execute_script("""
                window._capturedRequests = [];
                const origFetch = window.fetch;
                window.fetch = function(...args) {
                    window._capturedRequests.push({url: args[0], method: (args[1]?.method || 'GET')});
                    return origFetch.apply(this, args);
                };
                const origOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, reqUrl) {
                    window._capturedRequests.push({url: reqUrl, method: method});
                    return origOpen.apply(this, arguments);
                };
            """)

            driver.execute_script("window.scrollTo(0, document.body.scrollHeight)")
            time.sleep(2)

            try:
                logs = driver.get_log('performance')
                for entry in logs:
                    log = json.loads(entry['message'])['message']
                    if log.get('method') != 'Network.requestWillBeSent':
                        continue

                    req = log['params']['request']
                    req_url = req['url']
                    method = req['method']

                    if any(
                        req_url.endswith(ext)
                        for ext in ['.js', '.css', '.png', '.jpg', '.ico', '.woff', '.map']
                    ):
                        continue

                    if 'localhost' in req_url or urlparse(url).netloc in req_url:
                        parsed = urlparse(req_url)
                        if parsed.query:
                            for part in parsed.query.split('&'):
                                if '=' in part:
                                    param = part.split('=')[0]
                                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                    endpoints.append({
                                        'url': base,
                                        'param': param,
                                        'method': method,
                                        'source': 'network-query'
                                    })
                        else:
                            # Suy luận param thông minh thay vì hard-code 'id'
                            endpoints.extend(_infer_endpoint_params(
                                req_url, method, 'network-api'))
            except Exception as e:
                print(f"  {Color.YELLOW}⚠️  Performance log lỗi: {e}{Color.END}")

            try:
                captured_requests = driver.execute_script("return window._capturedRequests || [];")
                for req in captured_requests:
                    req_url = req.get('url')
                    method = (req.get('method') or 'GET').upper()
                    if not req_url:
                        continue
                    req_url = urljoin(url, req_url)
                    parsed = urlparse(req_url)
                    if parsed.query:
                        for part in parsed.query.split('&'):
                            if '=' in part:
                                param = part.split('=')[0]
                                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                                endpoints.append({
                                    'url': base,
                                    'param': param,
                                    'method': method,
                                    'source': 'captured-xhr'
                                })
                    else:
                        # Suy luận param thông minh thay vì hard-code 'id'
                        endpoints.extend(_infer_endpoint_params(
                            req_url, method, 'captured-xhr'))
            except Exception as e:
                print(f"  {Color.YELLOW}⚠️  Captured request log lỗi: {e}{Color.END}")

            try:
                api_paths = driver.execute_script("""
                    const scripts = Array.from(document.querySelectorAll('script[src]'));
                    return scripts.map(s => s.src).filter(
                        s => s.includes('localhost') || s.includes('assets')
                    );
                """)
                for script_url in api_paths[:5]:
                    try:
                        resp = self.session.get(script_url, timeout=5)
                        patterns = re.findall(r'["\\`](/api/[a-zA-Z0-9/_\\-]+)["\\`]', resp.text)
                        patterns += re.findall(r'["\\`](/v\\d+/[a-zA-Z0-9/_\\-]+)["\\`]', resp.text)
                        for path in set(patterns):
                            full_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{path}"
                            endpoints.append({
                                'url': full_url,
                                'param': 'id',
                                'method': 'GET',
                                'source': 'js-bundle-inline'
                            })
                    except Exception:
                        pass
            except Exception as e:
                print(f"  {Color.YELLOW}⚠️  JS scan lỗi: {e}{Color.END}")

            all_inputs = driver.find_elements(By.TAG_NAME, "input")
            existing_params = {ep['param'] for ep in endpoints}
            for inp in all_inputs:
                name = (
                    inp.get_attribute("name")
                    or inp.get_attribute("id")
                    or inp.get_attribute("placeholder")
                    or inp.get_attribute("v-model")
                )
                if name and name not in existing_params:
                    endpoints.append({
                        'url': url,
                        'param': name,
                        'method': 'GET',
                        'source': 'dom-input'
                    })
                    existing_params.add(name)

            seen = set()
            unique = []
            for ep in endpoints:
                key = f"{ep['url']}|{ep['param']}|{ep['method']}"
                if key not in seen:
                    seen.add(key)
                    unique.append(ep)
            endpoints = unique

        except Exception as e:
            print(f"  {Color.RED}❌ Lỗi: {e}{Color.END}")
        finally:
            driver.quit()

        print(f"  ✅ Tìm thêm {Color.BOLD}{len(endpoints)}{Color.END} endpoints động")
        return endpoints

    def scan_js_bundles(self, base_url):
        """Tìm API endpoints ẩn trong JS bundle files."""
        print(f"  {Color.CYAN}📦 Quét JS bundles...{Color.END}")
        found = []
        try:
            resp = self.session.get(base_url, timeout=10)
            js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            for js_path in js_files[:10]:
                js_url = urljoin(base_url, js_path)
                try:
                    js_resp = self.session.get(js_url, timeout=5)
                    paths = re.findall(
                        r'["\\`](/(?:api|v\\d+)/[a-zA-Z0-9/_\\-]{3,})["\\`]',
                        js_resp.text
                    )
                    for path in set(paths):
                        full = (
                            f"{urlparse(base_url).scheme}://"
                            f"{urlparse(base_url).netloc}{path}"
                        )
                        found.append({
                            'url': full,
                            'param': 'id',
                            'method': 'GET',
                            'source': 'js-bundle'
                        })
                        print(f"     • Phát hiện API: {Color.YELLOW}{path}{Color.END}")
                except Exception:
                    pass
        except Exception:
            pass
        return found

    # ----- Phase 2: Tấn công giả lập -----
    def attack_endpoint(self, endpoint, attack_type, payload):
        """Gửi 1 payload tấn công vào 1 endpoint, phân tích kết quả"""
        url = endpoint['url']
        param = endpoint['param']

        try:
            if endpoint['method'] == 'GET':
                resp = self.session.get(url, params={param: payload}, timeout=5)
            else:
                resp = self.session.post(url, data={param: payload}, timeout=5)

            is_vulnerable = False
            evidence = []

            if attack_type in VULN_SIGNATURES:
                for pattern in VULN_SIGNATURES[attack_type]:
                    match = re.search(pattern, resp.text, re.IGNORECASE | re.MULTILINE)
                    if match:
                        is_vulnerable = True
                        evidence.append(f"Pattern match: {match.group()[:60]}")

            if attack_type == "XSS":
                if payload in resp.text and html.escape(payload) != payload:
                    is_vulnerable = True
                    evidence.append("Payload reflected unencoded")

            # AI classification
            ai_label, ai_conf = self.ai.classify(payload)

            result = {
                'endpoint': url,
                'param': param,
                'method': endpoint['method'],
                'attack_type': attack_type,
                'payload': payload,
                'status_code': resp.status_code,
                'is_vulnerable': is_vulnerable,
                'evidence': evidence,
                'ai_classification': ai_label,
                'ai_confidence': ai_conf,
                'response_length': len(resp.text),
                'timestamp': datetime.now().isoformat()
            }

            self.scan_results.append(result)

            if is_vulnerable:
                self.vulnerabilities.append(result)

            return result

        except requests.Timeout:
            return {'payload': payload, 'error': 'Timeout', 'is_vulnerable': False}
        except Exception as e:
            return {'payload': payload, 'error': str(e), 'is_vulnerable': False}

    def run_attacks(self):
        """Phase 2: Gửi tất cả payload vào tất cả endpoint"""
        print(f"\n{Color.RED}[Phase 2]  Bắt đầu giả lập tấn công...{Color.END}")
        total_tests = 0

        for ep in self.endpoints:
            path = urlparse(ep['url']).path
            print(f"\n  {Color.BOLD}── Tấn công: {ep['method']} {path}?{ep['param']}=... ──{Color.END}")

            for attack_type, static_payloads in self._attack_payloads.items():
                payloads_to_test = list(static_payloads)
                if self.ai_brain_enabled and self.ai_generator:
                    print(f"    {Color.MAGENTA}[AI Payload] Đang suy nghĩ {attack_type} cho '{ep['param']}'...{Color.END}", end="", flush=True)
                    ai_payloads = self.ai_generator.generate_context_payloads(attack_type, ep['url'], ep['param'], count=3)
                    if ai_payloads:
                        payloads_to_test.extend(ai_payloads)
                        print(f" Xong (+{len(ai_payloads)} payloads)")
                    else:
                        print(" Fallback to static.")

                for payload in payloads_to_test:
                    total_tests += 1
                    result = self.attack_endpoint(ep, attack_type, payload)

                    if result.get('is_vulnerable'):
                        print(f"    {Color.RED}🔴 VULN{Color.END} [{attack_type}] "
                              f"{Color.YELLOW}{payload[:50]}{Color.END}")
                        for ev in result.get('evidence', []):
                            print(f"         └─ Evidence: {ev[:70]}")
                    else:
                        # Chỉ hiện dấu chấm cho SAFE để không spam
                        pass

            # Tóm tắt sau mỗi endpoint
            ep_vulns = [v for v in self.vulnerabilities
                        if v['endpoint'] == ep['url'] and v['param'] == ep['param']]
            ep_safe = total_tests - len(ep_vulns)
            if ep_vulns:
                print(f"    {Color.RED}⚠️  Endpoint này có {len(ep_vulns)} lỗ hổng!{Color.END}")
            else:
                print(f"    {Color.GREEN}✅ Endpoint này an toàn{Color.END}")

        print(f"\n  📊 Tổng: {total_tests} payloads đã gửi, "
              f"{Color.RED}{len(self.vulnerabilities)} lỗ hổng{Color.END} phát hiện")

    # ----- Phase 3: Tạo báo cáo -----
    def print_report(self):
        """In báo cáo tổng hợp ra terminal"""
        print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════╗
║           📋 BÁO CÁO QUÉT LỖ HỔNG                  ║
╚══════════════════════════════════════════════════════╝
{Color.END}""")

        duration = (self.end_time - self.start_time)
        print(f"  🎯 Target:     {self.target_url}")
        print(f"  ⏱️  Thời gian:  {duration:.1f} giây")
        print(f"  🔢 Endpoints:  {len(self.endpoints)}")
        print(f"  📦 Payloads:   {len(self.scan_results)}")
        print(f"  🔴 Lỗ hổng:    {len(self.vulnerabilities)}")

        if not self.vulnerabilities:
            print(f"\n  {Color.GREEN}{Color.BOLD}✅ KHÔNG TÌM THẤY LỖ HỔNG NÀO!{Color.END}")
            return

        # Nhóm theo loại
        vuln_by_type = {}
        for v in self.vulnerabilities:
            t = v['attack_type']
            if t not in vuln_by_type:
                vuln_by_type[t] = []
            vuln_by_type[t].append(v)

        print(f"\n  {Color.RED}{Color.BOLD}⚠️  PHÁT HIỆN {len(self.vulnerabilities)} LỖ HỔNG:{Color.END}")

        severity_map = {
            "SQLi": "🔴 CRITICAL",
            "Command Injection": "🔴 CRITICAL",
            "XSS": "🟠 HIGH",
            "Path Traversal": "🟠 HIGH",
            "SSRF": "🟠 HIGH",
            "CSRF": "🟡 MEDIUM",
        }

        for attack_type, vulns in vuln_by_type.items():
            severity = severity_map.get(attack_type, "🟡 MEDIUM")
            print(f"\n  {Color.BOLD}━━━ {severity} — {attack_type} ({len(vulns)} phát hiện) ━━━{Color.END}")

            # Lấy các endpoint bị ảnh hưởng (unique)
            affected = set()
            for v in vulns:
                affected.add(f"{v['method']} {urlparse(v['endpoint']).path}?{v['param']}")

            for ep_str in affected:
                print(f"    📍 Endpoint: {Color.YELLOW}{ep_str}{Color.END}")

            # Hiện 1-2 payload mẫu
            print(f"    💣 Payload mẫu:")
            for v in vulns[:2]:
                print(f"       • {v['payload'][:60]}")
                if v['evidence']:
                    print(f"         └─ {v['evidence'][0][:60]}")

        # Điểm số an toàn
        total_endpoints = len(self.endpoints)
        vuln_endpoints = len(set(
            f"{v['endpoint']}|{v['param']}" for v in self.vulnerabilities
        ))
        safe_endpoints = total_endpoints - vuln_endpoints
        if total_endpoints > 0:
            score = (safe_endpoints / total_endpoints) * 100
        else:
            score = 100

        print(f"\n  {Color.BOLD}📊 ĐIỂM AN TOÀN: ", end="")
        if score >= 80:
            print(f"{Color.GREEN}{score:.0f}/100{Color.END}")
        elif score >= 50:
            print(f"{Color.YELLOW}{score:.0f}/100{Color.END}")
        else:
            print(f"{Color.RED}{score:.0f}/100{Color.END}")

        print(f"     • Endpoint an toàn: {safe_endpoints}/{total_endpoints}")
        print(f"     • Endpoint có lỗi:  {vuln_endpoints}/{total_endpoints}")

    def save_report(self, output_path=None):
        """Lưu báo cáo ra file JSON + Markdown"""
        if output_path is None:
            output_path = os.path.dirname(os.path.abspath(__file__))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # JSON report
        json_path = os.path.join(output_path, f"scan_report_{timestamp}.json")
        report_data = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'duration_seconds': round(self.end_time - self.start_time, 2),
            'total_endpoints': len(self.endpoints),
            'total_payloads_sent': len(self.scan_results),
            'total_vulnerabilities': len(self.vulnerabilities),
            'endpoints': self.endpoints,
            'vulnerabilities': self.vulnerabilities,
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        # Markdown report
        md_path = os.path.join(output_path, f"scan_report_{timestamp}.md")
        duration = self.end_time - self.start_time

        vuln_by_type = {}
        for v in self.vulnerabilities:
            t = v['attack_type']
            if t not in vuln_by_type:
                vuln_by_type[t] = []
            vuln_by_type[t].append(v)

        severity_map = {
            "SQLi": "🔴 CRITICAL",
            "Command Injection": "🔴 CRITICAL",
            "XSS": "🟠 HIGH",
            "Path Traversal": "🟠 HIGH",
            "SSRF": "🟠 HIGH",
            "CSRF": "🟡 MEDIUM",
        }

        md = f"""#  BÁO CÁO QUÉT LỖ HỔNG — MODULE 1

**Ngày quét:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
**Target:** `{self.target_url}`
**Thời gian quét:** {duration:.1f} giây
**Engine:** AI Bi-LSTM + Rule-Based Signatures

---

## 📊 Tổng quan

| Metric | Giá trị |
|--------|---------|
| Endpoints quét | {len(self.endpoints)} |
| Payloads đã gửi | {len(self.scan_results)} |
| **Lỗ hổng phát hiện** | **{len(self.vulnerabilities)}** |

---

## ⚠️ Chi tiết lỗ hổng

"""
        if not self.vulnerabilities:
            md += "> ✅ **Không tìm thấy lỗ hổng nào!**\n"
        else:
            for attack_type, vulns in vuln_by_type.items():
                severity = severity_map.get(attack_type, "🟡 MEDIUM")
                md += f"### {severity} — {attack_type}\n\n"

                affected = set()
                for v in vulns:
                    affected.add(f"`{v['method']} {urlparse(v['endpoint']).path}?{v['param']}`")

                md += f"**Endpoints bị ảnh hưởng:** {', '.join(affected)}\n\n"
                md += "| Payload | Evidence | AI Classification |\n"
                md += "|---------|----------|--------------------|\n"
                for v in vulns[:5]:
                    ev = v['evidence'][0][:40] if v['evidence'] else "—"
                    md += f"| `{v['payload'][:40]}` | {ev} | {v['ai_classification']} ({v['ai_confidence']:.0f}%) |\n"
                md += "\n---\n\n"

        # Score
        total_ep = len(self.endpoints)
        vuln_ep = len(set(f"{v['endpoint']}|{v['param']}" for v in self.vulnerabilities))
        score = ((total_ep - vuln_ep) / total_ep * 100) if total_ep > 0 else 100
        md += f"\n## 📊 Điểm an toàn: **{score:.0f}/100**\n"

        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md)

        print(f"\n  💾 Báo cáo đã lưu:")
        print(f"     • JSON: {json_path}")
        print(f"     • MD:   {md_path}")
        return json_path, md_path

    # ----- CHẠY SCAN TOÀN BỘ -----
    def run(self, save_report=False):
        """Chạy toàn bộ quy trình scan"""
        self.banner()
        self.start_time = time.time()

        # Phase 0: AI Brain (Llama via Groq)
        if self.ai_brain_enabled:
            print(f"\n{Color.MAGENTA}[Phase 0] 🧠 AI Brain kích hoạt. Các Payload sẽ được sinh độc lập theo ngữ cảnh ở Phase 2...{Color.END}")

        # Phase 1: Crawl
        if not self.crawl_target():
            print(f"\n{Color.RED}❌ Không tìm được endpoint nào. Dừng scan.{Color.END}")
            return

        # Phase 2: Attack
        self.run_attacks()

        self.end_time = time.time()

        # Phase 3: Report
        self.print_report()

        if save_report:
            self.save_report()

        return self.vulnerabilities


# ===== FLASK API SERVER MODE =====
def create_api_server():
    """Tạo Flask server để HTML frontend gọi scan qua API"""
    from flask import Flask, request as flask_request, jsonify, send_file
    from flask_cors import CORS

    api = Flask(__name__)
    CORS(api)

    # Pre-load AI engine 1 lần
    shared_ai = AIEngine()
    shared_ai.load()

    @api.route('/')
    def serve_ui():
        """Serve giao diện HTML"""
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ai_waf_scanner.html')
        return send_file(html_path)

    @api.route('/api/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'operational',
            'ai_engine': shared_ai.loaded,
            'timestamp': datetime.now().isoformat()
        })

    @api.route('/api/scan', methods=['POST'])
    def api_scan():
        """API scan — nhận target URL, trả kết quả JSON"""
        data = flask_request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'Thiếu trường "target" trong request body'}), 400

        target_url = data['target'].strip()
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url

        logger.info(f" API Scan requested: {target_url}")

        try:
            scanner = VulnerabilityScanner(target_url)
            scanner.ai = shared_ai  # Dùng chung AI engine đã load
            scanner.start_time = time.time()

            # Phase 1: Crawl
            if not scanner.crawl_target():
                return jsonify({
                    'error': 'Không tìm thấy endpoint nào trên trang',
                    'target': target_url
                }), 404

            # Phase 2: Attack
            scanner.ai_brain_enabled = data.get('ai_brain', False)
            if scanner.ai_brain_enabled:
                scanner.ai_generator = AIPayloadGenerator()
            scanner.run_attacks()

            scanner.end_time = time.time()
            duration = scanner.end_time - scanner.start_time

            # Phase 3: Build response
            severity_map = {
                "SQLi": "CRITICAL",
                "Command Injection": "CRITICAL",
                "XSS": "HIGH",
                "Path Traversal": "HIGH",
                "SSRF": "HIGH",
                "CSRF": "MEDIUM",
            }

            vuln_by_type = {}
            for v in scanner.vulnerabilities:
                t = v['attack_type']
                if t not in vuln_by_type:
                    vuln_by_type[t] = []
                vuln_by_type[t].append(v)

            total_ep = len(scanner.endpoints)
            vuln_ep = len(set(f"{v['endpoint']}|{v['param']}" for v in scanner.vulnerabilities))
            score = int(((total_ep - vuln_ep) / total_ep * 100)) if total_ep > 0 else 100

            # Lưu báo cáo lỗi cho Feedback Loop (AI Agent fix)
            report_path = None
            if scanner.vulnerabilities:
                report_path = scanner.save_report()

            result = {
                'target': target_url,
                'duration': round(duration, 1),
                'total_endpoints': total_ep,
                'total_payloads': len(scanner.scan_results),
                'total_vulnerabilities': len(scanner.vulnerabilities),
                'score': score,
                'endpoints': scanner.endpoints,
                'vulnerabilities_by_type': {},
                'report_files': report_path,
            }

            for attack_type, vulns in vuln_by_type.items():
                affected = list(set(
                    f"{v['method']} {urlparse(v['endpoint']).path}?{v['param']}"
                    for v in vulns
                ))
                result['vulnerabilities_by_type'][attack_type] = {
                    'severity': severity_map.get(attack_type, 'MEDIUM'),
                    'count': len(vulns),
                    'affected_endpoints': affected,
                    'samples': [
                        {
                            'payload': v['payload'],
                            'evidence': v['evidence'][:2] if v['evidence'] else [],
                            'ai_label': v['ai_classification'],
                            'ai_confidence': round(v['ai_confidence'], 1),
                        }
                        for v in vulns[:5]
                    ]
                }

            logger.info(f"✅ Scan hoàn tất: {len(scanner.vulnerabilities)} lỗ hổng, {duration:.1f}s")
            return jsonify(result)
            
        except Exception as e:
            import traceback
            logger.error(f"❌ Exception in /api/scan: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'error': f'Internal server error: {str(e)}',
                'details': traceback.format_exc()
            }), 500

    return api


# ===== MAIN =====
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=' AI Vulnerability Scanner — Module 1'
    )
    parser.add_argument(
        '--target', '-t',
        default=None,
        help='URL web mục tiêu cần quét (ví dụ: http://localhost:5173)'
    )
    parser.add_argument(
        '--report', '-r',
        action='store_true',
        help='Lưu báo cáo ra file (JSON + Markdown)'
    )
    parser.add_argument(
        '--server', '-s',
        action='store_true',
        help='Chạy chế độ Web Server (API + giao diện HTML)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5001,
        help='Port cho Web Server (mặc định: 5001)'
    )
    parser.add_argument(
        '--loop', '-l',
        action='store_true',
        help='Chế độ giám sát liên tục (quét lặp lại sau mỗi khoảng nghỉ)'
    )
    parser.add_argument(
        '--ai-brain', '-a',
        action='store_true',
        help='Kích hoạt AI Brain (Groq) để sinh thêm payload sáng tạo'
    )
    args = parser.parse_args()

    if args.server:
        # CHẾ ĐỘ WEB SERVER: Bản thân nó đã chạy liên tục chờ request từ UI
        app = create_api_server()
        logger.info(f" Module 1 Web UI đang chạy tại: http://127.0.0.1:{args.port}")
        app.run(debug=False, port=args.port, threaded=True)
    else:
        # CHẾ ĐỘ CLI (Dòng lệnh)
        target = args.target
        while not target:
            print(f"{Color.CYAN} Vui lòng nhập URL mục tiêu: {Color.END}", end="")
            target = input().strip()
            if target and not target.startswith('http'):
                target = 'http://' + target

        if args.loop:
            # KỊCH BẢN CHẠY LIÊN TỤC (Dành cho sau này tích hợp làm WAF)
            print(f"{Color.GREEN} BẮT ĐẦU CHẾ ĐỘ GIÁM SÁT LIÊN TỤC TRÊN: {target}{Color.END}")
            print(f"{Color.YELLOW}Nhấn Ctrl+C để dừng hệ thống.{Color.END}\n")
            try:
                scanner = VulnerabilityScanner(target, ai_brain=args.ai_brain)
                while True:
                    scanner.run(save_report=args.report)
                    print(f"\n{Color.BLUE} Hoàn tất chu kỳ quét. Nghỉ 60 giây trước khi quét lại...{Color.END}")
                    time.sleep(60) # Nghỉ 60s để tránh làm nghẽn mạng target
            except KeyboardInterrupt:
                print(f"\n{Color.RED} Đã dừng giám sát.{Color.END}")
        else:
            # KỊCH BẢN QUÉT 1 LẦN RỒI HỎI (Như cũ nhưng gọn hơn)
            scanner = VulnerabilityScanner(target, ai_brain=args.ai_brain)
            while True:
                scanner.run(save_report=args.report)
                print(f"\n{Color.YELLOW} Bạn có muốn quét lại hoặc thử URL khác không? (y/n): {Color.END}", end="")
                choice = input().lower().strip()
                if choice != 'y':
                    break
                print(f"{Color.CYAN}👉 Nhập URL mới (để trống để dùng lại URL cũ): {Color.END}", end="")
                new_target = input().strip()
                if new_target:
                    if not new_target.startswith('http'):
                        new_target = 'http://' + new_target
                    scanner = VulnerabilityScanner(new_target)
