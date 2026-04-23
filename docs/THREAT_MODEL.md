# Threat Model — AI Security System

## 1. System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     AI Security System (Core)                    │
│                                                                  │
│  ┌────────────────────┐         ┌────────────────────┐          │
│  │     Module 1        │         │     Module 2        │          │
│  │     Scanner         │────────►│     AI WAF          │          │
│  │     (Attacker)      │         │     (Defender)      │          │
│  └────────────────────┘         └────────────────────┘          │
│        │                               │                         │
│        ▼                               ▼                         │
│  Adversarial                     Rule-Based                      │
│  Hill Climbing                   + Bi-LSTM                       │
│  (15 iterations)                 (4 layers)                      │
└──────────────────────────────────────────────────────────────────┘
```

- **Module 1 (Scanner)**: Gia lap attacker — chu dong quet endpoint, ban payload, thuc hien adversarial mutation (Greedy Hill Climbing) de bypass WAF.
- **Module 2 (WAF)**: Bao ve backend — loc request qua 4 lop defense (Blacklist → Rate Limit → Rule → AI).

---

## 1.1. Threat Model Refinement — Oracle Assumption

Adversarial scanner (Module 1) su dung **chinh model Bi-LSTM cua WAF** lam oracle de danh gia confidence payload truoc khi mutation. Day la **white-box assumption**: attacker co access truc tiep vao confidence scores cua model.

> **Luu y quan trong**: Attacker ngoai doi **KHONG** co access vao model. Gia dinh white-box duoc su dung co chu dich:

| Gia dinh | Ly do |
|----------|-------|
| White-box oracle | Kiem chung **worst-case robustness** cua model. Neu model chiu duoc white-box attack, thi black-box attack cang khong thanh cong. |
| Shared confidence threshold | Oracle va WAF dung cung nguong 75% de dam bao ket qua mutation phan anh chinh xac hanh vi thuc te cua WAF. |
| Attacker biet architecture | Scanner biet model la Bi-LSTM, nhung KHONG biet weights/training data. Tuong duong voi kich ban attacker doc paper nghien cuu ve he thong. |

**Ket luan**: Day la kiem thu **upper-bound** cho nang luc ke tan cong. Bypass rate do duoc (6.2%) la **gia tri xau nhat** — trong thuc te, attacker se kho bypass hon nhieu vi khong co oracle.

**De mo rong sang black-box testing**: Thay the oracle bang **response-based scoring** (chi dua tren HTTP status code 200/403/429), loai bo truc tiep model access. Day la huong phat trien cho phien ban tiep theo.


## 2. Attacker Profile

| Thuộc tính | Mô tả |
|------------|-------|
| **Identity** | External attacker, không xác thực |
| **Access** | Gửi HTTP request tùy ý qua mạng |
| **Privilege** | Không có quyền truy cập hệ thống, không đọc được source code |
| **Knowledge** | Black-box — chỉ quan sát response (block/allow/error) |
| **Goal** | Bypass AI WAF → khai thác lỗ hổng backend (SQLi, XSS, RCE) |

### Attacker Capabilities

1. **Payload crafting**: Tạo payload tấn công cho 7+ loại (SQLi, XSS, Command Injection, Path Traversal, SSRF, SSTI, NoSQLi, XXE, JWTAuth)
2. **Payload mutation**: Biến đổi payload bằng kỹ thuật obfuscation:
   - Case swapping (`SELECT` → `sElEcT`)
   - URL encoding (`'` → `%27`)
   - HTML entity encoding (`<` → `&lt;`)
   - SQL comment injection (`UNION` → `U/**/NION`)
   - Whitespace substitution (space → tab/newline)
   - String concatenation (`'` → `CHAR(39)`)
3. **Iterative refinement**: Greedy hill climbing — thử nhiều mutation, chọn cái giảm confidence nhất, lặp lại trên kết quả tốt nhất
4. **Response analysis**: Phân tích HTTP status code và response body để xác nhận exploit thành công

### Attacker Limitations

- Không thể truy cập model weights hoặc architecture
- Không thể đọc WAF logs hoặc configuration
- Bị giới hạn bởi rate limiting (100 req/min → 10 req/min sau khi bị flag)
- Bị blacklist tự động sau 5 lần bị block trong 60 giây

---

## 3. Attack Surface

### Input Vectors

| Vector | Scan Coverage | Ví dụ |
|--------|--------------|-------|
| Query parameters | ✅ Đầy đủ | `?q=' OR 1=1--` |
| POST body (form) | ✅ Đầy đủ | `username=admin'--` |
| POST body (JSON) | ✅ Đầy đủ | `{"query": "' OR 1=1"}` |
| URL path | ✅ Đầy đủ | `/../../etc/passwd` |
| Cookie values | ✅ WAF scan | `session=<script>alert(1)</script>` |
| Headers | ✅ WAF scan (5 headers) | `Referer: javascript:alert(1)` |

### Attack Types Covered

| Loại | Severity | Mô tả |
|------|----------|-------|
| SQL Injection | 🔴 CRITICAL | Injection qua query parameter/body |
| Command Injection | 🔴 CRITICAL | OS command execution qua input |
| XSS | 🟠 HIGH | Reflected/stored script injection |
| Path Traversal | 🟠 HIGH | Đọc file hệ thống qua `../` |
| SSRF | 🟠 HIGH | Request tới internal services |
| SSTI | 🟠 HIGH | Template injection (`{{7*7}}`) |
| NoSQLi | 🟠 HIGH | MongoDB operator injection |
| XXE | 🟠 HIGH | XML external entity |
| JWTAuth | 🟡 MEDIUM | JWT algorithm manipulation |
| CSRF | 🟡 MEDIUM | Cross-site request forgery |

---

## 4. Defense Boundary

### Defense-in-Depth Architecture

```
HTTP Request
    │
    ▼
┌──────────────────────────────────────────┐
│  L1: IP Blacklist Check                  │  ← Auto-ban IP tan cong lien tuc
│  Condition: 5 blocks/60s → ban 10 min    │
├──────────────────────────────────────────┤
│  L2: Rate Limiting                       │  ← Chong brute force / DoS
│  Normal: 100 req/min                     │
│  Flagged: 10 req/min                     │
├──────────────────────────────────────────┤
│  L2.5: CANONICALIZATION                   │  ← Chong encoding bypass
│  Recursive URL decode (max 5 rounds)     │
│  HTML entity decode (&lt; → <)           │
│  Null byte strip (%00)                   │
├──────────────────────────────────────────┤
│  L3: Rule-Based Regex (15 patterns)       │  ← Chan nhanh known signatures
│  Confidence: 99.9% (hard block)           │
│  Coverage: SQLi, XSS, CMDi, Path, SSRF   │
│            SSTI, NoSQLi, XXE, JWTAuth     │
├──────────────────────────────────────────┤
│  L4: AI Bi-LSTM Deep Scan                 │  ← Phat hien unknown/mutated
│  Threshold: 75% confidence                │
│  Model: Bi-LSTM (97.43% test accuracy)    │
│  Suspicious zone: 50-75% (log, allow)     │
└──────────────────────────────────────────┘
    │
    ▼ (ALLOWED)
┌──────────────────────────────────────────┐
│  Backend Application                     │
└──────────────────────────────────────────┘
```

### Canonicalization Layer (L2.5)

Day la lop **preprocessing bat buoc** truoc khi payload duoc scan boi Rule-based hoac AI:

```
%3Cscript%3E  →  URL decode  →  <script>    → L3 Regex bat
&lt;script&gt; →  HTML decode →  <script>    → L3 Regex bat  
%253Cscript   →  Double decode →  <script>  → L3 Regex bat
admin%00--    →  Null strip  →  admin--     → L4 AI scan
```

Khong co lop nay, attacker chi can `url_encode()` 1 lan la bypass ca Regex lan AI.


### Threshold Design Rationale

**Tại sao WAF dùng 75% threshold, không phải 50%?**

- **50% threshold**: Quá nhiều false positive → block request hợp lệ → ảnh hưởng UX
- **75% threshold**: Cân bằng giữa security và usability
- **Rule-based layer bù đắp**: Các attack signature rõ ràng (VD: `<script>`, `UNION SELECT`) đã bị chặn bởi regex TRƯỚC khi đến AI → AI chỉ cần xử lý payload đã bị biến đổi
- **Suspicious zone (50-75%)**: Ghi log nhưng không block → cho phép phân tích offline

**Tại sao Scanner Oracle cũng dùng 75%?**

- Oracle threshold = WAF threshold là thiết kế có chủ ý
- Scanner cần biết "WAF sẽ chặn payload này không?" → dùng cùng ngưỡng để mô phỏng chính xác
- Nếu oracle dùng ngưỡng khác → kết quả mutation không phản ánh thực tế

---

## 5. Risk Assessment

### Known Weaknesses

| ID | Weakness | Impact | Mitigation |
|----|----------|--------|------------|
| W1 | AI model co the bi bypass bang encoding | Payload lot qua L4 | L2.5 canonicalization + L3 (rule-based) bat lai |
| W2 | Rule-based khong cover zero-day patterns | Unknown attack lot qua L3 | L4 (AI) xu ly payload moi |
| W3 | Rate limit khong chan duoc distributed attack | Attacker dung nhieu IP | Can them L0: Cloudflare/CDN level protection |
| W4 | Model chi train tren text payload | Binary/multipart bypass | Can mo rong training data |
| W5 | **Oracle leakage (white-box)** | Scanner dung model WAF lam oracle → ko phan anh black-box thuc te | **Da document tai section 1.1** — bypass rate 6.2% la worst-case upper bound |

### Residual Risk

Sau khi đi qua 4 lớp defense, rủi ro còn lại:
- **Zero-day attack pattern**: Payload hoàn toàn mới mà cả rule lẫn AI chưa từng thấy
- **Slow-rate attack**: Tấn công rải rác dưới ngưỡng rate limit
- **Application-level logic bugs**: Lỗi logic không phải injection → WAF không detect được

---

## 6. Adversarial Testing Strategy

Scanner (Module 1) đóng vai trò adversary để kiểm chứng defense:

```
Payload gốc
    │
    ▼
Oracle Check: AI model confidence ≥ 75%?
    │
    ├── YES (detected) ──► Greedy Hill Climbing (15 iterations)
    │                           │
    │                           ├── mutate payload (6 strategies)
    │                           ├── evaluate confidence per mutation
    │                           ├── chọn mutation giảm confidence nhiều nhất
    │                           ├── lặp lại trên kết quả tốt nhất
    │                           └── dừng khi confidence < 50% hoặc hết vòng
    │                           │
    │                           ▼
    │                      Fire evasive payload → WAF
    │
    └── NO (not detected) ──► Fire original payload → WAF
                                    │
                                    ▼
                              Log kết quả vào attack_log.db
                              Phân tích: model_evaded? waf_blocked? vuln_found?
```

### Security Metrics Tracked

| Metric | Mô tả |
|--------|-------|
| **Bypass Rate** | `evasions / model_detected` — % payload vượt qua AI sau mutation |
| **Attack Success Rate** | `vulns_found / total_payloads` — % khai thác lỗ hổng thành công |
| **Time to Bypass** | Thời gian trung bình cho 1 lần bypass thành công |
| **Rounds to Bypass** | Số vòng hill climbing trung bình để bypass |
| **Rule Catch Rate** | `rule_blocked / (rule_blocked + ai_blocked)` — tỷ lệ rule "cứu" khi AI miss |
