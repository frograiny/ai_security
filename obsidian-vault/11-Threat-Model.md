---
tags: [threat-model, security, theory]
aliases: [Threat Model, Mô hình đe doạ]
---

# 🎯 Threat Model

> Mô hình mối đe doạ mô tả **ai tấn công**, **tấn công gì**, **bề mặt tấn công** ở đâu, và hệ thống **phòng thủ** như thế nào.

---

## Attacker Profile

| Thuộc tính | Mô tả |
|-----------|-------|
| **Identity** | External attacker, không xác thực |
| **Access** | Gửi HTTP request tùy ý qua mạng |
| **Privilege** | Không có quyền truy cập hệ thống |
| **Knowledge** | Black-box — chỉ quan sát response |
| **Goal** | Bypass [[05-Module-2-WAF|AI WAF]] → khai thác lỗ hổng backend |

### Capabilities
1. **Payload crafting** — 10+ loại tấn công
2. **Payload mutation** — 6 chiến lược obfuscation
3. **Iterative refinement** — [[07-Adversarial-Loop|Greedy Hill Climbing]] (15 vòng)
4. **Response analysis** — Phân tích HTTP status + response body

### Limitations
- ❌ Không truy cập model weights / architecture
- ❌ Không đọc được WAF logs / config
- ❌ Bị rate limiting (100 → 10 req/min sau khi flagged)
- ❌ Bị auto-blacklist sau 5,000 blocks/60s

---

## Bề mặt Tấn công (Attack Surface)

### Input Vectors

| Vector | Scan Coverage | Ví dụ |
|--------|:---:|-------|
| Query parameters | ✅ | `?q=' OR 1=1--` |
| POST body (form) | ✅ | `username=admin'--` |
| POST body (JSON) | ✅ | `{"query": "' OR 1=1"}` |
| URL path | ✅ | `/../../etc/passwd` |
| Cookie values | ✅ | `session=<script>alert(1)` |
| Headers (5 loại) | ✅ | `Referer: javascript:alert(1)` |

### Attack Types (xem chi tiết: [[10-Attack-Catalog]])

| Loại | Severity |
|------|----------|
| SQL Injection | 🔴 CRITICAL |
| Command Injection | 🔴 CRITICAL |
| XSS | 🟠 HIGH |
| Path Traversal | 🟠 HIGH |
| SSRF | 🟠 HIGH |
| SSTI | 🟠 HIGH |
| NoSQLi | 🟠 HIGH |
| XXE | 🟠 HIGH |
| JWTAuth | 🟡 MEDIUM |
| CSRF | 🟡 MEDIUM |

---

## Oracle Assumption (White-box)

> [!important] White-box Testing — Có chủ ý
> [[04-Module-1-Scanner|Scanner]] sử dụng **chính model Bi-LSTM của WAF** làm oracle.
> Đây là **worst-case assumption** — attacker thực tế **KHÔNG** có access vào model.

| Gia định | Lý do |
|----------|-------|
| White-box oracle | Kiểm chứng worst-case robustness |
| Shared confidence | Oracle & WAF cùng ngưỡng 75% |
| Biết architecture | Tương đương attacker đọc paper |

**Kết luận:** Bypass rate ~6.2% là **upper-bound**. Thực tế sẽ **thấp hơn nhiều**.

---

## Đánh giá Rủi ro (Risk Assessment)

### Điểm yếu Đã biết

| ID | Điểm yếu | Impact | Mitigation |
|----|----------|--------|------------|
| W1 | AI model có thể bị bypass bằng encoding | Payload lọt qua L4 | L2.5 canonicalization + L3 regex |
| W2 | Rule-based không cover zero-day | Unknown attack lọt qua L3 | L4 AI xử lý payload mới |
| W3 | Rate limit không chặn distributed attack | Nhiều IP tấn công | Cần thêm CDN/Cloudflare |
| W4 | Model chỉ train trên text payload | Binary/multipart bypass | Mở rộng training data |
| W5 | Oracle leakage (white-box) | Bypass rate cao hơn thực tế | Đã document — upper bound |

### Rủi ro Còn lại (Residual Risk)

1. **Zero-day pattern** — Payload hoàn toàn mới, chưa từng thấy
2. **Slow-rate attack** — Tấn công dưới ngưỡng rate limit
3. **Application logic bugs** — Lỗi logic không phải injection → WAF không detect được

---

## Security Metrics

| Metric | Mô tả | Công thức |
|--------|-------|-----------|
| **Bypass Rate** | % payload vượt qua AI sau mutation | `evasions / model_detected` |
| **Attack Success Rate** | % khai thác lỗ hổng thành công | `vulns_found / total_payloads` |
| **Time to Bypass** | Thời gian trung bình cho 1 bypass | seconds |
| **Rounds to Bypass** | Số vòng hill climbing trung bình | rounds |
| **Rule Catch Rate** | Tỷ lệ rule "cứu" khi AI miss | `rule_blocked / (rule + ai)` |

---

**Xem thêm:** [[07-Adversarial-Loop]] | [[05-Module-2-WAF]] | [[12-Kết-Quả-Thực-Nghiệm]]
