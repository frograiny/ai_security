---
tags: [results, experiment, evaluation]
aliases: [Kết quả, Results, Evaluation]
---

# 📊 Kết Quả Thực Nghiệm

> Tổng hợp kết quả đánh giá từ các thí nghiệm **Red Team vs Blue Team** — Scanner tấn công, WAF phòng thủ.

---

## Kết quả Model AI

| Metric | Giá trị | Ghi chú |
|--------|---------|---------|
| **Test Accuracy** | 97.43% | Trên tập Test độc lập |
| **Test Loss** | 0.0858 | Cross-entropy loss |
| **Training Samples** | 65,643 | Từ nhiều nguồn |
| **Test Samples** | 9,847 | 15% tổng dataset |
| **Số nhãn** | 13 | 12 attack + Normal |
| **Split** | 70/15/15 | Train/Val/Test (proper, no leakage) |

---

## Red Team vs Blue Team

### Kịch bản 1: Scanner vs WAF (Tấn công Đa luồng)

Bật [[04-Module-1-Scanner|Scanner (M1)]] quét trực diện vào [[05-Module-2-WAF|WAF (M2)]]:

| Chỉ số | Kết quả |
|--------|---------|
| **Kết quả** | WAF báo động đỏ ngay lập tức |
| **Rate Limiting** | IP Scanner bị giáng xuống 10 req/min |
| **Auto-Blacklist** | IP bị ban hoàn toàn |
| **HTTP Response** | `429 Too Many Requests` cho mọi request sau đó |

> [!success] WAF hoạt động hoàn hảo
> Kiến trúc WAF đã chống chịu được áp lực tấn công tự động cường độ cao. Scanner bị **vô hiệu hóa hoàn toàn** chỉ sau vài giây.

### Kịch bản 2: Scanner vs Backend (Không có WAF)

Scanner tấn công **trực tiếp** vào webtest.py (port 5170):

| Chỉ số | Không WAF | Có WAF |
|--------|:---------:|:------:|
| **Safety Score** | 18/100 | **91/100** |
| **Vulnerabilities Found** | 8+ | 0 |
| **SQLi** | ✅ Exploit thành công | ❌ Blocked |
| **XSS** | ✅ Script chạy | ❌ Blocked |
| **CMDi** | ✅ OS output | ❌ Blocked |

---

## Adversarial Analysis

Kết quả [[07-Adversarial-Loop|Greedy Hill Climbing]]:

```
═══ ADVERSARIAL ANALYSIS ═══
  📡 Payloads gốc:        ~240
  🔍 Model detected:       ~228 (95%)
  🧬 Mutations thử:        ~1,368
  💀 Evasions tìm được:    ~15 (6.2%)
  
  📊 Model Robustness:     93.8%
```

### Top Mutation Strategies

| # | Strategy | Hiệu quả | Ý nghĩa |
|---|----------|-----------|---------|
| 1 | `case_swap` | Cao nhất | Bi-LSTM nhạy cảm với case |
| 2 | `url_encode` | Cao | Encoding thay đổi token |
| 3 | `sql_comment` | Trung bình | Ngắt chuỗi keyword |
| 4 | `whitespace` | Thấp | Ít ảnh hưởng tokenizer |
| 5 | `html_entity` | Thấp | Canonicalization bắt lại |

### Insight quan trọng

| Trạng thái | Số lượng | Ý nghĩa |
|-----------|----------|---------|
| Model detect + WAF block | Đa số | Hoạt động bình thường ✅ |
| Model evade + WAF block | ~10 | Model yếu nhưng Rule cứu ⚡ |
| Model evade + WAF pass | ~5 | **BYPASS** — insight giá trị nhất 🔥 |

> [!tip] Vai trò của Rule-based
> Rule-based (L3) đóng vai trò **lưới an toàn** — khi AI miss, regex vẫn bắt được ~67% trường hợp. Đây là lý do cần kết hợp **AI + Rule**.

---

## So sánh Module 1 vs Module 3

| Tiêu chí | [[04-Module-1-Scanner|M1 Scanner]] | [[06-Module-3-HackerBrain|M3 Hacker Brain]] |
|----------|:---------:|:--------:|
| Payload source | List cố định | AI sinh theo context |
| Mutation | Greedy Hill Climbing | Groq LLM |
| Chaining | Không | Có (multi-step) |
| Tốc độ | Rất nhanh (multi-thread) | Chậm (API call) |
| Coverage | 10 loại | 15+ loại |
| Độ chính xác | Signature-based | Context-aware |

---

## Performance Metrics

| Metric | Giá trị |
|--------|---------|
| **Inference Time** (1 payload) | ~25ms |
| **Batch Inference** (8 payloads) | ~30ms |
| **WAF Throughput** | ~1,000 req/s (ước lượng) |
| **Cache Hit Rate** | ~60-80% (phụ thuộc traffic) |
| **Average Response Time** | ~50ms (có WAF) |

---

## Bảng Tổng hợp

| Chỉ số | Giá trị |
|--------|---------|
| ✅ Model Accuracy | 97.43% |
| ✅ Safety Score (có WAF) | 91/100 |
| ✅ Bypass Rate (worst-case) | ~6.2% |
| ✅ Rule Catch Rate | ~67% khi AI miss |
| ✅ Inference Time | ~25ms |
| ✅ Số nhãn hỗ trợ | 13 |
| ✅ Số endpoint testbed | 12 |
| ✅ Số mutation strategies | 6 safe + 2 risky |

---

**Xem thêm:** [[07-Adversarial-Loop]] | [[11-Threat-Model]] | [[16-Định-Hướng-Tương-Lai]]
