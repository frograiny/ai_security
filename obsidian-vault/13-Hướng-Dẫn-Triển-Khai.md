---
tags: [deployment, guide, operations]
aliases: [Hướng dẫn, Deployment Guide, Cách chạy]
---

# 🚀 Hướng Dẫn Triển Khai & Vận Hành

> Tài liệu hướng dẫn chi tiết các bước khởi chạy và kiểm thử toàn bộ hệ thống AI Security.

---

## Yêu cầu

### Phần mềm
- Python 3.8+
- pip (Python package manager)
- (Tuỳ chọn) Node.js + npm (cho WAF Dashboard)

### Cài đặt Dependencies

```bash
cd d:\AI\ai_security
pip install -r requirements.txt
```

**Dependencies chính:**
| Package | Vai trò |
|---------|---------|
| `flask` | Web framework |
| `flask-cors` | CORS support |
| `tensorflow` | Deep Learning model |
| `numpy` | Xử lý số |
| `requests` | HTTP client |
| `python-dotenv` | Load `.env` file |
| `waitress` | Production WSGI server |
| `scikit-learn` | Label Encoder |

### File `.env` (cho Module 3)

```ini
GROQ_API_KEY=gsk_your_api_key_here
GROQ_MODEL_FAST=qwen3-32b
GROQ_MODEL_SMART=qwen3-32b
```

---

## Kiến trúc Triển khai

```
Terminal 1: webtest.py     ──► Port 5170 (Backend Vulnerable)
Terminal 2: modul2_waf.py  ──► Port 5000 (WAF Proxy)
Terminal 3: modul1_scanner.py ──► Tấn công vào Port 5000
Terminal 4: (Tuỳ chọn) WAF Dashboard ──► Port 5173
```

---

## Bước 1: Khởi động Web Testbed

> Đây là trang web chứa 10 loại lỗ hổng — "bia đỡ đạn".

```bash
# Terminal 1
cd d:\AI\ai_security
python webtest.py
```

**Kết quả mong đợi:**
```
🔥 Web mục tiêu đang chạy tại http://localhost:5170
```

> [!tip] Kiểm tra
> Mở trình duyệt → `http://localhost:5170` → Thấy giao diện Portal NCKH.

---

## Bước 2: Khởi động AI WAF Shield

> WAF đứng chắn trước port 5170, kiểm duyệt mọi request.

```bash
# Terminal 2
cd d:\AI\ai_security
python modul2_waf.py
```

**Kết quả mong đợi:**
```
✅ SHIELD AGENT: Bi-LSTM sẵn sàng
🛡️ Threshold: Block=90% | Alert=75%
   Serving on http://0.0.0.0:5000
```

> [!info] Kiểm tra WAF
> Mở `http://localhost:5000` → Thấy trang web **qua WAF**.
> Thử gửi `http://localhost:5000/search-user?id=' OR 1=1--` → Bị **403 Blocked**.

---

## Bước 3: Tấn công bằng AI Scanner

> Đóng vai Hacker, sử dụng Scanner để tấn công WAF.

### Mode 1: Scanner (Module 1) — Payload list + Hill Climbing

```bash
# Terminal 3
cd d:\AI\ai_security
python modul1_scanner.py --target http://localhost:5000
```

Với báo cáo:
```bash
python modul1_scanner.py --target http://localhost:5000 --report
```

### Mode 2: Hacker Brain (Module 3) — AI Context-Aware

```bash
# Terminal 3
cd d:\AI\ai_security
python modul3.py --target http://localhost:5000 --report
```

> [!caution] Cần GROQ_API_KEY
> Module 3 cần file `.env` với `GROQ_API_KEY`. Đăng ký tại https://console.groq.com

---

## Bước 4: Quan sát kết quả

### Bên Scanner (Terminal 3)
- Thấy payload được tạo, đột biến, gửi đi
- Báo cáo `🔥 BYPASS` hoặc `🛡️ BLOCKED`
- Cuối cùng: Security Score + danh sách findings

### Bên WAF (Terminal 2)
- Log cảnh báo: `⚡ [RULE-BLOCKED]`, `🛡️ [AI-BLOCKED]`
- Rate limiting: `⏱️ [RATE LIMITED]`
- Auto-blacklist: `🚫 [AUTO-BLACKLIST]`

### Báo cáo Output
- `scan_report_*.json` — Chi tiết kỹ thuật
- `scan_report_*.md` — Markdown tóm tắt
- `attack_log.db` — SQLite log (cho phân tích sâu)

---

## Bước 5: Huấn luyện liên tục (Tuỳ chọn)

> Khi có False Positive — WAF chặn nhầm request hợp lệ.

```bash
cd d:\AI\ai_security
python modul3_retrain.py
```

**Xem chi tiết:** [[08-Continual-Learning]]

---

## Bước 6: WAF Dashboard (Tuỳ chọn)

```bash
cd d:\AI\ai_security\waf-dashboard
npm install
npm run dev
```

Truy cập `http://localhost:5173` → Dashboard realtime.

---

## Quick Reference

| Lệnh | Mục đích |
|-------|----------|
| `python webtest.py` | Khởi động backend vulnerable |
| `python modul2_waf.py` | Khởi động WAF Shield |
| `python modul1_scanner.py --target URL` | Scan bằng Module 1 |
| `python modul1_scanner.py --target URL --report` | Scan + lưu báo cáo |
| `python modul3.py --target URL` | Scan bằng Hacker Brain |
| `python modul3_retrain.py` | Huấn luyện liên tục từ FP |

---

## Troubleshooting

| Lỗi | Giải pháp |
|-----|-----------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| `Connection refused` | Kiểm tra webtest.py đã chạy chưa |
| `GROQ_API_KEY missing` | Tạo file `.env` với API key |
| `Model load error` | Kiểm tra thư mục `model/` có đủ 3 file |
| `Port already in use` | Đổi port hoặc kill process cũ |

---

**Xem thêm:** [[02-Kiến-Trúc-Hệ-Thống]] | [[09-Web-Testbed]] | [[12-Kết-Quả-Thực-Nghiệm]]
