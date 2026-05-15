---
tags: [overview, architecture]
aliases: [Tổng quan, Overview]
---

# 🎯 Tổng Quan Dự Án

> **AI Security Suite** — Hệ sinh thái an ninh mạng toàn diện kết hợp **Tấn công Chủ động (Offensive)** và **Phòng thủ Đa tầng (Defensive)** sử dụng Deep Learning.

---

## Mục tiêu Dự án

Dự án giải quyết **3 câu hỏi nghiên cứu** chính:

1. ✅ Có thể huấn luyện model Deep Learning để nhận diện payload web độc hại từ text?
2. ✅ Có thể dùng model đó để hỗ trợ scanner chủ động (pentest automation)?
3. ✅ Có thể đặt model vào đường đi request để làm lớp chặn lọc runtime (WAF)?

**Câu trả lời:** Toàn bộ repo là một **thực nghiệm sống** cho 3 câu hỏi trên.

---

## Kiến trúc Tổng quan

Hệ thống gồm **4 Module lõi**:

| Module | Vai trò | File chính |
|--------|---------|------------|
| **Module 1** — Scanner | 🗡️ Red Team: Quét lỗ hổng đối kháng | `modul1_scanner.py` |
| **Module 2** — WAF Shield | 🛡️ Blue Team: Tường lửa AI 5 lớp | `modul2_waf.py` |
| **Module 3** — Hacker Brain | 🧠 AI Pentest: Sinh payload thông minh (Groq) | `modul3.py` |
| **Module 4** — Retrain | 📚 Continual Learning: Học từ False Positive | `modul3_retrain.py` |

> [!info] Mối quan hệ Đối kháng
> Module 1 (Scanner) tấn công → Module 2 (WAF) chống đỡ → Kết quả phản hồi ngược lại giúp cả hai bên mạnh hơn. Đây chính là triết lý **Red Team vs Blue Team**.

---

## Tính năng Nổi bật

### 🔥 Offensive (Tấn công)
- **Adversarial Mutation Engine** — Sử dụng thuật toán [[07-Adversarial-Loop|Greedy Hill Climbing]] để tìm biến thể payload bypass AI
- **Context-Aware Payload** — [[06-Module-3-HackerBrain|AI Hacker Brain]] tự đọc HTML và suy ra loại tấn công phù hợp
- **Exploit Chaining** — Xâu chuỗi nhiều lỗ hổng (VD: Tìm `.env` → Lấy API Key → Tấn công endpoint thanh toán)

### 🛡️ Defensive (Phòng thủ)
- **Defense-in-Depth 5 lớp** — Từ IP Blacklist đến Deep Scan bằng [[03-Mô-Hình-AI-BiLSTM|Bi-LSTM]]
- **Dual-Threshold** — Block (≥90%) vs Monitor (75-89%) để giảm False Positive
- **Production Ready** — Chạy trên Waitress WSGI, đa luồng

### 🔄 Liên tục cải tiến
- **[[08-Continual-Learning|Continual Learning]]** — Tự học từ False Positive mà không quên kiến thức cũ
- **[[10-Attack-Catalog|13 Nhãn Tấn công]]** — Bao phủ từ SQLi cổ điển đến SSTI, NoSQLi hiện đại

---

## Công nghệ Sử dụng

| Lĩnh vực | Công nghệ |
|-----------|-----------|
| Deep Learning | TensorFlow / Keras (Bi-LSTM) |
| LLM | Groq API — Qwen3-32B |
| Web Framework | Flask + Waitress (WSGI) |
| Frontend | React (WAF Dashboard) |
| Ngôn ngữ | Python 3.8+ |
| Database | SQLite (Attack Log) |

---

## Kết quả Đạt được

| Chỉ số | Giá trị | Ghi chú |
|--------|---------|---------|
| Accuracy | **97.43%** | Trên tập Test (9,847 mẫu) |
| Số nhãn | **13** | 12 loại tấn công + Normal |
| Safety Score (có WAF) | **91/100** | Tăng từ 18/100 khi không có WAF |
| Bypass Rate | **~0%** | Không payload nào vượt qua 5 lớp |
| Inference Time | **~25ms** | Tối ưu cho real-time |

---

## Tác giả

**Đinh Trường An & Phạm Hoàng Anh** — 2026

License: MIT (Chỉ phục vụ nghiên cứu & giáo dục)

---

> [!warning] Miễn trừ trách nhiệm
> Công cụ này chỉ phục vụ mục đích **nghiên cứu** và **giáo dục**. Việc sử dụng để tấn công hệ thống không được phép là **vi phạm pháp luật**.

---

**Xem thêm:** [[02-Kiến-Trúc-Hệ-Thống]] | [[13-Hướng-Dẫn-Triển-Khai]] | [[12-Kết-Quả-Thực-Nghiệm]]
