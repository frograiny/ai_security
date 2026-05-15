---
tags: [glossary, reference]
aliases: [Glossary, Thuật ngữ, Viết tắt]
---

# 📖 Glossary — Bảng Thuật ngữ

> Danh sách thuật ngữ, viết tắt và khái niệm chính trong dự án.

---

## A

**Adversarial Attack**
: Tấn công đối kháng — kỹ thuật biến đổi input để đánh lừa model AI. Xem: [[07-Adversarial-Loop]]

**Auto-Blacklist**
: Tự động cấm IP sau khi vượt ngưỡng block. Xem: [[05-Module-2-WAF]]

---

## B

**Bi-LSTM (Bidirectional Long Short-Term Memory)**
: Mạng neural đọc chuỗi theo 2 chiều (trái→phải & phải→trái). Xem: [[03-Mô-Hình-AI-BiLSTM]]

**Blue Team**
: Đội phòng thủ — bảo vệ hệ thống. Trong project: [[05-Module-2-WAF|WAF Shield]]

**Bypass**
: Payload vượt qua được tất cả lớp phòng thủ (cả AI lẫn rule).

---

## C

**Canonicalization**
: Quá trình đưa payload về dạng "nguyên thuỷ" bằng URL decode + HTML decode + null byte strip. Lớp L2.5 trong WAF.

**Catastrophic Forgetting**
: Hiện tượng model quên kiến thức cũ khi học kiến thức mới. Xem: [[08-Continual-Learning]]

**Confidence**
: Mức độ tin cậy (%) của AI khi phân loại payload. VD: "SQLi 95%" = AI tin 95% đây là SQL Injection.

**Continual Learning**
: Học trọn đời — cập nhật model liên tục mà không quên kiến thức cũ. Xem: [[08-Continual-Learning]]

**CMDi (Command Injection)**
: Chèn lệnh OS vào input. Xem: [[10-Attack-Catalog]]

**CSRF (Cross-Site Request Forgery)**
: Giả mạo request từ trình duyệt nạn nhân. Xem: [[10-Attack-Catalog]]

---

## D

**Defense-in-Depth**
: Phòng thủ đa tầng — nhiều lớp bảo vệ xếp chồng. WAF có 5 lớp.

**Dual-Threshold**
: Cơ chế 2 ngưỡng: Block (≥90%) và Monitor (75-89%). Giảm False Positive.

---

## E

**Evasion**
: Payload đã bị biến đổi (mutation) thành công, khiến AI không nhận diện được.

**Evasion Threshold**
: Ngưỡng 50% — nếu confidence < 50% → coi là evasion thành công.

**Exploit Chaining**
: Xâu chuỗi nhiều lỗ hổng lại với nhau để tăng impact. Xem: [[06-Module-3-HackerBrain]]

---

## F

**False Positive (FP)**
: Chặn nhầm — WAF block request hợp lệ.

**False Negative (FN)**
: Bỏ lọt — WAF cho qua request độc hại.

**Fine-tuning**
: Tinh chỉnh model đã train bằng cách train thêm với learning rate nhỏ.

---

## G

**Greedy Hill Climbing**
: Thuật toán "leo đồi tham lam" — thử nhiều mutation, chọn cái tốt nhất, lặp lại. Xem: [[07-Adversarial-Loop]]

**Groq**
: Nền tảng API chạy LLM tốc độ cao. Project dùng model Qwen3-32B qua Groq.

---

## I

**IDOR (Insecure Direct Object Reference)**
: Truy cập tài nguyên của user khác bằng cách thay đổi ID.

**Inference**
: Quá trình AI dự đoán/phân loại — chạy payload qua model để có kết quả.

---

## J

**JWT (JSON Web Token)**
: Token xác thực dạng JSON. Lỗ hổng JWTAuth: dùng algorithm `none` để bypass.

---

## L

**Label Encoder**
: Bộ ánh xạ giữa tên nhãn (VD: "SQLi") và số index (VD: 1).

**LLM (Large Language Model)**
: Mô hình ngôn ngữ lớn. Project dùng Qwen3-32B qua Groq API.

---

## M

**MAX_LEN**
: Chiều dài tối đa payload (150 ký tự) cho input vào model AI.

**Mutation**
: Biến đổi payload (VD: đổi case, URL encode) để thử bypass AI.

---

## N

**NoSQLi (NoSQL Injection)**
: Chèn NoSQL operator ($gt, $ne) vào query MongoDB. Xem: [[10-Attack-Catalog]]

---

## O

**Oracle**
: Bộ "hỏi-đáp" — Scanner hỏi model "payload này có bị detect không?" trước khi gửi.

**Oracle Threshold**
: Ngưỡng 75% — trigger mutation khi model detect payload với confidence ≥ 75%.

---

## P

**Padding**
: Thêm số 0 vào cuối sequence để đồng nhất chiều dài (150).

**Payload**
: Chuỗi ký tự được gửi đến server nhằm khai thác lỗ hổng.

**Pentest (Penetration Testing)**
: Kiểm thử xâm nhập — mô phỏng tấn công để tìm lỗ hổng.

---

## R

**Rate Limiting**
: Giới hạn số request/phút cho mỗi IP. Normal: 100, Flagged: 10.

**Red Team**
: Đội tấn công — tìm lỗ hổng. Trong project: [[04-Module-1-Scanner|Scanner]] + [[06-Module-3-HackerBrain|Hacker Brain]]

**Reverse Proxy**
: Proxy đứng trước backend, kiểm tra request trước khi chuyển tiếp.

---

## S

**SSRF (Server-Side Request Forgery)**
: Ép server gửi request đến URL nội bộ. Xem: [[10-Attack-Catalog]]

**SSTI (Server-Side Template Injection)**
: Chèn code vào template engine. Xem: [[10-Attack-Catalog]]

**SQLi (SQL Injection)**
: Chèn SQL vào input. Xem: [[10-Attack-Catalog]]

---

## T

**Tokenizer**
: Bộ chuyển đổi text → sequence số. VD: `"SELECT"` → `[42]`.

**Threshold**
: Ngưỡng — giá trị quyết định hành động (block/monitor/allow).

---

## W

**WAF (Web Application Firewall)**
: Tường lửa ứng dụng web — lọc HTTP request độc hại.

**Waitress**
: WSGI server production-grade cho Python. Thay thế Flask dev server.

**White-box**
: Attacker biết chi tiết model (architecture, weights). Đối lập: Black-box.

---

## X

**XSS (Cross-Site Scripting)**
: Chèn JavaScript vào trang web. Xem: [[10-Attack-Catalog]]

**XXE (XML External Entity)**
: Khai thác XML parser để đọc file. Xem: [[10-Attack-Catalog]]

---

**Xem thêm:** [[00-MOC]] | [[10-Attack-Catalog]]
