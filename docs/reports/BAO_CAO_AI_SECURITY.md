# Báo Cáo Chi Tiết Dự Án AI Security WAF

## 1. Giới thiệu tổng quan
Dự án **AI Security WAF** là sự kết hợp giữa **Active Vulnerability Scanning (Quét lỗ hổng chủ động)** và **AI-based Web Application Firewall (Tường lửa ứng dụng web dựa trên AI)**. Mục tiêu của dự án là không chỉ bảo vệ các ứng dụng web khỏi các cuộc tấn công đã biết mà còn có khả năng tự động gửi các payload tấn công để tìm ra lỗ hổng, từ đó chặn các cuộc tấn công theo thời gian thực bằng mô hình học sâu.

## 2. Kiến trúc hệ thống
Hệ thống được chia làm 4 thành phần chính (phase):

### Phase 1: Chuẩn bị Dữ liệu & Mô hình (Data & Model Preparation)
- **Dataset:** Sử dụng file `WEB_APPLICATION_PAYLOADS.jsonl` chứa danh sách lớn các payload mô phỏng những dạng tấn công thực tế (SQL Injection, XSS, Path Traversal, Command Injection, SSRF, CSRF...).
- **Model Deep Learning:** Mô hình AI (sử dụng kiến trúc Bi-LSTM trên TensorFlow/Keras) được huấn luyện từ tập dữ liệu. File model là `deep_learning_agent_core.keras` đạt độ chính xác phân loại các hình thức tấn công cao (>99% trong một số bài kiểm tra XSS và SQLi).

### Phase 2: Quét Lỗ Hổng Chủ Động (Active Scanner) - Module 1
- **File thực thi:** `modul1_scanner.py`
- **Mô tả:** Đóng vai trò là kẻ giả lập tấn công. Scanner sẽ yêu cầu 1 URL để target, tự động thu thập (crawl) form input và các tham số trên trang đó.
- Sau đó, Scanner phát (inject) nhiều loại payload tấn công độc hại vào từng endpoint và đưa ra phân tích đánh giá phản hồi (response analysis).
- Kết xuất báo cáo các điểm yếu có thể bị khai thác (`--report flag`).

### Phase 3: AI-WAF Shield (Tường Lửa Web) - Module 2
- **File thực thi:** `modul2_waf.py`
- **Mô tả:** Đóng vai trò như một **Reverse Proxy** thông minh giúp loại bỏ request có hại (malicious request). Bất cứ HTTP Request nào gửi lên web phải qua cổng Middleware này.
- **Tiến trình bảo vệ:**
  - **Blacklist:** Chặn IP bị gắn mác trước.
  - **Rate Limiting:** Chống Brute Force / DoS (100reqs/min an toàn, 10reqs/min nếu nghi ngờ).
  - **Trích xuất Data:** Lấy toàn bộ nội dung trong Query Params, Body JSON, FormData.
  - **AI Analysis:** Truyền data qua model Bi-LSTM check với threshold ≥75% bị coi là xâm nhập (block 403). Để tăng tốc, hệ thống có LRU Cache để lưu trữ các payload lặp đi lặp lại.
  - **Cơ chế Logs/Alerting:** Chặn sẽ log trực tiếp ra `shield_protection.log` báo động ra màn hình.

### Phase 4: Frontend Giao diện theo dõi (Web Dashboard)
- **File HTML:** `ai_waf_scanner.html`
- **Mô tả:** Cung cấp tính năng real-time monitoring giám sát, báo cáo với giao diện trực quan hỗ trợ quét và hiển thị thông tin bằng bảng điện tử.

---

## 3. Quá trình phát triển và kiểm thử hệ thống
Trong quá trình xây dựng, nhóm đã có một số thử nghiệm với các endpoint API (`webtest.py` được dựng để làm "bao cát" test lỗ hổng).

- **Kiểm thử Module 1:** Phát hiện ra SSRF và Command Injection thường gây lọt cho các WAF thông thường vì thiếu dữ liệu train hoặc sai nhãn phân loại (vd: CmdInj nhận nhầm SQLi).
- **Scanner Mode Mới Mẻ:** Scanner không chỉ làm WAF tĩnh chờ xử lý (passive) mà còn tự thu thập, phân tích (tấn công chủ động) sau đó in JSON Report với bằng chứng.
- Trong một bài kiểm tra nội bộ qua máy chủ giả lập, module đã tìm thấy:
  - 10 lỗi **SQLi (CRITICAL)**.
  - 15 lỗi **XSS (HIGH)**.
  - 12 lỗi **Path Traversal (HIGH)**.
  - 1 lỗi **Command Injection (CRITICAL)**.

---

## 4. Hướng dẫn cài đặt và sử dụng

### Khởi động hệ thống
```bash
# 1. Cài đặt các thư viện cần thiết
pip install -r requirements.txt
```

### Module 1 - Chạy Quét Chủ Động
Mở terminal hoặc bash:
```bash
python modul1_scanner.py --target http://localhost:5170 --report
```
*Lưu ý: Có thể sử dụng giao diện bằng cách khởi động server trên cổng 5001 (chạy `modul1_scanner.py --server`)*.

### Module 2 - Bật Hệ thống Firewall bảo vệ
Giả sử backend ứng dụng web chạy ở cổng `5170` (vd testbed `webtest.py`), bạn dùng `modul2_waf` bảo vệ chúng thông qua port proxy (vd `5000`):
```bash
python modul2_waf.py --target http://127.0.0.1:5170 --port 5000
```
- Người dùng chỉ được truy cập vào cổng `5000`. Cổng `5170` chỉ nhận thông tin từ Reverse Proxy của cổng 5000. WAF sẽ lọc mọi payload SQLi, XSS, SSRF trước khi truyền về Backend.

### Tổng Kết
Dự án giải quyết được song song vấn đề tìm lỗ hổng hiện có của target bằng hệ thống quét (Active Scanner) và vá ngay tức khắc bằng công nghệ học máy (AI WAF). Việc sử dụng reverse proxy đem lại hiệu năng mạnh mẽ khi không can thiệp sâu nội bộ backend hiện hữu và sử dụng được cho rất nhiều loại web server.
