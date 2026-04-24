# HƯỚNG DẪN TRIỂN KHAI VÀ VẬN HÀNH HỆ THỐNG AI SECURITY

Tài liệu này hướng dẫn chi tiết các bước khởi chạy và kiểm thử hệ thống AI Security (WAF, Scanner, Continual Learning) trong môi trường thực tế.

---

## 🚀 Kiến trúc các thành phần

Hệ thống bao gồm 4 thành phần chính, bạn cần mở nhiều cửa sổ Terminal (Command Prompt / PowerShell) để chạy đồng thời các thành phần này.

1. **Web Testbed (Mục tiêu):** Trang web chứa các lỗ hổng (Vulnerable App).
2. **AI WAF Shield (Tấm khiên):** Module 2 - Đứng trước Web Testbed để lọc và chặn các cuộc tấn công.
3. **AI Scanner (Máy quét):** Module 1 - Giả lập Hacker để tấn công trực tiếp vào WAF.
4. **Continual Learning:** Module 3 - Cập nhật kiến thức cho mô hình AI dựa trên các mẫu False Positive.

---

## 🛠️ Các bước khởi chạy chi tiết

### BƯỚC 1: Khởi động Web Testbed (Mục tiêu tấn công)
Đây là trang web chứa 10 loại lỗ hổng web dùng để làm "bia đỡ đạn".
1. Mở một Terminal mới.
2. Chuyển vào thư mục chứa code dự án:
   ```bash
   cd d:\AI\ai_security
   ```
3. Chạy file web:
   ```bash
   python webtest.py
   ```
   > **Kết quả mong đợi:** Terminal hiển thị `🔥 Web mục tiêu đang chạy tại http://localhost:5170`.

---

### BƯỚC 2: Khởi động AI WAF Shield (Lớp bảo vệ Production)
WAF sẽ đứng chắn trước `localhost:5170`. Hiện tại WAF đang chạy qua **Waitress WSGI** đa luồng với cơ chế Dual-Threshold.
1. Mở một Terminal thứ 2.
2. Chuyển vào thư mục dự án và chạy Module 2:
   ```bash
   cd d:\AI\ai_security
   python modul2_waf.py
   ```
   > **Kết quả mong đợi:** WAF sẽ khởi động, lắng nghe tại **http://localhost:5000**. Mọi request gửi vào port 5000 sẽ được AI WAF kiểm duyệt rồi mới đẩy tới web mục tiêu (port 5170).

---

### BƯỚC 3: Giả lập Tấn công bằng AI Scanner (Đa luồng)
Bây giờ chúng ta đóng vai Hacker, sử dụng công cụ Pentest để tấn công vào WAF (Port 5000). Công cụ này đã được tối ưu chạy đa luồng cực nhanh.
1. Mở một Terminal thứ 3.
2. Chuyển vào thư mục dự án và chạy Module 1:
   ```bash
   cd d:\AI\ai_security
   python modul1_scanner.py --target http://localhost:5000
   ```
3. Quan sát:
   * **Bên Terminal của Scanner:** Xem nó liên tục tạo ra các đột biến (Mutation) bằng AI để cố gắng bypass WAF.
   * **Bên Terminal của WAF:** Thấy các luồng truy cập bị chặn (Block) theo IP, in log cảnh báo liên tục ra màn hình.

---

### BƯỚC 4: Huấn luyện liên tục (Continual Learning / FP Recovery)
Khi vận hành thực tế, có thể AI sẽ "chặn nhầm" (False Positive) các request của người dùng thực sự (VD: Nhập văn bản tiếng Việt lạ). WAF của chúng ta có luồng Monitor với mức ngưỡng `LOG_THRESHOLD (60%)`.
Nếu có báo cáo chặn nhầm, payload sạch đó sẽ lưu ở `data/fp_reports.json`.

Để dạy lại cho mô hình AI khôn hơn (sau 1 ngày thu thập FP):
1. Mở Terminal.
2. Chạy file huấn luyện trực tuyến:
   ```bash
   cd d:\AI\ai_security
   python modul3_retrain.py
   ```
   > **Quy trình:** Script sẽ load file `deep_learning_agent_core.keras`, feed danh sách bị chặn nhầm, gắn lại nhãn "Normal", và train với tỷ lệ học (Learning Rate) siêu nhỏ `1e-5`. Sau khi train xong, mô hình được đè lên bản cũ, file FP sẽ tự động được sao lưu để dọn chỗ cho ngày tiếp theo.

---

### Mẹo: Mở giao diện Dashboard WAF (Giao diện React - Tuỳ chọn)
Nếu bạn muốn trực quan hóa các Block/Allowed Requests:
1. Chuyển vào thư mục frontend:
   ```bash
   cd d:\AI\ai_security\waf-dashboard
   ```
2. Khởi chạy React App:
   ```bash
   npm run dev
   ```
   > Truy cập trình duyệt (thường là http://localhost:5173) để xem biểu đồ thống kê AI đang chặn bắt tấn công trong thời gian thực.
