---
description: Cách chạy Module 1 (AI Vulnerability Scanner) để quét và giả lập tấn công.
---

1. Khởi động Web mục tiêu (nếu chưa chạy) trên Port 5170.
   ```powershell
   python webtest.py
   ```

2. Chạy Scanner ở chế độ CLI để quét toàn diện và tạo báo cáo:
   // turbo
   ```powershell
   python modul1_scanner.py --target http://localhost:5170 --report
   ```

3. (Tùy chọn) Chạy Scanner ở chế độ Web UI để quan sát trực quan:
   ```powershell
   python modul1_scanner.py --server
   ```
   Sau đó mở trình duyệt tại: `http://localhost:5001`

4. Kiểm tra các báo cáo được tạo ra trong thư mục gốc (`scan_report_*.md`).
