---
description: Toàn bộ quy trình kiểm tra lỗ hổng và khả năng bảo vệ của AI WAF.
---

1. Khởi động Web mục tiêu (Vulnerable Target):
   ```powershell
   python webtest.py
   ```

2. Khởi động AI WAF (Protection Layer):
   // turbo
   ```powershell
   python modul2_waf.py
   ```

3. Chạy Scanner tấn công WAF (Pentest Challenge):
   ```powershell
   python modul1_scanner.py --target http://localhost:5000 --report
   ```

4. Theo dõi logs của `modul2_waf.py` để thấy thông báo `403 Forbidden` khi phát hiện tấn công.

5. Xem điểm an toàn trong báo cáo quét `scan_report_*.md`.
