---
description: Cách triển khai Module 2 (AI WAF) để bảo vệ hệ thống trước các cuộc tấn công.
---

1. Đảm bảo Web mục tiêu đang chạy trên Port 5170.
   ```powershell
   python webtest.py
   ```

2. Khởi động AI WAF (Port 5000):
   // turbo
   ```powershell
   python modul2_waf.py
   ```

3. Gửi yêu cầu qua WAF để thử nghiệm khả năng chặn:
   ```powershell
   # Ví dụ: Thử SQL Injection qua WAF
   curl "http://localhost:5000/search-user?id=admin' OR 1=1 --"
   ```

4. Truy cập Health Check để xem trạng thái model và backend:
   `http://localhost:5000/ai-waf/health`

5. Xem thống kê tấn công bị chặn:
   `http://localhost:5000/ai-waf/stats`
