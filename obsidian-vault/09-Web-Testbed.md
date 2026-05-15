---
tags: [testbed, vulnerable-app, deployment]
aliases: [Web Testbed, Webtest, Vulnerable App]
---

# 🎯 Web Testbed (Ứng dụng Mục tiêu)

> **File:** `webtest.py` (~345 dòng)
> **Vai trò:** Ứng dụng web có **lỗ hổng cố ý** — dùng làm "bia đỡ đạn" cho Scanner quét và WAF bảo vệ.

---

## Tổng quan

Web Testbed giả lập một **Portal Nghiên cứu Khoa học — ĐH Công nghệ** với 12 endpoint chứa 10 loại lỗ hổng khác nhau.

- **Port:** `5170`
- **Framework:** Flask
- **Database:** SQLite in-memory
- **Giao diện:** Tailwind CSS

---

## 12 Endpoint Có Lỗ Hổng

### Nhóm 1: Form-based (GET)

| # | Endpoint | Lỗ hổng | Kỹ thuật lỗi |
|---|----------|---------|---------------|
| 1 | `GET /search-user?id=` | **SQL Injection** | Nối chuỗi trực tiếp vào query SQLite |
| 2 | `GET /feedback?msg=` | **XSS (Reflected)** | `render_template_string` không escape |
| 3 | `GET /view-doc?file=` | **Path Traversal** | Không validate đường dẫn file |
| 4 | `GET /ping?ip=` | **Command Injection** | `subprocess.check_output(shell=True)` |
| 5 | `GET /fetch-url?url=` | **SSRF** | Server fetch URL bất kỳ do user chỉ định |
| 7 | `GET /ssti?tmpl=` | **SSTI** | `render_template_string` trực tiếp |
| 8 | `GET /nosqli?query=` | **NoSQLi** | Giả lập nhận NoSQL operator |
| 9 | `GET /xxe?xml=` | **XXE** | Giả lập parse XML có entity SYSTEM |
| 10 | `GET /jwtauth?token=` | **JWT Bypass** | Chấp nhận token `alg:none` |

### Nhóm 2: POST-based

| # | Endpoint | Lỗ hổng | Kỹ thuật lỗi |
|---|----------|---------|---------------|
| 6 | `POST /transfer` | **CSRF** | Không có CSRF token |
| 11 | `POST /api/login` | **SQLi (JSON)** | Nối chuỗi từ JSON body |
| 12 | `POST /api/nosql-login` | **NoSQLi (JSON)** | Nhận dict chứa NoSQL operators |

---

## Database Giả lập

SQLite in-memory với bảng `users`:

| id | username | password | role |
|----|----------|----------|------|
| 1 | `admin` | `password123` | Administrator |
| 2 | `giangvien_an` | `nckh2024` | Giảng viên |
| 3 | `sinhvien_binh` | `student_pass` | Sinh viên |

> [!info] Dữ liệu nhạy cảm giả
> Các password (`password123`, `nckh2024`, `student_pass`) được dùng để **kiểm tra** xem Scanner có phát hiện credential leak không.

---

## Payload Test cho từng Lỗ hổng

| Lỗ hổng | Payload test | Kết quả mong đợi |
|---------|-------------|-------------------|
| SQLi | `1' OR '1'='1` | Trả về tất cả users |
| XSS | `<script>alert('XSS')</script>` | Script thực thi |
| Path Traversal | `../../windows/win.ini` | Nội dung file bị lộ |
| CMDi | `127.0.0.1 ; whoami` | OS output |
| SSRF | `http://169.254.169.254/` | Cloud metadata |
| CSRF | `GET /transfer?to=hacker&amount=999` | Chuyển khoản không cần token |
| SSTI | `{{7*7}}` | Trả về `49` |
| NoSQLi | `{"$gt": ""}` | Trả về tất cả records |
| XXE | `<!ENTITY xxe SYSTEM 'file:///etc/passwd'>` | Nội dung file |
| JWT | `eyJhbGciOiJub25lIn0...` | Bypass xác thực |

---

## Trạng thái Bảo vệ

Trang web tự kiểm tra có đang chạy qua WAF hay không:

- **Port 5000:** ✅ Đang chạy qua AI WAF SHIELD
- **Port 5170:** ❌ Đang chạy trực tiếp — KHÔNG CÓ BẢO VỆ!

---

## Cách Chạy

```bash
cd d:\AI\ai_security
python webtest.py
```

**Output:**
```
Web muc tieu (Vulnerable) dang chay tai http://localhost:5170
   Endpoints: /search-user, /feedback, /view-doc, /ping, /fetch-url,
              /transfer, /ssti, /nosqli, /xxe, /jwtauth,
              /api/login, /api/nosql-login
```

---

**Xem thêm:** [[04-Module-1-Scanner]] | [[05-Module-2-WAF]] | [[13-Hướng-Dẫn-Triển-Khai]]
