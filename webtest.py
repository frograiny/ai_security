from flask import Flask, request, render_template_string, send_file
import os
import sqlite3
import subprocess

app = Flask(__name__)

# Tạo Database giả lập trong bộ nhớ để test SQL Injection
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'password123', 'Administrator')")
    cursor.execute("INSERT INTO users VALUES (2, 'giangvien_an', 'nckh2024', 'Giảng viên')")
    cursor.execute("INSERT INTO users VALUES (3, 'sinhvien_binh', 'student_pass', 'Sinh viên')")
    return conn

db_conn = init_db()

# Giao diện chính của Portal (Dùng Tailwind CSS cho đẹp)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Portal Nghiên cứu Khoa học - ĐH Công nghệ</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <nav class="bg-blue-800 text-white p-4 shadow-lg">
        <div class="container mx-auto flex justify-between">
            <h1 class="text-xl font-bold">🔬 Portal NCKH (Vulnerable Testbed)</h1>
            <span class="bg-red-500 px-2 py-1 rounded text-xs">⚠️ HỆ THỐNG ĐANG CÓ LỖ HỔNG</span>
        </div>
    </nav>

    <div class="container mx-auto p-8 grid grid-cols-1 md:grid-cols-2 gap-8">
        <!-- 1. SQL Injection Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-blue-700">1. Tìm kiếm Sinh viên (SQL Injection)</h2>
            <form action="/search-user" method="GET">
                <input name="id" type="text" placeholder="Nhập ID (vd: 1)" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Tìm kiếm</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">1' OR '1'='1</code></p>
        </div>

        <!-- 2. XSS Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-green-700">2. Góp ý Đề tài (XSS)</h2>
            <form action="/feedback" method="GET">
                <input name="msg" type="text" placeholder="Nhập góp ý..." class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700">Gửi</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
        </div>

        <!-- 3. Path Traversal Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-yellow-700">3. Xem Tài liệu (Path Traversal)</h2>
            <form action="/view-doc" method="GET">
                <input name="file" type="text" placeholder="vd: huongdan.txt" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-yellow-600 text-white px-4 py-2 rounded hover:bg-yellow-700">Xem</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">../../windows/win.ini</code> (hoặc file nhạy cảm khác)</p>
        </div>

        <!-- 4. Command Injection Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-red-700">4. Kiểm tra Máy chủ (Command Injection)</h2>
            <form action="/ping" method="GET">
                <input name="ip" type="text" placeholder="Nhập IP (vd: 127.0.0.1)" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700">Ping</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">127.0.0.1 ; whoami</code></p>
        </div>

        <!-- 5. SSRF Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-purple-700">5. Tải trang web (SSRF)</h2>
            <form action="/fetch-url" method="GET">
                <input name="url" type="text" placeholder="Nhập URL (vd: http://example.com)" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-purple-600 text-white px-4 py-2 rounded hover:bg-purple-700">Fetch</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">http://169.254.169.254/latest/meta-data/</code></p>
        </div>

        <!-- 6. CSRF Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-orange-700">6. Chuyển khoản (CSRF)</h2>
            <form action="/transfer" method="POST">
                <input name="to" type="text" placeholder="Số tài khoản" class="border p-2 w-full rounded mb-2">
                <input name="amount" type="text" placeholder="Số tiền" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-orange-600 text-white px-4 py-2 rounded hover:bg-orange-700">Chuyển</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Lỗ hổng: Không có CSRF token → GET <code class="bg-gray-200">/transfer?to=hacker&amount=999</code></p>
        </div>
    </div>
    
    <div class="container mx-auto px-8">
        <div class="bg-blue-100 border-l-4 border-blue-500 p-4">
            <p class="text-blue-700 font-bold">Trạng thái bảo vệ:</p>
            <p id="waf-status" class="text-sm">Đang kiểm tra...</p>
        </div>
    </div>

    <script>
        // Kiểm tra xem có đang chạy qua Proxy 5000 không
        if (window.location.port == '5000') {
            document.getElementById('waf-status').innerHTML = "✅ Đang chạy qua AI WAF SHIELD (Port 5000)";
            document.getElementById('waf-status').className = "text-green-700 font-bold";
        } else {
            document.getElementById('waf-status').innerHTML = "❌ Đang chạy trực tiếp (Port 5173) - KHÔNG CÓ BẢO VỆ!";
            document.getElementById('waf-status').className = "text-red-700 font-bold";
        }
    </script>
</body>
</html>
"""

# --- CÁC ROUTE BỊ LỖI (VULNERABLE ENDPOINTS) ---

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/search-user')
def search_user():
    user_id = request.args.get('id', '')
    # LỖI SQL INJECTION: Cộng chuỗi trực tiếp vào query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return f"<h3>Kết quả truy vấn:</h3><p>{query}</p><br><b>Dữ liệu:</b> {str(results)}"
    except Exception as e:
        return f"Lỗi database: {str(e)}"

@app.route('/feedback')
def feedback():
    msg = request.args.get('msg', '')
    # LỖI XSS: Render trực tiếp input mà không escape
    return render_template_string(f"<h3>Cảm ơn bạn đã góp ý:</h3><p>{msg}</p><br><a href='/'>Quay lại</a>")

@app.route('/view-doc')
def view_doc():
    filename = request.args.get('file', '')
    # LỖI PATH TRAVERSAL: Không kiểm tra đường dẫn file
    # Giả lập đọc file (trong thực tế sẽ nguy hiểm hơn)
    try:
        return f"Đang mô phỏng đọc nội dung file: <b>{filename}</b> (AI WAF sẽ chặn nếu thấy ../)"
    except Exception as e:
        return str(e)

@app.route('/ping')
def ping():
    ip = request.args.get('ip', '')
    # LỖI COMMAND INJECTION: Sử dụng os.system hoặc subprocess trực tiếp
    # Trong môi trường test này ta chỉ giả lập lệnh echo để an toàn cho máy ông
    cmd = f"echo Pinging {ip}..." 
    try:
        # Giả lập thực thi lệnh hệ thống
        output = subprocess.check_output(cmd, shell=True).decode()
        return f"<h3>Hệ thống phản hồi:</h3><pre>{output}</pre>"
    except:
        return "Lỗi thực thi lệnh"

@app.route('/fetch-url')
def fetch_url():
    url = request.args.get('url', '')
    # LỖI SSRF: Cho phép người dùng chỉ định URL bất kỳ và server sẽ fetch
    if not url:
        return "<h3>Nhập URL cần tải:</h3><p>Ví dụ: /fetch-url?url=http://example.com</p>"
    try:
        import requests as ssrf_req
        resp = ssrf_req.get(url, timeout=5)
        return f"<h3>Kết quả fetch URL:</h3><p>URL: {url}</p><p>Status: {resp.status_code}</p><pre>{resp.text[:500]}</pre>"
    except Exception as e:
        return f"<h3>Lỗi khi fetch:</h3><p>{str(e)}</p>"

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    # LỖI CSRF: Không có CSRF token, cho phép thực hiện hành động nhạy cảm bằng GET
    if request.method == 'POST' or request.args.get('to'):
        to_account = request.args.get('to', '') or request.form.get('to', '')
        amount = request.args.get('amount', '0') or request.form.get('amount', '0')
        return f"<h3>✅ Chuyển khoản thành công (MÔ PHỎNG)</h3><p>Tới: {to_account} | Số tiền: {amount} VND</p><p class='text-red-500'>⚠️ Endpoint này không có CSRF token → dễ bị tấn công CSRF</p>"
    return """
    <h3>Chuyển khoản (CSRF Vulnerable)</h3>
    <form method="POST">
        <input name="to" placeholder="Số tài khoản" class="border p-2 rounded mb-2"><br>
        <input name="amount" placeholder="Số tiền" class="border p-2 rounded mb-2"><br>
        <button type="submit" class="bg-purple-600 text-white px-4 py-2 rounded">Chuyển</button>
    </form>
    """

if __name__ == '__main__':
    print("🔥 Web mục tiêu (Vulnerable) đang chạy tại http://localhost:5170")
    print("   Endpoints: /search-user, /feedback, /view-doc, /ping, /fetch-url, /transfer")
    app.run(port=5170)