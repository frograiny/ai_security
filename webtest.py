import argparse
from flask import Flask, request, render_template_string, send_file
import os
import sqlite3
import subprocess

# Parse arguments for demo
parser = argparse.ArgumentParser(description="Vulnerable Testbed")
parser.add_argument('--no-waf', action='store_true', help="Disable AI WAF protection")
parser.add_argument('--port', type=int, default=5170, help="Port to run on")
args = parser.parse_args()

app = Flask(__name__)

if not args.no_waf:
    try:
        from ai_waf_shield import AIWafShield
        waf = AIWafShield()
        waf.protect(app)
        app.config['WAF_ENABLED'] = True
    except ImportError:
        print("Warning: ai_waf_shield not found. Running without WAF.")
        app.config['WAF_ENABLED'] = False
else:
    app.config['WAF_ENABLED'] = False

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

        <!-- 7. SSTI Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-pink-700">7. Template Engine (SSTI)</h2>
            <form action="/ssti" method="GET">
                <input name="tmpl" type="text" placeholder="Nhập template (vd: {{ 7*7 }})" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-pink-600 text-white px-4 py-2 rounded hover:bg-pink-700">Hiển thị</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">{{ config.items() }}</code></p>
        </div>

        <!-- 8. NoSQL Injection Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-cyan-700">8. Tìm kiếm NoSQL (NoSQLi)</h2>
            <form action="/nosqli" method="GET">
                <input name="query" type="text" placeholder="Nhập filter (vd: {'$ne': 1})" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-cyan-600 text-white px-4 py-2 rounded hover:bg-cyan-700">Tra cứu</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">{"$gt": ""}</code></p>
        </div>

        <!-- 9. XXE Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-teal-700">9. Parse XML (XXE)</h2>
            <form action="/xxe" method="GET">
                <input name="xml" type="text" placeholder="Nhập chuỗi XML" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-teal-600 text-white px-4 py-2 rounded hover:bg-teal-700">Phân tích XML</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">&lt;!ENTITY xxe SYSTEM 'file:///etc/passwd'&gt;</code></p>
        </div>

        <!-- 10. JWT Bypass Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-indigo-700">10. Đăng nhập JWT</h2>
            <form action="/jwtauth" method="GET">
                <input name="token" type="text" placeholder="Nhập Token JWT" class="border p-2 w-full rounded mb-2">
                <button type="submit" class="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700">Xác thực</button>
            </form>
            <p class="text-xs text-gray-500 mt-2">Payload test: <code class="bg-gray-200">eyJhbGciOiJub25lIn0...</code> (Thuật toán none)</p>
        </div>

        <!-- 11. API JSON SQLi Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-emerald-700">11. Đăng nhập API (SQLi JSON)</h2>
            <form id="json-sqli-form" class="mb-2">
                <input id="json-sqli-user" type="text" placeholder="Username" class="border p-2 w-full rounded mb-2">
                <input id="json-sqli-pass" type="text" placeholder="Password" class="border p-2 w-full rounded mb-2">
                <button type="button" onclick="sendJsonSqli()" class="bg-emerald-600 text-white px-4 py-2 rounded hover:bg-emerald-700">Login API</button>
            </form>
            <div id="json-sqli-result" class="text-xs bg-gray-100 p-2 rounded hidden mt-2 break-all"></div>
            <p class="text-xs text-gray-500 mt-2">Payload (User): <code class="bg-gray-200">admin' OR '1'='1</code></p>
        </div>

        <!-- 12. API JSON NoSQLi Test -->
        <div class="bg-white p-6 rounded-lg shadow">
            <h2 class="text-lg font-bold mb-4 text-sky-700">12. Đăng nhập NoSQL (NoSQLi JSON)</h2>
            <form id="json-nosqli-form" class="mb-2">
                <textarea id="json-nosqli-data" placeholder='{"username": {"$gt": ""}, "password": {"$gt": ""}}' class="border p-2 w-full rounded mb-2 text-sm" rows="2"></textarea>
                <button type="button" onclick="sendJsonNosqli()" class="bg-sky-600 text-white px-4 py-2 rounded hover:bg-sky-700">Login NoSQL API</button>
            </form>
            <div id="json-nosqli-result" class="text-xs bg-gray-100 p-2 rounded hidden mt-2 break-all"></div>
            <p class="text-xs text-gray-500 mt-2">Lỗ hổng: Gửi JSON gán toán tử NoSQL</p>
        </div>
    </div>
    
    <div class="container mx-auto px-8">
        <div class="bg-blue-100 border-l-4 border-blue-500 p-4">
            <p class="text-blue-700 font-bold">Trạng thái bảo vệ:</p>
            <p id="waf-status" class="text-sm">Đang kiểm tra...</p>
        </div>
    </div>

    <script>
        // Check if WAF is enabled via backend config
        const wafEnabled = {{ 'true' if config.get('WAF_ENABLED', False) else 'false' }};
        if (wafEnabled) {
            document.getElementById('waf-status').innerHTML = "✅ Đang được bảo vệ bởi AI WAF Shield Middleware";
            document.getElementById('waf-status').className = "text-green-700 font-bold";
        } else {
            document.getElementById('waf-status').innerHTML = "❌ KHÔNG CÓ BẢO VỆ! Hệ thống dễ bị tấn công.";
            document.getElementById('waf-status').className = "text-red-700 font-bold";
        }

        // Logic test API JSON
        function sendJsonSqli() {
            let u = document.getElementById('json-sqli-user').value;
            let p = document.getElementById('json-sqli-pass').value;
            fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: u, password: p})
            }).then(r => r.text()).then(t => {
                let res = document.getElementById('json-sqli-result');
                res.innerHTML = t; res.classList.remove('hidden');
            });
        }

        function sendJsonNosqli() {
            let data = document.getElementById('json-nosqli-data').value;
            if (!data) data = '{"username": {"$gt": ""}, "password": {"$gt": ""}}';
            fetch('/api/nosql-login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: data
            }).then(r => r.text()).then(t => {
                let res = document.getElementById('json-nosqli-result');
                res.innerHTML = t; res.classList.remove('hidden');
            });
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

@app.route('/ssti')
def ssti():
    tmpl = request.args.get('tmpl', '')
    # LỖI SSTI: Sử dụng render_template_string với input trực tiếp chưa qua escape
    if tmpl:
        try:
            return render_template_string(f"Nội dung template trả về: {tmpl}")
        except Exception as e:
            return f"Lỗi template: {e}"
    return "Nhập template để hiển thị"

@app.route('/nosqli')
def nosqli():
    query = request.args.get('query', '')
    # LỖI NoSQLi: Giả lập việc nhận string json filter và thực thi trực tiếp trên DB NoSQL
    return f"<h3>🔍 Kết quả truy vấn NoSQL:</h3><p>Đã thực thi mảng Filter: <b>{query}</b></p><br><p>Tất cả bản ghi nội bộ đã bị trả về!</p>"

@app.route('/xxe')
def xxe():
    xml_data = request.args.get('xml', '')
    # LỖI XXE: Giả lập việc parse XML trực tiếp mà không tắt tính năng resolver
    return f"<h3>💥 Đã phân tích XML:</h3><p>Dữ liệu trích xuất (đã load entities SYSTEM): <b>{xml_data}</b></p>"

@app.route('/jwtauth')
def jwtauth():
    token = request.args.get('token', '')
    # LỖI JWT: Giả lập xác thực bằng token dễ bị dính None algorithm/Signature bypass
    if token.startswith("eyJh"):  # JWT Base64 encoded Header
        return f"<h3>🔓 Xác thực JWT thành công!</h3><p>Đã bypass bằng token: <b>{token}</b></p><br><p>Quyền: admin</p>"
    return "Token JWT không hợp lệ"

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    # LỖI SQL INJECTION (JSON Payload): Cộng chuỗi
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        if results:
            return f"<b>✅ Đăng nhập thành công:</b> <br>{str(results)}"
        return "❌ Sai tài khoản/mật khẩu"
    except Exception as e:
        return f"Lỗi database: {str(e)}"

@app.route('/api/nosql-login', methods=['POST'])
def api_nosql_login():
    data = request.json or {}
    # LỖI NoSQLi (JSON Payload): Nhận Dict từ user (Gán NoSQL Operators)
    return f"<b>✅ Đã nhận payload NoSQLi từ JSON:</b> <br>{str(data)} <br>Dữ liệu đã bị bypass!"

if __name__ == '__main__':
    print(f"Web muc tieu (Vulnerable) dang chay tai http://localhost:{args.port}")
    if app.config.get('WAF_ENABLED'):
        print("🛡️  AI WAF Shield is ENABLED.")
        print(f"   Dashboard: http://localhost:{args.port}/ai-waf/dashboard")
    else:
        print("⚠️  AI WAF Shield is DISABLED (--no-waf).")
    
    print("   Endpoints: /search-user, /feedback, /view-doc, /ping, /fetch-url, /transfer, /ssti, /nosqli, /xxe, /jwtauth, /api/login, /api/nosql-login")
    app.run(port=args.port, host='0.0.0.0')
