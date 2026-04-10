"""
FIX TRIỆT ĐỂ - Lần cuối:
1. XÓA mẫu CSRF dạng URL (chúng làm hỏng phân loại Normal URL)
2. CSRF chỉ giữ dạng auto-submit form (đặc trưng riêng, không overlap)
3. Thêm RẤT NHIỀU Normal URL (2000 mẫu) để tạo tín hiệu mạnh
4. Đảm bảo short SQLi tồn tại đúng cách
"""
import json

NB_PATH = r"D:\AI\ai_security\projectai.ipynb"

with open(NB_PATH, 'r', encoding='utf-8') as f:
    nb = json.load(f)

for i, cell in enumerate(nb['cells']):
    if cell['cell_type'] != 'code':
        continue
    src = ''.join(cell['source'])
    if 'target_count' not in src:
        continue
    if 'CÂN BẰNG' not in src:
        continue

    print(f"Found target cell at index {i}")

    # ═══ Xây lại toàn bộ block CSRF + Normal URLs ═══
    # Tìm và xóa block pure_csrf_patterns (URL-based - có hại)
    new_lines = []
    skip_block = False
    skip_marker = None

    for line in cell['source']:
        # Xóa block CSRF thuần URL-based (gây nhầm Normal → CSRF)
        if "CSRF THUẦN" in line or "pure_csrf_patterns" in line:
            skip_block = True
            skip_marker = "csrf_clean_df"
            continue
        if skip_block:
            if skip_marker and skip_marker in line:
                if "dfs.append" in line:
                    skip_block = False
                    skip_marker = None
                continue
            if "print(f" in line and "CSRF thuần" in line:
                skip_block = False
                skip_marker = None
                continue
            continue

        new_lines.append(line)

    print("  ✅ Xóa block CSRF URL-based (gây false positive)")

    # Tìm block short_xss_df → thêm CSRF dạng auto-submit form SAU nó
    final_lines = []
    for j, line in enumerate(new_lines):
        final_lines.append(line)

        if "dfs.append(short_xss_df)" in line:
            # Thêm CSRF dạng auto-submit form (đặc trưng riêng biệt)
            csrf_form_code = [
                "\n",
                "# ── CSRF: chỉ giữ dạng AUTO-SUBMIT FORM (đặc trưng riêng, không overlap URL/XSS) ──\n",
                "csrf_form_patterns = [\n",
                "    \"<form action='https://bank.com/transfer' method='POST' id='f'><input type='hidden' name='to' value='hacker'/><input type='hidden' name='amount' value='9999'/></form><script>document.getElementById('f').submit()</script>\",\n",
                "    \"<form action='/api/change-password' method='POST'><input type='hidden' name='new_pass' value='hacked'/></form><script>document.forms[0].submit()</script>\",\n",
                "    \"<form action='/admin/delete-user' method='POST'><input type='hidden' name='user_id' value='1'/></form><script>document.forms[0].submit()</script>\",\n",
                "    \"<form action='https://target.com/settings/email' method='POST'><input name='email' value='evil@hacker.com'/></form><script>document.forms[0].submit()</script>\",\n",
                "    \"<form method='POST' action='/transfer'><input type='hidden' name='to' value='attacker'/></form><script>document.forms[0].submit()</script>\",\n",
                "    \"<form action='/api/grant-admin' method='POST'><input type='hidden' name='role' value='admin'/></form><script>document.forms[0].submit()</script>\",\n",
                "    \"<iframe src='https://target.com/transfer?to=hacker&amount=100' style='display:none'></iframe>\",\n",
                "    \"<iframe src='/api/delete-account?confirm=1' width='0' height='0'></iframe>\",\n",
                "]\n",
                "csrf_form_df = pd.DataFrame({\n",
                "    'text': [clean_payload(p) for p in csrf_form_patterns] * 15,\n",
                "    'label': ['CSRF'] * (len(csrf_form_patterns) * 15)\n",
                "})\n",
                "dfs.append(csrf_form_df)\n",
                "print(f\"  ✅ Thêm {len(csrf_form_df)} mẫu CSRF auto-submit form\")\n",
            ]
            final_lines.extend(csrf_form_code)
            print("  ✅ Thêm CSRF dạng auto-submit form (không overlap URL/XSS)")

    # Tìm normal_url_samples → thay bằng danh sách lớn hơn nhiều (100 URL × 20 = 2000)
    result_lines = []
    replacing_normal = False
    for line in final_lines:
        if "normal_url_samples = [" in line:
            replacing_normal = True
            result_lines.append(
                "# Normal URLs — MASSIVE list để model hiểu 'URL != tấn công'\n"
            )
            result_lines.append("normal_url_samples = [\n")
            # 50 URL đa dạng
            urls = [
                "https://www.google.com/search?q=cat",
                "https://www.google.com/search?q=machine+learning",
                "https://www.google.com/search?q=python+tutorial",
                "https://www.google.com/maps?q=hanoi",
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "https://www.youtube.com/results?search_query=flask",
                "https://www.wikipedia.org/wiki/Python",
                "https://en.wikipedia.org/wiki/Artificial_intelligence",
                "https://stackoverflow.com/questions/12345",
                "https://stackoverflow.com/search?q=pandas+dataframe",
                "https://github.com/tensorflow/tensorflow",
                "https://github.com/search?q=machine+learning",
                "https://mail.google.com/mail/u/0/",
                "https://drive.google.com/file/d/abc123/view",
                "https://docs.google.com/document/d/xyz/edit",
                "http://localhost:5173/dashboard/users?id=123",
                "http://localhost:8080/api/v1/products",
                "http://localhost:3000/health",
                "http://localhost:8000/docs",
                "http://localhost:5000/login",
                "https://uet.vnu.edu.vn/category/tin-tuc/",
                "https://hus.vnu.edu.vn/nghien-cuu/bai-bao",
                "http://portal.edu.vn/api/docs/file.pdf",
                "https://example.com/login?redirect=home",
                "https://example.com/api/users/123",
                "https://example.com/products?page=2&sort=name",
                "http://192.168.1.1/admin/settings",
                "http://192.168.0.100/printer/status",
                "http://10.0.0.1:8080/api/v1/users",
                "http://company.internal:9090/metrics",
                "http://myapp.local:3000/health",
                "https://cdn.jsdelivr.net/npm/vue@3",
                "https://fonts.googleapis.com/css?family=Roboto",
                "http://api.weather.com/v1/forecast?city=hanoi",
                "https://jsonplaceholder.typicode.com/posts/1",
                "https://api.github.com/users/octocat",
                "https://httpbin.org/get?foo=bar",
                "http://worldtimeapi.org/api/timezone/Asia/Ho_Chi_Minh",
                "https://pokeapi.co/api/v2/pokemon/pikachu",
                "https://dog.ceo/api/breeds/image/random",
                "https://www.facebook.com/profile.php?id=100",
                "https://twitter.com/search?q=python",
                "https://www.linkedin.com/in/username",
                "https://www.reddit.com/r/learnpython",
                "https://medium.com/@user/article-title",
                "https://dev.to/search?q=flask+tutorial",
                "https://www.npmjs.com/package/express",
                "https://pypi.org/project/tensorflow/",
                "https://hub.docker.com/_/python",
                "https://www.amazon.com/dp/B09V3KXJPB",
            ]
            for url in urls:
                result_lines.append(f"    '{url}',\n")
            result_lines.append("]\n")
            result_lines.append("normal_urls = pd.DataFrame({\n")
            result_lines.append(f"    'text': normal_url_samples * 40,  # {len(urls)} URL * 40 = {len(urls)*40} mẫu Normal URL\n")
            result_lines.append(f"    'label': ['Normal'] * (len(normal_url_samples) * 40)\n")
            result_lines.append("})\n")
            result_lines.append("dfs.append(normal_urls)\n")
            result_lines.append(f"print(f\"  ✅ Thêm {{len(normal_urls)}} mẫu Normal URL (chống SSRF/CSRF false positive)\")\n")
            continue

        if replacing_normal:
            if "dfs.append(normal_urls)" in line:
                replacing_normal = False
            continue

        result_lines.append(line)

    print(f"  ✅ Thay 20 Normal URLs → 50 Normal URLs × 40 = 2000 mẫu")

    cell['source'] = result_lines
    print(f"\n  ✅ Cell {i} rebuild hoàn tất")
    break

with open(NB_PATH, 'w', encoding='utf-8') as f:
    json.dump(nb, f, ensure_ascii=False, indent=1)

print("\n" + "="*60)
print("✅ FIX TRIỆT ĐỂ")
print("="*60)
print("""
Thay đổi:
  1. XÓA CSRF URL-based (gây google.com → CSRF)
  2. CSRF chỉ còn auto-submit form (đặc trưng riêng biệt)
  3. Normal URLs: 50 URL × 40 = 2000 mẫu (áp đảo CSRF URLs)
  4. SQLi ngắn 800 mẫu (giữ nguyên từ fix trước)

Logic mới:
  - <form action=... submit()>  → CSRF  (auto-submit = CSRF)
  - <img onerror=alert()>       → XSS   (event handler = XSS)
  - http://google.com/...       → Normal (URL bình thường = Normal)
  - admin' OR 1                 → SQLi  (short-form SQL injection)
""")
