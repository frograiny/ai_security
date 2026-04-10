"""
Khắc phục lỗi data distribution do drop_duplicates phá hỏng:
1. drop_duplicates() xoá sạch các * 20, * 40 của ta.
2. Downsampling (sample n=16000) vô tình vứt bỏ luôn các mẫu ngắn mà ta khó khăn nhét vào.
Cách sửa:
Tìm cell 6, di chuyển việc nạp các mẫu này xuống SAU phần cân bằng (sau new_dfs),
để đảm bảo chúng được giữ nguyên số lượng và không bị cắt xén.
"""

import json

NB_PATH = r"D:\AI\ai_security\projectai.ipynb"

with open(NB_PATH, 'r', encoding='utf-8') as f:
    nb = json.load(f)

for i, cell in enumerate(nb['cells']):
    if cell['cell_type'] != 'code':
        continue
    src = ''.join(cell['source'])
    if 'CÂN BẰNG' not in src:
        continue

    # Chúng ta sẽ chèn mã ngay trước dòng: print("📊 Phân bổ nhãn MỚI NHẤT sau cân bằng:")
    new_src = []
    for line in cell['source']:
        if "print(\"📊 Phân bổ nhãn MỚI NHẤT sau cân bằng:\")" in line:
            # Chèn block data ở đây
            injector = [
                "\n",
                "    # ── BƠM TRỰC TIẾP DATA QUAN TRỌNG VÀO CUỐI CÙNG (CHỐNG DROP_DUPLICATES) ──\n",
                "    print(\"\\n💉 Đang bơm trực tiếp các mẫu đặc chủng vào tập dữ liệu cuối...\")\n",
                "    \n",
                "    # 1. Normal URLs (Chống SSRF false positive)\n",
                "    normal_urls = pd.DataFrame({\n",
                "        'text': normal_url_samples * 40,\n",
                "        'label': ['Normal'] * (len(normal_url_samples) * 40)\n",
                "    })\n",
                "    \n",
                "    # 2. Short SQLi (Chống admin' OR 1 false negative)\n",
                "    short_sqli_df = pd.DataFrame({\n",
                "        'text': [clean_payload(p) for p in short_sqli_patterns] * 20,\n",
                "        'label': ['SQLi'] * (len(short_sqli_patterns) * 20)\n",
                "    })\n",
                "    \n",
                "    # 3. Short XSS (Chống nhầm CSRF)\n",
                "    short_xss_df = pd.DataFrame({\n",
                "        'text': [clean_payload(p) for p in short_xss_patterns] * 20,\n",
                "        'label': ['XSS'] * (len(short_xss_patterns) * 20)\n",
                "    })\n",
                "    \n",
                "    # 4. Pure CSRF Form\n",
                "    csrf_form_df2 = pd.DataFrame({\n",
                "        'text': [clean_payload(p) for p in csrf_form_patterns] * 20,\n",
                "        'label': ['CSRF'] * (len(csrf_form_patterns) * 20)\n",
                "    })\n",
                "    \n",
                "    # Gộp tất cả\n",
                "    df = pd.concat([df, normal_urls, short_sqli_df, short_xss_df, csrf_form_df2], ignore_index=True).sample(\n",
                "        frac=1, random_state=42).reset_index(drop=True)\n",
                "    print(f\"  ✅ Đã bơm an toàn: {len(normal_urls)} Normal, {len(short_sqli_df)} SQLi, {len(short_xss_df)} XSS, {len(csrf_form_df2)} CSRF.\\n\")\n",
            ]
            new_src.extend(injector)
        new_src.append(line)

    cell['source'] = new_src
    print("✅ Đã vá lỗi drop_duplicates thành công!")
    break

with open(NB_PATH, 'w', encoding='utf-8') as f:
    json.dump(nb, f, ensure_ascii=False, indent=1)
