import json

file_path = r"d:\AI\ai_security\projectai.ipynb"
with open(file_path, "r", encoding="utf-8") as f:
    nb = json.load(f)

for cell in nb["cells"]:
    if cell["cell_type"] == "code":
        source = "".join(cell["source"])
        if "# --- F. DATA MỚI TỪ GITHUB ---" in source:
            old_list = """    ("OS-Command-Fuzzing.txt",  "Command Injection"),
    ("path-traversal.txt",      "Path Traversal"),
    ("ssrf.txt",                "SSRF"),
    # ("csrf-attack-payload-list.md",     "CSRF"),  # BỎ: file này là README, không phải payload
    ("SSRF.txt",                "SSRF"),
    ("traversal.txt",      "Path Traversal"),"""
            
            new_list = """    ("OS-Command-Fuzzing.txt",  "Command Injection"),
    ("path-traversal.txt",      "Path Traversal"),
    ("ssrf.txt",                "SSRF"),
    ("SSRF.txt",                "SSRF"),
    ("traversal.txt",           "Path Traversal"),
    # ── MỚI: MODERN ATTACKS ──
    ("ssti.txt",                "SSTI"),
    ("nosqli.txt",              "NoSQLi"),
    ("xxe.txt",                 "XXE"),
    ("jwt.txt",                 "JWTAuth"),"""
            
            if old_list in source:
                new_source = source.replace(old_list, new_list)
                new_cell_source = []
                for line in new_source.split('\n'):
                    new_cell_source.append(line + '\n')
                new_cell_source[-1] = new_cell_source[-1].rstrip('\n')
                cell["source"] = new_cell_source

with open(file_path, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)
