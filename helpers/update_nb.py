import json

filepath = r"d:\AI\ai_security\projectai.ipynb"
with open(filepath, 'r', encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb['cells']:
    if cell['cell_type'] == 'code':
        source = cell['source']
        for i, line in enumerate(source):
            if '"csrf-attack-payload-list.md",       "CSRF"' in line:
                # Add the new lines after this one if not already there
                # Let's check if they exist
                has_ssrf = any('"SSRF.txt"' in l for l in source)
                if not has_ssrf:
                    # insert after i
                    source.insert(i+1, '    ("SSRF.txt",                "SSRF"),\n')
                    source.insert(i+2, '    ("traversal.txt",      "Path Traversal"),\n')
                    break

with open(filepath, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print("Done updating projectai.ipynb")
