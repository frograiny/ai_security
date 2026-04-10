import json

NB_PATH = r"D:\AI\ai_security\projectai.ipynb"

with open(NB_PATH, 'r', encoding='utf-8') as f:
    nb = json.load(f)

# Cell index 6 (where the loading logic is)
cell = nb['cells'][6]
new_source = []
for line in cell['source']:
    if 'csrf_clean_df' in line:
        print(f"Removing invalid line: {line.strip()}")
        continue
    new_source.append(line)

cell['source'] = new_source

with open(NB_PATH, 'w', encoding='utf-8') as f:
    json.dump(nb, f, ensure_ascii=False, indent=1)

print("Fixed NameError in projectai.ipynb")
