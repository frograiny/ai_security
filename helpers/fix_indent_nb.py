import json

path = 'd:/AI/ai_security/projectai.ipynb'
with open(path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

changed = False
for cell in nb.get('cells', []):
    if cell.get('cell_type') == 'code':
        source = cell.get('source', [])
        for i, line in enumerate(source):
            if 'Đang bơm trực tiếp các mẫu đặc chủng vào tập dữ liệu cuối' in line:
                start_i = i - 1
                for j in range(start_i, len(source)):
                    if source[j].startswith('    '):
                        source[j] = source[j][4:]
                        changed = True

if changed:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(nb, f, indent=1)
    print('Done fixing indentation!')
else:
    print('No changes made, could not find the lines or already fixed.')
