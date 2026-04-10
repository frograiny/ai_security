import urllib.request
import os

target_dir = r"D:\AI\clawweb\data\new"
os.makedirs(target_dir, exist_ok=True)

files = {
    "SSRF.txt": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/SSRF.txt",
        "https://raw.githubusercontent.com/h0tak88r/Wordlists/master/vulns/ssrf.txt"
    ],
    "traversal.txt": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Path%20Traversal/Intruder/traversal.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt"
    ]
}

def dl(file_name, urls):
    dest = os.path.join(target_dir, file_name)
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            res = urllib.request.urlopen(req)
            if res.getcode() == 200:
                with open(dest, "wb") as f:
                    f.write(res.read())
                print(f"[OK] {file_name} from {url}")
                return
        except Exception as e:
            print(f"[Fail] {url}: {e}")

for name, urls in files.items():
    dl(name, urls)

