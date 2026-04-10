import urllib.request
import os

target_dir = r"D:\AI\clawweb\data\new"
os.makedirs(target_dir, exist_ok=True)

files_to_download = {
    "ssrf.txt": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/ssrf.txt",
        "https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/ssrf.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF.txt"
    ],
    "csrf-attack-payload-list.md": [
        "https://raw.githubusercontent.com/payloadbox/csrf-payload-list/master/README.md",
        "https://raw.githubusercontent.com/payloadbox/csrf-attack-payloads/master/README.md",
        "https://raw.githubusercontent.com/0xInfection/Awesome-WAF/master/README.md"
    ]
}

for filename, urls in files_to_download.items():
    filepath = os.path.join(target_dir, filename)
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        continue
    
    success = False
    for url in urls:
        print(f"[*] Trying {url} ...")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                content = response.read()
                with open(filepath, "wb") as f:
                    f.write(content)
                print(f"[+] Successfully downloaded {filename}")
                success = True
                break
        except Exception as e:
            print(f"[!] Failed: {e}")
            
    if not success:
        print(f"[X] Could not download {filename} from any URL.")
