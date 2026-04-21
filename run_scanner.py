import subprocess
import sys
import threading
import time

def run():
    print("Bắt đầu quét...")
    p = subprocess.Popen(
        [sys.executable, "-u", "modul1_scanner.py", "--target", "http://localhost:5170", "--report"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        encoding="utf-8"
    )
    
    def read_output():
        for line in p.stdout:
            print(line, end="")
            if "Bạn có muốn quét lại hoặc thử URL khác không?" in line:
                p.stdin.write("n\n")
                p.stdin.flush()
                
    t = threading.Thread(target=read_output)
    t.start()
    t.join()
    p.wait()
    print("Quét kết thúc!")

if __name__ == "__main__":
    run()
