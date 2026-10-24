import subprocess
import sys
import time
import os

os.chdir(r"c:\Users\moham\Downloads\TrustVault")

# 1. Start Flask app
python_exe = os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe")
flask_proc = subprocess.Popen(
    [python_exe, "run.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)

time.sleep(2)

# 2. Start localtunnel
lt_cmd = ["cmd.exe", "/c", "npx", "--yes", "localtunnel", "--port", "5000", "--subdomain", "trustvault-demo"]
lt_proc = subprocess.Popen(
    lt_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

for line in iter(lt_proc.stdout.readline, ""):
    print(line, end="", flush=True)
    if "your url is:" in line.lower():
        with open("tunnel_url.txt", "w") as f:
            f.write(line.strip())
        break

# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    flask_proc.terminate()
    lt_proc.terminate()
