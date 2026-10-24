import subprocess
import sys
import time
import re
import os

# Change to project root directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 1. Start Flask app
python_exe = os.path.join(os.getcwd(), ".venv", "Scripts", "python.exe")
if not os.path.exists(python_exe):
    python_exe = sys.executable

flask_process = subprocess.Popen(
    [python_exe, "run.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

time.sleep(2)

# 2. Start SSH tunnel via Pinggy
cmd = ["ssh", "-p", "443", "-T", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30", "-R0:localhost:5000", "a.pinggy.io"]

try:
    ssh_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    url_found = False
    for line in iter(ssh_proc.stdout.readline, ""):
        sys.stdout.write(line)
        sys.stdout.flush()
        # Look for https://....pinggy.link
        match = re.search(r"https://[a-zA-Z0-9.-]+\.pinggy\.link", line)
        if match and not url_found:
            url_found = True
            print(f"\n==========================================", flush=True)
            print(f"YOUR REAL LIVE URL: {match.group(0)}", flush=True)
            print(f"==========================================\n", flush=True)
except Exception as e:
    print(f"Error starting tunnel: {e}")
    flask_process.kill()
