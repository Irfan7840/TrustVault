import subprocess
import time
import sys

cmd = ["cmd.exe", "/c", "npx", "--yes", "localtunnel", "--port", "5000", "--subdomain", "trustvault-app"]

print("Starting persistent localtunnel keep-alive loop...", flush=True)

while True:
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in iter(proc.stdout.readline, ""):
            print(line, end="", flush=True)
        proc.wait()
    except Exception as e:
        print(f"Error: {e}", flush=True)
    print("Tunnel process ended, reconnecting in 2 seconds...", flush=True)
    time.sleep(2)
