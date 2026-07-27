#!/usr/bin/env python3
import os
import subprocess
import sys
import time

# Lower CPU/nice priority to stay nice to system
os.nice(19)

print("[*] Throttler active: nice=%d" % os.nice(0))

cmd = [
    sys.executable,
    os.path.expanduser("~/.local/lib/trufflehog-tools/mass_scan.py"),
    "-f",
    os.path.expanduser("~/paste.txt"),
    "-j",
    "2",
    "-o",
    os.path.expanduser("~/.trufflehog_mass_results.jsonl"),
]

print("[*] Launching mass scan with throttle:", " ".join(cmd))

proc = subprocess.Popen(
    cmd,
    cwd=os.path.expanduser("~"),
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

try:
    for line in proc.stdout:
        sys.stdout.write("[%s] %s" % (time.strftime("%H:%M:%S"), line))
        sys.stdout.flush()
except KeyboardInterrupt:
    print("[!] Caught interrupt, terminating child...")
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

ret = proc.wait()
print(f"[*] Mass scan exited with code {ret}")
