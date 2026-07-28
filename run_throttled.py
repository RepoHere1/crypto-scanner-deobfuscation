#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import signal

# Lower CPU/nice priority to stay nice to system
os.nice(19)

HOME = os.path.expanduser("~")
PID_DIR = os.path.join(HOME, ".run_pids")
PID_FILE = os.path.join(PID_DIR, "mass_scan.pid")
os.makedirs(PID_DIR, exist_ok=True)

# Write PID file
with open(PID_FILE, "w") as f:
    f.write(str(os.getpid()))

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
    cwd=HOME,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
)

def cleanup(signum=None, frame=None):
    print("[!] Caught signal, terminating child...")
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    try:
        os.remove(PID_FILE)
    except OSError:
        pass
    sys.exit(0)

signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

try:
    for line in proc.stdout:
        sys.stdout.write("[%s] %s" % (time.strftime("%H:%M:%S"), line))
        sys.stdout.flush()
except KeyboardInterrupt:
    cleanup()

ret = proc.wait()
cleanup()
