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

# ---------------------------------------------------------------------------
# WiFi resilience — wait for connectivity before launching, and auto-restart
# the mass scan if WiFi drops mid-execution so scanning resumes from where
# it left off rather than crashing.
# ---------------------------------------------------------------------------
WIFI_WAIT_INTERVAL = 30  # seconds between connectivity checks


def _is_wifi_connected(timeout=5):
    """Return True if the device has working internet connectivity."""
    try:
        import urllib.request
        urllib.request.urlopen("https://www.google.com", timeout=timeout)
        return True
    except Exception:
        return False


def _wait_for_wifi():
    """Block until WiFi/internet connectivity is restored, then return."""
    start = time.time()
    while True:
        if _is_wifi_connected():
            elapsed = time.time() - start
            print("[wifi] Connectivity restored after ~%.0fs — resuming." % elapsed)
            return
        elapsed = time.time() - start
        print(
            "[wifi] No connectivity for ~%.0fs — retrying in %ds..."
            % (elapsed, WIFI_WAIT_INTERVAL)
        )
        time.sleep(WIFI_WAIT_INTERVAL)


def _wait_for_wifi_before_launch():
    """Block until WiFi is available before starting the mass scan."""
    if _is_wifi_connected():
        print("[wifi] Connectivity OK — starting mass scan.")
        return
    print("[wifi] No connectivity at launch — waiting for WiFi...")
    _wait_for_wifi()


# Wait for WiFi before starting the mass scan.
# This prevents the scan from crashing immediately when WiFi is down.
_wait_for_wifi_before_launch()

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

# ---------------------------------------------------------------------------
# Retry loop: if the mass scan exits because WiFi dropped, wait for WiFi
# and restart from where it left off.  TruffleHog resumes scanning
# repos from its checkpoint file so nothing is re-scanned unnecessarily.
# ---------------------------------------------------------------------------
while True:
    try:
        for line in proc.stdout:
            sys.stdout.write("[%s] %s" % (time.strftime("%H:%M:%S"), line))
            sys.stdout.flush()
    except KeyboardInterrupt:
        cleanup()

    ret = proc.wait()

    # If WiFi looks down, wait for it and restart the mass scan.
    if ret != 0 and not _is_wifi_connected():
        print("[wifi] Mass scan exited with code %d — WiFi down, waiting..." % ret)
        _wait_for_wifi()
        print("[wifi] Restarting mass scan after connectivity restored.")
        proc = subprocess.Popen(
            cmd,
            cwd=HOME,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        continue

    # Non-zero exit while WiFi was up — trufflehog failed for a
    # reason other than network loss; don't loop forever.
    break

cleanup()
