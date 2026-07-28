#!/usr/bin/env python3
"""
pipeline.py - Single-command orchestrator for the crypto scanner pipeline.

Usage:
    python3 ~/pipeline.py              # run full pipeline (generate, paste, start services, learn, summary)
    python3 ~/pipeline.py --status     # show service status and target counts
    python3 ~/pipeline.py --stop       # stop all background services
    python3 ~/pipeline.py --learn-only # run learn_crawl.py once and exit

All output is appended to ~/pipeline.log.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
PID_DIR = HOME / ".run_pids"
MASS_PID_FILE = PID_DIR / "mass_scan.pid"
CRYPTO_PID_FILE = PID_DIR / "crypto_scanner.pid"
LOGFILE = HOME / "pipeline.log"

# ---------------------------------------------------------------------------
# WiFi resilience helpers
# ---------------------------------------------------------------------------
WIFI_WAIT_INTERVAL = 30  # seconds between connectivity checks when waiting


def _is_wifi_connected(timeout: float = 5.0) -> bool:
    """Return True if the device has working internet connectivity."""
    try:
        import urllib.request
        urllib.request.urlopen("https://www.google.com", timeout=timeout)
        return True
    except Exception:
        return False


def _wait_for_wifi() -> None:
    """Block until WiFi/internet connectivity is restored."""
    _log("[wifi] No connectivity — waiting for WiFi to return...")
    start = time.time()
    while True:
        if _is_wifi_connected():
            elapsed = time.time() - start
            _log("[wifi] Connectivity restored after ~%.0fs — resuming." % elapsed)
            return
        elapsed = time.time() - start
        _log("[wifi] Still offline for ~%.0fs — checking again in %ds..." % (elapsed, WIFI_WAIT_INTERVAL))
        time.sleep(WIFI_WAIT_INTERVAL)


def _ensure_wifi() -> None:
    """Wait for WiFi if it is currently down, so pipeline steps can proceed."""
    if not _is_wifi_connected():
        _wait_for_wifi()


TARGET_GENERATOR = HOME / "target_generator.py"
PASTE_BOX = HOME / "paste_box.py"
RUN_THROTTLED = HOME / "run_throttled.py"
CRYPTO_SCANNER = HOME / "crypto_scanner.py"
LEARN_CRAWL = HOME / "learn_crawl.py"

PASTE_BOX_TXT = HOME / "paste_box.txt"
PASTE_TXT = HOME / "paste.txt"
TRUFFLEHOG_RESULTS = HOME / ".trufflehog_results.jsonl"
TRUFFLEHOG_MASS_RESULTS = HOME / ".trufflehog_mass_results.jsonl"
CRYPTO_SCANNER_LOG = HOME / "crypto_scanner_scanner.log"
LEARN_FILE = HOME / "learn_findings.jsonl"


def _load_env() -> None:
    """Load ~/.env into the current process environment so subprocesses see tokens."""
    env_path = HOME / ".env"
    if not env_path.exists():
        return
    try:
        with env_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except OSError:
        pass


_load_env()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    line = f"[{_now()}] {msg}"
    print(line)
    LOGFILE.parent.mkdir(parents=True, exist_ok=True)
    with LOGFILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _run(cmd: list[str | Path], check: bool = True, cwd: Path = HOME) -> subprocess.CompletedProcess:
    """Run a command synchronously and log its output."""
    str_cmd = [str(c) for c in cmd]
    _log(f"[exec] {' '.join(str_cmd)}")
    proc = subprocess.run(
        str_cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if proc.stdout:
        for line in proc.stdout.splitlines():
            _log(f"  {line}")
    if check and proc.returncode != 0:
        _log(f"[!] Command failed with exit code {proc.returncode}: {' '.join(str_cmd)}")
        raise subprocess.CalledProcessError(proc.returncode, str_cmd, output=proc.stdout)
    return proc


def _is_running(pidfile: Path) -> bool:
    if not pidfile.exists():
        return False
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _pid(pidfile: Path) -> int | None:
    if not pidfile.exists():
        return None
    try:
        return int(pidfile.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _start_if_not_running(script: Path, pidfile: Path, logfile: Path, args: list[str] | None = None) -> None:
    if _is_running(pidfile):
        _log(f"[*] {script.name} already running (PID {_pid(pidfile)})")
        return
    _log(f"[*] Starting {script.name} in background...")
    PID_DIR.mkdir(parents=True, exist_ok=True)
    str_cmd = [sys.executable, str(script)] + (args or [])
    with logfile.open("a", encoding="utf-8") as fh:
        proc = subprocess.Popen(
            str_cmd,
            cwd=HOME,
            stdout=fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    # The throttled runner and crypto scanner also write their own PID files.
    # We additionally write the PID we launched so pipeline.py can manage it.
    pidfile.write_text(str(proc.pid), encoding="utf-8")
    _log(f"[+] {script.name} started (PID: {proc.pid}); log: {logfile}")
    time.sleep(0.5)


def _stop_service(pidfile: Path, name: str) -> None:
    pid = _pid(pidfile)
    if pid is None or not _is_running(pidfile):
        _log(f"[*] {name} not running")
        if pidfile.exists():
            pidfile.unlink()
        return
    _log(f"[*] Stopping {name} (PID {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(20):
        if not _is_running(pidfile):
            break
        time.sleep(0.5)
    if _is_running(pidfile):
        _log(f"[*] Force killing {name}...")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if pidfile.exists():
        pidfile.unlink()
    _log(f"[+] {name} stopped")


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _count_generated_targets() -> dict[str, int]:
    counts: dict[str, int] = {}
    if not PASTE_BOX_TXT.exists():
        return counts
    current_platform: str | None = None
    try:
        with PASTE_BOX_TXT.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                stripped = line.strip()
                # Only count blocks produced by target_generator.py, e.g.:
                #   # --- github: 1800 targets ---
                if (
                    stripped.startswith("# --- ")
                    and ": " in stripped
                    and stripped.endswith(" targets ---")
                ):
                    current_platform = stripped[6:].split(":", 1)[0].strip()
                    counts[current_platform] = 0
                elif stripped.startswith("#"):
                    continue
                elif stripped and current_platform:
                    counts[current_platform] = counts.get(current_platform, 0) + 1
    except OSError:
        pass
    return counts


def _human_size(path: Path) -> str:
    try:
        size = path.stat().st_size
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
    except OSError:
        return "?"



def show_status() -> int:
    print("")
    print("=" * 42)
    print("PIPELINE STATUS")
    print("=" * 42)

    mass_pid = _pid(MASS_PID_FILE)
    crypto_pid = _pid(CRYPTO_PID_FILE)
    mass_running = _is_running(MASS_PID_FILE)
    crypto_running = _is_running(CRYPTO_PID_FILE)

    print(f"Mass scan:        {'RUNNING' if mass_running else 'STOPPED'} (PID {mass_pid if mass_pid else 'none'})")
    print(f"Crypto scanner:   {'RUNNING' if crypto_running else 'STOPPED'} (PID {crypto_pid if crypto_pid else 'none'})")

    print("")
    print("Target counts (from paste_box.txt):")
    target_counts = _count_generated_targets()
    if target_counts:
        for platform, count in sorted(target_counts.items()):
            print(f"  {platform:15s} {count:6d}")
        print(f"  {'total':15s} {sum(target_counts.values()):6d}")
    else:
        print("  [no generated targets yet]")

    print("")
    print("Output files:")
    print(f"  paste.txt:                {_count_lines(PASTE_TXT):6d} lines")
    print(f"  .trufflehog_results:      {_count_lines(TRUFFLEHOG_RESULTS):6d} lines  ({_human_size(TRUFFLEHOG_RESULTS)})")
    print(f"  .trufflehog_mass_results: {_count_lines(TRUFFLEHOG_MASS_RESULTS):6d} lines  ({_human_size(TRUFFLEHOG_MASS_RESULTS)})")
    print(f"  learn_findings.jsonl:     {_count_lines(LEARN_FILE):6d} lines  ({_human_size(LEARN_FILE)})")

    print("")
    print("Useful commands:")
    print(f"  python3 {HOME}/pipeline.py --status")
    print(f"  tail -f {LOGFILE}")
    print(f"  tail -f {CRYPTO_SCANNER_LOG}")
    print(f"  python3 {HOME}/pipeline.py --stop")
    print("=" * 42)
    return 0


def show_summary() -> None:
    print("")
    print("=" * 42)
    print("PIPELINE SUMMARY")
    print("=" * 42)
    mass_running = _is_running(MASS_PID_FILE)
    crypto_running = _is_running(CRYPTO_PID_FILE)
    print(f"Mass scan:        {'RUNNING' if mass_running else 'STOPPED'}")
    print(f"Crypto scanner:   {'RUNNING' if crypto_running else 'STOPPED'}")
    print(f"Main log:         {LOGFILE}")
    print(f"Crypto scanner log: {CRYPTO_SCANNER_LOG}")
    print("")
    print("Target counts (from paste_box.txt):")
    target_counts = _count_generated_targets()
    if target_counts:
        for platform, count in sorted(target_counts.items()):
            print(f"  {platform:15s} {count:6d}")
        print(f"  {'total':15s} {sum(target_counts.values()):6d}")
    print("")
    print("Useful commands:")
    print(f"  python3 {HOME}/pipeline.py --status")
    print(f"  tail -f {LOGFILE}")
    print(f"  tail -f {CRYPTO_SCANNER_LOG}")
    print(f"  python3 {HOME}/pipeline.py --stop")
    print("=" * 42)



def run_pipeline(learn_only: bool = False) -> int:
    _log("========================================")
    _log("PIPELINE - Starting")
    _log("========================================")

    if learn_only:
        _log("[*] Learn-only mode")
        _ensure_wifi()
        if LEARN_CRAWL.exists():
            _run([sys.executable, str(LEARN_CRAWL)], check=False)
        else:
            _log(f"[!] {LEARN_CRAWL} not found; skipping learn crawl")
        show_status()
        return 0

    # Step 1: Generate deterministic targets idempotently.
    if TARGET_GENERATOR.exists():
        _ensure_wifi()
        _log("[*] Step 1/5: Generating deterministic targets...")
        _run([sys.executable, str(TARGET_GENERATOR)])
    else:
        _log(f"[!] {TARGET_GENERATOR} not found; skipping target generation")

    # Step 2: Process paste_box.txt into per-platform files.
    if PASTE_BOX.exists():
        _ensure_wifi()
        _log("[*] Step 2/5: Processing paste box...")
        _run([sys.executable, str(PASTE_BOX)])
    else:
        _log(f"[!] {PASTE_BOX} not found; skipping paste box processing")

    # Step 3: Start throttled mass scan in background if not running.
    _ensure_wifi()
    _log("[*] Step 3/5: Ensuring mass scan is running...")
    if RUN_THROTTLED.exists():
        _start_if_not_running(RUN_THROTTLED, MASS_PID_FILE, LOGFILE)
    else:
        _log(f"[!] {RUN_THROTTLED} not found; skipping mass scan")

    # Step 4: Start crypto scanner in background if not running.
    _ensure_wifi()
    _log("[*] Step 4/5: Ensuring crypto scanner is running...")
    if CRYPTO_SCANNER.exists():
        _start_if_not_running(
            CRYPTO_SCANNER,
            CRYPTO_PID_FILE,
            CRYPTO_SCANNER_LOG,
            [str(TRUFFLEHOG_RESULTS)],
        )
    else:
        _log(f"[!] {CRYPTO_SCANNER} not found; skipping crypto scanner")

    # Step 5: Run learn_crawl.py once.
    _ensure_wifi()
    _log("[*] Step 5/5: Running learn crawl...")
    if LEARN_CRAWL.exists():
        _run([sys.executable, str(LEARN_CRAWL)], check=False)
    else:
        _log(f"[!] {LEARN_CRAWL} not found; skipping learn crawl")

    _log("[+] Pipeline complete")
    show_summary()
    return 0


def stop_all() -> int:
    _log("[*] Stopping all pipeline services...")
    _stop_service(MASS_PID_FILE, "mass scan")
    _stop_service(CRYPTO_PID_FILE, "crypto scanner")
    # Fallback pkill in case PID files are stale / services started elsewhere.
    subprocess.run(["pkill", "-f", "run_throttled.py"], capture_output=True)
    subprocess.run(["pkill", "-f", "crypto_scanner.py"], capture_output=True)
    _log("[+] All services stopped")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Single-command orchestrator for the crypto scanner pipeline.",
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop all background services and remove PID files.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show service status, target counts, and useful tail commands.",
    )
    parser.add_argument(
        "--learn-only",
        action="store_true",
        help="Run only learn_crawl.py once and print status.",
    )
    args = parser.parse_args()

    if args.stop:
        return stop_all()
    if args.status:
        return show_status()
    return run_pipeline(learn_only=args.learn_only)


if __name__ == "__main__":
    sys.exit(main())

