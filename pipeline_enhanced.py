#!/usr/bin/env python3
"""
Enhanced pipeline.py - Single-command orchestrator for the crypto scanner pipeline.

Incorporates all 5 recommendations: target intelligence, enhanced deobfuscation,
adaptive throttling, result verification, and resource management.
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

# Import enhanced modules
try:
    from target_intelligence import TargetIntelligence
    from enhanced_deobfuscate import AdvancedDeobfuscator
    from result_verifier import ResultVerifier
    from resource_manager import ResourceManager
    from adaptive_throttler import AdaptiveThrottler
    ENHANCED_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"[!] Enhanced modules not available: {e}")
    ENHANCED_MODULES_AVAILABLE = False
    # Fall back to basic functionality

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

def _log(msg: str) -> None:
    """Log a message to both stdout and the main log file."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    formatted_msg = f"[{timestamp}] {msg}"
    print(formatted_msg)
    with LOGFILE.open("a", encoding="utf-8") as f:
        f.write(formatted_msg + "\n")

def _exec(cmd: list[str], desc: str) -> int:
    """Execute a command and return its exit code."""
    _log(f"[exec] {' '.join(cmd)}")
    start = time.time()
    ret = subprocess.call(cmd, cwd=str(HOME))
    elapsed = time.time() - start
    status = "succeeded" if ret == 0 else f"failed (exit {ret})"
    _log(f"  [{desc}] {status} in {elapsed:.1f}s")
    return ret

def _step(n: int, desc: str) -> None:
    """Print a step header."""
    _log(f"[*] Step {n}/5: {desc}...")

def _ensure_mass_scan_running() -> bool:
    """Ensure mass scan is running via adaptive throttler."""
    if ENHANCED_MODULES_AVAILABLE:
        # Use adaptive throttler instead of basic run_throttled
        throttler_script = HOME / "adaptive_throttler.py"
        throttler_pid_file = PID_DIR / "adaptive_scan.pid"
    else:
        throttler_script = RUN_THROTTLED
        throttler_pid_file = MASS_PID_FILE

    if throttler_pid_file.exists():
        pid_str = throttler_pid_file.read_text().strip()
        try:
            import psutil
            pid = int(pid_str)
            proc = psutil.Process(pid)
            if proc.is_running():
                _log(f"[*] {throttler_script.name} already running (PID {pid})")
                return True
        except (ValueError, ImportError):
            # If psutil is not available, just check if PID exists in process list
            try:
                os.kill(int(pid_str), 0)  # Check if process exists without killing
                _log(f"[*] {throttler_script.name} already running (PID {pid_str})")
                return True
            except (OSError, ValueError):
                pass  # Process doesn't exist
        except psutil.NoSuchProcess:
            pass
        # Clean up stale PID file
        throttler_pid_file.unlink(missing_ok=True)

    _log(f"[*] Starting {throttler_script.name}...")
    cmd = [sys.executable, str(throttler_script)]
    subprocess.Popen(cmd, cwd=str(HOME))
    # Give it a moment to start and write PID
    time.sleep(2)
    return throttler_pid_file.exists()

def _ensure_crypto_scanner_running() -> bool:
    """Ensure crypto scanner is running."""
    if CRYPTO_PID_FILE.exists():
        pid_str = CRYPTO_PID_FILE.read_text().strip()
        try:
            import psutil
            pid = int(pid_str)
            proc = psutil.Process(pid)
            if proc.is_running():
                _log(f"[*] {CRYPTO_SCANNER.name} already running (PID {pid})")
                return True
        except (ValueError, ImportError):
            # If psutil is not available, just check if PID exists in process list
            try:
                os.kill(int(pid_str), 0)  # Check if process exists without killing
                _log(f"[*] {CRYPTO_SCANNER.name} already running (PID {pid_str})")
                return True
            except (OSError, ValueError):
                pass  # Process doesn't exist
        except psutil.NoSuchProcess:
            pass
        # Clean up stale PID file
        CRYPTO_PID_FILE.unlink(missing_ok=True)

    _log(f"[*] Starting {CRYPTO_SCANNER.name}...")
    cmd = [sys.executable, str(CRYPTO_SCANNER), "-l", str(TRUFFLEHOG_MASS_RESULTS)]
    subprocess.Popen(cmd, cwd=str(HOME), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Give it a moment to start and write PID
    time.sleep(2)
    return CRYPTO_PID_FILE.exists()

def generate_targets() -> int:
    """Live production targets + outcome-based reorder. No placeholders."""
    ret = _exec([sys.executable, str(TARGET_GENERATOR)], "target generation (live)")
    if ret != 0:
        return ret
    if ENHANCED_MODULES_AVAILABLE:
        try:
            ti = TargetIntelligence()
            n = ti.reorder_paste_box()
            _log(f"[*] Outcome intelligence prioritized {n} real targets")
        except Exception as exc:
            _log(f"[!] Intelligence reorder failed: {exc}")
    return 0

def process_paste_box() -> int:
    """Process paste box with enhanced deobfuscation."""
    if ENHANCED_MODULES_AVAILABLE:
        _log("[*] Using enhanced deobfuscation...")
        deobfuscator = AdvancedDeobfuscator()
        
        # First run enhanced deobfuscation on the paste box
        paste_box_path = str(PASTE_BOX_TXT)
        if os.path.exists(paste_box_path):
            deobfuscator.deobfuscate_file(paste_box_path)
            enhanced_file = paste_box_path + '.enhanced'
            if os.path.exists(enhanced_file):
                # Combine original and enhanced versions
                with open(paste_box_path, 'a') as orig, open(enhanced_file, 'r') as enh:
                    orig.write('\n# Enhanced deobfuscation results:\n')
                    orig.write(enh.read())
    
    return _exec([sys.executable, str(PASTE_BOX)], "paste box processing")

def run_pipeline() -> int:
    """Run the complete pipeline with all enhancements."""
    _log("=" * 40)
    _log("PIPELINE - Starting with enhancements")
    _log("=" * 40)

    # Load environment variables
    _load_env()

    # Ensure WiFi connectivity
    _ensure_wifi()

    # Step 1: Generate targets with intelligence
    _step(1, "Generating intelligent targets")
    if generate_targets() != 0:
        _log("[!] Target generation failed")
        return 1

    # Step 2: Process paste box with enhanced deobfuscation
    _step(2, "Processing paste box with enhanced deobfuscation")
    if process_paste_box() != 0:
        _log("[!] Paste box processing failed")
        return 1

    # Step 3: Ensure mass scan is running with adaptive throttling
    _step(3, "Ensuring adaptive mass scan is running")
    if not _ensure_mass_scan_running():
        _log("[!] Failed to start adaptive mass scan")
        return 1

    # Step 4: Ensure crypto scanner is running with verification
    _step(4, "Ensuring crypto scanner is running with verification")
    if not _ensure_crypto_scanner_running():
        _log("[!] Failed to start crypto scanner")
        return 1

    # Step 5: Run learn crawl
    _step(5, "Running learn crawl with verification")
    ret = _exec([sys.executable, str(LEARN_CRAWL)], "learn crawl")
    
    # Apply result verification if available
    if ENHANCED_MODULES_AVAILABLE:
        _log("[*] Applying result verification...")
        verifier = ResultVerifier()
        
        # Verify the results from the crypto scanner
        results_file = HOME / "crypto_findings.jsonl"
        if results_file.exists():
            # Read and verify results
            verified_results = []
            with open(results_file, 'r') as f:
                import json
                for line in f:
                    try:
                        result = json.loads(line.strip())
                        # Verify this result
                        is_valid, reason = verifier.verify_result(result)
                        if is_valid:
                            verified_results.append(result)
                    except json.JSONDecodeError:
                        continue
            
            # Write verified results back
            verified_file = HOME / "verified_crypto_findings.jsonl"
            with open(verified_file, 'w') as f:
                for result in verified_results:
                    f.write(json.dumps(result) + '\n')
            
            _log(f"[+] Verified {len(verified_results)} out of {len(open(results_file).readlines())} results")

    _log("[+] Pipeline complete")
    return ret

def show_status() -> int:
    """Show service status and target counts."""
    _log("=" * 40)
    _log("PIPELINE STATUS")
    _log("=" * 40)

    # Show service status
    services = [
        ("Mass scan", MASS_PID_FILE),
        ("Crypto scanner", CRYPTO_PID_FILE),
    ]

    for name, pid_file in services:
        if pid_file.exists():
            pid_str = pid_file.read_text().strip()
            try:
                import psutil
                pid = int(pid_str)
                proc = psutil.Process(pid)
                if proc.is_running():
                    status = f"RUNNING (PID {pid})"
                else:
                    status = f"STOPPED (stale PID {pid})"
            except (ValueError, psutil.NoSuchProcess, ImportError):
                status = f"UNKNOWN (PID {pid_str})"
        else:
            status = "STOPPED"
        _log(f"{name:<15}: {status}")

    _log("")
    _log(f"Main log:         {LOGFILE}")
    _log(f"Crypto scanner log: {CRYPTO_SCANNER_LOG}")

    # Show target counts
    _log("")
    _log("Target counts (from paste_box.txt):")
    targets_dir = HOME / "targets"
    if targets_dir.exists():
        import re
        paste_content = (HOME / "paste_box.txt").read_text()
        # Count targets by platform
        platforms = [
            "aws_s3", "circleci", "docker", "elasticsearch", "gcs",
            "github", "gitlab", "huggingface", "jenkins", "postman", "syslog"
        ]
        total = 0
        for platform in platforms:
            # Simple count based on platform name appearing in targets
            count = len(re.findall(rf'{platform}[+://]', paste_content))
            _log(f"  {platform:<15} {count:>4}")
            total += count
        _log(f"  {'total':<15} {total:>4}")

    return 0

def stop_services() -> int:
    """Stop all background services."""
    _log("Stopping services...")

    # Kill processes from PID files
    for name, pid_file in [("mass scan", MASS_PID_FILE), ("crypto scanner", CRYPTO_PID_FILE)]:
        if pid_file.exists():
            try:
                pid_str = pid_file.read_text().strip()
                pid = int(pid_str)
                import os
                os.kill(pid, signal.SIGTERM)
                _log(f"  Sent SIGTERM to {name} (PID {pid})")
            except (ValueError, ProcessLookupError, ImportError):
                _log(f"  Could not stop {name} (invalid PID or process not found)")
            finally:
                pid_file.unlink(missing_ok=True)
        else:
            _log(f"  {name} not running (no PID file)")

    return 0

def main() -> int:
    parser = argparse.ArgumentParser(description="Enhanced crypto scanner pipeline")
    parser.add_argument("--status", action="store_true", help="show service status and target counts")
    parser.add_argument("--stop", action="store_true", help="stop all background services")
    parser.add_argument("--learn-only", action="store_true", help="run learn_crawl.py once and exit")
    args = parser.parse_args()

    # Setup resource management if available
    if ENHANCED_MODULES_AVAILABLE:
        _log("[*] Initializing resource management...")
        rm = ResourceManager()
        rm.monitor_resources()  # Start resource monitoring

    if args.status:
        return show_status()
    elif args.stop:
        return stop_services()
    elif args.learn_only:
        return _exec([sys.executable, str(LEARN_CRAWL)], "learn crawl (single run)")
    else:
        return run_pipeline()


if __name__ == "__main__":
    sys.exit(main())
