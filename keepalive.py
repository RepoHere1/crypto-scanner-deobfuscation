#!/usr/bin/env python3
"""Multi-day keepalive supervisor. Survives until device reboot."""
from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
PID_DIR = HOME / ".run_pids"
PID_DIR.mkdir(parents=True, exist_ok=True)

KEEPALIVE_PID = PID_DIR / "keepalive.pid"
LOG = HOME / "keepalive.log"

ADAPTIVE = HOME / "adaptive_throttler.py"
RUN_THROTTLED = HOME / "run_throttled.py"
CRYPTO = HOME / "crypto_scanner.py"
LEARN = HOME / "learn_crawl.py"
TARGET_GEN = HOME / "target_generator.py"
TARGET_INTEL = HOME / "target_intelligence.py"
PASTE_BOX = HOME / "paste_box.py"

MASS_RESULTS = HOME / ".trufflehog_mass_results.jsonl"
STD_RESULTS = HOME / ".trufflehog_results.jsonl"
PASTE_TXT = HOME / "paste.txt"

ADAPTIVE_PID = PID_DIR / "adaptive_scan.pid"
MASS_PID = PID_DIR / "mass_scan.pid"
CRYPTO_PID = PID_DIR / "crypto_scanner.pid"

ADAPTIVE_LOG = HOME / "adaptive_scan.log"
CRYPTO_LOG = HOME / "crypto_scanner_scanner.log"
LEARN_LOG = HOME / "learn_run.log"

CHECK_EVERY = 45
TARGET_REFRESH_EVERY = 6 * 3600
PASTE_REFRESH_EVERY = 12 * 3600
LEARN_EVERY = 4 * 3600
MIN_RESTART_GAP = 20

_last_start: dict[str, float] = {}
_last_target = 0.0
_last_paste = 0.0
_last_learn = 0.0
_stop = False
_log_stdout = True


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(msg: str) -> None:
    line = f"[{_ts()}] {msg}"
    if _log_stdout:
        try:
            print(line, flush=True)
        except Exception:
            pass
    try:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _load_env() -> None:
    tok = HOME / ".github_token"
    if tok.exists():
        try:
            t = tok.read_text(encoding="utf-8").splitlines()[0].strip()
            if t:
                os.environ.setdefault("GITHUB_TOKEN", t)
                os.environ.setdefault("GH_TOKEN", t)
        except OSError:
            pass
    envp = HOME / ".env"
    if envp.exists():
        try:
            for line in envp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k:
                    os.environ.setdefault(k, v)
        except OSError:
            pass
    if not os.environ.get("ALCHEMY_API_KEY"):
        brc = HOME / ".bashrc"
        if brc.exists():
            try:
                for line in brc.read_text(encoding="utf-8").splitlines():
                    if "ALCHEMY_API_KEY=" in line and not line.strip().startswith("#"):
                        part = line.split("ALCHEMY_API_KEY=", 1)[1].strip().strip('"').strip("'")
                        if part:
                            os.environ["ALCHEMY_API_KEY"] = part
                            break
            except OSError:
                pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid(path: Path):
    try:
        if not path.exists():
            return None
        return int(path.read_text().strip().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _service_alive(pid_file: Path) -> bool:
    pid = _read_pid(pid_file)
    return bool(pid and _pid_alive(pid))


def _write_pid(path: Path, pid: int) -> None:
    path.write_text(str(pid) + "\n")


def _pgrep_alive(pattern: str) -> bool:
    try:
        r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False
        for line in r.stdout.strip().splitlines():
            try:
                pid = int(line.strip())
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            # ignore our parent shells matching the pattern by chance
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
            except OSError:
                cmdline = ""
            if pattern.split("|")[0].replace("\\", "") in cmdline or any(
                p in cmdline for p in pattern.replace("\\", "").split("|")
            ):
                if "bash -c" in cmdline or "/bin/bash" in cmdline and "python" not in cmdline:
                    continue
                if "python" in cmdline or pattern.endswith(".py") and pattern.split("/")[-1].replace("\\", "") in cmdline:
                    return True
        return False
    except Exception:
        return False


def _spawn(name: str, cmd: list, log_path: Path, pid_file: Path | None = None):
    now = time.time()
    if now - _last_start.get(name, 0) < MIN_RESTART_GAP:
        return None
    _last_start[name] = now
    try:
        with log_path.open("a", encoding="utf-8") as lf:
            lf.write(f"\n--- keepalive spawn {_ts()} {' '.join(cmd)} ---\n")
            lf.flush()
            proc = subprocess.Popen(
                cmd,
                cwd=str(HOME),
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=os.environ.copy(),
            )
        if pid_file is not None:
            _write_pid(pid_file, proc.pid)
        log(f"spawned {name} pid={proc.pid}")
        return proc.pid
    except Exception as exc:
        log(f"FAILED spawn {name}: {exc}")
        return None


def ensure_adaptive() -> None:
    if _service_alive(ADAPTIVE_PID) or _service_alive(MASS_PID):
        return
    if _pgrep_alive(r"adaptive_throttler\.py") or _pgrep_alive(r"mass_scan\.py"):
        return
    script = ADAPTIVE if ADAPTIVE.exists() else RUN_THROTTLED
    if not script.exists():
        return
    pid_file = ADAPTIVE_PID if script == ADAPTIVE else MASS_PID
    log_path = ADAPTIVE_LOG if script == ADAPTIVE else (HOME / "run_throttled_out.log")
    _spawn("adaptive", [sys.executable, str(script)], log_path, pid_file)


def ensure_crypto() -> None:
    if _service_alive(CRYPTO_PID):
        return
    if _pgrep_alive(r"crypto_scanner\.py"):
        return
    scan = MASS_RESULTS if MASS_RESULTS.exists() and MASS_RESULTS.stat().st_size > 0 else STD_RESULTS
    try:
        scan.touch(exist_ok=True)
    except OSError:
        pass
    _spawn("crypto", [sys.executable, str(CRYPTO), str(scan)], CRYPTO_LOG, CRYPTO_PID)


def maybe_refresh_targets() -> None:
    global _last_target
    now = time.time()
    if now - _last_target < TARGET_REFRESH_EVERY:
        return
    _last_target = now
    if TARGET_GEN.exists():
        log("periodic target_generator")
        try:
            subprocess.run([sys.executable, str(TARGET_GEN)], cwd=str(HOME),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        except Exception as exc:
            log(f"target_generator error: {exc}")
    if TARGET_INTEL.exists():
        try:
            subprocess.run([sys.executable, str(TARGET_INTEL)], cwd=str(HOME),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        except Exception:
            pass


def maybe_paste_box() -> None:
    global _last_paste
    now = time.time()
    if now - _last_paste < PASTE_REFRESH_EVERY:
        return
    if PASTE_TXT.exists() and PASTE_TXT.stat().st_size > 1000:
        if now - PASTE_TXT.stat().st_mtime < PASTE_REFRESH_EVERY:
            _last_paste = now
            return
    _last_paste = now
    if not PASTE_BOX.exists():
        return
    log("periodic paste_box (timeout 180s)")
    try:
        subprocess.run([sys.executable, str(PASTE_BOX)], cwd=str(HOME),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    except subprocess.TimeoutExpired:
        log("paste_box timed out — skipped")
    except Exception as exc:
        log(f"paste_box error: {exc}")


def maybe_learn() -> None:
    global _last_learn
    now = time.time()
    if now - _last_learn < LEARN_EVERY:
        return
    if not LEARN.exists():
        return
    _last_learn = now
    log("periodic learn_crawl")
    try:
        with LEARN_LOG.open("a", encoding="utf-8") as lf:
            subprocess.Popen([sys.executable, str(LEARN)], cwd=str(HOME),
                             stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
    except Exception as exc:
        log(f"learn_crawl error: {exc}")


def _wifi_ok(timeout: float = 4.0) -> bool:
    for url in (
        "https://www.google.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://1.1.1.1",
        "https://api.github.com",
    ):
        try:
            urllib.request.urlopen(url, timeout=timeout)
            return True
        except Exception:
            continue
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _wake_lock() -> None:
    try:
        subprocess.Popen(["termux-wake-lock"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _handle_signal(signum, frame):
    global _stop
    log(f"signal {signum} — keepalive exiting (children keep running)")
    _stop = True


def run_loop() -> int:
    global _last_target, _last_paste, _last_learn
    _load_env()
    _wake_lock()
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    _write_pid(KEEPALIVE_PID, os.getpid())
    log(f"keepalive START pid={os.getpid()} check_every={CHECK_EVERY}s")
    log(f"alchemy={'yes' if os.environ.get('ALCHEMY_API_KEY') else 'no'} "
        f"gh_token={'yes' if os.environ.get('GITHUB_TOKEN') else 'no'}")
    now = time.time()
    _last_target = now
    _last_paste = now
    _last_learn = now - LEARN_EVERY + 600

    while not _stop:
        try:
            online = _wifi_ok()
            if not online:
                log("wifi probe failed — still ensuring local scanners")
            ensure_adaptive()
            ensure_crypto()
            if online:
                maybe_refresh_targets()
                maybe_paste_box()
                maybe_learn()
            if int(time.time()) % 1800 < CHECK_EVERY:
                _wake_lock()
        except Exception as exc:
            log(f"loop error: {exc}")
        left = CHECK_EVERY
        while left > 0 and not _stop:
            time.sleep(min(5, left))
            left -= 5

    try:
        if KEEPALIVE_PID.exists() and _read_pid(KEEPALIVE_PID) == os.getpid():
            KEEPALIVE_PID.unlink(missing_ok=True)
    except OSError:
        pass
    log("keepalive STOP")
    return 0


def _find_mass_pid():
    """mass_scan runs as child of adaptive — may have no mass_scan.pid."""
    pid = _read_pid(MASS_PID)
    if pid and _pid_alive(pid):
        return pid
    try:
        r = subprocess.run(["pgrep", "-f", r"mass_scan\.py"], capture_output=True, text=True, timeout=5)
        for line in (r.stdout or "").splitlines():
            try:
                p = int(line.strip())
            except ValueError:
                continue
            if p == os.getpid():
                continue
            try:
                cmd = Path(f"/proc/{p}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
            except OSError:
                continue
            if "mass_scan.py" in cmd and "python" in cmd:
                return p
    except Exception:
        pass
    return None

def status() -> int:
    kp = _read_pid(KEEPALIVE_PID)
    print(f"keepalive:  {'RUNNING pid=' + str(kp) if kp and _pid_alive(kp) else 'STOPPED'}")
    ap = _read_pid(ADAPTIVE_PID)
    ap_ok = bool(ap and _pid_alive(ap))
    print(f"adaptive:    {'RUNNING pid=' + str(ap) if ap_ok else 'STOPPED'}")
    mp = _find_mass_pid()
    print(f"mass:        {'RUNNING pid=' + str(mp) + ' (under adaptive)' if mp else 'STOPPED'}")
    cp = _read_pid(CRYPTO_PID)
    cp_ok = bool(cp and _pid_alive(cp))
    if not cp_ok:
        # orphan detect
        try:
            r = subprocess.run(["pgrep", "-f", r"crypto_scanner\.py"], capture_output=True, text=True, timeout=5)
            for line in (r.stdout or "").splitlines():
                try:
                    p = int(line.strip())
                except ValueError:
                    continue
                try:
                    cmd = Path(f"/proc/{p}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore")
                except OSError:
                    continue
                if "crypto_scanner.py" in cmd and "python" in cmd:
                    cp, cp_ok = p, True
                    break
        except Exception:
            pass
    print(f"crypto:      {'RUNNING pid=' + str(cp) if cp_ok else 'STOPPED'}")
    for pat in ("adaptive_throttler.py", "mass_scan.py", "crypto_scanner.py", "keepalive.py"):
        try:
            r = subprocess.run(["pgrep", "-af", pat], capture_output=True, text=True, timeout=5)
            for line in (r.stdout or "").strip().splitlines()[:4]:
                if "pgrep" in line or "--status" in line:
                    continue
                if "bash -c" in line:
                    continue
                print(f"  proc: {line[:140]}")
        except Exception:
            pass
    if LOG.exists():
        print("--- log tail ---")
        try:
            for ln in LOG.read_text(encoding="utf-8", errors="ignore").splitlines()[-10:]:
                print(ln)
        except OSError:
            pass
    return 0


def stop() -> int:
    pid = _read_pid(KEEPALIVE_PID)
    if pid and _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"sent SIGTERM to keepalive pid={pid}")
        except OSError as exc:
            print(f"could not signal {pid}: {exc}")
    else:
        print("keepalive not running via pidfile")
    subprocess.run(["pkill", "-f", "/keepalive.py"], capture_output=True)
    KEEPALIVE_PID.unlink(missing_ok=True)
    return 0


def main() -> int:
    global _log_stdout
    ap = argparse.ArgumentParser(description="Multi-day stack keepalive supervisor")
    ap.add_argument("--daemon", "-d", action="store_true")
    ap.add_argument("--foreground-daemon", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stop", action="store_true")
    args = ap.parse_args()
    if args.status:
        return status()
    if args.stop:
        return stop()
    if args.foreground_daemon:
        _log_stdout = False
        return run_loop()
    if args.daemon:
        pid = _read_pid(KEEPALIVE_PID)
        if pid and _pid_alive(pid):
            print(f"keepalive already running pid={pid}")
            return 0
        print("starting keepalive daemon...")
        with open(os.devnull, "wb") as devnull:
            proc = subprocess.Popen(
                [sys.executable, str(HOME / "keepalive.py"), "--foreground-daemon"],
                cwd=str(HOME),
                stdout=devnull,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=os.environ.copy(),
            )
        time.sleep(1.2)
        live = _read_pid(KEEPALIVE_PID) or proc.pid
        print(f"keepalive daemon pid={live} log={LOG}")
        return 0
    return run_loop()


if __name__ == "__main__":
    sys.exit(main())
