#!/usr/bin/env python3
"""Second-window live ops watcher.

Designed to run in a separate Termux session while scanners run in the background.
Does not start/stop services — observe only.

Usage:
    watch2              # default 5s refresh
    python3 ~/watch2.py -i 3
    python3 ~/watch2.py --wallet   # focus wallet truth strip
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
PID_DIR = HOME / ".run_pids"
STATUS = HOME / "crypto_scanner_status.txt"
MEMORY = HOME / "crypto_scanner_memory.jsonl"
HITS = HOME / "balances_hit.jsonl"
CACHE = HOME / "balance_cache.jsonl"
HOT = HOME / ".hot_targets.json"
OUTCOMES = HOME / ".scan_outcomes.jsonl"
LAUNCH_LOG = HOME / "launch_all.log"
SCAN_LOG = HOME / "crypto_scanner_scanner.log"
MASS_LOG = HOME / "run_throttled_out.log"
ADAPT_LOG = HOME / "adaptive_scan.log"
TH_RESULTS = HOME / ".trufflehog_results.jsonl"
TH_MASS = HOME / ".trufflehog_mass_results.jsonl"
DEOBF_LOG = HOME / "deobfuscation_daemon.log"
DEOBF_FILE = HOME / ".trufflehog_deobfuscated.jsonl"
DEOBF_RAW = HOME / "deobfuscated_secrets.txt"

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

SERVICES = [
    ("mass_scan", "mass_scan.pid", r"mass_scan\.py"),
    ("adaptive", "adaptive_scan.pid", r"adaptive_throttler\.py"),
    ("crypto", "crypto_scanner.pid", r"crypto_scanner\.py"),
    ("deobf", "deobfuscation_daemon.pid", r"deobfuscation_daemon\.py"),
    ("watchdog", "stack_watchdog.pid", r"stack_watchdog\.sh|perpetual_watchdog"),
]


def clear():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def is_running(pid_file: Path, pattern: str = "") -> tuple[bool, str]:
    if pid_file.exists():
        try:
            pid = pid_file.read_text().strip().splitlines()[0].strip()
            os.kill(int(pid), 0)
            return True, pid
        except Exception:
            pass
    if pattern:
        # Fall back to live process lookup when the pid file is stale/absent.
        try:
            import subprocess
            r = subprocess.run(["pgrep", "-f", pattern],
                               capture_output=True, text=True, timeout=5)
            pids = [p for p in r.stdout.split() if p.isdigit()]
            if pids:
                return True, pids[0]
        except Exception:
            pass
    return False, "-"


def fsize(path: Path) -> str:
    try:
        n = path.stat().st_size
    except Exception:
        return "-"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def flines(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        size = path.stat().st_size
        if size == 0:
            return 0
        if size <= 2_000_000:
            with path.open("rb") as f:
                return sum(1 for _ in f)
        with path.open("rb") as f:
            head = f.read(512_000)
            try:
                f.seek(-min(256_000, size), 2)
            except OSError:
                f.seek(0)
            tail = f.read(256_000)
        nl = bytes([10])
        sample = head + nl + tail
        n = sample.count(nl) or 1
        avg = max(len(sample) / n, 40.0)
        return int(size / avg)
    except Exception:
        return 0


def tail_text(path: Path, n: int = 6) -> list[str]:
    if not path.exists():
        return []
    try:
        data = path.read_bytes()
        if len(data) > 200_000:
            data = data[-200_000:]
        lines = data.decode("utf-8", errors="ignore").splitlines()
        return lines[-n:]
    except Exception:
        return []


def load_jsonl_tail(path: Path, n: int = 5) -> list[dict]:
    out = []
    for line in tail_text(path, n=n * 3):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out[-n:]


def wallet_truth() -> dict:
    try:
        sys.path.insert(0, str(HOME))
        import wallet_view as wv
        wallets = wv.gather_wallets()
        bals, meta = wv.load_balances()
        keys = set()
        for w in wallets:
            keys.update(w.get("addresses", {}).keys())
        nz = []
        pending = 0
        total = 0.0
        for k in keys:
            b = bals.get(k)
            if b is None:
                pending += 1
            elif isinstance(b, (int, float)) and b > 1e-12:
                nz.append((k[0], k[1], float(b)))
                total += float(b)
        nz.sort(key=lambda x: -x[2])
        return {
            "wallets": len(wallets),
            "addrs": len(keys),
            "nz": nz,
            "pending": pending,
            "total": total,
        }
    except Exception as e:
        return {"error": str(e)}


def render(show_wallet: bool = True) -> str:
    cols = shutil.get_terminal_size((80, 24)).columns
    bar = "=" * cols
    thin = "-" * cols
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []
    lines.append(bar)
    lines.append(f"{BOLD}  WATCH2 — LIVE OPS (2nd window){RESET}  {DIM}{now}{RESET}")
    lines.append(bar)

    # Services
    lines.append(f"{BOLD}  SERVICES{RESET}")
    lines.append(thin)
    any_up = False
    for name, pf, pat in SERVICES:
        up, pid = is_running(PID_DIR / pf, pat)
        any_up = any_up or up
        state = f"{GREEN}RUN{RESET}" if up else f"{RED}OFF{RESET}"
        lines.append(f"  {name:10} {state}  pid={pid}")
    # also detect stray processes
    try:
        import subprocess
        ps = subprocess.check_output(["ps", "-A", "-o", "pid,args"], text=True, errors="ignore")
        extras = []
        for row in ps.splitlines():
            if any(x in row for x in ("crypto_scanner.py", "adaptive_throttler", "run_throttled", "trufflehog")):
                extras.append(row.strip()[:cols - 4])
        if extras:
            lines.append(f"  {DIM}procs:{RESET}")
            for e in extras[:6]:
                lines.append(f"  {DIM}{e}{RESET}")
    except Exception:
        pass
    if not any_up:
        lines.append(f"  {YELLOW}No core services up — run: go   or   bash ~/stack_on.sh{RESET}")
    lines.append("")

    # Scanner status
    lines.append(f"{BOLD}  SCANNER STATUS{RESET}")
    lines.append(thin)
    if STATUS.exists():
        lines.append(f"  {STATUS.read_text(encoding='utf-8', errors='ignore').strip()}")
    else:
        lines.append("  (no status yet)")
    lines.append("")

    # Files
    lines.append(f"{BOLD}  PIPELINE FILES{RESET}")
    lines.append(thin)
    for label, path in [
        ("trufflehog", TH_RESULTS),
        ("mass results", TH_MASS),
        ("deobf out", DEOBF_FILE),
        ("deobf secrets", DEOBF_RAW),
        ("memory", MEMORY),
        ("bal cache", CACHE),
        ("bal hits", HITS),
        ("outcomes", OUTCOMES),
        ("hot targets", HOT),
    ]:
        lines.append(f"  {label:12} {flines(path):>8} lines  {fsize(path):>8}")
    lines.append("")

    # Hot targets snapshot
    if HOT.exists():
        try:
            hot = json.loads(HOT.read_text())
            lines.append(f"{BOLD}  HOT QUEUE{RESET}  {DIM}{hot.get('generated_at','')}{RESET}")
            lines.append(thin)
            lines.append(f"  count={hot.get('count')}")
            for t in (hot.get("targets") or [])[:5]:
                lines.append(f"  {float(t.get('score') or 0):.2f}  {t.get('uri','')[:cols-12]}")
            lines.append("")
        except Exception:
            pass

    # Recent outcomes
    outs = load_jsonl_tail(OUTCOMES, 5)
    if outs:
        lines.append(f"{BOLD}  RECENT OUTCOMES{RESET}")
        lines.append(thin)
        for o in outs:
            flag = "BAL" if o.get("has_balance") else ("KEY" if o.get("has_key") else "empty")
            col = GREEN if flag in ("BAL", "KEY") else DIM
            lines.append(
                f"  {col}{flag:5}{RESET} {float(o.get('score') or 0):.2f}  "
                f"{(o.get('uri') or '')[: cols - 20]}"
            )
        lines.append("")

    # Wallet truth
    if show_wallet:
        wt = wallet_truth()
        lines.append(f"{BOLD}  WALLET TRUTH (derived keys only){RESET}")
        lines.append(thin)
        if "error" in wt:
            lines.append(f"  {YELLOW}{wt['error']}{RESET}")
        else:
            lines.append(
                f"  wallets={wt['wallets']}  addrs={wt['addrs']}  "
                f"nz={len(wt['nz'])}  pending={wt['pending']}  "
                f"total={GREEN}{wt['total']:,.8f}{RESET}"
            )
            for chain, addr, bal in wt["nz"][:6]:
                lines.append(f"  {GREEN}***{RESET} {chain.upper():6} {addr[:42]}  {bal:,.8f}")
        lines.append("")

    # Log tails
    lines.append(f"{BOLD}  LOG TAIL{RESET}")
    lines.append(thin)
    for label, path in [("launch", LAUNCH_LOG), ("crypto", SCAN_LOG), ("mass", MASS_LOG), ("adapt", ADAPT_LOG), ("deobf", DEOBF_LOG)]:
        rows = tail_text(path, 2)
        if not rows:
            continue
        lines.append(f"  {CYAN}{label}{RESET}")
        for r in rows:
            lines.append(f"  {DIM}{r[: cols - 4]}{RESET}")
    lines.append("")
    lines.append(thin)
    lines.append(f"  {DIM}Ctrl+C exits watch only — scanners keep running{RESET}")
    lines.append(f"  {DIM}other window: walletview | dashw | tail -f ~/crypto_scanner_scanner.log{RESET}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="2nd-window live ops watcher")
    ap.add_argument("-i", "--interval", type=int, default=5)
    ap.add_argument("--wallet", action="store_true", help="force wallet section (default on)")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    def stop(_s=None, _f=None):
        clear()
        print(render())
        print("\nwatch2 stopped (services still running).")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    if args.once:
        print(render(show_wallet=True))
        return

    while True:
        clear()
        print(render(show_wallet=True))
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    main()
