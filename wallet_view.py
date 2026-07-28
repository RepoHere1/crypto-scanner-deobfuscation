#!/usr/bin/env python3
"""
Live Wallet Balance Viewer — production truth view.

Always hits live chain providers for every reconstructed wallet address,
writes results back to balance_cache.jsonl, and only totals balances that
belong to wallets derived from keys/seeds (never unrelated cache junk).

Usage:
    python3 ~/wallet_view.py              # live check once
    python3 ~/wallet_view.py --watch      # live refresh loop (default 30s)
    python3 ~/wallet_view.py -w -i 15     # refresh every 15s
    python3 ~/wallet_view.py --cached     # display-only from cache (no RPC)
"""
import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
MEMORY_FILE = os.path.join(HOME, "crypto_scanner_memory.jsonl")
CACHE_FILE = os.path.join(HOME, "balance_cache.jsonl")
HITS_FILE = os.path.join(HOME, "balances_hit.jsonl")

sys.path.insert(0, HOME)
import crypto_scanner as cs

# Parallel live checks — keep modest on Termux to avoid rate-limits / OOM.
LIVE_WORKERS = 6
DEFAULT_INTERVAL = 30

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"


def load_records(path):
    records = []
    if not os.path.exists(path):
        return records
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    return records


def load_balances():
    """Load cache as {(chain, address): balance_or_None} plus meta."""
    balances = {}
    meta = {}
    for rec in load_records(CACHE_FILE):
        chain = (rec.get("chain") or "?").lower()
        addr = rec.get("address") or ""
        if not addr:
            continue
        key = (chain, addr)
        balances[key] = rec.get("balance")
        meta[key] = {
            "checked_at": rec.get("checked_at"),
            "live": rec.get("live", False),
            "ts": rec.get("ts"),
        }
    return balances, meta


def format_balance(bal):
    if bal is None:
        return f"{YELLOW}PENDING{RESET}"
    if bal == 0:
        return "0.00000000"
    if bal > 0:
        return f"{GREEN}{bal:,.8f}{RESET}"
    return f"{bal:,.8f}"


def derive_for_key(key_type, key_value):
    """Re-derive the current chain set from a private key/seed."""
    if key_type == "WIF":
        priv = cs.wif_to_priv_bytes(key_value)
        addrs = cs.priv_to_addresses(priv) if priv else {}
    elif key_type == "HEX":
        try:
            addrs = cs.priv_to_addresses(bytes.fromhex(key_value))
        except Exception:
            addrs = {}
    elif key_type == "SEED":
        addrs = cs.seed_to_addresses(key_value)
    else:
        addrs = {}
    result = {}
    for chain, addr in addrs.items():
        chain = (chain or "?").lower()
        if addr:
            result[(chain, addr)] = {"chain": chain, "address": addr, "from": key_type.lower()}
    return result


def gather_wallets():
    """Group records by private key/seed and collect all derived addresses."""
    wallets = {}
    records = load_records(MEMORY_FILE)

    sorted_records = sorted(
        records,
        key=lambda x: x.get("timestamp", str(x.get("time", ""))),
        reverse=True,
    )

    for rec in sorted_records:
        findings = rec.get("findings", {}) or {}
        wallet = findings.get("wallet", {}) or {}
        derived = findings.get("derived_addresses", []) or []

        def add_wallet(key_type, key_value, rec=rec, derived=derived):
            if not key_value:
                return
            w = wallets.setdefault(
                (key_type, key_value),
                {
                    "type": key_type,
                    "key": key_value,
                    "addresses": {},
                    "timestamp": rec.get("timestamp", rec.get("time", "")),
                },
            )
            for d in derived:
                chain = (d.get("chain") or "?").lower()
                addr = d.get("address") or ""
                if addr:
                    w["addresses"][(chain, addr)] = {
                        "chain": chain,
                        "address": addr,
                        "from": d.get("from", key_type.lower()),
                    }

        for wif in wallet.get("wifs", []) or []:
            add_wallet("WIF", wif)
        for hexk in wallet.get("hex_keys", []) or []:
            add_wallet("HEX", hexk)
        for seed in wallet.get("seed_phrases", []) or []:
            add_wallet("SEED", seed)

    # Ensure every wallet shows the latest supported chains (re-derive).
    for (key_type, key_value), w in wallets.items():
        w["addresses"].update(derive_for_key(key_type, key_value))

    return sorted(wallets.values(), key=lambda x: x.get("timestamp", ""), reverse=True)


def _check_one(chain, addr):
    """Live force-refresh a single (chain, address). Returns rec dict."""
    try:
        return cs.get_balance(chain, addr, force=True)
    except Exception as exc:
        return {
            "chain": chain,
            "address": addr,
            "balance": None,
            "error": str(exc),
            "ts": time.time(),
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "live": False,
        }


def live_refresh(address_keys, progress_cb=None):
    """Force live balance checks for every (chain, addr) in parallel.

    Returns {(chain, addr): balance_or_None} for the keys we checked.
    Also merges results into balance_cache.jsonl via crypto_scanner.get_balance.
    """
    seen = set()
    targets = []
    for chain, addr in address_keys:
        key = ((chain or "?").lower(), addr)
        if not addr or key in seen:
            continue
        seen.add(key)
        targets.append(key)

    results = {}
    total = len(targets)
    done = 0
    lock = threading.Lock()

    if total == 0:
        return results

    with ThreadPoolExecutor(max_workers=LIVE_WORKERS) as pool:
        futures = {pool.submit(_check_one, c, a): (c, a) for c, a in targets}
        for fut in as_completed(futures):
            chain, addr = futures[fut]
            try:
                rec = fut.result()
            except Exception as exc:
                rec = {
                    "chain": chain,
                    "address": addr,
                    "balance": None,
                    "error": str(exc),
                }
            bal = rec.get("balance") if isinstance(rec, dict) else None
            results[(chain, addr)] = bal
            with lock:
                done += 1
                if progress_cb:
                    progress_cb(done, total, chain, addr, bal)
    return results


def record_hits(balances_for_wallets):
    """Append any newly discovered nonzero wallet balances to hits file."""
    try:
        existing = set()
        for rec in load_records(HITS_FILE):
            existing.add(
                (
                    (rec.get("chain") or "").lower(),
                    rec.get("address") or "",
                    rec.get("balance"),
                )
            )
        with open(HITS_FILE, "a", encoding="utf-8") as f:
            for (chain, addr), bal in balances_for_wallets.items():
                if bal is None or bal <= 0:
                    continue
                tup = (chain, addr, bal)
                if tup in existing:
                    continue
                rec = {
                    "chain": chain,
                    "address": addr,
                    "balance": bal,
                    "ts": time.time(),
                    "checked_at": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "source": "wallet_view_live",
                }
                f.write(json.dumps(rec) + "\n")
                existing.add(tup)
    except Exception:
        pass


def clear_screen():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def render(live=True, status_line=""):
    wallets = gather_wallets()

    all_addresses = []
    seen = set()
    for w in wallets:
        for key in w["addresses"].keys():
            if key not in seen:
                seen.add(key)
                all_addresses.append(key)

    # Start from cache so first paint is instant, then overlay live results.
    balances, meta = load_balances()
    live_checked = 0
    live_failed = 0
    refresh_started = time.time()

    if live and all_addresses:
        # Show a "refreshing" frame first so the user knows it's not frozen.
        clear_screen()
        print("=" * 76)
        print(" " * 18 + f"{BOLD}WALLET BALANCE VIEWER — LIVE{RESET}")
        print("=" * 76)
        print()
        print(f"  Wallets reconstructed: {len(wallets)}")
        print(f"  Unique addresses:      {len(all_addresses)}")
        print(f"  {CYAN}Hitting live chain RPCs...{RESET}")
        if status_line:
            print(f"  {DIM}{status_line}{RESET}")
        print()
        sys.stdout.flush()

        progress_state = {"last_print": 0.0}

        def on_progress(done, total, chain, addr, bal):
            now = time.time()
            # Throttle progress redraws
            if now - progress_state["last_print"] < 0.25 and done < total:
                return
            progress_state["last_print"] = now
            bal_s = "PENDING" if bal is None else f"{bal:.8f}"
            sys.stdout.write(
                f"\r  [{done:>3}/{total}] {chain.upper():>6}  {addr[:34]:<34}  {bal_s:<14}"
            )
            sys.stdout.flush()

        live_results = live_refresh(all_addresses, progress_cb=on_progress)
        sys.stdout.write("\r" + " " * 76 + "\r")
        sys.stdout.flush()

        for key, bal in live_results.items():
            balances[key] = bal
            meta[key] = {
                "checked_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "live": True,
                "ts": time.time(),
            }
            live_checked += 1
            if bal is None:
                live_failed += 1

        # Only count / record hits for wallet-owned addresses
        wallet_bals = {k: balances.get(k) for k in all_addresses}
        record_hits(wallet_bals)

    # TRUTH totals: only addresses that belong to reconstructed wallets
    wallet_keys = set(all_addresses)
    nonzero = [
        k
        for k in wallet_keys
        if isinstance(balances.get(k), (int, float)) and balances.get(k) > 0
    ]
    total_balance = sum(float(balances[k]) for k in nonzero)
    pending = sum(1 for k in wallet_keys if balances.get(k) is None)
    elapsed = time.time() - refresh_started

    # Freshest checked_at among wallet addresses
    newest = None
    for k in wallet_keys:
        m = meta.get(k) or {}
        ca = m.get("checked_at")
        if ca and (newest is None or ca > newest):
            newest = ca

    clear_screen()
    mode = f"{GREEN}LIVE RPC{RESET}" if live else f"{YELLOW}CACHE ONLY{RESET}"
    print("=" * 76)
    print(" " * 18 + f"{BOLD}WALLET BALANCE VIEWER — {mode}{RESET}")
    print("=" * 76)
    print()
    print(f"  Wallets reconstructed:  {len(wallets)}")
    print(f"  Unique addresses:       {len(all_addresses)}")
    print(f"  Addresses with balance: {len(nonzero)}")
    print(f"  Pending / failed RPC:   {pending}")
    print(f"  Total nonzero balance:  {GREEN}{total_balance:,.8f}{RESET}")
    print(
        f"  Updated:                {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    if newest:
        print(f"  Last on-chain check:    {newest}")
    if live:
        print(
            f"  Live refresh:           {live_checked} addr in {elapsed:.1f}s"
            + (f" ({live_failed} still pending)" if live_failed else "")
        )
    if status_line:
        print(f"  {DIM}{status_line}{RESET}")
    print()

    if not wallets:
        print("  No wallet data yet. Waiting for crypto_scanner.py to process keys...")
        print()
        print("-" * 76)
        print("Press Ctrl+C to exit.")
        return {
            "wallets": 0,
            "nonzero": 0,
            "total": 0.0,
            "pending": 0,
        }

    for w in wallets:
        print("-" * 76)
        print(f"  TYPE: {w['type']}")
        print(f"  KEY:  {w['key']}")
        print()
        print(f"  {'CHAIN':>8}  {'ADDRESS':<50}  {'BALANCE':>12}")
        print(f"  {'-' * 8}  {'-' * 50}  {'-' * 12}")

        for (chain, addr), _info in sorted(w["addresses"].items()):
            bal = balances.get((chain, addr), None)
            marker = (
                f"{GREEN}*** {RESET}"
                if isinstance(bal, (int, float)) and bal > 0
                else "    "
            )
            print(
                f"{marker}{chain.upper():>8}  {addr:<50}  {format_balance(bal):>12}"
            )
        print()

    print("-" * 76)
    print(
        f"  Totals above count ONLY wallet-derived addresses "
        f"({len(wallet_keys)}), never unrelated cache rows."
    )
    print("Press Ctrl+C to exit.")
    return {
        "wallets": len(wallets),
        "nonzero": len(nonzero),
        "total": total_balance,
        "pending": pending,
    }


def main():
    parser = argparse.ArgumentParser(description="Live wallet balance viewer")
    parser.add_argument(
        "--watch", "-w", action="store_true", help="refresh continuously"
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"watch refresh interval seconds (default {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--cached",
        action="store_true",
        help="display cache only (skip live RPC force-refresh)",
    )
    args = parser.parse_args()
    live = not args.cached

    if not args.watch:
        render(live=live)
        return

    try:
        cycle = 0
        while True:
            cycle += 1
            status = f"watch cycle #{cycle} · next refresh in {args.interval}s"
            render(live=live, status_line=status)
            # Sleep in 1s slices so Ctrl+C is snappy
            remaining = max(1, int(args.interval))
            while remaining > 0:
                time.sleep(1)
                remaining -= 1
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
