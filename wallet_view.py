#!/usr/bin/env python3
"""
Wallet Balance Viewer - full wallet picture with keys and derived addresses.

Usage:
    python3 ~/wallet_view.py          # show once
    python3 ~/wallet_view.py --watch  # refresh every 5 seconds
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
MEMORY_FILE = os.path.join(HOME, "crypto_scanner_memory.jsonl")
CACHE_FILE = os.path.join(HOME, "balance_cache.jsonl")
HITS_FILE = os.path.join(HOME, "balances_hit.jsonl")

sys.path.insert(0, HOME)
import crypto_scanner as cs


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
    balances = {}
    for rec in load_records(CACHE_FILE):
        key = (rec.get("chain", "?"), rec.get("address", ""))
        balances[key] = rec.get("balance")
    return balances


def format_balance(bal):
    if bal is None:
        return "PENDING"
    if bal == 0:
        return "0.00000000"
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
        result[(chain, addr)] = {"chain": chain, "address": addr, "from": key_type.lower()}
    return result


def gather_wallets():
    """Group records by private key/seed and collect all derived addresses."""
    wallets = {}
    for rec in load_records(MEMORY_FILE):
        findings = rec.get("findings", {})
        wallet = findings.get("wallet", {})
        derived = findings.get("derived_addresses", [])

        def add_wallet(key_type, key_value):
            if not key_value:
                return
            w = wallets.setdefault((key_type, key_value), {
                "type": key_type,
                "key": key_value,
                "addresses": {},
            })
            for d in derived:
                chain = d.get("chain", "?")
                addr = d.get("address", "")
                if addr:
                    w["addresses"][(chain, addr)] = d

        for wif in wallet.get("wifs", []):
            add_wallet("WIF", wif)
        for hexk in wallet.get("hex_keys", []):
            add_wallet("HEX", hexk)
        for seed in wallet.get("seed_phrases", []):
            add_wallet("SEED", seed)

    # Ensure every wallet shows the latest supported chains.
    for (key_type, key_value), w in wallets.items():
        w["addresses"].update(derive_for_key(key_type, key_value))

    return list(wallets.values())


def render():
    balances = load_balances()
    wallets = gather_wallets()

    all_addresses = set()
    for w in wallets:
        all_addresses.update(w["addresses"].keys())

    nonzero = [k for k, v in balances.items() if v and v > 0]
    total_balance = sum(balances.get(k, 0) or 0 for k in nonzero)

    os.system("clear")
    print("=" * 76)
    print(" " * 22 + "WALLET BALANCE VIEWER")
    print("=" * 76)
    print()
    print(f"  Wallets reconstructed: {len(wallets)}")
    print(f"  Unique addresses:      {len(all_addresses)}")
    print(f"  Addresses with balance: {len(nonzero)}")
    print(f"  Total nonzero balance:  {total_balance:,.8f}")
    print(f"  Updated:                {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()

    if not wallets:
        print("  No wallet data yet. Waiting for crypto_scanner.py to process keys...")
        print()
        print("-" * 76)
        print("Press Ctrl+C to exit.")
        return

    for w in wallets:
        print("-" * 76)
        print(f"  TYPE: {w['type']}")
        print(f"  KEY:  {w['key']}")
        print()
        print(f"  {'CHAIN':>8}  {'ADDRESS':<50}  {'BALANCE':>12}")
        print(f"  {'-'*8}  {'-'*50}  {'-'*12}")

        for (chain, addr), info in sorted(w["addresses"].items()):
            bal = balances.get((chain, addr), None)
            marker = "*** " if bal and bal > 0 else "    "
            print(f"{marker}{chain.upper():>8}  {addr:<50}  {format_balance(bal):>12}")
        print()

    print("-" * 76)
    print("Press Ctrl+C to exit.")


def main():
    parser = argparse.ArgumentParser(description="Wallet balance viewer")
    parser.add_argument("--watch", "-w", action="store_true", help="refresh every 5 seconds")
    args = parser.parse_args()

    try:
        while True:
            render()
            if not args.watch:
                break
            time.sleep(5)
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
