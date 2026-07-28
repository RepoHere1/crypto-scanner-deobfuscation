#!/usr/bin/env python3
"""
Refresh wallet balances shown by wallet_view.py.

Reads crypto_scanner_memory.jsonl, LIVE force-checks every derived (and directly
detected) address, and writes results to balance_cache.jsonl.
Run this after changing balance providers or when many addresses show PENDING.
"""
import hashlib
import json
import os
import sys
import threading
import time
import itertools

HOME = os.path.expanduser("~")
MEMORY_FILE = os.path.join(HOME, "crypto_scanner_memory.jsonl")
CACHE_FILE = os.path.join(HOME, "balance_cache.jsonl")

sys.path.insert(0, HOME)
import crypto_scanner as cs


class Spinner:
    """Threaded terminal spinner with updatable message."""

    def __init__(self, message: str = "Working"):
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def update(self, message: str):
        self.message = message

    def _spin(self):
        for char in itertools.cycle(["|", "/", "-", "\\"]):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r{self.message} {char}")
            sys.stdout.flush()
            time.sleep(0.12)
        sys.stdout.write(f"\r{self.message} done\n")
        sys.stdout.flush()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *args):
        self._stop.set()
        self._thread.join()


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


def gather_addresses():
    targets = set()
    chains = ("btc", "eth", "ltc", "sol", "doge", "xrp", "ton", "avax", "matic", "bnb", "base", "monad")
    keys = set()
    for rec in load_records(MEMORY_FILE):
        findings = rec.get("findings", {})
        wallet = findings.get("wallet", {})
        for wif in wallet.get("wifs", []):
            keys.add(("WIF", wif))
        for hexk in wallet.get("hex_keys", []):
            keys.add(("HEX", hexk))
        for seed in wallet.get("seed_phrases", []):
            keys.add(("SEED", seed))
        for chain in chains:
            for addr in findings.get(chain, []):
                targets.add((chain, addr))
        for derived in findings.get("derived_addresses", []):
            chain = derived.get("chain", "?")
            addr = derived.get("address", "")
            if addr:
                targets.add((chain, addr))

    # Re-derive the current supported chains for every wallet key so new chains
    # (base, monad, etc.) are checked even if the memory file is old.
    for key_type, key_value in keys:
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
        for chain, addr in addrs.items():
            targets.add((chain, addr))

    return targets


def main():
    targets = gather_addresses()
    if not targets:
        print("No addresses found in memory file yet.")
        return

    total = len(targets)
    checked = 0
    nonzero = 0
    with Spinner(f"Refreshing 0/{total} balances") as sp:
        for chain, addr in sorted(targets):
            checked += 1
            sp.update(f"Refreshing {checked}/{total} balances ({chain})")
            try:
                rec = cs.get_balance(chain, addr, force=True)
                bal = rec.get("balance")
                if bal and bal > 0:
                    nonzero += 1
            except Exception:
                pass
            time.sleep(0.02)

    print(f"[*] Checked {checked} address(es); {nonzero} with non-zero balance.")
    print(f"[*] Cache written to {CACHE_FILE}")


if __name__ == "__main__":
    main()
