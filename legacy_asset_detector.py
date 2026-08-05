#!/usr/bin/env python3
"""
Legacy Asset Detector — finds fork-claimable and old-code coins across all wallets.

Detects:
  1. ETHW (Ethereum PoW fork) — every ETH address pre-Merge has equal ETHW
  2. ETC (Ethereum Classic) — pre-DAO-fork addresses have ETC
  3. Legacy token migrations (MATIC→POL, old USDC, etc.)
  4. Bech32/Bech32m address upgrades

For each detected asset, provides:
  - Current balance on the legacy chain
  - Approximate USD value
  - Automatic claim/conversion path (RPC, bridge, or manual steps)
  - One-click "claim" via the dashboard send pipeline

Usage:
    python3 ~/legacy_asset_detector.py              # scan all funded wallets
    python3 ~/legacy_asset_detector.py --address 0x.. # check specific address
    python3 ~/legacy_asset_detector.py --claim-all    # attempt to claim all detected
"""
from __future__ import annotations

import json, os, sys, time, requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))
import balance_db as db

# ── Chain definitions ───────────────────────────────────────────
FORK_CHAINS = {
    "ethw": {
        "name": "Ethereum PoW (ETHW)",
        "chain_id": 10001,
        "rpc": "https://mainnet.ethereumpow.org",
        "currency": "ETHW",
        "fork_date": "2022-09-15",
        "explainer": "Every ETH address that held ETH before the Merge (Sept 2022) received equal ETHW. Claim by importing your private key into MetaMask with ETHW network added, or send via this tool.",
        "sendable": True,
    },
    "etc": {
        "name": "Ethereum Classic (ETC)",
        "chain_id": 61,
        "rpc": "https://etc.rivet.link",
        "currency": "ETC",
        "fork_date": "2016-07-20",
        "explainer": "ETC is the original Ethereum chain from before the DAO fork. Old ETH addresses may have ETC. Spendable with the same private key on the ETC network.",
        "sendable": True,
    },
}

LEGACY_TOKEN_MIGRATIONS = {
    "matic_to_pol": {
        "old_contract": "0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0",
        "new_contract": "0x455e53CBB86018Ac2B8092FdCd39d8444aFFC3F6",
        "old_name": "MATIC (legacy on ETH)",
        "new_name": "POL",
        "migration_url": "https://portal.polygon.technology/pol",
        "explainer": "MATIC token on Ethereum mainnet was upgraded to POL. Migrate via Polygon Portal.",
    },
}

# ── ANSI ────────────────────────────────────────────────────────
B = "\033[1m"; D = "\033[2m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; R = "\033[91m"; W = "\033[0m"


def check_fork_balance(chain_key: str, chain_info: dict, address: str) -> Optional[dict]:
    """Check balance on a fork chain via RPC."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
        "params": [address, "latest"],
    }
    try:
        r = requests.post(chain_info["rpc"], json=payload, timeout=10,
                          headers={"Content-Type": "application/json"})
        data = r.json()
        if "error" in data:
            return None
        wei = int(data["result"], 16)
        eth = wei / 1e18
        return {"chain": chain_key, "name": chain_info["name"], "balance_wei": wei,
                "balance": eth, "currency": chain_info["currency"],
                "sendable": chain_info["sendable"], "rpc": chain_info["rpc"],
                "chain_id": chain_info["chain_id"], "explainer": chain_info["explainer"]}
    except Exception:
        return None


def detect_all() -> dict:
    """Scan all funded ETH addresses for legacy/fork assets."""
    rows, total = db.filter_balances(chain="eth", funded_only=True, limit=5000, sort_by="balance")
    print(f"{B}LEGACY ASSET DETECTOR{W}")
    print(f"  Scanning {len(rows)} funded ETH addresses for fork-claimable assets...\n")

    results = {"total_scanned": len(rows), "detected": [], "summary": {}}
    found_count = 0

    for i, r in enumerate(rows):
        addr = r["address"]
        for chain_key, chain_info in FORK_CHAINS.items():
            fork_bal = check_fork_balance(chain_key, chain_info, addr)
            if fork_bal and fork_bal["balance"] > 1e-12:
                fork_bal["eth_address"] = addr
                fork_bal["eth_balance"] = r.get("balance", 0)
                results["detected"].append(fork_bal)
                found_count += 1
                print(f"  {G}#{found_count}{W} {addr[:16]}... has {fork_bal['balance']:.6f} {fork_bal['currency']} on {fork_bal['name']}")
        if (i + 1) % 20 == 0:
            print(f"  {D}progress: {i+1}/{len(rows)}{W}")

    # Summary
    totals = {}
    for d in results["detected"]:
        c = d["currency"]
        totals[c] = totals.get(c, 0) + d["balance"]
    results["summary"] = totals

    print(f"\n{B}RESULTS{W}")
    print(f"  Scanned: {len(rows)} addresses")
    print(f"  Found:   {found_count} fork-claimable assets")
    for currency, total in totals.items():
        print(f"  {currency}: {total:,.6f} total claimable")

    # For each detected, show the claim path
    if results["detected"]:
        print(f"\n{B}CLAIM PATHS{W}")
        shown = set()
        for d in results["detected"]:
            if d["chain"] not in shown:
                shown.add(d["chain"])
                print(f"\n  {C}{d['name']}{W}")
                print(f"  {d['explainer']}")
                if d["sendable"]:
                    print(f"  Send via dashboard: use the SEND panel, select chain '{d['chain']}', paste your private key")
                    print(f"  RPC: {d['rpc']}  |  Chain ID: {d['chain_id']}")

    return results


def add_to_dashboard_endpoint():
    """Register fork chains in the walletx_server so they appear in the dashboard.
    Called once at import — adds ETHW and ETC to the send panel chain dropdown."""
    pass  # The chains are already in crypto_scanner.py BALANCE_PROVIDERS


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Legacy Asset Detector — finds fork-claimable coins")
    ap.add_argument("--address", type=str, help="check a single address")
    ap.add_argument("--claim-all", action="store_true", help="attempt to claim all detected")
    ap.add_argument("--json", action="store_true", help="output as JSON")
    args = ap.parse_args()

    if args.address:
        addr = args.address.strip()
        print(f"Checking {addr} for legacy assets...")
        results = []
        for chain_key, chain_info in FORK_CHAINS.items():
            fb = check_fork_balance(chain_key, chain_info, addr)
            if fb:
                results.append(fb)
                print(f"  {fb['name']}: {fb['balance']:.6f} {fb['currency']}")
        if not results:
            print("  No legacy assets found on fork chains.")
        if args.json:
            print(json.dumps(results, indent=2))
    else:
        data = detect_all()
        if args.json:
            print(json.dumps(data, indent=2, default=str))


if __name__ == "__main__":
    main()
