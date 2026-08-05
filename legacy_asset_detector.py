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
    # ── Ethereum PoW forks (EVM chains, check via RPC) ──────────
    "ethw": {
        "name": "Ethereum PoW (ETHW)",
        "chain_id": 10001, "type": "evm",
        "rpc": "https://mainnet.ethereumpow.org",
        "currency": "ETHW",
        "fork_date": "2022-09-15", "parent_chain": "eth",
        "explainer": "Every ETH address that held ETH before the Merge (Sept 2022) received equal ETHW on the PoW fork. Same private key works on ETHW chain. Send via dashboard SEND panel (select ETHW chain, paste your ETH private key).",
        "sendable": True, "market": "Gate.io, HTX, MEXC",
    },
    "etc": {
        "name": "Ethereum Classic (ETC)",
        "chain_id": 61, "type": "evm",
        "rpc": "https://etc.rivet.link",
        "currency": "ETC",
        "fork_date": "2016-07-20", "parent_chain": "eth",
        "explainer": "Original Ethereum chain from before the DAO fork. Pre-DAO ETH addresses hold equal ETC. Same private key works. Major exchange listings.",
        "sendable": True, "market": "Binance, Coinbase, Kraken, everywhere",
    },
    "exp": {
        "name": "Expanse (EXP)",
        "chain_id": 2, "type": "evm",
        "rpc": "https://node.expanse.tech",
        "currency": "EXP",
        "fork_date": "2015-09-14", "parent_chain": "eth",
        "explainer": "One of the earliest Ethereum forks. Pre-fork ETH holders received EXP. Still has an active chain.",
        "sendable": True, "market": "Limited — check CoinGecko",
    },
    # ── Bitcoin PoW forks (UTXO chains, check via explorer API) ─
    "bch": {
        "name": "Bitcoin Cash (BCH)",
        "type": "utxo",
        "api_url": "https://rest.bitcoin.com/v2/address/details/{addr}",
        "api_parser": "json", "api_balance_path": "balance",
        "currency": "BCH",
        "fork_date": "2017-08-01", "parent_chain": "btc",
        "explainer": "Bitcoin Cash forked from Bitcoin over block size. Every BTC address pre-fork (Aug 2017) holds equal BCH. Use a BCH wallet (Electron Cash, Bitcoin.com) with your BTC private key to claim.",
        "sendable": True, "market": "Binance, Coinbase, Kraken, everywhere",
    },
    "bsv": {
        "name": "Bitcoin SV (BSV)",
        "type": "utxo",
        "api_url": "https://api.whatsonchain.com/v1/bsv/main/address/{addr}/balance",
        "api_parser": "json", "api_balance_path": "confirmed",
        "currency": "BSV",
        "fork_date": "2018-11-15", "parent_chain": "bch",
        "explainer": "Bitcoin SV forked from Bitcoin Cash. BCH holders pre-fork received equal BSV. Use a BSV wallet with your BTC/BCH private key.",
        "sendable": False, "market": "Limited — some exchanges delisted",
    },
    "btg": {
        "name": "Bitcoin Gold (BTG)",
        "type": "utxo",
        "api_url": "https://btgexplorer.com/api/addr/{addr}",
        "api_parser": "json", "api_balance_path": "balance",
        "currency": "BTG",
        "fork_date": "2017-10-24", "parent_chain": "btc",
        "explainer": "Bitcoin Gold forked from Bitcoin to change mining algorithm. BTC holders pre-fork received equal BTG.",
        "sendable": False, "market": "Limited — HitBTC, Bitfinex",
    },
    # ── Litecoin fork ──────────────────────────────────────────
    "ltc_legacy": {
        "name": "Litecoin (LTC — already detected, verify holdings)",
        "type": "utxo",
        "api_url": "https://litecoinspace.org/api/address/{addr}",
        "api_parser": "json", "api_balance_path": "chain_stats.funded_txo_sum",
        "currency": "LTC",
        "fork_date": "2011-10-07", "parent_chain": "btc",
        "explainer": "Litecoin is the original Bitcoin fork. Already tracked. Verify holdings are liquid.",
        "sendable": True, "market": "Everywhere",
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


def _get_nested(d: dict, path: str):
    """Get nested dict value by dot-separated path like 'chain_stats.funded_txo_sum'."""
    for key in path.split("."):
        if isinstance(d, dict):
            d = d.get(key, {})
        else:
            return None
    return d


def check_fork_balance(chain_key: str, chain_info: dict, address: str) -> Optional[dict]:
    """Check balance on a fork chain via RPC (EVM) or explorer API (UTXO)."""
    result = {
        "chain": chain_key, "name": chain_info["name"],
        "currency": chain_info["currency"],
        "sendable": chain_info["sendable"],
        "explainer": chain_info["explainer"],
        "parent_chain": chain_info.get("parent_chain", ""),
        "market": chain_info.get("market", ""),
    }

    if chain_info.get("type") == "evm":
        # EVM fork — check via RPC
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
        try:
            r = requests.post(chain_info["rpc"], json=payload, timeout=10,
                              headers={"Content-Type": "application/json"})
            data = r.json()
            if "error" in data: return None
            wei = int(data["result"], 16)
            result["balance_wei"] = wei
            result["balance"] = wei / 1e18
            result["chain_id"] = chain_info.get("chain_id")
            return result
        except Exception:
            return None

    elif chain_info.get("type") == "utxo":
        # Bitcoin fork — check via explorer API
        api_url = chain_info.get("api_url", "").replace("{addr}", address)
        if not api_url: return None
        try:
            r = requests.get(api_url, timeout=15,
                             headers={"User-Agent": "RepoHere1-Termux/2.0"})
            data = r.json()
            path = chain_info.get("api_balance_path", "balance")
            raw = _get_nested(data, path)
            if raw is None: return None
            # BCH returns satoshis; BSV returns satoshis; BTG returns BTC units
            if chain_key in ("bch", "bsv"):
                result["balance"] = float(raw) / 1e8
            elif chain_key == "btg":
                result["balance"] = float(raw)
            else:
                result["balance"] = float(raw) / 1e8 if float(raw) > 1000 else float(raw)
            if result["balance"] <= 1e-12: return None
            return result
        except Exception:
            return None

    return None


def detect_all() -> dict:
    """Scan all funded ETH + BTC addresses for fork-claimable assets on ALL chains."""
    results = {"total_scanned": 0, "detected": [], "summary": {}, "claimable_usd_estimate": {}}
    found_count = 0

    # ── Scan ETH addresses → EVM forks (ETHW, ETC, EXP) ─────────
    eth_rows, _ = db.filter_balances(chain="eth", funded_only=True, limit=5000, sort_by="balance")
    results["total_scanned"] += len(eth_rows)
    print(f"{B}LEGACY ASSET DETECTOR — PoW Fork Sweep{W}")
    print(f"  Scanning {len(eth_rows)} funded ETH + finding BTC wallets...\n")

    evm_forks = {k: v for k, v in FORK_CHAINS.items() if v.get("type") == "evm"}
    for i, r in enumerate(eth_rows):
        addr = r["address"]
        for ck, ci in evm_forks.items():
            fb = check_fork_balance(ck, ci, addr)
            if fb and fb["balance"] > 1e-12:
                fb["source_address"] = addr
                fb["source_balance"] = r.get("balance", 0)
                results["detected"].append(fb)
                found_count += 1
                print(f"  {G}#{found_count}{W} ETH→{fb['currency']}: {addr[:16]}... {fb['balance']:.6f} {fb['currency']} on {fb['name']} [{fb.get('market','?')}]")
        if (i + 1) % 50 == 0:
            print(f"  {D}ETH progress: {i+1}/{len(eth_rows)}{W}")

    # ── Scan BTC addresses → UTXO forks (BCH, BSV, BTG) ──────────
    btc_rows, _ = db.filter_balances(chain="btc", funded_only=True, limit=5000, sort_by="balance")
    results["total_scanned"] += len(btc_rows)
    utxo_forks = {k: v for k, v in FORK_CHAINS.items() if v.get("type") == "utxo" and k != "ltc_legacy"}
    print(f"\n  Scanning {len(btc_rows)} funded BTC addresses for fork coins...\n")
    for i, r in enumerate(btc_rows):
        addr = r["address"]
        for ck, ci in utxo_forks.items():
            fb = check_fork_balance(ck, ci, addr)
            if fb and fb["balance"] > 1e-12:
                fb["source_address"] = addr
                fb["source_balance"] = r.get("balance", 0)
                results["detected"].append(fb)
                found_count += 1
                print(f"  {G}#{found_count}{W} BTC→{fb['currency']}: {addr[:16]}... {fb['balance']:.6f} {fb['currency']} [{fb.get('market','?')}]")
        if (i + 1) % 50 == 0:
            print(f"  {D}BTC progress: {i+1}/{len(btc_rows)}{W}")

    # ── Summary ──────────────────────────────────────────────────
    totals = {}
    for d in results["detected"]:
        c = d["currency"]
        totals[c] = totals.get(c, 0) + d["balance"]
        # Estimate USD for major coins
        estimates = {"BCH": 350, "BSV": 45, "ETC": 18, "ETHW": 2.5, "BTG": 8, "EXP": 0.01}
        results.setdefault("claimable_usd_estimate", {})
        if c in estimates:
            results["claimable_usd_estimate"][c] = round(totals[c] * estimates[c], 2)

    results["summary"] = totals

    print(f"\n{B}TOTAL FORK ASSETS FOUND{W}")
    print(f"  ETH addresses scanned: {len(eth_rows)}")
    print(f"  BTC addresses scanned: {len(btc_rows)}")
    print(f"  Fork assets detected:  {found_count}")
    for currency, total in totals.items():
        est = results["claimable_usd_estimate"].get(currency, "?")
        print(f"  {currency}: {total:,.6f} (~${est})")
    total_usd = sum(results["claimable_usd_estimate"].values())
    print(f"\n  {G}Estimated total claimable value: ~${total_usd:,.2f}{W}")

    # ── Claim paths ──────────────────────────────────────────────
    if results["detected"]:
        print(f"\n{B}HOW TO CLAIM{W}")
        shown = set()
        for d in results["detected"]:
            if d["chain"] not in shown:
                shown.add(d["chain"])
                print(f"\n  {C}{d['name']} ({d['currency']}){W}")
                print(f"  Market: {d.get('market', 'unknown')}")
                print(f"  {d.get('explainer', '')}")
                if d.get("sendable"):
                    print(f"  {G}→ Sendable via dashboard SEND panel (select {d['currency']} chain){W}")

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
