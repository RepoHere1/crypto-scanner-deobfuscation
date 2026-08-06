#!/usr/bin/env python3
"""
abandoned_coin_scanner.py — Find forgotten wealth in abandoned PoW fork chains.

Philosophy:
  Every major crypto fork created coins that most people forgot about.
  If you held ETH pre-Merge, you have ETHW. If you held BTC during any
  of the 40+ Bitcoin forks, you have fork coins sitting in wallets you
  already own the keys for. This scanner finds ALL of them.

Supported fork families:
  - Ethereum forks: ETHW, ETC, CLO, UBQ, ESN, ELLA, MIX, EGEM, PIRL, MINTME + more
  - Bitcoin forks: BCH, BSV, BTG, BCD, SBTC, BTCP, BCA, BTCZ, LBTC, BTX, BTF, BCX + more
  - Monero forks: XMV, XMC
  - Zcash forks: ZCL, ZEN
  - Litecoin forks: LCC (Litecoin Cash)
  - Dash forks: SAFE

Usage:
    python3 abandoned_coin_scanner.py              # scan all funded ETH+BT C wallets for fork coins
    python3 abandoned_coin_scanner.py --address 0x.. --chain eth  # check single address
    python3 abandoned_coin_scanner.py --json         # JSON output for walletx /api/legacy
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

import requests
import balance_db as db

# ═══════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE FORK CHAIN DATABASE
# ═══════════════════════════════════════════════════════════════════════════

FORK_CHAINS: dict[str, dict] = {
    # ── Ethereum PoW / old-code forks ──────────────────────────────
    "ethw": {
        "name": "Ethereum PoW (ETHW)", "family": "ethereum",
        "chain_id": 10001, "type": "evm",
        "rpc": "https://mainnet.ethereumpow.org",
        "currency": "ETHW", "fork_date": "2022-09-15",
        "market": "Gate.io, HTX, MEXC",
        "sendable": True,
    },
    "etc": {
        "name": "Ethereum Classic (ETC)", "family": "ethereum",
        "chain_id": 61, "type": "evm",
        "rpc": "https://etc.rivet.link",
        "currency": "ETC", "fork_date": "2016-07-20",
        "market": "Binance, Coinbase, Kraken",
        "sendable": True,
    },
    "clo": {
        "name": "Callisto (CLO)", "family": "ethereum",
        "chain_id": 820, "type": "evm",
        "rpc": "https://clo-geth.0xinfra.com",
        "currency": "CLO", "fork_date": "2018-03-05",
        "market": "STEX, BitForex",
        "sendable": True,
    },
    "ubq": {
        "name": "Ubiq (UBQ)", "family": "ethereum",
        "chain_id": 8, "type": "evm",
        "rpc": "https://rpc.ubiqscan.io",
        "currency": "UBQ", "fork_date": "2017-01-28",
        "market": "Bittrex, Upbit",
        "sendable": True,
    },
    "esn": {
        "name": "Ethersocial (ESN)", "family": "ethereum",
        "chain_id": 31102, "type": "evm",
        "rpc": "https://api.esn.gonspool.com",
        "currency": "ESN", "fork_date": "2018-04-15",
        "market": "Delisted most exchanges",
        "sendable": False,
    },
    "ella": {
        "name": "Ellaism (ELLA)", "family": "ethereum",
        "chain_id": 64, "type": "evm",
        "rpc": "https://jsonrpc.ellaism.org",
        "currency": "ELLA", "fork_date": "2017-09-11",
        "market": "Limited",
        "sendable": False,
    },
    "mix": {
        "name": "MixMarvel (MIX)", "family": "ethereum",
        "chain_id": 76, "type": "evm",
        "rpc": "https://rpc.miexs.com",
        "currency": "MIX", "fork_date": "2019-01-15",
        "market": "Gate.io, MEXC",
        "sendable": False,
    },
    "egem": {
        "name": "EtherGem (EGEM)", "family": "ethereum",
        "chain_id": 1987, "type": "evm",
        "rpc": "https://jsonrpc.egem.io",
        "currency": "EGEM", "fork_date": "2018-06-01",
        "market": "Limited - Graviex",
        "sendable": False,
    },
    "pirl": {
        "name": "Pirl (PIRL)", "family": "ethereum",
        "chain_id": 164, "type": "evm",
        "rpc": "https://wallrpc.pirl.io",
        "currency": "PIRL", "fork_date": "2017-09-01",
        "market": "Limited",
        "sendable": False,
    },
    "mintme": {
        "name": "MintMe Coin (MINTME)", "family": "ethereum",
        "chain_id": 24734, "type": "evm",
        "rpc": "https://node1.mintme.com",
        "currency": "MINTME", "fork_date": "2021-03-01",
        "market": "MintMe.com",
        "sendable": True,
    },
    "exp": {
        "name": "Expanse (EXP)", "family": "ethereum",
        "chain_id": 2, "type": "evm",
        "rpc": "https://node.expanse.tech",
        "currency": "EXP", "fork_date": "2015-09-14",
        "market": "Limited",
        "sendable": True,
    },

    # ── Bitcoin forks ─────────────────────────────────────────────
    "bch": {
        "name": "Bitcoin Cash (BCH)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://rest.bitcoin.com/v2/address/details/{addr}",
        "api_balance_path": "balance",
        "currency": "BCH", "fork_date": "2017-08-01",
        "market": "Binance, Coinbase, Kraken",
        "sendable": True, "claim_wallet": "Electron Cash",
    },
    "bsv": {
        "name": "Bitcoin SV (BSV)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://api.whatsonchain.com/v1/bsv/main/address/{addr}/balance",
        "api_balance_path": "confirmed",
        "currency": "BSV", "fork_date": "2018-11-15",
        "market": "Limited - some exchanges delisted",
        "sendable": True, "claim_wallet": "Electrum SV",
    },
    "btg": {
        "name": "Bitcoin Gold (BTG)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://btgexplorer.com/api/addr/{addr}",
        "api_balance_path": "balance",
        "currency": "BTG", "fork_date": "2017-10-24",
        "market": "HitBTC, Bitfinex",
        "sendable": False, "claim_wallet": "BTG Core",
    },
    "bcd": {
        "name": "Bitcoin Diamond (BCD)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://explorer.btcd.io/api/addr/{addr}",
        "api_balance_path": "balance",
        "currency": "BCD", "fork_date": "2017-11-24",
        "market": "Gate.io, HitBTC",
        "sendable": False, "claim_wallet": "BCD Core",
    },
    "sbtc": {
        "name": "Super Bitcoin (SBTC)", "family": "bitcoin",
        "type": "utxo",
        "api_url": None,  # Explorer down
        "currency": "SBTC", "fork_date": "2017-12-12",
        "market": "Dead - no market",
        "sendable": False,
    },
    "btcp": {
        "name": "Bitcoin Private (BTCP)", "family": "bitcoin",
        "type": "utxo",
        "api_url": None,
        "currency": "BTCP", "fork_date": "2018-02-28",
        "market": "TradeOgre",
        "sendable": False,
    },
    "bca": {
        "name": "Bitcoin Atom (BCA)", "family": "bitcoin",
        "type": "utxo",
        "api_url": None,
        "currency": "BCA", "fork_date": "2018-01-24",
        "market": "Dead",
        "sendable": False,
    },
    "btcz": {
        "name": "BitcoinZ (BTCZ)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://explorer.btcz.rocks/api/addr/{addr}",
        "api_balance_path": "balance",
        "currency": "BTCZ", "fork_date": "2017-09-09",
        "market": "STEX, Graviex",
        "sendable": False,
    },
    "lbtc": {
        "name": "Lightning Bitcoin (LBTC)", "family": "bitcoin",
        "type": "utxo",
        "api_url": None,
        "currency": "LBTC", "fork_date": "2017-12-23",
        "market": "Dead",
        "sendable": False,
    },
    "btf": {
        "name": "Bitcoin Faith (BTF)", "family": "bitcoin",
        "type": "utxo",
        "api_url": None,
        "currency": "BTF", "fork_date": "2017-12-21",
        "market": "Dead",
        "sendable": False,
    },
    "btx": {
        "name": "Bitcore (BTX)", "family": "bitcoin",
        "type": "utxo",
        "api_url": "https://chainz.cryptoid.info/btx/api.dws?q=getbalance&a={addr}",
        "api_balance_path": None,  # Returns plain number
        "currency": "BTX", "fork_date": "2017-04-24",
        "market": "Limited",
        "sendable": False,
    },

    # ── Litecoin fork ─────────────────────────────────────────────
    "lcc": {
        "name": "Litecoin Cash (LCC)", "family": "litecoin",
        "type": "utxo",
        "api_url": "https://chainz.cryptoid.info/lcc/api.dws?q=getbalance&a={addr}",
        "api_balance_path": None,
        "currency": "LCC", "fork_date": "2018-02-18",
        "market": "Limited",
        "sendable": False, "claim_wallet": "LCC Core",
    },

    # ── Monero forks ──────────────────────────────────────────────
    "xmv": {
        "name": "MoneroV (XMV)", "family": "monero",
        "type": "cryptonote",
        "api_url": None,
        "currency": "XMV", "fork_date": "2018-04-30",
        "market": "HitBTC, Exrates",
        "sendable": False,
    },
    "xmc": {
        "name": "Monero Classic (XMC)", "family": "monero",
        "type": "cryptonote",
        "api_url": None,
        "currency": "XMC", "fork_date": "2018-04-06",
        "market": "HitBTC",
        "sendable": False,
    },

    # ── Zcash forks ───────────────────────────────────────────────
    "zcl": {
        "name": "Zclassic (ZCL)", "family": "zcash",
        "type": "utxo",
        "api_url": "https://chainz.cryptoid.info/zcl/api.dws?q=getbalance&a={addr}",
        "api_balance_path": None,
        "currency": "ZCL", "fork_date": "2016-11-01",
        "market": "TradeOgre",
        "sendable": False,
    },
    "zen": {
        "name": "Horizen (ZEN)", "family": "zcash",
        "type": "utxo",
        "api_url": "https://explorer.horizen.io/api/addr/{addr}",
        "api_balance_path": "balance",
        "currency": "ZEN", "fork_date": "2017-05-30",
        "market": "Binance, Coinbase (~$8-15 each)",
        "sendable": True,
    },
}

# ── Which forks apply to which parent chains ─────────────────────────────
FORK_FAMILIES = {
    "eth": ["ethw", "etc", "clo", "ubq", "esn", "ella", "mix", "egem", "pirl", "mintme", "exp"],
    "btc": ["bch", "bsv", "btg", "bcd", "sbtc", "btcp", "bca", "btcz", "lbtc", "btf", "btx"],
    "ltc": ["lcc"],
    "xmr": ["xmv", "xmc"],
    "zec": ["zcl", "zen"],
}

# Price estimates (USD) for major fork coins - rough estimates
PRICE_ESTIMATES = {
    "BCH": 350, "BSV": 45, "ETC": 18, "ETHW": 2.5, "BTG": 8, "ZEN": 8,
    "BCD": 0.05, "BTCP": 0.10, "CLO": 0.001, "UBQ": 0.02, "EXP": 0.005,
    "XMV": 0.003, "XMC": 0.15, "ZCL": 0.05, "LCC": 0.002,
}

# ── Color helpers ─────────────────────────────────────────────────────────
B = "\033[1m"; D = "\033[2m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; R = "\033[91m"; W = "\033[0m"; M = "\033[95m"

# ═══════════════════════════════════════════════════════════════════════════
# BALANCE CHECK ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def _check_evm_fork(info: dict, address: str) -> dict | None:
    """Check balance on an EVM fork chain via RPC."""
    rpc = info.get("rpc")
    if not rpc:
        return None
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    try:
        r = requests.post(rpc, json=payload, timeout=10,
                          headers={"Content-Type": "application/json"})
        data = r.json()
        if "error" in data:
            return None
        wei = int(data["result"], 16)
        bal = wei / 1e18
        if bal <= 1e-12:
            return None
        return {
            "chain_key": info.get("currency", "?").lower(),
            "name": info["name"], "currency": info["currency"],
            "balance": bal, "chain_id": info.get("chain_id"),
            "market": info.get("market", ""),
            "sendable": info.get("sendable", False),
        }
    except Exception:
        return None


def _check_utxo_fork(info: dict, address: str) -> dict | None:
    """Check balance on a UTXO fork chain via explorer API."""
    api_url = info.get("api_url", "").replace("{addr}", address)
    if not api_url:
        return None
    try:
        r = requests.get(api_url, timeout=15,
                         headers={"User-Agent": "WalletX-AbandonedScanner/2.0"})
        path = info.get("api_balance_path")
        if path is None:
            # Plain number response
            bal = float(r.text.strip() or 0)
        else:
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            # Walk nested path
            for key in path.split("."):
                if isinstance(data, dict):
                    data = data.get(key, {})
                else:
                    return None
            bal = float(data or 0)

        # Convert to native units (UTXO APIs often return satoshis or base units)
        if bal > 10000:
            bal = bal / 1e8  # assume satoshis

        if bal <= 1e-12:
            return None

        return {
            "chain_key": info.get("currency", "?").lower(),
            "name": info["name"], "currency": info["currency"],
            "balance": bal,
            "market": info.get("market", ""),
            "sendable": info.get("sendable", False),
            "claim_wallet": info.get("claim_wallet", ""),
        }
    except Exception:
        return None


def check_fork_balance(fork_key: str, address: str) -> dict | None:
    """Check a single fork chain for balance at an address."""
    info = FORK_CHAINS.get(fork_key)
    if not info:
        return None

    if info.get("type") == "evm":
        return _check_evm_fork(info, address)
    elif info.get("type") == "utxo":
        return _check_utxo_fork(info, address)
    elif info.get("type") == "cryptonote":
        # Monero forks: explorer APIs are unreliable, flag manually
        return {
            "chain_key": fork_key,
            "name": info["name"], "currency": info["currency"],
            "balance": 0,
            "market": info.get("market", ""),
            "sendable": False,
            "needs_manual_check": True,
            "explainer": f"Monero fork explorers are unreliable. Import your XMR keys into {info['name']} wallet to check manually.",
        }

    return None


def scan_address(chain: str, address: str) -> list[dict]:
    """Scan one address for ALL applicable fork coins."""
    chain = chain.lower()
    fork_keys = FORK_FAMILIES.get(chain, [])
    if chain == "eth":
        fork_keys = FORK_FAMILIES["eth"]
    elif chain == "btc":
        fork_keys = FORK_FAMILIES["btc"]

    findings = []
    for fk in fork_keys:
        result = check_fork_balance(fk, address)
        if result:
            result["source_chain"] = chain
            result["source_address"] = address
            findings.append(result)

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# FULL SCAN — ALL FUNDED WALLETS
# ═══════════════════════════════════════════════════════════════════════════

def scan_all_funded(max_per_chain: int = 2000) -> dict:
    """Scan all funded ETH and BTC wallets for fork claimable assets."""
    results = {
        "total_scanned": 0,
        "detected": [],
        "by_currency": {},
        "estimated_usd_total": 0.0,
    }

    total_found = 0
    eth_est = 0.0
    btc_est = 0.0

    # ── Scan ETH addresses → all Ethereum forks ──────────────────────
    try:
        eth_rows, _ = db.filter_balances(
            chain="eth", funded_only=True, limit=max_per_chain, sort_by="balance")
    except Exception:
        eth_rows = []
    results["total_scanned"] += len(eth_rows)

    print(f"\n{B}{'='*60}{W}")
    print(f"{B}ABANDONED COIN SCANNER — PoW Fork Sweep{W}")
    print(f"{D}Scanning {len(eth_rows)} ETH wallets → {len(FORK_FAMILIES['eth'])} forks each{W}")
    print(f"{B}{'='*60}{W}\n")

    eth_forks = [f for f in FORK_FAMILIES["eth"] if FORK_CHAINS.get(f, {}).get("type") == "evm"]
    for i, row in enumerate(eth_rows):
        addr = row["address"]
        for fk in eth_forks:
            fb = check_fork_balance(fk, addr)
            if fb:
                total_found += 1
                fb["source_balance"] = row.get("balance", 0)
                results["detected"].append(fb)
                curr = fb["currency"]
                results["by_currency"][curr] = results["by_currency"].get(curr, 0) + fb["balance"]
                est = PRICE_ESTIMATES.get(curr, 0) * fb["balance"]
                eth_est += est
                print(f"  {G}#{total_found}{W} ETH→{fb['currency']}: {addr[:18]}... "
                      f"{fb['balance']:.6f} {fb['currency']} "
                      f"~${est:.2f} [{fb.get('market','?')}]")
        if (i + 1) % 100 == 0:
            print(f"  {D}ETH: {i+1}/{len(eth_rows)}{W}")

    # ── Scan BTC addresses → all Bitcoin forks ───────────────────────
    try:
        btc_rows, _ = db.filter_balances(
            chain="btc", funded_only=True, limit=max_per_chain, sort_by="balance")
    except Exception:
        btc_rows = []
    results["total_scanned"] += len(btc_rows)

    print(f"\n  Scanning {len(btc_rows)} BTC wallets → {len(FORK_FAMILIES['btc'])} forks each\n")

    btc_forks = [f for f in FORK_FAMILIES["btc"] if FORK_CHAINS.get(f, {}).get("type") == "utxo"]
    for i, row in enumerate(btc_rows):
        addr = row["address"]
        for fk in btc_forks:
            fb = check_fork_balance(fk, addr)
            if fb:
                total_found += 1
                fb["source_balance"] = row.get("balance", 0)
                results["detected"].append(fb)
                curr = fb["currency"]
                results["by_currency"][curr] = results["by_currency"].get(curr, 0) + fb["balance"]
                est = PRICE_ESTIMATES.get(curr, 0) * fb["balance"]
                btc_est += est
                print(f"  {G}#{total_found}{W} BTC→{fb['currency']}: {addr[:18]}... "
                      f"{fb['balance']:.6f} {fb['currency']} "
                      f"~${est:.2f} [{fb.get('market','?')}]")
        if (i + 1) % 100 == 0:
            print(f"  {D}BTC: {i+1}/{len(btc_rows)}{W}")

    results["estimated_usd_total"] = round(eth_est + btc_est, 2)

    # ── Summary ──────────────────────────────────────────────────────
    print(f"\n{B}{'='*60}{W}")
    print(f"{B}ABANDONED COIN SUMMARY{W}")
    print(f"{'='*60}")
    print(f"  ETH wallets scanned:  {len(eth_rows)}")
    print(f"  BTC wallets scanned:  {len(btc_rows)}")
    print(f"  Fork assets found:    {total_found}")
    print(f"  Estimated ETH forks:  ${eth_est:,.2f}")
    print(f"  Estimated BTC forks:  ${btc_est:,.2f}")
    print(f"  {G}Total estimated:      ${results['estimated_usd_total']:,.2f}{W}")
    print(f"{'='*60}\n")

    if results["detected"]:
        print(f"{B}HOW TO CLAIM{W}")
        shown = set()
        for d in results["detected"]:
            ck = d.get("chain_key", "")
            if ck not in shown:
                shown.add(ck)
                info = FORK_CHAINS.get(ck, {})
                cw = info.get("claim_wallet", "")
                cw_str = f" — use {cw}" if cw else ""
                print(f"\n  {C}{d['name']} ({d['currency']}){W}{cw_str}")
                print(f"  Market: {d.get('market', 'unknown')}")
                if d.get("sendable"):
                    print(f"  {G}→ Can send via WalletX dashboard SEND panel{W}")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Abandoned Coin Scanner — find forgotten wealth in PoW fork chains")
    ap.add_argument("--address", type=str, help="Check a single address")
    ap.add_argument("--chain", type=str, default="eth",
                    help="Parent chain of the address (eth/btc/ltc)")
    ap.add_argument("--max", type=int, default=2000,
                    help="Max wallets to scan per chain (full scan mode)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    if args.address:
        findings = scan_address(args.chain, args.address)
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                print(f"{Y}No fork assets found for {args.address}{W}")
            for f in findings:
                est = PRICE_ESTIMATES.get(f["currency"], 0) * f["balance"]
                print(f"{G}{f['name']}:{W} {f['balance']:.6f} {f['currency']} "
                      f"~${est:.2f} [{f.get('market','?')}]")
    else:
        # Full scan mode
        results = scan_all_funded(max_per_chain=args.max)
        if args.json:
            print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
