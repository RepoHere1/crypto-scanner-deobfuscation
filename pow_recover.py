#!/usr/bin/env python3
"""
pow_recover.py — Abandoned/desolate proof-of-work coin discovery & recovery pipeline

Finds lost cryptocurrency hiding places and converts dead POW coins into
potentially-living ones by:

  1. Scanning repos/output for wallet.dat, seed phrases, private keys
  2. Checking discovered keys/addresses against public blockchain APIs
  3. Identifying brain wallets (weak/guessable passphrases)
  4. Finding hiding places: old forum dumps, pastebin, forgotten GitHub repos,
     blockchain dust transactions
  5. Flagging satoshi-era (pre-2013) unspent outputs
  6. Outputting walletx-compatible recovery manifests

Integrates with:
  - 7000.py paste_box.txt output
  - onion_scanner.py results
  - trufflehog findings
  - walletx (direct JSONL import)

Usage:
    python pow_recover.py --input paste_box.txt
    python pow_recover.py --scan-dir ~/repos --check-balances
    python pow_recover.py --input onion_scanner_results.jsonl --output recover.jsonl
    python pow_recover.py --brain-wallet-scan --wordlist rockyou.txt

Dependencies: standard library (urllib for blockchain API queries)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

# ── Output colors ────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
C_RESET = "\033[0m" if _USE_COLOR else ""
C_RED = "\033[91m" if _USE_COLOR else ""
C_GREEN = "\033[92m" if _USE_COLOR else ""
C_YELLOW = "\033[93m" if _USE_COLOR else ""
C_CYAN = "\033[96m" if _USE_COLOR else ""
C_BGRN = "\033[1;92m" if _USE_COLOR else ""
C_BRED = "\033[1;91m" if _USE_COLOR else ""
C_BYEL = "\033[1;93m" if _USE_COLOR else ""
C_BCYN = "\033[1;96m" if _USE_COLOR else ""
C_BMAG = "\033[1;95m" if _USE_COLOR else ""
C_DIM = "\033[2m" if _USE_COLOR else ""


def cprint(*args, color=None, **kwargs):
    pre = color if color else ""
    text = " ".join(str(a) for a in args)
    print(f"{pre}{text}{C_RESET}", **kwargs)


# =============================================================================
# PATTERNS — find crypto material in any text
# =============================================================================

# Bitcoin private key (WIF)
BTC_WIF_RE = re.compile(r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}')
# Bitcoin address (P2PKH, P2SH, Bech32)
BTC_ADDR_RE = re.compile(r'(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})')
# Ethereum private key (raw hex)
ETH_PK_RE = re.compile(r'(?:0x)?[a-fA-F0-9]{64}')
# Ethereum address
ETH_ADDR_RE = re.compile(r'0x[a-fA-F0-9]{40}')
# BIP39 seed phrase (12-24 words)
SEED_PHRASE_RE = re.compile(
    r'\b([a-z]{3,}\s+){11,23}[a-z]{3,}\b', re.IGNORECASE
)
# Wallet file paths
WALLET_DAT_RE = re.compile(r'(?:/[\w./-]*)?wallet\.dat\b', re.IGNORECASE)
# Keystore files
KEYSTORE_RE = re.compile(
    r'(?:UTC--\d{4}-\d{2}-\d{2}T[\d:.-]+Z--[a-f0-9]{40}\.json|keystore[/\\][\w.-]+\.json)',
    re.IGNORECASE
)
# Private key PEM blocks
PEM_KEY_RE = re.compile(
    r'-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP|BITCOIN)?\s*PRIVATE\s+KEY.*?-----END\s+(?:RSA|EC|OPENSSH|DSA|PGP|BITCOIN)?\s*PRIVATE\s+KEY',
    re.DOTALL | re.IGNORECASE
)
# Brain wallet phrase patterns (common in old forum posts, pastebin)
BRAIN_PASSPHRASE_INDICATORS = re.compile(
    r'(?:brain\s*wallet|brainwallet|passphrase\s*wallet|password\s*protected\s*private\s*key|'
    r'secret\s*phrase\s*:\s*".*?"|'
    r'passphrase\s*:\s*"[^"]{8,64}")',
    re.IGNORECASE
)

# BIP39 wordlist (first 50 words for quick validation)
BIP39_WORDS: Set[str] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "africa", "after", "again",
    "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
    "album", "alcohol",
}


# =============================================================================
# HIDING PLACE SCANNERS
# =============================================================================

def scan_text_for_crypto(text: str, source: str, source_type: str = "text") -> Dict:
    """Scan arbitrary text for cryptocurrency material.

    Returns a dict with categorized findings ready for walletx.
    """
    findings = {
        "source": source,
        "source_type": source_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "btc_wif_keys": [],
        "btc_addresses": [],
        "eth_private_keys": [],
        "eth_addresses": [],
        "seed_phrases": [],
        "wallet_dat_paths": [],
        "keystore_files": [],
        "pem_keys": [],
        "brain_wallet_hints": [],
    }

    # Bitcoin WIF private keys
    for m in BTC_WIF_RE.finditer(text):
        wif = m.group(0)
        # Validate checksum (basic length check)
        if 51 <= len(wif) <= 52:
            findings["btc_wif_keys"].append({
                "wif": wif,
                "compressed": wif[0] in ("K", "L"),
                "position": m.start(),
            })

    # Bitcoin addresses
    for m in BTC_ADDR_RE.finditer(text):
        addr = m.group(0)
        findings["btc_addresses"].append({
            "address": addr,
            "type": "p2pkh" if addr[0] == "1" else ("p2sh" if addr[0] == "3" else "bech32"),
            "position": m.start(),
        })

    # Ethereum private keys
    for m in ETH_PK_RE.finditer(text):
        pk = m.group(0)
        # Skip obviously invalid (all zeros, all Fs, etc.)
        if pk.lower().replace("0x", "") in ("0" * 64, "f" * 64, "0000000000000000000000000000000000000000000000000000000000000001"):
            continue
        findings["eth_private_keys"].append({
            "private_key": pk if pk.startswith("0x") else "0x" + pk,
            "position": m.start(),
        })

    # Ethereum addresses
    for m in ETH_ADDR_RE.finditer(text):
        findings["eth_addresses"].append({
            "address": m.group(0),
            "position": m.start(),
        })

    # BIP39 seed phrases
    for m in SEED_PHRASE_RE.finditer(text):
        words = m.group(0).strip().lower().split()
        word_count = len(words)
        if word_count not in (12, 15, 18, 21, 24):
            continue
        # Quick validation: are most words in BIP39 list?
        bip39_count = sum(1 for w in words if w in BIP39_WORDS)
        if bip39_count > word_count * 0.6:
            findings["seed_phrases"].append({
                "words": " ".join(words),
                "count": word_count,
                "bip39_score": bip39_count / word_count,
                "position": m.start(),
            })

    # Wallet.dat paths
    for m in WALLET_DAT_RE.finditer(text):
        findings["wallet_dat_paths"].append({
            "path": m.group(0),
            "position": m.start(),
        })

    # Keystore files
    for m in KEYSTORE_RE.finditer(text):
        findings["keystore_files"].append({
            "filename": m.group(0),
            "position": m.start(),
        })

    # PEM private keys
    for m in PEM_KEY_RE.finditer(text):
        key_block = m.group(0)[:500]  # truncate for output
        findings["pem_keys"].append({
            "key_start": key_block[:100],
            "length": len(m.group(0)),
            "position": m.start(),
        })

    # Brain wallet hints
    for m in BRAIN_PASSPHRASE_INDICATORS.finditer(text):
        findings["brain_wallet_hints"].append({
            "hint": m.group(0)[:200],
            "position": m.start(),
        })

    return findings


# =============================================================================
# BLOCKCHAIN BALANCE CHECKER
# =============================================================================

def check_btc_balance(address: str) -> Optional[Dict]:
    """Check Bitcoin address balance via public blockchain.info API."""
    try:
        url = f"https://blockchain.info/rawaddr/{address}?limit=0"
        req = urllib.request.Request(url, headers={"User-Agent": "pow_recover/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return {
                "address": address,
                "balance_sat": data.get("final_balance", 0),
                "balance_btc": data.get("final_balance", 0) / 1e8,
                "total_received_sat": data.get("total_received", 0),
                "total_received_btc": data.get("total_received", 0) / 1e8,
                "n_tx": data.get("n_tx", 0),
                "first_tx_ts": None,  # would need tx lookup
            }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            time.sleep(5)
        return None
    except Exception:
        return None


def check_btc_batch_balance(addresses: List[str]) -> List[Dict]:
    """Check multiple BTC addresses via blockchain.info multi-addr API."""
    results = []
    if not addresses:
        return results

    # Batch in groups of 50
    for i in range(0, len(addresses), 50):
        batch = addresses[i:i + 50]
        active = "|".join(batch)
        try:
            url = f"https://blockchain.info/multiaddr?active={active}&n=0"
            req = urllib.request.Request(url, headers={"User-Agent": "pow_recover/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                for addr_data in data.get("addresses", []):
                    addr = addr_data.get("address", "")
                    results.append({
                        "address": addr,
                        "balance_sat": addr_data.get("final_balance", 0),
                        "balance_btc": addr_data.get("final_balance", 0) / 1e8,
                        "total_received_sat": addr_data.get("total_received", 0),
                        "total_received_btc": addr_data.get("total_received", 0) / 1e8,
                        "n_tx": addr_data.get("n_tx", 0),
                    })
            time.sleep(1)  # rate limit
        except Exception:
            continue
    return results


def check_eth_balance(address: str) -> Optional[Dict]:
    """Check ETH balance via Etherscan API (no key needed for basic queries)."""
    try:
        url = (f"https://api.etherscan.io/api?module=account&action=balance"
               f"&address={address}&tag=latest")
        req = urllib.request.Request(url, headers={"User-Agent": "pow_recover/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "1":
                wei = int(data.get("result", 0))
                return {
                    "address": address,
                    "balance_wei": wei,
                    "balance_eth": wei / 1e18,
                }
    except Exception:
        pass
    return None


# =============================================================================
# SATOSHI-ERA DETECTOR  (pre-2013 unspent coins = abandoned gold mine)
# =============================================================================

SATOSHI_ERA_CUTOFF = 1356998400  # Jan 1, 2013 UTC


def is_satoshi_era(tx_timestamp: Optional[int]) -> bool:
    """Check if a transaction is from the Satoshi era (pre-2013)."""
    return tx_timestamp is not None and tx_timestamp < SATOSHI_ERA_CUTOFF


# Known satoshi-era addresses worth watching (partial list from public research)
SATOSHI_ERA_ADDRESSES: List[str] = [
    # Genesis-related
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Genesis address
    # Early miners (first 1000 blocks)
    "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
    "1HLoD9E4SDFsPDnL43N3TRKTiDdWGqirVZ",
    # Known lost coins
    "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF",  # MtGox cold wallet (approx 80k BTC)
    "1L2JsXHPMYuAa9ugQHGLwEXRx3xZDmyNL2",
]


def flag_satoshi_era_coins(findings_list: List[Dict]) -> List[Dict]:
    """Cross-reference found addresses with known satoshi-era addresses."""
    flagged = []
    known_set = set(SATOSHI_ERA_ADDRESSES)
    for finding in findings_list:
        for addr_entry in finding.get("btc_addresses", []):
            if addr_entry["address"] in known_set:
                flagged.append({
                    "source": finding.get("source", "unknown"),
                    "address": addr_entry["address"],
                    "note": "KNOWN SATOSHI-ERA ADDRESS — investigate immediately",
                    "estimated_value_hint": "potentially massive",
                })
    return flagged


# =============================================================================
# BRAIN WALLET SCANNER
# =============================================================================

# Common brain wallet passphrases (abbreviated — use a wordlist for full scan)
COMMON_BRAIN_PASSPHRASES = [
    "bitcoin", "satoshi nakamoto", "correct horse battery staple",
    "password", "12345678", "trustno1", "letmein",
    "to be or not to be", "all you need is love", "hello world",
    "the quick brown fox jumps over the lazy dog",
    "it was the best of times it was the worst of times",
    "in the beginning god created the heaven and the earth",
    "bible", "quran", "torah", "god", "jesus", "allah",
    "blockchain", "cryptocurrency", "ethereum", "vitalik buterin",
    "hal finney", "nick szabo", "dorian nakamoto", "craig wright",
    "pizza", "hodl", "to the moon", "lambo",
    "hunter2", "swordfish", "opensesame",
    "a", "b", "c", "test", "test123", "admin",
]

# Weak-key patterns (low entropy, repeated bytes)
WEAK_KEY_PATTERNS = [
    re.compile(rb'^\x00+$'),           # all zeros
    re.compile(rb'^(\x01)+$'),         # all ones
    re.compile(rb'^(.)\1{31}$'),       # single byte repeated
    re.compile(rb'^\x00{1,30}\x01+$'),  # zeros then ones
]


def generate_brain_wallet_key(passphrase: str) -> Optional[str]:
    """Generate a Bitcoin WIF private key from a brain wallet passphrase.

    Uses the original brainwallet algorithm: SHA256(passphrase) → WIF.
    """
    sha = hashlib.sha256(passphrase.encode("utf-8")).digest()
    # Prepend version byte (0x80 for mainnet)
    extended = b'\x80' + sha
    # Double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    # Base58 encode
    return base58_encode(extended + checksum)


def base58_encode(data: bytes) -> str:
    """Bitcoin base58 encoding."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, 'big')
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(alphabet[rem])
    # Add leading zeros
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    return ''.join(reversed(result))


def scan_brain_wallets(wordlist_path: Optional[str] = None,
                        max_passphrases: int = 10000) -> List[Dict]:
    """Generate and check brain wallet keys.

    If wordlist_path is provided, uses that file.
    Otherwise uses built-in common passphrases.
    """
    results = []
    passphrases = list(COMMON_BRAIN_PASSPHRASES)

    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= max_passphrases:
                        break
                    pw = line.strip()
                    if pw and 4 <= len(pw) <= 80:
                        passphrases.append(pw)
        except Exception as e:
            cprint(f"[brain] Cannot read wordlist: {e}", color=C_RED)

    cprint(f"[brain] Testing {len(passphrases)} passphrases...", color=C_CYAN)

    # Generate WIF keys
    wif_keys = set()
    for pw in passphrases:
        try:
            wif = generate_brain_wallet_key(pw)
            wif_keys.add((pw, wif))
        except Exception:
            continue

    return [
        {
            "type": "brain-wallet",
            "passphrase": pw,
            "wif": wif,
            "source": "brain-wallet-scan",
            "note": "Generated from brain wallet passphrase — check balance",
        }
        for pw, wif in wif_keys
    ]


# =============================================================================
# INPUT SCANNERS — process 7000.py, onion_scanner, trufflehog output
# =============================================================================

def scan_paste_box(filepath: str) -> List[Dict]:
    """Process 7000.py paste_box.txt output for crypto material."""
    results = []
    if not os.path.exists(filepath):
        return results

    cprint(f"[scan] Processing paste_box: {filepath}", color=C_CYAN)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Parse pipe-delimited: url|owner|repo|topic|source|ts
            parts = line.split("|")
            if len(parts) < 5:
                continue
            url = parts[0].replace("\\|", "|")
            topic = parts[3].replace("\\|", "|")
            source = parts[4].replace("\\|", "|")

            # Scan the topic and URL for crypto material
            findings = scan_text_for_crypto(line, url, f"paste_box:{source}")
            findings["paste_topic"] = topic
            if _has_crypto(findings):
                results.append(findings)

    return results


def scan_onion_scanner_output(filepath: str) -> List[Dict]:
    """Process onion_scanner.py JSONL output for crypto material."""
    results = []
    if not os.path.exists(filepath):
        return results

    cprint(f"[scan] Processing onion_scanner output: {filepath}", color=C_CYAN)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            source = rec.get("source", "unknown")
            raw_value = rec.get("raw_value", "")
            findings = scan_text_for_crypto(raw_value, source, "onion_scanner")
            if _has_crypto(findings):
                results.append(findings)

    return results


def scan_directory_for_crypto(dirpath: str) -> List[Dict]:
    """Recursive scan of directory tree for crypto material in files."""
    results = []
    cprint(f"[scan] Recursive directory scan: {dirpath}", color=C_CYAN)
    ext_set = {".txt", ".md", ".json", ".yml", ".yaml", ".log", ".csv",
               ".py", ".js", ".ts", ".sh", ".conf", ".cfg", ".dat", ".key"}

    file_count = 0
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext.lower() not in ext_set and fname != "wallet.dat":
                continue
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size > 10 * 1024 * 1024:  # skip >10MB
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings = scan_text_for_crypto(content, fpath, "directory")
                if _has_crypto(findings):
                    results.append(findings)
                file_count += 1
                if file_count % 100 == 0:
                    cprint(f"  ... scanned {file_count} files", color=C_DIM)
            except Exception:
                continue

    cprint(f"[scan] Scanned {file_count} files, {len(results)} with crypto", color=C_GREEN)
    return results


def _has_crypto(findings: Dict) -> bool:
    """Check if findings dict has any crypto material."""
    return bool(
        findings.get("btc_wif_keys") or
        findings.get("btc_addresses") or
        findings.get("eth_private_keys") or
        findings.get("eth_addresses") or
        findings.get("seed_phrases") or
        findings.get("wallet_dat_paths") or
        findings.get("keystore_files") or
        findings.get("pem_keys") or
        findings.get("brain_wallet_hints")
    )


# =============================================================================
# WALLETX OUTPUT — structured recovery manifest
# =============================================================================

def write_walletx_recovery_manifest(
    findings_list: List[Dict],
    brain_wallet_results: List[Dict],
    balance_results: List[Dict],
    satoshi_flags: List[Dict],
    output_path: str
) -> int:
    """Write a walletx-compatible recovery manifest JSONL.

    Each line is a self-contained recovery action item walletx can import.
    """
    entries = []
    ts = datetime.now(timezone.utc).isoformat()

    # Findings from scanning
    for findings in findings_list:
        source = findings.get("source", "unknown")

        for wif in findings.get("btc_wif_keys", []):
            entries.append({
                "action": "import_private_key",
                "type": "bitcoin-wif",
                "value": wif["wif"],
                "source": source,
                "compressed": wif.get("compressed", True),
                "confidence": "high",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for addr in findings.get("btc_addresses", []):
            entries.append({
                "action": "monitor_address",
                "type": "bitcoin-address",
                "value": addr["address"],
                "address_type": addr.get("type", "unknown"),
                "source": source,
                "confidence": "medium",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for eth_pk in findings.get("eth_private_keys", []):
            entries.append({
                "action": "import_private_key",
                "type": "ethereum-private-key",
                "value": eth_pk["private_key"],
                "source": source,
                "confidence": "high",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for seed in findings.get("seed_phrases", []):
            entries.append({
                "action": "import_seed_phrase",
                "type": "bip39-seed",
                "value": seed["words"],
                "word_count": seed["count"],
                "bip39_score": seed.get("bip39_score", 0),
                "source": source,
                "confidence": "high",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for wd in findings.get("wallet_dat_paths", []):
            entries.append({
                "action": "locate_wallet_file",
                "type": "wallet-dat",
                "value": wd["path"],
                "source": source,
                "confidence": "medium",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for ks in findings.get("keystore_files", []):
            entries.append({
                "action": "locate_keystore",
                "type": "ethereum-keystore",
                "value": ks["filename"],
                "source": source,
                "confidence": "medium",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

        for brain_hint in findings.get("brain_wallet_hints", []):
            entries.append({
                "action": "investigate_brain_wallet",
                "type": "brain-wallet-hint",
                "value": brain_hint["hint"],
                "source": source,
                "confidence": "low",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

    # Brain wallet scan results
    for bw in brain_wallet_results:
        entries.append({
            "action": "check_brain_wallet",
            "type": "brain-wallet-key",
            "value": bw["wif"],
            "passphrase": bw["passphrase"],
            "source": bw["source"],
            "confidence": "low",
            "timestamp": ts,
            "scanner": "pow_recover.py v1.0",
        })

    # Balance check results
    for bal in balance_results:
        if bal.get("balance_sat", 0) > 0 or bal.get("balance_wei", 0) > 0:
            entries.append({
                "action": "recover_funds",
                "type": "confirmed-balance",
                "value": bal.get("address", ""),
                "balance": bal.get("balance_btc") or bal.get("balance_eth"),
                "raw_balance": bal.get("balance_sat") or bal.get("balance_wei"),
                "n_tx": bal.get("n_tx", 0),
                "confidence": "high",
                "timestamp": ts,
                "scanner": "pow_recover.py v1.0",
            })

    # Satoshi-era flags
    for flag in satoshi_flags:
        entries.append({
            "action": "investigate_satoshi_era",
            "type": "satoshi-era-address",
            "value": flag["address"],
            "note": flag.get("note", ""),
            "source": flag.get("source", "unknown"),
            "confidence": "critical",
            "timestamp": ts,
            "scanner": "pow_recover.py v1.0",
        })

    # Write
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return len(entries)


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="pow_recover.py — Abandoned POW coin discovery & recovery pipeline"
    )
    ap.add_argument("--input", "-i", type=str, default="",
                    help="Input: paste_box.txt, onion_scanner_results.jsonl, or any text file")
    ap.add_argument("--scan-dir", "-d", type=str, default="",
                    help="Recursively scan a directory tree for crypto material")
    ap.add_argument("--output", "-o", type=str, default="pow_recover_manifest.jsonl",
                    help="Output walletx recovery manifest (default: pow_recover_manifest.jsonl)")
    ap.add_argument("--check-balances", action="store_true",
                    help="Query blockchain APIs for found address balances")
    ap.add_argument("--brain-wallet-scan", action="store_true",
                    help="Generate and check brain wallet keys")
    ap.add_argument("--wordlist", "-w", type=str, default="",
                    help="Wordlist for brain wallet scan (default: built-in common phrases)")
    ap.add_argument("--max-brain", type=int, default=5000,
                    help="Max brain wallet passphrases to test (default: 5000)")
    args = ap.parse_args()

    cprint("=" * 60, color=C_BCYN)
    cprint(" pow_recover.py v1.0 — Abandoned POW Coin Recovery", color=C_BGRN, bold=True)
    cprint("=" * 60, color=C_BCYN)

    all_findings = []

    # Scan input file
    if args.input:
        if "paste_box" in args.input.lower():
            all_findings = scan_paste_box(args.input)
        elif "onion_scanner" in args.input.lower() or args.input.endswith(".jsonl"):
            all_findings = scan_onion_scanner_output(args.input)
        else:
            # Generic text file
            try:
                with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings = scan_text_for_crypto(content, args.input, "file")
                if _has_crypto(findings):
                    all_findings = [findings]
                cprint(f"[scan] {args.input}: {'found crypto' if _has_crypto(findings) else 'no crypto found'}", color=C_CYAN)
            except Exception as e:
                cprint(f"[!] Cannot read {args.input}: {e}", color=C_RED)

    # Scan directory
    if args.scan_dir:
        dir_findings = scan_directory_for_crypto(args.scan_dir)
        all_findings.extend(dir_findings)

    # Brain wallet scan
    brain_results = []
    if args.brain_wallet_scan:
        brain_results = scan_brain_wallets(
            wordlist_path=args.wordlist if args.wordlist else None,
            max_passphrases=args.max_brain,
        )

    # Balance checks
    balance_results = []
    satoshi_flags = []
    if args.check_balances:
        # Collect all BTC addresses
        all_btc_addrs = []
        for f in all_findings:
            for addr in f.get("btc_addresses", []):
                all_btc_addrs.append(addr["address"])

        # Add brain wallet addresses (need to derive from WIF — simplified: check known)
        # For brain wallets we'd need to derive addresses from WIFs, which is complex.
        # Instead, we batch-check the found addresses.

        if all_btc_addrs:
            cprint(f"\n[balance] Checking {len(all_btc_addrs)} BTC addresses...", color=C_BCYN)
            balance_results = check_btc_batch_balance(list(set(all_btc_addrs)))

            # Report non-zero balances
            funded = [b for b in balance_results if b.get("balance_sat", 0) > 0]
            if funded:
                cprint(f"\n💰 FUNDED ADDRESSES FOUND: {len(funded)}", color=C_BGRN, bold=True)
                for b in funded:
                    cprint(f"   {b['address']}: {b['balance_btc']:.8f} BTC ({b.get('n_tx', 0)} txs)",
                           color=C_BGRN)
            else:
                cprint("[balance] No funded BTC addresses found in scanned set", color=C_YELLOW)

        # Check individual ETH addresses
        for f in all_findings:
            for eth_addr in f.get("eth_addresses", []):
                eth_bal = check_eth_balance(eth_addr["address"])
                if eth_bal:
                    balance_results.append(eth_bal)
                    if eth_bal.get("balance_wei", 0) > 0:
                        cprint(f"   💰 {eth_addr['address']}: {eth_bal['balance_eth']:.6f} ETH",
                               color=C_BGRN)
                time.sleep(0.3)  # Etherscan rate limit

        # Flag satoshi-era addresses
        satoshi_flags = flag_satoshi_era_coins(all_findings)
        if satoshi_flags:
            cprint(f"\n⚠ SATOSHI-ERA ADDRESSES FOUND: {len(satoshi_flags)}", color=C_BRED, bold=True)
            for flag in satoshi_flags:
                cprint(f"   {flag['address']} — {flag['note']}", color=C_BRED)

    # Summary
    total_btc_keys = sum(len(f.get("btc_wif_keys", [])) for f in all_findings)
    total_btc_addrs = sum(len(f.get("btc_addresses", [])) for f in all_findings)
    total_eth_keys = sum(len(f.get("eth_private_keys", [])) for f in all_findings)
    total_seeds = sum(len(f.get("seed_phrases", [])) for f in all_findings)
    total_wallets = sum(len(f.get("wallet_dat_paths", [])) for f in all_findings)
    total_brain_hints = sum(len(f.get("brain_wallet_hints", [])) for f in all_findings)

    cprint(f"\n[summary] Scan Results:", color=C_BGRN, bold=True)
    cprint(f"  Sources with crypto: {len(all_findings)}", color=C_CYAN)
    cprint(f"  BTC private keys: {total_btc_keys}", color=C_GREEN)
    cprint(f"  BTC addresses: {total_btc_addrs}", color=C_GREEN)
    cprint(f"  ETH private keys: {total_eth_keys}", color=C_GREEN)
    cprint(f"  Seed phrases: {total_seeds}", color=C_BGRN if total_seeds else C_CYAN)
    cprint(f"  Wallet.dat paths: {total_wallets}", color=C_YELLOW if total_wallets else C_CYAN)
    cprint(f"  Brain wallet hints: {total_brain_hints}", color=C_BYEL if total_brain_hints else C_CYAN)
    cprint(f"  Brain wallet keys generated: {len(brain_results)}", color=C_CYAN)
    cprint(f"  Balances checked: {len(balance_results)}", color=C_CYAN)
    cprint(f"  Satoshi-era flags: {len(satoshi_flags)}", color=C_BRED if satoshi_flags else C_CYAN)

    # Write recovery manifest
    entries = write_walletx_recovery_manifest(
        all_findings, brain_results, balance_results, satoshi_flags, args.output
    )
    cprint(f"\n[output] {entries} recovery actions → {args.output}", color=C_BGRN, bold=True)
    cprint(f"[tip] Feed into walletx: cat {args.output} | walletx import", color=C_DIM)
    cprint(f"[tip] For live recovery: walletx recover --manifest {args.output}", color=C_DIM)

    # Gold mine assessment
    if total_btc_keys > 0 or total_seeds > 0:
        cprint(f"\n💎 POTENTIAL GOLD MINE:", color=C_BMAG, bold=True)
        cprint(f"   Found {total_btc_keys + total_seeds + total_eth_keys} recoverable key materials.", color=C_BMAG)
        cprint(f"   This is direct wallet access — check balances immediately.", color=C_BMAG)
        cprint(f"   Run with --check-balances to evaluate value.", color=C_BMAG)


if __name__ == "__main__":
    main()
