#!/usr/bin/env python3
"""
Paste Box - Universal messy-text preprocessor for the crypto scanner pipeline.

Drop any messy text into ~/paste_box.txt (URLs, keys, addresses, seed phrases,
API keys, RPC endpoints, repo names, copy-pasted terminal output, etc.).
This script:

  1. Deobfuscates backspaces / ANSI escape sequences.
  2. Extracts GitHub URLs and bare org/user names -> ~/paste.txt
  3. Extracts crypto material (addresses, WIFs, hex keys, seed phrases,
     API keys, tokens) -> ~/.trufflehog_results.jsonl (pseudo-trufflehog JSONL
     so crypto_scanner.py can tail it directly).
  4. Extracts RPC endpoint URLs -> ~/rpc_endpoints.jsonl
  5. Extracts API keys -> ~/api_keys.jsonl

Usage:
    python3 ~/paste_box.py                # process ~/paste_box.txt
    python3 ~/paste_box.py <file>         # process another file
    cat messy.txt | python3 ~/paste_box.py # process stdin
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import List, Set, Tuple

HOME = os.path.expanduser("~")
PASTE_BOX = os.path.join(HOME, "paste_box.txt")
PASTE_OUT = os.path.join(HOME, "paste.txt")
CRYPTO_OUT = os.path.join(HOME, ".trufflehog_results.jsonl")
RPC_OUT = os.path.join(HOME, "rpc_endpoints.jsonl")
API_KEYS_OUT = os.path.join(HOME, "api_keys.jsonl")

# ---------------------------------------------------------------------------
# Deobfuscation (backspaces + ANSI)
# ---------------------------------------------------------------------------
def deobfuscate(text: str) -> str:
    result = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\b":
            if result:
                result.pop()
            i += 1
        elif ch == "\x1b":
            # skip ANSI CSI sequences \e[...m
            if i + 1 < len(text) and text[i + 1] == "[":
                j = i + 2
                while j < len(text) and text[j] not in "mABCD":
                    j += 1
                if j < len(text):
                    i = j + 1
                    continue
            result.append(ch)
            i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Regex constants
# ---------------------------------------------------------------------------
GITHUB_HTTPS_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?"
)
GITHUB_SSH_RE = re.compile(r"git@github\.com:([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:\.git)?")
BARE_NAME_RE = re.compile(r"@?([A-Za-z0-9_-]{2,})")

BTC_ADDR_RE = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{8,87})\b")
ETH_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
LTC_ADDR_RE = re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{8,87})\b")
SOL_ADDR_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
DOGE_ADDR_RE = re.compile(r"\bD[5KL][1-9A-HJ-NP-Za-km-z]{32,34}\b")
XRP_ADDR_RE = re.compile(r"\b[rR][1-9A-HJ-NP-Za-km-z]{25,34}\b")
TON_ADDR_RE = re.compile(r"\b[UE]Q[a-zA-Z0-9_-]{46}\b")
AVAX_ADDR_RE = re.compile(r"\b[XC][1-9A-HJ-NP-Za-km-z]{33}\b")
WIF_RE = re.compile(r"\b([5][1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b")
HEX_KEY_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
SEED_RE = re.compile(r"\b([a-z]{3,}(?:\s+[a-z]{3,}){11,23})\b", re.IGNORECASE)

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT_RE = re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]+\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[a-zA-Z0-9]{24})?\b")
STRIPE_KEY_RE = re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b")
GENERIC_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
    re.IGNORECASE,
)
RPC_RE = re.compile(
    r"(?:https?|wss?)://[a-zA-Z0-9_.-]*(?:alchemy|ankr|infura|quicknode|helius|"
    r"publicnode|blastapi|cloudflare|solana|ethereum|binance|avax|polygon|"
    r"bitcoin|core|getblock|nodereal|chainstack|figment|lb\.drpc)[a-zA-Z0-9_.:/=?&\-]*",
    re.IGNORECASE,
)

COMMON_WORDS = {
    "check", "scan", "all", "repos", "in", "org", "user", "the", "and", "for",
    "with", "https", "http", "git", "com", "api", "v2", "www", "app", "web",
    "get", "post", "put", "delete", "json", "html", "txt", "raw", "blob",
}



# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
def extract_github(text: str) -> Tuple[Set[str], Set[str]]:
    urls: Set[str] = set()
    orgs: Set[str] = set()

    for m in GITHUB_HTTPS_RE.finditer(text):
        urls.add(f"https://github.com/{m.group(1)}/{m.group(2)}".rstrip("/"))
    for m in GITHUB_SSH_RE.finditer(text):
        urls.add(f"https://github.com/{m.group(1)}/{m.group(2)}".rstrip("/"))

    stripped = GITHUB_HTTPS_RE.sub(" ", text)
    stripped = GITHUB_SSH_RE.sub(" ", stripped)

    for line in stripped.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for cand in BARE_NAME_RE.findall(line):
            low = cand.lower()
            if low in COMMON_WORDS:
                continue
            if "." in cand or len(cand) < 2:
                continue
            # Skip things that look like API keys/tokens (mixed case + digits, 16+)
            if len(cand) >= 16 and any(c.isupper() for c in cand) and any(c.islower() for c in cand) and any(c.isdigit() for c in cand):
                continue
            # Skip hyphenated subdomain fragments like eth-mainnet, solana-mainnet
            if "-" in cand and any(part in low for part in ("mainnet", "testnet", "devnet", "alchemy", "infura")):
                continue
            orgs.add(cand)

    return urls, orgs


def extract_crypto_material(text: str) -> List[dict]:
    """Return pseudo-trufflehog JSONL records for crypto material."""
    records = []
    seen = set()

    def add(kind: str, value: str, chain: str = ""):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "reason": kind,
            "string": value,
            "chain": chain,
            "path": "paste_box",
            "commit": "",
            "source_line": value,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    for m in BTC_ADDR_RE.finditer(text):
        add("BTC address", m.group(0), "btc")
    for m in ETH_ADDR_RE.finditer(text):
        add("ETH address", m.group(0), "eth")
    for m in LTC_ADDR_RE.finditer(text):
        add("LTC address", m.group(0), "ltc")
    for m in SOL_ADDR_RE.finditer(text):
        add("SOL address", m.group(0), "sol")
    for m in DOGE_ADDR_RE.finditer(text):
        add("DOGE address", m.group(0), "doge")
    for m in XRP_ADDR_RE.finditer(text):
        add("XRP address", m.group(0), "xrp")
    for m in TON_ADDR_RE.finditer(text):
        add("TON address", m.group(0), "ton")
    for m in AVAX_ADDR_RE.finditer(text):
        add("AVAX address", m.group(0), "avax")
    for m in WIF_RE.finditer(text):
        add("Bitcoin WIF", m.group(0), "btc")
    for m in HEX_KEY_RE.finditer(text):
        add("Hex private key", m.group(0), "eth")
    for m in SEED_RE.finditer(text):
        add("Seed phrase", m.group(0).strip(), "seed")

    return records


def extract_api_keys(text: str) -> List[dict]:
    keys = []
    seen = set()

    def add(provider: str, value: str):
        if value in seen:
            return
        seen.add(value)
        keys.append({
            "provider": provider,
            "key": value,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    for k in re.findall(r"https?://[a-z0-9-]+\.g\.alchemy\.com/v2/([a-zA-Z0-9_-]+)", text, re.IGNORECASE):
        add("alchemy", k)
    for k in re.findall(r"https?://[a-z0-9-]+\.infura\.io/v3/([a-zA-Z0-9]{32})", text, re.IGNORECASE):
        add("infura", k)
    for m in GENERIC_SECRET_RE.finditer(text):
        add("generic", m.group(1))
    for m in AWS_KEY_RE.finditer(text):
        add("aws", m.group(0))
    for m in GITHUB_PAT_RE.finditer(text):
        add("github", m.group(0))
    for m in SLACK_TOKEN_RE.finditer(text):
        add("slack", m.group(0))
    for m in STRIPE_KEY_RE.finditer(text):
        add("stripe", m.group(0))

    return keys


def extract_rpc_endpoints(text: str) -> List[dict]:
    endpoints = []
    seen = set()
    for url in RPC_RE.findall(text):
        url = url.rstrip("/")
        if url in seen:
            continue
        seen.add(url)
        endpoints.append({
            "url": url,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return endpoints



# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
def read_input(argv: List[str]) -> str:
    # Use explicit file arg if given; '-' means read stdin.
    if len(argv) > 1:
        path = argv[1]
        if path == "-":
            return sys.stdin.read()
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # Default: read the paste box file
    if not os.path.exists(PASTE_BOX):
        open(PASTE_BOX, "w").close()
        print(f"[*] Created empty paste box: {PASTE_BOX}")
        return ""

    with open(PASTE_BOX, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def write_lines(path: str, lines: List[str]) -> None:
    """Write text lines (deduped, preserving order)."""
    seen = set()
    out = []
    for line in lines:
        line = line.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        out.append(line)
    with open(path, "w", encoding="utf-8") as f:
        for line in out:
            f.write(line + "\n")


def append_jsonl(path: str, records: List[dict]) -> None:
    if not records:
        return
    with open(path, "a", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    raw = read_input(sys.argv)
    if not raw.strip():
        print("[!] Paste box is empty. Add text to ~/paste_box.txt first.")
        return

    text = deobfuscate(raw)

    urls, orgs = extract_github(text)
    crypto_records = extract_crypto_material(text)
    api_keys = extract_api_keys(text)
    rpc_endpoints = extract_rpc_endpoints(text)

    paste_lines = [
        "# Auto-generated from ~/paste_box.txt by paste_box.py",
        "# Put messy text in paste_box.txt, then run: python3 ~/paste_box.py",
    ]
    if urls:
        paste_lines.append("# GitHub URLs")
        paste_lines.extend(sorted(urls))
    if orgs:
        paste_lines.append("# Bare orgs/users (resolved by mass_scan.py)")
        paste_lines.extend(sorted(orgs))
    if not urls and not orgs:
        paste_lines.append("# No GitHub URLs or orgs detected")

    write_lines(PASTE_OUT, paste_lines)
    append_jsonl(CRYPTO_OUT, crypto_records)
    append_jsonl(API_KEYS_OUT, api_keys)
    append_jsonl(RPC_OUT, rpc_endpoints)

    print("[+] Paste box processed")
    print(f"    GitHub URLs:   {len(urls)}")
    print(f"    Orgs/users:    {len(orgs)}")
    print(f"    Crypto items:  {len(crypto_records)}")
    print(f"    API keys:      {len(api_keys)}")
    print(f"    RPC endpoints: {len(rpc_endpoints)}")
    print("    Output files:")
    print(f"      {PASTE_OUT}")
    print(f"      {CRYPTO_OUT}")
    print(f"      {API_KEYS_OUT}")
    print(f"      {RPC_OUT}")


if __name__ == "__main__":
    main()
