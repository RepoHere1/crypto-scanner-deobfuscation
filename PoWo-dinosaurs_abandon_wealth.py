#!/usr/bin/env python3
"""
PoWo-dinosaurs_abandon_wealth — Abandoned PoW-era Ethereum account scanner.

Scans paste_box.txt in chunks for raw Ethereum private keys from the
proof-of-work era, derives addresses, checks on-chain balances, and
feeds findings back to trufflehog for deeper reconnaissance.

Display: abandoned accounts show $0.00 on screen.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

# ── Third-party imports (same deps as crypto_scanner.py) ──────────────────
try:
    import ecdsa
except ImportError:
    raise SystemExit("[!] ecdsa required: pip3 install ecdsa")

try:
    import requests
except ImportError:
    raise SystemExit("[!] requests required: pip3 install requests")

# ── Optional IQ layer ─────────────────────────────────────────────────────
try:
    import crypto_iq as _crypto_iq
except ImportError:
    _crypto_iq = None

# ── Constants ──────────────────────────────────────────────────────────────
HOME = Path(os.path.expanduser("~"))
PASTE_BOX = HOME / "paste_box.txt"
FINDINGS_DIR = HOME / "powo_findings"
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
FINDINGS_JSONL = FINDINGS_DIR / "abandoned_accounts.jsonl"
TRUFFLEHOG_FEED = FINDINGS_DIR / "trufflehog_feed.txt"
STATE_FILE = FINDINGS_DIR / ".powo_state.json"

# Chunk processing: read this many lines at a time from paste_box.txt
CHUNK_LINES = 2000

# Regex: raw 64-char hex private keys (with optional 0x prefix)
HEX_PRIVKEY_RE = re.compile(
    r'(?:^|[^a-fA-F0-9x])'
    r'(0x)?'
    r'([a-fA-F0-9]{64})'
    r'(?:[^a-fA-F0-9]|$)'
)

# Secp256k1 order
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Alchemy RPC — loaded from environment or .env
ALCHEMY_KEY = os.environ.get("ALCHEMY_API_KEY", "") or os.environ.get("ALCHEMY_KEY", "")
if not ALCHEMY_KEY:
    # Try to load from .env / .bashrc
    for src in [HOME / ".env", HOME / ".bashrc"]:
        try:
            if src.exists():
                for line in src.read_text().splitlines():
                    line = line.strip()
                    if "ALCHEMY_API_KEY=" in line and not line.startswith("#"):
                        ALCHEMY_KEY = line.split("ALCHEMY_API_KEY=", 1)[1].strip().strip('"').strip("'")
                        os.environ["ALCHEMY_API_KEY"] = ALCHEMY_KEY
                        break
        except Exception:
            pass
        if ALCHEMY_KEY:
            break

ETH_RPC = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}" if ALCHEMY_KEY else ""
BATCH_SIZE = 20  # addresses per batch RPC call

# Warm/abandoned threshold in ETH — anything below this is "abandoned"
ABANDONED_THRESHOLD_ETH = 0.001

# ── Keccak-256 ─────────────────────────────────────────────────────────────

def _rot(x, n):
    return ((x << n) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - n))

def _keccak_f1600(state):
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    for r in range(24):
        C = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        D = [C[(x + 4) % 5] ^ _rot(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= D[x]
        x, y = 1, 0
        current = state[x]
        for t in range(24):
            X, Y = y, (2 * x + 3 * y) % 5
            tmp = state[X + 5 * Y]
            state[X + 5 * Y] = _rot(current, ((t + 1) * (t + 2) // 2) % 64)
            current = tmp
            x, y = X, Y
        for y in range(5):
            T = [state[x + 5 * y] for x in range(5)]
            for x in range(5):
                state[x + 5 * y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])
        state[0] ^= RC[r]

def keccak_256(data: bytes) -> bytes:
    if _crypto_iq is not None and getattr(_crypto_iq, "_PYCRYPTODOME", False):
        try:
            return _crypto_iq.keccak_256(data)
        except Exception:
            pass
    rate = 136
    state = [0] * 25
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % rate != (rate - 1):
        buf.append(0x00)
    buf.append(0x80)
    for offset in range(0, len(buf), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(buf[offset + i * 8:offset + i * 8 + 8], "little")
        _keccak_f1600(state)
    out = b""
    for i in range(4):
        out += state[i].to_bytes(8, "little")
    return out


def hex_to_eth_address(hex_key: str) -> Optional[str]:
    """64-char hex private key -> checksummed Ethereum address."""
    try:
        h = hex_key.strip().lower().removeprefix("0x")
        if len(h) != 64:
            return None
        if _crypto_iq is not None:
            ok, _reason, _score = _crypto_iq.validate_hex_privkey(h)
            if not ok:
                return None
        priv = bytes.fromhex(h)
        if len(priv) != 32 or priv == bytes(32):
            return None
        n = int.from_bytes(priv, "big")
        if n <= 0 or n >= SECP256K1_N:
            return None
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        pub = vk.to_string()
        addr_bytes = keccak_256(pub)[12:]
        addr_hex = addr_bytes.hex()
        hashed = keccak_256(addr_hex.encode("ascii")).hex()
        checksummed = "0x" + "".join(
            c.upper() if hashed[i] in "89abcdef" else c.lower()
            for i, c in enumerate(addr_hex)
        )
        return checksummed
    except Exception:
        return None


# ── Balance checking ───────────────────────────────────────────────────────

def check_balances_batch(addresses: List[str]) -> dict:
    """Check ETH balances for a batch of addresses via Alchemy JSON-RPC."""
    if not ETH_RPC:
        return {addr: {"error": "no RPC endpoint"} for addr in addresses}

    payload = []
    for i, addr in enumerate(addresses):
        payload.append({
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "eth_getBalance",
            "params": [addr, "latest"],
        })

    try:
        resp = requests.post(
            ETH_RPC,
            json=payload,
            timeout=30,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        results = resp.json()
    except Exception as e:
        return {addr: {"error": str(e)} for addr in addresses}

    balances = {}
    # Results may be a list or a single object
    items = results if isinstance(results, list) else [results]
    for item in items:
        idx = item.get("id", 0) - 1
        if 0 <= idx < len(addresses):
            addr = addresses[idx]
            if "error" in item:
                balances[addr] = {"error": item["error"]}
            else:
                wei = int(item.get("result", "0x0"), 16)
                eth = wei / 1e18
                balances[addr] = {"wei": wei, "eth": eth}
    return balances


# ── State management ───────────────────────────────────────────────────────

def load_state() -> dict:
    """Load tracking state: last processed byte offset + seen keys."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"last_byte_offset": 0, "seen_keys": [], "total_found": 0, "total_abandoned": 0}


def save_state(state: dict) -> None:
    """Persist tracking state atomically."""
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.rename(STATE_FILE)


def already_seen(hex_key: str, seen_keys: list) -> bool:
    """Fast check — compare first 8 and last 8 chars for O(1)-ish lookup."""
    fingerprint = hex_key[:8] + hex_key[-8:]
    return fingerprint in seen_keys


# ── Trufflehog feed ────────────────────────────────────────────────────────

def feed_trufflehog(source_line: str, linenum: int, context: str) -> None:
    """Append a finding context to the trufflehog feed file for deeper scanning."""
    entry = (
        f"# PoWo finding — line {linenum} of paste_box.txt\n"
        f"# {datetime.now(timezone.utc).isoformat()}\n"
        f"{context}\n"
        f"{'-' * 60}\n"
    )
    with open(TRUFFLEHOG_FEED, "a") as f:
        f.write(entry)


# ── Main scanner ───────────────────────────────────────────────────────────

def scan_chunk(lines: List[str], start_line: int, state: dict) -> int:
    """Scan a chunk of lines for private keys, derive addresses, check balances.
    Returns number of new findings in this chunk.
    """
    findings_this_chunk = 0
    seen_keys = state.setdefault("seen_keys", [])

    # Collect candidates first
    candidates: List[Tuple[str, str, int, str]] = []  # (hex_key, address, linenum, context)

    for i, line in enumerate(lines):
        linenum = start_line + i
        for match in HEX_PRIVKEY_RE.finditer(line):
            hex_key = match.group(2)
            if not hex_key or already_seen(hex_key, seen_keys):
                continue
            addr = hex_to_eth_address(hex_key)
            if addr is None:
                continue
            # Capture context: 100 chars around the key
            start = max(0, match.start() - 40)
            end = min(len(line), match.end() + 40)
            context = line[start:end].strip()
            candidates.append((hex_key, addr, linenum, context))
            # Track fingerprint to avoid re-processing
            seen_keys.append(hex_key[:8] + hex_key[-8:])

    if not candidates:
        return 0

    # Batch check balances
    for batch_start in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[batch_start:batch_start + BATCH_SIZE]
        addresses = [c[1] for c in batch]
        balances = check_balances_batch(addresses)

        for (hex_key, addr, linenum, context), bal in zip(batch, addresses):
            if bal not in balances:
                continue
            bal_info = balances[bal]
            eth = bal_info.get("eth", 0.0)
            error = bal_info.get("error")

            # Only report abandoned (balance ~$0.00 or below threshold)
            is_abandoned = error or eth < ABANDONED_THRESHOLD_ETH

            finding = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "address": addr,
                "hex_key_prefix": hex_key[:8] + "..." + hex_key[-4:],
                "balance_eth": round(eth, 8),
                "balance_usd": "$0.00",
                "abandoned": is_abandoned,
                "source_line": linenum,
                "source_context": context,
                "error": error,
            }

            # Display on screen
            tag = "💀 ABANDONED" if is_abandoned else "💎 ACTIVE"
            bal_str = f"${eth:,.2f}" if not error else "ERR"
            print(f"  {tag}  {addr}  {bal_str}  line:{linenum}  "
                  f"key:{hex_key[:6]}...{hex_key[-4:]}")

            # Write to findings JSONL
            with open(FINDINGS_JSONL, "a") as f:
                f.write(json.dumps(finding) + "\n")

            # Feed context to trufflehog
            if is_abandoned:
                feed_trufflehog(context, linenum, context)

            findings_this_chunk += 1

        # Rate-limit between batches
        if batch_start + BATCH_SIZE < len(candidates):
            time.sleep(1)

    return findings_this_chunk


def main() -> None:
    print("🦖 PoWo-Dinosaurs-Abandon-Wealth — PoW-era abandoned account scanner")
    print(f"   Source: {PASTE_BOX}")
    print(f"   Findings: {FINDINGS_JSONL}")
    print(f"   Trufflehog feed: {TRUFFLEHOG_FEED}")
    print(f"   RPC: {'✓ Alchemy' if ETH_RPC else '✗ NO RPC — balance checks disabled'}")
    print()

    if not PASTE_BOX.exists():
        print("[!] paste_box.txt not found — waiting for it to appear...")
        while not PASTE_BOX.exists():
            time.sleep(10)
        print("[✓] paste_box.txt appeared")

    state = load_state()
    last_offset = state.get("last_byte_offset", 0)
    print(f"   Resuming from byte offset {last_offset} "
          f"({state.get('total_found', 0)} found, {state.get('total_abandoned', 0)} abandoned)")

    # Continuous scanning loop
    while True:
        try:
            file_size = PASTE_BOX.stat().st_size
            if file_size <= last_offset:
                # Nothing new — wait and re-check
                time.sleep(15)
                continue

            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                  f"New data: {file_size - last_offset} bytes to scan "
                  f"(file size {file_size})")

            # Read new data in chunks
            with open(PASTE_BOX, "r", errors="replace") as f:
                f.seek(last_offset)
                chunk_buf: List[str] = []
                chunk_start_line = 0
                lines_read = 0

                for line in f:
                    chunk_buf.append(line)
                    lines_read += 1
                    if len(chunk_buf) >= CHUNK_LINES:
                        n = scan_chunk(chunk_buf, chunk_start_line, state)
                        state["total_found"] = state.get("total_found", 0) + n
                        # Approximate offset tracking
                        byte_consumed = sum(len(l) for l in chunk_buf)
                        last_offset += byte_consumed
                        state["last_byte_offset"] = last_offset
                        save_state(state)
                        if n > 0:
                            print(f"  → {n} findings in this chunk "
                                  f"({state['total_found']} total)")
                        chunk_buf.clear()
                        chunk_start_line += CHUNK_LINES

                # Process remaining lines
                if chunk_buf:
                    n = scan_chunk(chunk_buf, chunk_start_line, state)
                    state["total_found"] = state.get("total_found", 0) + n
                    byte_consumed = sum(len(l) for l in chunk_buf)
                    last_offset += byte_consumed
                    state["last_byte_offset"] = last_offset
                    save_state(state)
                    if n > 0:
                        print(f"  → {n} findings in final chunk "
                              f"({state['total_found']} total)")

            last_offset = file_size
            state["last_byte_offset"] = last_offset
            save_state(state)

            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Scan complete. {state['total_found']} total findings. "
                  f"Waiting for new data...")

        except KeyboardInterrupt:
            print("\n[!] Shutting down. State saved.")
            break
        except Exception as e:
            print(f"[!] Error: {e} — retrying in 30s...")
            time.sleep(30)

        time.sleep(15)

    # Final dump of abandoned accounts
    print(f"\n{'=' * 60}")
    print(f"💀 ABANDONED PoW ACCOUNTS ($0.00)")
    print(f"{'=' * 60}")
    if FINDINGS_JSONL.exists():
        abandoned = 0
        for line in FINDINGS_JSONL.read_text().splitlines():
            f = json.loads(line)
            if f.get("abandoned"):
                abandoned += 1
                print(f"  {f['address']}  $0.00  line:{f['source_line']}")
        print(f"\n  Total abandoned: {abandoned}")
    print(f"\n  Trufflehog feed ready at: {TRUFFLEHOG_FEED}")


if __name__ == "__main__":
    main()
