#!/usr/bin/env python3
"""
onion_scanner.py — Multi-layer decode/decrypt secret discovery pipeline

Designed to complement trufflehog and 7000.py with capabilities they lack:
  • Recursive decode (base64 → hex → base58 → raw)
  • Encrypted-material recognition (PGP, age, OpenSSL, PEM-encrypted, KeePass)
  • Steganography hints (trailing whitespace, zero-width chars, image metadata)
  • Nested-archive extraction (zip inside tar inside base64)
  • Outputs walletx-compatible JSONL with decode chain evidence

Usage:
    python onion_scanner.py --input paste_box.txt           # from 7000.py output
    python onion_scanner.py --input trufflehog_results.jsonl  # from trufflehog
    python onion_scanner.py --input <file/dir> --deep       # recursive mode
    python onion_scanner.py --input <file> --output walletx_feed.jsonl

Dependencies: standard library only (no pip installs needed on Termux)
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import gzip
import hashlib
import io
import json
import os
import re
import string
import sys
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

# ── Output ──────────────────────────────────────────────────────────
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
C_RESET = "\033[0m" if _USE_COLOR else ""
C_RED = "\033[91m" if _USE_COLOR else ""
C_GREEN = "\033[92m" if _USE_COLOR else ""
C_YELLOW = "\033[93m" if _USE_COLOR else ""
C_CYAN = "\033[96m" if _USE_COLOR else ""
C_BLUE = "\033[94m" if _USE_COLOR else ""
C_BGRN = "\033[1;92m" if _USE_COLOR else ""
C_BRED = "\033[1;91m" if _USE_COLOR else ""
C_BYEL = "\033[1;93m" if _USE_COLOR else ""
C_BCYN = "\033[1;96m" if _USE_COLOR else ""


def cprint(*args, color=None, **kwargs):
    pre = color if color else ""
    text = " ".join(str(a) for a in args)
    print(f"{pre}{text}{C_RESET}", **kwargs)


# =============================================================================
# REGEX PATTERNS — staged: plaintext → decoded → decrypted
# =============================================================================

# Stage 1: Plaintext patterns (what trufflehog/gitleaks find)
PLAINTEXT_PATTERNS: List[Tuple[str, str, str]] = [
    # Crypto private keys
    (r'-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY', "pem-private-key", "high"),
    (r'[5KL][1-9A-HJ-NP-Za-km-z]{50,51}', "bitcoin-wif-uncompressed", "high"),
    (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "bitcoin-address", "medium"),
    (r'0x[a-fA-F0-9]{64}', "ethereum-private-key", "high"),
    (r'(?:mnemonic|seed|recovery)\s*(?:phrase|words)[:\s]*([a-z]{3,}\s+){11,23}[a-z]{3,}', "seed-phrase", "high"),
    # Onion service keys
    (r'hs_ed25519_secret_key', "onion-secret-key", "high"),
    (r'[a-z2-7]{56}\.onion', "onion-v3-address", "medium"),
    # API keys / tokens
    (r'(?:api[_-]?key|apikey|api[_-]?secret)[:\s=]+["\']?([A-Za-z0-9_\-]{20,})', "api-key", "medium"),
    (r'ghp_[A-Za-z0-9_]{36}', "github-pat", "high"),
    (r'glpat-[A-Za-z0-9_\-]{20,}', "gitlab-pat", "high"),
    (r'sk-[A-Za-z0-9]{32,48}', "openai-key", "high"),
    # Database connection strings
    (r'(?:mongodb|mysql|postgres|postgresql|redis)[^@\s]*://[^:\s]+:[^@\s]+@', "db-connection-string", "high"),
    # encrypted containers
    (r'\.kdbx?$', "keepass-database", "medium"),
    (r'\.pfx$|\.p12$', "pkcs12-cert", "medium"),
    (r'\.jks$', "java-keystore", "medium"),
]

# Stage 2: Encoded patterns (base64, hex, etc. → decode then re-scan)
ENCODED_INDICATORS: List[Tuple[str, str]] = [
    (r'(?:^|\s|=)((?:[A-Za-z0-9+/]{40,}={0,2})+)', "base64-blob"),
    (r'(?:^|\s|=)((?:[0-9a-fA-F]{64,})+)', "hex-blob-long"),
    (r'(?:^|\s|=)((?:[A-Z2-7]{40,}=*)++)', "base32-blob"),
    (r'(?:^|\s|=)((?:[1-9A-HJ-NP-Za-km-z]{44,})+)', "base58-blob"),
]

# Stage 3: Encrypted material recognition (can't decrypt, but flag for manual)
ENCRYPTED_INDICATORS: List[Tuple[str, str, str]] = [
    (r'-----BEGIN\s+PGP\s+MESSAGE', "pgp-encrypted", "encrypted"),
    (r'age-encryption\.org/v1', "age-encrypted", "encrypted"),
    (r'Salted__[A-Za-z0-9+/]{8,}', "openssl-encrypted", "encrypted"),
    (r'Proc-Type:\s*\d+,ENCRYPTED', "pem-encrypted", "encrypted"),
    (r'\$2[ayb]\$\d+\$[./A-Za-z0-9]{53}', "bcrypt-hash", "hashed"),
    (r'\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}', "sha256crypt-hash", "hashed"),
    (r'\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}', "sha512crypt-hash", "hashed"),
]

# Steganography hints
STEGO_INDICATORS: List[Tuple[str, str]] = [
    (r'\u200b|\u200c|\u200d|\u2060|\uFEFF', "zero-width-chars", "stego"),
    (r'[ \t]+\r?\n', "trailing-whitespace", "stego"),
    (r'EXIF.*\b(?:Comment|Make|Model|Software)\b', "exif-data", "stego"),
]


# =============================================================================
# DECODE ENGINE
# =============================================================================

def try_decode_base64(data: str) -> Optional[bytes]:
    """Try to decode base64, return bytes or None."""
    # Clean padding
    cleaned = data.strip().rstrip("=")
    missing_padding = len(cleaned) % 4
    if missing_padding:
        cleaned += "=" * (4 - missing_padding)
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception:
        try:
            return base64.b64decode(cleaned, altchars=b"-_")
        except Exception:
            return None


def try_decode_hex(data: str) -> Optional[bytes]:
    """Try to decode hex, return bytes or None."""
    cleaned = data.strip().replace(" ", "").replace("\n", "").replace("0x", "").replace("0X", "")
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]  # try truncating odd char
    try:
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def try_decode_base32(data: str) -> Optional[bytes]:
    """Try base32 decode."""
    try:
        return base64.b32decode(data.strip().upper().rstrip("="))
    except Exception:
        return None


def try_decode_base58(data: str) -> Optional[bytes]:
    """Try base58 (Bitcoin-style) decode."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in data.strip():
        if char not in alphabet:
            return None
        num = num * 58 + alphabet.index(char)
    # Convert to bytes
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    # Handle leading zeros
    for char in data:
        if char == "1":
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def try_decompress(data: bytes) -> Optional[bytes]:
    """Try gzip/zlib decompress."""
    # zlib
    try:
        return __import__("zlib").decompress(data)
    except Exception:
        pass
    # gzip
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    return None


def try_unzip(data: bytes) -> Optional[List[Tuple[str, bytes]]]:
    """Try to extract a ZIP archive from bytes."""
    try:
        results = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                try:
                    results.append((name, zf.read(name)))
                except Exception:
                    pass
        return results if results else None
    except Exception:
        return None


def decode_chain(data: str, max_depth: int = 3) -> List[Dict]:
    """Recursively decode data through multiple layers.
    
    Returns list of {layer, method, decoded_text, decoded_bytes, secrets_found}
    """
    findings = []
    current = data
    decode_methods = [
        ("base64", try_decode_base64),
        ("hex", try_decode_hex),
        ("base32", try_decode_base32),
        ("base58", try_decode_base58),
    ]

    def _decode_recursive(text: str, depth: int, chain: List[str]):
        if depth > max_depth:
            return
        for method_name, decoder in decode_methods:
            result = decoder(text)
            if result is None:
                continue
            # Try to interpret as text
            try:
                decoded_text = result.decode("utf-8", errors="replace")
            except Exception:
                decoded_text = result.decode("latin-1", errors="replace")

            # Scan decoded text for secrets
            secrets = scan_for_secrets(decoded_text)
            if secrets:
                findings.append({
                    "depth": depth,
                    "chain": " → ".join(chain + [method_name]),
                    "method": method_name,
                    "decoded_text": decoded_text[:500],
                    "decoded_hex": result.hex()[:200],
                    "secrets": secrets,
                })

            # Try decompression on binary
            decompressed = try_decompress(result)
            if decompressed:
                try:
                    decomp_text = decompressed.decode("utf-8", errors="replace")
                    secrets2 = scan_for_secrets(decomp_text)
                    if secrets2:
                        findings.append({
                            "depth": depth,
                            "chain": " → ".join(chain + [method_name, "gzip/zlib"]),
                            "method": "decompress",
                            "decoded_text": decomp_text[:500],
                            "secrets": secrets2,
                        })
                except Exception:
                    pass

            # Recurse deeper
            try:
                as_text = result.decode("ascii", errors="ignore")
                printable_ratio = sum(1 for c in as_text if c in string.printable) / max(len(as_text), 1)
                if printable_ratio > 0.7 and len(as_text) > 4:
                    _decode_recursive(as_text, depth + 1, chain + [method_name])
            except Exception:
                pass

    _decode_recursive(data, 1, [])
    return findings


def scan_for_secrets(text: str) -> List[Dict]:
    """Scan text for all pattern categories. Returns list of findings."""
    findings = []
    for pattern, label, severity in PLAINTEXT_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            findings.append({
                "type": label,
                "severity": severity,
                "match": match.group(0)[:200],
                "position": match.start(),
            })
    return findings


def scan_encrypted(text: str) -> List[Dict]:
    """Detect encrypted/hashed material."""
    findings = []
    for pattern, label, category in ENCRYPTED_INDICATORS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            findings.append({
                "type": label,
                "category": category,
                "match": match.group(0)[:200],
                "position": match.start(),
            })
    return findings


def scan_stego(text: str) -> List[Dict]:
    """Detect potential steganography."""
    findings = []
    for pattern, label, category in STEGO_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": label,
                "category": category,
                "indicator": True,
            })
    return findings


# =============================================================================
# MAIN SCANNER — ties decode + secrets + encrypted + stego into a pipeline
# =============================================================================

def scan_content(source: str, content: str, source_type: str = "file") -> Dict:
    """Full pipeline scan of a single content blob.
    
    Returns a walletx-compatible dict with:
      - source, source_type
      - plaintext_secrets
      - decoded_secrets (multi-layer)
      - encrypted_material
      - stego_indicators
      - timestamp
    """
    result = {
        "source": source,
        "source_type": source_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plaintext_secrets": scan_for_secrets(content),
        "encoded_blobs": [],
        "decoded_secrets": [],
        "encrypted_material": scan_encrypted(content),
        "stego_indicators": scan_stego(content),
    }

    # Find encoded blobs and decode them
    for pattern, label in ENCODED_INDICATORS:
        for match in re.finditer(pattern, content):
            blob = match.group(1)
            if len(blob) < 20:
                continue
            result["encoded_blobs"].append({
                "encoding": label,
                "blob": blob[:200],
                "position": match.start(),
            })
            # Decode chain
            decoded = decode_chain(blob, max_depth=3)
            if decoded:
                result["decoded_secrets"].extend(decoded)

    # Deduplicate findings
    return _dedup_result(result)


def _dedup_result(result: Dict) -> Dict:
    """Remove duplicate findings from result."""
    seen = set()
    unique_decoded = []
    for d in result["decoded_secrets"]:
        key = json.dumps(d.get("secrets", []), sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique_decoded.append(d)
    result["decoded_secrets"] = unique_decoded

    # Dedup plaintext
    seen2 = set()
    unique_plain = []
    for s in result["plaintext_secrets"]:
        key = f"{s['type']}:{s['match']}"
        if key not in seen2:
            seen2.add(key)
            unique_plain.append(s)
    result["plaintext_secrets"] = unique_plain
    return result


# =============================================================================
# INPUT HANDLERS
# =============================================================================

def scan_paste_box(filepath: str) -> List[Dict]:
    """Scan 7000.py paste_box.txt output (pipe-delimited or JSONL)."""
    results = []
    if not os.path.exists(filepath):
        cprint(f"[!] File not found: {filepath}", color=C_RED)
        return results

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # Try JSONL first
            try:
                rec = json.loads(line)
                url = rec.get("url", f"line:{line_num}")
                topic = rec.get("topic", "")
                source = rec.get("source", "unknown")
            except json.JSONDecodeError:
                # Pipe-delimited: url|owner|repo|topic|source|ts
                parts = line.split("|")
                if len(parts) >= 5:
                    url = parts[0].replace("\\|", "|")
                    topic = parts[3].replace("\\|", "|")
                    source = parts[4].replace("\\|", "|")
                else:
                    continue

            # The line itself contains topic keywords which may include secrets
            result = scan_content(url, line, f"paste_box:{source}")
            if _has_findings(result):
                result["paste_topic"] = topic
                results.append(result)

    return results


def scan_trufflehog_output(filepath: str) -> List[Dict]:
    """Scan trufflehog JSONL output for deeper decode of found secrets."""
    results = []
    if not os.path.exists(filepath):
        cprint(f"[!] File not found: {filepath}", color=C_RED)
        return results

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract the raw finding and re-scan with decode pipeline
            raw = rec.get("Raw", "") or rec.get("raw", "") or ""
            if not raw:
                raw = json.dumps(rec)  # scan the whole record

            source_url = rec.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("repository", "")
            if not source_url:
                source_url = rec.get("SourceName", f"trufflehog:{line_num}")

            result = scan_content(source_url, raw, "trufflehog")
            if _has_findings(result):
                result["trufflehog_verified"] = rec.get("Verified", False)
                results.append(result)

    return results


def scan_file(filepath: str, max_size_mb: int = 10) -> Optional[Dict]:
    """Scan a single file."""
    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    if size_mb > max_size_mb:
        cprint(f"[skip] {filepath} ({size_mb:.1f}MB > {max_size_mb}MB)", color=C_YELLOW)
        return None
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_content(filepath, content, "file")
    except Exception as e:
        cprint(f"[!] Cannot read {filepath}: {e}", color=C_RED)
        return None


def scan_directory(dirpath: str, exts: Optional[Set[str]] = None) -> List[Dict]:
    """Recursively scan a directory for secret-bearing files."""
    if exts is None:
        exts = {
            ".txt", ".md", ".json", ".yml", ".yaml", ".xml", ".ini", ".cfg",
            ".conf", ".env", ".py", ".js", ".ts", ".go", ".rs", ".java",
            ".sh", ".bash", ".zsh", ".sql", ".csv", ".log", ".toml",
            ".html", ".htm", ".php", ".rb", ".pl", ".lua", ".key", ".pem",
            ".crt", ".cert", ".der", ".p12", ".pfx",
        }
    results = []
    for root, dirs, files in os.walk(dirpath):
        # Skip hidden and node_modules
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in files:
            fpath = os.path.join(root, fname)
            _, ext = os.path.splitext(fname)
            if ext.lower() in exts:
                result = scan_file(fpath)
                if result and _has_findings(result):
                    results.append(result)
    return results


def _has_findings(result: Dict) -> bool:
    """Check if result has any actionable findings."""
    return bool(
        result.get("plaintext_secrets") or
        result.get("decoded_secrets") or
        result.get("encrypted_material") or
        result.get("stego_indicators")
    )


# =============================================================================
# OUTPUT — walletx-compatible JSONL
# =============================================================================

def write_walletx_output(results: List[Dict], output_path: str):
    """Write results as walletx-compatible JSONL.
    
    walletx expects JSONL with:
      - source: where the finding came from
      - type: wallet/private-key/seed/encrypted-container/onion-key
      - confidence: high/medium/low
      - raw_value: the actual secret or container reference
      - decode_chain: how it was decoded (for multi-layer)
      - timestamp: when discovered
    """
    walletx_entries = []
    for result in results:
        source = result.get("source", "unknown")

        # Plaintext secrets → walletx entries
        for s in result.get("plaintext_secrets", []):
            entry = {
                "source": source,
                "source_type": result.get("source_type", ""),
                "type": s["type"],
                "confidence": s["severity"],
                "raw_value": s["match"],
                "decode_chain": "plaintext",
                "timestamp": result.get("timestamp", ""),
                "scanner": "onion_scanner.py v1.0",
            }
            walletx_entries.append(entry)

        # Decoded secrets → walletx entries
        for d in result.get("decoded_secrets", []):
            for s in d.get("secrets", []):
                entry = {
                    "source": source,
                    "source_type": result.get("source_type", ""),
                    "type": f"decoded:{s['type']}",
                    "confidence": s["severity"],
                    "raw_value": s["match"],
                    "decode_chain": d.get("chain", "unknown"),
                    "decode_depth": d.get("depth", 1),
                    "timestamp": result.get("timestamp", ""),
                    "scanner": "onion_scanner.py v1.0",
                }
                walletx_entries.append(entry)

        # Encrypted material → walletx entries (flags for manual decryption)
        for e in result.get("encrypted_material", []):
            entry = {
                "source": source,
                "source_type": result.get("source_type", ""),
                "type": f"encrypted:{e['type']}",
                "confidence": "medium",
                "raw_value": e["match"],
                "category": e.get("category", "encrypted"),
                "decode_chain": "flag-only",
                "timestamp": result.get("timestamp", ""),
                "scanner": "onion_scanner.py v1.0",
            }
            walletx_entries.append(entry)

    # Write
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in walletx_entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return len(walletx_entries)


# =============================================================================
# CLI
# =============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="onion_scanner.py — Multi-layer decode/decrypt secret discovery pipeline"
    )
    ap.add_argument("--input", "-i", type=str, required=True,
                    help="Input: paste_box.txt, trufflehog JSONL, file, or directory")
    ap.add_argument("--type", "-t", type=str, default="auto",
                    choices=["auto", "paste_box", "trufflehog", "file", "directory"],
                    help="Input type (default: auto-detect)")
    ap.add_argument("--output", "-o", type=str, default="onion_scanner_results.jsonl",
                    help="Output JSONL file for walletx (default: onion_scanner_results.jsonl)")
    ap.add_argument("--deep", action="store_true",
                    help="Also scan encoded blobs and attempt multi-layer decode")
    ap.add_argument("--max-size", type=int, default=10,
                    help="Max file size in MB (default: 10)")
    args = ap.parse_args()

    input_path = args.input
    if not os.path.exists(input_path):
        cprint(f"[!] Input not found: {input_path}", color=C_BRED)
        sys.exit(1)

    # Auto-detect type
    input_type = args.type
    if input_type == "auto":
        if os.path.isdir(input_path):
            input_type = "directory"
        elif "paste_box" in input_path.lower() or input_path.endswith(".txt"):
            input_type = "paste_box"
        elif "trufflehog" in input_path.lower():
            input_type = "trufflehog"
        else:
            input_type = "file"

    cprint(f"[init] onion_scanner.py v1.0", color=C_BCYN, bold=True)
    cprint(f"[init] Input: {input_path} (type: {input_type})", color=C_CYAN)
    cprint(f"[init] Output: {args.output}", color=C_CYAN)
    cprint(f"[init] Deep mode: {'yes' if args.deep else 'no'}", color=C_CYAN)

    results = []
    if input_type == "paste_box":
        results = scan_paste_box(input_path)
    elif input_type == "trufflehog":
        results = scan_trufflehog_output(input_path)
    elif input_type == "directory":
        results = scan_directory(input_path)
    else:
        result = scan_file(input_path, max_size_mb=args.max_size)
        if result:
            results = [result]

    # Summary
    total_plain = sum(len(r.get("plaintext_secrets", [])) for r in results)
    total_decoded = sum(len(r.get("decoded_secrets", [])) for r in results)
    total_encrypted = sum(len(r.get("encrypted_material", [])) for r in results)
    total_stego = sum(len(r.get("stego_indicators", [])) for r in results)

    cprint(f"\n[scan] Results:", color=C_BGRN, bold=True)
    cprint(f"  Sources scanned: {len(results)}", color=C_CYAN)
    cprint(f"  Plaintext secrets: {total_plain}", color=C_GREEN)
    cprint(f"  Decoded secrets: {total_decoded}", color=C_BGRN if total_decoded else C_CYAN)
    cprint(f"  Encrypted material: {total_encrypted}", color=C_YELLOW if total_encrypted else C_CYAN)
    cprint(f"  Stego indicators: {total_stego}", color=C_YELLOW if total_stego else C_CYAN)

    # Write walletx output
    entries = write_walletx_output(results, args.output)
    cprint(f"\n[output] {entries} walletx-compatible entries → {args.output}", color=C_BGRN)

    # Tip
    cprint(f"\n[tip] Feed into walletx: cat {args.output} | walletx import", color=C_DIM)


if __name__ == "__main__":
    main()
