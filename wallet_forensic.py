#!/usr/bin/env python3
"""
WalletX — Forensic Wallet Examiner (LIVE production, no mocks, no truncation).

Stability / UX:
  - Does NOT auto-flip pages while you navigate
  - Auto-refresh ONLY after IDLE_REFRESH_SEC of no input (default 120s)
  - Free-run rotates dossier focus across all ranks (not stuck on #1)
  - Refresh always pins FORENSIC DOSSIER rank #N of M at top of screen
  - Rank / Funded / Portfolio facts are live-rescored from balance cache every paint
  - Touch/key activity resets the idle timer — scroll freely without repaint fights
  - Full private keys / seeds / WIFs / sources always printed complete (wrapped, never ellipsized)
  - Highest balance always on top; focus pinned across soft re-ranks while you navigate
  - Live RPC is background-only; UI never blocks on it
  - All paint exceptions caught and shown on-screen

Forensics (live, real data only):
  - secp256k1 range + entropy + quality scoring via crypto_iq
  - Full address derivation (BTC/LTC/DOGE + all EVM + SOL when available)
  - Reverse-link funded ADDR hits back to HEX/WIF/SEED from scanner memory
  - Compressed pubkey, keccak fingerprint, WIF export, BIP39 word-count check
  - Export focused dossier to ~/forensic_exports/ (full JSON, no truncation)

Usage:
    walletx                         # funded-only forensic (stable, idle-refresh 120s)
    walletforensic                  # all wallets, interactive
    walletforensic --once --cached  # one snapshot
    walletforensic --index 2        # jump to rank #3
    walletforensic --idle-sec 120   # custom idle before auto-refresh
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import sys
import termios
import time
import traceback
import tty
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

HOME = os.path.expanduser("~")
sys.path.insert(0, HOME)

import logging
logging.getLogger().setLevel(logging.WARNING)
for _name in ("crypto_scanner", "urllib3", "requests"):
    logging.getLogger(_name).setLevel(logging.WARNING)

import wallet_view as wv  # noqa: E402

try:
    import crypto_iq as _iq  # noqa: E402
except Exception:
    _iq = None

try:
    import crypto_scanner as _cs  # noqa: E402
except Exception:
    _cs = None

try:
    import base58 as _base58  # noqa: E402
except Exception:
    _base58 = None

try:
    import ecdsa as _ecdsa  # noqa: E402
except Exception:
    _ecdsa = None

try:
    from mnemonic import Mnemonic as _Mnemonic  # noqa: E402
except Exception:
    _Mnemonic = None

BOLD = wv.BOLD
DIM = wv.DIM
GREEN = wv.GREEN
YELLOW = wv.YELLOW
CYAN = wv.CYAN
RESET = wv.RESET
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BLUE = "\033[94m"

# HARD freeze while interacting:
#   - Any key/touch resets the idle timer
#   - ZERO full-screen repaint / gather / live-RPC while idle_left > 0
#   - After DEFAULT_IDLE_REFRESH_SEC of silence, free-run refresh until next touch
DEFAULT_IDLE_REFRESH_SEC = 120.0
DEFAULT_TICK_SEC = 0.35         # snappy key poll only (never repaints by itself)
DEFAULT_BATCH = 24
LEADERBOARD_N = 14
DETAIL_ADDRS = 0                # 0 = show ALL derived addresses (no truncation)
GATHER_SEC = 120                # full memory re-scan only on idle free-run
PAINT_MIN_SEC = 0.0             # paint on demand (nav / idle free-run); never spin
IDLE_FREE_RUN_TICK = 8.0        # while fully idle, refresh cadence (seconds)
FREE_RUN_ROTATE = True          # cycle dossier focus across leaderboard while free-running
COUNTDOWN_UPDATE_SEC = 30.0    # status-line only tick (no full clear) during freeze
MEMORY_DEEP_BYTES = 6_000_000  # deeper reverse-link scan for funded addrs
EXPORT_DIR = os.path.join(HOME, "forensic_exports")
WRAP_WIDTH = 70                 # visual wrap only — full content always printed

# ── small helpers ──────────────────────────────────────────────────

def _age_str(ts) -> str:
    try:
        t = float(ts or 0)
    except (TypeError, ValueError):
        return "?"
    if t <= 0:
        return "never"
    age = max(0.0, time.time() - t)
    if age < 60:
        return f"{int(age)}s"
    if age < 3600:
        return f"{int(age // 60)}m"
    if age < 86400:
        return f"{int(age // 3600)}h"
    return f"{int(age // 86400)}d"


def _bar(frac: float, width: int = 16) -> str:
    frac = max(0.0, min(1.0, float(frac)))
    filled = int(round(frac * width))
    return f"{GREEN}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"


def _hide_cursor():
    try:
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
    except Exception:
        pass


def _show_cursor():
    try:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
    except Exception:
        pass


def _safe_clear():
    """Hard clear + drop scrollback so Termux lands at top of frame."""
    try:
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()
    except Exception:
        pass


def _home_cursor():
    """Force viewport to top-left after paint (walk-by: rank #N always visible)."""
    try:
        sys.stdout.write("\033[H\033[1;1H")
        sys.stdout.flush()
    except Exception:
        pass


def _visible_len(s: str) -> int:
    out = []
    i = 0
    n = len(s or "")
    while i < n:
        if s[i] == "\033" and i + 1 < n and s[i + 1] == "[":
            i += 2
            while i < n and not (64 <= ord(s[i]) <= 126):
                i += 1
            i += 1
            continue
        out.append(s[i])
        i += 1
    return len(out)


def _term_size():
    try:
        import shutil
        c, r = shutil.get_terminal_size((80, 24))
        return max(40, int(c)), max(12, int(r))
    except Exception:
        return 80, 24


def _fit_frame(lines: list, rows: int = 0, cols: int = 0) -> str:
    """Clip paint lines to terminal height. First lines (dossier rank) stay."""
    tcols, trows = _term_size()
    if cols <= 0:
        cols = tcols
    if rows <= 0:
        rows = trows
    budget = max(8, rows - 1)
    body = []
    used = 0
    clipped = False
    for line in lines:
        vis = max(1, _visible_len(line))
        need = max(1, (vis + cols - 1) // cols)
        if used + need > budget - 1 and body:
            clipped = True
            break
        if used + need > budget:
            clipped = True
            break
        body.append(line)
        used += need
    if clipped:
        notice = (
            f"{DIM}  … +more clipped — top pinned (rank #) · "
            f"n/p scroll dossiers · a full analyze{RESET}"
        )
        while used >= budget and body:
            last = body.pop()
            used -= max(1, (_visible_len(last) + cols - 1) // cols)
        if used < budget:
            body.append(notice)
            used += 1
    while used < budget:
        body.append("")
        used += 1
    return "\n".join(body)


def _emit_frame(lines: list, pin_top: bool = True) -> None:
    """Clear, write height-capped frame, home cursor to top."""
    _safe_clear()
    frame = _fit_frame(lines) if pin_top else "\n".join(lines)
    try:
        sys.stdout.write(frame)
        if not frame.endswith("\n"):
            sys.stdout.write("\n")
        if pin_top:
            _home_cursor()
        sys.stdout.flush()
    except Exception:
        try:
            print("\n".join(lines))
            sys.stdout.flush()
        except Exception:
            pass


def _print_full(label: str, value: str, indent: str = "  ", color: str = ""):
    """Print label + FULL value, wrapped for terminal width. NEVER truncates."""
    val = "" if value is None else str(value)
    prefix = f"{indent}{BOLD}{label}{RESET} "
    pad = " " * (len(indent) + len(label) + 1)
    if not val:
        print(f"{prefix}{DIM}(empty){RESET}")
        return
    first_budget = max(8, WRAP_WIDTH)
    if len(val) <= first_budget:
        print(f"{prefix}{color}{val}{RESET if color else ''}")
        return
    print(f"{prefix}{color}{val[:first_budget]}{RESET if color else ''}")
    rest = val[first_budget:]
    while rest:
        chunk = rest[: WRAP_WIDTH + 8]
        rest = rest[WRAP_WIDTH + 8 :]
        print(f"{pad}{color}{chunk}{RESET if color else ''}")


def _leaderboard_label(key: str, max_vis: int = 40) -> str:
    """Leaderboard row only — visual fit. Full key always in dossier."""
    k = key or ""
    if len(k) <= max_vis:
        return k
    keep = max(8, (max_vis - 1) // 2)
    return k[:keep] + "…" + k[-keep:]


# ── forensic crypto analysis (LIVE) ────────────────────────────────

def _hex_norm(h: str) -> str:
    if not h:
        return ""
    return str(h).strip().lower().removeprefix("0x")


def _priv_bytes_from_hex(h: str) -> Optional[bytes]:
    hx = _hex_norm(h)
    if len(hx) != 64:
        return None
    try:
        b = bytes.fromhex(hx)
    except ValueError:
        return None
    if len(b) != 32:
        return None
    return b


def _compressed_pub_hex(priv: bytes) -> Optional[str]:
    if _ecdsa is None:
        return None
    try:
        sk = _ecdsa.SigningKey.from_string(priv, curve=_ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        raw = vk.to_string()
        x, y = raw[:32], raw[32:]
        prefix = b"\x02" if int.from_bytes(y, "big") % 2 == 0 else b"\x03"
        return (prefix + x).hex()
    except Exception:
        return None


def _uncompressed_pub_hex(priv: bytes) -> Optional[str]:
    if _ecdsa is None:
        return None
    try:
        sk = _ecdsa.SigningKey.from_string(priv, curve=_ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return "04" + vk.to_string().hex()
    except Exception:
        return None


def _wif_from_priv(priv: bytes, compressed: bool = True, mainnet: bool = True) -> Optional[str]:
    if _base58 is None:
        return None
    try:
        ver = b"\x80" if mainnet else b"\xef"
        payload = ver + priv + (b"\x01" if compressed else b"")
        return _base58.b58encode_check(payload).decode()
    except Exception:
        return None


def _keccak_hex(data: bytes) -> Optional[str]:
    try:
        if _iq is not None:
            return _iq.keccak_256(data).hex()
    except Exception:
        pass
    try:
        if _cs is not None and hasattr(_cs, "keccak_256"):
            return _cs.keccak_256(data).hex()
    except Exception:
        pass
    try:
        from Crypto.Hash import keccak  # type: ignore
        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest().hex()
    except Exception:
        return None


def analyze_hex_key(hex_key: str) -> Dict[str, Any]:
    """Full LIVE forensic dossier for a 64-char hex private key. No mocks."""
    out: Dict[str, Any] = {
        "kind": "HEX",
        "raw": hex_key or "",
        "hex": _hex_norm(hex_key),
        "valid": False,
        "reason": "",
        "quality": 0.0,
        "entropy": 0.0,
        "secp_ok": False,
        "banned_test": False,
        "n_int": None,
        "pub_compressed": None,
        "pub_uncompressed": None,
        "wif_compressed": None,
        "wif_uncompressed": None,
        "eth_address": None,
        "addresses": {},
        "keccak_priv_fp": None,
        "sha256_priv_fp": None,
        "backends": {},
    }
    hx = out["hex"]
    if not hx:
        out["reason"] = "empty"
        return out
    if len(hx) != 64:
        out["reason"] = f"bad_len:{len(hx)}"
        return out

    if _iq is not None:
        try:
            out["backends"] = _iq.backend_info()
            out["entropy"] = float(_iq.shannon_entropy(hx))
            ok, reason, score = _iq.validate_hex_privkey(hx)
            out["valid"] = bool(ok)
            out["reason"] = str(reason)
            out["quality"] = float(score)
            if reason == "banned_test_key":
                out["banned_test"] = True
        except Exception as exc:
            out["reason"] = f"iq_err:{exc}"
    else:
        out["reason"] = "crypto_iq_unavailable"

    priv = _priv_bytes_from_hex(hx)
    if priv is None:
        out["reason"] = out["reason"] or "parse_fail"
        return out

    n = int.from_bytes(priv, "big")
    out["n_int"] = str(n)
    if _iq is not None:
        try:
            sok, sreason = _iq.validate_secp256k1_priv(priv)
            out["secp_ok"] = bool(sok)
            if not sok and not out["reason"]:
                out["reason"] = sreason
        except Exception:
            pass
    else:
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        out["secp_ok"] = 0 < n < N

    out["sha256_priv_fp"] = hashlib.sha256(priv).hexdigest()
    out["keccak_priv_fp"] = _keccak_hex(priv)
    out["pub_compressed"] = _compressed_pub_hex(priv)
    out["pub_uncompressed"] = _uncompressed_pub_hex(priv)
    out["wif_compressed"] = _wif_from_priv(priv, compressed=True)
    out["wif_uncompressed"] = _wif_from_priv(priv, compressed=False)

    addrs: Dict[str, str] = {}
    if _cs is not None and out["secp_ok"]:
        try:
            raw = _cs.priv_to_addresses(priv) or {}
            addrs.update({str(k).lower(): str(v) for k, v in raw.items() if v})
        except Exception:
            pass
        # If ETH missing (banned test key), still derive for forensic display
        if "eth" not in addrs and _ecdsa is not None:
            try:
                sk = _ecdsa.SigningKey.from_string(priv, curve=_ecdsa.SECP256k1)
                pub = sk.get_verifying_key().to_string()
                kh = _keccak_hex(pub)
                if kh:
                    body = kh[-40:]
                    hashed = _keccak_hex(body.encode("ascii"))
                    if hashed:
                        eth = "0x" + "".join(
                            c.upper() if hashed[i] in "89abcdef" else c.lower()
                            for i, c in enumerate(body.lower())
                        )
                    else:
                        eth = "0x" + body
                    addrs["eth"] = eth
                    for c in ("matic", "avax", "bnb", "base", "arb", "op", "monad"):
                        addrs.setdefault(c, eth)
            except Exception:
                pass
    out["addresses"] = addrs
    out["eth_address"] = addrs.get("eth")
    if out["secp_ok"] and not out["banned_test"]:
        out["valid"] = out["valid"] or bool(addrs)
    return out


def analyze_wif(wif: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "kind": "WIF",
        "raw": wif or "",
        "valid": False,
        "reason": "",
        "hex": None,
        "compressed": None,
        "mainnet": None,
        "nested": None,
    }
    if not wif:
        out["reason"] = "empty"
        return out
    if _iq is not None:
        try:
            ok, reason = _iq.validate_wif(wif)
            out["valid"] = bool(ok)
            out["reason"] = str(reason)
        except Exception as exc:
            out["reason"] = f"iq_err:{exc}"
    priv = None
    if _cs is not None:
        try:
            priv = _cs.wif_to_priv_bytes(wif)
        except Exception:
            priv = None
    if priv is None and _base58 is not None:
        try:
            decoded = _base58.b58decode_check(wif)
            if len(decoded) in (33, 34):
                out["mainnet"] = decoded[0] == 0x80
                out["compressed"] = len(decoded) == 34 and decoded[-1] == 0x01
                priv = decoded[1:33]
        except Exception as exc:
            out["reason"] = out["reason"] or f"b58:{exc}"
    if priv is None:
        return out
    out["hex"] = priv.hex()
    out["nested"] = analyze_hex_key(priv.hex())
    out["valid"] = bool(out["nested"].get("secp_ok"))
    if out["valid"] and not out["reason"]:
        out["reason"] = "ok"
    return out


def analyze_seed(seed: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "kind": "SEED",
        "raw": seed or "",
        "valid": False,
        "reason": "",
        "word_count": 0,
        "words": [],
        "language": None,
        "nested_hex": None,
        "addresses": {},
    }
    s = (seed or "").strip()
    if not s:
        out["reason"] = "empty"
        return out
    words = s.split()
    out["words"] = list(words)
    out["word_count"] = len(words)
    if _Mnemonic is not None:
        try:
            m = _Mnemonic("english")
            out["language"] = "english"
            ok = bool(m.check(s))
            out["valid"] = ok
            out["reason"] = "ok" if ok else "bip39_checksum_fail"
            if ok:
                seed_bytes = m.to_seed(s)
                master = seed_bytes[:32]
                out["nested_hex"] = analyze_hex_key(master.hex())
                if _cs is not None:
                    try:
                        out["addresses"] = _cs.seed_to_addresses(s) or {}
                    except Exception:
                        out["addresses"] = (out["nested_hex"] or {}).get("addresses") or {}
        except Exception as exc:
            out["reason"] = f"mnemonic_err:{exc}"
    else:
        out["reason"] = "mnemonic_lib_unavailable"
        if out["word_count"] in (12, 15, 18, 21, 24):
            out["reason"] = "word_count_ok_lib_missing"
    return out


def forensic_bundle_for_wallet(w: dict) -> Dict[str, Any]:
    """Build complete forensic analysis for a wallet dict (LIVE)."""
    typ = (w.get("type") or "?").upper()
    key = w.get("key") or ""
    bundle: Dict[str, Any] = {
        "type": typ,
        "key_full": key,
        "source_full": w.get("source") or "",
        "timestamp": w.get("timestamp") or "",
        "hit_boost": float(w.get("_hit_boost") or 0.0),
        "linked_hex_full": w.get("_linked_hex") or "",
        "linked_wif_full": w.get("_linked_wif") or "",
        "linked_seed_full": w.get("_linked_seed") or "",
        "analysis": None,
        "linked_analysis": [],
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if typ == "HEX":
        bundle["analysis"] = analyze_hex_key(key)
    elif typ == "WIF":
        bundle["analysis"] = analyze_wif(key)
    elif typ == "SEED":
        bundle["analysis"] = analyze_seed(key)
    elif typ == "ADDR":
        bundle["analysis"] = {
            "kind": "ADDR",
            "raw": key,
            "chains": list(w.get("_chains") or []),
            "note": "address-only hit; linked material below if reverse-matched",
        }
        if w.get("_linked_hex"):
            bundle["linked_analysis"].append(analyze_hex_key(w["_linked_hex"]))
        if w.get("_linked_wif"):
            bundle["linked_analysis"].append(analyze_wif(w["_linked_wif"]))
        if w.get("_linked_seed"):
            bundle["linked_analysis"].append(analyze_seed(w["_linked_seed"]))
    if typ != "ADDR":
        if w.get("_linked_hex") and w.get("_linked_hex") != key:
            bundle["linked_analysis"].append(analyze_hex_key(w["_linked_hex"]))
        if w.get("_linked_wif") and w.get("_linked_wif") != key:
            bundle["linked_analysis"].append(analyze_wif(w["_linked_wif"]))
        if w.get("_linked_seed") and w.get("_linked_seed") != key:
            bundle["linked_analysis"].append(analyze_seed(w["_linked_seed"]))
    return bundle


def export_dossier(w: dict, balances: dict, meta: dict, rank: int, total_bal: float) -> str:
    """Write FULL forensic JSON (no truncation) to ~/forensic_exports/."""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    rows = wallet_addr_rows(w, balances, meta)
    bundle = forensic_bundle_for_wallet(w)
    try:
        prices = wv.get_usd_prices()
    except Exception:
        prices = {}
    addr_table = []
    for r in rows:
        m = r.get("meta") or {}
        bal = r["balance"]
        usd = None
        try:
            if isinstance(bal, (int, float)) and bal > 1e-12:
                usd = wv.usd_value(r["chain"], bal, prices)
        except Exception:
            usd = None
        addr_table.append({
            "chain": r["chain"],
            "address": r["address"],
            "balance": bal,
            "usd": usd,
            "noise": r["noise"],
            "from": r.get("from"),
            "ts": m.get("ts"),
            "live": m.get("live"),
            "settled": m.get("settled"),
            "checked_at": m.get("checked_at"),
            "error": m.get("error"),
        })
    try:
        total_usd = wv.wallet_usd_total(w, balances, prices)
    except Exception:
        total_usd = None
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "rank": rank,
        "total_balance": total_bal,
        "total_usd": total_usd,
        "usd_prices": prices,
        "wallet_type": w.get("type"),
        "key_full": w.get("key"),
        "source_full": w.get("source"),
        "timestamp": w.get("timestamp"),
        "hit_boost": w.get("_hit_boost"),
        "linked_hex_full": w.get("_linked_hex"),
        "linked_wif_full": w.get("_linked_wif"),
        "linked_seed_full": w.get("_linked_seed"),
        "chains": w.get("_chains"),
        "addresses": addr_table,
        "forensic": bundle,
        "live_production": True,
        "mock": False,
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    typ = (w.get("type") or "x").lower()
    safe = ""
    rawk = str(w.get("key") or "")[:24]
    for ch in rawk:
        safe += ch if ch.isalnum() else "_"
    path = os.path.join(EXPORT_DIR, f"dossier_r{rank}_{typ}_{safe}_{ts}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    return path


# ── wallet shaping ─────────────────────────────────────────────────

def consolidate_addr_wallets(wallets):
    """Merge ADDR hits for the same address across chains into one dossier."""
    out = []
    by_addr = {}
    for w in wallets:
        try:
            if (w.get("type") or "") != "ADDR":
                out.append(w)
                continue
            key = w.get("key") or ""
            if ":" in key:
                chain, addr = key.split(":", 1)
            else:
                chain, addr = "?", key
            chain = (chain or "?").lower()
            addr = addr or ""
            body = addr.lower() if addr.startswith("0x") else addr
            if not body:
                out.append(w)
                continue
            if body not in by_addr:
                nw = {
                    "type": "ADDR",
                    "key": addr if addr.startswith("0x") else f"{chain}:{addr}",
                    "addresses": {},
                    "timestamp": w.get("timestamp") or "",
                    "source": w.get("source") or "",
                    "_derived": True,
                    "_hit_boost": float(w.get("_hit_boost") or 0.0),
                    "_chains": set(),
                }
                by_addr[body] = nw
                out.append(nw)
            nw = by_addr[body]
            for (c, a), info in (w.get("addresses") or {}).items():
                nw["addresses"][(c, a)] = info
                nw["_chains"].add(c)
            nw["addresses"][(chain, addr)] = {
                "chain": chain, "address": addr, "from": "hit",
            }
            nw["_chains"].add(chain)
            nw["_hit_boost"] = max(
                float(nw.get("_hit_boost") or 0.0),
                float(w.get("_hit_boost") or 0.0),
            )
            ts = w.get("timestamp") or ""
            if ts and ts > (nw.get("timestamp") or ""):
                nw["timestamp"] = ts
            src = w.get("source") or ""
            if src and (
                not nw.get("source")
                or nw.get("source") in ("balance_hit", "wallet_view_live")
            ):
                nw["source"] = src
            if addr.startswith("0x"):
                nw["key"] = addr
            elif len(nw.get("_chains") or []) > 1:
                nw["key"] = f"{addr} ({len(nw['_chains'])} chains)"
            else:
                nw["key"] = f"{chain}:{addr}"
            for lk in ("_linked_hex", "_linked_wif", "_linked_seed"):
                if w.get(lk) and not nw.get(lk):
                    nw[lk] = w[lk]
        except Exception:
            out.append(w)
    for w in out:
        ch = w.get("_chains")
        if isinstance(ch, set):
            w["_chains"] = sorted(ch)
    return out


def attach_memory_meta(wallets, max_bytes: int = MEMORY_DEEP_BYTES):
    """Attach source_uri + reverse-link key material from scanner memory (LIVE)."""
    path = wv.MEMORY_FILE
    if not os.path.exists(path):
        return wallets

    want = {}
    hex_wallets = []
    for w in wallets:
        typ = (w.get("type") or "")
        if typ == "HEX":
            hex_wallets.append(w)
        if typ != "ADDR":
            continue
        key = w.get("key") or ""
        body = key.lower() if key.startswith("0x") else key
        if ":" in body:
            body = body.split(":", 1)[-1]
        body = body.lower()
        if body:
            want[body] = w

    try:
        with open(path, "rb") as f:
            size = os.path.getsize(path)
            if size > max_bytes:
                f.seek(-max_bytes, 2)
                data = f.read()
                nl = data.find(bytes([10]))
                if nl >= 0:
                    data = data[nl + 1 :]
            else:
                data = f.read()
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return wallets

    for line in text.splitlines():
        try:
            low = line.lower()
            hit_bodies = [b for b in want if b in low] if want else []
            if "hex_keys" not in low and "seed_phrases" not in low and "wifs" not in low:
                if not hit_bodies:
                    continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            src = rec.get("source_uri") or rec.get("source") or ""
            ts = rec.get("ts") or rec.get("timestamp") or ""
            findings = rec.get("findings") or {}
            wallet = findings.get("wallet") or {}
            hexes = [str(h) for h in (wallet.get("hex_keys") or []) if h]
            wifs = [str(x) for x in (wallet.get("wifs") or []) if x]
            seeds = [str(s) for s in (wallet.get("seed_phrases") or []) if s]

            for body in hit_bodies:
                w = want[body]
                if src and (
                    not w.get("source")
                    or w.get("source") in ("balance_hit", "wallet_view_live")
                ):
                    w["source"] = src
                if ts and str(ts) > str(w.get("timestamp") or ""):
                    w["timestamp"] = ts
                if hexes:
                    if not w.get("_linked_hex"):
                        w["_linked_hex"] = hexes[0]
                    prev = w.get("_linked_hexes") or []
                    for h in hexes:
                        if h not in prev:
                            prev.append(h)
                    w["_linked_hexes"] = prev
                if wifs:
                    if not w.get("_linked_wif"):
                        w["_linked_wif"] = wifs[0]
                    prev = w.get("_linked_wifs") or []
                    for x in wifs:
                        if x not in prev:
                            prev.append(x)
                    w["_linked_wifs"] = prev
                if seeds:
                    if not w.get("_linked_seed"):
                        w["_linked_seed"] = seeds[0]
                    prev = w.get("_linked_seeds") or []
                    for s in seeds:
                        if s not in prev:
                            prev.append(s)
                    w["_linked_seeds"] = prev

            # Co-occurrence only inside this loop (fast).
            # Full reverse-derive is done once after the file scan, capped.
        except Exception:
            continue

    # Reverse-link: derive from in-scope HEX wallets first (already gathered)
    still = [w for w in want.values() if not w.get("_linked_hex")]
    if still and hex_wallets and _cs is not None:
        for w in hex_wallets:
            if not still:
                break
            try:
                wv.ensure_derived(w)
            except Exception:
                continue
            hx = w.get("key") or ""
            for (chain, addr) in (w.get("addresses") or {}):
                body = (addr or "").lower()
                bare = body[2:] if body.startswith("0x") else body
                target = want.get(body) or want.get(bare) or want.get("0x" + bare)
                if target is None or target.get("_linked_hex"):
                    continue
                target["_linked_hex"] = hx
                target["_link_method"] = "wallet_derive_match"
                if w.get("source") and (
                    not target.get("source")
                    or target.get("source") in ("balance_hit", "wallet_view_live")
                ):
                    target["source"] = w.get("source")
        still = [w for w in want.values() if not w.get("_linked_hex")]

    # Optional capped reverse-derive from co-located linked hex candidates only
    if still and _cs is not None:
        candidates = []
        seen_h = set()
        for w in want.values():
            for h in ([w.get("_linked_hex")] + list(w.get("_linked_hexes") or [])):
                if not h:
                    continue
                hx = _hex_norm(h)
                if len(hx) != 64 or hx in seen_h:
                    continue
                seen_h.add(hx)
                candidates.append(hx)
        # also try a small sample of hex_wallets keys
        for w in hex_wallets[:200]:
            hx = _hex_norm(w.get("key") or "")
            if len(hx) == 64 and hx not in seen_h:
                seen_h.add(hx)
                candidates.append(hx)
        for hx in candidates[:400]:
            if not still:
                break
            try:
                if wv.is_junk_hex(hx):
                    continue
                derived = _cs.priv_to_addresses(bytes.fromhex(hx)) or {}
            except Exception:
                continue
            for _chain, addr in derived.items():
                if not addr:
                    continue
                body = addr.lower()
                bare = body[2:] if body.startswith("0x") else body
                target = want.get(body) or want.get(bare) or want.get("0x" + bare)
                if target is None or target.get("_linked_hex"):
                    continue
                target["_linked_hex"] = hx
                target["_link_method"] = "derive_match"
            still = [w for w in want.values() if not w.get("_linked_hex")]
    return wallets


def rank_wallets(wallets, balances, funded_only: bool = False):
    scored = []
    for w in wallets:
        try:
            sc, pend, chk = wv.wallet_score(w, balances)
            boost = float(w.get("_hit_boost") or 0.0)
            total = sc if sc > 0 else boost
            if funded_only and total <= 1e-12:
                continue
            if funded_only and (w.get("type") or "") == "ADDR":
                rows = wallet_addr_rows(w, balances, {})
                real = [
                    r for r in rows
                    if not r["noise"]
                    and isinstance(r["balance"], (int, float))
                    and r["balance"] > 1e-12
                ]
                if not real and boost <= 1e-12:
                    continue
                if real:
                    total = sum(float(r["balance"]) for r in real)
            scored.append((float(total), int(pend), int(chk), w.get("timestamp") or "", w))
        except Exception:
            continue
    scored.sort(key=lambda t: (t[0], t[3]), reverse=True)
    return scored


def ensure_top_derived(ranked, balances, n: int = 60):
    for i in range(min(n, len(ranked))):
        try:
            total, pend, chk, ts, w = ranked[i]
            wv.ensure_derived(w)
            typ = (w.get("type") or "").upper()
            if typ == "HEX" and _cs is not None:
                try:
                    hx = _hex_norm(w.get("key") or "")
                    if len(hx) == 64 and not wv.is_junk_hex(hx):
                        raw = _cs.priv_to_addresses(bytes.fromhex(hx)) or {}
                        for chain, addr in raw.items():
                            if addr:
                                w.setdefault("addresses", {})[(chain, addr)] = {
                                    "chain": chain, "address": addr, "from": "hex",
                                }
                except Exception:
                    pass
            sc, pend2, chk2 = wv.wallet_score(w, balances)
            boost = float(w.get("_hit_boost") or 0.0)
            ranked[i] = (sc if sc > 0 else boost, pend2, chk2, ts, w)
        except Exception:
            continue
    ranked.sort(key=lambda t: (t[0], t[3]), reverse=True)
    return ranked


def rescore_ranked(ranked, balances):
    out = []
    for _total, _p, _c, ts, w in ranked:
        try:
            sc, pend, chk = wv.wallet_score(w, balances)
            boost = float(w.get("_hit_boost") or 0.0)
            if (w.get("type") or "") == "ADDR":
                rows = wallet_addr_rows(w, balances, {})
                real_sum = sum(
                    float(r["balance"])
                    for r in rows
                    if not r["noise"]
                    and isinstance(r["balance"], (int, float))
                    and r["balance"] > 1e-12
                )
                if real_sum > 0:
                    sc = real_sum
            out.append((sc if sc > 0 else boost, pend, chk, ts, w))
        except Exception:
            out.append((0.0, 0, 0, ts, w))
    out.sort(key=lambda t: (t[0], t[3]), reverse=True)
    return out


def wallet_addr_rows(w, balances, meta):
    try:
        wv.ensure_derived(w)
    except Exception:
        pass
    rows = []
    seen = set()
    for (chain, addr), info in list((w.get("addresses") or {}).items()):
        try:
            nk = wv._norm_addr(chain, addr)
            if nk in seen:
                continue
            seen.add(nk)
            bal = wv.bal_get(balances, chain, addr)
            m = wv.meta_get(meta, chain, addr) or {}
            noise = wv._is_noise_address(chain, addr)
            rows.append({
                "chain": chain,
                "address": addr,
                "balance": bal,
                "meta": m,
                "noise": noise,
                "from": (info or {}).get("from") or w.get("type") or "?",
            })
        except Exception:
            continue

    def rank(r):
        b = r["balance"]
        if r["noise"]:
            return (3, 0.0)
        if isinstance(b, (int, float)) and b > 1e-12:
            return (0, -float(b))
        if b is None:
            return (1, 0.0)
        return (2, 0.0)

    rows.sort(key=rank)
    return rows


def collect_refresh_keys(ranked, balances, meta, focus_idx: int, batch: int):
    """Fair RPC targets across the leaderboard (not only rank #1).

    Order keys round-robin by wallet rank so a multi-chain #1 cannot starve
    ranks 2..N. Focus wallet still gets first slot within the fair queue.
    """
    keys = []
    seen = set()

    def wallet_keys(w):
        out = []
        try:
            wv.ensure_derived(w)
        except Exception:
            return out
        for chain, addr in (w.get("addresses") or {}):
            k = (chain, addr)
            if k not in seen:
                seen.add(k)
                out.append(k)
        return out

    try:
        n = len(ranked or [])
        if n == 0:
            return []
        focus_idx = max(0, min(n - 1, int(focus_idx)))
        # Walk focus first, then the rest of the visible leaderboard, then tail.
        order = list(range(n))
        # rotate so focus is first
        order = order[focus_idx:] + order[:focus_idx]
        # Prefer leaderboard window, still include the rest for pending fills
        lb = min(LEADERBOARD_N, n)
        lb_set = set(range(lb))
        order = [i for i in order if i in lb_set] + [i for i in order if i not in lb_set]

        per_wallet = [wallet_keys(ranked[i][4]) for i in order]
        # Round-robin merge so batch covers many ranks each tick
        max_len = max((len(p) for p in per_wallet), default=0)
        for col in range(max_len):
            for bucket in per_wallet:
                if col < len(bucket):
                    keys.append(bucket[col])
        return wv.pick_refresh_targets(keys, balances, meta, batch=batch)
    except Exception:
        return []


def _advance_free_run_focus(ranked, focus: int) -> int:
    """Step dossier focus to the next rank (wrap). Used only during free-run."""
    n = len(ranked or [])
    if n <= 0:
        return 0
    # Rotate through the full ranked set (funded list is usually <= LEADERBOARD_N)
    return (int(focus) + 1) % n


# ── paint ──────────────────────────────────────────────────────────

def _print_analysis_block(analysis: dict, title: str = "FORENSIC ANALYSIS"):
    if not analysis:
        return
    print(f"  {BOLD}{BLUE}{title}{RESET}  {DIM}(live · production · no mock){RESET}")
    kind = analysis.get("kind") or "?"
    print(f"  {BOLD}KIND{RESET}      {kind}")

    if kind == "HEX":
        _print_full("HEX", analysis.get("hex") or analysis.get("raw") or "", color=YELLOW)
        valid = analysis.get("valid")
        banned = analysis.get("banned_test")
        secp = analysis.get("secp_ok")
        vcol = GREEN if valid and not banned else (RED if banned else YELLOW)
        print(
            f"  {BOLD}VALID{RESET}     {vcol}{valid}{RESET}  "
            f"reason={analysis.get('reason')!s}  "
            f"secp256k1={secp}  banned_test={banned}"
        )
        print(
            f"  {BOLD}QUALITY{RESET}   {float(analysis.get('quality') or 0):.6f}  "
            f"entropy={float(analysis.get('entropy') or 0):.6f}"
        )
        if analysis.get("n_int") is not None:
            _print_full("N_INT", str(analysis.get("n_int")))
        if analysis.get("pub_compressed"):
            _print_full("PUB_C", analysis["pub_compressed"])
        if analysis.get("pub_uncompressed"):
            _print_full("PUB_U", analysis["pub_uncompressed"])
        if analysis.get("wif_compressed"):
            _print_full("WIF_C", analysis["wif_compressed"], color=YELLOW)
        if analysis.get("wif_uncompressed"):
            _print_full("WIF_U", analysis["wif_uncompressed"], color=YELLOW)
        if analysis.get("eth_address"):
            _print_full("ETH", analysis["eth_address"], color=GREEN)
        if analysis.get("sha256_priv_fp"):
            _print_full("SHA256", analysis["sha256_priv_fp"])
        if analysis.get("keccak_priv_fp"):
            _print_full("KECCAK", analysis["keccak_priv_fp"])
        addrs = analysis.get("addresses") or {}
        if addrs:
            print(f"  {BOLD}DERIVED{RESET}   {len(addrs)} chains (full):")
            for chain in sorted(addrs.keys()):
                print(f"            {chain.upper():8}  {addrs[chain]}")
        be = analysis.get("backends") or {}
        if be:
            print(f"  {BOLD}BACKEND{RESET}   {be}")

    elif kind == "WIF":
        _print_full("WIF", analysis.get("raw") or "", color=YELLOW)
        print(
            f"  {BOLD}VALID{RESET}     {analysis.get('valid')}  "
            f"reason={analysis.get('reason')!s}  "
            f"compressed={analysis.get('compressed')}  mainnet={analysis.get('mainnet')}"
        )
        if analysis.get("hex"):
            _print_full("HEX", analysis["hex"], color=YELLOW)
        nested = analysis.get("nested")
        if nested:
            _print_analysis_block(nested, title="WIF → HEX ANALYSIS")

    elif kind == "SEED":
        _print_full("SEED", analysis.get("raw") or "", color=YELLOW)
        print(
            f"  {BOLD}VALID{RESET}     {analysis.get('valid')}  "
            f"reason={analysis.get('reason')!s}  "
            f"words={analysis.get('word_count')}  lang={analysis.get('language')}"
        )
        words = analysis.get("words") or []
        if words:
            print(f"  {BOLD}WORDS{RESET}     (complete list):")
            for i, word in enumerate(words, 1):
                print(f"            {i:02d}. {word}")
        if analysis.get("nested_hex"):
            _print_analysis_block(analysis["nested_hex"], title="SEED → MASTER HEX")
        addrs = analysis.get("addresses") or {}
        if addrs:
            print(f"  {BOLD}DERIVED{RESET}   {len(addrs)} chains (full):")
            for chain in sorted(addrs.keys()):
                print(f"            {chain.upper():8}  {addrs[chain]}")

    elif kind == "ADDR":
        _print_full("ADDR", analysis.get("raw") or "")
        chains = analysis.get("chains") or []
        if chains:
            print(f"  {BOLD}CHAINS{RESET}    {', '.join(str(c).upper() for c in chains)}")
        if analysis.get("note"):
            print(f"  {DIM}{analysis['note']}{RESET}")
    print()


def paint_forensic(
    ranked,
    balances,
    meta,
    focus: int = 0,
    funded_only: bool = False,
    status_line: str = "",
    live_note: str = "",
    error_line: str = "",
    idle_left: float = -1.0,
    idle_sec: float = DEFAULT_IDLE_REFRESH_SEC,
    pin_top: bool = True,
):
    try:
        return _paint_forensic_inner(
            ranked, balances, meta, focus, funded_only,
            status_line, live_note, error_line, idle_left, idle_sec,
            pin_top=pin_top,
        )
    except Exception as exc:
        lines = [
            "=" * 78,
            f"  {RED}FORENSIC PAINT ERROR{RESET}: {exc}",
            f"  {DIM}{traceback.format_exc(limit=6)}{RESET}",
            "-" * 78,
        ]
        _emit_frame(lines, pin_top=True)
        return {"n": len(ranked or []), "focus": focus, "page_keys": [], "err": str(exc)}


def _live_facts(ranked, balances, meta, focus: int, funded_only: bool):
    """Hard-wire live production facts from current cache — never trust stale totals.

    Re-scores every row against the balance cache so "rank #N of M" and Funded/
    Portfolio numbers always match what is on disk right now.
    """
    raw = list(ranked or [])
    # Fresh score from balances (production cache), drop empties if funded_only.
    live_rows = []
    for _sc, _p, _c, ts, w in raw:
        try:
            sc, pend, chk = wv.wallet_score(w, balances)
            boost = float(w.get("_hit_boost") or 0.0)
            if (w.get("type") or "") == "ADDR":
                rows = wallet_addr_rows(w, balances, meta)
                real_sum = sum(
                    float(r["balance"])
                    for r in rows
                    if not r["noise"]
                    and isinstance(r["balance"], (int, float))
                    and r["balance"] > 1e-12
                )
                if real_sum > 0:
                    sc = real_sum
            total = sc if sc > 0 else boost
            if funded_only and total <= 1e-12:
                continue
            live_rows.append((float(total), int(pend), int(chk), ts, w))
        except Exception:
            continue
    live_rows.sort(key=lambda t: (t[0], t[3]), reverse=True)
    n = len(live_rows)
    if n == 0:
        return {
            "ranked": [],
            "n": 0,
            "focus": 0,
            "funded_n": 0,
            "grand": 0.0,
            "total_bal": 0.0,
            "pend": 0,
            "chk": 0,
            "w": None,
            "rows": [],
            "page_keys": [],
            "top_bal": 0.0,
        }
    # Clamp focus into live list; try to keep same wallet if still present.
    focus = max(0, min(n - 1, int(focus)))
    if 0 <= focus < len(raw):
        want = (raw[focus][4].get("type"), raw[focus][4].get("key"))
        for i, row in enumerate(live_rows):
            if (row[4].get("type"), row[4].get("key")) == want:
                focus = i
                break
    total_bal, pend, chk, _ts, w = live_rows[focus]
    rows = wallet_addr_rows(w, balances, meta)
    # Live chain-sum for the focused wallet (authoritative funded flag).
    live_sum = 0.0
    live_pend = 0
    live_zero = 0
    for r in rows:
        if r["noise"]:
            continue
        b = r["balance"]
        if isinstance(b, (int, float)) and b > 1e-12:
            live_sum += float(b)
        elif b is None:
            live_pend += 1
        else:
            live_zero += 1
    if live_sum > 0:
        total_bal = live_sum
        # keep ranked row in sync for this paint
        tb, p, c, ts, ww = live_rows[focus]
        live_rows[focus] = (total_bal, live_pend, live_zero, ts, ww)
    else:
        pend, chk = live_pend, live_zero
    funded_n = sum(1 for t, *_ in live_rows if t > 1e-12)
    grand = sum(t for t, *_ in live_rows if t > 1e-12)
    top_bal = live_rows[0][0] if live_rows else 0.0
    page_keys = [(r["chain"], r["address"]) for r in rows if not r["noise"]]
    return {
        "ranked": live_rows,
        "n": n,
        "focus": focus,
        "funded_n": funded_n,
        "grand": grand,
        "total_bal": float(total_bal),
        "pend": int(pend),
        "chk": int(chk),
        "w": w,
        "rows": rows,
        "page_keys": page_keys,
        "top_bal": float(top_bal),
    }


def _line_full(label: str, value: str, color: str = "") -> list:
    """Same as _print_full but returns lines (never truncates key material)."""
    val = "" if value is None else str(value)
    indent = "  "
    prefix_plain_len = len(indent) + len(label) + 1
    pad = " " * prefix_plain_len
    head = f"{indent}{BOLD}{label}{RESET} "
    if not val:
        return [f"{head}{DIM}(empty){RESET}"]
    first_budget = max(8, WRAP_WIDTH)
    out = []
    if len(val) <= first_budget:
        out.append(f"{head}{color}{val}{RESET if color else ''}")
        return out
    out.append(f"{head}{color}{val[:first_budget]}{RESET if color else ''}")
    rest = val[first_budget:]
    while rest:
        chunk = rest[: WRAP_WIDTH + 8]
        rest = rest[WRAP_WIDTH + 8 :]
        out.append(f"{pad}{color}{chunk}{RESET if color else ''}")
    return out


def _paint_forensic_inner(
    ranked, balances, meta, focus, funded_only,
    status_line, live_note, error_line, idle_left, idle_sec,
    pin_top: bool = True,
):
    facts = _live_facts(ranked, balances, meta, focus, funded_only)
    ranked = facts["ranked"]
    n = facts["n"]
    focus = facts["focus"]
    funded_n = facts["funded_n"]
    grand = facts["grand"]
    total_bal = facts["total_bal"]
    pend = facts["pend"]
    chk = facts["chk"]
    w = facts["w"]
    rows = facts["rows"]
    page_keys = facts["page_keys"]
    top_bal = facts["top_bal"]

    if n == 0 or w is None:
        lines = [
            "=" * 78,
            " " * 14 + f"{BOLD}{MAGENTA}WALLETX FORENSIC EXAMINER{RESET}",
            "=" * 78,
            "",
            "  No wallets to examine yet.",
            "  Wait for scanner findings, or drop --funded-only.",
        ]
        if error_line:
            lines.append(f"  {RED}{error_line}{RESET}")
        if status_line:
            lines.append(f"  {DIM}{status_line}{RESET}")
        lines.append("-" * 78)
        lines.append(
            f"  {DIM}q quit · r force-reload · f toggle funded · "
            f"idle-refresh {int(idle_sec)}s{RESET}"
        )
        _emit_frame(lines, pin_top=pin_top)
        return {"n": 0, "focus": 0, "page_keys": [], "funded_n": 0, "grand": 0.0}

    try:
        with wv._refresh_lock:
            rs = dict(wv._refresh_state)
    except Exception:
        rs = {}

    try:
        bundle = forensic_bundle_for_wallet(w)
    except Exception as exc:
        bundle = {"error": str(exc)}

    try:
        prices = wv.get_usd_prices()
    except Exception:
        prices = {}

    portfolio_usd = 0.0
    portfolio_usd_any = False
    for row in ranked:
        try:
            u = wv.wallet_usd_total(row[4], balances, prices)
            if u is not None:
                portfolio_usd += u
                portfolio_usd_any = True
        except Exception:
            pass
    focus_usd = None
    try:
        focus_usd = wv.wallet_usd_total(w, balances, prices)
    except Exception:
        focus_usd = None

    # LIVE hard facts — single source of truth for the header the user walks by.
    rank_no = focus + 1
    funded_tag = (
        f"· {GREEN}FUNDED{RESET}" if total_bal > 1e-12 else f"· {DIM}empty{RESET}"
    )
    mode = "FUNDED ONLY" if funded_only else "all wallets"
    now_z = datetime.now(timezone.utc).strftime("%H:%M:%S") + "Z"

    lines = []
    # ═══ TOP PIN: dossier rank first so refresh always lands on #N of M ═══
    lines.append("=" * 78)
    lines.append(
        f"  {BOLD}{WHITE}FORENSIC DOSSIER{RESET}  "
        f"— rank {CYAN}#{rank_no}{RESET} of {CYAN}{n}{RESET}  {funded_tag}  "
        f"{DIM}LIVE{RESET}"
    )
    lines.append(
        f"  {DIM}examining {CYAN}#{rank_no}/{n}{RESET}  ·  "
        f"{mode}  ·  live production  ·  {now_z}{RESET}"
    )
    lines.append("=" * 78)

    # Compact live stats strip (always current)
    usd_port = (
        f"  {wv.format_usd(portfolio_usd, color=True)}" if portfolio_usd_any else ""
    )
    lines.append(
        f"  Funded: {GREEN}{funded_n}{RESET}/{n}   "
        f"Portfolio: {GREEN}{grand:,.8f}{RESET}{usd_port}   "
        f"Keys: {n}"
    )
    if idle_left >= 0:
        if idle_left > 0:
            mins = int(idle_left) // 60
            secs = int(idle_left) % 60
            lines.append(
                f"  {GREEN}FROZEN{RESET}  free-run in {CYAN}{mins:02d}:{secs:02d}{RESET}  "
                f"{DIM}(touch resets){RESET}"
            )
        else:
            lines.append(
                f"  {YELLOW}FREE-RUN{RESET}  rotating ranks + live RPC  "
                f"{DIM}(touch freezes){RESET}"
            )
    if rs.get("running"):
        lines.append(
            f"  {CYAN}Live RPC: {rs.get('done', 0)}/{rs.get('total', 0)}  "
            f"{rs.get('last_msg', '')}{RESET}"
        )
    elif live_note:
        lines.append(f"  {DIM}{live_note}{RESET}")
    if status_line:
        lines.append(f"  {DIM}{status_line}{RESET}")
    if error_line:
        lines.append(f"  {RED}! {error_line}{RESET}")

    # Focus wallet core facts (always on-screen with rank header)
    typ = w.get("type") or "?"
    key = w.get("key") or ""
    src = w.get("source") or ""
    found_ts = w.get("timestamp") or ""
    lines.append("─" * 78)
    lines.append(f"  {BOLD}TYPE{RESET}      {typ}")
    chains_meta = w.get("_chains") or []
    if chains_meta and len(chains_meta) > 1:
        lines.append(
            f"  {BOLD}CHAINS{RESET}    {', '.join(c.upper() for c in chains_meta)}  "
            f"{DIM}(multi-chain){RESET}"
        )
    lines.extend(
        _line_full("KEY", key, color=YELLOW if typ in ("HEX", "WIF", "SEED") else "")
    )
    lines.append(f"  {BOLD}KEY_LEN{RESET}   {len(key)} chars  {DIM}(complete){RESET}")
    if src:
        lines.extend(_line_full("SOURCE", src))
    else:
        lines.append(f"  {BOLD}SOURCE{RESET}    {DIM}(unknown){RESET}")
    lines.append(f"  {BOLD}FOUND{RESET}     {found_ts or (DIM + 'n/a' + RESET)}")
    usd_bit = f"  ≈ {wv.format_usd(focus_usd, color=True)}" if focus_usd is not None else ""
    lines.append(
        f"  {BOLD}BALANCE{RESET}   {GREEN}{total_bal:,.12f}{RESET}{usd_bit}  "
        f"(unresolved={pend}  zeroed={chk}  chains={len(rows)})"
    )
    if w.get("_hit_boost"):
        lines.append(
            f"  {BOLD}HIT BOOST{RESET} {YELLOW}{float(w['_hit_boost']):.12f}{RESET}"
        )
    if w.get("_link_method"):
        lines.append(f"  {BOLD}LINK VIA{RESET}  {w['_link_method']}")
    if w.get("_linked_hex"):
        lines.extend(_line_full("LINKED HEX", w["_linked_hex"], color=YELLOW))
    if w.get("_linked_wif"):
        lines.extend(_line_full("LINKED WIF", w["_linked_wif"], color=YELLOW))
    if w.get("_linked_seed"):
        lines.extend(_line_full("LINKED SEED", w["_linked_seed"], color=YELLOW))

    # Chain balances (compact — always live from cache)
    lines.append("")
    lines.append(
        f"  {BOLD}{'CHAIN':>6}  {'BAL':>12}  {'USD':>9}  "
        f"{'AGE':>4}  FLAG{RESET}"
    )
    lines.append(f"  {'-'*6}  {'-'*12}  {'-'*9}  {'-'*4}  {'-'*6}")
    show_rows = rows if not DETAIL_ADDRS else rows[:DETAIL_ADDRS]
    # Prefer funded rows first already sorted; cap for screen if many
    for r in show_rows:
        chain = r["chain"]
        addr = r["address"]
        bal = r["balance"]
        m = r["meta"] or {}
        age = _age_str(m.get("ts"))
        live = "LIVE" if m.get("live") else ("SET" if m.get("settled") else "")
        if r["noise"]:
            flag = f"{DIM}noise{RESET}"
            bal_s = f"{DIM}{'0':>12}{RESET}"
            usd_s = f"{DIM}{'—':>9}{RESET}"
            mark = " "
        elif isinstance(bal, (int, float)) and bal > 1e-12:
            flag = f"{GREEN}FUNDED{RESET}"
            bal_s = f"{GREEN}{bal:>12.8f}{RESET}"
            usd_s = wv.format_usd(wv.usd_value(chain, bal, prices), width=9, color=True)
            mark = f"{GREEN}▶{RESET}"
        elif bal is None:
            flag = f"{YELLOW}pend{RESET}"
            bal_s = f"{YELLOW}{'…':>12}{RESET}"
            usd_s = f"{DIM}{'—':>9}{RESET}"
            mark = " "
        else:
            flag = f"{DIM}zero{RESET}"
            bal_s = f"{DIM}{'0':>12}{RESET}"
            usd_s = f"{DIM}{'—':>9}{RESET}"
            mark = " "
        live_s = f" {DIM}{live}{RESET}" if live else ""
        lines.append(
            f"  {mark}{chain.upper():>5}  {bal_s}  {usd_s}  "
            f"{age:>4}  {flag}{live_s}"
        )
        lines.append(f"         {addr}")
    if not rows:
        lines.append(f"  {DIM}  (no derived addresses){RESET}")

    # Compact leaderboard under the dossier (secondary — may clip on short screens)
    lines.append("")
    lines.append(f"  {BOLD}LEADERBOARD{RESET}  {DIM}(live · highest balance){RESET}")
    lb_n = min(LEADERBOARD_N, n)
    # Show a window around focus so current rank is in the mini-board
    if n <= lb_n:
        lb_start, lb_end = 0, n
    else:
        half = lb_n // 2
        lb_start = max(0, min(n - lb_n, focus - half))
        lb_end = lb_start + lb_n
    for i in range(lb_start, lb_end):
        sc, _pnd, _ck, _ts, ww = ranked[i]
        marker = f"{CYAN}▶{RESET}" if i == focus else " "
        typ_s = (ww.get("type") or "?")[:4]
        if sc > 1e-12:
            bal_s = f"{GREEN}{sc:>12.8f}{RESET}"
        else:
            bal_s = f"{DIM}{'0':>12}{RESET}"
        try:
            row_usd = wv.wallet_usd_total(ww, balances, prices)
        except Exception:
            row_usd = None
        usd_s = wv.format_usd(row_usd, width=9, color=True)
        show = _leaderboard_label(ww.get("key") or "", 22)
        lines.append(
            f"  {marker}{i + 1:>3}/{n:<3}  {typ_s:<4}  {bal_s}  {usd_s}  {show}"
        )
    if lb_start > 0 or lb_end < n:
        lines.append(
            f"  {DIM}  showing #{lb_start + 1}–#{lb_end} of {n}  "
            f"(n/p move focus){RESET}"
        )

    lines.append("─" * 78)
    lines.append(
        f"  {BOLD}KEYS{RESET}  "
        f"{CYAN}n{RESET}/→ next  {CYAN}p{RESET}/← prev  "
        f"{CYAN}g{RESET} jump  {CYAN}t{RESET} top  "
        f"{CYAN}f{RESET} funded  {CYAN}r{RESET} reload  "
        f"{CYAN}e{RESET} export  {CYAN}q{RESET} quit"
    )
    lines.append(
        f"  {DIM}LIVE facts rescore every paint  ·  top pinned on refresh  ·  "
        f"rank #{rank_no} of {n} hard-wired{RESET}"
    )
    lines.append("-" * 78)

    _emit_frame(lines, pin_top=pin_top)
    return {
        "n": n,
        "focus": focus,
        "page_keys": page_keys,
        "funded_n": funded_n,
        "grand": grand,
        "bundle": bundle,
        "ranked_live": ranked,
        "total_bal": total_bal,
    }


# ── IO / state ─────────────────────────────────────────────────────

def _stdin_key(timeout: float = 0.0):
    if not sys.stdin.isatty():
        return None
    try:
        r, _, _ = select.select([sys.stdin], [], [], max(0.0, timeout))
        if not r:
            return None
        ch = sys.stdin.read(1)
        return ch
    except Exception:
        return None


def _drain_stdin():
    """Consume bursty key/paste input so we don't process a flood after paint."""
    if not sys.stdin.isatty():
        return 0
    n = 0
    while True:
        ch = _stdin_key(0.0)
        if ch is None:
            break
        n += 1
        if n > 64:
            break
    return n


def _with_cbreak(fn):
    if not sys.stdin.isatty():
        return fn()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        _hide_cursor()
        return fn()
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass
        _show_cursor()


def _refocus(ranked, target_key, fallback: int) -> int:
    if not ranked:
        return 0
    if target_key:
        for i, row in enumerate(ranked):
            w = row[4]
            if (w.get("type"), w.get("key")) == target_key:
                return i
    return max(0, min(len(ranked) - 1, int(fallback)))


def _prompt_jump(cur, nmax):
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except Exception:
        old = None
    try:
        if old is not None:
            cooked = termios.tcgetattr(fd)
            cooked[3] = cooked[3] | termios.ECHO | termios.ICANON
            termios.tcsetattr(fd, termios.TCSADRAIN, cooked)
        _show_cursor()
        sys.stdout.write(
            f"\n  {CYAN}Jump to rank (1–{nmax}, now {cur + 1}): {RESET}"
        )
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            return None
        return max(0, int(line) - 1)
    except Exception:
        return None
    finally:
        _hide_cursor()
        if old is not None:
            try:
                tty.setcbreak(fd)
            except Exception:
                pass


def visible_fingerprint(ranked, focus: int, funded_only: bool, rs_sig: str = "") -> str:
    try:
        n = len(ranked or [])
        if n == 0:
            return f"empty|{funded_only}|{rs_sig}"
        focus = max(0, min(n - 1, int(focus)))
        top = []
        for i, row in enumerate(ranked[:LEADERBOARD_N]):
            sc, pend, chk, _ts, w = row
            top.append(f"{i}:{w.get('type')}:{w.get('key') or ''}:{sc:.12f}")
        fw = ranked[focus][4]
        fsc = ranked[focus][0]
        return "|".join([
            f"n={n}",
            f"fo={int(funded_only)}",
            f"fi={focus}",
            f"fsc={fsc:.12f}",
            f"fkey={fw.get('type')}:{fw.get('key') or ''}",
            f"rs={rs_sig}",
            "^".join(top),
        ])
    except Exception as exc:
        return f"err:{exc}"


class ForensicState:
    """Caches heavy gathers; idle-refresh drives full reload."""

    def __init__(self, max_wallets: int = 0, funded_only: bool = False):
        self.max_wallets = max_wallets
        self.funded_only = funded_only
        self.wallets = []
        self.ranked = []
        self.balances = {}
        self.meta = {}
        self.last_gather = 0.0
        self.last_bal = 0.0
        self._bal_mtime = None
        self.last_paint = 0.0
        self._last_rpc_sig = ""
        self._last_fp = ""
        self.last_error = ""
        self.gather_ms = 0
        self.bal_ms = 0
        self.n_cycle = 0
        self.last_export = ""

    def full_gather(self, force: bool = False):
        now = time.time()
        if not force and self.wallets and (now - self.last_gather) < GATHER_SEC:
            return
        t0 = time.time()
        try:
            raw = wv.gather_wallets(max_wallets=self.max_wallets)
            shaped = consolidate_addr_wallets(raw)
            shaped = attach_memory_meta(shaped, max_bytes=MEMORY_DEEP_BYTES)
            self.wallets = shaped
            self.last_gather = time.time()
            self.gather_ms = int((time.time() - t0) * 1000)
        except Exception as exc:
            self.last_error = f"gather: {exc}"

    def reload_balances(self) -> bool:
        t0 = time.time()
        try:
            path = wv.CACHE_FILE
            mtime = os.path.getmtime(path) if os.path.exists(path) else None
            if (
                mtime is not None
                and self._bal_mtime is not None
                and mtime == self._bal_mtime
                and self.balances
            ):
                self.bal_ms = 0
                return False
            self.balances, self.meta = wv.load_balances()
            self._bal_mtime = mtime
            self.last_bal = time.time()
            self.bal_ms = int((time.time() - t0) * 1000)
            return True
        except Exception as exc:
            self.last_error = f"balances: {exc}"
            return False

    def rebuild_ranked(self):
        try:
            # Always score against the freshest balance cache (production).
            self.reload_balances()
            ranked = rank_wallets(self.wallets, self.balances, funded_only=False)
            ranked = ensure_top_derived(ranked, self.balances, n=80)
            ranked = rescore_ranked(ranked, self.balances)
            if self.funded_only:
                ranked = [row for row in ranked if row[0] > 1e-12]
            self.ranked = ranked
            self._facts_ts = time.time()
        except Exception as exc:
            self.last_error = f"rank: {exc}"

    def soft_rescore(self):
        """Re-score in place from live cache. Falls back to full rebuild if empty."""
        try:
            self.reload_balances()
            if not self.ranked:
                self.rebuild_ranked()
                return
            base = [(0.0, 0, 0, ts, w) for *_x, ts, w in self.ranked]
            scored = rescore_ranked(base, self.balances)
            if self.funded_only:
                scored = [row for row in scored if row[0] > 1e-12]
            # If soft path dropped everyone (stale scores), do a full rebuild.
            if not scored and self.wallets:
                self.rebuild_ranked()
                return
            self.ranked = scored
            self._facts_ts = time.time()
        except Exception as exc:
            self.last_error = f"rescore: {exc}"

    def snapshot(self, force_gather: bool = False):
        self.n_cycle += 1
        self.full_gather(force=force_gather)
        self.reload_balances()
        # Free-run / force always full rebuild so N and ranks stay live.
        if force_gather or not self.ranked:
            self.rebuild_ranked()
        else:
            self.soft_rescore()
        return self.ranked, self.balances, self.meta

    def live_count(self) -> int:
        return len(self.ranked or [])


def load_ranked(max_wallets: int, funded_only: bool, derive_top: int = 50):
    st = ForensicState(max_wallets=max_wallets, funded_only=funded_only)
    st.snapshot(force_gather=True)
    return st.ranked, st.balances, st.meta, st.gather_ms + st.bal_ms


def _maybe_start_refresh(st: ForensicState, focus: int, live: bool, batch: int):
    if not live or not st.ranked:
        return
    try:
        with wv._refresh_lock:
            if wv._refresh_state.get("running"):
                return
        targets = collect_refresh_keys(
            st.ranked, st.balances, st.meta, focus, batch=batch
        )
        if targets:
            wv.background_refresh(targets)
    except Exception as exc:
        st.last_error = f"refresh: {exc}"


def _status(st: ForensicState, focus: int, idle_sec: float, batch: int, tag: str) -> str:
    n = len(st.ranked or [])
    focus = max(0, min(max(0, n - 1), int(focus))) if n else 0
    return (
        f"{tag} #{st.n_cycle} · rank {focus + 1}/{n} · "
        f"idle {int(idle_sec)}s · rpc {batch} · "
        f"gather {st.gather_ms}ms · bal {st.bal_ms}ms · LIVE"
    )


def _live_note(st: ForensicState, live: bool) -> str:
    try:
        with wv._refresh_lock:
            rs = dict(wv._refresh_state)
    except Exception:
        rs = {}
    if rs.get("running"):
        return (
            f"live RPC {rs.get('done', 0)}/{rs.get('total', 0)} "
            f"{rs.get('last_msg', '')}"
        )
    if not live:
        return "cache only (still live-rescored facts)"
    return "live production · idle-refresh armed"


def paint_state(
    st, focus, live, idle_sec, batch, tag="forensic",
    force=False, idle_left: float = -1.0,
):
    now = time.time()
    # Pull freshest balances before every forced paint so N/rank stay true.
    if force:
        try:
            st.reload_balances()
            st.soft_rescore()
        except Exception:
            pass
    note = _live_note(st, live)
    fp = visible_fingerprint(st.ranked, focus, st.funded_only, rs_sig="")
    if not force and fp == st._last_fp and (now - st.last_paint) < 30.0:
        return None
    n = len(st.ranked or [])
    focus = max(0, min(max(0, n - 1), int(focus))) if n else 0
    info = paint_forensic(
        st.ranked,
        st.balances,
        st.meta,
        focus=focus,
        funded_only=st.funded_only,
        status_line=_status(st, focus, idle_sec, batch, tag),
        live_note=note,
        error_line=st.last_error,
        idle_left=idle_left,
        idle_sec=idle_sec,
        pin_top=True,
    )
    # Write back hard-wired live ranked list + corrected focus from paint.
    if info:
        live_ranked = info.get("ranked_live")
        if live_ranked is not None:
            st.ranked = live_ranked
        if "focus" in info:
            focus = int(info["focus"])
        st._last_fp = visible_fingerprint(
            st.ranked, focus, st.funded_only, rs_sig=""
        )
    else:
        st._last_fp = fp
    st.last_paint = time.time()
    if info is not None:
        info["focus"] = focus
        info["n"] = len(st.ranked or [])
    return info


def cycle_once(focus, funded_only, live, batch, max_wallets, block_refresh, status_line=""):
    st = ForensicState(max_wallets=max_wallets, funded_only=funded_only)
    st.snapshot(force_gather=True)
    focus = max(0, min(max(0, len(st.ranked) - 1), focus))
    if st.ranked:
        try:
            wv.ensure_derived(st.ranked[focus][4])
        except Exception:
            pass

    info = paint_forensic(
        st.ranked, st.balances, st.meta,
        focus=focus, funded_only=funded_only,
        status_line=f"{status_line} · gather {st.gather_ms}ms bal {st.bal_ms}ms",
        live_note=("cache only" if not live else "live production"),
        error_line=st.last_error,
        idle_left=-1,
        idle_sec=DEFAULT_IDLE_REFRESH_SEC,
        pin_top=True,
    )
    if info:
        if info.get("ranked_live") is not None:
            st.ranked = info["ranked_live"]
        focus = int(info.get("focus", focus))

    if not live:
        return {"focus": focus, "n": len(st.ranked)}

    _maybe_start_refresh(st, focus, live, batch)
    if not block_refresh:
        return {"focus": focus, "n": len(st.ranked)}

    t_end = time.time() + 45
    target_key = None
    if st.ranked:
        target_key = (st.ranked[focus][4].get("type"), st.ranked[focus][4].get("key"))
    while time.time() < t_end:
        with wv._refresh_lock:
            running = bool(wv._refresh_state.get("running"))
        if not running:
            break
        time.sleep(1.5)
        st.reload_balances()
        st.soft_rescore()
        focus = _refocus(st.ranked, target_key, focus)
        info = paint_forensic(
            st.ranked, st.balances, st.meta,
            focus=focus, funded_only=funded_only,
            status_line="once · waiting live batch",
            live_note=_live_note(st, True),
            error_line=st.last_error,
            pin_top=True,
        )
        if info:
            if info.get("ranked_live") is not None:
                st.ranked = info["ranked_live"]
            focus = int(info.get("focus", focus))
    st.reload_balances()
    st.soft_rescore()
    focus = _refocus(st.ranked, target_key, focus)
    info = paint_forensic(
        st.ranked, st.balances, st.meta,
        focus=focus, funded_only=funded_only,
        status_line="once · done",
        live_note=_live_note(st, True),
        error_line=st.last_error,
        pin_top=True,
    )
    if info:
        if info.get("ranked_live") is not None:
            st.ranked = info["ranked_live"]
        focus = int(info.get("focus", focus))
    return {"focus": focus, "n": len(st.ranked)}



def _status_line_inplace(msg: str) -> None:
    """Update bottom status without clearing the whole screen (no flicker)."""
    try:
        # Save cursor, jump near bottom, write one dim line, restore.
        sys.stdout.write("\033[s")
        sys.stdout.write("\033[999;1H")  # go to last row
        sys.stdout.write("\033[2K")
        sys.stdout.write(f"  {DIM}{msg}{RESET}")
        sys.stdout.write("\033[u")
        sys.stdout.flush()
    except Exception:
        pass


def interactive_loop(args):
    """Keyboard nav. Screen FREEZES while you touch; free-runs only after idle_sec silence."""
    focus = max(0, int(args.index))
    live = not args.cached
    batch = max(1, int(args.batch))
    idle_sec = max(30.0, float(getattr(args, "idle_sec", DEFAULT_IDLE_REFRESH_SEC)))
    poll_sec = max(0.12, float(getattr(args, "tick_sec", DEFAULT_TICK_SEC)))
    global GATHER_SEC
    GATHER_SEC = max(idle_sec, float(idle_sec))

    st = ForensicState(
        max_wallets=args.max_wallets,
        funded_only=bool(args.funded_only),
    )
    pinned_key = None

    def run_safe():
        nonlocal focus, pinned_key
        try:
            st.snapshot(force_gather=True)
        except Exception as exc:
            st.last_error = f"boot: {exc}"
        if st.ranked:
            focus = max(0, min(len(st.ranked) - 1, focus))
            pinned_key = (
                st.ranked[focus][4].get("type"),
                st.ranked[focus][4].get("key"),
            )
            try:
                wv.ensure_derived(st.ranked[focus][4])
            except Exception:
                pass

        # User is "active" at boot — do NOT auto-RPC or auto-reload until idle_sec.
        last_input = time.time()
        last_idle_refresh = 0.0
        last_countdown_tick = 0.0
        free_run = False  # True only after idle_sec of silence

        paint_state(
            st, focus, live, idle_sec, batch, tag="walletx",
            force=True, idle_left=idle_sec,
        )
        # No _maybe_start_refresh at boot — wait for full idle freeze expiry.

        while True:
            try:
                now = time.time()
                idle_for = now - last_input
                idle_left = max(0.0, idle_sec - idle_for)
                # While user is active (idle_left > 0): ONLY poll keys, never gather/RPC/repaint.
                if idle_left > 0:
                    free_run = False
                    timeout = min(poll_sec, max(0.08, idle_left))
                else:
                    free_run = True
                    timeout = min(poll_sec, 0.5)

                key = _stdin_key(timeout=timeout)
                now = time.time()
                force_paint = False
                did_nav = False
                user_touched = key is not None

                if user_touched:
                    # HARD freeze again — cancel any free-run refresh cycle.
                    last_input = now
                    free_run = False
                    if key in ("q", "Q", "\x03"):
                        print()
                        return
                    if key in ("n", "N", "j", "J", " ", "\r", "\n"):
                        focus += 1
                        pinned_key = None
                        did_nav = True
                    elif key in ("p", "P", "k", "K", "b", "B"):
                        focus = max(0, focus - 1)
                        pinned_key = None
                        did_nav = True
                    elif key in ("t", "T", "h", "H"):
                        focus = 0
                        pinned_key = None
                        did_nav = True
                    elif key in ("f", "F"):
                        st.funded_only = not st.funded_only
                        focus = 0
                        pinned_key = None
                        st.rebuild_ranked()
                        did_nav = True
                    elif key in ("r", "R"):
                        # Manual reload is explicit user action — allowed anytime.
                        st.snapshot(force_gather=True)
                        force_paint = True
                        last_input = time.time()
                        free_run = False
                        _maybe_start_refresh(st, focus, live, batch)
                    elif key in ("e", "E"):
                        if st.ranked:
                            focus = max(0, min(len(st.ranked) - 1, focus))
                            tw = st.ranked[focus][4]
                            tbal = st.ranked[focus][0]
                            try:
                                path = export_dossier(
                                    tw, st.balances, st.meta, focus + 1, tbal
                                )
                                st.last_export = path
                                st.last_error = f"exported → {path}"
                            except Exception as exc:
                                st.last_error = f"export: {exc}"
                            force_paint = True
                    elif key in ("a", "A"):
                        force_paint = True
                    elif key in "123456789":
                        focus = int(key) - 1
                        pinned_key = None
                        did_nav = True
                    elif key in ("g", "G", "#"):
                        dest = _prompt_jump(focus, len(st.ranked) if st.ranked else 1)
                        last_input = time.time()
                        free_run = False
                        if dest is not None:
                            focus = dest
                            pinned_key = None
                            did_nav = True
                        else:
                            force_paint = True
                    elif key == "\x1b":
                        k2 = _stdin_key(0.06)
                        if k2 == "[":
                            k3 = _stdin_key(0.06)
                            if k3 in ("C", "B"):
                                focus += 1
                                pinned_key = None
                                did_nav = True
                            elif k3 in ("D", "A"):
                                focus = max(0, focus - 1)
                                pinned_key = None
                                did_nav = True
                            elif k3 == "5":
                                _stdin_key(0.02)
                                focus = max(0, focus - LEADERBOARD_N)
                                pinned_key = None
                                did_nav = True
                            elif k3 == "6":
                                _stdin_key(0.02)
                                focus += LEADERBOARD_N
                                pinned_key = None
                                did_nav = True
                        elif k2 is None:
                            print()
                            return
                    _drain_stdin()
                    # Any residual burst also counts as activity.
                    last_input = time.time()
                    free_run = False

                # ── FREE-RUN only after full idle_sec with ZERO input ──
                idle_for = time.time() - last_input
                if (not user_touched) and idle_for >= idle_sec:
                    free_run = True
                    # First entry into free-run, or cadence tick: full gather + RPC + paint.
                    if (time.time() - last_idle_refresh) >= IDLE_FREE_RUN_TICK:
                        st.snapshot(force_gather=True)
                        if pinned_key:
                            focus = _refocus(st.ranked, pinned_key, focus)
                        # Rotate dossier across ranks so free-run doesn't stick on #1.
                        # Skip advance on the very first free-run tick so rank #1 still
                        # gets examined once before cycling.
                        if FREE_RUN_ROTATE and st.ranked and last_idle_refresh > 0:
                            focus = _advance_free_run_focus(st.ranked, focus)
                            if st.ranked:
                                focus = max(0, min(len(st.ranked) - 1, focus))
                                pinned_key = (
                                    st.ranked[focus][4].get("type"),
                                    st.ranked[focus][4].get("key"),
                                )
                        _maybe_start_refresh(st, focus, live, batch)
                        # Pull latest cache so paint shows RPC progress without fighting user
                        # (user is idle here by definition).
                        try:
                            st.reload_balances()
                        except Exception:
                            pass
                        if pinned_key:
                            focus = _refocus(st.ranked, pinned_key, focus)
                        try:
                            if st.ranked:
                                wv.ensure_derived(st.ranked[focus][4])
                        except Exception:
                            pass
                        force_paint = True
                        last_idle_refresh = time.time()

                if pinned_key and st.ranked:
                    focus = _refocus(st.ranked, pinned_key, focus)
                elif st.ranked:
                    focus = max(0, min(len(st.ranked) - 1, focus))

                if did_nav and st.ranked:
                    focus = max(0, min(len(st.ranked) - 1, focus))
                    try:
                        wv.ensure_derived(st.ranked[focus][4])
                    except Exception:
                        pass
                    pinned_key = (
                        st.ranked[focus][4].get("type"),
                        st.ranked[focus][4].get("key"),
                    )
                    force_paint = True

                idle_left_now = max(0.0, idle_sec - (time.time() - last_input))

                # FULL screen paint ONLY on: user nav / explicit r|e|a / free-run tick.
                # NEVER while user is mid-session freezing (idle_left > 0 and no nav).
                if force_paint or did_nav:
                    info = paint_state(
                        st, focus, live, idle_sec, batch,
                        tag="walletx", force=True,
                        idle_left=idle_left_now,
                    )
                    if info and "focus" in info:
                        focus = int(info["focus"])
                        if st.ranked and 0 <= focus < len(st.ranked):
                            pinned_key = (
                                st.ranked[focus][4].get("type"),
                                st.ranked[focus][4].get("key"),
                            )
                    last_countdown_tick = time.time()
                elif (
                    idle_left_now > 0
                    and (time.time() - last_countdown_tick) >= COUNTDOWN_UPDATE_SEC
                ):
                    # Soft status only — no clear, no data reload, no RPC.
                    mins = int(idle_left_now) // 60
                    secs = int(idle_left_now) % 60
                    _status_line_inplace(
                        f"FROZEN · idle-refresh in {mins:02d}:{secs:02d} "
                        f"(touch resets · free-run after {int(idle_sec)}s silence)"
                    )
                    last_countdown_tick = time.time()

            except KeyboardInterrupt:
                print()
                return
            except Exception as exc:
                st.last_error = f"loop: {exc}"
                try:
                    paint_forensic(
                        st.ranked, st.balances, st.meta,
                        focus=focus, funded_only=st.funded_only,
                        status_line="recovered from error",
                        live_note=_live_note(st, live),
                        error_line=st.last_error,
                        idle_left=max(0.0, idle_sec - (time.time() - last_input)),
                        idle_sec=idle_sec,
                    )
                    st.last_paint = time.time()
                except Exception:
                    _safe_clear()
                    print(f"{RED}FATAL:{RESET} {exc}")
                    print(traceback.format_exc(limit=8))
                    sys.stdout.flush()
                    time.sleep(2)
                time.sleep(0.3)

    try:
        _with_cbreak(run_safe)
    except KeyboardInterrupt:
        print()
    finally:
        _show_cursor()


def watch_static(args):
    """Non-interactive stable watch — free-run refresh only after idle interval."""
    focus = max(0, int(args.index))
    live = not args.cached
    batch = max(1, int(args.batch))
    idle_sec = max(30.0, float(getattr(args, "idle_sec", DEFAULT_IDLE_REFRESH_SEC)))
    global GATHER_SEC
    GATHER_SEC = max(idle_sec, float(idle_sec))

    st = ForensicState(
        max_wallets=args.max_wallets,
        funded_only=bool(args.funded_only),
    )
    pinned_key = None
    _hide_cursor()
    try:
        st.snapshot(force_gather=True)
        if st.ranked:
            focus = max(0, min(len(st.ranked) - 1, focus))
            pinned_key = (
                st.ranked[focus][4].get("type"),
                st.ranked[focus][4].get("key"),
            )
        # Boot paint once; then wait full idle_sec before free-run.
        next_refresh = time.time() + idle_sec
        paint_state(
            st, focus, live, idle_sec, batch, tag="watch",
            force=True, idle_left=idle_sec,
        )
        # no RPC at boot

        last_status = 0.0
        free_run_ticks = 0
        while True:
            try:
                now = time.time()
                left = max(0.0, next_refresh - now)
                time.sleep(min(1.0, left if left > 0 else IDLE_FREE_RUN_TICK))
                now = time.time()
                if now >= next_refresh:
                    # free-run window
                    st.snapshot(force_gather=True)
                    if pinned_key:
                        focus = _refocus(st.ranked, pinned_key, focus)
                    # Rotate dossier across ranks so watch doesn't stick on #1.
                    if FREE_RUN_ROTATE and st.ranked and free_run_ticks > 0:
                        focus = _advance_free_run_focus(st.ranked, focus)
                        if st.ranked:
                            focus = max(0, min(len(st.ranked) - 1, focus))
                            pinned_key = (
                                st.ranked[focus][4].get("type"),
                                st.ranked[focus][4].get("key"),
                            )
                    _maybe_start_refresh(st, focus, live, batch)
                    try:
                        st.reload_balances()
                    except Exception:
                        pass
                    if pinned_key:
                        focus = _refocus(st.ranked, pinned_key, focus)
                    try:
                        if st.ranked:
                            wv.ensure_derived(st.ranked[focus][4])
                    except Exception:
                        pass
                    free_run_ticks += 1
                    # Keep free-running every IDLE_FREE_RUN_TICK until process ends
                    # (no interactive touch in this mode).
                    next_refresh = time.time() + IDLE_FREE_RUN_TICK
                    info = paint_state(
                        st, focus, live, idle_sec, batch, tag="watch",
                        force=True, idle_left=0.0,
                    )
                    if info and "focus" in info:
                        focus = int(info["focus"])
                        if st.ranked and 0 <= focus < len(st.ranked):
                            pinned_key = (
                                st.ranked[focus][4].get("type"),
                                st.ranked[focus][4].get("key"),
                            )
                elif (now - last_status) >= COUNTDOWN_UPDATE_SEC:
                    left_now = max(0.0, next_refresh - time.time())
                    mins = int(left_now) // 60
                    secs = int(left_now) % 60
                    _status_line_inplace(
                        f"FROZEN · first free-run in {mins:02d}:{secs:02d} "
                        f"(no keys mode · idle {int(idle_sec)}s)"
                    )
                    last_status = now
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                st.last_error = f"watch: {exc}"
                try:
                    paint_forensic(
                        st.ranked, st.balances, st.meta,
                        focus=focus, funded_only=st.funded_only,
                        status_line="watch recovered",
                        live_note=_live_note(st, live),
                        error_line=st.last_error,
                        idle_left=max(0.0, next_refresh - time.time()),
                        idle_sec=idle_sec,
                    )
                    st.last_paint = time.time()
                except Exception:
                    pass
                time.sleep(1.0)
    except KeyboardInterrupt:
        print()
    finally:
        _show_cursor()



def main():
    ap = argparse.ArgumentParser(
        description=(
            "WalletX forensic examiner — static, balance-ranked, idle-refresh. "
            "Full keys always. LIVE production only. Does NOT replace walletview."
        )
    )
    ap.add_argument(
        "-w", "--watch", action="store_true",
        help="static watch (no keys; refresh on idle interval)",
    )
    ap.add_argument("--once", action="store_true", help="single paint and exit")
    ap.add_argument(
        "--interactive", "-I", action="store_true",
        help="keyboard nav (default on tty)",
    )
    ap.add_argument("--cached", action="store_true", help="no live RPC")
    ap.add_argument(
        "--index", type=int, default=0,
        help="0-based rank (0 = highest balance)",
    )
    ap.add_argument(
        "--funded-only", action="store_true",
        help="only nonzero-balance wallets",
    )
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    ap.add_argument(
        "--idle-sec", type=float, default=DEFAULT_IDLE_REFRESH_SEC,
        help="seconds of ZERO input before free-run refresh (default 120; touch freezes)",
    )
    ap.add_argument(
        "--refresh-sec", type=float, default=None,
        help="alias for --idle-sec (back-compat)",
    )
    ap.add_argument(
        "--tick-sec", type=float, default=DEFAULT_TICK_SEC,
        help="input poll cadence seconds (default 2.0; does not repaint alone)",
    )
    ap.add_argument("--max-wallets", type=int, default=0)
    ap.add_argument(
        "--interval", type=int, default=0, help=argparse.SUPPRESS
    )
    args = ap.parse_args()

    if args.refresh_sec is not None:
        args.idle_sec = float(args.refresh_sec)
    if args.interval and args.interval > 0:
        args.idle_sec = float(args.interval)

    try:
        if args.once:
            cycle_once(
                focus=max(0, args.index),
                funded_only=bool(args.funded_only),
                live=not args.cached,
                batch=max(1, args.batch),
                max_wallets=args.max_wallets,
                block_refresh=False,
                status_line="once",
            )
            if not args.cached:
                time.sleep(0.3)
            return

        if args.watch and not args.interactive:
            watch_static(args)
            return

        if args.interactive or (sys.stdin.isatty() and not args.watch):
            interactive_loop(args)
        else:
            watch_static(args)
    except KeyboardInterrupt:
        print()
    finally:
        _show_cursor()


if __name__ == "__main__":
    main()
