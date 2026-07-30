#!/usr/bin/env python3
"""
denoise_history.py — Retroactively scrub noise from scanner JSONL artifacts.

Uses crypto_iq filters (same as live forward path):
  * Drop invalid / ascii-text / low-entropy / banned hex keys
  * Drop WIFs that fail secp checks
  * Recompute derived_addresses + confidence for kept keys
  * Drop records with no remaining material (optional)
  * Rebuild high_confidence_hits from cleaned memory (optional)

Streaming, atomic replace, keeps .bak beside each file.

Usage:
  python3 ~/denoise_history.py                  # dry-run stats
  python3 ~/denoise_history.py --apply          # rewrite files
  python3 ~/denoise_history.py --apply --rebuild-hc
  python3 ~/denoise_history.py --apply --memory-only
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HOME = Path.home()
MEMORY_FILE = HOME / "crypto_scanner_memory.jsonl"
HIGH_CONF_FILE = HOME / "high_confidence_hits.jsonl"
HITS_FILE = HOME / "balances_hit.jsonl"
REPORT_FILE = HOME / "denoise_report.json"

try:
    import crypto_iq as iq
except ImportError:
    print("[!] crypto_iq required", file=sys.stderr)
    sys.exit(1)

# Lazy import scanner derive helpers (heavy)
_cs = None

def _scanner():
    global _cs
    if _cs is None:
        import crypto_scanner as cs
        _cs = cs
    return _cs


def _norm_hex_list(vals) -> List[str]:
    out = []
    for v in vals or []:
        if not v:
            continue
        h = str(v).strip().lower().removeprefix("0x")
        if len(h) == 64:
            out.append(h)
    return out


def scrub_findings(findings: Dict[str, Any], context: str = "") -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Return cleaned findings + counters of drops."""
    stats = Counter()
    if not isinstance(findings, dict):
        return {}, stats

    f = dict(findings)
    ctx = context or ""

    # --- hex ---
    raw_hex = []
    wallet = dict(f.get("wallet") or {})
    raw_hex.extend(_norm_hex_list(f.get("hex_key")))
    raw_hex.extend(_norm_hex_list(wallet.get("hex_keys")))
    # unique preserve order
    seen = set()
    uniq = []
    for h in raw_hex:
        if h not in seen:
            seen.add(h)
            uniq.append(h)

    kept_hex_meta = iq.filter_hex_keys(uniq, context=ctx)
    kept_hex = [x["hex"] for x in kept_hex_meta]
    stats["hex_in"] += len(uniq)
    stats["hex_out"] += len(kept_hex)
    stats["hex_dropped"] += len(uniq) - len(kept_hex)

    # --- wif ---
    raw_wif = list(f.get("wif") or []) + list(wallet.get("wifs") or [])
    kept_wif = []
    seen_w = set()
    for w in raw_wif:
        if not w or w in seen_w:
            continue
        seen_w.add(w)
        ok, reason, _priv = iq.validate_wif(str(w))
        if ok:
            kept_wif.append(w)
        else:
            stats["wif_dropped"] += 1
    stats["wif_in"] += len(seen_w)
    stats["wif_out"] += len(kept_wif)

    # --- seeds (keep as-is if present; bip39 already validated at scan) ---
    seeds = list(f.get("seed_phrase") or []) + list(wallet.get("seed_phrases") or [])
    seeds = list(dict.fromkeys(seeds))

    f["hex_key"] = kept_hex
    f["wif"] = kept_wif
    f["seed_phrase"] = seeds

    # rebuild wallet + derived
    new_wallet = {
        "wifs": kept_wif,
        "hex_keys": kept_hex,
        "seed_phrases": seeds,
        "hex_meta": kept_hex_meta[:32],
    }
    f["wallet"] = new_wallet

    derived = []
    cs = _scanner()
    for wif in kept_wif:
        try:
            priv = cs.wif_to_priv_bytes(wif)
            if not priv:
                continue
            for chain, addr in (cs.priv_to_addresses(priv) or {}).items():
                derived.append({"chain": chain, "address": addr, "from": "wif"})
        except Exception:
            pass
    for h in kept_hex:
        try:
            for chain, addr in (cs.priv_to_addresses(bytes.fromhex(h)) or {}).items():
                derived.append({"chain": chain, "address": addr, "from": "hex_key"})
        except Exception:
            pass
    for seed in seeds:
        try:
            for chain, addr in (cs.seed_to_addresses(seed) or {}).items():
                derived.append({"chain": chain, "address": addr, "from": "seed_phrase"})
        except Exception:
            pass

    # dedupe derived
    seen_d = set()
    dedup = []
    for d in derived:
        k = (d.get("chain"), (d.get("address") or "").lower())
        if k in seen_d:
            continue
        seen_d.add(k)
        dedup.append(d)
    f["derived_addresses"] = dedup

    has_key = bool(kept_hex or kept_wif or seeds)
    best = max((float(x.get("score") or 0) for x in kept_hex_meta), default=0.0)
    nearby = ctx
    matched = False
    nl = nearby.lower()
    for d in dedup:
        a = d.get("address") or ""
        if a and a.lower() in nl:
            d["matched_nearby"] = True
            matched = True

    conf, corr, nscore = iq.score_finding(
        has_valid_key=has_key,
        derived_count=len(dedup),
        nearby_addr=bool(kept_hex or kept_wif),  # conservative
        key_context=bool(iq._KEY_CONTEXT_RE.search(ctx)) if ctx else False,
        seed=bool(seeds),
        wif=bool(kept_wif),
        hex_best_score=best,
        matched_derived_to_nearby=matched,
    )
    f["confidence"] = conf
    f["correlated"] = corr
    f["iq_score"] = nscore
    f["iq_backend"] = "pycryptodome" if iq._PYCRYPTODOME else "fallback"
    f["denoised"] = True

    # strip bulky noise fields that bloat memory (optional keep empty)
    # keep high_entropy etc. but they are not material

    stats["has_key_out"] += 1 if has_key else 0
    return f, stats


def record_has_material(findings: Dict[str, Any]) -> bool:
    if not findings:
        return False
    wallet = findings.get("wallet") or {}
    if wallet.get("hex_keys") or wallet.get("wifs") or wallet.get("seed_phrases"):
        return True
    if findings.get("hex_key") or findings.get("wif") or findings.get("seed_phrase"):
        return True
    # bare addresses still useful for balance re-check? keep if any chain addr
    for k in ("btc", "eth", "ltc", "sol", "doge", "xrp", "ton", "avax", "matic", "bnb", "base", "monad"):
        if findings.get(k):
            return True
    if findings.get("aws_key") or findings.get("github_pat") or findings.get("slack_token") or findings.get("stripe_key"):
        return True
    return False


def is_high_confidence(findings: Dict[str, Any]) -> bool:
    if not findings:
        return False
    if findings.get("confidence") == "high" and findings.get("correlated"):
        return True
    wallet = findings.get("wallet") or {}
    if wallet.get("wifs") or wallet.get("seed_phrases"):
        return True
    # hex only if decent iq_score
    if wallet.get("hex_keys") and float(findings.get("iq_score") or 0) >= 0.55:
        return True
    if findings.get("seed_phrase") or findings.get("wif"):
        return True
    return False


def scrub_record(rec: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Counter]:
    stats = Counter()
    findings = rec.get("findings")
    if findings is None and any(k in rec for k in ("hex_key", "wallet", "wif")):
        findings = rec
    ctx = " ".join(
        str(x) for x in (
            rec.get("source_line"),
            rec.get("source_uri"),
            rec.get("source_path"),
            rec.get("repo"),
        ) if x
    )
    if not isinstance(findings, dict):
        stats["skip_bad"] += 1
        return None, stats

    cleaned, st = scrub_findings(findings, context=ctx)
    stats.update(st)

    if not record_has_material(cleaned):
        stats["dropped_empty"] += 1
        return None, stats

    out = dict(rec)
    out["findings"] = cleaned
    out["denoised_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    stats["kept"] += 1
    if is_high_confidence(cleaned):
        stats["high_conf"] += 1
    return out, stats


def stream_denoise(path: Path, apply: bool, drop_empty: bool = True) -> Counter:
    stats = Counter()
    if not path.exists():
        print(f"[skip] missing {path}")
        return stats

    size = path.stat().st_size
    print(f"[denoise] {path.name} ({size/1e6:.1f} MB) apply={apply}")
    tmp = path.with_suffix(path.suffix + ".denoise.tmp")
    bak = path.with_suffix(path.suffix + f".bak_denoise_{int(time.time())}")

    t0 = time.time()
    out_f = open(tmp, "w", encoding="utf-8") if apply else None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as inf:
            for i, line in enumerate(inf, 1):
                line = line.strip()
                if not line:
                    continue
                stats["lines_in"] += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    stats["bad_json"] += 1
                    continue
                cleaned, st = scrub_record(rec)
                stats.update(st)
                if cleaned is None:
                    continue
                if apply and out_f is not None:
                    out_f.write(json.dumps(cleaned, separators=(",", ":")) + "\n")
                    stats["lines_out"] += 1
                if i % 2000 == 0:
                    elapsed = time.time() - t0
                    print(f"  … {i} lines, kept={stats['kept']}, dropped_empty={stats['dropped_empty']}, {elapsed:.0f}s")
    finally:
        if out_f is not None:
            out_f.close()

    if apply:
        # backup original then replace
        try:
            shutil.copy2(path, bak)
            print(f"  backup -> {bak.name}")
        except Exception as e:
            print(f"  [!] backup failed: {e}", file=sys.stderr)
        os.replace(tmp, path)
        print(f"  wrote {path} lines_out={stats['lines_out']}")
    else:
        if tmp.exists():
            tmp.unlink()
        stats["lines_out"] = stats["kept"]

    elapsed = time.time() - t0
    print(
        f"  done in {elapsed:.1f}s  in={stats['lines_in']} kept={stats['kept']} "
        f"empty_drop={stats['dropped_empty']} hex {stats['hex_in']}->{stats['hex_out']} "
        f"(dropped {stats['hex_dropped']}) high_conf={stats['high_conf']}"
    )
    return stats


def rebuild_high_confidence(memory_path: Path, hc_path: Path, apply: bool) -> Counter:
    """Rebuild HC file from cleaned memory using strict gate."""
    stats = Counter()
    if not memory_path.exists():
        return stats
    tmp = hc_path.with_suffix(hc_path.suffix + ".denoise.tmp")
    bak = hc_path.with_suffix(hc_path.suffix + f".bak_denoise_{int(time.time())}") if hc_path.exists() else None
    out_f = open(tmp, "w", encoding="utf-8") if apply else None
    t0 = time.time()
    try:
        with open(memory_path, "r", encoding="utf-8", errors="ignore") as inf:
            for line in inf:
                line = line.strip()
                if not line:
                    continue
                stats["mem_lines"] += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                findings = rec.get("findings") or {}
                if is_high_confidence(findings):
                    stats["hc_out"] += 1
                    if out_f is not None:
                        out_f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    finally:
        if out_f is not None:
            out_f.close()
    if apply:
        if bak and hc_path.exists():
            try:
                shutil.copy2(hc_path, bak)
                print(f"  HC backup -> {bak.name}")
            except Exception as e:
                print(f"  [!] HC backup failed: {e}", file=sys.stderr)
        os.replace(tmp, hc_path)
        print(f"  rebuilt HC: {stats['hc_out']} records from {stats['mem_lines']} memory lines")
    else:
        if tmp.exists():
            tmp.unlink()
        print(f"  [dry-run] HC would have {stats['hc_out']} records from {stats['mem_lines']} memory lines")
    print(f"  HC rebuild {time.time()-t0:.1f}s")
    return stats


def scrub_balance_hits(path: Path, apply: bool) -> Counter:
    """Dedupe hits + drop dust already handled; mainly dedupe."""
    stats = Counter()
    if not path.exists():
        return stats
    best = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            stats["in"] += 1
            try:
                rec = json.loads(line)
            except Exception:
                stats["bad"] += 1
                continue
            chain = (rec.get("chain") or "?").lower()
            addr = rec.get("address") or ""
            if not addr:
                continue
            bal = rec.get("balance")
            if not isinstance(bal, (int, float)) or bal <= 1e-12:
                stats["dust"] += 1
                continue
            try:
                from crypto_iq import is_noise_address
                if is_noise_address(chain, addr):
                    stats["noise"] += 1
                    continue
            except Exception:
                pass
            addr_key = addr.lower() if addr.startswith("0x") else addr
            k = f"{chain}:{addr_key}"
            prev = best.get(k)
            ts = float(rec.get("ts") or 0)
            if prev is None or float(bal) > float(prev.get("balance") or 0) or (
                float(bal) == float(prev.get("balance") or 0) and ts >= float(prev.get("ts") or 0)
            ):
                best[k] = rec
    stats["out"] = len(best)
    print(f"[hits] in={stats['in']} dust={stats['dust']} noise={stats['noise']} unique_nonzero={stats['out']} apply={apply}")
    if apply:
        bak = path.with_suffix(path.suffix + f".bak_denoise_{int(time.time())}")
        shutil.copy2(path, bak)
        with open(path, "w", encoding="utf-8") as f:
            for rec in sorted(best.values(), key=lambda r: -float(r.get("balance") or 0)):
                f.write(json.dumps(rec) + "\n")
        print(f"  hits rewritten, bak={bak.name}")
    return stats


def main():
    ap = argparse.ArgumentParser(description="Retroactively denoise scanner JSONL files")
    ap.add_argument("--apply", action="store_true", help="Write changes (default dry-run)")
    ap.add_argument("--rebuild-hc", action="store_true", help="Rebuild high_confidence from memory")
    ap.add_argument("--memory-only", action="store_true", help="Only process memory file")
    ap.add_argument("--hc-only", action="store_true", help="Only process high_confidence file")
    ap.add_argument("--hits", action="store_true", help="Also dedupe balances_hit.jsonl")
    args = ap.parse_args()

    print("crypto_iq", iq.backend_info())
    print("mode", "APPLY" if args.apply else "DRY-RUN")
    report = {"started": datetime.now(timezone.utc).isoformat(), "apply": args.apply}

    if not args.hc_only:
        report["memory"] = dict(stream_denoise(MEMORY_FILE, apply=args.apply))

    if not args.memory_only and not args.rebuild_hc:
        # scrub HC in place too (unless rebuilding from memory)
        if not args.hc_only:
            pass
        report["high_confidence"] = dict(stream_denoise(HIGH_CONF_FILE, apply=args.apply))
    elif args.hc_only and not args.rebuild_hc:
        report["high_confidence"] = dict(stream_denoise(HIGH_CONF_FILE, apply=args.apply))

    if args.rebuild_hc:
        # if memory was just cleaned in apply mode, rebuild HC from it
        report["hc_rebuild"] = dict(rebuild_high_confidence(MEMORY_FILE, HIGH_CONF_FILE, apply=args.apply))

    if args.hits:
        report["hits"] = dict(scrub_balance_hits(HITS_FILE, apply=args.apply))

    report["finished"] = datetime.now(timezone.utc).isoformat()
    REPORT_FILE.write_text(json.dumps(report, indent=2, default=str))
    print(f"report -> {REPORT_FILE}")


if __name__ == "__main__":
    main()
