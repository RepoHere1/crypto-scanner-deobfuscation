#!/usr/bin/env python3
"""
Wallet Balance Viewer — instant paint, live truth in background.

Never blanks the screen waiting on RPCs.
  1) Paint from balance_cache immediately
  2) Refresh a limited batch of stale/pending wallet addrs in background
  3) Re-paint when batch finishes (watch mode)

Usage:
    walletview                     # watch (default)
    python3 ~/wallet_view.py -w
    python3 ~/wallet_view.py --once
    python3 ~/wallet_view.py --cached
    python3 ~/wallet_view.py -w -i 20 --batch 40
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
MEMORY_FILE = os.path.join(HOME, "crypto_scanner_memory.jsonl")
CACHE_FILE = os.path.join(HOME, "balance_cache.jsonl")
HITS_FILE = os.path.join(HOME, "balances_hit.jsonl")

sys.path.insert(0, HOME)
import crypto_scanner as cs  # noqa: E402

LIVE_WORKERS = 4
DEFAULT_INTERVAL = 20
DEFAULT_BATCH = 48          # max live RPC checks per refresh cycle
MEMORY_TAIL_BYTES = 800_000  # only reconstruct wallets from recent memory
STALE_OK_SEC = 300           # reuse cache younger than 5 min unless pending

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

_refresh_lock = threading.Lock()
_refresh_state = {
    "running": False,
    "done": 0,
    "total": 0,
    "last_msg": "",
    "last_finish": 0.0,
}


def clear_screen():
    sys.stdout.write("\033[H\033[J")
    sys.stdout.flush()


def load_jsonl_tail(path: str, max_bytes: int = 0):
    """Load jsonl rows; if max_bytes>0 only read file tail (fast on huge memory)."""
    records = []
    if not os.path.exists(path):
        return records
    try:
        with open(path, "rb") as f:
            if max_bytes and os.path.getsize(path) > max_bytes:
                f.seek(-max_bytes, 2)
                data = f.read()
                # drop partial first line
                nl = data.find(b"\n")
                if nl >= 0:
                    data = data[nl + 1 :]
            else:
                data = f.read()
        for line in data.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass
    return records


def load_balances():
    balances = {}
    meta = {}
    if not os.path.exists(CACHE_FILE) or os.path.getsize(CACHE_FILE) == 0:
        return balances, meta
    try:
        with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                chain = (rec.get("chain") or "?").lower()
                addr = rec.get("address") or ""
                if not addr:
                    continue
                key = (chain, addr)
                # keep newest ts if dupes
                prev = meta.get(key)
                ts = float(rec.get("ts") or 0)
                if prev and float(prev.get("ts") or 0) > ts:
                    continue
                balances[key] = rec.get("balance")
                meta[key] = {
                    "checked_at": rec.get("checked_at"),
                    "live": rec.get("live", False),
                    "ts": ts,
                }
    except Exception:
        pass
    return balances, meta


def format_balance(bal):
    if bal is None:
        return f"{YELLOW}PENDING{RESET}"
    if bal == 0:
        return "0.00000000"
    if isinstance(bal, (int, float)) and bal > 0:
        return f"{GREEN}{bal:,.8f}{RESET}"
    return f"{bal:,.8f}"


def derive_for_key(key_type, key_value):
    try:
        if key_type == "WIF":
            priv = cs.wif_to_priv_bytes(key_value)
            addrs = cs.priv_to_addresses(priv) if priv else {}
        elif key_type == "HEX":
            addrs = cs.priv_to_addresses(bytes.fromhex(key_value))
        elif key_type == "SEED":
            addrs = cs.seed_to_addresses(key_value)
        else:
            addrs = {}
    except Exception:
        addrs = {}
    out = {}
    for chain, addr in (addrs or {}).items():
        chain = (chain or "?").lower()
        if addr:
            out[(chain, addr)] = {"chain": chain, "address": addr, "from": key_type.lower()}
    return out


def gather_wallets(max_wallets: int = 40):
    """Reconstruct wallets from recent memory only (fast)."""
    wallets = {}
    records = load_jsonl_tail(MEMORY_FILE, MEMORY_TAIL_BYTES)
    # newest first
    records.sort(key=lambda x: x.get("ts") or x.get("timestamp") or "", reverse=True)

    for rec in records:
        findings = rec.get("findings") or {}
        wallet = findings.get("wallet") or {}
        derived = findings.get("derived_addresses") or []

        def add(key_type, key_value, rec=rec, derived=derived):
            if not key_value:
                return
            # cap total wallets
            if (key_type, key_value) not in wallets and len(wallets) >= max_wallets:
                return
            w = wallets.setdefault(
                (key_type, key_value),
                {
                    "type": key_type,
                    "key": key_value,
                    "addresses": {},
                    "timestamp": rec.get("ts") or rec.get("timestamp") or "",
                    "source": rec.get("source_uri") or rec.get("source") or "",
                },
            )
            for d in derived:
                chain = (d.get("chain") or "?").lower()
                addr = d.get("address") or ""
                if addr:
                    w["addresses"][(chain, addr)] = {
                        "chain": chain,
                        "address": addr,
                        "from": d.get("from", key_type.lower()),
                    }

        for wif in wallet.get("wifs") or []:
            add("WIF", wif)
        for hx in wallet.get("hex_keys") or []:
            add("HEX", hx)
        for seed in wallet.get("seed_phrases") or []:
            add("SEED", seed)

    # re-derive current chain set (cheap crypto, no network)
    for (kt, kv), w in list(wallets.items()):
        try:
            w["addresses"].update(derive_for_key(kt, kv))
        except Exception:
            pass

    return sorted(wallets.values(), key=lambda x: x.get("timestamp") or "", reverse=True)


def pick_refresh_targets(all_keys, balances, meta, batch: int):
    """Prefer PENDING and stale; skip fresh zeros/nonzeros within STALE_OK_SEC."""
    now = time.time()
    pending = []
    stale = []
    fresh = []
    for k in all_keys:
        bal = balances.get(k)
        m = meta.get(k) or {}
        age = now - float(m.get("ts") or 0)
        if bal is None:
            pending.append(k)
        elif age > STALE_OK_SEC:
            stale.append(k)
        else:
            fresh.append(k)
    # pending first, then oldest stale
    stale.sort(key=lambda k: float((meta.get(k) or {}).get("ts") or 0))
    ordered = pending + stale
    return ordered[: max(1, batch)]


def _check_one(chain, addr):
    try:
        return cs.get_balance(chain, addr, force=True)
    except Exception as exc:
        return {
            "chain": chain,
            "address": addr,
            "balance": None,
            "error": str(exc),
            "ts": time.time(),
            "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "live": False,
        }


def live_refresh_batch(targets, progress_cb=None):
    results = {}
    if not targets:
        return results
    total = len(targets)
    done = 0
    with ThreadPoolExecutor(max_workers=LIVE_WORKERS) as pool:
        futs = {pool.submit(_check_one, c, a): (c, a) for c, a in targets}
        for fut in as_completed(futs):
            c, a = futs[fut]
            try:
                rec = fut.result()
            except Exception as exc:
                rec = {"balance": None, "error": str(exc)}
            results[(c, a)] = rec.get("balance") if isinstance(rec, dict) else None
            done += 1
            if progress_cb:
                progress_cb(done, total, c, a, results[(c, a)])
    return results


def record_hits(wallet_bals):
    try:
        existing = set()
        if os.path.exists(HITS_FILE):
            with open(HITS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        existing.add(
                            ((rec.get("chain") or "").lower(), rec.get("address") or "", rec.get("balance"))
                        )
                    except Exception:
                        pass
        with open(HITS_FILE, "a", encoding="utf-8") as f:
            for (chain, addr), bal in wallet_bals.items():
                if not isinstance(bal, (int, float)) or bal <= 1e-12:
                    continue
                tup = (chain, addr, bal)
                if tup in existing:
                    continue
                rec = {
                    "chain": chain,
                    "address": addr,
                    "balance": bal,
                    "ts": time.time(),
                    "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "source": "wallet_view_live",
                }
                f.write(json.dumps(rec) + "\n")
                existing.add(tup)
    except Exception:
        pass


def paint(wallets, balances, meta, status_line="", live_note=""):
    all_keys = []
    seen = set()
    for w in wallets:
        for k in w.get("addresses") or {}:
            if k not in seen:
                seen.add(k)
                all_keys.append(k)

    wallet_keys = set(all_keys)
    nonzero = [
        k for k in wallet_keys
        if isinstance(balances.get(k), (int, float)) and balances.get(k) > 1e-12
    ]
    total = sum(float(balances[k]) for k in nonzero)
    pending = sum(1 for k in wallet_keys if balances.get(k) is None)

    newest = None
    for k in wallet_keys:
        ca = (meta.get(k) or {}).get("checked_at")
        if ca and (newest is None or ca > newest):
            newest = ca

    with _refresh_lock:
        rs = dict(_refresh_state)

    clear_screen()
    print("=" * 76)
    print(" " * 14 + f"{BOLD}WALLET VIEW — INSTANT + LIVE{RESET}")
    print("=" * 76)
    print()
    print(f"  Wallets shown (recent):   {len(wallets)}")
    print(f"  Unique addresses:         {len(all_keys)}")
    print(f"  With nonzero balance:     {len(nonzero)}")
    print(f"  Pending (no cache yet):   {pending}")
    print(f"  Total nonzero (truth):    {GREEN}{total:,.8f}{RESET}")
    print(f"  Updated:                  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if newest:
        print(f"  Last on-chain check:      {newest}")
    if rs.get("running"):
        print(
            f"  {CYAN}Live refresh: {rs.get('done',0)}/{rs.get('total',0)}  "
            f"{rs.get('last_msg','')}{RESET}"
        )
    elif live_note:
        print(f"  {DIM}{live_note}{RESET}")
    if status_line:
        print(f"  {DIM}{status_line}{RESET}")
    print()

    if not wallets:
        print("  No wallet keys in recent memory yet.")
        print("  Scanner is still running — wait for key findings.")
        print()
        print("-" * 76)
        print("Ctrl+C exits view only.")
        return {"total": total, "nonzero": len(nonzero), "pending": pending}

    # show wallets with nonzero first, then others (cap display)
    def w_score(w):
        s = 0.0
        for k in w.get("addresses") or {}:
            b = balances.get(k)
            if isinstance(b, (int, float)) and b > 1e-12:
                s += float(b)
        return s

    ordered = sorted(wallets, key=w_score, reverse=True)
    shown = 0
    max_show = 12
    for w in ordered:
        if shown >= max_show:
            break
        shown += 1
        print("-" * 76)
        print(f"  TYPE: {w['type']}")
        key = w.get("key") or ""
        if len(key) > 72:
            key = key[:34] + "…" + key[-34:]
        print(f"  KEY:  {key}")
        src = w.get("source") or ""
        if src:
            print(f"  SRC:  {src[:70]}")
        print()
        print(f"  {'CHAIN':>8}  {'ADDRESS':<46}  {'BALANCE':>12}")
        print(f"  {'-'*8}  {'-'*46}  {'-'*12}")
        for (chain, addr), _ in sorted((w.get("addresses") or {}).items()):
            bal = balances.get((chain, addr))
            mark = f"{GREEN}*** {RESET}" if isinstance(bal, (int, float)) and bal > 1e-12 else "    "
            a = addr if len(addr) <= 46 else addr[:22] + "…" + addr[-21:]
            print(f"{mark}{chain.upper():>8}  {a:<46}  {format_balance(bal):>12}")
        print()

    if len(ordered) > max_show:
        print(f"  {DIM}… {len(ordered) - max_show} more wallets not shown (recent tail only){RESET}")
        print()

    print("-" * 76)
    print(
        f"  Totals count ONLY wallet-derived addrs ({len(wallet_keys)}). "
        f"Never unrelated cache junk."
    )
    print("  Ctrl+C exits view only — scanners keep running.")
    sys.stdout.flush()
    return {"total": total, "nonzero": len(nonzero), "pending": pending, "all_keys": all_keys}


def background_refresh(targets):
    def run():
        with _refresh_lock:
            if _refresh_state["running"]:
                return
            _refresh_state["running"] = True
            _refresh_state["done"] = 0
            _refresh_state["total"] = len(targets)
            _refresh_state["last_msg"] = "starting"

        def prog(done, total, chain, addr, bal):
            with _refresh_lock:
                _refresh_state["done"] = done
                _refresh_state["total"] = total
                bs = "PENDING" if bal is None else f"{bal:.6f}"
                _refresh_state["last_msg"] = f"{chain}:{bs}"

        try:
            results = live_refresh_batch(targets, progress_cb=prog)
            # hits for nonzero
            record_hits(results)
        finally:
            with _refresh_lock:
                _refresh_state["running"] = False
                _refresh_state["last_finish"] = time.time()
                _refresh_state["last_msg"] = "idle"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def cycle(live: bool, batch: int, status_line: str = "", max_wallets: int = 40):
    # Instant path — no network
    wallets = gather_wallets(max_wallets=max_wallets)
    balances, meta = load_balances()
    info = paint(wallets, balances, meta, status_line=status_line, live_note=("cache only" if not live else ""))

    if not live:
        return info

    all_keys = info.get("all_keys") or []
    targets = pick_refresh_targets(all_keys, balances, meta, batch=batch)
    if not targets:
        paint(
            wallets,
            balances,
            meta,
            status_line=status_line,
            live_note="all shown addrs fresh in cache",
        )
        return info

    thr = background_refresh(targets)
    # while refreshing, re-paint every 1s so screen is never blank
    start = time.time()
    while thr.is_alive() and time.time() - start < 120:
        time.sleep(1.0)
        balances, meta = load_balances()
        paint(
            wallets,
            balances,
            meta,
            status_line=status_line,
            live_note=f"refreshing {len(targets)} addrs…",
        )
    thr.join(timeout=1)
    balances, meta = load_balances()
    return paint(
        wallets,
        balances,
        meta,
        status_line=status_line,
        live_note=f"last batch {len(targets)} live checks done",
    )


def main():
    ap = argparse.ArgumentParser(description="Instant wallet viewer with live background refresh")
    ap.add_argument("-w", "--watch", action="store_true", help="continuous (default if no --once)")
    ap.add_argument("--once", action="store_true", help="one shot then exit")
    ap.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH, help="max live RPC checks per cycle")
    ap.add_argument("--cached", action="store_true", help="cache only, no RPC")
    ap.add_argument("--max-wallets", type=int, default=40)
    args = ap.parse_args()

    live = not args.cached
    watch = args.watch or not args.once

    if not watch:
        cycle(live=live, batch=args.batch, max_wallets=args.max_wallets)
        return

    # default watch
    try:
        n = 0
        while True:
            n += 1
            status = f"watch #{n} · interval {args.interval}s · batch {args.batch}"
            cycle(live=live, batch=args.batch, status_line=status, max_wallets=args.max_wallets)
            # sleep in 1s slices
            left = max(1, int(args.interval))
            while left > 0:
                time.sleep(1)
                left -= 1
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
