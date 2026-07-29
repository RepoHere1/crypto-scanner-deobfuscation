#!/usr/bin/env python3
"""
Wallet Balance Viewer — fast paging through ALL wallets, live refresh.

Fixes:
  - No more "28 wallets hidden forever" — pages rotate + NEXT UP index
  - No perpetual same-screen loop — page advances every --page-sec
  - Lazy address derive (only current page) so 1000s of keys stay snappy
  - Deduped wallet keys from memory tail

Usage:
    walletview
    python3 ~/wallet_view.py --once --cached
    python3 ~/wallet_view.py --once --all --cached
    python3 ~/wallet_view.py --once --page 3 --page-size 10
    python3 ~/wallet_view.py -w --page-size 8 --page-sec 8
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

# Always load ~/.env so RPC API keys are present before crypto_scanner import
def _load_dotenv():
    env_path = os.path.join(HOME, ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and v:
                    os.environ.setdefault(k, v)
    except OSError:
        pass

_load_dotenv()
# bashrc fallback for alchemy
if not os.environ.get("ALCHEMY_API_KEY"):
    brc = os.path.join(HOME, ".bashrc")
    if os.path.exists(brc):
        try:
            for line in open(brc, encoding="utf-8", errors="ignore"):
                if "ALCHEMY_API_KEY=" in line and not line.strip().startswith("#"):
                    part = line.split("ALCHEMY_API_KEY=", 1)[1].strip().strip('"').strip("'")
                    if part and "YOUR_" not in part:
                        os.environ["ALCHEMY_API_KEY"] = part.split()[0]
                        break
        except OSError:
            pass

import crypto_scanner as cs  # noqa: E402

LIVE_WORKERS = 4
DEFAULT_INTERVAL = 10
DEFAULT_BATCH = 36
MEMORY_TAIL_BYTES = 3_000_000
STALE_OK_SEC = 900
DEFAULT_PAGE_SIZE = 8
DEFAULT_PAGE_SEC = 8
MAX_ADDRS_SHOW = 14
DERIVE_CACHE: dict = {}

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
    records = []
    if not os.path.exists(path):
        return records
    try:
        with open(path, "rb") as f:
            size = os.path.getsize(path)
            if max_bytes and size > max_bytes:
                f.seek(-max_bytes, 2)
                data = f.read()
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
                prev = meta.get(key)
                ts = float(rec.get("ts") or 0)
                if prev and float(prev.get("ts") or 0) > ts:
                    continue
                bal = rec.get("balance")
                if bal is None and (rec.get("settled") or rec.get("invalid")):
                    bal = 0.0
                balances[key] = bal
                meta[key] = {
                    "checked_at": rec.get("checked_at"),
                    "live": rec.get("live", False),
                    "ts": ts,
                    "settled": bool(rec.get("settled") or rec.get("invalid")),
                }
    except Exception:
        pass
    return balances, meta


def format_balance(bal):
    if bal is None:
        return f"{YELLOW}…{RESET}"
    if isinstance(bal, (int, float)) and abs(bal) < 1e-18:
        return f"{DIM}0{RESET}"
    if isinstance(bal, (int, float)) and bal > 0:
        return f"{GREEN}{bal:,.8f}{RESET}"
    return str(bal)


def derive_for_key(key_type: str, key_value: str) -> dict:
    ck = (key_type, key_value)
    if ck in DERIVE_CACHE:
        return DERIVE_CACHE[ck]
    addrs = {}
    try:
        if key_type == "WIF":
            priv = cs.wif_to_priv_bytes(key_value)
            raw = cs.priv_to_addresses(priv) if priv else {}
        elif key_type == "HEX":
            hv = key_value.strip().lower().removeprefix("0x")
            if len(hv) == 64:
                raw = cs.priv_to_addresses(bytes.fromhex(hv))
            else:
                raw = {}
        elif key_type == "SEED":
            raw = cs.seed_to_addresses(key_value)
        else:
            raw = {}
        for chain, addr in (raw or {}).items():
            chain = (chain or "?").lower()
            if addr:
                addrs[(chain, addr)] = {"chain": chain, "address": addr, "from": key_type.lower()}
    except Exception:
        addrs = {}
    DERIVE_CACHE[ck] = addrs
    return addrs


def gather_wallets(max_wallets: int = 0):
    """Collect unique wallet keys FAST — no crypto derive here."""
    wallets = {}  # (type, key) -> wallet dict
    records = load_jsonl_tail(MEMORY_FILE, MEMORY_TAIL_BYTES)
    # newest first so first-seen keeps freshest source
    records.sort(key=lambda x: x.get("ts") or x.get("timestamp") or "", reverse=True)

    for rec in records:
        findings = rec.get("findings") or {}
        wallet = findings.get("wallet") or {}
        ts = rec.get("ts") or rec.get("timestamp") or ""
        src = rec.get("source_uri") or rec.get("source") or ""

        def add(kt, kv):
            if not kv:
                return
            kv = kv.strip() if isinstance(kv, str) else kv
            k = (kt, kv)
            if k in wallets:
                return
            if max_wallets and len(wallets) >= max_wallets:
                return
            # light sanity
            if kt == "HEX":
                hx = kv.lower().removeprefix("0x")
                if len(hx) != 64:
                    return
                try:
                    int(hx, 16)
                except ValueError:
                    return
            wallets[k] = {
                "type": kt,
                "key": kv,
                "addresses": {},  # filled lazily
                "timestamp": ts,
                "source": src,
                "_derived": False,
            }

        for wif in wallet.get("wifs") or []:
            add("WIF", wif)
        for hx in wallet.get("hex_keys") or []:
            add("HEX", hx)
        for seed in wallet.get("seed_phrases") or []:
            add("SEED", seed)

        if max_wallets and len(wallets) >= max_wallets:
            break

    # stable order: newest first
    return sorted(wallets.values(), key=lambda x: x.get("timestamp") or "", reverse=True)


def ensure_derived(w):
    if w.get("_derived"):
        return w
    if w.get("type") == "ADDR":
        w["_derived"] = True
        return w
    addrs = derive_for_key(w.get("type") or "", w.get("key") or "")
    w["addresses"] = dict(addrs)
    w["_derived"] = True
    return w


def ensure_derived_many(wallets):
    for w in wallets:
        ensure_derived(w)
    return wallets


def wallet_score(w, balances):
    """Score using derived addrs if present, else 0 (index may show 0 until page opens)."""
    s = 0.0
    pending = 0
    checked = 0
    addrs = w.get("addresses") or {}
    if not addrs and not w.get("_derived"):
        # peek derive cache without forcing
        ck = (w.get("type"), w.get("key"))
        addrs = DERIVE_CACHE.get(ck) or {}
    for k in addrs:
        b = balances.get(k)
        if isinstance(b, (int, float)) and b > 1e-12:
            s += float(b)
        elif b is None:
            pending += 1
        else:
            checked += 1
    return s, pending, checked


def order_wallets(wallets, balances):
    """Nonzero first (from cache/derived), then newest. Lazy — won't derive all."""
    # Optionally quick-score from cache by deriving only if already cached
    scored = []
    for w in wallets:
        sc, pend, chk = wallet_score(w, balances)
        scored.append((sc, w.get("timestamp") or "", w))
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [w for _, _, w in scored]


def pick_refresh_targets(all_keys, balances, meta, batch: int):
    now = time.time()
    pending = []
    stale = []
    for k in all_keys:
        bal = balances.get(k)
        m = meta.get(k) or {}
        age = now - float(m.get("ts") or 0)
        if m.get("settled") and (bal is None or bal == 0):
            if age < 21600:
                continue
        if bal is None:
            pending.append(k)
        elif age > STALE_OK_SEC:
            if isinstance(bal, (int, float)) and bal <= 1e-12 and age < 3600:
                continue
            stale.append(k)
    stale.sort(key=lambda k: float((meta.get(k) or {}).get("ts") or 0))
    return (pending + stale)[: max(0, batch)]


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
                bs = "…" if bal is None else f"{bal:.6f}"
                _refresh_state["last_msg"] = f"{chain}:{bs}"

        try:
            results = live_refresh_batch(targets, progress_cb=prog)
            record_hits(results)
        finally:
            with _refresh_lock:
                _refresh_state["running"] = False
                _refresh_state["last_finish"] = time.time()
                _refresh_state["last_msg"] = "idle"

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def _short_key(key: str, width: int = 52) -> str:
    if not key:
        return ""
    if len(key) <= width:
        return key
    keep = (width - 1) // 2
    return key[:keep] + "…" + key[-keep:]


def _short_addr(addr: str, width: int = 42) -> str:
    if len(addr) <= width:
        return addr
    return addr[:18] + "…" + addr[-(width - 19) :]


def collect_keys_from_wallets(wallets):
    keys = []
    seen = set()
    for w in wallets:
        for k in w.get("addresses") or {}:
            if k not in seen:
                seen.add(k)
                keys.append(k)
    return keys


def paint(
    wallets,
    balances,
    meta,
    status_line="",
    live_note="",
    page: int = 0,
    page_size: int = DEFAULT_PAGE_SIZE,
    show_all: bool = False,
):
    ordered = order_wallets(wallets, balances)
    n_wallets = len(ordered)

    if show_all or page_size <= 0:
        page_size = max(1, n_wallets) if n_wallets else 1
        page = 0
        pages = 1
    else:
        pages = max(1, (n_wallets + page_size - 1) // page_size) if n_wallets else 1
        page = page % pages if pages else 0

    start = page * page_size
    end = min(n_wallets, start + page_size)
    page_wallets = ordered[start:end]

    # Derive ONLY this page (+ small peek) — keeps UI instant
    peek_end = min(n_wallets, end + 12)
    ensure_derived_many(ordered[start:peek_end])

    # Stats from whatever is derived so far + full cache isn't required
    all_keys = collect_keys_from_wallets([w for w in ordered if w.get("_derived")])
    # also include keys from entire derived cache for better totals when paging
    for addrs in DERIVE_CACHE.values():
        for k in addrs:
            if k not in all_keys:
                all_keys.append(k)

    wallet_keys = set(all_keys)
    nonzero_keys = [
        k for k in wallet_keys
        if isinstance(balances.get(k), (int, float)) and balances.get(k) > 1e-12
    ]
    total = sum(float(balances[k]) for k in nonzero_keys)
    pending = sum(1 for k in wallet_keys if balances.get(k) is None)
    zeroed = sum(
        1 for k in wallet_keys
        if isinstance(balances.get(k), (int, float)) and balances.get(k) <= 1e-12
    )

    newest = None
    for k in wallet_keys:
        ca = (meta.get(k) or {}).get("checked_at")
        if ca and (newest is None or ca > newest):
            newest = ca

    with _refresh_lock:
        rs = dict(_refresh_state)

    clear_screen()
    print("=" * 78)
    print(" " * 16 + f"{BOLD}WALLET VIEW — ALL WALLETS PAGED{RESET}")
    print("=" * 78)
    print()
    print(f"  Wallets total:               {n_wallets}")
    print(f"  Addrs known (derived so far):{len(all_keys)}")
    print(f"  Nonzero / zero / unresolved: {len(nonzero_keys):>4} / {zeroed:<5} / {pending}")
    print(f"  Total nonzero (truth):       {GREEN}{total:,.8f}{RESET}")
    print(f"  Updated:                     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if newest:
        print(f"  Last on-chain check:         {newest}")
    print(
        f"  {CYAN}PAGE {page + 1}/{pages}{RESET}  "
        f"wallets {start + 1 if n_wallets else 0}–{end} of {n_wallets}  "
        f"· size {page_size}  · auto-rotates in watch"
    )
    if rs.get("running"):
        print(
            f"  {CYAN}Live refresh: {rs.get('done', 0)}/{rs.get('total', 0)}  "
            f"{rs.get('last_msg', '')}{RESET}"
        )
    elif live_note:
        print(f"  {DIM}{live_note}{RESET}")
    if status_line:
        print(f"  {DIM}{status_line}{RESET}")
    print()

    if not ordered:
        print("  No wallet keys in recent memory yet.")
        print("  Scanner is still running — wait for key findings.")
        print("-" * 78)
        print("Ctrl+C exits view only.")
        sys.stdout.flush()
        return {
            "total": total, "nonzero": len(nonzero_keys), "pending": pending,
            "all_keys": all_keys, "pages": pages, "page": page, "n_wallets": 0,
            "page_keys": [],
        }

    # INDEX — every wallet on this page listed
    print(f"  {BOLD}INDEX — page {page + 1}/{pages}{RESET}")
    print(f"  {'#':>4}  {'TYPE':<5}  {'NZ':>8}  {'P':>3}  KEY / SRC")
    print(f"  {'-'*4}  {'-'*5}  {'-'*8}  {'-'*3}  {'-'*52}")
    for i, w in enumerate(page_wallets, start=start + 1):
        sc, pend, _ = wallet_score(w, balances)
        nz_s = f"{GREEN}{sc:.6g}{RESET}" if sc > 0 else f"{DIM}0{RESET}"
        src = (w.get("source") or "")
        if len(src) > 28:
            src = "…" + src[-27:]
        print(
            f"  {i:>4}  {w.get('type','?'):<5}  {nz_s:>8}  {pend:>3}  "
            f"{_short_key(w.get('key') or '', 40)}  {DIM}{src}{RESET}"
        )

    # NEXT UP — where the "hidden" wallets are
    if end < n_wallets and not show_all:
        left = n_wallets - end
        peek_n = min(15, left)
        print()
        nxt_page = page + 2
        print(f"  {BOLD}WHERE THE REST ARE{RESET}  {DIM}({left} more → pages {nxt_page}–{pages}){RESET}")
        for i, w in enumerate(ordered[end : end + peek_n], start=end + 1):
            # don't force-derive peek beyond what ensure_derived_many did
            sc, _, _ = wallet_score(w, balances)
            star = f"{GREEN}*{RESET}" if sc > 0 else " "
            tgt_page = (i - 1) // page_size + 1
            print(
                f"  {DIM}{star}#{i:<4} p{tgt_page:<3} {w.get('type','?'):<4} "
                f"{_short_key(w.get('key') or '', 46)}{RESET}"
            )
        if left > peek_n:
            print(f"  {DIM}  … +{left - peek_n} more keys; watch mode flips page every few seconds{RESET}")
        print(f"  {DIM}  jump:  python3 ~/wallet_view.py --once --cached --page N{RESET}")
        print(f"  {DIM}  dump:  python3 ~/wallet_view.py --once --all --cached | less{RESET}")

    # DETAIL cards
    print()
    print(f"  {BOLD}DETAIL — page {page + 1}/{pages}{RESET}")
    page_keys = []
    for idx, w in enumerate(page_wallets, start=start + 1):
        ensure_derived(w)
        sc, pend, chk = wallet_score(w, balances)
        print("-" * 78)
        print(
            f"  [{idx}/{n_wallets}] TYPE={w.get('type')}  "
            f"bal_sum={sc:.8f}  unresolved={pend}  zero={chk}"
        )
        print(f"  KEY:  {w.get('key')}")
        src = w.get("source") or ""
        if src:
            print(f"  SRC:  {src[:74]}")
        if w.get("timestamp"):
            print(f"  TS:   {w.get('timestamp')}")
        print()
        addrs = list((w.get("addresses") or {}).items())

        def addr_rank(item):
            (chain, addr), _ = item
            b = balances.get((chain, addr))
            page_keys.append((chain, addr))
            if isinstance(b, (int, float)) and b > 1e-12:
                return (0, -float(b), chain)
            if b is None:
                return (1, 0, chain)
            return (2, 0, chain)

        addrs_sorted = sorted(addrs, key=addr_rank)
        show_list = addrs_sorted[:MAX_ADDRS_SHOW]
        print(f"  {'CHAIN':>8}  {'ADDRESS':<46}  {'BALANCE':>14}")
        print(f"  {'-'*8}  {'-'*46}  {'-'*14}")
        for (chain, addr), _ in show_list:
            bal = balances.get((chain, addr))
            mark = f"{GREEN}*** {RESET}" if isinstance(bal, (int, float)) and bal > 1e-12 else "    "
            print(f"{mark}{chain.upper():>8}  {_short_addr(addr, 46):<46}  {format_balance(bal):>14}")
        rest = len(addrs_sorted) - len(show_list)
        if rest > 0:
            print(f"  {DIM}  … {rest} more chains/addrs (all listed in --all dump){RESET}")
        print()

    print("-" * 78)
    print(
        f"  Page {page + 1}/{pages}  ·  {n_wallets} wallets total  ·  "
        f"nothing permanently hidden — pages rotate in watch mode"
    )
    print(
        f"  {DIM}walletall  |  walletpage N  |  --page-size 20  |  Ctrl+C = exit view only{RESET}"
    )
    sys.stdout.flush()
    return {
        "total": total,
        "nonzero": len(nonzero_keys),
        "pending": pending,
        "all_keys": all_keys,
        "page_keys": page_keys,
        "pages": pages,
        "page": page,
        "n_wallets": n_wallets,
        "ordered": ordered,
    }


def dump_all_text(wallets, balances):
    print("=" * 78)
    print(f"FULL WALLET DUMP — deriving {len(wallets)} wallets (one-time)…")
    print("=" * 78)
    ordered = order_wallets(wallets, balances)
    for i, w in enumerate(ordered, 1):
        ensure_derived(w)
        sc, pend, chk = wallet_score(w, balances)
        print("-" * 78)
        print(f"[{i}/{len(ordered)}] {w.get('type')} sum={sc:.8f} pend={pend} zero={chk}")
        print(f"KEY: {w.get('key')}")
        print(f"SRC: {w.get('source')}")
        print(f"TS:  {w.get('timestamp')}")
        for (chain, addr) in sorted((w.get("addresses") or {}).keys()):
            bal = balances.get((chain, addr))
            bs = "PENDING" if bal is None else f"{bal:.8f}"
            flag = " ***" if isinstance(bal, (int, float)) and bal > 1e-12 else ""
            print(f"  {chain.upper():8} {addr}  {bs}{flag}")
        if i % 25 == 0:
            sys.stdout.flush()
    print("=" * 78)
    print(f"done — {len(ordered)} wallets")


def cycle(
    live: bool,
    batch: int,
    status_line: str = "",
    max_wallets: int = 0,
    page: int = 0,
    page_size: int = DEFAULT_PAGE_SIZE,
    show_all: bool = False,
    dump_all: bool = False,
):
    t0 = time.time()
    wallets = gather_wallets(max_wallets=max_wallets)
    balances, meta = load_balances()
    gather_ms = int((time.time() - t0) * 1000)

    if dump_all:
        dump_all_text(wallets, balances)
        return {"n_wallets": len(wallets), "all_keys": [], "pages": 1, "page": 0, "page_keys": []}

    status = status_line or ""
    if status:
        status = f"{status} · load {gather_ms}ms / {len(wallets)} keys"
    else:
        status = f"load {gather_ms}ms / {len(wallets)} keys"

    info = paint(
        wallets, balances, meta,
        status_line=status,
        live_note=("cache only" if not live else ""),
        page=page, page_size=page_size, show_all=show_all,
    )

    if not live:
        return info

    # refresh keys on current page first (what user sees), then other known keys
    page_keys = info.get("page_keys") or []
    all_keys = info.get("all_keys") or []
    # prioritize page keys
    seen = set()
    ordered_keys = []
    for k in list(page_keys) + list(all_keys):
        if k not in seen:
            seen.add(k)
            ordered_keys.append(k)
    targets = pick_refresh_targets(ordered_keys, balances, meta, batch=batch)
    if not targets:
        paint(
            wallets, balances, meta,
            status_line=status,
            live_note="page addrs fresh in cache",
            page=page, page_size=page_size, show_all=show_all,
        )
        return info

    thr = background_refresh(targets)
    start = time.time()
    while thr.is_alive() and time.time() - start < 75:
        time.sleep(1.2)
        balances, meta = load_balances()
        paint(
            wallets, balances, meta,
            status_line=status,
            live_note=f"refreshing {len(targets)} addrs…",
            page=page, page_size=page_size, show_all=show_all,
        )
    thr.join(timeout=1)
    balances, meta = load_balances()
    return paint(
        wallets, balances, meta,
        status_line=status,
        live_note=f"batch {len(targets)} live checks done",
        page=page, page_size=page_size, show_all=show_all,
    )


def main():
    ap = argparse.ArgumentParser(description="Wallet viewer — full paging, no permanent hide")
    ap.add_argument("-w", "--watch", action="store_true")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    ap.add_argument("--cached", action="store_true")
    ap.add_argument("--max-wallets", type=int, default=0, help="0 = all unique keys in memory tail")
    ap.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    ap.add_argument("--page-sec", type=int, default=DEFAULT_PAGE_SEC)
    ap.add_argument("--page", type=int, default=0, help="0-based page index")
    ap.add_argument("--all", action="store_true", help="with --once: full text dump of every wallet")
    ap.add_argument("--show-all-page", action="store_true", help="one giant scrolling page")
    args = ap.parse_args()

    # LIVE by default always — balances check via wired public + .env RPCs.
    # Only --cached skips network.
    live = not args.cached
    watch = args.watch or not args.once

    if not watch:
        cycle(
            live=live, batch=args.batch, max_wallets=args.max_wallets,
            page=max(0, args.page), page_size=max(1, args.page_size),
            show_all=args.show_all_page, dump_all=args.all,
        )
        return

    try:
        n = 0
        page = max(0, args.page)
        page_size = max(1, args.page_size)
        page_sec = max(3, int(args.page_sec))
        while True:
            n += 1
            status = (
                f"watch #{n} · auto-page every {page_sec}s · "
                f"rpc batch {args.batch}"
            )
            info = cycle(
                live=live, batch=args.batch, status_line=status,
                max_wallets=args.max_wallets,
                page=page, page_size=page_size,
                show_all=args.show_all_page,
            )
            pages = max(1, int(info.get("pages") or 1))
            # readable hold on this page
            hold = page_sec
            while hold > 0:
                time.sleep(1)
                hold -= 1
            page = (page + 1) % pages
            if page == 0:
                # brief breather after full rotation before heavier work
                extra = max(0, int(args.interval) - page_sec)
                while extra > 0:
                    time.sleep(1)
                    extra -= 1
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
