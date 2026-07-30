#!/usr/bin/env python3
"""
Wallet Balance Viewer — fast paging through ALL wallets, live refresh.

Fixes:
  - No more "28 wallets hidden forever" — pages rotate + NEXT UP index
  - No perpetual same-screen loop — page advances every --page-sec
  - Live RPC is NON-BLOCKING in watch mode (was freezing page up to 75s)
  - Nonzero-balance wallets from cache always float to page 1
  - Junk HEX (PNG headers, curve constants, low-entropy) filtered out
  - Address cache lookup is case-insensitive for EVM chains
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
MAX_ADDRS_SHOW = 64
DERIVE_CACHE: dict = {}

JUNK_HEX_EXACT = {
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
}
JUNK_HEX_PREFIXES = (
    "89504e47", "ffd8ffe0", "ffd8ffe1", "ffd8ffdb", "47494638",
    "504b0304", "7f454c46", "25504446", "d0cf11e0", "52494646",
)
EVM_CHAINS = {
    "eth", "matic", "avax", "bnb", "base", "arb", "op", "monad",
    "ftm", "cro", "gno", "scrl", "linea", "blast", "zksync",
}

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
_BAL_INDEX: dict = {}
_META_INDEX: dict = {}


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


def _is_noise_address(chain: str, addr: str) -> bool:
    """Burn/null/hardhat/demo — never count as real nonzero loot."""
    try:
        from crypto_iq import is_noise_address
        return bool(is_noise_address(chain, addr))
    except Exception:
        a = (addr or "").strip().lower()
        if a.startswith("0x") and len(a) == 42:
            body = a[2:]
            if body == "0" * 40 or body == "f" * 40 or len(set(body)) == 1:
                return True
            noise = {
                "0x000000000000000000000000000000000000dead",
                "0x1234567890123456789012345678901234567890",
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            }
            return a in noise
        return False


def _norm_addr(chain: str, addr: str) -> tuple:
    chain = (chain or "?").lower()
    addr = addr or ""
    if chain in EVM_CHAINS:
        return chain, addr.lower()
    return chain, addr


def load_balances():
    global _BAL_INDEX, _META_INDEX
    balances = {}
    meta = {}
    idx = {}
    midx = {}
    if not os.path.exists(CACHE_FILE) or os.path.getsize(CACHE_FILE) == 0:
        _BAL_INDEX, _META_INDEX = {}, {}
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
                nk = _norm_addr(chain, addr)
                ts = float(rec.get("ts") or 0)
                prev = meta.get(key)
                if prev and float(prev.get("ts") or 0) > ts:
                    continue
                prev_n = midx.get(nk)
                if prev_n and float(prev_n.get("ts") or 0) > ts:
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
                idx[nk] = key
                midx[nk] = meta[key]
    except Exception:
        pass
    _BAL_INDEX = idx
    _META_INDEX = midx
    return balances, meta


def bal_get(balances, chain, addr):
    key = (chain, addr)
    if key in balances:
        return balances[key]
    nk = _norm_addr(chain, addr)
    canon = _BAL_INDEX.get(nk)
    if canon is not None:
        return balances.get(canon)
    return balances.get((chain, (addr or "").lower()))


def meta_get(meta, chain, addr):
    key = (chain, addr)
    if key in meta:
        return meta[key]
    nk = _norm_addr(chain, addr)
    canon = _BAL_INDEX.get(nk)
    if canon is not None:
        return meta.get(canon) or {}
    return meta.get((chain, (addr or "").lower())) or {}


def format_balance(bal):
    if bal is None:
        return f"{YELLOW}…{RESET}"
    if isinstance(bal, (int, float)) and abs(bal) < 1e-18:
        return f"{DIM}0{RESET}"
    if isinstance(bal, (int, float)) and bal > 0:
        return f"{GREEN}{bal:,.8f}{RESET}"
    return str(bal)


# ── USD spot prices (CoinGecko, cached) ─────────────────────────────
# Native-token balances are chain units. Show ~$USD next to each balance.

PRICE_CACHE_FILE = os.path.join(HOME, ".token_prices.json")
PRICE_TTL_SEC = 300.0
_PRICE_LOCK = threading.Lock()
_PRICE_MEM: dict = {"ts": 0.0, "prices": {}, "source": ""}

CHAIN_CG_ID = {
    "btc": "bitcoin",
    "eth": "ethereum",
    "ltc": "litecoin",
    "doge": "dogecoin",
    "matic": "matic-network",
    "polygon": "matic-network",
    "sol": "solana",
    "xrp": "ripple",
    "avax": "avalanche-2",
    "bnb": "binancecoin",
    "bsc": "binancecoin",
    "arb": "ethereum",
    "op": "ethereum",
    "base": "ethereum",
    "blast": "ethereum",
    "scrl": "ethereum",
    "linea": "ethereum",
    "zksync": "ethereum",
    "monad": "ethereum",
    "ftm": "fantom",
    "cro": "crypto-com-chain",
    "gno": "gnosis",
}

CHAIN_TICKER = {
    "btc": "BTC", "eth": "ETH", "ltc": "LTC", "doge": "DOGE",
    "matic": "MATIC", "polygon": "MATIC", "sol": "SOL", "xrp": "XRP",
    "avax": "AVAX", "bnb": "BNB", "bsc": "BNB", "arb": "ETH", "op": "ETH",
    "base": "ETH", "blast": "ETH", "scrl": "ETH", "linea": "ETH",
    "zksync": "ETH", "monad": "MON", "ftm": "FTM", "cro": "CRO", "gno": "GNO",
}


def _load_price_disk() -> dict:
    try:
        if not os.path.exists(PRICE_CACHE_FILE):
            return {}
        with open(PRICE_CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("prices"), dict):
            return data
    except Exception:
        pass
    return {}


def _save_price_disk(prices: dict, source: str = "coingecko") -> None:
    try:
        payload = {
            "ts": time.time(),
            "source": source,
            "prices": prices,
            "checked_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        tmp = PRICE_CACHE_FILE + f".tmp.{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, PRICE_CACHE_FILE)
    except Exception:
        pass


def _fetch_coingecko_usd(ids: list) -> dict:
    """Return {cg_id: usd_float}. Empty on failure. Chunked to avoid CG drops."""
    if not ids:
        return {}
    try:
        import urllib.parse
        import urllib.request

        uniq = sorted(set(ids))
        out = {}
        # CoinGecko free tier occasionally omits ids from large batches —
        # pull in small chunks so every native token gets a spot.
        chunk_size = 6
        for i in range(0, len(uniq), chunk_size):
            chunk = uniq[i : i + chunk_size]
            q = urllib.parse.urlencode(
                {"ids": ",".join(chunk), "vs_currencies": "usd"}
            )
            url = f"https://api.coingecko.com/api/v3/simple/price?{q}"
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "walletx-forensic/1.0",
                    "Accept": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=8) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw)
            except Exception:
                continue
            for cid, body in (data or {}).items():
                if isinstance(body, dict) and body.get("usd") is not None:
                    try:
                        out[cid] = float(body["usd"])
                    except (TypeError, ValueError):
                        pass
        return out
    except Exception:
        return {}


def _normalize_price_map(raw: dict) -> dict:
    """Accept {chain: usd} or {cg_id: usd} → {chain: usd}."""
    if not raw:
        return {}
    out = {}
    cg_to_chains: dict = {}
    for ch, cid in CHAIN_CG_ID.items():
        cg_to_chains.setdefault(cid, []).append(ch)
    for k, v in raw.items():
        try:
            px = float(v)
        except (TypeError, ValueError):
            continue
        kl = str(k).lower()
        if kl in CHAIN_CG_ID:
            out[kl] = px
        elif kl in cg_to_chains:
            for ch in cg_to_chains[kl]:
                out[ch] = px
    return out


def get_usd_prices(force: bool = False) -> dict:
    """Map chain → USD spot. Cached in memory + ~/.token_prices.json (5 min)."""
    now = time.time()
    with _PRICE_LOCK:
        if (
            not force
            and _PRICE_MEM.get("prices")
            and (now - float(_PRICE_MEM.get("ts") or 0)) < PRICE_TTL_SEC
        ):
            return dict(_PRICE_MEM["prices"])

        disk = _load_price_disk()
        disk_ts = float(disk.get("ts") or 0)
        disk_prices = disk.get("prices") or {}
        if not force and disk_prices and (now - disk_ts) < PRICE_TTL_SEC:
            by_chain = _normalize_price_map(disk_prices)
            _PRICE_MEM["ts"] = disk_ts
            _PRICE_MEM["prices"] = by_chain
            _PRICE_MEM["source"] = disk.get("source") or "disk"
            return dict(by_chain)

        ids = sorted(set(CHAIN_CG_ID.values()))
        fetched = _fetch_coingecko_usd(ids)
        if fetched:
            by_chain = {}
            for chain, cid in CHAIN_CG_ID.items():
                if cid in fetched:
                    by_chain[chain] = float(fetched[cid])
            _PRICE_MEM["ts"] = now
            _PRICE_MEM["prices"] = by_chain
            _PRICE_MEM["source"] = "coingecko"
            _save_price_disk(fetched, source="coingecko")
            return dict(by_chain)

        if disk_prices:
            by_chain = _normalize_price_map(disk_prices)
            _PRICE_MEM["ts"] = now
            _PRICE_MEM["prices"] = by_chain
            _PRICE_MEM["source"] = "stale-disk"
            return dict(by_chain)
        if _PRICE_MEM.get("prices"):
            return dict(_PRICE_MEM["prices"])
        return {}


def chain_usd_price(chain: str, prices=None):
    if not chain:
        return None
    pxmap = prices if prices is not None else get_usd_prices()
    c = str(chain).lower().strip()
    v = pxmap.get(c)
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def usd_value(chain: str, amount, prices=None):
    if not isinstance(amount, (int, float)):
        return None
    if amount <= 1e-18:
        return 0.0
    px = chain_usd_price(chain, prices)
    if px is None:
        return None
    return float(amount) * float(px)


def format_usd(usd, width: int = 0, color: bool = True) -> str:
    """Compact $ display: $1.23  $12.3k  $1.2M  or '—' if unknown."""
    if usd is None:
        s = "—"
        if color and width:
            return f"{DIM}{s:>{width}}{RESET}"
        return f"{DIM}{s}{RESET}" if color else s
    try:
        u = float(usd)
    except (TypeError, ValueError):
        s = "—"
        return f"{DIM}{s:>{width}}{RESET}" if color and width else s
    if abs(u) < 1e-12:
        s = "$0"
    elif abs(u) < 0.01:
        s = f"${u:.4f}"
    elif abs(u) < 1000:
        s = f"${u:,.2f}"
    elif abs(u) < 1_000_000:
        s = f"${u / 1000:,.2f}k"
    else:
        s = f"${u / 1_000_000:,.2f}M"
    if color:
        col = GREEN if u > 0 else DIM
        return f"{col}{s:>{width}}{RESET}" if width else f"{col}{s}{RESET}"
    return f"{s:>{width}}" if width else s


def format_balance_with_usd(chain: str, bal, prices=None) -> str:
    """Token amount + $USD, e.g. '0.42344431  $1,482.05'."""
    base = format_balance(bal)
    if not isinstance(bal, (int, float)) or bal <= 1e-12:
        return base
    u = usd_value(chain, bal, prices)
    if u is None:
        return f"{base}  {DIM}$?{RESET}"
    return f"{base}  {format_usd(u, color=True)}"


def wallet_usd_total(w, balances, prices=None):
    """Sum USD across a wallet's derived addresses. None if no prices apply."""
    pxmap = prices if prices is not None else get_usd_prices()
    if not pxmap:
        return None
    total = 0.0
    any_priced = False
    addrs = w.get("addresses") or {}
    seen = set()
    for chain, addr in addrs:
        nk = _norm_addr(chain, addr)
        if nk in seen:
            continue
        seen.add(nk)
        if _is_noise_address(chain, addr):
            continue
        b = bal_get(balances, chain, addr)
        if not isinstance(b, (int, float)) or b <= 1e-12:
            continue
        u = usd_value(chain, b, pxmap)
        if u is not None:
            total += u
            any_priced = True
    return total if any_priced else None


def is_junk_hex(hv: str) -> bool:
    if not hv:
        return True
    h = hv.strip().lower().removeprefix("0x")
    if len(h) != 64:
        return True
    if h in JUNK_HEX_EXACT:
        return True
    if any(h.startswith(p) for p in JUNK_HEX_PREFIXES):
        return True
    # long zero runs → structured binary, not a private key
    if "000000" in h and h.count("00") >= 6:
        return True
    if len(set(h)) <= 4:
        return True
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return True
    if b.count(0) > 8:
        return True
    if len(set(b)) < 12:
        return True
    # high printable-ASCII ratio → text/binary misread as hex
    printable = sum(1 for x in b if 32 <= x < 127)
    if printable >= 24:
        return True
    # control-char heavy (DFM/resource dumps)
    controls = sum(1 for x in b if x < 32)
    if controls >= 10:
        return True
    # repeating byte pairs / mask patterns (ff00ff00, ffffffff…)
    if h.count("ff") >= 8 or h.count("00") >= 8:
        return True
    # low nibble diversity beyond earlier check
    if len(set(h[i:i+2] for i in range(0, 64, 2))) < 10:
        return True
    return False


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
            if len(hv) == 64 and not is_junk_hex(hv):
                raw = cs.priv_to_addresses(bytes.fromhex(hv))
            else:
                raw = {}
        elif key_type == "SEED":
            raw = cs.seed_to_addresses(key_value)
        elif key_type == "ADDR":
            chain = key_value.split(":", 1)[0] if ":" in key_value else "?"
            addr = key_value.split(":", 1)[1] if ":" in key_value else key_value
            raw = {chain: addr} if addr else {}
        else:
            raw = {}
        for chain, addr in (raw or {}).items():
            chain = (chain or "?").lower()
            if addr:
                addrs[(chain, addr)] = {
                    "chain": chain, "address": addr, "from": key_type.lower()
                }
    except Exception:
        addrs = {}
    DERIVE_CACHE[ck] = addrs
    return addrs


def _inject_hit_wallets(wallets: dict):
    """Promote every nonzero cached/hit address so funded wallets always page-1."""
    hit_rows = []
    for path in (HITS_FILE, CACHE_FILE):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    bal = rec.get("balance")
                    if not isinstance(bal, (int, float)) or bal <= 1e-12:
                        continue
                    chain = (rec.get("chain") or "?").lower()
                    addr = rec.get("address") or ""
                    if not addr:
                        continue
                    if _is_noise_address(chain, addr):
                        continue
                    hit_rows.append((float(bal), chain, addr, rec))
        except Exception:
            pass
    hit_rows.sort(key=lambda t: t[0], reverse=True)
    seen_hit = set()
    for bal, chain, addr, rec in hit_rows:
        nk = _norm_addr(chain, addr)
        if nk in seen_hit:
            continue
        seen_hit.add(nk)
        syn_key = f"{chain}:{addr}"
        k = ("ADDR", syn_key)
        if k in wallets:
            wallets[k]["_hit_boost"] = max(
                float(wallets[k].get("_hit_boost") or 0.0), float(bal)
            )
            continue
        wallets[k] = {
            "type": "ADDR",
            "key": syn_key,
            "addresses": {
                (chain, addr): {"chain": chain, "address": addr, "from": "hit"}
            },
            "timestamp": rec.get("checked_at") or "",
            "source": rec.get("source") or "balance_hit",
            "_derived": True,
            "_hit_boost": float(bal),
        }


def gather_wallets(max_wallets: int = 0, include_hits: bool = True):
    """Collect unique wallet keys FAST — no crypto derive here."""
    wallets = {}
    records = load_jsonl_tail(MEMORY_FILE, MEMORY_TAIL_BYTES)
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
            if kt == "HEX":
                hx = kv.lower().removeprefix("0x") if isinstance(kv, str) else ""
                if len(hx) != 64:
                    return
                try:
                    int(hx, 16)
                except ValueError:
                    return
                if is_junk_hex(hx):
                    return
            elif kt == "WIF":
                if not isinstance(kv, str) or len(kv) < 50:
                    return
            wallets[k] = {
                "type": kt,
                "key": kv,
                "addresses": {},
                "timestamp": ts,
                "source": src,
                "_derived": False,
                "_hit_boost": 0.0,
            }

        for wif in wallet.get("wifs") or []:
            add("WIF", wif)
        for hx in wallet.get("hex_keys") or []:
            add("HEX", hx)
        for seed in wallet.get("seed_phrases") or []:
            add("SEED", seed)

        if max_wallets and len(wallets) >= max_wallets:
            break

    if include_hits:
        _inject_hit_wallets(wallets)

    return sorted(
        wallets.values(), key=lambda x: x.get("timestamp") or "", reverse=True
    )


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
    """Score using derived addrs if present, else hit_boost."""
    addrs = w.get("addresses") or {}
    if not addrs and not w.get("_derived"):
        ck = (w.get("type"), w.get("key"))
        addrs = DERIVE_CACHE.get(ck) or {}
    pos_sum = 0.0
    pending = 0
    checked = 0
    seen_n = set()
    for chain, addr in addrs:
        nk = _norm_addr(chain, addr)
        if nk in seen_n:
            continue
        seen_n.add(nk)
        b = bal_get(balances, chain, addr)
        if isinstance(b, (int, float)) and b > 1e-12:
            pos_sum += float(b)
        elif b is None:
            pending += 1
        else:
            checked += 1
    boost = float(w.get("_hit_boost") or 0.0)
    s = pos_sum if pos_sum > 0 else boost
    return s, pending, checked


def order_wallets(wallets, balances):
    """Nonzero / hit-boost first, then newest. Lazy — won't derive all."""
    scored = []
    for w in wallets:
        sc, pend, chk = wallet_score(w, balances)
        boost = 1 if sc > 0 or (w.get("_hit_boost") or 0) > 0 else 0
        scored.append((boost, sc, w.get("timestamp") or "", w))
    scored.sort(key=lambda t: (t[0], t[1], t[2]), reverse=True)
    return [w for _, _, _, w in scored]


def pick_refresh_targets(all_keys, balances, meta, batch: int):
    now = time.time()
    pending = []
    stale = []
    for k in all_keys:
        chain, addr = k
        bal = bal_get(balances, chain, addr)
        m = meta_get(meta, chain, addr) or {}
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
    stale.sort(
        key=lambda k: float((meta_get(meta, k[0], k[1]) or {}).get("ts") or 0)
    )
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
                            (
                                (rec.get("chain") or "").lower(),
                                rec.get("address") or "",
                                rec.get("balance"),
                            )
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
                    "checked_at": datetime.now(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z"),
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

    peek_end = min(n_wallets, end + 12)
    ensure_derived_many(ordered[start:peek_end])

    all_keys = collect_keys_from_wallets([w for w in ordered if w.get("_derived")])
    for addrs in DERIVE_CACHE.values():
        for k in addrs:
            if k not in all_keys:
                all_keys.append(k)

    wallet_keys = list(all_keys)
    for (chain, addr), bal in balances.items():
        if isinstance(bal, (int, float)) and bal > 1e-12 and not _is_noise_address(chain, addr):
            k = (chain, addr)
            if k not in wallet_keys:
                wallet_keys.append(k)

    nonzero_keys = []
    nz_seen = set()
    for k in wallet_keys:
        if _is_noise_address(k[0], k[1]):
            continue
        b = bal_get(balances, k[0], k[1])
        if isinstance(b, (int, float)) and b > 1e-12:
            nk = _norm_addr(k[0], k[1])
            if nk in nz_seen:
                continue
            nz_seen.add(nk)
            nonzero_keys.append(k)

    total = sum(float(bal_get(balances, k[0], k[1]) or 0) for k in nonzero_keys)
    pending = sum(1 for k in all_keys if bal_get(balances, k[0], k[1]) is None)
    zeroed = sum(
        1
        for k in all_keys
        if isinstance(bal_get(balances, k[0], k[1]), (int, float))
        and bal_get(balances, k[0], k[1]) <= 1e-12
    )

    prices = get_usd_prices()
    total_usd = 0.0
    any_usd = False
    for k in nonzero_keys:
        u = usd_value(k[0], bal_get(balances, k[0], k[1]), prices)
        if u is not None:
            total_usd += u
            any_usd = True

    newest = None
    for k in wallet_keys:
        ca = (meta_get(meta, k[0], k[1]) or {}).get("checked_at")
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
    print(
        f"  Nonzero / zero / unresolved: "
        f"{len(nonzero_keys):>4} / {zeroed:<5} / {pending}"
    )
    print(f"  Total nonzero (truth):       {GREEN}{total:,.8f}{RESET}")
    if any_usd:
        print(
            f"  Portfolio USD (approx):      {format_usd(total_usd, color=True)}"
            f"  {DIM}(CoinGecko spot){RESET}"
        )
    print(
        f"  Updated:                     "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    if newest:
        print(f"  Last on-chain check:         {newest}")
    print(
        f"  {CYAN}PAGE {page + 1}/{pages}{RESET}  "
        f"wallets {start + 1 if n_wallets else 0}–{end} of {n_wallets}  "
        f"· size {page_size}  · auto-rotates every page-sec"
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
            "total": total,
            "nonzero": len(nonzero_keys),
            "pending": pending,
            "all_keys": all_keys,
            "pages": pages,
            "page": page,
            "n_wallets": 0,
            "page_keys": [],
        }

    print(f"  {BOLD}INDEX — page {page + 1}/{pages}{RESET}")
    print(f"  {'#':>4}  {'TYPE':<5}  {'NZ':>8}  {'P':>3}  KEY / SRC")
    print(f"  {'-'*4}  {'-'*5}  {'-'*8}  {'-'*3}  {'-'*52}")
    for i, w in enumerate(page_wallets, start=start + 1):
        sc, pend, _ = wallet_score(w, balances)
        usd = wallet_usd_total(w, balances, prices)
        if sc > 0 and usd is not None:
            nz_s = f"{GREEN}{sc:.6g}{RESET} {format_usd(usd, color=True)}"
        elif sc > 0:
            nz_s = f"{GREEN}{sc:.6g}{RESET}"
        else:
            nz_s = f"{DIM}0{RESET}"
        src = w.get("source") or ""
        if len(src) > 28:
            src = "…" + src[-27:]
        print(
            f"  {i:>4}  {w.get('type', '?'):<5}  {nz_s}  {pend:>3}  "
            f"{_short_key(w.get('key') or '', 40)}  {DIM}{src}{RESET}"
        )

    if end < n_wallets and not show_all:
        left = n_wallets - end
        peek_n = min(15, left)
        print()
        nxt_page = page + 2
        print(
            f"  {BOLD}WHERE THE REST ARE{RESET}  "
            f"{DIM}({left} more → pages {nxt_page}–{pages}){RESET}"
        )
        for i, w in enumerate(ordered[end : end + peek_n], start=end + 1):
            sc, _, _ = wallet_score(w, balances)
            star = f"{GREEN}*{RESET}" if sc > 0 else " "
            tgt_page = (i - 1) // page_size + 1
            print(
                f"  {DIM}{star}#{i:<4} p{tgt_page:<3} {w.get('type', '?'):<4} "
                f"{_short_key(w.get('key') or '', 46)}{RESET}"
            )
        if left > peek_n:
            print(
                f"  {DIM}  … +{left - peek_n} more keys; "
                f"watch mode flips page every few seconds{RESET}"
            )
        print(
            f"  {DIM}  jump:  python3 ~/wallet_view.py --once --cached --page N{RESET}"
        )
        print(
            f"  {DIM}  dump:  python3 ~/wallet_view.py --once --all --cached | less{RESET}"
        )

    print()
    print(f"  {BOLD}DETAIL — page {page + 1}/{pages}{RESET}")
    page_keys = []
    for idx, w in enumerate(page_wallets, start=start + 1):
        ensure_derived(w)
        sc, pend, chk = wallet_score(w, balances)
        w_usd = wallet_usd_total(w, balances, prices)
        usd_bit = f"  usd≈{format_usd(w_usd, color=True)}" if w_usd is not None else ""
        print("-" * 78)
        print(
            f"  [{idx}/{n_wallets}] TYPE={w.get('type')}  "
            f"bal_sum={sc:.8f}{usd_bit}  unresolved={pend}  zero={chk}"
        )
        # FULL key — never truncate (wrap only)
        _k = w.get("key") or ""
        if len(_k) <= 72:
            print(f"  KEY:  {_k}")
        else:
            print(f"  KEY:  {_k[:72]}")
            _rest = _k[72:]
            while _rest:
                print(f"        {_rest[:72]}")
                _rest = _rest[72:]
        print(f"  KEY_LEN: {len(_k)} chars (complete)")
        src = w.get("source") or ""
        if src:
            if len(src) <= 72:
                print(f"  SRC:  {src}")
            else:
                print(f"  SRC:  {src[:72]}")
                _rest = src[72:]
                while _rest:
                    print(f"        {_rest[:72]}")
                    _rest = _rest[72:]
        if w.get("timestamp"):
            print(f"  TS:   {w.get('timestamp')}")
        print()
        addrs = list((w.get("addresses") or {}).items())

        def addr_rank(item):
            (chain, addr), _ = item
            b = bal_get(balances, chain, addr)
            page_keys.append((chain, addr))
            if isinstance(b, (int, float)) and b > 1e-12:
                return (0, -float(b), chain)
            if b is None:
                return (1, 0, chain)
            return (2, 0, chain)

        addrs_sorted = sorted(addrs, key=addr_rank)
        show_list = addrs_sorted[:MAX_ADDRS_SHOW]
        print(f"  {'CHAIN':>8}  {'ADDRESS':<46}  {'BALANCE':>14}  {'USD':>10}")
        print(f"  {'-'*8}  {'-'*46}  {'-'*14}  {'-'*10}")
        for (chain, addr), _ in show_list:
            bal = bal_get(balances, chain, addr)
            mark = (
                f"{GREEN}*** {RESET}"
                if isinstance(bal, (int, float)) and bal > 1e-12
                else "    "
            )
            usd_s = ""
            if isinstance(bal, (int, float)) and bal > 1e-12:
                usd_s = format_usd(usd_value(chain, bal, prices), width=10, color=True)
            else:
                usd_s = f"{DIM}{'—':>10}{RESET}"
            # FULL address — never truncate
            if len(addr) <= 46:
                print(
                    f"{mark}{chain.upper():>8}  "
                    f"{addr:<46}  {format_balance(bal):>14}  {usd_s}"
                )
            else:
                print(f"{mark}{chain.upper():>8}  {addr}")
                print(f"{'':>10}  {'':<46}  {format_balance(bal):>14}  {usd_s}")
        rest = len(addrs_sorted) - len(show_list)
        if rest > 0:
            print(
                f"  {DIM}  … {rest} more chains/addrs "
                f"(all listed in --all dump){RESET}"
            )
        if not addrs_sorted:
            print(f"  {DIM}  (no derived addresses){RESET}")
        print()

    print("-" * 78)
    print(
        f"  Page {page + 1}/{pages}  ·  {n_wallets} wallets total  ·  "
        f"nothing permanently hidden — pages rotate in watch mode"
    )
    print(
        f"  {DIM}walletall  |  walletpage N  |  --page-size 20  |  "
        f"Ctrl+C = exit view only{RESET}"
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
        print(
            f"[{i}/{len(ordered)}] {w.get('type')} "
            f"sum={sc:.8f} pend={pend} zero={chk}"
        )
        print(f"KEY: {w.get('key')}")
        print(f"SRC: {w.get('source')}")
        print(f"TS:  {w.get('timestamp')}")
        for chain, addr in sorted((w.get("addresses") or {}).keys()):
            bal = bal_get(balances, chain, addr)
            bs = "PENDING" if bal is None else f"{bal:.8f}"
            flag = (
                " ***" if isinstance(bal, (int, float)) and bal > 1e-12 else ""
            )
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
    block_refresh: bool = True,
):
    """One paint + optional live refresh.

    block_refresh=True  → --once: wait for batch (up to 75s)
    block_refresh=False → watch: fire-and-forget so pages keep rotating
    """
    t0 = time.time()
    wallets = gather_wallets(max_wallets=max_wallets)
    balances, meta = load_balances()
    gather_ms = int((time.time() - t0) * 1000)

    if dump_all:
        dump_all_text(wallets, balances)
        return {
            "n_wallets": len(wallets),
            "all_keys": [],
            "pages": 1,
            "page": 0,
            "page_keys": [],
        }

    status = status_line or ""
    if status:
        status = f"{status} · load {gather_ms}ms / {len(wallets)} keys"
    else:
        status = f"load {gather_ms}ms / {len(wallets)} keys"

    info = paint(
        wallets,
        balances,
        meta,
        status_line=status,
        live_note=("cache only" if not live else ""),
        page=page,
        page_size=page_size,
        show_all=show_all,
    )

    if not live:
        return info

    page_keys = info.get("page_keys") or []
    all_keys = info.get("all_keys") or []
    seen = set()
    ordered_keys = []
    for k in list(page_keys) + list(all_keys):
        if k not in seen:
            seen.add(k)
            ordered_keys.append(k)
    targets = pick_refresh_targets(ordered_keys, balances, meta, batch=batch)

    if not targets:
        paint(
            wallets,
            balances,
            meta,
            status_line=status,
            live_note="page addrs fresh in cache",
            page=page,
            page_size=page_size,
            show_all=show_all,
        )
        return info

    with _refresh_lock:
        already = bool(_refresh_state.get("running"))

    if already:
        paint(
            wallets,
            balances,
            meta,
            status_line=status,
            live_note="live refresh still running (non-blocking)",
            page=page,
            page_size=page_size,
            show_all=show_all,
        )
        return info

    thr = background_refresh(targets)

    if not block_refresh:
        paint(
            wallets,
            balances,
            meta,
            status_line=status,
            live_note=f"live refresh started ({len(targets)} addrs, background)",
            page=page,
            page_size=page_size,
            show_all=show_all,
        )
        return info

    start = time.time()
    while thr.is_alive() and time.time() - start < 75:
        time.sleep(1.2)
        balances, meta = load_balances()
        paint(
            wallets,
            balances,
            meta,
            status_line=status,
            live_note=f"refreshing {len(targets)} addrs…",
            page=page,
            page_size=page_size,
            show_all=show_all,
        )
    thr.join(timeout=1)
    balances, meta = load_balances()
    return paint(
        wallets,
        balances,
        meta,
        status_line=status,
        live_note=f"batch {len(targets)} live checks done",
        page=page,
        page_size=page_size,
        show_all=show_all,
    )


def main():
    ap = argparse.ArgumentParser(
        description="Wallet viewer — full paging, no permanent hide"
    )
    ap.add_argument("-w", "--watch", action="store_true")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL)
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    ap.add_argument("--cached", action="store_true")
    ap.add_argument(
        "--max-wallets",
        type=int,
        default=0,
        help="0 = all unique keys in memory tail",
    )
    ap.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    ap.add_argument("--page-sec", type=int, default=DEFAULT_PAGE_SEC)
    ap.add_argument("--page", type=int, default=0, help="0-based page index")
    ap.add_argument(
        "--all",
        action="store_true",
        help="with --once: full text dump of every wallet",
    )
    ap.add_argument(
        "--show-all-page", action="store_true", help="one giant scrolling page"
    )
    args = ap.parse_args()

    live = not args.cached
    watch = args.watch or not args.once

    if not watch:
        cycle(
            live=live,
            batch=args.batch,
            max_wallets=args.max_wallets,
            page=max(0, args.page),
            page_size=max(1, args.page_size),
            show_all=args.show_all_page,
            dump_all=args.all,
            block_refresh=True,
        )
        return

    try:
        n = 0
        page = max(0, args.page)
        page_size = max(1, args.page_size)
        page_sec = max(3, int(args.page_sec))
        next_flip = time.time() + page_sec
        while True:
            n += 1
            status = (
                f"watch #{n} · page {page + 1} · auto-page every {page_sec}s · "
                f"rpc batch {args.batch}"
            )
            info = cycle(
                live=live,
                batch=args.batch,
                status_line=status,
                max_wallets=args.max_wallets,
                page=page,
                page_size=page_size,
                show_all=args.show_all_page,
                block_refresh=False,
            )
            pages = max(1, int(info.get("pages") or 1))

            while True:
                now = time.time()
                left = next_flip - now
                if left <= 0:
                    break
                time.sleep(min(1.0, left))
                if left > 1.5:
                    balances, meta = load_balances()
                    wallets = gather_wallets(max_wallets=args.max_wallets)
                    with _refresh_lock:
                        rs = dict(_refresh_state)
                    note = ""
                    if rs.get("running"):
                        note = (
                            f"live {rs.get('done', 0)}/{rs.get('total', 0)} "
                            f"{rs.get('last_msg', '')}"
                        )
                    paint(
                        wallets,
                        balances,
                        meta,
                        status_line=status + f" · flip in {int(left)}s",
                        live_note=note,
                        page=page,
                        page_size=page_size,
                        show_all=args.show_all_page,
                    )

            page = (page + 1) % pages
            next_flip = time.time() + page_sec
            if page == 0:
                extra = max(0, int(args.interval) - page_sec)
                if extra:
                    time.sleep(extra)
                    next_flip = time.time() + page_sec
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
