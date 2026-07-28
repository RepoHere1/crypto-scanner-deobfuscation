#!/usr/bin/env python3
"""
Crypto Scanner and Balance Checker v2.0

Upgrades in this version:
  - Address checksum validation (BTC, ETH, SOL, ...)
  - Private-key -> address derivation and balance check
  - Multi-provider balance checks with retry + persistent cache
  - Contextual correlation of keys / addresses / seed phrases
  - Tightened regexes + new secret patterns
  - Normalized input that accepts both raw text and truffleHog JSONL
  - Android notifications via termux-notification
"""
import json
import re
import sys
import os
import time
import math
import hashlib
import base64
import functools
import threading
import queue as queue_module
import logging
import shutil
from urllib.error import URLError, HTTPError
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any

# Third-party packages installed via pip3 install base58 ecdsa requests mnemonic
try:
    import base58
except ImportError:
    raise SystemExit("[!] base58 is required: pip3 install base58")
try:
    import ecdsa
except ImportError:
    raise SystemExit("[!] ecdsa is required: pip3 install ecdsa")
try:
    import requests
except ImportError:
    raise SystemExit("[!] requests is required: pip3 install requests")
try:
    from mnemonic import Mnemonic
except ImportError:
    raise SystemExit("[!] mnemonic is required: pip3 install mnemonic")

# ---------------------------------------------------------------------------
# WiFi resilience helpers
# ---------------------------------------------------------------------------
_WIFI_WAIT_INTERVAL = 30  # seconds between connectivity checks
_WIFI_WAIT_TIMEOUT = None  # None = wait forever; set to seconds for a limit

def is_wifi_connected(timeout: float = 5.0) -> bool:
    """Return True if the device has working internet connectivity."""
    try:
        requests.head(
            "https://www.google.com",
            timeout=timeout,
            headers={"User-Agent": "RepoHere1-Termux/2.0"},
        )
        return True
    except Exception:
        return False


def wait_for_wifi(
    check_interval: float = _WIFI_WAIT_INTERVAL,
    max_wait: float | None = _WIFI_WAIT_TIMEOUT,
) -> None:
    """Block until WiFi/internet connectivity is restored, or *max_wait*
    seconds elapse (whichever comes first).  Default *max_wait* is
    ``None`` — wait forever.  In production callers typically pass a
    finite ceiling so a single stuck provider doesn't freeze a worker
    thread indefinitely."""
    logger.info("[wifi] No connectivity — waiting for WiFi to return...")
    start = time.time()
    while True:
        if is_wifi_connected(timeout=5):
            logger.info("[wifi] Connectivity restored — resuming.")
            return
        if max_wait is not None and (time.time() - start) >= max_wait:
            logger.warning("[wifi] Wait timed out after %.0fs — proceeding anyway.", max_wait)
            return
        time.sleep(check_interval)


def _is_connectivity_error(exc: BaseException) -> bool:
    """Return True if *exc* looks like a lost-WiFi / network-level failure
    rather than a provider-side issue.  Timeouts are excluded because a
    slow provider is not the same as no WiFi."""
    if isinstance(exc, requests.ConnectionError):
        return True
    msg = str(exc).lower()
    keywords = (
        "connection refused",
        "connection reset",
        "connection aborted",
        "name or service not known",
        "no address associated",
        "network is unreachable",
        "temporary failure in name resolution",
        "err_connection",
    )
    return any(kw in msg for kw in keywords)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CHECK_INTERVAL = 5
ENTROPY_THRESHOLD = 4.0
MIN_BASE64_LEN = 20
MIN_BASE58_LEN = 25
SCAN_FILE = sys.argv[1] if len(sys.argv) > 1 else ".trufflehog_results.jsonl"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
MEMORY_FILE = os.path.join(APP_DIR, "crypto_scanner_memory.jsonl")
PID_FILE = os.path.join(APP_DIR, ".run_pids", "crypto_scanner.pid")
STATUS_FILE = os.path.join(APP_DIR, "crypto_scanner_status.txt")
BALANCE_CACHE_FILE = os.path.join(APP_DIR, "balance_cache.jsonl")
HIGH_CONFIDENCE_FILE = os.path.join(APP_DIR, "high_confidence_hits.jsonl")
BALANCE_HIT_FILE = os.path.join(APP_DIR, "balances_hit.jsonl")

# ---------------------------------------------------------------------------
# Disk space safety
# ---------------------------------------------------------------------------
SAFE_SHUTDOWN_THRESHOLD_MB = 100  # MB free below this → controlled shutdown
CONTROLLED_SHUTDOWN_FLAG = os.path.join(APP_DIR, ".controlled_shutdown")
CHECKPOINT_FILE = os.path.join(APP_DIR, ".scanner_checkpoint")

# Optional API keys read from env
ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ALCHEMY_KEY = os.environ.get("ALCHEMY_API_KEY", "")
ANKR_API_KEY = os.environ.get("ANKR_API_KEY", "")

# Load user-supplied RPC endpoints discovered by paste_box.py.
# We dedupe them and drop known-broken / key-required placeholders so a noisy
# rpc_endpoints.jsonl file cannot drown out the curated public providers.
USER_RPC_ENDPOINTS: Dict[str, List[str]] = {"eth": [], "sol": [], "btc": [], "matic": [], "avax": [], "bnb": []}
_RPC_FILE = os.path.join(APP_DIR, "rpc_endpoints.jsonl")
_BLOCKED_RPC_PARTS = (
    "YOUR_ALCHEMY_KEY",
    "llamarpc.com",
    "meowrpc.com",
    "cloudflare-eth.com",
    "bsc-dataseed.binance.org",
    "polygon-rpc.com",
    "avalanche.public-rpc.com",
    "bscrpc.com",
)

def _is_keyless_ankr(url: str) -> bool:
    """Keyless Ankr URLs require an API key and just waste time."""
    if "rpc.ankr.com" not in url.lower():
        return False
    # A keyed URL looks like .../eth/<64-char-key>. A keyless URL ends with the chain name.
    last = url.rstrip("/").rsplit("/", 1)[-1]
    return len(last) != 64

if os.path.exists(_RPC_FILE):
    try:
        seen_urls: set = set()
        with open(_RPC_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                url = rec.get("url", "").strip().rstrip("/")
                if not url or url in seen_urls:
                    continue
                if any(part.lower() in url.lower() for part in _BLOCKED_RPC_PARTS):
                    continue
                if _is_keyless_ankr(url):
                    continue
                seen_urls.add(url)
                low = url.lower()
                if "solana" in low or "sol" in low:
                    USER_RPC_ENDPOINTS["sol"].append(url)
                elif "polygon" in low or "matic" in low:
                    USER_RPC_ENDPOINTS["matic"].append(url)
                elif "binance" in low or "bsc" in low:
                    USER_RPC_ENDPOINTS["bnb"].append(url)
                elif "avax" in low or "avalanche" in low:
                    USER_RPC_ENDPOINTS["avax"].append(url)
                elif "bitcoin" in low or "btc" in low:
                    USER_RPC_ENDPOINTS["btc"].append(url)
                else:
                    USER_RPC_ENDPOINTS["eth"].append(url)
    except Exception as e:
        logger.debug("Could not load RPC endpoints: %s", e)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(os.path.join(APP_DIR, "crypto_scanner.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("CryptoScanner")


# Pure-Python Keccak-256 (Ethereum)
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
    """Return Keccak-256 digest (as used by Ethereum)."""
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

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
BIP39_WORDS = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach",
    "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame",
    "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur",
    "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost",
    "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring",
    "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubbles", "buddy",
    "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer", "buzz"
}

WIF_PAT = re.compile(r"\b([5][1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})\b")
HEX_KEY_PAT = re.compile(r"\b[0-9a-fA-F]{64}\b")
BTC_ADDR = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
BTC_BECH32 = re.compile(r"\bbc1[a-z0-9]{8,87}\b")
ETH_ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
LTC_ADDR = re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
LTC_BECH32 = re.compile(r"\bltc1[a-z0-9]{8,87}\b")
SOL_ADDR = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
DOGE_ADDR = re.compile(r"\bD[5KL][1-9A-HJ-NP-Za-km-z]{32,34}\b")
XRP_ADDR = re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{25,34}\b")
TON_ADDR = re.compile(r"\b[UE]Q[a-zA-Z0-9_-]{46}\b")
AVAX_ADDR = re.compile(r"\b[XC][1-9A-HJ-NP-Za-km-z]{33}\b")
MATIC_ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")

AWS_KEY_PAT = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9_]{36}\b")
GITHUB_PAT2 = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?\b")
STRIPE_KEY = re.compile(r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b")

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def validate_btc_address(addr: str) -> bool:
    if addr.startswith(("1", "3")):
        try:
            return len(base58.b58decode_check(addr)) == 21
        except Exception:
            return False
    if addr.startswith("bc1"):
        return 14 <= len(addr) <= 74
    return False

def validate_ltc_address(addr: str) -> bool:
    if addr.startswith(("L", "M", "3")):
        try:
            return len(base58.b58decode_check(addr)) == 21
        except Exception:
            return False
    if addr.startswith("ltc1"):
        return 14 <= len(addr) <= 74
    return False

def validate_sol_address(addr: str) -> bool:
    try:
        decoded = base58.b58decode(addr)
        return len(decoded) == 32
    except Exception:
        return False

def validate_eth_address(addr: str) -> bool:
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        return False
    try:
        addr_lower = addr[2:].lower()
        hashed = keccak_256(addr_lower.encode("ascii")).hex()
        for i, ch in enumerate(addr[2:]):
            if ch.isalpha():
                expected_upper = hashed[i] in "89abcdef"
                if expected_upper and not ch.isupper():
                    return False
                if not expected_upper and not ch.islower():
                    return False
        return True
    except Exception:
        return True

def validate_seed_phrase(words: List[str]) -> bool:
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    return Mnemonic("english").check(" ".join(words).lower())

# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
def wif_to_btc_address(wif: str) -> Optional[str]:
    """Decode WIF -> compressed Bitcoin address."""
    try:
        decoded = base58.b58decode_check(wif)
        if len(decoded) not in (33, 34):
            return None
        priv = decoded[1:33]
        compressed = len(decoded) == 34 and decoded[33] == 0x01
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compressed:
            x, y = vk.to_string()[:32], vk.to_string()[32:]
            prefix = b"\x02" if int.from_bytes(y, "big") % 2 == 0 else b"\x03"
            pub = prefix + x
        else:
            pub = b"\x04" + vk.to_string()
        sha = hashlib.sha256(pub).digest()
        ripe = hashlib.new("ripemd160", sha).digest()
        return base58.b58encode_check(b"\x00" + ripe).decode()
    except Exception as e:
        logger.debug("WIF derivation failed: %s", e)
        return None


def wif_to_priv_bytes(wif: str) -> Optional[bytes]:
    """Decode WIF -> 32-byte private key."""
    try:
        decoded = base58.b58decode_check(wif)
        if len(decoded) not in (33, 34):
            return None
        return decoded[1:33]
    except Exception as e:
        logger.debug("WIF decode failed: %s", e)
        return None


def hex_to_eth_address(hex_key: str) -> Optional[str]:
    """64-char hex private key -> checksummed Ethereum address."""
    try:
        priv = bytes.fromhex(hex_key)
        if len(priv) != 32 or priv == bytes(32):
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
    except Exception as e:
        logger.debug("ETH derivation failed: %s", e)
        return None

def hex_to_sol_address(hex_key: str) -> Optional[str]:
    """64-char hex private key -> Solana address (base58 public key)."""
    try:
        priv = bytes.fromhex(hex_key)
        if len(priv) != 32 or priv == bytes(32):
            return None
        # Prefer PyNaCl; fallback to solders/keypair if available
        try:
            from nacl.bindings import crypto_sign_seed_keypair
            pub, _ = crypto_sign_seed_keypair(priv)
            return base58.b58encode(pub).decode()
        except Exception:
            pass
        try:
            from solders.keypair import Keypair
            kp = Keypair.from_seed(priv)
            return str(kp.pubkey())
        except Exception:
            pass
        return None
    except Exception as e:
        logger.debug("SOL derivation failed: %s", e)
        return None


def priv_to_compressed_pub(priv: bytes) -> bytes:
    """32-byte private key -> 33-byte compressed public key (secp256k1)."""
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x, y = vk.to_string()[:32], vk.to_string()[32:]
    prefix = b"\x02" if int.from_bytes(y, "big") % 2 == 0 else b"\x03"
    return prefix + x


def pub_to_p2pkh(pub: bytes, version_byte: int) -> str:
    """Compressed public key -> Base58Check P2PKH address with given version byte."""
    sha = hashlib.sha256(pub).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return base58.b58encode_check(bytes([version_byte]) + ripe).decode()


def priv_to_addresses(priv: bytes) -> Dict[str, str]:
    """32-byte private key -> addresses for common chains."""
    if len(priv) != 32 or priv == bytes(32):
        return {}
    try:
        pub = priv_to_compressed_pub(priv)
        addresses = {
            "btc": pub_to_p2pkh(pub, 0x00),
            "ltc": pub_to_p2pkh(pub, 0x30),
            "doge": pub_to_p2pkh(pub, 0x1e),
        }
        # ETH / EVM chains share address format
        eth_addr = hex_to_eth_address(priv.hex())
        if eth_addr:
            addresses["eth"] = eth_addr
            addresses["matic"] = eth_addr
            addresses["avax"] = eth_addr
            addresses["bnb"] = eth_addr
            addresses["base"] = eth_addr
            addresses["monad"] = eth_addr
        sol_addr = hex_to_sol_address(priv.hex())
        if sol_addr:
            addresses["sol"] = sol_addr
        return addresses
    except Exception as e:
        logger.debug("priv_to_addresses failed: %s", e)
        return {}


def seed_to_addresses(seed_phrase: str) -> Dict[str, str]:
    """BIP39 seed phrase -> deterministic addresses (master key = first 32 bytes of seed)."""
    try:
        mnemo = Mnemonic("english")
        if not mnemo.check(seed_phrase):
            return {}
        seed = mnemo.to_seed(seed_phrase)
        return priv_to_addresses(seed[:32])
    except Exception as e:
        logger.debug("seed_to_addresses failed: %s", e)
        return {}


# ---------------------------------------------------------------------------
# Throttling helpers
# ---------------------------------------------------------------------------
import gc


def available_memory_mb() -> float:
    """Return available memory in MB by reading /proc/meminfo."""
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    return kb / 1024.0
    except Exception:
        pass
    return 0.0


def throttle_cpu_ram(sleep_base: float = 0.05):
    """Sleep a little and collect garbage if memory is low."""
    time.sleep(sleep_base)
    mem = available_memory_mb()
    if 0 < mem < 256:
        logger.info("Throttling: low memory (%.1f MB available)", mem)
        gc.collect()
        time.sleep(sleep_base * 4)
    elif mem >= 256:
        logger.debug("Memory OK: %.1f MB available", mem)


# ---------------------------------------------------------------------------
# Disk space safety
# ---------------------------------------------------------------------------
def check_disk_space(threshold_mb: float = SAFE_SHUTDOWN_THRESHOLD_MB) -> Optional[str]:
    """Return None if free space > *threshold_mb*, otherwise a human-readable
    warning string.  Uses the APP_DIR filesystem (where all scan files live)."""
    try:
        usage = shutil.disk_usage(APP_DIR)
        free_mb = usage.free / (1024 * 1024)
        if free_mb < threshold_mb:
            return f"Only {free_mb:.1f} MB free (threshold {threshold_mb} MB)"
    except Exception as exc:
        logger.debug("check_disk_space: %s", exc)
    return None


def save_checkpoint(processed: int, findings_total: int) -> None:
    """Persist scanner state so it can resume after a controlled shutdown."""
    data = {
        "processed": processed,
        "findings_total": findings_total,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    try:
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Checkpoint saved to %s", CHECKPOINT_FILE)
    except Exception as exc:
        logger.warning("Failed to save checkpoint: %s", exc)


def controlled_shutdown(processed: int, findings_total: int, reason: str) -> None:
    """Graceful exit that saves state so the scanner can resume later."""
    logger.warning("CONTROLLED SHUTDOWN triggered: %s", reason)
    save_checkpoint(processed, findings_total)
    try:
        with open(CONTROLLED_SHUTDOWN_FLAG, "w", encoding="utf-8") as f:
            f.write(f"reason={reason}\ntimestamp={datetime.now(timezone.utc).isoformat()}\n")
    except Exception:
        pass
    logger.info("Controlled shutdown complete. Restart %s to resume.", __file__)


# ---------------------------------------------------------------------------
# Balance providers
# ---------------------------------------------------------------------------
def _resp_json(r: requests.Response) -> Any:
    return r.json()

def _resp_text(r: requests.Response) -> str:
    return r.text

def _json_rpc_result(r: requests.Response) -> Any:
    data = r.json()
    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data.get("result")

def _evm_balance_wei(data: Any) -> float:
    """Parse hex wei string or integer to ETH."""
    if isinstance(data, str):
        if data.startswith("0x"):
            return int(data, 16) / 1e18
        return int(data) / 1e18
    return int(data or 0) / 1e18

def _sol_balance_lamports(data: Any) -> float:
    """Parse Solana lamports to SOL."""
    if isinstance(data, dict):
        return int(data.get("value", 0)) / 1e9
    if isinstance(data, str):
        return int(data) / 1e9
    return int(data or 0) / 1e9

def _btc_balance_satoshi(data: Any) -> float:
    if isinstance(data, dict):
        return int(data.get("balance", 0)) / 1e8
    return int(data or 0) / 1e8

def _alchemy_eth_request(addr: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [addr, "latest"],
    }

def _alchemy_sol_request(addr: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [addr],
    }

def _generic_rpc_request(addr: str, chain: str) -> dict:
    if chain == "sol":
        return {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]}
    return {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [addr, "latest"]}


def _make_rpc_providers(chain: str, extractor) -> List[Tuple[str, Any, Any, dict]]:
    """Build provider tuples for user-supplied JSON-RPC endpoints.
    Returns (url, parser, extractor, payload_template) tuples.
    """
    providers = []
    for url in USER_RPC_ENDPOINTS.get(chain, []):
        providers.append((url, _json_rpc_result, extractor, _generic_rpc_request("{addr}", chain)))
    return providers

# ---------------------------------------------------------------------------
# Balance providers
# Format: (url_template, parser, extractor, payload_dict_or_None)
# If payload_dict is not None, a POST with JSON body is sent instead of GET.
# ---------------------------------------------------------------------------
def _rpc_payload(addr: str, chain: str) -> dict:
    if chain == "sol":
        return {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]}
    return {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [addr, "latest"]}

BALANCE_PROVIDERS: Dict[str, List[Tuple[str, Any, Any, Optional[dict]]]] = {
    "btc": [
        ("https://blockchain.info/q/addressbalance/{addr}", _resp_text, lambda t: int(t) / 1e8, None),
        ("https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance", _resp_json, lambda d: d.get("balance", 0) / 1e8, None),
    ],
    "eth": [
        ("https://api.etherscan.io/api?module=account&action=balance&address={addr}&tag=latest&apikey={key}", _resp_json,
         lambda d: int(d.get("result", 0)) / 1e18, None),
        ("https://api.blockcypher.com/v1/eth/main/addrs/{addr}/balance", _resp_json, lambda d: d.get("balance", 0) / 1e18, None),
    ],
    "ltc": [
        ("https://api.blockcypher.com/v1/ltc/main/addrs/{addr}/balance", _resp_json, lambda d: d.get("balance", 0) / 1e8, None),
    ],
    "doge": [
        ("https://api.blockcypher.com/v1/doge/main/addrs/{addr}/balance", _resp_json, lambda d: d.get("balance", 0) / 1e8, None),
    ],
    "matic": [
        ("https://api.polygonscan.com/api?module=account&action=balance&address={addr}&tag=latest&apikey={key}", _resp_json,
         lambda d: int(d.get("result", 0)) / 1e18, None),
    ],
    "xrp": [
        ("https://api.xrpscan.com/api/v1/account/{addr}", _resp_json, lambda d: float(d.get("xrpBalance", 0) or 0), None),
    ],
    "sol": [],
    "base": [],
    "monad": [],
}

# Public RPC endpoints (curated, free, no API key required)
PUBLIC_RPCS = {
    "eth": [
        "https://ethereum.publicnode.com",
        "https://eth.drpc.org",
        "https://rpc.mevblocker.io",
        "https://eth-mainnet.public.blastapi.io",
        "https://eth.rpc.blxrbdn.com",
        "https://1rpc.io/eth",
    ],
    "matic": [
        "https://polygon.publicnode.com",
        "https://polygon.drpc.org",
    ],
    "avax": [
        "https://avalanche.publicnode.com",
        "https://avalanche.drpc.org",
        "https://api.avax.network/ext/bc/C/rpc",
        "https://1rpc.io/avax/c",
    ],
    "bnb": [
        "https://bsc.publicnode.com",
        "https://binance.nodereal.io",
        "https://bsc-mainnet.public.blastapi.io",
    ],
    "sol": [
        "https://api.mainnet-beta.solana.com",
        "https://solana.publicnode.com",
    ],
    "base": [
        "https://base.publicnode.com",
        "https://base.drpc.org",
        "https://mainnet.base.org",
    ],
    "monad": [
        "https://rpc.monad.xyz",
        "https://rpc1.monad.xyz",
        "https://rpc-mainnet.monadinfra.com",
    ],
}

for chain, urls in PUBLIC_RPCS.items():
    extractor = _sol_balance_lamports if chain == "sol" else _evm_balance_wei
    for url in urls:
        BALANCE_PROVIDERS.setdefault(chain, []).append((
            url, _json_rpc_result, extractor, _rpc_payload("{addr}", chain)
        ))

# Insert user-discovered RPC endpoints near the front so they are used in
# harmony with the public fallbacks.  Broken / placeholder / duplicate URLs
# have already been filtered out when USER_RPC_ENDPOINTS was loaded.
for chain in USER_RPC_ENDPOINTS:
    if chain == "btc":
        continue
    extractor = _sol_balance_lamports if chain == "sol" else _evm_balance_wei
    existing_urls = {p[0] for p in BALANCE_PROVIDERS.get(chain, [])}
    for url in USER_RPC_ENDPOINTS[chain]:
        if url in existing_urls:
            continue
        BALANCE_PROVIDERS.setdefault(chain, []).insert(0, (
            url, _json_rpc_result, extractor, _rpc_payload("{addr}", chain)
        ))

# Ankr providers (if key is available) - tried before public nodes.
if ANKR_API_KEY:
    _ANKR_CHAIN_MAP = {
        "eth": "eth",
        "bsc": "bsc",
        "matic": "polygon",
        "avax": "avalanche",
        "sol": "solana",
        "base": "base",
        "monad": "monad_mainnet",
    }
    for chain, ankr_name in _ANKR_CHAIN_MAP.items():
        url = f"https://rpc.ankr.com/{ankr_name}/{ANKR_API_KEY}"
        existing_urls = {p[0] for p in BALANCE_PROVIDERS.get(chain, [])}
        if url in existing_urls:
            continue
        extractor = _sol_balance_lamports if chain == "sol" else _evm_balance_wei
        BALANCE_PROVIDERS.setdefault(chain, []).insert(0, (
            url, _json_rpc_result, extractor, _rpc_payload("{addr}", chain)
        ))

# Alchemy providers (if key is available) - always first so the paid key is
# preferred over public nodes and any duplicate discovered URL.
if ALCHEMY_KEY:
    alchemy_eth = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"
    if alchemy_eth not in {p[0] for p in BALANCE_PROVIDERS.get("eth", [])}:
        BALANCE_PROVIDERS["eth"].insert(0, (
            alchemy_eth, _json_rpc_result, _evm_balance_wei, _rpc_payload("{addr}", "eth")
        ))
    alchemy_sol = f"https://solana-mainnet.g.alchemy.com/v2/{ALCHEMY_KEY}"
    if alchemy_sol not in {p[0] for p in BALANCE_PROVIDERS.get("sol", [])}:
        BALANCE_PROVIDERS["sol"].insert(0, (
            alchemy_sol, _json_rpc_result, _sol_balance_lamports, _rpc_payload("{addr}", "sol")
        ))

# ---------------------------------------------------------------------------
# Persistent balance cache
# ---------------------------------------------------------------------------
def load_balance_cache() -> Dict[str, Dict[str, Any]]:
    cache: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(BALANCE_CACHE_FILE):
        return cache
    try:
        with open(BALANCE_CACHE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    key = rec.get("chain", "") + ":" + rec.get("address", "")
                    cache[key] = rec
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.warning("Could not load balance cache: %s", e)
    return cache

BALANCE_CACHE = load_balance_cache()
BALANCE_CACHE_LOCK = threading.Lock()
BALANCE_HITS_COUNT = 0
BALANCE_HITS_LOCK = threading.Lock()

def save_balance_cache() -> None:
    """Atomic rewrite so readers never see a truncated 0-byte cache."""
    try:
        with BALANCE_CACHE_LOCK:
            tmp = BALANCE_CACHE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for rec in BALANCE_CACHE.values():
                    f.write(json.dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, BALANCE_CACHE_FILE)
    except Exception as e:
        logger.warning("Could not save balance cache: %s", e)
        try:
            if os.path.exists(BALANCE_CACHE_FILE + ".tmp"):
                os.remove(BALANCE_CACHE_FILE + ".tmp")
        except Exception:
            pass

def notify(title: str, message: str) -> None:
    """Send Android notification via termux-notification if available."""
    try:
        import subprocess
        subprocess.run(
            ["termux-notification", "--title", title, "--content", message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------
def retry(max_attempts: int = 3, base_delay: float = 1.0, backoff: float = 2.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    if attempt == max_attempts:
                        raise
                    delay = base_delay * (backoff ** (attempt - 1))
                    logger.debug("Attempt %d/%d failed for %s: %s. Retry in %.1fs", attempt, max_attempts, func.__name__, e, delay)
                    time.sleep(delay)
            raise last_exc
        return wrapper
    return decorator

def fetch_balance(chain: str, address: str) -> Optional[float]:
    providers = BALANCE_PROVIDERS.get(chain, [])
    headers = {"User-Agent": "RepoHere1-Termux/2.0", "Content-Type": "application/json"}
    for prov in providers:
        if len(prov) == 4:
            url_template, parser, extractor, payload_template = prov
        else:
            url_template, parser, extractor = prov
            payload_template = None
        url = url_template.format(addr=address, key=ETHERSCAN_KEY or "")
        try:
            if payload_template is not None:
                payload = json.loads(json.dumps(payload_template).replace("{addr}", address))
                r = requests.post(url, json=payload, timeout=10, headers=headers)
            else:
                r = requests.get(url, timeout=10, headers={"User-Agent": "RepoHere1-Termux/2.0"})
            r.raise_for_status()
            data = parser(r)
            return float(extractor(data))
        except requests.exceptions.HTTPError as e:
            if r.status_code == 429:
                logger.warning("Rate limited on %s for %s", chain, address)
            else:
                logger.debug("HTTP error %s for %s/%s: %s", r.status_code, chain, address, e)
        except Exception as e:
            if _is_connectivity_error(e):
                logger.warning("[wifi] Connectivity error on %s/%s — waiting for WiFi...", chain, address)
                wait_for_wifi()
                logger.info("[wifi] Retrying %s/%s after connectivity restored.", chain, address)
                continue  # retry this provider with fresh connection
            logger.debug("Provider error %s/%s: %s", chain, address, e)
    return None

def get_balance(chain: str, address: str, force: bool = False) -> Dict[str, Any]:
    """Return balance for address on chain.

    When force=False (scanner default), successful balances are cached for 1h
    and failed checks for 60s.  When force=True (wallet viewer / refresh),
    always hit live providers and rewrite the cache entry.
    """
    key = chain + ":" + address
    if not force:
        with BALANCE_CACHE_LOCK:
            cached = BALANCE_CACHE.get(key)
        if cached:
            age = time.time() - cached.get("ts", 0)
            # Successful balances are valid for one hour.
            if cached.get("balance") is not None and age < 3600:
                return cached
            # Failed checks are retried after one minute instead of staying ERROR.
            if cached.get("balance") is None and age < 60:
                return cached
    balance = fetch_balance(chain, address)
    rec = {
        "chain": chain,
        "address": address,
        "balance": balance,
        "ts": time.time(),
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "live": True,
    }
    with BALANCE_CACHE_LOCK:
        BALANCE_CACHE[key] = rec
        try:
            tmp = BALANCE_CACHE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for row in BALANCE_CACHE.values():
                    f.write(json.dumps(row) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, BALANCE_CACHE_FILE)
        except Exception as e:
            logger.warning("Could not save balance cache: %s", e)
    return rec


# ---------------------------------------------------------------------------
# Entropy / extraction helpers
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_high_entropy(text: str) -> List[str]:
    found = []
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            found.append(token)
    return found

def extract_base58(text: str) -> List[str]:
    return [t for t in re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{25,}\b", text)
            if len(t) >= MIN_BASE58_LEN and shannon_entropy(t) >= 3.5]

def extract_base64(text: str) -> List[str]:
    return [t for t in re.findall(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", text)
            if len(t) >= MIN_BASE64_LEN and shannon_entropy(t) >= 3.0]

def try_decode_base64(token: str) -> List[str]:
    results = []
    for pad in ("", "=", "=="):
        try:
            decoded = base64.b64decode((token + pad).encode(), validate=True)
            txt = decoded.decode("utf-8", errors="strict")
            if 4 <= len(txt) <= 200 and any(c.isalnum() for c in txt):
                results.append(txt)
        except Exception:
            continue
    return results

# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
def correlate_findings(findings: Dict[str, Any], source_line: str, context_window: List[str]) -> Dict[str, Any]:
    enriched = dict(findings)
    nearby = " ".join(context_window + [source_line])
    has_nearby_addr = any(
        pat.search(nearby) for pat in (BTC_ADDR, BTC_BECH32, ETH_ADDR, LTC_ADDR, LTC_BECH32, SOL_ADDR)
    )
    enriched["derived_addresses"] = []
    enriched["wallet"] = {
        "wifs": [],
        "hex_keys": [],
        "seed_phrases": [],
    }

    # Derive addresses from WIFs
    for wif in findings.get("wif", []):
        addr = wif_to_btc_address(wif)
        if addr:
            enriched["derived_addresses"].append({"chain": "btc", "address": addr, "from": "wif"})
        # Also try other chains from the same private key if we can decode WIF
        try:
            decoded = base58.b58decode_check(wif)
            priv = decoded[1:33]
            for chain, addr in priv_to_addresses(priv).items():
                if chain != "btc":
                    enriched["derived_addresses"].append({"chain": chain, "address": addr, "from": "wif"})
        except Exception:
            pass
        enriched["wallet"]["wifs"].append(wif)

    # Derive addresses from hex keys
    for hexk in findings.get("hex_key", []):
        for chain, addr in priv_to_addresses(bytes.fromhex(hexk)).items():
            enriched["derived_addresses"].append({"chain": chain, "address": addr, "from": "hex_key"})
        enriched["wallet"]["hex_keys"].append(hexk)

    # Derive addresses from seed phrases
    for seed in findings.get("seed_phrase", []):
        for chain, addr in seed_to_addresses(seed).items():
            enriched["derived_addresses"].append({"chain": chain, "address": addr, "from": "seed_phrase"})
        enriched["wallet"]["seed_phrases"].append(seed)

    # Confidence based on how much we derived
    if enriched["derived_addresses"] or findings.get("wif") or findings.get("hex_key") or findings.get("seed_phrase"):
        if enriched["derived_addresses"] and (findings.get("wif") or findings.get("hex_key") or findings.get("seed_phrase")):
            enriched["confidence"] = "high"
            enriched["correlated"] = True
        else:
            enriched["confidence"] = "medium"
    else:
        enriched["confidence"] = "low" if not has_nearby_addr else "medium"
    return enriched

# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------
def extract_source_metadata(line: str) -> Dict[str, Any]:
    """Pull real source URI/platform/repo from a trufflehog or raw line."""
    meta: Dict[str, Any] = {
        "source_uri": "",
        "platform": "unknown",
        "repo": "",
        "path": "",
        "commit": "",
        "detector": "",
        "verified": False,
    }
    gh_re = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
    gl_re = re.compile(r"https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
    try:
        obj = json.loads(line)
    except Exception:
        m = gh_re.search(line or "")
        if m:
            repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
            meta["source_uri"] = f"https://github.com/{repo}"
            meta["platform"] = "github"
            meta["repo"] = repo
        return meta

    if not isinstance(obj, dict):
        return meta

    meta["path"] = str(obj.get("path") or obj.get("File") or "")[:500]
    meta["commit"] = str(obj.get("commit") or obj.get("commitHash") or obj.get("Commit") or "")[:120]
    meta["detector"] = str(obj.get("reason") or obj.get("DetectorName") or "")[:120]
    meta["verified"] = bool(obj.get("Verified") or obj.get("verified"))

    candidates = []
    for k in ("repository", "repo", "url", "link", "SourceName", "source", "Source"):
        if obj.get(k):
            candidates.append(str(obj.get(k)))
    sm = obj.get("SourceMetadata") or {}
    if isinstance(sm, dict):
        data = sm.get("Data") or {}
        if isinstance(data, dict):
            for key in ("Github", "Git", "Gitlab", "Filesystem"):
                node = data.get(key) or {}
                if isinstance(node, dict):
                    for kk in ("repository", "repo", "link", "file"):
                        if node.get(kk):
                            candidates.append(str(node.get(kk)))

    blob = " ".join(candidates + [meta["path"], str(obj.get("commit") or "")[:300]])
    m = gh_re.search(blob)
    if m:
        repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
        meta["source_uri"] = f"https://github.com/{repo}"
        meta["platform"] = "github"
        meta["repo"] = repo
    else:
        m2 = gl_re.search(blob)
        if m2:
            repo = f"{m2.group(1)}/{m2.group(2).removesuffix('.git')}"
            meta["source_uri"] = f"https://gitlab.com/{repo}"
            meta["platform"] = "gitlab"
            meta["repo"] = repo
        elif meta["path"]:
            meta["source_uri"] = f"file://{meta['path']}"
            meta["platform"] = "filesystem"
    return meta


def normalize_input_line(line: str) -> str:
    """Flatten truffleHog/mass_scan JSONL into a searchable string."""
    try:
        obj = json.loads(line)
        parts = []
        seen = set()
        for key in (
            "reason", "string", "path", "commit", "source_line", "diff",
            "repository", "repo", "url", "Raw", "RawV2", "DetectorName",
        ):
            val = obj.get(key, "")
            if isinstance(val, list):
                val = " ".join(str(x) for x in val[:20])
            if val and str(val) not in seen:
                seen.add(str(val))
                parts.append(str(val)[:2000])
        sf = obj.get("stringsFound")
        if isinstance(sf, list):
            parts.extend(str(x)[:500] for x in sf[:30])
        return " ".join(parts)
    except json.JSONDecodeError:
        return line

def scan_line(line: str) -> Dict[str, Any]:
    text = normalize_input_line(line)
    findings: Dict[str, Any] = {
        "btc": [],
        "eth": [],
        "ltc": [],
        "sol": [],
        "doge": [],
        "xrp": [],
        "ton": [],
        "avax": [],
        "matic": [],
        "wif": [],
        "hex_key": [],
        "seed_phrase": [],
        "high_entropy": [],
        "base58_strings": [],
        "base64_strings": [],
        "aws_key": [],
        "github_pat": [],
        "slack_token": [],
        "stripe_key": [],
    }

    for a in BTC_ADDR.findall(text):
        if validate_btc_address(a):
            findings["btc"].append(a)
    findings["btc"].extend(BTC_BECH32.findall(text))

    for a in ETH_ADDR.findall(text):
        if validate_eth_address(a):
            findings["eth"].append(a)

    for a in LTC_ADDR.findall(text):
        if validate_ltc_address(a):
            findings["ltc"].append(a)
    findings["ltc"].extend(LTC_BECH32.findall(text))

    findings["sol"] = [a for a in SOL_ADDR.findall(text) if validate_sol_address(a)]
    findings["doge"] = DOGE_ADDR.findall(text)
    findings["xrp"] = XRP_ADDR.findall(text)
    findings["ton"] = TON_ADDR.findall(text)
    findings["avax"] = AVAX_ADDR.findall(text)
    findings["matic"] = [a for a in MATIC_ADDR.findall(text) if validate_eth_address(a)]

    findings["wif"] = WIF_PAT.findall(text)
    findings["hex_key"] = HEX_KEY_PAT.findall(text)

    # Seed phrase detection: sliding window over all words.
    # Pre-filter windows to avoid expensive PBKDF2 checksums on non-BIP39 text.
    words = re.findall(r"[a-zA-Z]+", text.lower())
    if len(words) >= 12:
        # Cap word count to prevent runaway CPU on huge inputs.
        if len(words) > 1000:
            words = words[:1000]
        for length in (12, 15, 18, 21, 24):
            max_start = len(words) - length + 1
            if max_start <= 0:
                continue
            for start in range(max_start):
                phrase = words[start:start + length]
                if any(w not in BIP39_WORDS for w in phrase):
                    continue
                if validate_seed_phrase(phrase):
                    findings["seed_phrase"].append(" ".join(phrase))

    findings["high_entropy"] = extract_high_entropy(text)
    findings["base58_strings"] = extract_base58(text)
    findings["base64_strings"] = extract_base64(text)

    findings["aws_key"] = AWS_KEY_PAT.findall(text)
    findings["github_pat"] = GITHUB_PAT.findall(text) + GITHUB_PAT2.findall(text)
    findings["slack_token"] = SLACK_TOKEN.findall(text)
    findings["stripe_key"] = STRIPE_KEY.findall(text)

    return findings

def material_findings(findings: Dict[str, Any]) -> bool:
    material_keys = ("btc", "eth", "ltc", "sol", "doge", "xrp", "ton", "avax", "matic",
                     "wif", "hex_key", "seed_phrase", "aws_key", "github_pat", "slack_token", "stripe_key")
    return any(findings.get(k) for k in material_keys)

# ---------------------------------------------------------------------------
# Balance checking with threading
# ---------------------------------------------------------------------------
def check_balances_blocking(addr_map: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Synchronous balance check (kept for compatibility/tests)."""
    results = []
    lock = threading.Lock()

    def run(chain: str, address: str):
        try:
            bal = get_balance(chain, address)
            with lock:
                results.append(bal)
        except Exception as e:
            logger.debug("Balance check error %s/%s: %s", chain, address, e)

    threads = []
    for chain, addrs in addr_map.items():
        for a in set(addrs):
            t = threading.Thread(target=run, args=(chain, a))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

    return results


def balance_worker(q: queue_module.Queue, stop_event: threading.Event):
    """Background worker that checks balances without blocking the scanner."""
    while not stop_event.is_set() or not q.empty():
        try:
            chain, address = q.get(timeout=0.5)
        except queue_module.Empty:
            continue
        try:
            throttle_cpu_ram(0.05)
            bal = get_balance(chain, address)
            if bal["balance"] is not None and bal["balance"] > 0:
                global BALANCE_HITS_COUNT
                with BALANCE_HITS_LOCK:
                    BALANCE_HITS_COUNT += 1
                msg = f"BALANCE FOUND {bal['chain']} {bal['address']} => {bal['balance']}"
                logger.info("*** %s", msg)
                try:
                    src_uri = ""
                    platform = "unknown"
                    if os.path.exists(MEMORY_FILE):
                        with open(MEMORY_FILE, "rb") as mf:
                            mf.seek(0, 2)
                            size = mf.tell()
                            mf.seek(max(0, size - 200_000))
                            tail = mf.read().decode("utf-8", errors="ignore")
                        for ln in reversed(tail.splitlines()):
                            if address not in ln:
                                continue
                            try:
                                rec = json.loads(ln)
                            except Exception:
                                continue
                            src_uri = rec.get("source_uri") or rec.get("source") or ""
                            platform = rec.get("platform") or "unknown"
                            if src_uri:
                                break
                    bal_out = dict(bal)
                    if src_uri:
                        bal_out["source_uri"] = src_uri
                        bal_out["platform"] = platform
                        try:
                            from target_intelligence import TargetIntelligence
                            TargetIntelligence().record_outcome(
                                src_uri,
                                platform=platform,
                                has_key=True,
                                has_balance=True,
                                balance_total=float(bal["balance"] or 0),
                                finding_types=[f"balance:{chain}"],
                                meta={"address": address, "chain": chain},
                            )
                        except Exception:
                            pass
                    with open(BALANCE_HIT_FILE, "a") as f:
                        f.write(json.dumps(bal_out) + "\n")
                except Exception:
                    with open(BALANCE_HIT_FILE, "a") as f:
                        f.write(json.dumps(bal) + "\n")
                notify("Crypto Scanner", msg)
        except Exception as e:
            logger.debug("Balance worker error %s/%s: %s", chain, address, e)
        finally:
            q.task_done()


def tail_file(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 0)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.5)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    scan_path = SCAN_FILE
    if not os.path.exists(scan_path):
        logger.error("Scan file not found: %s", scan_path)
        sys.exit(1)

    logger.info("Crypto Scanner v2.0 starting...")
    logger.info("Monitoring: %s", scan_path)
    logger.info("Memory: %s", MEMORY_FILE)
    logger.info("Balance cache: %s", BALANCE_CACHE_FILE)
    logger.info("High-confidence hits: %s", HIGH_CONFIDENCE_FILE)
    logger.info("Interval: %ds", CHECK_INTERVAL)
    logger.info("Press Ctrl+C to stop")

    # If a previous controlled shutdown flag exists, report it and remove it.
    if os.path.exists(CONTROLLED_SHUTDOWN_FLAG):
        try:
            with open(CONTROLLED_SHUTDOWN_FLAG, "r") as _f:
                _flag_line = _f.read().strip()
            logger.warning("Previous controlled shutdown: %s", _flag_line)
        except Exception:
            pass
        try:
            os.remove(CONTROLLED_SHUTDOWN_FLAG)
        except OSError:
            pass

    os.makedirs(os.path.dirname(PID_FILE), exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    seen_lines = set()
    processed = 0
    findings_total = 0
    start_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with open(STATUS_FILE, "w") as f:
        f.write(f"started={start_ts}, processed=0, findings=0, memory=0 bytes")

    context_window: List[str] = []
    balance_queue: queue_module.Queue = queue_module.Queue()
    stop_event = threading.Event()
    num_workers = 2  # throttled to avoid freeze on low-RAM devices
    workers = []
    for _ in range(num_workers):
        t = threading.Thread(target=balance_worker, args=(balance_queue, stop_event), daemon=True)
        t.start()
        workers.append(t)

    def queue_balances(addr_map: Dict[str, List[str]]):
        for chain, addrs in addr_map.items():
            for a in set(addrs):
                balance_queue.put((chain, a))

    try:
        _line_count = 0
        for line in tail_file(scan_path):
            _line_count += 1
            # Check disk space every 50 lines to protect against filling the disk.
            if _line_count % 50 == 0:
                low = check_disk_space()
                if low:
                    controlled_shutdown(processed, BALANCE_HITS_COUNT, low)
                    break
            if not line.strip():
                continue
            h = hashlib.md5(line.encode()).hexdigest()
            if h in seen_lines:
                continue
            seen_lines.add(h)
            if len(seen_lines) > 100_000:
                seen_lines.clear()

            findings = scan_line(line)
            if material_findings(findings):
                processed += 1
                findings = correlate_findings(findings, line, context_window)
                src_meta = extract_source_metadata(line)
                record = {
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "findings": findings,
                    "source_line": line[:200],
                    "source_uri": src_meta.get("source_uri") or "",
                    "source": src_meta.get("source_uri") or "",
                    "platform": src_meta.get("platform") or "unknown",
                    "repo": src_meta.get("repo") or "",
                    "source_path": src_meta.get("path") or "",
                    "source_commit": src_meta.get("commit") or "",
                    "detector": src_meta.get("detector") or "",
                    "verified": bool(src_meta.get("verified")),
                }
                with open(MEMORY_FILE, "a") as f:
                    f.write(json.dumps(record) + "\n")

                logger.info(
                    "Findings #%d at %s source=%s",
                    processed,
                    record["ts"],
                    record.get("source_uri") or "?",
                )
                for k, vs in findings.items():
                    if vs and k not in ("high_entropy", "base58_strings", "base64_strings"):
                        logger.info("  %s: %s", k, vs)

                addr_map: Dict[str, List[str]] = {}
                for chain in ("btc", "eth", "ltc", "sol", "doge", "xrp", "ton", "avax", "matic", "bnb", "base", "monad"):
                    for addr in findings.get(chain, []):
                        addr_map.setdefault(chain, []).append(addr)
                for derived in findings.get("derived_addresses", []):
                    chain = derived["chain"]
                    addr = derived["address"]
                    addr_map.setdefault(chain, []).append(addr)

                if addr_map:
                    queue_balances(addr_map)

                if findings.get("correlated") or findings.get("wif") or findings.get("hex_key") or findings.get("seed_phrase"):
                    with open(HIGH_CONFIDENCE_FILE, "a") as f:
                        f.write(json.dumps(record) + "\n")

                try:
                    from target_intelligence import TargetIntelligence
                    wallet = (findings.get("wallet") or {})
                    has_key = bool(
                        wallet.get("wifs")
                        or wallet.get("hex_keys")
                        or wallet.get("seed_phrases")
                        or findings.get("wif")
                        or findings.get("hex_key")
                        or findings.get("seed_phrase")
                    )
                    uri = record.get("source_uri") or ""
                    if uri:
                        TargetIntelligence().record_outcome(
                            uri,
                            platform=record.get("platform") or "unknown",
                            has_key=has_key,
                            has_balance=False,
                            finding_types=[
                                k for k, v in findings.items()
                                if v and k not in (
                                    "high_entropy", "base58_strings", "base64_strings",
                                    "derived_addresses", "wallet", "confidence", "correlated",
                                )
                            ],
                            meta={"ts": record["ts"], "repo": record.get("repo")},
                        )
                except Exception as _ti_exc:
                    logger.debug("target intelligence update skipped: %s", _ti_exc)

            with BALANCE_HITS_LOCK:
                total_hits = BALANCE_HITS_COUNT
            status = f"processed={processed}, findings={total_hits}, memory={os.path.getsize(MEMORY_FILE) if os.path.exists(MEMORY_FILE) else 0} bytes, queue={balance_queue.qsize()}"
            with open(STATUS_FILE, "w") as f:
                f.write(status)

            context_window.append(line[:200])
            if len(context_window) > 3:
                context_window.pop(0)

            throttle_cpu_ram(0.02)

    except KeyboardInterrupt:
        logger.info("Stopping. Waiting for balance queue to drain...")
    finally:
        stop_event.set()
        balance_queue.join()
        for w in workers:
            w.join(timeout=2)
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        save_balance_cache()
        with BALANCE_HITS_LOCK:
            total_hits = BALANCE_HITS_COUNT
        logger.info("Stopped. Processed %d finding-blocks, %d balance hits.", processed, total_hits)


if __name__ == "__main__":
    main()
