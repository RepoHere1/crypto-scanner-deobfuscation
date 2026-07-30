#!/usr/bin/env python3
"""
crypto_iq.py — PyCryptodome-backed intelligence for the live crypto scanner.

Raises scan quality by:
  * Validating secp256k1 private-key range (n-curve order)
  * Rejecting null/weak/low-entropy / hash-looking hex false positives
  * Faster Keccak-256 via PyCryptodome when available
  * Context-aware confidence scoring (key context keywords, nearby addrs)
  * Mining extra hex keys from high-entropy / base64 blobs

Note: PyCryptodome does NOT ship secp256k1 EC ops — derivation still uses ecdsa.
This module is the "IQ layer" around validation + scoring, not a full EC stack.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

# secp256k1 curve order n
SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

# Common false-positive / test keys we should never treat as real findings
_BANNED_HEX = {
    "0" * 64,
    "f" * 64,
    "1" * 64,
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    # well-known hardhat/anvil/ganache demo keys (public test vectors)
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
}

_KEY_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"private[_\-\s]?key|privkey|secret[_\-\s]?key|wallet[_\-\s]?key|"
    r"mnemonic|seed[_\-\s]?phrase|bip39|wif|p2pkh|"
    r"0x[0-9a-f]{64}|ethereum|bitcoin|metamask|ledger|trezor|"
    r"BEGIN\s+EC\s+PRIVATE|BEGIN\s+PRIVATE\s+KEY"
    r")\b"
)

_HASH_CONTEXT_RE = re.compile(
    r"(?i)\b(sha256|sha3|keccak|txid|txhash|blockhash|merkle|"
    r"content[_-]?hash|commit|checksum|fingerprint|md5|sha1)\b"
)

_PYCRYPTODOME = False
_keccak_new = None
try:
    from Crypto.Hash import keccak as _keccak_mod  # type: ignore

    def _keccak_new(data: bytes) -> bytes:
        h = _keccak_mod.new(digest_bits=256)
        h.update(data)
        return h.digest()

    _keccak_new = _keccak_new  # noqa: F841 — keep ref
    # smoke test
    assert len(_keccak_new(b"")) == 32
    _PYCRYPTODOME = True
except Exception:
    _PYCRYPTODOME = False
    _keccak_new = None


def backend_info() -> Dict[str, Any]:
    return {
        "pycryptodome": _PYCRYPTODOME,
        "keccak": "pycryptodome" if _PYCRYPTODOME else "pure-python",
        "secp256k1_validate": True,
        "module": "crypto_iq",
    }


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum). Prefer PyCryptodome C impl."""
    if _keccak_new is not None:
        return _keccak_new(data)
    # Fallback: caller should still provide pure impl; we keep a tiny one here
    # so this module is usable standalone.
    return hashlib.sha3_256(data).digest()  # NOT eth-keccak; only last-resort


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def _looks_like_ascii_hex_padding(h: str) -> bool:
    """Catch keys that are mostly repeated nibbles / low unique charset."""
    uniq = len(set(h.lower()))
    if uniq <= 4:
        return True
    # long runs of same char
    if re.search(r"(.)\1{15,}", h.lower()):
        return True
    return False


def _ascii_text_ratio(priv: bytes) -> float:
    """Fraction of bytes that are printable ASCII (space..~)."""
    if not priv:
        return 0.0
    return sum(32 <= b < 127 for b in priv) / len(priv)


def _looks_like_ascii_text_key(priv: bytes) -> bool:
    """True if 32 bytes decode as mostly English/text (common trufflehog FP)."""
    ratio = _ascii_text_ratio(priv)
    if ratio >= 0.85:
        return True
    # high printable + mostly letters/spaces
    if ratio >= 0.70:
        letters = sum(
            (65 <= b <= 90) or (97 <= b <= 122) or b in (32, 9, 10, 13)
            for b in priv
        )
        if letters / len(priv) >= 0.60:
            return True
    return False


def validate_secp256k1_priv(priv: bytes) -> Tuple[bool, str]:
    """Return (ok, reason). ok=True means usable as secp256k1 private key."""
    if not isinstance(priv, (bytes, bytearray)) or len(priv) != 32:
        return False, "len"
    if priv == bytes(32):
        return False, "zero"
    if priv == b"\xff" * 32:
        return False, "all_ff"
    n = int.from_bytes(priv, "big")
    if n <= 0:
        return False, "non_positive"
    if n >= SECP256K1_N:
        return False, "gte_curve_order"
    return True, "ok"


def validate_hex_privkey(hex_key: str, context: str = "") -> Tuple[bool, str, float]:
    """Validate a 64-char hex candidate.

    Returns (is_valid_key, reason, quality_score 0..1).
    quality_score is used for prioritization even among valid keys.
    """
    if not hex_key or not isinstance(hex_key, str):
        return False, "empty", 0.0
    h = hex_key.strip().lower().removeprefix("0x")
    if len(h) != 64:
        return False, "bad_len", 0.0
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        return False, "non_hex", 0.0
    if h in _BANNED_HEX:
        return False, "banned_test_key", 0.0

    try:
        priv = bytes.fromhex(h)
    except Exception:
        return False, "parse", 0.0

    ok, reason = validate_secp256k1_priv(priv)
    if not ok:
        return False, reason, 0.0

    if _looks_like_ascii_text_key(priv):
        return False, "ascii_text", 0.0

    if _looks_like_ascii_hex_padding(h):
        return False, "low_charset", 0.0

    ent = shannon_entropy(h)
    # Real random keys cluster ~3.7–4.0; text-as-hex often ~3.2–3.5
    if ent < 3.45:
        return False, "low_entropy", 0.0

    score = min(1.0, (ent - 3.45) / 0.55)  # 3.45→0, 4.0→1

    # Only penalize *text-like* byte distributions, not random printable density.
    # Random keys land ~30–45% printable; English text is >>70% letters/spaces.
    ascii_r = _ascii_text_ratio(priv)
    letters = sum(
        (65 <= b <= 90) or (97 <= b <= 122) or b in (32, 9, 10, 13)
        for b in priv
    ) / 32.0
    if letters >= 0.50:
        return False, "ascii_text", 0.0
    if ascii_r >= 0.75 and letters >= 0.35:
        score *= 0.6

    # Base quality gate BEFORE context bonuses — context must not
    # resurrect weak / patterned hex into "valid keys".
    if score < 0.35:
        return False, "low_score", score

    ctx = context or ""
    if _HASH_CONTEXT_RE.search(ctx) and not _KEY_CONTEXT_RE.search(ctx):
        # Likely a tx/block hash sitting next to hash-ish words — demote hard
        score *= 0.25
        if score < 0.35:
            return False, "hash_context", score

    if _KEY_CONTEXT_RE.search(ctx):
        score = min(1.0, score + 0.25)

    return True, "ok", score


# Public burn / null / hardhat-anvil / pattern addresses that often hold
# real on-chain balances but are never "findable" secrets. Dashboard truth
# and hit lists must exclude these so totals stay honest.
_NOISE_EVM_ADDRS = {
    # null / burn
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000001",
    "0xffffffffffffffffffffffffffffffffffffffff",
    # sequential / vanity test patterns
    "0x1234567890123456789012345678901234567890",
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
    "0x5555555555555555555555555555555555555555",
    "0x6666666666666666666666666666666666666666",
    "0x7777777777777777777777777777777777777777",
    "0x8888888888888888888888888888888888888888",
    "0x9999999999999999999999999999999999999999",
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "0xcccccccccccccccccccccccccccccccccccccccc",
    "0xdddddddddddddddddddddddddddddddddddddddd",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    # hardhat / anvil default accounts 0-9
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
    "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
    "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
    "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    "0x976ea74026e726554db657fa54763abd0c3a0aa9",
    "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
    "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f",
    "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
    # privkey = 1 (common unit-test vector)
    "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
}

_NOISE_BTC_ADDRS = {
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",  # privkey=1 P2PKH
    "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
}

_EVM_LIKE = {
    "eth", "matic", "avax", "bnb", "base", "arb", "op", "monad",
    "ftm", "cro", "gno", "scrl", "linea", "blast", "zksync",
    "polygon", "bsc", "arbitrum", "optimism",
}


def is_noise_address(chain: str, address: str) -> bool:
    """True if address is a known burn/null/demo/test wallet — not real loot."""
    if not address or not isinstance(address, str):
        return True
    chain_l = (chain or "").lower().strip()
    addr = address.strip()
    if not addr:
        return True

    # EVM-shaped addresses (0x + 40 hex), any EVM-like chain or bare 0x
    al = addr.lower()
    if al.startswith("0x") and len(al) == 42 and re.fullmatch(r"0x[0-9a-f]{40}", al):
        if al in _NOISE_EVM_ADDRS:
            return True
        body = al[2:]
        # all-same nibble / near-null patterns
        if len(set(body)) == 1:
            return True
        if body == "0" * 40 or body == "f" * 40:
            return True
        # leading 38 zero nibbles (null-ish contracts)
        if body[:38] == "0" * 38:
            return True
        return False

    if chain_l in ("btc", "bch", "ltc") or (not al.startswith("0x")):
        if addr in _NOISE_BTC_ADDRS:
            return True

    return False


def filter_hex_keys(candidates: Sequence[str], context: str = "") -> List[Dict[str, Any]]:
    """Filter + rank hex key candidates. Drops invalid; sorts best first."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for raw in candidates:
        h = (raw or "").strip().lower().removeprefix("0x")
        if h in seen:
            continue
        ok, reason, score = validate_hex_privkey(h, context=context)
        if not ok:
            continue
        seen.add(h)
        out.append({"hex": h, "score": round(score, 4), "reason": reason})
    out.sort(key=lambda x: -x["score"])
    return out


def validate_wif(wif: str) -> Tuple[bool, str, Optional[bytes]]:
    """Basic WIF structural check + secp range. Returns (ok, reason, priv|None)."""
    if not wif or not isinstance(wif, str):
        return False, "empty", None
    try:
        import base58
        decoded = base58.b58decode_check(wif)
    except Exception:
        return False, "b58check", None
    if len(decoded) not in (33, 34):
        return False, "len", None
    if decoded[0] not in (0x80, 0xEF):  # mainnet / testnet
        # still allow — some alts reuse; don't hard-fail version
        pass
    priv = decoded[1:33]
    ok, reason = validate_secp256k1_priv(priv)
    if not ok:
        return False, reason, None
    if len(decoded) == 34 and decoded[33] not in (0x01,):
        return False, "bad_compress_flag", None
    return True, "ok", priv


def mine_keys_from_blobs(blobs: Sequence[str], context: str = "") -> List[str]:
    """Pull valid hex privkeys hidden inside high-entropy / base64 tokens."""
    found: List[str] = []
    seen = set()
    hex_re = re.compile(r"(?i)(?:0x)?([0-9a-f]{64})")
    for blob in blobs or []:
        if not blob:
            continue
        # direct hex inside blob
        for m in hex_re.findall(blob):
            h = m.lower()
            if h in seen:
                continue
            ok, _, score = validate_hex_privkey(h, context=context or blob[:200])
            if ok and score >= 0.35:
                seen.add(h)
                found.append(h)
        # try base64 decode → hex
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", blob) and len(blob) >= 40:
            import base64
            for pad in ("", "=", "=="):
                try:
                    raw = base64.b64decode(blob + pad, validate=False)
                except Exception:
                    continue
                if len(raw) == 32:
                    h = raw.hex()
                    if h in seen:
                        continue
                    ok, _, score = validate_hex_privkey(h, context=context)
                    if ok and score >= 0.4:
                        seen.add(h)
                        found.append(h)
                elif len(raw) > 32:
                    # sliding 32-byte windows (rare but catches keybags)
                    for i in range(0, min(len(raw) - 31, 64)):
                        h = raw[i : i + 32].hex()
                        if h in seen:
                            continue
                        ok, _, score = validate_hex_privkey(h, context=context)
                        if ok and score >= 0.55:
                            seen.add(h)
                            found.append(h)
    return found


def score_finding(
    *,
    has_valid_key: bool,
    derived_count: int,
    nearby_addr: bool,
    key_context: bool,
    seed: bool,
    wif: bool,
    hex_best_score: float = 0.0,
    matched_derived_to_nearby: bool = False,
) -> Tuple[str, bool, float]:
    """Return (confidence_label, correlated, numeric_score)."""
    score = 0.0
    if has_valid_key:
        score += 0.35
    if wif:
        score += 0.2
    if seed:
        score += 0.3
    if derived_count > 0:
        score += min(0.25, 0.05 * derived_count)
    if nearby_addr:
        score += 0.1
    if key_context:
        score += 0.15
    if matched_derived_to_nearby:
        score += 0.35  # gold: key derives an address present in the same leak
    score += min(0.2, hex_best_score * 0.2)
    score = max(0.0, min(1.0, score))

    correlated = matched_derived_to_nearby or (has_valid_key and derived_count > 0 and (nearby_addr or key_context or wif or seed))

    if score >= 0.75 or matched_derived_to_nearby:
        label = "high"
    elif score >= 0.45:
        label = "medium"
    else:
        label = "low"
    return label, correlated, round(score, 4)


def enrich_correlate(
    findings: Dict[str, Any],
    source_line: str,
    context_window: Sequence[str],
    *,
    derive_fn=None,
    wif_to_priv_fn=None,
    seed_to_addrs_fn=None,
) -> Dict[str, Any]:
    """Smarter correlate_findings replacement body.

    derive_fn(priv: bytes) -> Dict[str,str]
    wif_to_priv_fn(wif) -> Optional[bytes]
    seed_to_addrs_fn(seed) -> Dict[str,str]
    """
    enriched = dict(findings)
    nearby = " ".join(list(context_window) + [source_line])
    key_ctx = bool(_KEY_CONTEXT_RE.search(nearby))
    enriched["crypto_iq"] = backend_info()
    enriched["derived_addresses"] = []
    enriched["wallet"] = {"wifs": [], "hex_keys": [], "seed_phrases": [], "hex_meta": []}
    enriched["rejected_hex"] = []

    # --- filter hex keys ---
    raw_hex = list(findings.get("hex_key") or [])
    # mine extras from entropy/base64 blobs
    mined = mine_keys_from_blobs(
        list(findings.get("high_entropy") or []) + list(findings.get("base64_strings") or []),
        context=nearby,
    )
    for h in mined:
        if h not in raw_hex:
            raw_hex.append(h)

    filtered = filter_hex_keys(raw_hex, context=nearby)
    valid_hex = [x["hex"] for x in filtered]
    enriched["hex_key"] = valid_hex
    enriched["wallet"]["hex_meta"] = filtered[:32]
    # track rejects for debugging IQ (cap)
    rejected = []
    seen_ok = set(valid_hex)
    for raw in findings.get("hex_key") or []:
        h = (raw or "").strip().lower().removeprefix("0x")
        if h and h not in seen_ok:
            ok, reason, _ = validate_hex_privkey(h, context=nearby)
            if not ok:
                rejected.append({"hex": h[:16] + "…", "reason": reason})
    enriched["rejected_hex"] = rejected[:20]

    # --- WIFs ---
    valid_wifs = []
    for wif in findings.get("wif") or []:
        ok, reason, priv = validate_wif(wif)
        if not ok:
            continue
        valid_wifs.append(wif)
        enriched["wallet"]["wifs"].append(wif)
        if derive_fn and priv is not None:
            try:
                for chain, addr in (derive_fn(priv) or {}).items():
                    enriched["derived_addresses"].append(
                        {"chain": chain, "address": addr, "from": "wif"}
                    )
            except Exception:
                pass
        elif wif_to_priv_fn:
            try:
                p = wif_to_priv_fn(wif)
                if p and derive_fn:
                    for chain, addr in (derive_fn(p) or {}).items():
                        enriched["derived_addresses"].append(
                            {"chain": chain, "address": addr, "from": "wif"}
                        )
            except Exception:
                pass
    enriched["wif"] = valid_wifs

    # --- hex derive ---
    best_hex_score = 0.0
    for item in filtered:
        h = item["hex"]
        best_hex_score = max(best_hex_score, float(item.get("score") or 0))
        enriched["wallet"]["hex_keys"].append(h)
        if derive_fn:
            try:
                for chain, addr in (derive_fn(bytes.fromhex(h)) or {}).items():
                    enriched["derived_addresses"].append(
                        {"chain": chain, "address": addr, "from": "hex_key", "key_score": item["score"]}
                    )
            except Exception:
                pass

    # --- seeds ---
    for seed in findings.get("seed_phrase") or []:
        enriched["wallet"]["seed_phrases"].append(seed)
        if seed_to_addrs_fn:
            try:
                for chain, addr in (seed_to_addrs_fn(seed) or {}).items():
                    enriched["derived_addresses"].append(
                        {"chain": chain, "address": addr, "from": "seed_phrase"}
                    )
            except Exception:
                pass

    # dedupe derived addresses
    dedup = []
    seen_a = set()
    for d in enriched["derived_addresses"]:
        k = (d.get("chain"), (d.get("address") or "").lower())
        if k in seen_a:
            continue
        seen_a.add(k)
        dedup.append(d)
    enriched["derived_addresses"] = dedup

    # match derived vs addresses present in the leak text
    nearby_l = nearby.lower()
    matched = False
    for d in dedup:
        addr = d.get("address") or ""
        if addr and addr.lower() in nearby_l:
            d["matched_nearby"] = True
            matched = True

    has_key = bool(valid_hex or valid_wifs or (findings.get("seed_phrase")))
    conf, corr, nscore = score_finding(
        has_valid_key=has_key,
        derived_count=len(dedup),
        nearby_addr=bool(re.search(r"\b(0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{8,})\b", nearby)),
        key_context=key_ctx,
        seed=bool(findings.get("seed_phrase")),
        wif=bool(valid_wifs),
        hex_best_score=best_hex_score,
        matched_derived_to_nearby=matched,
    )
    enriched["confidence"] = conf
    enriched["correlated"] = corr
    enriched["iq_score"] = nscore
    enriched["iq_backend"] = "pycryptodome" if _PYCRYPTODOME else "fallback"
    return enriched
