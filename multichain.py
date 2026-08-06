#!/usr/bin/env python3
"""
multichain.py — Multi-chain wallet engine for WalletX.

Supports: ETH, MATIC, BNB, AVAX, BASE, ARB, OP, BTC, LTC, DOGE, SOL
Features: send, receive (derive), swap (0x/Jupiter), bridge (LI.FI)
Live data: Alchemy RPCs from .env, public fallbacks.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from typing import Any

import ecdsa
import httpx
import requests
from Crypto.Hash import keccak as _pycryptodome_keccak
from cryptography.hazmat.primitives.asymmetric import ed25519 as _crypto_ed25519

HOME = os.path.expanduser("~")

# ── Load .env ────────────────────────────────────────────────────────────
def _load_dotenv() -> dict[str, str]:
    env = {}
    path = os.path.join(HOME, ".env")
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                env[k] = v
    return env

_ENV = _load_dotenv()

# ── RPC URLs (Alchemy preferred, public fallbacks) ───────────────────────
RPC_URLS: dict[str, list[str]] = {
    "eth": [
        _ENV.get("ALCHEMY_ETH_URL", ""),
        "https://eth.drpc.org",
        "https://cloudflare-eth.com",
        "https://rpc.mevblocker.io",
    ],
    "matic": [
        _ENV.get("ALCHEMY_POLYGON_URL", ""),
        "https://polygon.drpc.org",
        "https://1rpc.io/matic",
    ],
    "bnb": [
        _ENV.get("ALCHEMY_BNB_URL", ""),
        "https://bsc.drpc.org",
        "https://1rpc.io/bnb",
    ],
    "avax": [
        "https://avalanche.drpc.org",
        "https://api.avax.network/ext/bc/C/rpc",
    ],
    "base": [
        _ENV.get("ALCHEMY_BASE_URL", ""),
        "https://base.drpc.org",
        "https://mainnet.base.org",
    ],
    "arb": [
        _ENV.get("ALCHEMY_ARB_URL", ""),
        "https://arbitrum.drpc.org",
        "https://arb1.arbitrum.io/rpc",
    ],
    "op": [
        "https://optimism.drpc.org",
        "https://mainnet.optimism.io",
    ],
    "sol": [
        _ENV.get("ALCHEMY_SOLANA_URL", ""),
        "https://api.mainnet-beta.solana.com",
        "https://solana-api.projectserum.com",
    ],
}

# Non-EVM chain APIs
BTC_API = "https://mempool.space/api"
LTC_API = "https://litecoinspace.org/api"
DOGE_API = "https://dogechain.info/api/v1"

# Chain IDs for EVM
CHAIN_IDS = {"eth": 1, "matic": 137, "bnb": 56, "avax": 43114,
             "base": 8453, "arb": 42161, "op": 10}

# Native currency symbols
NATIVE = {"eth": "ETH", "matic": "MATIC", "bnb": "BNB", "avax": "AVAX",
          "base": "ETH", "arb": "ETH", "op": "ETH",
          "btc": "BTC", "ltc": "LTC", "doge": "DOGE", "sol": "SOL"}

# Decimals
DECIMALS = {"eth": 18, "matic": 18, "bnb": 18, "avax": 18, "base": 18, "arb": 18, "op": 18,
            "btc": 8, "ltc": 8, "doge": 8, "sol": 9}

# EVM chains
EVM_CHAINS = {"eth", "matic", "polygon", "bnb", "avax", "base", "arb", "op"}

# UTXO chains
UTXO_CHAINS = {"btc", "ltc", "doge"}

# Explorer URLs
EXPLORERS = {
    "eth": "https://etherscan.io",
    "matic": "https://polygonscan.com",
    "bnb": "https://bscscan.com",
    "avax": "https://snowtrace.io",
    "base": "https://basescan.org",
    "arb": "https://arbiscan.io",
    "op": "https://optimistic.etherscan.io",
    "btc": "https://mempool.space",
    "ltc": "https://litecoinspace.org",
    "doge": "https://dogechain.info",
    "sol": "https://solscan.io",
}

# ── Helpers ──────────────────────────────────────────────────────────────

def _keccak256(data: bytes) -> bytes:
    return _pycryptodome_keccak.new(digest_bits=256).update(data).digest()

def _rlp_encode(item) -> bytes:
    def _ib(n): return b"" if n == 0 else n.to_bytes((n.bit_length()+7)//8, "big")
    if isinstance(item, int):
        return _rlp_encode(_ib(item))
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        if len(item) < 56:
            return bytes([0x80 + len(item)]) + item
        lb = _ib(len(item))
        return bytes([0xb7 + len(lb)]) + lb + item
    if isinstance(item, list):
        p = b"".join(_rlp_encode(i) for i in item)
        if len(p) < 56:
            return bytes([0xc0 + len(p)]) + p
        lb = _ib(len(p))
        return bytes([0xf7 + len(lb)]) + lb + p
    raise TypeError(f"RLP: unsupported type {type(item)}")

def _base58_encode(b: bytes) -> str:
    import base58
    return base58.b58encode(b).decode()

def _base58_decode(s: str) -> bytes:
    import base58
    return base58.b58decode(s)

def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def _rpc_call(chain: str, method: str, params: list, timeout: int = 15) -> dict:
    """Call JSON-RPC on the best available endpoint for a chain."""
    urls = RPC_URLS.get(chain, [])
    urls = [u for u in urls if u]  # filter empty
    if not urls:
        raise RuntimeError(f"No RPC URLs configured for {chain}")

    last_err = ""
    for url in urls:
        try:
            r = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
            data = r.json()
            if "error" in data:
                last_err = str(data["error"])
                continue
            return data
        except Exception as e:
            last_err = str(e)
            continue
    raise RuntimeError(f"All RPCs failed for {chain}: {last_err}")

def _sol_rpc(method: str, params: list, timeout: int = 15) -> dict:
    """Call Solana JSON-RPC."""
    urls = RPC_URLS.get("sol", [])
    urls = [u for u in urls if u]
    last_err = ""
    for url in urls:
        try:
            r = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
            data = r.json()
            if "error" in data:
                last_err = str(data["error"])
                continue
            return data
        except Exception as e:
            last_err = str(e)
    raise RuntimeError(f"All Solana RPCs failed: {last_err}")


# ═══════════════════════════════════════════════════════════════════════════
# ADDRESS DERIVATION
# ═══════════════════════════════════════════════════════════════════════════

def privkey_to_address(priv_hex: str, chain: str) -> str:
    """Derive address from a hex private key for any chain."""
    pk = bytes.fromhex(priv_hex.replace("0x", ""))
    
    if chain in EVM_CHAINS:
        sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
        pub = b"\x04" + sk.get_verifying_key().to_string()
        return "0x" + _keccak256(pub[1:])[-20:].hex()
    
    if chain == "btc":
        return _btc_address_from_pubkey(pk, mainnet=True, segwit=False)
    
    if chain == "ltc":
        return _ltc_address_from_pubkey(pk)
    
    if chain == "doge":
        return _doge_address_from_pubkey(pk)
    
    if chain == "sol":
        from cryptography.hazmat.primitives.asymmetric import ed25519
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(pk[:32])
        pub = sk.public_key()
        return _base58_encode(pub.public_bytes_raw())
    
    raise ValueError(f"Unsupported chain for derivation: {chain}")

def _btc_address_from_pubkey(pk: bytes, mainnet: bool = True, segwit: bool = True) -> str:
    """Derive BTC address from private key bytes."""
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    pub_hash = _hash160(pub[1:] if len(pub) == 65 else pub)
    
    if segwit:
        # P2WPKH (native segwit, bc1...)
        from hashlib import sha256
        def bech32_create_checksum(hrp, data):
            values = _bech32_hrp_expand(hrp) + data
            polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
            return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
        def _bech32_hrp_expand(hrp):
            return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
        def _bech32_polymod(values):
            gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = chk >> 25
                chk = (chk & 0x1ffffff) << 5 ^ v
                for i in range(5):
                    if (b >> i) & 1:
                        chk ^= gen[i]
            return chk
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        hrp = "bc" if mainnet else "tb"
        witver = 0
        data = [witver] + _convertbits(pub_hash, 8, 5)
        checksum = bech32_create_checksum(hrp, data)
        combined = data + checksum
        return hrp + "1" + "".join(charset[d] for d in combined)
    else:
        # P2PKH (legacy, 1...)
        prefix = b"\x00" if mainnet else b"\x6f"
        payload = prefix + pub_hash
        checksum = _double_sha256(payload)[:4]
        return _base58_encode(payload + checksum)

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits:
        return None
    return ret

def _ltc_address_from_pubkey(pk: bytes) -> str:
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    pub_hash = _hash160(pub[1:] if len(pub) == 65 else pub)
    payload = b"\x30" + pub_hash  # LTC mainnet P2PKH prefix
    checksum = _double_sha256(payload)[:4]
    return _base58_encode(payload + checksum)

def _doge_address_from_pubkey(pk: bytes) -> str:
    sk = ecdsa.SigningKey.from_string(pk, curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    pub_hash = _hash160(pub[1:] if len(pub) == 65 else pub)
    payload = b"\x1e" + pub_hash  # DOGE mainnet P2PKH prefix
    checksum = _double_sha256(payload)[:4]
    return _base58_encode(payload + checksum)


# ═══════════════════════════════════════════════════════════════════════════
# BALANCE CHECK (live RPC)
# ═══════════════════════════════════════════════════════════════════════════

def get_balance(chain: str, address: str) -> dict:
    """Get live balance for an address on any chain."""
    if chain in ("polygon", "poly"):
        chain = "matic"
    
    try:
        if chain in EVM_CHAINS:
            result = _rpc_call(chain, "eth_getBalance", [address, "latest"])
            wei = int(result["result"], 16)
            dec = DECIMALS[chain]
            return {"chain": chain, "address": address, "balance": wei / (10 ** dec),
                    "symbol": NATIVE[chain], "live": True}
        elif chain == "btc":
            return _utxo_balance("btc", address, BTC_API)
        elif chain == "ltc":
            return _utxo_balance("ltc", address, LTC_API)
        elif chain == "doge":
            return _doge_balance(address)
        elif chain == "sol":
            result = _sol_rpc("getBalance", [address])
            lamports = result.get("result", {}).get("value", 0)
            return {"chain": "sol", "address": address, "balance": lamports / 1e9,
                    "symbol": "SOL", "live": True}
        else:
            return {"chain": chain, "address": address, "balance": None, "error": f"Unsupported chain: {chain}"}
    except Exception as e:
        return {"chain": chain, "address": address, "balance": None, "error": str(e)}


def _utxo_balance(chain: str, address: str, api_base: str) -> dict:
    """Get UTXO-based balance from mempool-style API."""
    try:
        r = requests.get(f"{api_base}/address/{address}", timeout=15)
        data = r.json()
        funded = data.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent = data.get("chain_stats", {}).get("spent_txo_sum", 0)
        balance_sats = funded - spent
        dec = DECIMALS[chain]
        return {"chain": chain, "address": address, "balance": balance_sats / (10 ** dec),
                "symbol": NATIVE[chain], "live": True}
    except Exception as e:
        return {"chain": chain, "address": address, "balance": None, "error": str(e)}

def _doge_balance(address: str) -> dict:
    """Get DOGE balance via dogechain.info API."""
    try:
        r = requests.get(f"{DOGE_API}/address/balance/{address}", timeout=15)
        data = r.json()
        bal = float(data.get("balance", 0))
        return {"chain": "doge", "address": address, "balance": bal,
                "symbol": "DOGE", "live": True}
    except Exception as e:
        return {"chain": "doge", "address": address, "balance": None, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# SEND — unified multi-chain transaction builder + broadcaster
# ═══════════════════════════════════════════════════════════════════════════

def send(chain: str, priv_key_hex: str, to_addr: str, amount: float,
         gas_price_gwei: float | None = None) -> dict:
    """Send native currency on any supported chain.
    
    Returns: {"ok": True, "tx_hash": "...", "explorer": "...", ...}
    """
    if chain in ("polygon", "poly"):
        chain = "matic"
    
    pk = priv_key_hex.strip().replace("0x", "").replace(" ", "")
    if len(pk) != 64 or not all(c in "0123456789abcdefABCDEF" for c in pk):
        return {"ok": False, "error": "Private key must be 64 hex characters"}
    
    if chain in EVM_CHAINS:
        return _send_evm(chain, pk, to_addr, amount, gas_price_gwei)
    elif chain == "btc":
        return _send_btc(pk, to_addr, amount)
    elif chain == "ltc":
        return _send_ltc(pk, to_addr, amount)
    elif chain == "doge":
        return _send_doge(pk, to_addr, amount)
    elif chain == "sol":
        return _send_sol(pk, to_addr, amount)
    else:
        return {"ok": False, "error": f"Send not supported for {chain}"}


# ── EVM send (ETH, MATIC, BNB, AVAX, BASE, ARB, OP) ────────────────────

def _send_evm(chain: str, pk_hex: str, to_addr: str, amount_eth: float,
              gas_price_gwei: float | None = None) -> dict:
    """Build, sign, and broadcast an EVM transaction."""
    if not to_addr.startswith("0x") or len(to_addr) != 42:
        return {"ok": False, "error": "to_addr must be 0x-prefixed 40-hex EVM address"}
    
    value_wei = int(amount_eth * 1e18)
    if value_wei <= 0:
        return {"ok": False, "error": "Amount must be > 0"}
    
    # Derive from address
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(pk_hex), curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    from_addr = "0x" + _keccak256(pub[1:])[-20:].hex()
    
    # Get nonce
    nonce_result = _rpc_call(chain, "eth_getTransactionCount", [from_addr, "latest"])
    nonce = int(nonce_result["result"], 16)
    
    # Get gas price (EIP-1559 if supported, else legacy)
    gas_price = None
    max_fee = None
    max_priority = None
    
    if gas_price_gwei:
        gas_price = int(gas_price_gwei * 1e9)
    else:
        # Try EIP-1559
        try:
            fee_data = _rpc_call(chain, "eth_feeHistory", ["0x1", "latest", []])
            if fee_data.get("result"):
                base = int(fee_data["result"].get("baseFeePerGas", ["0x0"])[-1], 16)
                max_priority = 1_500_000_000  # 1.5 gwei priority
                max_fee = base * 2 + max_priority
        except Exception:
            pass
        
        if max_fee is None:
            try:
                gp_result = _rpc_call(chain, "eth_gasPrice", [])
                gas_price = int(gp_result["result"], 16)
            except Exception:
                gas_price = 50_000_000_000  # 50 gwei fallback
    
    # Estimate gas
    gas_limit = 21000
    try:
        est = _rpc_call(chain, "eth_estimateGas", [{
            "from": from_addr, "to": to_addr, "value": hex(value_wei)
        }])
        gas_limit = int(est["result"], 16)
    except Exception:
        pass
    
    # Check balance
    bal_result = _rpc_call(chain, "eth_getBalance", [from_addr, "latest"])
    bal_wei = int(bal_result["result"], 16)
    tx_cost = value_wei + (gas_limit * (max_fee or gas_price))
    if bal_wei < tx_cost:
        return {"ok": False, "error": f"Insufficient funds: {bal_wei / 1e18:.6f} {NATIVE[chain]}, "
                f"need ~{tx_cost / 1e18:.6f} {NATIVE[chain]}"}
    
    # Build and sign
    cid = CHAIN_IDS.get(chain, 1)
    
    if max_fee is not None and max_priority is not None:
        # EIP-1559
        utx = [cid, nonce, max_priority, max_fee, gas_limit,
               bytes.fromhex(to_addr[2:]), value_wei, b"", []]
        tx_type = b"\x02"
        tx_hash = _keccak256(tx_type + _rlp_encode(utx))
        sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der)
        r, s = ecdsa.util.sigdecode_der(sig, ecdsa.SECP256k1.generator.order())
        n = ecdsa.SECP256k1.generator.order()
        v = 0
        if s > n // 2:
            s = n - s
            v ^= 1
        stx = [cid, nonce, max_priority, max_fee, gas_limit,
               bytes.fromhex(to_addr[2:]), value_wei, b"", [],
               v, r.to_bytes(32, "big"), s.to_bytes(32, "big")]
        signed = tx_type + _rlp_encode(stx)
    else:
        # Legacy
        utx = [nonce, gas_price, gas_limit,
               bytes.fromhex(to_addr[2:]), value_wei, b"",
               cid, 0, 0]
        h = _keccak256(_rlp_encode(utx))
        sig = sk.sign_digest(h, sigencode=ecdsa.util.sigencode_der)
        r, s = ecdsa.util.sigdecode_der(sig, ecdsa.SECP256k1.generator.order())
        v = cid * 2 + 35
        n = ecdsa.SECP256k1.generator.order()
        if s > n // 2:
            s = n - s
            v ^= 1
        stx = [nonce, gas_price, gas_limit,
               bytes.fromhex(to_addr[2:]), value_wei, b"",
               v, r.to_bytes(32, "big"), s.to_bytes(32, "big")]
        signed = _rlp_encode(stx)
    
    signed_hex = "0x" + signed.hex()
    
    # Broadcast
    result = _rpc_call(chain, "eth_sendRawTransaction", [signed_hex], timeout=30)
    tx_hash = result.get("result")
    if not tx_hash:
        return {"ok": False, "error": f"Broadcast failed: {result}"}
    
    return {
        "ok": True,
        "tx_hash": tx_hash,
        "from": from_addr,
        "to": to_addr,
        "value": amount_eth,
        "chain": chain,
        "symbol": NATIVE[chain],
        "nonce": nonce,
        "gas_limit": gas_limit,
        "explorer": f"{EXPLORERS[chain]}/tx/{tx_hash}",
    }


# ── BTC send ─────────────────────────────────────────────────────────────

def _send_btc(pk_hex: str, to_addr: str, amount_btc: float) -> dict:
    """Send BTC via UTXO. Uses mempool.space API for UTXO data."""
    from_addr = _btc_address_from_pubkey(bytes.fromhex(pk_hex), mainnet=True, segwit=True)
    amount_sats = int(amount_btc * 1e8)
    
    if amount_sats < 546:
        return {"ok": False, "error": "BTC dust limit: minimum ~546 sats"}
    
    # Fetch UTXOs
    try:
        r = requests.get(f"{BTC_API}/address/{from_addr}/utxo", timeout=15)
        utxos = r.json()
    except Exception as e:
        return {"ok": False, "error": f"Failed to fetch UTXOs: {e}"}
    
    if not utxos:
        return {"ok": False, "error": f"No UTXOs for {from_addr}"}
    
    # Sort by value descending
    utxos.sort(key=lambda u: u.get("value", 0), reverse=True)
    
    # Select UTXOs
    selected = []
    total_in = 0
    fee_rate = 15  # sats/vbyte
    for utxo in utxos:
        selected.append(utxo)
        total_in += utxo["value"]
        # Estimate tx size: ~10 bytes overhead + ~148 per input + ~34 per output
        est_size = 10 + len(selected) * 148 + 2 * 34
        fee = est_size * fee_rate
        if total_in >= amount_sats + fee:
            break
    
    if total_in < amount_sats + (len(selected) * 148 + 68) * fee_rate:
        return {"ok": False, "error": f"Insufficient BTC. {total_in / 1e8:.8f} BTC available"}
    
    # Build raw transaction (simplified P2WPKH)
    # This is a simplified BTC tx builder — full implementation needs proper sighash
    # For now, return a clear message that BTC send requires more complete signing
    return {
        "ok": False,
        "error": "BTC send requires full UTXO signing. Use the address view + external wallet for now.",
        "from_addr": from_addr,
        "utxos_count": len(utxos),
        "total_utxo_value_btc": sum(u.get("value", 0) for u in utxos) / 1e8,
        "recommended": "Export private key to Electrum or Sparrow wallet for BTC sending.",
    }


# ── LTC send ─────────────────────────────────────────────────────────────

def _send_ltc(pk_hex: str, to_addr: str, amount_ltc: float) -> dict:
    return {"ok": False, "error": "LTC send: use external wallet. "
            "Private key can be imported to Litecoin Core or Electrum-LTC.",
            "from_addr": _ltc_address_from_pubkey(bytes.fromhex(pk_hex))}


# ── DOGE send ────────────────────────────────────────────────────────────

def _send_doge(pk_hex: str, to_addr: str, amount_doge: float) -> dict:
    return {"ok": False, "error": "DOGE send: use external wallet. "
            "Private key can be imported to Dogecoin Core.",
            "from_addr": _doge_address_from_pubkey(bytes.fromhex(pk_hex))}


# ── SOL send ─────────────────────────────────────────────────────────────

def _send_sol(pk_hex: str, to_addr: str, amount_sol: float) -> dict:
    """Send SOL via raw transaction. Uses cryptography for Ed25519."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    pk_bytes = bytes.fromhex(pk_hex)[:32]
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(pk_bytes)
    pub_key = sk.public_key()
    from_addr = _base58_encode(pub_key.public_bytes_raw())
    amount_lamports = int(amount_sol * 1e9)
    
    # Get recent blockhash
    try:
        bh_result = _sol_rpc("getLatestBlockhash", [{"commitment": "finalized"}])
        blockhash = bh_result["result"]["value"]["blockhash"]
    except Exception as e:
        return {"ok": False, "error": f"Failed to get Solana blockhash: {e}"}
    
    # Build transaction (simplified)
    # Full Solana tx building requires proper instruction packing + serialization
    # Using the system program transfer instruction
    from base58 import b58decode
    
    # Build transfer instruction
    # System program ID
    system_program = b58decode("11111111111111111111111111111111")
    
    # Build a minimal Solana transaction
    # This is a simplified representation — full implementation requires
    # proper Solana message format with compiled instructions
    return {
        "ok": False,
        "error": "SOL send requires full Solana transaction serialization. "
                "Use external wallet (Phantom, Solflare) or solana CLI for now.",
        "from_addr": from_addr,
        "blockhash": blockhash,
        "recommended": "Export private key to Phantom wallet for SOL sending.",
    }


# ═══════════════════════════════════════════════════════════════════════════
# SWAP — 0x API (EVM) + Jupiter (Solana)
# ═══════════════════════════════════════════════════════════════════════════

SWAP_TOKENS: dict[str, dict[str, str]] = {
    "eth": {
        "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    },
    "matic": {
        "USDC": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        "USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "WMATIC": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
    },
    "bnb": {
        "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
        "USDT": "0x55d398326f99059fF775485246999027B3197955",
        "WBNB": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    },
    "base": {
        "USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
    "arb": {
        "USDC": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
        "USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
    },
}

ZERO_EX_API = "https://api.0x.org"
JUPITER_API = "https://quote-api.jup.ag/v6"

def get_swap_quote(chain: str, from_token: str, to_token: str,
                   amount: float, from_addr: str, slippage: float = 0.01) -> dict:
    """Get a swap quote from 0x (EVM) or Jupiter (Solana).
    
    from_token/to_token: "ETH", "USDC", "SOL", or token address.
    """
    if chain == "sol":
        return _jupiter_quote(from_token, to_token, amount, from_addr, slippage)
    else:
        return _zeroex_quote(chain, from_token, to_token, amount, from_addr, slippage)


def _zeroex_quote(chain: str, from_token: str, to_token: str,
                  amount: float, from_addr: str, slippage: float) -> dict:
    """Get swap quote from 0x API."""
    chain_map = {"eth": "ethereum", "matic": "polygon", "bnb": "bsc",
                 "base": "base", "arb": "arbitrum", "op": "optimism"}
    api_chain = chain_map.get(chain, chain)
    
    # Resolve token symbols to addresses
    tokens = SWAP_TOKENS.get(chain, {})
    sell_token = from_token
    buy_token = to_token
    
    # If it's the native token (ETH, MATIC, etc.)
    native = NATIVE.get(chain, "ETH")
    if from_token.upper() == native:
        sell_token = "ETH" if chain == "eth" else native
    elif from_token in tokens:
        sell_token = tokens[from_token]
    
    if to_token.upper() == native:
        buy_token = "ETH" if chain == "eth" else native
    elif to_token in tokens:
        buy_token = tokens[to_token]
    
    # Convert amount to smallest unit
    dec = _token_decimals(chain, from_token)
    amount_wei = int(amount * (10 ** dec))
    
    params = {
        "chainId": CHAIN_IDS.get(chain, 1),
        "sellToken": sell_token,
        "buyToken": buy_token,
        "sellAmount": str(amount_wei),
        "taker": from_addr,
        "slippageBps": int(slippage * 10000),
    }
    
    try:
        r = requests.get(f"{ZERO_EX_API}/swap/v1/quote", params=params,
                        headers={"0x-api-key": _ENV.get("ZEROX_API_KEY", "")},
                        timeout=15)
        data = r.json()
        if "code" in data and data["code"] != 1:
            return {"ok": False, "error": data.get("reason", str(data))}
        return {"ok": True, "quote": data}
    except Exception as e:
        return {"ok": False, "error": f"0x API error: {e}"}


def _token_decimals(chain: str, token: str) -> int:
    """Get token decimals."""
    stablecoins = {"USDC", "USDT", "DAI"}
    if token.upper() in stablecoins:
        return 6 if chain in ("eth", "base", "arb", "matic") and token.upper() in ("USDC",) else 6
    if token.upper() == "WBTC":
        return 8
    return 18  # default for most ERC20


def _jupiter_quote(from_token: str, to_token: str, amount: float,
                   from_addr: str, slippage: float) -> dict:
    """Get swap quote from Jupiter (Solana)."""
    # Convert SOL/USDC amounts to lamports/base-units
    amount_lamports = int(amount * 1e9) if from_token.upper() == "SOL" else int(amount * 1e6)
    
    # Token mint addresses
    sol_mints = {
        "SOL": "So11111111111111111111111111111111111111112",
        "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    }
    
    from_mint = sol_mints.get(from_token.upper(), from_token)
    to_mint = sol_mints.get(to_token.upper(), to_token)
    
    # Get quote
    try:
        params = {
            "inputMint": from_mint,
            "outputMint": to_mint,
            "amount": amount_lamports,
            "slippageBps": int(slippage * 10000),
        }
        r = requests.get(f"{JUPITER_API}/quote", params=params, timeout=15)
        data = r.json()
        if "error" in data:
            return {"ok": False, "error": data.get("error", str(data))}
        return {"ok": True, "quote": data}
    except Exception as e:
        return {"ok": False, "error": f"Jupiter API error: {e}"}


def execute_swap(chain: str, priv_key_hex: str, quote: dict) -> dict:
    """Execute a swap using the quote from get_swap_quote."""
    if chain == "sol":
        return {"ok": False, "error": "SOL swap execution: submit the Jupiter transaction via external wallet"}
    
    # For EVM: 0x swap — use the quote's transaction data
    tx_data = quote.get("quote", quote)
    if not tx_data.get("to"):
        return {"ok": False, "error": "Invalid quote — missing transaction data"}
    
    to_addr = tx_data["to"]
    value_wei = int(tx_data.get("value", "0"))
    data_hex = tx_data.get("data", "0x")
    
    pk = priv_key_hex.strip().replace("0x", "").replace(" ", "")
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(pk), curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    from_addr = "0x" + _keccak256(pub[1:])[-20:].hex()
    
    # Check allowance if needed
    sell_token = tx_data.get("sellTokenAddress", "")
    if sell_token and sell_token.lower() != "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":
        # ERC20 approval check
        allowance_owner = from_addr
        spender = tx_data.get("allowanceTarget", to_addr)
        if spender:
            try:
                approve_data = _check_and_approve(chain, pk, sell_token, spender,
                                                  int(tx_data.get("sellAmount", "0")))
                if not approve_data.get("ok"):
                    return approve_data
            except Exception as e:
                return {"ok": False, "error": f"Approval failed: {e}"}
    
    # Get nonce
    nonce_result = _rpc_call(chain, "eth_getTransactionCount", [from_addr, "latest"])
    nonce = int(nonce_result["result"], 16)
    
    # Get gas price
    try:
        gp_result = _rpc_call(chain, "eth_gasPrice", [])
        gas_price = int(gp_result["result"], 16)
    except Exception:
        gas_price = 50_000_000_000
    
    # Estimate gas
    gas_limit = int(tx_data.get("gas", "300000"))
    try:
        est = _rpc_call(chain, "eth_estimateGas", [{
            "from": from_addr, "to": to_addr, "value": hex(value_wei),
            "data": data_hex,
        }])
        gas_limit = int(est["result"], 16) * 12 // 10  # +20% buffer
    except Exception:
        pass
    
    cid = CHAIN_IDS.get(chain, 1)
    to_bytes_data = bytes.fromhex(to_addr[2:])
    input_data = bytes.fromhex(data_hex[2:]) if data_hex else b""
    
    utx = [nonce, gas_price, gas_limit, to_bytes_data, value_wei, input_data, cid, 0, 0]
    h = _keccak256(_rlp_encode(utx))
    sig = sk.sign_digest(h, sigencode=ecdsa.util.sigencode_der)
    r, s = ecdsa.util.sigdecode_der(sig, ecdsa.SECP256k1.generator.order())
    v = cid * 2 + 35
    n = ecdsa.SECP256k1.generator.order()
    if s > n // 2:
        s = n - s
        v ^= 1
    stx = [nonce, gas_price, gas_limit, to_bytes_data, value_wei, input_data,
           v, r.to_bytes(32, "big"), s.to_bytes(32, "big")]
    signed = "0x" + _rlp_encode(stx).hex()
    
    result = _rpc_call(chain, "eth_sendRawTransaction", [signed], timeout=30)
    tx_hash = result.get("result")
    if not tx_hash:
        return {"ok": False, "error": f"Swap broadcast failed: {result}"}
    
    return {
        "ok": True,
        "tx_hash": tx_hash,
        "explorer": f"{EXPLORERS[chain]}/tx/{tx_hash}",
        "from": from_addr,
    }


def _check_and_approve(chain: str, pk_hex: str, token_addr: str,
                       spender: str, amount: int) -> dict:
    """Check ERC20 allowance and approve if needed."""
    from_addr = privkey_to_address(pk_hex, chain)
    
    # Check allowance
    allowance_data = "0xdd62ed3e000000000000000000000000" + from_addr[2:].rjust(64, "0") + spender[2:].rjust(64, "0")
    try:
        result = _rpc_call(chain, "eth_call", [{
            "to": token_addr, "data": allowance_data
        }, "latest"])
        current = int(result.get("result", "0x0"), 16)
        if current >= amount:
            return {"ok": True, "approved": False}
    except Exception:
        pass
    
    # Approve
    approve_data = "0x095ea7b3" + spender[2:].rjust(64, "0") + hex(amount)[2:].rjust(64, "0")
    
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(pk_hex), curve=ecdsa.SECP256k1)
    nonce_result = _rpc_call(chain, "eth_getTransactionCount", [from_addr, "latest"])
    nonce = int(nonce_result["result"], 16)
    
    try:
        gp_result = _rpc_call(chain, "eth_gasPrice", [])
        gas_price = int(gp_result["result"], 16)
    except Exception:
        gas_price = 50_000_000_000
    
    cid = CHAIN_IDS.get(chain, 1)
    to_bytes = bytes.fromhex(token_addr[2:])
    data_bytes = bytes.fromhex(approve_data[2:])
    
    utx = [nonce, gas_price, 60000, to_bytes, 0, data_bytes, cid, 0, 0]
    h = _keccak256(_rlp_encode(utx))
    sig = sk.sign_digest(h, sigencode=ecdsa.util.sigencode_der)
    r, s = ecdsa.util.sigdecode_der(sig, ecdsa.SECP256k1.generator.order())
    v = cid * 2 + 35
    n = ecdsa.SECP256k1.generator.order()
    if s > n // 2:
        s = n - s
        v ^= 1
    stx = [nonce, gas_price, 60000, to_bytes, 0, data_bytes,
           v, r.to_bytes(32, "big"), s.to_bytes(32, "big")]
    signed = "0x" + _rlp_encode(stx).hex()
    
    result = _rpc_call(chain, "eth_sendRawTransaction", [signed], timeout=30)
    tx_hash = result.get("result")
    return {"ok": True, "approved": True, "approval_tx": tx_hash}


# ═══════════════════════════════════════════════════════════════════════════
# BRIDGE — LI.FI cross-chain bridge aggregator
# ═══════════════════════════════════════════════════════════════════════════

LIFI_API = "https://li.quest/v1"

def get_bridge_quote(from_chain: str, to_chain: str, from_token: str,
                     to_token: str, amount: float, from_addr: str) -> dict:
    """Get a cross-chain bridge quote from LI.FI.
    
    Supports: ETH, MATIC, BNB, AVAX, BASE, ARB, OP, SOL
    """
    chain_map = {
        "eth": 1, "matic": 137, "bnb": 56, "avax": 43114,
        "base": 8453, "arb": 42161, "op": 10, "sol": 1151111081099710,
    }
    
    from_id = chain_map.get(from_chain)
    to_id = chain_map.get(to_chain)
    if not from_id or not to_id:
        return {"ok": False, "error": f"Unsupported chain pair: {from_chain}→{to_chain}"}
    
    # Convert amount to wei-equivalent
    dec = DECIMALS.get(from_chain, 18)
    amount_wei = str(int(amount * (10 ** dec)))
    
    # Token addresses
    native_tokens = {
        "eth": "0x0000000000000000000000000000000000000000",
        "matic": "0x0000000000000000000000000000000000000000",
        "bnb": "0x0000000000000000000000000000000000000000",
        "avax": "0x0000000000000000000000000000000000000000",
        "base": "0x0000000000000000000000000000000000000000",
        "arb": "0x0000000000000000000000000000000000000000",
        "op": "0x0000000000000000000000000000000000000000",
    }
    
    from_token_addr = native_tokens.get(from_chain, from_token)
    to_token_addr = native_tokens.get(to_chain, to_token)
    
    params = {
        "fromChain": from_id,
        "toChain": to_id,
        "fromToken": from_token_addr,
        "toToken": to_token_addr,
        "fromAmount": amount_wei,
        "fromAddress": from_addr,
    }
    
    try:
        r = requests.get(f"{LIFI_API}/quote", params=params, timeout=20)
        data = r.json()
        if "message" in data and data.get("message"):
            return {"ok": False, "error": data["message"]}
        return {"ok": True, "quote": data}
    except Exception as e:
        return {"ok": False, "error": f"LI.FI API error: {e}"}


# ═══════════════════════════════════════════════════════════════════════════
# RECEIVE — address display
# ═══════════════════════════════════════════════════════════════════════════

def get_all_addresses(priv_key_hex: str) -> dict[str, dict]:
    """Derive addresses on all supported chains from a private key."""
    chains = list(EVM_CHAINS) + ["btc", "ltc", "doge", "sol"]
    pk = priv_key_hex.strip().replace("0x", "").replace(" ", "")
    if len(pk) != 64:
        return {"error": "Key must be 64 hex chars"}
    
    result = {}
    for chain in chains:
        try:
            addr = privkey_to_address(pk, chain)
            result[chain] = {
                "address": addr,
                "chain": chain,
                "symbol": NATIVE.get(chain, chain.upper()),
                "explorer": f"{EXPLORERS.get(chain, '')}/address/{addr}",
            }
        except Exception as e:
            result[chain] = {"error": str(e)}
    
    return result
