#!/usr/bin/env python3
"""
Contract / infrastructure-address filter.

The scanner finds 0x… addresses in source code.  Many are NOT personal
wallets — they are known smart contracts (WETH, USDC, Uniswap Router,
Polygon Bridge, exchange hot wallets, etc.) that developers reference
in their code.  These addresses DO hold real balances on-chain, but
nobody owns the private key.  Calling them "funded wallets" is wrong.

Detection strategy (ordered cheapest → most expensive):
  1. Known-infrastructure denylist (no RPC — instant)
  2. eth_getCode RPC — if bytecode is non-empty, it's a contract

Usage:
    from contract_filter import is_real_wallet, is_contract_address

    if is_real_wallet("eth", "0x742d35Cc..."):
        # This is an actual personal wallet
    else:
        # This is a contract / bridge / token / exchange hot wallet
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Dict, Optional

import requests

# ── Known infrastructure denylist ──────────────────────────────────
# Stored lowercase without 0x prefix for fast O(1) lookup.
_INFRA_BODIES: set = {
    # Polygon chain
    "0000000000000000000000000000000000001010",  # Polygon Bridge
    "0000000000000000000000000000000000001000",  # Polygon Bor
    "0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",  # WMATIC
    # Ethereum mainnet
    "00000000219ab540356cbb839cbe05303d7705fa",  # Beacon Deposit (ETH2)
    "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
    "dac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
    "5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",  # Uniswap V2 Factory
    "e592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
    "1f9840a85d5af5bf1d1762f925bdaddc4201f984",  # UNI token
    "def1c0ded9bec7f1a1670819833240f027b25eff",  # 0x Exchange Proxy
    "1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch v4
    "1111111254eeb25477b68fb85ed929f73a960582",  # 1inch v5
    "881d40237659c251811cec9c364ef91dc08d300c",  # Metamask Swap
    "7f5c764cbc14f9669b88837ca1490cca17c31607",  # USDC.e bridged
    "ae7ab96520de3a18e5e111b5eaab095312d7fe84",  # stETH (Lido)
    "be9895146f7af43049ca1c1ae358b0541ea49704",  # cbETH (Coinbase)
    "2260fac5e5542a773aa44fbcfedf7c193bc2c599",  # WBTC
    "6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    "514910771af9ca656af840dff83e8264ecf986ca",  # LINK
    "95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",  # SHIB
    "d533a949740bb3306d119cc777fa900ba034cd52",  # CRV
    "ba100000625a3754423978a60c9317c58a424e3d",  # BAL
    "c011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f",  # SNX
    "9f8f72aa9304c8b593d555f12ef6589cc3a579a2",  # MKR
    "1f573d6fb3f13d689ff844b4ce37794d79a7ff1c",  # BNT
    "c18360217d8f7ab5e7c516566761ea12ce7f9d72",  # ENS
    "4d224452801aced8b2f0aebe155379bb5d594381",  # APE
    "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0",  # wstETH
    "cbb7c0000ab88b473b1f5afd9ef808440eed33bf",  # cbBTC
    "dea5c09a3f6e8d03b325b7b4a1c6d48595f71df9",  # Binance hot
    "28c6c06298d514db089934071355e5743bf21d60",  # Binance 14
    "f977814e90da44bfa03b6295a0616a897441acec",  # Binance 8
    "e93381fb4c4f14bda253907b18fad305d799241a",  # Coinbase 10
    "71660c4005ba85c37ccec55d0c4493e66fe775d3",  # Coinbase hot
    "a9d1e08c7793af67e9d92fe308d5697fb81d3e43",  # Coinbase 3
    "cffad3200574698b78f32232aa9d63eabd290703",  # Kraken
    "53d284357ec70ce289d6d64134dfac8e511c8a3d",  # Kraken 6
    "267be1c1d684f78cb4f6a176c82595f15b3e5c47",  # Kraken hot
    "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",  # Upbit
    # BSC
    "10ed43c718714eb63d5aa57b78b54704e256024e",  # PancakeSwap Router
    "ca143ce32fe78f1f7019d7d551a6402fc5350c73",  # PancakeSwap Factory
    "bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB
    "55d398326f99059ff775485246999027b3197955",  # BUSD
    "8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # USDC on BSC
    "2170ed0880ac9a755fd29b2688956bd959f933f8",  # ETH on BSC
    "7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",  # BTCB
    "e9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD v2
    # Solana
    "so11111111111111111111111111111111111111112",  # Wrapped SOL
    "stepnq2ugegszcygvr2nmqazf8xuejwqebd84wcksck",  # STEPN
    "dezxaz8z7pnrnrjzjz3wxborgixca6xjnb7yab1ppb263",  # Bonk
    # Avalanche
    "b31f66aa3c1e785363f0875a1b74e27b85fd66c7",  # WAVAX
    "b97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",  # USDC on AVAX
    # Arbitrum
    "82af49447d8a07e3bd95bd0d56f35241523fbab1",  # WETH on ARB
    "ff970a61a04b1ca14834a43f5de4533ebddb5cc8",  # USDC on ARB
    "fd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",  # USDT on ARB
    "912ce59144191c1204e64559fe8253a0e49e6548",  # ARB token
    # Base
    "4200000000000000000000000000000000000006",  # WETH on Base
    "833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC on Base
    "50c5725949a6f0c72e6c4a641f24049a917db0cb",  # DAI on Base
    # Optimism
    "4200000000000000000000000000000000000042",  # OP token
    "0b2c639c533813f4aa9d7837caf62653d097ff85",  # USDC on OP
    "94b008aa00579c1307b0ef2c499ad98a8ce58e58",  # USDT on OP
    # Bridge / proxy patterns
    "0000a26b00c1f0df003000390027140000faa719",  # ERC-1967 proxy
    "0000000071727de22e5e9d8baf0edac6f37da032",  # ERC-1967 proxy
    "4e68ccd3e89f51c3074ca5072bbac773960dfa36",  # Uniswap Universal Router
    "3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",  # Uniswap Permit2
    "000000000022d473030f116ddee9f6b43ac78ba3",  # Permit2 canonical
    # Tornado Cash
    "12d66f87a04a9e220743712ce6d9bb1b5616b8fc",  # 0.1 ETH
    "47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # 1 ETH
    "910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # 10 ETH
    "a160cdab225685da1d56aa342ad8841c3b53f291",  # 100 ETH
    "d96f2b1c14db8458370dbb0dd1507b205c2f4f90",  # Tornado Gov
    # L2 bridges / sequencers
    "5777d92f208679db4b9778590fa3cab3ac9e2168",  # Uniswap V3 pool
    "88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",  # Uniswap V3 pool
    # More known token contracts
    "d31a59c85ae9d8edefec411d448f90841571b89c",  # SOL Wormhole
    "7d1afa7b718fb893db30a3abc0cfc608aacfebb0",  # MATIC token on ETH
    "9f8f72aa9304c8b593d555f12ef6589cc3a579a2",  # MKR
    "3845badade8e6dff049820680d1f14bd3903a5d0",  # SAND
    "b8c77482e45f1f44de1745f52c74426c631bdd52",  # BNB on ETH
    "75231f58b43240c9718dd58b4967c5114342a86c",  # OKB
    "2b591e99afe9f32eaa6214f7b7629768c40eeb39",  # HEX
    # Monad
    "760afe86e5de5fa0ee542fc7b7b713e1c5425701",  # WMON
}

_EVM_CHAINS = frozenset({
    "eth", "matic", "avax", "bnb", "base", "arb", "op", "monad",
    "scrl", "linea", "blast", "zksync", "ftm", "cro", "gno",
})

# ── Cache for eth_getCode results ──────────────────────────────────
_CONTRACT_CACHE: Dict[str, bool] = {}
_CACHE_LOCK = threading.Lock()


def _normalize_evm(a: str) -> str:
    """Strip 0x, lowercase, return 40-char hex or empty."""
    a = (a or "").strip().lower().removeprefix("0x")
    if re.fullmatch(r"[0-9a-f]{40}", a):
        return a
    return ""


def _body_of(addr: str) -> str:
    """Return the normalized 40-char hex body or full Solana string."""
    a = (addr or "").strip()
    # If it looks like an EVM address, return the hex body
    body = a.lower().removeprefix("0x")
    if re.fullmatch(r"[0-9a-f]{40}", body):
        return body
    # Otherwise return the full lowered string
    return a.lower()


def is_known_infrastructure(chain: str, address: str) -> bool:
    """True if the address is a known contract/bridge/token/DEX/exchange wallet.

    This is an instant O(1) hash-set lookup — no RPC needed."""
    c = (chain or "").strip().lower()
    body = _body_of(address)
    if not body:
        return False

    # EVM chains: check denylist
    if c in _EVM_CHAINS:
        # Normalize to 40-char hex
        hx = _normalize_evm(body)
        if hx:
            if hx in _INFRA_BODIES:
                return True
            # Zero-heavy prefixes → system contracts / precompiles
            if hx.startswith("0000000"):
                return True
            # Low entropy → likely precompile/system
            if len(set(hx)) <= 6:
                return True
        return False

    # Solana: check known tokens
    if c == "sol":
        bl = body.lower()
        for prefix in (
            "so111111111111111111111111111111111111111",
            "stepnq2ugegszcygvr2nmqazf8xuejwqebd",
            "dezxaz8z7pnrnrjzjz3wxborgixca6xjnb7y",
        ):
            if bl.startswith(prefix):
                return True
        return False

    # BTC/LTC/DOGE: no contracts exist
    return False


def is_contract_address(chain: str, address: str) -> Optional[bool]:
    """Return True if *address* is a smart contract, False if personal EOA,
    or None if the check could not be performed.

    Uses ``eth_getCode`` RPC for EVM chains.  UTXO chains always return False.
    Results are cached forever (a contract never becomes an EOA)."""
    c = (chain or "").strip().lower()

    # UTXO chains: no contracts
    if c in ("btc", "ltc", "doge"):
        return False

    # Denylist check first (instant)
    if is_known_infrastructure(c, address):
        return True

    # Solana: too expensive to check per-address; rely on denylist
    if c == "sol" or c == "xrp":
        return None

    # Non-EVM: unknown
    if c not in _EVM_CHAINS:
        return None

    hx = _normalize_evm(address)
    if not hx:
        return None

    cache_key = f"{c}:{hx}"
    with _CACHE_LOCK:
        if cache_key in _CONTRACT_CACHE:
            return _CONTRACT_CACHE[cache_key]

    # ── eth_getCode RPC call ──────────────────────────────────────
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": ["0x" + hx, "latest"],
    }
    headers = {"User-Agent": "RepoHere1-Termux/2.0", "Content-Type": "application/json"}

    # Try a few well-known public RPCs (fast, no API key needed)
    rpc_urls = [
        f"https://{c}.drpc.org",
        f"https://{c}.publicnode.com",
        f"https://rpc.ankr.com/{c}",
        "https://ethereum.publicnode.com",
        "https://eth.drpc.org",
        "https://rpc.ankr.com/eth",
        "https://cloudflare-eth.com",
    ]
    # De-duplicate
    seen = set()
    for url in rpc_urls:
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.post(url, json=payload, timeout=8, headers=headers)
            r.raise_for_status()
            data = r.json()
            code = (data.get("result") or "").strip()
            is_contract = bool(code and code != "0x")
            with _CACHE_LOCK:
                _CONTRACT_CACHE[cache_key] = is_contract
            return is_contract
        except Exception:
            continue

    # No RPC responded — don't cache uncertainty
    return None


def is_real_wallet(chain: str, address: str) -> bool:
    """True if *address* is likely a personal wallet (EOA), not infrastructure.

    Combines: denylist → eth_getCode cache → RPC check.
    False means: known contract, bridge, token, exchange hot wallet, or
    precompile — not spendable by a private key the scanner could find."""
    if is_known_infrastructure(chain, address):
        return False
    is_contract = is_contract_address(chain, address)
    if is_contract is True:
        return False
    # If unknown (None), err on the side of including it
    # but flag as unverified
    return True
