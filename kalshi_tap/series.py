"""Kalshi crypto series registry — maps series tickers to assets and data feeds.

Each entry defines how to fetch the spot price and what Binance/CoinGecko
symbol pair to use for the underlying asset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class SeriesDef:
    """Definition for a tradeable Kalshi crypto series."""

    ticker: str
    label: str               # Human-readable short name
    asset: str               # Underlying asset symbol (BTC, ETH, etc.)
    category: str            # "crypto"
    frequency: str           # "daily", "hourly", "15min", etc.
    coingecko_id: str        # CoinGecko API ID
    binance_symbol: str      # Binance ticker pair (e.g., "BTCUSDT")

    def __hash__(self) -> int:
        return hash(self.ticker)


# ---------------------------------------------------------------------------
# Registered series — the ones worth trading (directional, frequent enough)
# ---------------------------------------------------------------------------

SERIES: list[SeriesDef] = [
    # BTC — the primary series
    SeriesDef("KXBTCD",  "BTC Daily",     "BTC", "crypto", "daily",      "bitcoin",     "BTCUSDT"),
    SeriesDef("KXBTCH",  "BTC Hourly",    "BTC", "crypto", "hourly",     "bitcoin",     "BTCUSDT"),
    SeriesDef("KXBTCD-B","BTC Daily (B)",  "BTC", "crypto", "daily",      "bitcoin",     "BTCUSDT"),

    # ETH
    SeriesDef("KXETHD",  "ETH Daily",     "ETH", "crypto", "daily",      "ethereum",    "ETHUSDT"),
    SeriesDef("KXETHDH", "ETH Hourly",    "ETH", "crypto", "hourly",     "ethereum",    "ETHUSDT"),

    # SOL
    SeriesDef("KXSOLD",  "SOL Daily",     "SOL", "crypto", "daily",      "solana",      "SOLUSDT"),
    SeriesDef("KXSOLH",  "SOL Hourly",    "SOL", "crypto", "hourly",     "solana",      "SOLUSDT"),

    # XRP
    SeriesDef("KXXRPD",  "XRP Hourly",    "XRP", "crypto", "hourly",     "ripple",      "XRPUSDT"),

    # DOGE
    SeriesDef("KXDOGED", "DOGE Daily",    "DOGE","crypto", "daily",      "dogecoin",    "DOGEUSDT"),

    # ADA
    SeriesDef("KXADAD",  "ADA Daily",     "ADA", "crypto", "daily",      "cardano",     "ADAUSDT"),

    # AVAX
    SeriesDef("KXAVAXD", "AVAX Daily",    "AVAX","crypto", "daily",      "avalanche-2", "AVAXUSDT"),

    # LINK
    SeriesDef("KXLINKD", "LINK Daily",    "LINK","crypto", "daily",      "chainlink",   "LINKUSDT"),

    # DOT
    SeriesDef("KXDOTD",  "DOT Daily",     "DOT", "crypto", "daily",      "polkadot",    "DOTUSDT"),

    # LTC
    SeriesDef("KXLTCD",  "LTC Daily",     "LTC", "crypto", "daily",      "litecoin",    "LTCUSDT"),

    # BCH
    SeriesDef("KXBCHD",  "BCH Daily",     "BCH", "crypto", "daily",      "bitcoin-cash","BCHUSDT"),

    # SUI
    SeriesDef("KXSUID",  "SUI Daily",     "SUI", "crypto", "daily",      "sui",         "SUIUSDT"),
]


def get_series(ticker: str) -> SeriesDef | None:
    """Look up a series definition by ticker."""
    for s in SERIES:
        if s.ticker == ticker:
            return s
    return None


def get_default_series() -> SeriesDef:
    """Return the primary series (BTC Daily)."""
    return SERIES[0]
