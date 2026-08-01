"""Real volatility computation per asset from Binance klines.

Uses 30-day daily candles to compute annualized volatility.
Returns per-asset values instead of a flat 60% default.
Cached for 15 minutes to avoid rate-limiting.
"""

from __future__ import annotations

import json
import logging
import math
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

# Per-asset default volatilities (annualized) when Binance is unavailable
DEFAULTS: dict[str, float] = {
    "BTC": 0.55,
    "ETH": 0.70,
    "SOL": 0.85,
    "XRP": 0.75,
    "DOGE": 0.90,
    "ADA": 0.80,
    "AVAX": 0.85,
    "LINK": 0.80,
    "DOT": 0.80,
    "LTC": 0.70,
    "BCH": 0.75,
    "SUI": 1.00,
}

KLINES_URL = "https://api.binance.com/api/v3/klines"


class VolatilityStore:
    """Fetches and caches per-asset annualized volatility."""

    def __init__(self, cache_seconds: int = 900):
        self._cache: dict[str, float] = {}
        self._cache_time: float = 0.0
        self._cache_seconds = cache_seconds

    def get(self, asset: str, binance_symbol: str, days: int = 30) -> float:
        """Get annualized volatility for an asset.

        Returns a value like 0.55 (55% annualized).
        Uses Binance klines; falls back to per-asset default.
        Results cached for cache_seconds.
        """
        now = time.time()
        cached = self._cache.get(asset)
        if cached is not None and (now - self._cache_time) < self._cache_seconds:
            return cached

        vol = self._fetch(binance_symbol, days) or DEFAULTS.get(asset, 0.60)
        self._cache[asset] = vol
        self._cache_time = now
        logger.debug("%s volatility: %.1f%%", asset, vol * 100)
        return vol

    def _fetch(self, symbol: str, days: int) -> float | None:
        """Compute annualized volatility from Binance daily klines."""
        try:
            url = f"{KLINES_URL}?symbol={symbol}&interval=1d&limit={days}"
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            if not data or len(data) < 3:
                return None

            closes = [float(c[4]) for c in data]
            log_returns = [
                math.log(closes[i] / closes[i - 1])
                for i in range(1, len(closes))
            ]

            mean = sum(log_returns) / len(log_returns)
            variance = sum((r - mean) ** 2 for r in log_returns) / (len(log_returns) - 1)
            daily_vol = math.sqrt(variance)
            annual_vol = daily_vol * math.sqrt(365)

            return annual_vol
        except (URLError, OSError, KeyError, ValueError, IndexError) as e:
            logger.debug("Volatility fetch failed for %s: %s", symbol, e)
            return None


# Singleton
_vol_store: VolatilityStore | None = None


def get_vol_store() -> VolatilityStore:
    global _vol_store
    if _vol_store is None:
        _vol_store = VolatilityStore()
    return _vol_store


def get_volatility(asset: str, binance_symbol: str) -> float:
    """Convenience: get annualized volatility for an asset."""
    return get_vol_store().get(asset, binance_symbol)
