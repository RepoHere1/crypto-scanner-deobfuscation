"""Live BTC price feed from public exchanges.

Uses Binance public API (no auth required) as primary source with
CoinGecko as fallback. Both are free and rate-limited.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


@dataclass
class BTCPrice:
    """Current BTC price snapshot."""

    price_usd: float
    source: str
    timestamp: datetime

    def __repr__(self) -> str:
        return f"BTC ${self.price_usd:,.0f} via {self.source} at {self.timestamp:%H:%M:%S}"


class BTCFeed:
    """Multi-source BTC price feed with fallback and caching.

    Sources tried in order: Binance → CoinGecko.
    Results are cached for ``cache_seconds`` to avoid hammering APIs.
    """

    BINANCE_URL = "https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT"
    COINGECKO_URL = (
        "https://api.coingecko.com/api/v3/simple/price"
        "?ids=bitcoin&vs_currencies=usd"
    )

    def __init__(self, cache_seconds: int = 30):
        self._cache: BTCPrice | None = None
        self._cache_time: float = 0.0
        self._cache_seconds = cache_seconds

    def get_price(self) -> BTCPrice:
        """Get current BTC price in USD.

        Returns cached value if within the cache window, otherwise
        fetches from Binance (primary) or CoinGecko (fallback).
        """
        now = time.time()
        if self._cache and (now - self._cache_time) < self._cache_seconds:
            return self._cache

        price = self._fetch_binance() or self._fetch_coingecko()
        if price is None:
            if self._cache:
                logger.warning("All sources failed, returning stale cached price")
                return self._cache
            raise RuntimeError("Unable to fetch BTC price from any source")

        self._cache = price
        self._cache_time = now
        return price

    def _fetch_binance(self) -> BTCPrice | None:
        """Fetch BTC/USDT price from Binance public API."""
        try:
            req = Request(self.BINANCE_URL, headers={"Accept": "application/json"})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                price = float(data["price"])
                ts = datetime.now(timezone.utc)
                logger.debug("Binance: $%.2f", price)
                return BTCPrice(price_usd=price, source="binance", timestamp=ts)
        except (URLError, OSError, KeyError, ValueError) as e:
            logger.warning("Binance fetch failed: %s", e)
            return None

    def _fetch_coingecko(self) -> BTCPrice | None:
        """Fetch BTC/USD price from CoinGecko as fallback."""
        try:
            req = Request(self.COINGECKO_URL, headers={"Accept": "application/json"})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                price = float(data["bitcoin"]["usd"])
                ts = datetime.now(timezone.utc)
                logger.debug("CoinGecko: $%.2f", price)
                return BTCPrice(price_usd=price, source="coingecko", timestamp=ts)
        except (URLError, OSError, KeyError, ValueError) as e:
            logger.warning("CoinGecko fetch failed: %s", e)
            return None


def get_btc_volatility(days: int = 30) -> float:
    """Estimate daily BTC volatility from Binance klines.

    Returns annualized volatility as a decimal (e.g., 0.60 = 60%).
    Falls back to a reasonable default if unavailable.
    """
    try:
        url = (
            f"https://api.binance.com/api/v3/klines"
            f"?symbol=BTCUSDT&interval=1d&limit={days}"
        )
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if not data or len(data) < 2:
            return _DEFAULT_VOL

        # Daily log returns
        import math
        closes = [float(c[4]) for c in data]  # candle close prices
        log_returns = [
            math.log(closes[i] / closes[i - 1]) for i in range(1, len(closes))
        ]

        mean = sum(log_returns) / len(log_returns)
        variance = sum((r - mean) ** 2 for r in log_returns) / (len(log_returns) - 1)
        daily_vol = math.sqrt(variance)
        annual_vol = daily_vol * math.sqrt(365)
        logger.debug("BTC annualized vol: %.1f%%", annual_vol * 100)
        return annual_vol
    except Exception as e:
        logger.warning("Volatility calc failed: %s, using default", e)
        return _DEFAULT_VOL


_DEFAULT_VOL = 0.60  # 60% annualized — reasonable BTC default
