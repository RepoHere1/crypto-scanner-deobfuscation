"""Multi-asset crypto price feed.

Uses CoinGecko as primary (supports all assets with one API)
and Binance as fast-fallback for major pairs.
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
class CryptoPrice:
    """Current price snapshot for any crypto asset."""

    asset: str
    price_usd: float
    source: str
    timestamp: datetime

    def __repr__(self) -> str:
        return f"{self.asset} ${self.price_usd:,.2f} via {self.source}"


class CryptoFeed:
    """Multi-asset price feed with caching."""

    BINANCE_URL = "https://api.binance.com/api/v3/ticker/price"
    COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"

    def __init__(self, cache_seconds: float = 30):
        self._cache: dict[str, CryptoPrice] = {}
        self._cache_time: float = 0.0
        self._cache_seconds = cache_seconds

    def get(self, asset: str, coingecko_id: str, binance_symbol: str,
            force_fresh: bool = False) -> CryptoPrice:
        """Get current price for an asset.

        Tries Binance first (fast), falls back to CoinGecko (broad).
        Results cached per-asset for cache_seconds unless force_fresh=True.
        """
        now = time.time()
        if not force_fresh:
            cached = self._cache.get(asset)
            if cached and (now - self._cache_time) < self._cache_seconds:
                return cached

        price = self._fetch_binance(binance_symbol) or self._fetch_coingecko(coingecko_id)
        if price is None:
            if cached:
                logger.warning("All sources failed for %s, using stale cache", asset)
                return cached
            raise RuntimeError(f"Unable to fetch {asset} price from any source")

        result = CryptoPrice(
            asset=asset,
            price_usd=price,
            source=price > 0 and "binance" or "coingecko",
            timestamp=datetime.now(timezone.utc),
        )
        self._cache[asset] = result
        self._cache_time = now
        return result

    def _fetch_binance(self, symbol: str) -> float | None:
        """Fetch price from Binance public ticker."""
        try:
            url = f"{self.BINANCE_URL}?symbol={symbol}"
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                return float(data["price"])
        except (URLError, OSError, KeyError, ValueError) as e:
            logger.debug("Binance %s failed: %s", symbol, e)
            return None

    def _fetch_coingecko(self, coin_id: str) -> float | None:
        """Fetch USD price from CoinGecko."""
        try:
            url = f"{self.COINGECKO_URL}?ids={coin_id}&vs_currencies=usd"
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode())
                return float(data[coin_id]["usd"])
        except (URLError, OSError, KeyError, ValueError) as e:
            logger.debug("CoinGecko %s failed: %s", coin_id, e)
            return None


# Singleton instance
_feed: CryptoFeed | None = None


def get_feed() -> CryptoFeed:
    """Get or create the global CryptoFeed instance."""
    global _feed
    if _feed is None:
        _feed = CryptoFeed()
    return _feed
