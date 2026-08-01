"""Empirical probability engine — live streaming facts, not Black-Scholes.

The old BS model claimed 69% probability but delivered 0%. Why? Because
BTC doesn't follow a lognormal distribution with constant volatility.
This engine uses ACTUAL observed price behavior to compute win probabilities.

Core method: empirical_win_probability(spot, strike, tte_hours, returns, vol)
  1. Fetch last 30 daily returns from Binance klines (live streaming facts)
  2. Scale returns to the time-to-expiry period
  3. Compute: what fraction of historical scaled moves were larger than needed?
  4. Blend with normal CDF for tail stability (where we have few samples)
  5. Adjust for trend: if BTC has been rising, P(up) increases

Multi-asset: works for any asset with Binance klines — BTC, ETH, SOL, etc.

Usage:
    ep = EmpiricalProbability()
    prob = ep.probability("BTC", spot=63000, strike=63200, tte_hours=4.5)
    # Returns P(BTC > 63200 in 4.5 hours) based on observed BTC behavior
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

# Binance symbol mapping for Kalshi assets
ASSET_SYMBOLS = {
    "BTC": "BTCUSDT",
    "ETH": "ETHUSDT",
    "SOL": "SOLUSDT",
    "XRP": "XRPUSDT",
    "DOGE": "DOGEUSDT",
    "ADA": "ADAUSDT",
}

KLINES_URL = "https://api.binance.com/api/v3/klines"


@dataclass
class AssetData:
    """Cached empirical data for one asset."""
    returns: list[float] = field(default_factory=list)
    spot: float = 0.0
    volatility: float = 0.60
    trend: float = 0.0        # average recent daily return
    fetched_at: float = 0.0


class EmpiricalProbability:
    """Compute win probabilities from observed price behavior.

    Caches Binance data per asset for 5 minutes to avoid rate limiting.
    """

    def __init__(self, cache_seconds: int = 300):
        self._cache: dict[str, AssetData] = {}
        self._cache_seconds = cache_seconds

    # --- Public API ---

    def probability(
        self,
        asset: str,
        spot: float,
        strike: float,
        tte_hours: float,
    ) -> float:
        """Empirical probability that spot > strike at expiry.

        Args:
            asset: "BTC", "ETH", "SOL", etc.
            spot: current price
            strike: target price
            tte_hours: time to expiry in hours

        Returns:
            P(spot > strike at expiry) based on observed returns
        """
        data = self._get_data(asset, spot)

        if not data.returns or tte_hours <= 0:
            return 0.5

        # Compute period volatility
        period_vol = data.volatility * math.sqrt(tte_hours / (365.25 * 24))
        if period_vol < 1e-10:
            return 1.0 if spot > strike else 0.0

        # Target: what return moves us from spot to strike?
        target_return = math.log(strike / spot)

        # --- Empirical probability ---
        # Scale daily returns to period scale
        scale = math.sqrt(tte_hours / 24.0)
        scaled = [r * scale for r in data.returns]

        # What fraction of scaled returns exceeded the target?
        count_above = sum(1 for r in scaled if r > target_return)
        empirical_p = count_above / len(scaled)

        # --- Normal CDF for comparison ---
        z_score = (target_return + 0.5 * period_vol * period_vol) / period_vol
        normal_p = _norm_sf(z_score)  # survival function: 1 - CDF

        # --- Blend ---
        # Weight: trust empirical more when we have many samples
        n = len(data.returns)
        weight = min(0.85, n / 60.0)  # max 85% empirical weight
        prob = weight * empirical_p + (1.0 - weight) * normal_p

        # --- Trend adjustment ---
        # If BTC has been trending up, boost P(up) slightly
        if abs(data.trend) > 0.002:  # meaningful trend (>0.2% daily)
            trend_signal = 1.0 if data.trend > 0 else -1.0
            if (strike > spot and trend_signal > 0) or (strike < spot and trend_signal < 0):
                prob += 0.02  # small boost for trend-aligned bets
            else:
                prob -= 0.02  # small penalty for counter-trend bets

        return max(0.01, min(0.99, prob))

    def get_volatility(self, asset: str, spot: float = 0) -> float:
        """Get current annualized volatility for an asset."""
        return self._get_data(asset, spot).volatility

    def get_trend(self, asset: str, spot: float = 0) -> float:
        """Get average recent daily return (trend signal)."""
        return self._get_data(asset, spot).trend

    def get_returns(self, asset: str) -> list[float]:
        """Get the list of recent daily log returns."""
        return list(self._get_data(asset, 0).returns)

    # --- Internal ---

    def _get_data(self, asset: str, spot: float) -> AssetData:
        """Get cached or fresh asset data."""
        symbol = ASSET_SYMBOLS.get(asset, f"{asset}USDT")
        now = time.time()

        cached = self._cache.get(asset)
        if cached and (now - cached.fetched_at) < self._cache_seconds:
            if spot > 0:
                cached.spot = spot
            return cached

        data = self._fetch_data(symbol, spot)
        self._cache[asset] = data
        return data

    def _fetch_data(self, symbol: str, spot: float) -> AssetData:
        """Fetch daily klines and compute returns/volatility/trend."""
        try:
            url = f"{KLINES_URL}?symbol={symbol}&interval=1d&limit=35"
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=10) as resp:
                raw = json.loads(resp.read().decode())

            if not raw or len(raw) < 3:
                return AssetData(fetched_at=time.time())

            closes = [float(c[4]) for c in raw]
            returns = [
                math.log(closes[i] / closes[i - 1])
                for i in range(1, len(closes))
            ]

            # Volatility from last 30 returns
            r = returns[-30:] if len(returns) > 30 else returns
            mean_r = sum(r) / len(r)
            variance = sum((x - mean_r) ** 2 for x in r) / max(1, len(r) - 1)
            daily_vol = math.sqrt(max(0, variance))
            annual_vol = daily_vol * math.sqrt(365)

            # Trend: average of last 7 returns
            recent = returns[-7:] if len(returns) >= 7 else returns
            trend = sum(recent) / len(recent)

            return AssetData(
                returns=returns[-30:] if len(returns) >= 30 else returns,
                spot=spot or closes[-1],
                volatility=annual_vol,
                trend=trend,
                fetched_at=time.time(),
            )

        except (URLError, OSError, KeyError, ValueError, IndexError) as e:
            logger.debug("Empirical fetch failed for %s: %s", symbol, e)
            return AssetData(fetched_at=time.time())


# ---------------------------------------------------------------------------
# Normal distribution survival function (no scipy dependency)
# ---------------------------------------------------------------------------


def _norm_sf(x: float) -> float:
    """Standard normal survival function: 1 - CDF(x)."""
    if x < -8:
        return 1.0
    if x > 8:
        return 0.0

    b0, b1, b2, b3, b4, b5 = (
        0.2316419, 0.319381530, -0.356563782,
        1.781477937, -1.821255978, 1.330274429,
    )
    t = 1.0 / (1.0 + b0 * abs(x))
    pdf = math.exp(-0.5 * x * x) / math.sqrt(2.0 * math.pi)
    cdf = 1.0 - pdf * (b1 * t + b2 * t**2 + b3 * t**3 + b4 * t**4 + b5 * t**5)
    if x >= 0:
        return 1.0 - cdf
    return cdf


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_emp_prob: EmpiricalProbability | None = None


def get_empirical() -> EmpiricalProbability:
    global _emp_prob
    if _emp_prob is None:
        _emp_prob = EmpiricalProbability()
    return _emp_prob
