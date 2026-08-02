"""BTC microstructure signals — RSI, momentum, VWAP, SMA crossover.

Based on suislanchez/polymarket-kalshi-weather-bot's proven approach.
Uses CoinGecko OHLC data (already fetched by probability.py) to compute
short-term technical indicators that improve probability estimates for
sub-24h binary options.

Strategy from the bot:
  1. Fetch candle data (CoinGecko provides 4h OHLC)
  2. Compute 5 indicators: RSI(14), Momentum(3/6/12 candles),
     VWAP deviation, SMA crossover, trend direction
  3. Convergence filter: require 2+ of 4 indicators to agree
  4. Weighted composite → directional probability signal
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


@dataclass
class MicroSignals:
    """Computed microstructure signals for one asset."""
    rsi: float = 50.0              # RSI(14): 0-100
    momentum_short: float = 0.0    # 3-period momentum (%)
    momentum_mid: float = 0.0      # 6-period momentum (%)
    momentum_long: float = 0.0     # 12-period momentum (%)
    vwap_deviation: float = 0.0    # % deviation from VWAP
    sma_short: float = 0.0         # 5-period SMA
    sma_long: float = 0.0          # 20-period SMA
    trend: float = 0.0             # Average recent return
    convergence: int = 0           # How many indicators agree on direction
    direction: str = "neutral"     # "bullish", "bearish", or "neutral"
    directional_prob: float = 0.5  # P(price up) from microstructure (0-1)


def compute_rsi(closes: list[float], period: int = 14) -> float:
    """Compute RSI from close prices."""
    if len(closes) < period + 1:
        return 50.0
    gains = 0.0
    losses = 0.0
    for i in range(-period, 0):
        change = closes[i] - closes[i - 1]
        if change > 0:
            gains += change
        else:
            losses -= change
    avg_gain = gains / period
    avg_loss = losses / period
    if avg_loss == 0:
        return 100.0
    rs = avg_gain / avg_loss
    return 100.0 - (100.0 / (1.0 + rs))


def compute_momentum(closes: list[float], lookback: int) -> float:
    """Momentum as % change over lookback periods."""
    if len(closes) < lookback + 1:
        return 0.0
    return (closes[-1] / closes[-lookback - 1] - 1.0) * 100.0


def compute_vwap(highs: list[float], lows: list[float], closes: list[float],
                 volumes: list[float] | None = None) -> tuple[float, float]:
    """Compute VWAP and current price deviation from it.
    If no volume data, uses typical price average."""
    n = min(len(highs), len(lows), len(closes))
    if n < 2:
        return closes[-1] if closes else 0.0, 0.0

    if volumes and len(volumes) >= n:
        tp_sum = 0.0
        vol_sum = 0.0
        for i in range(n):
            tp = (highs[i] + lows[i] + closes[i]) / 3.0
            tp_sum += tp * volumes[i]
            vol_sum += volumes[i]
        vwap = tp_sum / vol_sum if vol_sum > 0 else closes[-1]
    else:
        vwap = sum((h + l + c) / 3.0 for h, l, c in zip(highs, lows, closes)) / n

    deviation = (closes[-1] / vwap - 1.0) * 100.0
    return vwap, deviation


def compute_sma(closes: list[float], period: int) -> float:
    """Simple moving average."""
    if len(closes) < period:
        return closes[-1] if closes else 0.0
    return sum(closes[-period:]) / period


def analyze_microstructure(
    closes: list[float],
    highs: list[float] | None = None,
    lows: list[float] | None = None,
    trend: float = 0.0,
) -> MicroSignals:
    """Compute full microstructure signal suite.

    Args:
        closes: List of close prices (most recent last)
        highs: Optional list of high prices
        lows: Optional list of low prices
        trend: Average daily return (from probability engine)

    Returns:
        MicroSignals with all indicators and directional probability
    """
    if len(closes) < 20:
        return MicroSignals()

    hs = highs or closes
    ls = lows or closes

    # RSI
    rsi = compute_rsi(closes, 14)

    # Momentum (short=3, mid=6, long=12 candles)
    mom_short = compute_momentum(closes, 3)
    mom_mid = compute_momentum(closes, 6)
    mom_long = compute_momentum(closes, 12)

    # VWAP
    _, vwap_dev = compute_vwap(hs, ls, closes)

    # SMA
    sma_short = compute_sma(closes, 5)
    sma_long = compute_sma(closes, 20)

    # Convergence: count how many indicators point bullish
    bullish_signals = 0
    total_signals = 4  # RSI, momentum_mid, VWAP, SMA crossover

    # RSI > 50 = bullish
    if rsi > 50:
        bullish_signals += 1

    # Positive mid-momentum = bullish
    if mom_mid > 0:
        bullish_signals += 1

    # Price above VWAP = bullish
    if vwap_dev > 0:
        bullish_signals += 1

    # SMA crossover: short > long = bullish
    if sma_short > sma_long:
        bullish_signals += 1

    # Direction
    if bullish_signals >= 3:
        direction = "bullish"
    elif bullish_signals <= 1:
        direction = "bearish"
    else:
        direction = "neutral"

    # Directional probability from microstructure
    # Weighted: convergence gives 0.35-0.65 range, trend adjusts
    directional_prob = 0.35 + (bullish_signals / total_signals) * 0.30
    if abs(trend) > 0.001:
        trend_signal = 0.03 if trend > 0 else -0.03
        directional_prob += trend_signal
    directional_prob = max(0.10, min(0.90, directional_prob))

    return MicroSignals(
        rsi=round(rsi, 1),
        momentum_short=round(mom_short, 2),
        momentum_mid=round(mom_mid, 2),
        momentum_long=round(mom_long, 2),
        vwap_deviation=round(vwap_dev, 2),
        sma_short=round(sma_short, 2),
        sma_long=round(sma_long, 2),
        trend=trend,
        convergence=bullish_signals,
        direction=direction,
        directional_prob=round(directional_prob, 4),
    )
