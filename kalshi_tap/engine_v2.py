"""Calibrated engine v2 — the predictive logic upgrade.

Root-cause diagnosis (from live DB evidence, 2026-07-31):
-----------------------------------------------------------------
54 "high confidence" recommendations across 3 runs. Raw BS model
says 83% chance BTC drops from $62,936 to below $61,250 in ~13h.
That's absurd for any reasonable volatility estimate. The model
systematically overestimates tail probabilities, buys cheap
lottery-ticket bets, and calls it "value."

What this engine does differently:
-----------------------------------------------------------------
1. RAW BS PROB — same Black-Scholes N(d2) as base (directional
   information is still useful)
2. CALIBRATION — adjust raw prob toward observed reality using
   actual Kalshi settlement outcomes (via calibrate.py)
3. MARKET WISDOM — near expiry, increasingly trust the market
   consensus. A 3c option at T-2h is probably worth 3c.
4. SPREAD COST — use execution price (ask), not mid, for EV calc.
   The bid/ask spread is real friction.
5. NEAR-EXPIRY DAMPING — at T<1h, the BS model breaks down entirely.
   Damp the model signal and trust the market.
6. VOLATILITY REGIME — higher recent vol = wider model uncertainty.
   Don't bet big when the market is jittery.

Result: calibrated_prob replaces true_prob. EV now accounts for
execution cost. Kelly sizing uses calibrated probabilities. The
engine no longer treats every 2c lottery ticket as "high confidence."
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .calibrate import OutcomeResolver, CalibrationCurve
    from .risk import RiskManager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class CalibratedConfig:
    """Tunable parameters for the calibrated engine."""

    # Thresholds
    min_ev_threshold: float = 0.01        # Minimum expected value (1c per $1)
    max_bet_dollars: float = 50.0          # Max bet per market
    min_bet_dollars: float = 1.0           # Minimum bet
    max_contracts: int = 50

    # Kelly
    kelly_fraction: float = 0.10           # Very conservative: 10% of full Kelly

    # Calibration
    calibration_weight: float = 0.70       # How much to trust calibration vs raw model
    min_calibration_samples: int = 20      # Need this many samples before calibrating

    # Market wisdom (near-expiry adjustment)
    market_wisdom_tte_hours: float = 4.0    # Start blending at T-4h
    market_wisdom_full_hours: float = 0.5   # Full market trust at T-30min
    market_wisdom_min_weight: float = 0.30  # Minimum model weight at near-expiry

    # Spread cost
    max_spread_pct: float = 0.05            # Max acceptable bid/ask spread (5c)

    # Volatility regime
    high_vol_threshold: float = 0.80        # Annualized vol threshold for "high" regime
    high_vol_kelly_mult: float = 0.5        # Halve Kelly fraction in high vol

    # Near-expiry safety
    min_tte_minutes: float = 5.0            # Ignore markets expiring in <5 min


# ---------------------------------------------------------------------------
# Calibrated engine
# ---------------------------------------------------------------------------


class CalibratedEngine:
    """Engine with calibration, market wisdom, and real friction costs.

    Usage:
        engine = CalibratedEngine(config, resolver, risk_manager)
        recs = engine.analyze(markets_raw, btc_price, volatility)
        # recs now have calibrated probabilities and honest EV estimates
    """

    def __init__(
        self,
        config: CalibratedConfig | None = None,
        resolver: "OutcomeResolver | None" = None,
        risk_manager: "RiskManager | None" = None,
    ):
        self.cfg = config or CalibratedConfig()
        self._resolver = resolver
        self._risk = risk_manager

    # --- Public API ---

    def analyze(
        self,
        markets_raw: list[dict],
        btc_price: float,
        volatility: float | None = None,
    ) -> list[dict]:
        """Analyze markets and return calibrated recommendations.

        Args:
            markets_raw: Raw market dicts from Kalshi API
            btc_price: Current spot price
            volatility: Annualized volatility (auto-calculated if None)

        Returns:
            List of recommendation dicts sorted by calibrated_ev descending
        """
        from .engine import AnalysisEngine, EngineConfig

        # Raw engine for base BS probabilities and market parsing
        raw_config = EngineConfig(
            min_ev_threshold=-99.0,  # accept everything — we filter later
            max_bet_per_market_dollars=self.cfg.max_bet_dollars,
            kelly_fraction=1.0,      # we do our own Kelly
        )
        raw_engine = AnalysisEngine(raw_config)

        # Get volatility
        if volatility is None:
            from .btc_feed import get_btc_volatility
            volatility = get_btc_volatility()

        # Classify volatility regime
        is_high_vol = volatility >= self.cfg.high_vol_threshold
        if is_high_vol:
            logger.info("HIGH VOL regime: %.0f%% annualized", volatility * 100)

        # Parse markets via raw engine's internal parser
        parsed = [raw_engine._parse_market(m) for m in markets_raw]
        valid = [m for m in parsed if m is not None]

        if not valid:
            logger.warning("No valid markets to analyze")
            return []

        # Resolve calibration (lazy, from disk if available)
        calibration = self._get_calibration()

        recommendations: list[dict] = []
        for market in valid:
            rec = self._evaluate_calibrated(
                raw_engine, market, btc_price, volatility,
                calibration, is_high_vol,
            )
            if rec is not None:
                recommendations.append(rec)

        # Sort by calibrated EV descending
        recommendations.sort(key=lambda r: r["calibrated_ev"], reverse=True)
        return recommendations

    # --- Core calibrated evaluation ---

    def _evaluate_calibrated(
        self,
        raw_engine,
        market,
        spot: float,
        vol: float,
        calibration,
        is_high_vol: bool,
    ) -> dict | None:
        """Evaluate one market through the full calibration pipeline."""
        now = datetime.now(timezone.utc)
        tte_seconds = (market.close_time - now).total_seconds()
        tte_hours = tte_seconds / 3600.0

        # Skip near-expiry noise
        if tte_hours * 60 < self.cfg.min_tte_minutes:
            return None
        if tte_seconds <= 0:
            return None

        tte_years = max(tte_seconds / (365.25 * 86400), 1 / (365.25 * 24))

        # --- Step 1: Raw BS probability ---
        raw_prob_yes = raw_engine._binary_call_probability(
            spot, market.strike, tte_years, vol
        )

        # --- Step 2: Market-implied probability from mid ---
        mid_price = raw_engine._mid_price(market)
        if mid_price <= 0.005 or mid_price >= 0.995:
            return None  # No edge at extremes

        # --- Step 3: Calibrate ---
        cal_prob_yes = self._apply_calibration(raw_prob_yes, calibration)

        # --- Step 4: Market wisdom blend ---
        blended_prob = self._apply_market_wisdom(
            cal_prob_yes, mid_price, tte_hours
        )

        # --- Step 5: Execution cost ---
        side, exec_price, spread = self._determine_execution(
            blended_prob, mid_price, market
        )

        if spread > self.cfg.max_spread_pct:
            return None  # Spread too wide — no real edge

        # --- Step 6: Calibrated EV ---
        if side == "yes":
            cal_ev = blended_prob - exec_price
            cal_prob = blended_prob
        else:
            cal_ev = (1.0 - blended_prob) - exec_price
            cal_prob = 1.0 - blended_prob

        if cal_ev < self.cfg.min_ev_threshold:
            return None

        # --- Step 7: Kelly sizing (calibrated) ---
        kelly = self._calibrated_kelly(cal_prob, exec_price)
        kelly_frac = kelly * self.cfg.kelly_fraction

        # High-vol regime: halve Kelly
        if is_high_vol:
            kelly_frac *= self.cfg.high_vol_kelly_mult

        # Dynamic sizing from risk manager
        bet_dollars = self.cfg.max_bet_dollars * kelly_frac
        if self._risk:
            can_trade, _, risk_bet = self._risk.check()
            if not can_trade:
                return None  # Risk manager says no
            if risk_bet > 0:
                bet_dollars = min(bet_dollars, risk_bet * 50)

        contracts = int(bet_dollars / exec_price) if exec_price > 0 else 0
        contracts = min(contracts, self.cfg.max_contracts)
        bet_total = contracts * exec_price

        if contracts < 1 or bet_total < self.cfg.min_bet_dollars:
            return None

        # --- Confidence (now honest) ---
        confidence = self._assign_confidence(
            cal_ev, is_high_vol, calibration is not None
        )

        return {
            "ticker": market.ticker,
            "title": getattr(market, "title", ""),
            "strike": market.strike,
            "side": side,
            "price": round(exec_price, 4),
            "market_prob": round(mid_price, 4),
            "raw_prob": round(raw_prob_yes, 4),
            "calibrated_prob": round(cal_prob, 4),
            "calibrated_ev": round(cal_ev, 4),
            "kelly_fraction": round(kelly_frac, 4),
            "contracts": contracts,
            "bet_dollars": round(bet_total, 2),
            "confidence": confidence,
            "tte_hours": round(tte_hours, 1),
            "spread": round(spread, 4),
            "vol_regime": "high" if is_high_vol else "normal",
            "close_time": market.close_time.isoformat(),
        }

    # --- Adjustment methods ---

    def _apply_calibration(self, raw_prob: float, calibration) -> float:
        """Apply calibration curve to raw BS probability."""
        if calibration is None:
            return raw_prob
        if calibration.total_samples < self.cfg.min_calibration_samples:
            return raw_prob
        cal = calibration.lookup(raw_prob)
        w = self.cfg.calibration_weight
        return raw_prob + w * (cal - raw_prob)

    def _apply_market_wisdom(
        self, model_prob: float, market_prob: float, tte_hours: float
    ) -> float:
        """Blend model probability toward market consensus near expiry.

        Rationale: as expiry approaches, the market becomes more efficient.
        A 3c option with 5 minutes left is probably worth about 3c.
        """
        t_remaining = max(0.0, tte_hours)

        if t_remaining >= self.cfg.market_wisdom_tte_hours:
            return model_prob  # Far from expiry, trust the model

        if t_remaining <= self.cfg.market_wisdom_full_hours:
            # Maximum market wisdom
            market_weight = 1.0 - self.cfg.market_wisdom_min_weight
            return (
                self.cfg.market_wisdom_min_weight * model_prob +
                market_weight * market_prob
            )

        # Linear interpolation in the wisdom zone
        wisdom_range = (
            self.cfg.market_wisdom_tte_hours -
            self.cfg.market_wisdom_full_hours
        )
        progress = (
            1.0 -
            (t_remaining - self.cfg.market_wisdom_full_hours) / wisdom_range
        )
        market_weight = progress * (1.0 - self.cfg.market_wisdom_min_weight)
        return (1.0 - market_weight) * model_prob + market_weight * market_prob

    def _determine_execution(
        self, cal_prob: float, mid_price: float, market
    ) -> tuple:
        """Determine which side to bet and at what price.

        Returns (side, execution_price, spread).
        """
        yes_ask = getattr(market, "yes_ask", mid_price)
        no_ask = getattr(market, "no_ask", 1.0 - mid_price)

        ev_yes = cal_prob - yes_ask
        ev_no = (1.0 - cal_prob) - no_ask

        if ev_yes >= ev_no:
            spread = max(0.0, yes_ask - mid_price)
            return "yes", max(yes_ask, 0.01), spread
        else:
            spread = max(0.0, no_ask - (1.0 - mid_price))
            return "no", max(no_ask, 0.01), spread

    @staticmethod
    def _calibrated_kelly(true_prob: float, price: float) -> float:
        """Full Kelly fraction for a binary bet, clamped to [0, 1]."""
        if price >= 1.0 or price <= 0.0:
            return 0.0
        numerator = true_prob - price
        if numerator <= 0:
            return 0.0
        kelly = numerator / (1.0 - price)
        return max(0.0, min(1.0, kelly))

    def _assign_confidence(
        self, ev: float, is_high_vol: bool, is_calibrated: bool
    ) -> str:
        """Assign confidence level — now honest about uncertainty.

        When uncalibrated, we know the BS model overestimates edges,
        so we cap confidence at "medium" and require higher EV thresholds.
        """
        if not is_calibrated:
            # Without calibration, we're flying blind — max "medium"
            return (
                "high" if ev > 0.12 else
                "medium" if ev > 0.06 else
                "low"
            )

        if is_high_vol:
            # In high vol, everything is less certain
            return (
                "high" if ev > 0.10 else
                "medium" if ev > 0.05 else
                "low"
            )

        return (
            "high" if ev > 0.08 else
            "medium" if ev > 0.03 else
            "low"
        )

    def _get_calibration(self):
        """Get calibration curve, loading from disk if needed."""
        if self._resolver is not None:
            # Try loading from disk first (fast path)
            curve = self._resolver._load_curve()
            if curve is not None:
                return curve
            # Build fresh if we have data
            return self._resolver.build_calibration()
        return None


# ---------------------------------------------------------------------------
# Convenience: calibrated analysis from raw markets
# ---------------------------------------------------------------------------


def run_calibrated_analysis(
    markets_raw: list[dict],
    btc_price: float,
    *,
    volatility: float | None = None,
    resolver: "OutcomeResolver | None" = None,
    risk_manager: "RiskManager | None" = None,
    max_bet: float = 50.0,
) -> list[dict]:
    """One-shot calibrated analysis.

    Returns list of recommendation dicts with calibrated fields.
    """
    config = CalibratedConfig(max_bet_dollars=max_bet)
    engine = CalibratedEngine(config, resolver, risk_manager)
    return engine.analyze(markets_raw, btc_price, volatility)
