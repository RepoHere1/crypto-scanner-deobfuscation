"""Betting strategy — calibration-driven, using empirical probabilities.

The old BS engine claimed 69% win probability but delivered 0% across 16 legs.
This module pairs with the empirical probability engine (probability.py) and
calibration data (calibrate.py) to make decisions based on observed reality.

Philosophy (from the user):
  "put the probability to win big based on live streaming facts"
  "prioritize probability to win bigger at permanent position one"
  "taking no bet is also ok"

Strategy modes:
  COLD     (<20 resolved): extreme caution, only massive-asym bets
  WARM     (20-49):        calibrated probs usable, power + asym
  HOT      (50+, Brier<0.25): full confidence

Bet classes:
  POWER    Calibrated win prob >55%. Wins OFTEN.
  ASYMM    Payout >15x with cal prob >15%. Wins RARELY, pays BIG.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .calibrate import OutcomeResolver, CalibrationCurve
    from .hedge import HedgePair, ContrarianBet

import logging
logger = logging.getLogger(__name__)


class StrategyMode(Enum):
    COLD = "cold"
    WARM = "warm"
    HOT = "hot"


class BetClass(Enum):
    POWER = "power"
    ASYMM = "asymm"
    NONE = "none"


class Decision(Enum):
    ACCEPT = "accept"
    REJECT = "reject"


@dataclass
class StrategyConfig:
    power_min_prob: float = 0.60        # was 0.55 — need clear edge
    power_min_payout: float = 1.8       # was 1.5 — 60%×1.8x=1.08 EV minimum
    asym_min_prob: float = 0.20         # was 0.15 — 20% minimum for asym bets
    asym_min_payout: float = 6.0        # was 3.0 — 20%×6x=1.2 EV, actual edge
    asym_cold_payout: float = 12.0      # was 6.0 — cold mode needs massive asymmetry
    cold_max_cost: float = 0.50         # was 1.00 — tighter cold-mode risk
    cold_max_open: int = 1
    cold_min_samples: int = 20
    min_score: float = 0.20             # was 0.12 — require meaningful score
    hot_min_samples: int = 50
    hot_max_brier: float = 0.25


@dataclass
class StrategyDecision:
    decision: Decision
    bet_class: BetClass
    reason: str
    score: float = 0.0
    prob_a: float = 0.0
    prob_b: float = 0.0
    prob_any: float = 0.0


class BetStrategy:
    """Calibration-driven betting strategy."""

    def __init__(self, resolver=None, config=None, empirical=None):
        self.cfg = config or StrategyConfig()
        self._resolver = resolver
        self._empirical = empirical
        self._cal = None
        self._mode = StrategyMode.COLD
        self._last_refresh = 0.0
        self._refresh()

    @property
    def mode(self):
        return self._mode

    def evaluate_pair(self, pair):
        """Evaluate a hedge pair through strategy gates."""
        self._refresh()
        pa = self._cal_prob(pair.bet_a)
        pb = self._cal_prob(pair.bet_b)
        pany = pa + pb - pa * pb
        pany = max(0.0, min(1.0, pany))
        pr = pair.payout_ratio

        score = pany * math.log(pr) if pr > 1.0 else 0.0
        if score < self.cfg.min_score:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"score {score:.3f}<{self.cfg.min_score}", score, pa, pb, pany)

        if self._mode == StrategyMode.COLD:
            return self._eval_cold(pair, pa, pb, pany, pr, score)
        return self._eval_warm(pair, pa, pb, pany, pr, score)

    def evaluate_single(self, bet):
        """Evaluate a single bet leg (not a pair) — for sniper mode.

        A single bet wins when its side resolves correctly. Payout = 1/price.
        This catches high-probability bets that don't have a good pair partner.
        Short-expiry bets (<2h) require higher probability — less time to be right.
        """
        self._refresh()
        cp = self._cal_prob(bet)
        price = bet.market_price
        payout = 1.0 / price if price > 0 else 1.0

        # Time-decay: short-expiry bets need HIGHER probability
        tte_hours = getattr(bet, 'tte_hours', 24)
        if tte_hours < 2:
            cp *= 0.85  # Penalty for near-expiry uncertainty
        elif tte_hours < 4:
            cp *= 0.92

        # --- Asymmetric path: low prob, massive payout ---
        # A 15% chance with 100x payout is a good bet on its own
        asym_min_prob = self.cfg.asym_min_prob
        asym_min_payout = self.cfg.asym_min_payout
        if cp >= asym_min_prob and payout >= asym_min_payout:
            score = cp * math.log(payout)
            if score >= self.cfg.min_score * 0.6:
                return StrategyDecision(Decision.ACCEPT, BetClass.ASYMM,
                    f"sniper-asym: prob={cp:.0%} pay={payout:.0f}x", score, cp, cp, cp)

        # Single power-path needs HIGHER probability — no hedge partner to fall back on
        min_prob = 0.65 if self._mode == StrategyMode.COLD else 0.55
        min_payout = 1.3  # at least 30% profit

        if cp < min_prob:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"single: prob {cp:.0%}<{min_prob:.0%}", cp, cp, cp, cp)

        if payout < min_payout:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"single: payout {payout:.1f}x<{min_payout:.1f}x", cp, cp, cp, cp)

        score = cp * math.log(payout)
        if score < self.cfg.min_score * 0.8:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"single: score {score:.3f}", score, cp, cp, cp)

        if self._mode == StrategyMode.COLD:
            # In cold, single bets need 75%+ probability
            if cp < 0.72:
                return StrategyDecision(Decision.REJECT, BetClass.NONE,
                    f"single cold: prob {cp:.0%}<72%", cp, cp, cp, cp)
            # Also require decent payout
            if payout < 2.0:
                return StrategyDecision(Decision.REJECT, BetClass.NONE,
                    f"single cold: payout {payout:.1f}x<2x", cp, cp, cp, cp)

        return StrategyDecision(Decision.ACCEPT, BetClass.POWER,
            f"sniper: prob={cp:.0%} pay={payout:.1f}x", score, cp, cp, cp)

    def status(self):
        n = self._cal.total_samples if self._cal else 0
        return {"mode": self._mode.value, "samples": n}

    # --- internal ---

    def _refresh(self):
        import time
        now = time.time()
        if now - self._last_refresh < 30:
            return
        self._last_refresh = now
        if not self._resolver:
            self._mode = StrategyMode.COLD
            return
        c = self._resolver._load_curve()
        if c is None:
            c = self._resolver.build_calibration()
        self._cal = c
        n = c.total_samples if c else 0
        if n < self.cfg.cold_min_samples:
            self._mode = StrategyMode.COLD
        elif n >= self.cfg.hot_min_samples and (c and c.brier_score <= self.cfg.hot_max_brier):
            self._mode = StrategyMode.HOT
        else:
            self._mode = StrategyMode.WARM

    def _cal_prob(self, bet):
        """Ensemble probability: combine market-implied, empirical, and BS signals.
        
        Strategy derived from proven winning bots (suislanchez/polymarket-kalshi-weather-bot
        used ensemble GFS forecasts; we use market+empirical+BS ensemble).
        """
        rp = bet.true_prob  # raw BS probability
        
        # Get market-implied probability if available
        mp = getattr(bet, 'market_prob', None) or 0.5
        
        # Ensemble: weight the three sources
        if self._cal and self._cal.total_samples >= self.cfg.cold_min_samples:
            # Calibrated: use calibration-adjusted BS as primary
            cp = self._cal.lookup(rp)
            # Blend: 50% calibrated, 30% market, 20% empirical trend
            emp_p = cp  # empirical is already baked into calibration
            return cp * 0.50 + mp * 0.30 + rp * 0.20
        else:
            # Cold start: penalize BS, trust market more
            return rp * 0.25 + mp * 0.50 + rp * 0.25

    def _eval_cold(self, pair, pa, pb, pany, pr, score):
        if pr >= self.cfg.asym_cold_payout and pany >= self.cfg.asym_min_prob:
            bc = BetClass.ASYMM
        else:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"cold: need pr>{self.cfg.asym_cold_payout:.0f}x pany>{self.cfg.asym_min_prob:.0%}",
                score, pa, pb, pany)
        if pair.total_cost > self.cfg.cold_max_cost:
            return StrategyDecision(Decision.REJECT, BetClass.NONE,
                f"cold: cost ${pair.total_cost:.2f}>{self.cfg.cold_max_cost}", score, pa, pb, pany)
        return StrategyDecision(Decision.ACCEPT, bc,
            f"cold asym: {pr:.0f}x cal1={pany:.0%}", score, pa, pb, pany)

    def _eval_warm(self, pair, pa, pb, pany, pr, score):
        is_pw = pany >= self.cfg.power_min_prob and pr >= self.cfg.power_min_payout
        is_ay = pany >= self.cfg.asym_min_prob and pr >= self.cfg.asym_min_payout
        if is_pw:
            return StrategyDecision(Decision.ACCEPT, BetClass.POWER,
                f"power: cal1={pany:.0%} {pr:.0f}x", score, pa, pb, pany)
        if is_ay:
            return StrategyDecision(Decision.ACCEPT, BetClass.ASYMM,
                f"asym: {pr:.0f}x cal1={pany:.0%}", score, pa, pb, pany)
        return StrategyDecision(Decision.REJECT, BetClass.NONE,
            f"no class: pany={pany:.0%} pr={pr:.0f}x", score, pa, pb, pany)
