"""Hedge-pair scanner — find complementary contrarian bets for asymmetric returns.

Strategy: buy deeply mispriced binary options on DIFFERENT strikes/series
where at least one is likely to win, and the payout from one winner covers
both sides many times over.

Example:
  Bet A: NO  on $61,000 strike @ 3c  (pays $33 per $1 if BTC stays below)
  Bet B: YES on $65,000 strike @ 4c  (pays $25 per $1 if BTC moons)

Total cost $2. If either hits, $25–33 return. If both hit, $58 return.
The engine finds pairs where the joint-win probability justifies the risk.

Algorithm:
1. Contrarian scan — flag every YES/NO side priced <= 5c with true_prob >= 12%
2. Cross-join all flagged bets into candidate pairs (excluding same-market siblings)
3. Compute joint outcome distribution via lognormal model (same-series)
   or correlation-adjusted independence (cross-series)
4. Score each pair: hedge_score = P(at_least_one) × log(min_payout / total_cost)
   × direction_diversity_penalty
5. Rank and return top pairs
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import BTCMarket

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class HedgeConfig:
    """Tunable parameters for the hedge-pair scanner."""

    max_contrarian_price: float = 0.05    # Only consider bets priced <= 5c
    min_true_prob: float = 0.03           # True probability must be >= 3% (lowered for emp)
    min_ev: float = 0.005                 # Minimum edge per bet (0.5%)
    min_joint_win_prob: float = 0.15      # At least 15% chance one wins
    min_payout_ratio: float = 2.5         # min_payout / total_cost >= 2.5x (lowered for >1c bets)
    min_hedge_score: float = 0.02         # Score threshold for display
    max_pairs: int = 30                   # Maximum pairs to return
    bet_per_leg_dollars: float = 1.0      # Assume $1 per leg for scoring
    cross_series_correlation: float = 0.65  # Default crypto cross-correlation
    same_direction_penalty: float = 0.60  # Penalize pairs betting same direction
    max_tte_minutes: float = 0.0          # Only markets closing within N min (0=disabled)
    watch_alert_score: float = 0.90       # Score threshold for watch-mode alerts


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ContrarianBet:
    """A single deeply mispriced binary option."""

    ticker: str
    event_ticker: str
    title: str
    series_ticker: str
    strike: float
    side: str                     # "yes" or "no"
    market_price: float           # Price we'd pay (0.00–1.00)
    true_prob: float              # Engine-estimated true probability
    expected_value: float         # EV per $1 bet
    contracts_per_dollar: int     # How many contracts $1 buys
    payout_per_dollar: float      # Payout if $1 wins (contracts × $1)
    direction: str                # "bullish" (wins if price up) or "bearish"
    close_time: datetime
    tte_hours: float              # Time to expiry in hours
    market: "BTCMarket | None" = field(default=None, repr=False)

    @property
    def price_cents(self) -> int:
        return int(round(self.market_price * 100))


@dataclass
class HedgePair:
    """A scored pair of complementary contrarian bets."""

    bet_a: ContrarianBet
    bet_b: ContrarianBet
    total_cost: float                  # Cost for both legs
    min_payout: float                  # Payout if exactly one wins
    max_payout: float                  # Payout if both win
    joint_win_prob: float              # P(at least one wins)
    both_win_prob: float               # P(both win)
    neither_win_prob: float            # P(both lose)
    expected_return: float             # EV of the pair
    payout_ratio: float                # min_payout / total_cost
    hedge_score: float                 # Composite quality score
    pair_type: str                     # "same-series-opposite", "same-series-same", "cross-series"
    description: str                   # Human-readable hedge mechanics


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class HedgeScanner:
    """Find and score hedge-pair opportunities across Kalshi markets."""

    def __init__(self, config: HedgeConfig | None = None, empirical=None):
        self.config = config or HedgeConfig()
        self._empirical = empirical

    # --- Public API ---

    def scan(
        self,
        markets: list["BTCMarket"],
        spot: float,
        volatility: float,
        series_ticker: str = "",
        cross_markets: list[tuple[str, list["BTCMarket"], float, float]] | None = None,
    ) -> list[HedgePair]:
        """Scan markets and return ranked hedge pairs.

        Args:
            markets: List of parsed BTCMarket objects for the primary series
            spot: Current spot price of the underlying
            volatility: Annualized volatility
            series_ticker: Ticker of the primary series
            cross_markets: Optional list of (series_ticker, markets, spot, vol)
                           for cross-series hedging

        Returns:
            Ranked list of HedgePair, best first
        """
        # Phase 1: Find all contrarian bets in primary series
        primary_bets = self._scan_contrarian(markets, spot, volatility, series_ticker)

        # Cross-series bets
        all_bets = list(primary_bets)
        if cross_markets:
            for xs_ticker, xs_markets, xs_spot, xs_vol in cross_markets:
                xs_bets = self._scan_contrarian(xs_markets, xs_spot, xs_vol, xs_ticker)
                all_bets.extend(xs_bets)

        if len(all_bets) < 2:
            logger.info("Need at least 2 contrarian bets to form pairs (found %d)", len(all_bets))
            return []

        logger.info(
            "Contrarian scan: %d bets across all series (%d primary)",
            len(all_bets), len(primary_bets),
        )

        # Phase 2: Form and score all candidate pairs
        pairs: list[HedgePair] = []
        n = len(all_bets)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = all_bets[i], all_bets[j]
                pair = self._score_pair(a, b, spot, volatility)
                if pair is not None:
                    pairs.append(pair)

        # Phase 3: Rank and return top
        pairs.sort(key=lambda p: p.hedge_score, reverse=True)
        return pairs[: self.config.max_pairs]

    # --- Contrarian scanner ---

    def _scan_contrarian(
        self,
        markets: list["BTCMarket"],
        spot: float,
        volatility: float,
        series_ticker: str = "",
    ) -> list[ContrarianBet]:
        """Find all mispriced bets across all markets in a series.

        Uses empirical probabilities when available (from live Binance data),
        falling back to raw Black-Scholes. Scans ALL prices — the strategy
        module handles the quality filtering downstream.
        """
        bets: list[ContrarianBet] = []
        now = datetime.now(timezone.utc)
        cfg = self.config

        for m in markets:
            tte_sec = (m.close_time - now).total_seconds()
            tte_years = max(tte_sec / (365.25 * 86400), 1 / (365.25 * 24))
            tte_hours = tte_sec / 3600.0

            if cfg.max_tte_minutes > 0 and tte_sec > cfg.max_tte_minutes * 60:
                continue

            # YES side: scan ALL prices, let strategy filter downstream.
            # No arbitrary price cap — edges exist at every price level.
            yes_price = self._execution_price(m, "yes")
            if yes_price > 0 and yes_price <= 0.98:
                true_p_yes = self._binary_prob(spot, m.strike, tte_years, volatility, tte_hours)
                ev_yes = true_p_yes - yes_price
                if true_p_yes >= cfg.min_true_prob and ev_yes >= cfg.min_ev:
                    bets.append(self._make_bet(m, "yes", yes_price, true_p_yes, ev_yes,
                                               tte_hours, series_ticker))

            # NO side: scan ALL prices (same as YES — edges exist everywhere)
            no_price = self._execution_price(m, "no")
            if no_price > 0 and no_price <= 0.98:
                true_p_no = 1.0 - self._binary_prob(spot, m.strike, tte_years, volatility, tte_hours)
                ev_no = true_p_no - no_price
                if true_p_no >= cfg.min_true_prob and ev_no >= cfg.min_ev:
                    bets.append(self._make_bet(m, "no", no_price, true_p_no, ev_no,
                                               tte_hours, series_ticker))

        return bets

    @staticmethod
    def _make_bet(
        market: "BTCMarket",
        side: str,
        price: float,
        true_prob: float,
        ev: float,
        tte_hours: float,
        series_ticker: str,
    ) -> ContrarianBet:
        contracts = int(1.0 / price) if price > 0 else 0
        direction = "bullish" if side == "yes" else "bearish"
        return ContrarianBet(
            ticker=market.ticker,
            event_ticker=market.event_ticker,
            title=market.title,
            series_ticker=series_ticker,
            strike=market.strike,
            side=side,
            market_price=round(price, 4),
            true_prob=round(true_prob, 4),
            expected_value=round(ev, 4),
            contracts_per_dollar=contracts,
            payout_per_dollar=float(contracts),
            direction=direction,
            close_time=market.close_time,
            tte_hours=round(tte_hours, 1),
            market=market,
        )

    # --- Pair scoring ---

    def _score_pair(
        self,
        a: ContrarianBet,
        b: ContrarianBet,
        primary_spot: float,
        primary_vol: float,
    ) -> HedgePair | None:
        """Score a pair of contrarian bets. Returns None if below thresholds."""
        cfg = self.config

        # --- Basic cost/payout ---
        bet_dollars = cfg.bet_per_leg_dollars
        total_cost = bet_dollars * 2.0

        payout_a = a.payout_per_dollar * bet_dollars
        payout_b = b.payout_per_dollar * bet_dollars
        min_payout = min(payout_a, payout_b)
        max_payout = payout_a + payout_b

        payout_ratio = min_payout / total_cost if total_cost > 0 else 0
        if payout_ratio < cfg.min_payout_ratio:
            return None

        # --- Joint probabilities ---
        if a.series_ticker == b.series_ticker:
            # Same underlying — use lognormal bivariate model
            joint = self._joint_probs_same_series(a, b, primary_spot, primary_vol)
        else:
            # Cross-series — use correlation-adjusted independence
            joint = self._joint_probs_cross_series(a, b)

        if joint["at_least_one"] < cfg.min_joint_win_prob:
            return None

        # --- Direction diversity ---
        if a.direction == b.direction:
            direction_factor = cfg.same_direction_penalty
            pair_type = "same-series-same" if a.series_ticker == b.series_ticker else "cross-series-same"
        else:
            direction_factor = 1.0
            pair_type = "same-series-opposite" if a.series_ticker == b.series_ticker else "cross-series-opposite"

        # --- Hedge score ---
        # Core: high win prob + high payout magnification + directional diversity
        if payout_ratio <= 1.0:
            return None
        hedge_score = joint["at_least_one"] * math.log(payout_ratio) * direction_factor

        if hedge_score < cfg.min_hedge_score:
            return None

        # --- Expected return ---
        expected_return = (
            joint["at_least_one"] * min_payout
            + joint["both"] * (max_payout - min_payout)
            - total_cost
        )

        # --- Description ---
        desc = self._describe_pair(a, b)

        return HedgePair(
            bet_a=a,
            bet_b=b,
            total_cost=round(total_cost, 2),
            min_payout=round(min_payout, 2),
            max_payout=round(max_payout, 2),
            joint_win_prob=round(joint["at_least_one"], 4),
            both_win_prob=round(joint["both"], 4),
            neither_win_prob=round(joint["neither"], 4),
            expected_return=round(expected_return, 2),
            payout_ratio=round(payout_ratio, 1),
            hedge_score=round(hedge_score, 4),
            pair_type=pair_type,
            description=desc,
        )

    # --- Joint probability models ---

    @staticmethod
    def _joint_probs_same_series(
        a: ContrarianBet,
        b: ContrarianBet,
        spot: float,
        volatility: float,
    ) -> dict[str, float]:
        """Compute joint probabilities for two bets on the SAME underlying.

        Uses the lognormal price distribution. Each bet defines an interval
        on the price axis where it wins, and we compute the probability mass
        in the intersection of those intervals.
        """
        from .engine import _norm_cdf

        # Use the shorter TTE for both (conservative)
        tte_years_a = max(a.tte_hours / (365.25 * 24), 1 / (365.25 * 24))
        tte_years_b = max(b.tte_hours / (365.25 * 24), 1 / (365.25 * 24))
        tte = min(tte_years_a, tte_years_b)

        sigma_sqrt_t = volatility * math.sqrt(tte)
        if sigma_sqrt_t < 1e-10:
            # Degenerate: price is certain
            certain_above = spot > a.strike if a.side == "yes" else spot <= a.strike
            return {"at_least_one": 1.0 if (certain_above or (spot > b.strike if b.side == "yes" else spot <= b.strike)) else 0.0,
                    "both": 1.0 if certain_above and (spot > b.strike if b.side == "yes" else spot <= b.strike) else 0.0,
                    "neither": 0.0}

        def d2(strike: float) -> float:
            return math.log(spot / strike) / sigma_sqrt_t - 0.5 * sigma_sqrt_t

        def prob_above(strike: float) -> float:
            """P(spot > strike)"""
            return _norm_cdf(d2(strike))

        def prob_below(strike: float) -> float:
            """P(spot <= strike)"""
            return 1.0 - prob_above(strike)

        # Map each bet to its win interval
        # A wins when: (side=="yes" AND S > strike_a) OR (side=="no" AND S <= strike_a)

        def win_interval(side: str, strike: float) -> tuple[str, float]:
            return ("above", strike) if side == "yes" else ("below", strike)

        int_a = win_interval(a.side, a.strike)
        int_b = win_interval(b.side, b.strike)

        # Compute P(both win) — intersection of two intervals
        both = _intersection_prob(int_a, int_b, prob_above, prob_below)

        # P(at least one wins) = P(A) + P(B) - P(both)
        p_a = a.true_prob
        p_b = b.true_prob
        at_least_one = p_a + p_b - both
        at_least_one = max(0.0, min(1.0, at_least_one))

        neither = 1.0 - at_least_one

        return {
            "at_least_one": at_least_one,
            "both": both,
            "neither": neither,
        }

    @staticmethod
    def _joint_probs_cross_series(a: ContrarianBet, b: ContrarianBet) -> dict[str, float]:
        """Estimate joint probabilities for cross-series bets.

        Uses correlation-adjusted independence. For crypto assets,
        we assume high positive correlation (~0.65 default).
        With correlation ρ:
          P(both win) ≈ p_a·p_b + ρ·√(p_a·(1-p_a)·p_b·(1-p_b))
        """
        rho = HedgeConfig.cross_series_correlation
        p_a, p_b = a.true_prob, b.true_prob

        # Correlation adjustment
        cov_adjustment = rho * math.sqrt(p_a * (1 - p_a) * p_b * (1 - p_b))
        both = p_a * p_b + cov_adjustment
        both = max(0.0, min(min(p_a, p_b), both))

        at_least_one = p_a + p_b - both
        at_least_one = max(0.0, min(1.0, at_least_one))

        return {
            "at_least_one": at_least_one,
            "both": both,
            "neither": 1.0 - at_least_one,
        }

    @staticmethod
    def _describe_pair(a: ContrarianBet, b: ContrarianBet) -> str:
        """Build a human-readable description of the hedge mechanics."""
        parts = []

        if a.series_ticker == b.series_ticker:
            parts.append(f"Same series {a.series_ticker}")
        else:
            parts.append(f"Cross-series {a.series_ticker} × {b.series_ticker}")

        if a.direction != b.direction:
            parts.append("— opposite directions (structural hedge)")
        else:
            parts.append("— same direction (diversified strikes)")

        # Describe win conditions
        def win_cond(bet: ContrarianBet) -> str:
            op = ">" if bet.side == "yes" else "≤"
            return f"price {op} ${bet.strike:,.0f}"

        parts.append(f"Leg A ({a.direction}): {win_cond(a)}")
        parts.append(f"Leg B ({b.direction}): {win_cond(b)}")

        return " | ".join(parts)

    # --- Helpers ---

    @staticmethod
    def _execution_price(market: "BTCMarket", side: str) -> float:
        """Get the price we'd pay as a taker."""
        if side == "yes":
            return market.yes_ask if market.yes_ask > 0 else _mid(market.yes_bid, market.yes_ask)
        else:
            no_price = market.no_ask if market.no_ask > 0 else _mid(market.no_bid, market.no_ask)
            return no_price if no_price > 0 else 1.0 - _mid(market.yes_bid, market.yes_ask)

    def _binary_prob(self, spot: float, strike: float, tte: float, vol: float, tte_hours: float = 0) -> float:
        """P(spot > strike). Uses empirical probabilities when available,
        falling back to Black-Scholes N(d2)."""
        # Try empirical first (live streaming facts from Binance)
        if self._empirical is not None and tte_hours > 0:
            try:
                asset = "BTC"
                ep = self._empirical.probability(asset, spot, strike, tte_hours)
                # Sanity: if strike is far from spot with short TTE, prob should
                # not be near 0.5. If it is, empirical data is stale/broken.
                pct_away = abs(strike - spot) / spot if spot > 0 else 0
                if abs(ep - 0.5) < 0.01 and pct_away > 0.05 and tte_hours < 24:
                    raise ValueError(f"Empirical returned suspicious 0.5 for {pct_away:.0%} OTM")
                return ep
            except Exception:
                pass

        # Fallback: Black-Scholes
        from .engine import _norm_cdf
        if tte <= 0 or vol <= 0 or spot <= 0 or strike <= 0:
            return 0.5
        sigma_sqrt_t = vol * math.sqrt(tte)
        if sigma_sqrt_t < 1e-10:
            return 1.0 if spot > strike else 0.0
        d2 = math.log(spot / strike) / sigma_sqrt_t - 0.5 * sigma_sqrt_t
        return _norm_cdf(d2)


def _mid(bid: float, ask: float) -> float:
    """Mid-price with fallbacks."""
    if bid > 0 and ask < 1:
        return (bid + ask) / 2
    return bid or ask or 0.5


def _intersection_prob(
    int_a: tuple[str, float],
    int_b: tuple[str, float],
    prob_above,
    prob_below,
) -> float:
    """P(both intervals contain the price).

    Each interval is ("above", K) or ("below", K) meaning price > K or price <= K.
    """
    type_a, k_a = int_a
    type_b, k_b = int_b

    # Both "above": intersection is "above max(K_a, K_b)"
    if type_a == "above" and type_b == "above":
        return prob_above(max(k_a, k_b))

    # Both "below": intersection is "below min(K_a, K_b)"
    if type_a == "below" and type_b == "below":
        return prob_below(min(k_a, k_b))

    # One above, one below
    if type_a == "above" and type_b == "below":
        k_above, k_below = k_a, k_b
    else:
        k_above, k_below = k_b, k_a

    # Intersection: k_above < price <= k_below
    if k_above >= k_below:
        return 0.0  # No overlap

    return prob_below(k_below) - prob_below(k_above)


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------


def run_hedge_scan(
    markets: list["BTCMarket"],
    spot: float,
    volatility: float,
    series_ticker: str = "",
    config: HedgeConfig | None = None,
    cross_markets: list[tuple[str, list["BTCMarket"], float, float]] | None = None,
) -> list[HedgePair]:
    """One-shot hedge scan. Returns ranked pairs."""
    scanner = HedgeScanner(config)
    return scanner.scan(markets, spot, volatility, series_ticker, cross_markets)


def format_hedge_results(pairs: list[HedgePair]) -> str:
    """Pretty-print hedge pair results."""
    if not pairs:
        return "No hedge pairs found meeting thresholds.\n"

    lines = [
        "=" * 78,
        "  HEDGE PAIR SCANNER — Contrarian Bet Pairs",
        "=" * 78,
        "",
        f"{'#':>3}  {'Score':>7}  {'Type':<22}  {'Leg A':<22}  {'Leg B':<22}  {'1-Win':>8}  {'Ratio':>6}",
        f"{'—'*3}  {'—'*7}  {'—'*22}  {'—'*22}  {'—'*22}  {'—'*8}  {'—'*6}",
    ]

    for i, pair in enumerate(pairs, 1):
        a_label = f"{'↑' if pair.bet_a.direction == 'bullish' else '↓'} {pair.bet_a.series_ticker} ${pair.bet_a.strike:,.0f} {pair.bet_a.side.upper()}@{pair.bet_a.price_cents}c"
        b_label = f"{'↑' if pair.bet_b.direction == 'bullish' else '↓'} {pair.bet_b.series_ticker} ${pair.bet_b.strike:,.0f} {pair.bet_b.side.upper()}@{pair.bet_b.price_cents}c"
        pct = pair.joint_win_prob * 100
        lines.append(
            f"{i:>3}  {pair.hedge_score:>7.4f}  {pair.pair_type:<22}  "
            f"{a_label:<22}  {b_label:<22}  ${pair.min_payout:>6.0f}  {pair.payout_ratio:>5.0f}x"
        )

    lines.append("")
    lines.append(f"  {len(pairs)} pairs found. Cost per pair: ${pairs[0].total_cost:.0f} (${pairs[0].total_cost/2:.0f}/leg)")
    lines.append("")

    # Detail for top 5
    lines.append("─" * 78)
    lines.append("  TOP 5 DETAIL")
    lines.append("─" * 78)
    for i, pair in enumerate(pairs[:5], 1):
        lines.append("")
        lines.append(f"  [{i}]  Score: {pair.hedge_score:.4f}  |  {pair.pair_type}")
        lines.append(f"       {pair.description}")
        lines.append(f"       Leg A: {pair.bet_a.side.upper()} ${pair.bet_a.strike:,.0f} @ {pair.bet_a.price_cents}c  "
                     f"|  True P: {pair.bet_a.true_prob:.1%}  |  EV: +{pair.bet_a.expected_value:.4f}  "
                     f"|  Pays: ${pair.bet_a.payout_per_dollar:.0f}/$1")
        lines.append(f"       Leg B: {pair.bet_b.side.upper()} ${pair.bet_b.strike:,.0f} @ {pair.bet_b.price_cents}c  "
                     f"|  True P: {pair.bet_b.true_prob:.1%}  |  EV: +{pair.bet_b.expected_value:.4f}  "
                     f"|  Pays: ${pair.bet_b.payout_per_dollar:.0f}/$1")
        lines.append(f"       Combined: Cost ${pair.total_cost:.0f}  |  Min win ${pair.min_payout:.0f}  "
                     f"|  Max win ${pair.max_payout:.0f}  |  Ratio {pair.payout_ratio:.0f}x")
        lines.append(f"       Outcomes: ≥1 wins {pair.joint_win_prob:.1%}  "
                     f"|  Both win {pair.both_win_prob:.1%}  "
                     f"|  Both lose {pair.neither_win_prob:.1%}")
        lines.append(f"       Expected return: ${pair.expected_return:+.2f}")

    lines.append("")
    return "\n".join(lines)
