"""Analysis and decision engine for Kalshi BTC daily markets.

Core algorithm:
1. Fetch KXBTCD markets → list of strike-level binary options
2. For each market:
   a. Derive market-implied probability from bid/ask midpoint
   b. Compute "true" probability: P(BTC > strike at expiry)
      using current spot price, time to expiry, and historical volatility
      via Black-Scholes binary option pricing (inverted)
   c. Calculate expected value: EV = true_p * (1 - price) - (1 - true_p) * price
   d. Size the bet using fractional Kelly criterion
3. Rank by EV, filter by threshold, return actionable bets.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Protocol

    class _PriceProto(Protocol):
        price_usd: float

    from .client import KalshiClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class EngineConfig:
    """Tunable parameters for the betting engine."""

    min_ev_threshold: float = 0.03       # Minimum expected value (3 cents per $1)
    kelly_fraction: float = 0.25         # Fraction of full Kelly to bet
    max_bet_per_market_dollars: float = 50.0  # Max bet per market
    min_bet_dollars: float = 1.0         # Minimum bet to bother placing
    max_contracts: int = 50              # Maximum contracts per bet
    vol_override: float | None = None    # Override volatility (None = live calc)
    prefer_yes_over_no: bool = True      # Analyzing YES is simpler; NO when needed


# ---------------------------------------------------------------------------
# Market data model
# ---------------------------------------------------------------------------

@dataclass
class BTCMarket:
    """A single Kalshi BTC daily binary market."""

    ticker: str
    event_ticker: str
    title: str
    strike: float                # The floor_strike price level
    close_time: datetime
    yes_bid: float               # 0.00–1.00
    yes_ask: float               # 0.00–1.00
    no_bid: float
    no_ask: float
    volume_fp: str               # Volume in fixed-point string
    raw: dict = field(repr=False)


@dataclass
class BetRecommendation:
    """A recommended bet with computed EV and sizing."""

    market: BTCMarket
    side: str                    # "yes" or "no"
    price: float                 # Price we'd pay (0.00–1.00)
    market_prob: float           # Market-implied probability
    true_prob: float             # Engine-estimated true probability
    expected_value: float        # EV per $1 bet
    kelly_fraction: float        # Recommended fraction of bankroll
    bet_contracts: int           # Recommended contract count
    bet_dollars: float           # Total cost in dollars
    confidence: str              # "high", "medium", "low"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AnalysisEngine:
    """Compute expected value and generate bet recommendations."""

    def __init__(self, config: EngineConfig | None = None):
        self.config = config or EngineConfig()

    # --- Public API ---

    def analyze(
        self,
        markets_raw: list[dict],
        btc_price: "_PriceProto",
        volatility: float | None = None,
    ) -> list[BetRecommendation]:
        """Analyze a list of KXBTCD markets and return ranked recommendations.

        Args:
            markets_raw: Raw market dicts from Kalshi API
            btc_price: Current BTC price snapshot
            volatility: Annualized volatility (auto-calculated if None)

        Returns:
            List of BetRecommendation sorted by EV descending
        """
        parsed = [self._parse_market(m) for m in markets_raw]
        valid = [m for m in parsed if m is not None]

        if not valid:
            logger.warning("No valid BTC markets found")
            return []

        vol = volatility if volatility is not None else self.config.vol_override
        if vol is None:
            from .btc_feed import get_btc_volatility
            vol = get_btc_volatility()

        logger.info(
            "Analyzing %d markets | BTC $%.0f | vol %.0f%%",
            len(valid), btc_price.price_usd, vol * 100,
        )

        recommendations: list[BetRecommendation] = []
        for market in valid:
            rec = self._evaluate_market(market, btc_price.price_usd, vol)
            if rec is not None:
                recommendations.append(rec)

        recommendations.sort(key=lambda r: r.expected_value, reverse=True)
        return recommendations

    # --- Market parsing ---

    def _parse_market(self, raw: dict) -> BTCMarket | None:
        """Parse a raw market dict into a BTCMarket, skipping invalid entries."""
        try:
            close_str = raw.get("close_time", "")
            if not close_str:
                return None
            close_time = datetime.fromisoformat(close_str.replace("Z", "+00:00"))

            return BTCMarket(
                ticker=raw["ticker"],
                event_ticker=raw.get("event_ticker", ""),
                title=raw.get("title", ""),
                strike=float(raw.get("floor_strike", 0)),
                close_time=close_time,
                yes_bid=float(raw.get("yes_bid_dollars", 0)),
                yes_ask=float(raw.get("yes_ask_dollars", 0)),
                no_bid=float(raw.get("no_bid_dollars", 0)),
                no_ask=float(raw.get("no_ask_dollars", 0)),
                volume_fp=raw.get("volume_fp", "0"),
                raw=raw,
            )
        except (KeyError, ValueError, TypeError) as e:
            logger.debug("Skipping unparseable market: %s", e)
            return None

    # --- Core evaluation ---

    def _evaluate_market(
        self,
        market: BTCMarket,
        spot: float,
        volatility: float,
    ) -> BetRecommendation | None:
        """Evaluate a single market for betting opportunities.

        Returns a BetRecommendation if EV exceeds threshold, else None.
        """
        # Time to expiry in years
        now = datetime.now(timezone.utc)
        tte_seconds = (market.close_time - now).total_seconds()
        tte_years = max(tte_seconds / (365.25 * 24 * 3600), 1 / (365.25 * 24))  # min 1 hour

        # Market-implied probability (use mid-price for YES)
        mid_price = self._mid_price(market)
        if mid_price <= 0.01 or mid_price >= 0.99:
            return None  # No edge when market is near-certain

        # True probability: P(spot > strike at expiry)
        true_prob = self._binary_call_probability(spot, market.strike, tte_years, volatility)

        # Expected value
        ev = self._compute_ev(true_prob, mid_price, market)

        if ev < self.config.min_ev_threshold:
            return None

        # Determine which side to bet
        side, price = self._pick_side(true_prob, mid_price, market)

        # Kelly sizing
        kelly = self._kelly_fraction(true_prob, price)
        bet_frac = kelly * self.config.kelly_fraction

        # Convert fraction to contracts
        contracts = self._size_bet(bet_frac, price, market)

        if contracts < 1:
            return None

        bet_dollars = contracts * price

        if bet_dollars < self.config.min_bet_dollars:
            return None

        confidence = (
            "high" if ev > 0.08 else
            "medium" if ev > 0.04 else
            "low"
        )

        return BetRecommendation(
            market=market,
            side=side,
            price=price,
            market_prob=mid_price,
            true_prob=true_prob,
            expected_value=ev,
            kelly_fraction=kelly,
            bet_contracts=contracts,
            bet_dollars=round(bet_dollars, 2),
            confidence=confidence,
        )

    # --- Probability math ---

    @staticmethod
    def _binary_call_probability(
        spot: float,
        strike: float,
        tte_years: float,
        volatility: float,
    ) -> float:
        """Black-Scholes probability that spot > strike at expiry.

        For a binary (digital) call option, the risk-neutral probability
        that the option finishes in the money is N(d2), where:

            d2 = (ln(S/K) - (σ²/2)*T) / (σ * sqrt(T))

        We use a zero-drift assumption (no risk-free rate adjustment)
        which is standard for short-dated prediction market analysis.
        """
        if spot <= 0 or strike <= 0 or tte_years <= 0 or volatility <= 0:
            return 0.5

        sigma_sqrt_t = volatility * math.sqrt(tte_years)
        if sigma_sqrt_t < 1e-10:
            return 1.0 if spot > strike else 0.0

        d2 = math.log(spot / strike) / sigma_sqrt_t - 0.5 * sigma_sqrt_t

        # Standard normal CDF approximation (Abramowitz & Stegun 26.2.17)
        return _norm_cdf(d2)

    @staticmethod
    def _mid_price(market: BTCMarket) -> float:
        """Best available mid-price for the YES side."""
        # Use the tighter of bid/ask if available, else fall back
        if market.yes_bid > 0 and market.yes_ask < 1:
            return (market.yes_bid + market.yes_ask) / 2
        if market.no_bid > 0 and market.no_ask < 1:
            no_mid = (market.no_bid + market.no_ask) / 2
            return 1.0 - no_mid
        # Fallback: just use yes bid or ask
        return market.yes_bid or market.yes_ask or 0.5

    def _compute_ev(
        self,
        true_prob: float,
        market_price: float,
        market: BTCMarket,
    ) -> float:
        """Compute expected value of betting YES at market_price.

        EV = true_prob * (1 - price) - (1 - true_prob) * price
           = true_prob - price

        For NO bets, we flip: EV = (1 - true_prob) - (1 - price) = price - true_prob
        """
        # First compute EV for YES
        ev_yes = true_prob - market_price

        # Also compute EV for NO
        ev_no = -ev_yes  # (1-true_prob) - (1-market_price) = market_price - true_prob

        # Return the better EV (positive if any edge exists)
        return max(ev_yes, ev_no)

    def _pick_side(
        self,
        true_prob: float,
        mid_price: float,
        market: BTCMarket,
    ) -> tuple[str, float]:
        """Pick the optimal side (yes/no) and execution price.

        Returns (side, price_to_pay).
        """
        ev_yes = true_prob - mid_price
        ev_no = mid_price - true_prob

        if ev_yes >= ev_no:
            # Bet YES at the ask price (we're a taker)
            price = market.yes_ask if market.yes_ask > 0 else mid_price
            return "yes", price
        else:
            # Bet NO — effective price is the no_ask
            no_price = market.no_ask if market.no_ask > 0 else (1.0 - mid_price)
            return "no", no_price

    @staticmethod
    def _kelly_fraction(true_prob: float, price: float) -> float:
        """Full Kelly fraction for a binary bet.

        f* = (true_p * (1 - price) - (1 - true_p) * price) / (1 - price)
           = (true_p - price) / (1 - price)    for YES bets

        Clamped to [0, 1].
        """
        if price >= 1.0:
            return 0.0
        numerator = true_prob - price
        if numerator <= 0:
            return 0.0
        kelly = numerator / (1.0 - price)
        return max(0.0, min(1.0, kelly))

    def _size_bet(
        self,
        bet_fraction: float,
        price: float,
        market: BTCMarket,
    ) -> int:
        """Convert a Kelly fraction into an integer contract count.

        bet_fraction is the *fractional* Kelly (already multiplied by kelly_fraction).
        """
        if bet_fraction <= 0 or price <= 0:
            return 0

        # Use a fixed notional sizing: bet_fraction * max_bet / price
        raw_contracts = (bet_fraction * self.config.max_bet_per_market_dollars) / price

        contracts = min(
            int(raw_contracts),
            self.config.max_contracts,
        )
        return contracts


# ---------------------------------------------------------------------------
# Standard normal CDF (no scipy dependency)
# ---------------------------------------------------------------------------

def _norm_cdf(x: float) -> float:
    """Standard normal CDF using the Abramowitz & Stegun approximation.

    Accurate to ~7.5e-8 absolute error.
    """
    if x < -8:
        return 0.0
    if x > 8:
        return 1.0

    # Constants for approximation
    b0 = 0.2316419
    b1 = 0.319381530
    b2 = -0.356563782
    b3 = 1.781477937
    b4 = -1.821255978
    b5 = 1.330274429

    t = 1.0 / (1.0 + b0 * abs(x))
    pdf = math.exp(-0.5 * x * x) / math.sqrt(2.0 * math.pi)
    cdf = 1.0 - pdf * (b1 * t + b2 * t ** 2 + b3 * t ** 3 + b4 * t ** 4 + b5 * t ** 5)

    return cdf if x >= 0 else 1.0 - cdf


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------

def run_analysis(
    client: "KalshiClient | None",
    btc_price: "_PriceProto",
    *,
    live: bool = False,
    max_bet: float = 50.0,
    verbose: bool = False,
) -> list[BetRecommendation]:
    """Fetch markets, run analysis, optionally place trades.

    If client is None, runs in dry-run mode (no order placement).
    """
    config = EngineConfig(max_bet_per_market_dollars=max_bet)
    engine = AnalysisEngine(config)

    # Fetch markets
    if client is None:
        from .client import API_BASE
        logger.warning("No Kalshi client — running in analysis-only mode")
        logger.info("Would fetch from: %s/markets?series_ticker=KXBTCD", API_BASE)
        # In dry-run without a client, we need to fetch markets somehow
        # For now, just report that we can't
        return []
    else:
        logger.info("Fetching KXBTCD markets from Kalshi...")
        markets_raw = client.get_markets(series_ticker="KXBTCD", status="open")
        logger.info("Got %d markets", len(markets_raw))

    if not markets_raw:
        logger.warning("No open KXBTCD markets found")
        return []

    # Run analysis
    recs = engine.analyze(markets_raw, btc_price)

    # Place trades if live
    if live and client and recs:
        logger.info("LIVE mode: placing %d trades", len(recs))
        for rec in recs:
            try:
                price_cents = int(round(rec.price * 100))
                result = client.place_order(
                    ticker=rec.market.ticker,
                    side=rec.side,
                    count=rec.bet_contracts,
                    price_cents=price_cents,
                )
                logger.info(
                    "ORDER: %s %s x%d @ $%.2f → %s",
                    rec.side.upper(), rec.market.ticker,
                    rec.bet_contracts, rec.price,
                    result.get("order_id", result.get("status", "?")),
                )
            except Exception as e:
                logger.error("Order failed: %s", e)

    return recs
