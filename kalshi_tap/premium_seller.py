"""Premium Seller — volatility mean-reversion strategy for Kalshi binary options.

Core edge: retail traders systematically overpay for far-OTM binary options
(1-10c YES "lottery tickets"). We SELL this premium by buying NO positions
and collecting the time decay.

How it works:
1. Monitor BTC price and recent volatility
2. After a volatility spike (>1.5% move in 15 min), implied vol is elevated
3. Sell premium: buy NO on far-OTM strikes in the OPPOSITE direction of the spike
   (after a crash, buy NO on far-below strikes — people overpay for crash protection)
   (after a pump, buy NO on far-above strikes — people chase the pump)
4. Hold until expiry or take-profit (50% of premium decayed)
5. Size: 2% of bankroll per position, max 3 open

Why this works:
- Mean reversion: after a spike, BTC tends to stabilize
- Volatility risk premium: implied vol > realized vol after spikes
- Time decay: binary option theta is highest near expiry
- Asymmetric edge: selling 2-5c premiums at 95-98% win rate compounds

This is NOT directional betting. We don't care where BTC goes — we just
bet that extreme moves won't continue at the same pace.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────

@dataclass
class PremiumSellerConfig:
    # Entry conditions
    vol_spike_pct: float = 1.2          # BTC must move this % in lookback window
    vol_lookback_minutes: int = 15      # Lookback window for vol spike
    min_tte_minutes: int = 30           # Minimum time to expiry
    max_tte_minutes: int = 120          # Maximum time to expiry (2 hours)
    min_no_price_cents: int = 85        # Minimum NO price (cents) — we want 85-98c
    max_no_price_cents: int = 98        # Maximum NO price (cents)
    otm_pct: float = 1.5                # Strike must be this % away from spot

    # Position management
    max_open_positions: int = 3         # Max simultaneous positions
    position_size_pct: float = 0.02     # 2% of bankroll per position
    take_profit_pct: float = 0.50       # Close when 50% of premium decayed
    stop_loss_pct: float = 2.0          # Close if loss exceeds 2x premium (catches blowups)

    # Risk controls
    max_daily_trades: int = 10          # Max new positions per day
    cooldown_minutes: int = 5           # Wait between entries
    trend_filter: bool = True           # Don't sell puts into a crash trending down

    # Kelly sizing
    kelly_fraction: float = 0.25        # Fraction of full Kelly


# ── Market State ──────────────────────────────────────────────────────────────

@dataclass
class MarketSnapshot:
    btc_price: float
    btc_change_15m_pct: float          # % change in last 15 min
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Position ──────────────────────────────────────────────────────────────────

@dataclass
class PremiumPosition:
    id: int
    ticker: str
    strike: float
    entry_price: float                  # Price we paid (0.85–0.98)
    entry_cost: float                   # Total cost in dollars
    contracts: int                      # Number of contracts
    entry_time: datetime
    expiry_time: datetime
    btc_at_entry: float
    entry_reason: str                   # Why we entered

    # Risk
    max_loss: float                     # If NO loses, we lose entry_cost
    max_profit: float                   # contracts - entry_cost
    stop_price: float | None = None     # NO price at which we exit (loss side)
    target_price: float | None = None   # NO price for take-profit

    # State
    closed: bool = False
    exit_price: float | None = None
    pnl: float = 0.0
    closed_at: datetime | None = None
    side: str = "no"                    # We always buy NO (sell premium)


# ── Signal ────────────────────────────────────────────────────────────────────

@dataclass
class SellSignal:
    """A premium-selling opportunity."""
    ticker: str
    strike: float
    no_price: float                    # Current NO price (0.85–0.98)
    yes_price: float                   # Corresponding YES price
    tte_minutes: float
    btc_price: float
    otm_pct: float                     # How far OTM the strike is
    reason: str
    score: float                       # 0-1 quality score


# ── Strategy Engine ───────────────────────────────────────────────────────────

class PremiumSeller:
    """Sell overpriced tail-risk premium on Kalshi binaries."""

    def __init__(self, config: PremiumSellerConfig | None = None,
                 bankroll: float = 100.0):
        self.cfg = config or PremiumSellerConfig()
        self.bankroll = bankroll
        self.positions: list[PremiumPosition] = []
        self.closed_positions: list[PremiumPosition] = []
        self._last_entry_time: datetime | None = None
        self._daily_trade_count: int = 0
        self._last_btc_15m: float | None = None
        self._next_id: int = 1

    # ── Public API ─────────────────────────────────────────────────────────

    def scan(self, markets: list, btc_price: float, btc_change_15m: float) -> list[SellSignal]:
        """Scan markets for premium-selling opportunities.

        Args:
            markets: List of parsed Kalshi market objects (from AnalysisEngine)
            btc_price: Current BTC price
            btc_change_15m: BTC % change in last 15 minutes
        """
        signals: list[SellSignal] = []

        # Gate: need volatility spike or elevated vol
        abs_change = abs(btc_change_15m)
        if abs_change < self.cfg.vol_spike_pct:
            return signals  # No vol spike, don't sell premium

        for m in markets:
            strike = getattr(m, 'strike', 0.0)
            if strike <= 0:
                continue

            # Calculate OTM distance
            otm_pct = abs(strike - btc_price) / btc_price * 100
            if otm_pct < self.cfg.otm_pct:
                continue  # Too close to the money

            # Time to expiry
            tte = getattr(m, 'tte_hours', 24.0) * 60
            if tte < self.cfg.min_tte_minutes or tte > self.cfg.max_tte_minutes:
                continue

            # Get NO price (we buy NO)
            no_price_cents = getattr(m, 'no_price_cents', None)
            if no_price_cents is None:
                # Try to derive from market price
                mp = getattr(m, 'market_price', None)
                if mp is None:
                    continue
                # If mp is YES price, NO = 100 - YES
                side = getattr(m, 'side', 'yes')
                if side == 'yes':
                    no_price_cents = 100 - int(mp * 100)
                else:
                    no_price_cents = int(mp * 100)

            if no_price_cents < self.cfg.min_no_price_cents:
                continue
            if no_price_cents > self.cfg.max_no_price_cents:
                continue

            # Trend filter: don't sell puts into a crash
            if self.cfg.trend_filter and btc_change_15m < -self.cfg.vol_spike_pct:
                # Crash — only sell calls (NO on high strikes)
                if strike < btc_price:
                    continue  # Skip low strikes during downtrend

            if self.cfg.trend_filter and btc_change_15m > self.cfg.vol_spike_pct:
                # Pump — only sell puts (NO on low strikes)
                if strike > btc_price:
                    continue  # Skip high strikes during uptrend

            # Score: higher = better opportunity
            no_price = no_price_cents / 100.0
            yes_price = 1.0 - no_price
            premium_pct = yes_price * 100  # How much premium we're collecting
            score = (premium_pct * tte / 60.0 * otm_pct) / 10.0
            score = min(1.0, max(0.0, score))

            direction = "above" if strike > btc_price else "below"
            reason = (
                f"vol={abs_change:+.1f}% {direction} strike={strike:.0f} "
                f"OTM={otm_pct:.1f}% NO={no_price_cents}c TTE={tte:.0f}m"
            )

            signal = SellSignal(
                ticker=getattr(m, 'ticker', ''),
                strike=strike,
                no_price=no_price,
                yes_price=yes_price,
                tte_minutes=tte,
                btc_price=btc_price,
                otm_pct=otm_pct,
                reason=reason,
                score=score,
            )
            signals.append(signal)

        # Sort by score descending
        signals.sort(key=lambda s: s.score, reverse=True)
        return signals

    def should_enter(self) -> bool:
        """Check if we're allowed to open a new position."""
        if len(self.positions) >= self.cfg.max_open_positions:
            return False
        if self._daily_trade_count >= self.cfg.max_daily_trades:
            return False
        if self._last_entry_time:
            elapsed = (datetime.now(timezone.utc) - self._last_entry_time).total_seconds()
            if elapsed < self.cfg.cooldown_minutes * 60:
                return False
        return True

    def enter(self, signal: SellSignal) -> PremiumPosition | None:
        """Execute a premium-selling trade (buy NO)."""
        if not self.should_enter():
            return None

        # Position size: Kelly-based
        win_prob = signal.no_price  # NO price IS the win probability
        if win_prob <= 0 or win_prob >= 1:
            return None

        odds = signal.yes_price / signal.no_price  # odds = profit / risk
        if odds <= 0:
            return None

        kelly = (win_prob * odds - (1 - win_prob)) / odds
        if kelly <= 0:
            return None

        bet_size = kelly * self.cfg.kelly_fraction * self.bankroll
        pos_size = min(bet_size, self.bankroll * self.cfg.position_size_pct)
        pos_size = max(0.50, pos_size)  # Minimum $0.50

        contracts = int(pos_size / signal.no_price)
        if contracts < 1:
            return None

        cost = round(contracts * signal.no_price, 4)
        if cost > self.bankroll:
            return None

        pos = PremiumPosition(
            id=self._next_id,
            ticker=signal.ticker,
            strike=signal.strike,
            side="no",
            entry_price=signal.no_price,
            entry_cost=cost,
            contracts=contracts,
            entry_time=datetime.now(timezone.utc),
            expiry_time=datetime.now(timezone.utc),  # Will be set from market data
            btc_at_entry=signal.btc_price,
            entry_reason=signal.reason,
            max_loss=cost,
            max_profit=round(contracts - cost, 4),
            stop_price=signal.no_price * (1 - self.cfg.stop_loss_pct * signal.yes_price),
            target_price=signal.no_price + (1.0 - signal.no_price) * self.cfg.take_profit_pct,
        )

        self._next_id += 1
        self.bankroll = round(self.bankroll - cost, 4)
        self.positions.append(pos)
        self._last_entry_time = datetime.now(timezone.utc)
        self._daily_trade_count += 1

        logger.info(
            "PREMIUM SELL #%d: NO %sc @ %.0f | %d contracts | cost $%.2f | "
            "max profit $%.2f | %s",
            pos.id, int(signal.no_price * 100), signal.strike,
            contracts, cost, pos.max_profit, signal.reason,
        )
        return pos

    def check_positions(self, kalshi_client=None) -> int:
        """Check open positions for settlement or exit conditions. Returns count closed."""
        closed = 0
        for pos in list(self.positions):
            # Check if settled via API
            ticker = pos.ticker
            settled = False
            outcome_won = False

            if kalshi_client and ticker:
                try:
                    status = kalshi_client.get_market_status(ticker)
                    if status in ("settled", "closed", "resolved"):
                        settled = True
                        # Determine outcome
                        resolved = getattr(kalshi_client, 'get_market_outcome', None)
                        if resolved:
                            outcome = resolved(ticker)
                            outcome_won = (outcome == "no")  # We bought NO
                except Exception:
                    pass

            if settled:
                if outcome_won:
                    pos.pnl = pos.max_profit
                else:
                    pos.pnl = -pos.max_loss
                self._close_position(pos, "settled", None)
                closed += 1
                continue

            # Check take-profit / stop-loss via current NO price
            # (not implemented without real-time pricing — rely on settlement)

        return closed

    def _close_position(self, pos: PremiumPosition, reason: str,
                        exit_price: float | None):
        """Close a position and update bankroll."""
        pos.closed = True
        pos.exit_price = exit_price
        pos.closed_at = datetime.now(timezone.utc)
        self.bankroll = round(self.bankroll + pos.entry_cost + pos.pnl, 4)
        self.positions.remove(pos)
        self.closed_positions.append(pos)

        logger.info(
            "CLOSED #%d: %s | P&L $%.4f | bal $%.2f | %s",
            pos.id, "WIN" if pos.pnl > 0 else "LOSS",
            pos.pnl, self.bankroll, reason,
        )

    # ── Stats ──────────────────────────────────────────────────────────────

    @property
    def total_pnl(self) -> float:
        return sum(p.pnl for p in self.closed_positions)

    @property
    def win_rate(self) -> float:
        if not self.closed_positions:
            return 0.0
        wins = sum(1 for p in self.closed_positions if p.pnl > 0)
        return wins / len(self.closed_positions)

    def summary(self) -> dict:
        return {
            "bankroll": round(self.bankroll, 2),
            "total_pnl": round(self.total_pnl, 2),
            "open": len(self.positions),
            "closed": len(self.closed_positions),
            "win_rate": f"{self.win_rate:.0%}",
            "daily_trades": self._daily_trade_count,
        }
