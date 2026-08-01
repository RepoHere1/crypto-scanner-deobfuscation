"""Autopilot paper-trading engine v2 — calibrated, risk-managed, persistent.

Upgraded from the original which:
- Used raw Black-Scholes probabilities (systematically overestimates edges)
- Had no drawdown limits or win-rate monitoring (lost $100 → $0 silently)
- Didn't persist state (every restart was a fresh $100)
- Never learned from past outcomes (zero feedback loop)

Now integrates:
- CalibratedEngine: probabilities adjusted by real Kalshi settlement data
- RiskManager: drawdown circuit breakers, dynamic sizing, recovery mode
- OutcomeResolver: fetches real outcomes from Kalshi, builds calibration curves
- Persistent state: balance, P&L, and calibration survive restarts

Starts with a virtual balance. Watch your $100 grow (or get stopped safely).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time as _time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hedge import HedgePair, HedgeConfig
    from .calibrate import OutcomeResolver
    from .risk import RiskManager, RiskConfig
    from .strategy import BetStrategy, StrategyDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class AutopilotConfig:
    """Autopilot runtime parameters."""

    starting_balance: float = 100.0
    bet_per_leg_dollars: float = 1.0       # $1 per leg
    bet_per_pair_dollars: float = 2.0       # $2 total per pair
    max_open_pairs: int = 5                 # Cap on simultaneous open pairs
    settle_check_interval_scans: int = 1    # Check settlements every N scans
    target_balance: float = 0.0             # Stop if balance reaches this (0=disabled)
    max_scans: int = 0                      # Stop after N scans (0=unlimited)
    scan_interval_seconds: int = 15
    force_fresh: bool = True
    skip_duplicate_pairs: bool = True       # Don't re-buy the same pair


# ---------------------------------------------------------------------------
# Position tracking
# ---------------------------------------------------------------------------


@dataclass
class PaperPosition:
    """A single paper-traded pair (two legs)."""

    pos_id: int
    pair_type: str
    pair_score: float

    # Leg A
    ticker_a: str
    side_a: str
    strike_a: float
    price_a: float
    contracts_a: int
    cost_a: float

    # Leg B
    ticker_b: str
    side_b: str
    strike_b: float
    price_b: float
    contracts_b: int
    cost_b: float

    # Meta
    total_cost: float
    max_payout: float
    min_payout: float
    opened_at: datetime
    settled: bool = False
    settled_at: datetime | None = None
    outcome_a: str | None = None   # "won", "lost", or None
    outcome_b: str | None = None
    pnl: float = 0.0
    pair_key: str = ""              # Unique key: "ticker_a|side_a|ticker_b|side_b"
    db_id_a: int = 0                # DB recommendation ID for leg A
    db_id_b: int = 0                # DB recommendation ID for leg B


# ---------------------------------------------------------------------------
# Autopilot engine
# ---------------------------------------------------------------------------


class Autopilot:
    """Paper-trading engine for the hedge strategy."""

    def __init__(
        self,
        config: AutopilotConfig | None = None,
        risk_manager: "RiskManager | None" = None,
        resolver: "OutcomeResolver | None" = None,
        strategy: "BetStrategy | None" = None,
    ):
        self.cfg = config or AutopilotConfig()
        self._risk = risk_manager
        self._resolver = resolver
        self._strategy = strategy

        # Load balance from risk manager if available (persistent)
        if self._risk is not None:
            self.balance = self._risk.state.balance
            self.total_pnl = self._risk.state.total_pnl
        else:
            self.balance = self.cfg.starting_balance
            self.total_pnl = 0.0

        self.positions: list[PaperPosition] = []
        self.settled_positions: list[PaperPosition] = []
        self._next_id = 1
        self._settled_tickers: set[str] = set()  # Cache: tickers already resolved
        self._placed_keys: set[str] = set()       # Cache: pair keys already bought
        self.stats = {
            "scans": 0,
            "trades_placed": 0,
            "trades_settled": 0,
            "wins": 0,
            "losses": 0,
            "total_won": 0.0,
            "total_lost": 0.0,
        }

    # --- Public API ---

    def step(
        self,
        pairs: list["HedgePair"],
        price_usd: float,
        volatility: float,
    ) -> dict:
        """Execute one autopilot cycle.

        Args:
            pairs: Ranked hedge pairs from the scanner
            price_usd: Current spot price
            volatility: Current volatility

        Returns:
            Dict with status info for the dashboard
        """
        self.stats["scans"] += 1

        # 1. Resolve outcomes via OutcomeResolver (fetches real Kalshi data)
        if self._resolver and self.stats["scans"] % self.cfg.settle_check_interval_scans == 0:
            try:
                resolved_count = self._resolver.resolve_pending()
                if resolved_count > 0:
                    logger.info("Resolved %d bets via Kalshi API", resolved_count)
            except Exception as e:
                logger.debug("Outcome resolution skipped: %s", e)

        # 2. Check settlements on open positions
        if self.stats["scans"] % self.cfg.settle_check_interval_scans == 0:
            self._check_settlements()

        # 3. Check risk manager before trading
        can_trade = True
        risk_reason = ""
        bet_per_leg = self.cfg.bet_per_leg_dollars
        if self._risk is not None:
            can_trade, risk_reason, risk_bet = self._risk.check()
            if not can_trade:
                logger.warning("Risk manager blocked: %s", risk_reason)
            if risk_bet > 0:
                bet_per_leg = risk_bet

        # 4. Sniper mode: evaluate single bets first (prioritize win probability)
        placed_singles = 0
        if can_trade and self._strategy is not None:
            seen_singles: set[str] = set()
            for pair in pairs:
                for bet in (pair.bet_a, pair.bet_b):
                    key = f"{bet.ticker}|{bet.side}"
                    if key in seen_singles:
                        continue
                    seen_singles.add(key)
                    decision = self._strategy.evaluate_single(bet)
                    if decision.decision.value != "accept":
                        continue
                    # Place single-leg trade
                    bet_dollars = bet_per_leg * 0.50  # Half-size for singles (no hedge)
                    contracts = int(bet_dollars / bet.market_price) if bet.market_price > 0 else 0
                    if contracts < 1:
                        continue
                    cost = contracts * bet.market_price
                    if cost > self.balance or cost < 0.50:
                        continue
                    # Quick single-leg position
                    pos = PaperPosition(
                        pos_id=self._next_id,
                        pair_type="sniper",
                        pair_score=decision.score,
                        ticker_a=bet.ticker, side_a=bet.side,
                        strike_a=bet.strike, price_a=bet.market_price,
                        contracts_a=contracts, cost_a=round(cost, 4),
                        ticker_b="", side_b="", strike_b=0, price_b=0,
                        contracts_b=0, cost_b=0,
                        total_cost=round(cost, 4),
                        max_payout=contracts, min_payout=0,
                        opened_at=datetime.now(timezone.utc),
                        pair_key=f"sniper:{key}",
                    )
                    self._next_id += 1
                    self.balance = round(self.balance - cost, 4)
                    self.positions.append(pos)
                    self.stats["trades_placed"] += 1
                    placed_singles += 1
                    if self._risk:
                        self._risk.update_balance(self.balance)
                    # Record to DB
                    pos.db_id_a = self._record_leg_to_db(
                        bet.ticker, bet.side, bet.market_price,
                        bet.true_prob, contracts, cost)
                    logger.info(
                        "SNIPER #%d: %s %s@%dc x%d | cost $%.4f | bal $%.2f | %s",
                        pos.pos_id, bet.side.upper(), bet.ticker[-12:],
                        int(bet.market_price * 100), contracts, cost,
                        self.balance, decision.reason)
                    if placed_singles >= 2:
                        break
                if placed_singles >= 2:
                    break

        # 5. Place hedge pairs from top pairs
        placed_this_scan = 0
        max_pairs_per_scan = 3
        if can_trade:
            for pair in pairs:
                # --- Gate: per-scan limit ---
                if placed_this_scan >= max_pairs_per_scan:
                    break

                pair_cost = bet_per_leg * 2.0
                if self.balance < pair_cost:
                    break
                if len(self.positions) >= self.cfg.max_open_pairs:
                    break

                # --- Gate: strategy evaluation (primary quality filter) ---
                if self._strategy is not None:
                    decision = self._strategy.evaluate_pair(pair)
                    if decision.decision.value != "accept":
                        continue

                # --- Gate: skip same-direction pairs (not a hedge) ---
                if pair.bet_a.direction == pair.bet_b.direction:
                    continue

                # --- Gate: don't reuse tickers already in open positions ---
                open_tickers: set[str] = set()
                for p in self.positions:
                    open_tickers.add(p.ticker_a)
                    open_tickers.add(p.ticker_b)
                if pair.bet_a.ticker in open_tickers or pair.bet_b.ticker in open_tickers:
                    continue

                pair_key = f"{pair.bet_a.ticker}|{pair.bet_a.side}|{pair.bet_b.ticker}|{pair.bet_b.side}"
                if self.cfg.skip_duplicate_pairs and pair_key in self._placed_keys:
                    continue

                # --- Gate: inter-trade risk check ---
                if self._risk is not None:
                    can_trade, risk_reason, risk_bet = self._risk.check()
                    if not can_trade:
                        logger.warning("Risk manager blocked mid-scan: %s", risk_reason)
                        break
                    if risk_bet > 0:
                        bet_per_leg = risk_bet

                pos = self._place_pair(pair, bet_per_leg)
                if pos:
                    self._placed_keys.add(pair_key)
                    placed_this_scan += 1

        # 5. Check stop conditions (including risk manager)
        stopped_reason = ""
        if not can_trade:
            stopped_reason = f"Risk manager: {risk_reason}"
        elif self.balance < self.cfg.bet_per_pair_dollars:
            stopped_reason = f"balance ${self.balance:.2f} < ${self.cfg.bet_per_pair_dollars:.2f}"
        elif self.cfg.target_balance > 0 and self.balance >= self.cfg.target_balance:
            stopped_reason = f"target ${self.cfg.target_balance:.0f} reached"
        elif self.cfg.max_scans > 0 and self.stats["scans"] >= self.cfg.max_scans:
            stopped_reason = f"max scans ({self.cfg.max_scans}) reached"

        return {
            "balance": self.balance,
            "open_count": len(self.positions),
            "settled_count": len(self.settled_positions),
            "total_pnl": self.total_pnl,
            "placed_this_scan": placed_this_scan,
            "stopped": bool(stopped_reason),
            "stopped_reason": stopped_reason,
            "stats": dict(self.stats),
        }

    def get_open_positions(self) -> list[PaperPosition]:
        return list(self.positions)

    def get_recent_settlements(self, n: int = 5) -> list[PaperPosition]:
        return self.settled_positions[-n:]

    # --- Internal ---

    def _place_pair(self, pair: "HedgePair", bet_per_leg: float | None = None) -> PaperPosition | None:
        """Place a paper trade for a hedge pair. Deducts from balance."""
        bet = bet_per_leg if bet_per_leg is not None else self.cfg.bet_per_leg_dollars

        # Leg A
        contracts_a = int(bet / pair.bet_a.market_price) if pair.bet_a.market_price > 0 else 0
        cost_a = contracts_a * pair.bet_a.market_price if contracts_a > 0 else bet
        if cost_a <= 0:
            return None

        # Leg B
        contracts_b = int(bet / pair.bet_b.market_price) if pair.bet_b.market_price > 0 else 0
        cost_b = contracts_b * pair.bet_b.market_price if contracts_b > 0 else bet
        if cost_b <= 0:
            return None

        total_cost = round(cost_a + cost_b, 4)
        if total_cost > self.balance:
            return None

        pos = PaperPosition(
            pos_id=self._next_id,
            pair_type=pair.pair_type,
            pair_score=pair.hedge_score,
            ticker_a=pair.bet_a.ticker,
            side_a=pair.bet_a.side,
            strike_a=pair.bet_a.strike,
            price_a=pair.bet_a.market_price,
            contracts_a=contracts_a,
            cost_a=round(cost_a, 4),
            ticker_b=pair.bet_b.ticker,
            side_b=pair.bet_b.side,
            strike_b=pair.bet_b.strike,
            price_b=pair.bet_b.market_price,
            contracts_b=contracts_b,
            cost_b=round(cost_b, 4),
            total_cost=total_cost,
            max_payout=contracts_a + contracts_b,
            min_payout=min(contracts_a, contracts_b),
            opened_at=datetime.now(timezone.utc),
            pair_key=f"{pair.bet_a.ticker}|{pair.bet_a.side}|{pair.bet_b.ticker}|{pair.bet_b.side}",
        )

        self._next_id += 1
        self.balance = round(self.balance - total_cost, 4)
        self.positions.append(pos)
        self.stats["trades_placed"] += 1

        # Record legs in history DB for calibration feedback loop
        pos.db_id_a = self._record_leg_to_db(
            pos.ticker_a, pos.side_a, pos.price_a,
            pair.bet_a.true_prob, pos.contracts_a, pos.cost_a,
        )
        pos.db_id_b = self._record_leg_to_db(
            pos.ticker_b, pos.side_b, pos.price_b,
            pair.bet_b.true_prob, pos.contracts_b, pos.cost_b,
        )

        # Sync risk manager balance after trade
        if self._risk is not None:
            self._risk.update_balance(self.balance)

        logger.info(
            "PAPER TRADE #%d: %s %s@%dc x%d + %s %s@%dc x%d | cost $%.4f | bal $%.2f",
            pos.pos_id,
            pos.side_a.upper(), pos.ticker_a[-12:], int(pos.price_a * 100), pos.contracts_a,
            pos.side_b.upper(), pos.ticker_b[-12:], int(pos.price_b * 100), pos.contracts_b,
            pos.total_cost, self.balance,
        )
        return pos

    def _check_settlements(self) -> int:
        """Check all open positions for settlement. Returns number settled."""
        settled = 0
        still_open: list[PaperPosition] = []

        for pos in self.positions:
            # Check if both legs' markets are resolved
            a_settled = pos.ticker_a in self._settled_tickers or self._check_ticker_settled(pos.ticker_a)
            b_settled = pos.ticker_b in self._settled_tickers or self._check_ticker_settled(pos.ticker_b)

            if a_settled and b_settled:
                self._resolve_position(pos)
                self.settled_positions.append(pos)
                self.stats["trades_settled"] += 1
                settled += 1
            else:
                still_open.append(pos)

        self.positions = still_open
        return settled

    def _check_ticker_settled(self, ticker: str) -> bool:
        """Check if a specific market has settled via Kalshi API."""
        try:
            from .client import KalshiClient
            client = KalshiClient()
            data = client.get(f"/markets/{ticker}")
            status = data.get("market", {}).get("status", data.get("status", ""))
            if status in ("settled", "closed", "resolved"):
                self._settled_tickers.add(ticker)
                market = data.get("market", data)
                outcome = (market.get("yes_outcome") or market.get("result") or "").lower()
                setattr(self, f"_outcome_{ticker}", outcome)
                return True
        except Exception as e:
            logger.debug("Settlement check failed for %s: %s", ticker, e)
        return False

    def _record_leg_to_db(
        self, ticker: str, side: str, price: float,
        true_prob: float, contracts: int, cost: float,
    ) -> int:
        """Insert a paper trade leg into the history DB. Returns the row ID."""
        try:
            db_path = os.path.expanduser("~/.kalshi/history.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            conn = sqlite3.connect(db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO recommendations "
                "(run_id, ticker, title, strike, side, price, market_prob, "
                " true_prob, expected_value, kelly_fraction, contracts, cost, "
                " confidence, resolved, actual_outcome, pnl) "
                "VALUES (0, ?, '', 0, ?, ?, 0, ?, 0, 0, ?, ?, 'paper', 0, NULL, NULL)",
                (ticker, side, price, true_prob, contracts, cost),
            )
            row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
            conn.close()
            return row_id
        except Exception as e:
            logger.debug("Failed to record leg to DB: %s", e)
            return 0

    def _resolve_leg_in_db(self, db_id: int, outcome: str, won: bool, cost: float) -> None:
        """Mark a paper trade leg as resolved in the history DB."""
        if db_id <= 0:
            return
        try:
            db_path = os.path.expanduser("~/.kalshi/history.db")
            conn = sqlite3.connect(db_path)
            pnl = round((1.0 - cost) if won else (-cost), 4)
            conn.execute(
                "UPDATE recommendations SET resolved=1, actual_outcome=?, pnl=? "
                "WHERE id=?",
                (outcome, pnl, db_id),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Failed to resolve leg in DB: %s", e)

    def _resolve_position(self, pos: PaperPosition) -> None:
        """Resolve a settled position and update P&L."""
        outcome_a = self._get_outcome(pos.ticker_a)
        outcome_b = self._get_outcome(pos.ticker_b)

        # Leg A resolution
        won_a = (pos.side_a == "yes" and outcome_a == "yes") or \
                (pos.side_a == "no" and outcome_a == "no")
        payout_a = pos.contracts_a if won_a else 0.0
        pnl_a = round(payout_a - pos.cost_a, 4)

        # Leg B resolution
        won_b = (pos.side_b == "yes" and outcome_b == "yes") or \
                (pos.side_b == "no" and outcome_b == "no")
        payout_b = pos.contracts_b if won_b else 0.0
        pnl_b = round(payout_b - pos.cost_b, 4)

        pos.settled = True
        pos.settled_at = datetime.now(timezone.utc)
        pos.outcome_a = "won" if won_a else "lost"
        pos.outcome_b = "won" if won_b else "lost"
        pos.pnl = round(pnl_a + pnl_b, 4)

        self.balance = round(self.balance + pos.pnl + pos.total_cost, 4)
        self.total_pnl = round(self.total_pnl + pos.pnl, 4)

        # Record outcomes in history DB for calibration feedback loop
        self._resolve_leg_in_db(pos.db_id_a, outcome_a, won_a, pos.cost_a)
        self._resolve_leg_in_db(pos.db_id_b, outcome_b, won_b, pos.cost_b)

        # Update risk manager with outcomes
        if self._risk is not None:
            self._risk.record_outcome(won_a, pnl_a)
            self._risk.record_outcome(won_b, pnl_b)
            self._risk.update_balance(self.balance)

        if won_a:
            self.stats["wins"] += 1
            self.stats["total_won"] += payout_a
        else:
            self.stats["losses"] += 1
            self.stats["total_lost"] += pos.cost_a
        if won_b:
            self.stats["wins"] += 1
            self.stats["total_won"] += payout_b
        else:
            self.stats["losses"] += 1
            self.stats["total_lost"] += pos.cost_b

        logger.info(
            "SETTLED #%d: A=%s($%.2f) B=%s($%.2f) | P&L $%.4f | bal $%.2f",
            pos.pos_id, pos.outcome_a, payout_a, pos.outcome_b, payout_b,
            pos.pnl, self.balance,
        )

    def _get_outcome(self, ticker: str) -> str:
        """Get the cached outcome for a settled ticker."""
        return getattr(self, f"_outcome_{ticker}", "")


# ---------------------------------------------------------------------------
# Dashboard formatter
# ---------------------------------------------------------------------------



# -- ANSI color codes --
ESC = chr(27)
C = {
    "R": ESC + "[0m",   "B": ESC + "[1m",
    "g": ESC + "[32m",  "r": ESC + "[31m",
    "y": ESC + "[33m",  "c": ESC + "[36m",
    "m": ESC + "[35m",  "b": ESC + "[34m",
    "d": ESC + "[2m",
}

# -- Unicode icons --
I = {
    "money": "💰", "bank": "🏦", "chart": "📊",
    "target": "🎯", "win": "✅", "lose": "❌",
    "scan": "🔄", "live": "⚡", "rocket": "🚀",
    "skull": "💀", "gem": "💎", "fire": "🔥",
    "bull": "📈", "bear": "📉", "dice": "🎲",
    "clock": "⏱", "stop": "🛑", "pkg": "📦",
    "star": "⭐", "zap": "💥",
}

def format_autopilot_dashboard(
    pilot: Autopilot,
    status: dict,
    last_pair: "HedgePair | None",
    price_usd: float,
    volatility: float,
    series: str = "BTC",
) -> str:
    """Render the autopilot dashboard with colors and icons."""
    bal = status["balance"]
    pnl = status["total_pnl"]
    pnl_sign = "+" if pnl >= 0 else ""
    pct = (bal / pilot.cfg.starting_balance - 1) * 100
    pct_sign = "+" if pct >= 0 else ""
    pnl_color = "g" if pnl >= 0 else "r"
    pct_color = "g" if pct >= 0 else "r"
    bal_color = "g" if bal >= pilot.cfg.starting_balance else ("y" if bal >= pilot.cfg.starting_balance * 0.5 else "r")

    total_legs = pilot.stats["wins"] + pilot.stats["losses"]
    wr = (pilot.stats["wins"] / total_legs * 100) if total_legs > 0 else 0.0
    wr_color = "g" if wr >= 50 else ("y" if wr >= 25 else "r")

    s = status["stats"]

    def c(color, text):
        return C.get(color, "") + text + C["R"]

    def dim(text):
        return C["d"] + text + C["R"]

    horz = dim("\u2500" * 62)

    lines = [
        "\u2554" + "\u2550" * 62 + "\u2557",
        "\u2551  " + c("B", I["dice"] + "  AUTOPILOT  " + I["money"] + " $" + str(int(pilot.cfg.starting_balance)) + " DRY RUN") + "\u2551",
        "\u2551  " + I["live"] + " " + series + " " + c("b", "${:,.0f}".format(price_usd)) + "  " + I["chart"] + " vol " + c("c", "{:.0f}%".format(volatility * 100)) + "  " + I["scan"] + " scan " + c("m", "#{:03d}".format(s["scans"])) + "\u2551",
        "\u2560" + "\u2550" * 62 + "\u2563",
        "\u2551  " + I["bank"] + " " + c(bal_color, c("B", "${:,.2f}".format(bal))) + "  " + I["chart"] + " P&L " + c(pnl_color, "{}{:,.2f}".format(pnl_sign, abs(pnl))) + " (" + c(pct_color, "{}{:+.1f}%".format(pct_sign, pct)) + ")  " + I["target"] + " WR " + c(wr_color, "{:.0f}%".format(wr)) + "\u2551",
    ]

    open_n = status["open_count"]
    settled_n = status["settled_count"]
    placed_n = status["placed_this_scan"]
    placed_icon = "🔔" if placed_n > 0 else "\u00b7"
    placed_color = "y" if placed_n > 0 else "d"
    lines.append(
        "\u2551  " + I["pkg"] + " open " + c("m", str(open_n)) + "  "
        + I["win"] + " settled " + c("c", str(settled_n)) + "  "
        + placed_icon + " placed " + c(placed_color, str(placed_n)) + "\u2551"
    )

    lines.append("\u2560" + "\u2550" * 62 + "\u2563")

    if last_pair:
        a_dir = I["bull"] if last_pair.bet_a.direction == "bullish" else I["bear"]
        b_dir = I["bull"] if last_pair.bet_b.direction == "bullish" else I["bear"]
        si = I["fire"] if last_pair.hedge_score >= 1.0 else (I["star"] if last_pair.hedge_score >= 0.7 else I["dice"])
        ri = I["rocket"] if last_pair.payout_ratio >= 20 else (I["gem"] if last_pair.payout_ratio >= 10 else I["zap"])

        lines.append(
            "\u2551  " + si + " " + c("m", "{:.4f}".format(last_pair.hedge_score)) + "  "
            + a_dir + " " + last_pair.bet_a.side.upper() + " "
            + c("b", "${:,.0f}".format(last_pair.bet_a.strike))
            + "@" + c("y", "{}c".format(last_pair.bet_a.price_cents)) + "  \u00d7  "
            + b_dir + " " + last_pair.bet_b.side.upper() + " "
            + c("b", "${:,.0f}".format(last_pair.bet_b.strike))
            + "@" + c("y", "{}c".format(last_pair.bet_b.price_cents)) + "\u2551"
        )
        lines.append(
            "\u2551     P(\u22651) " + c("c", "{:.0%}".format(last_pair.joint_win_prob))
            + "  \u2502  min " + c("g", "${:.0f}".format(last_pair.min_payout))
            + "  max " + c("g", "${:.0f}".format(last_pair.max_payout))
            + "  \u2502  " + ri + " " + c("g", "{:.0f}x".format(last_pair.payout_ratio)) + "\u2551"
        )

    open_pos = pilot.get_open_positions()
    if open_pos:
        lines.append("\u2560" + horz + "\u2563")
        lines.append("\u2551  " + I["pkg"] + " " + c("B", "OPEN POSITIONS") + " (" + str(len(open_pos)) + ")" + "\u2551")
        for pos in open_pos[-5:]:
            da = I["bull"] if pos.side_a == "yes" else I["bear"]
            db = I["bull"] if pos.side_b == "yes" else I["bear"]
            lines.append(
                "\u2551  #" + str(pos.pos_id) + " " + da + " " + pos.side_a.upper() + " "
                + "${:,.0f}".format(pos.strike_a) + "@" + str(int(pos.price_a * 100)) + "c + "
                + db + " " + pos.side_b.upper() + " "
                + "${:,.0f}".format(pos.strike_b) + "@" + str(int(pos.price_b * 100)) + "c  "
                + "${:.2f}".format(pos.total_cost) + "\u2551"
            )
        if len(open_pos) > 5:
            lines.append("\u2551  " + dim("... and " + str(len(open_pos) - 5) + " more") + "\u2551")

    recent = pilot.get_recent_settlements(3)
    if recent:
        lines.append("\u2560" + horz + "\u2563")
        lines.append("\u2551  " + I["target"] + " " + c("B", "RECENT SETTLEMENTS") + "\u2551")
        for pos in recent:
            oa = I["win"] if pos.outcome_a == "won" else I["lose"]
            ob = I["win"] if pos.outcome_b == "won" else I["lose"]
            pc = "g" if pos.pnl >= 0 else "r"
            ps = "+${:.2f}".format(pos.pnl) if pos.pnl >= 0 else "-${:.2f}".format(abs(pos.pnl))
            lines.append(
                "\u2551  #" + str(pos.pos_id) + " " + oa + " " + ob + "  " + c(pc, ps) + "  \u2502  "
                + pos.side_a.upper() + " ${:,.0f}".format(pos.strike_a) + " + "
                + pos.side_b.upper() + " ${:,.0f}".format(pos.strike_b) + "\u2551"
            )

    if status["stopped"]:
        lines.append("\u2560" + horz + "\u2563")
        lines.append("\u2551  " + I["stop"] + " " + c("r", "STOPPED") + ": " + status["stopped_reason"] + "\u2551")
    else:
        interval = pilot.cfg.scan_interval_seconds
        lines.append("\u2560" + horz + "\u2563")
        lines.append(
            "\u2551  " + I["clock"] + " next scan in " + dim(str(interval) + "s") + "  "
            + "\u2502  " + I["scan"] + " " + dim("#" + str(s["scans"])) + "  "
            + "\u2502  Ctrl+C to stop  \u2502  " + I["dice"] + " dry-run" + "\u2551"
        )

    lines.append("\u255a" + "\u2550" * 62 + "\u255d")
    return "\n".join(lines)




def run_autopilot(
    series_def,
    series_ticker: str,
    hedge_config: "HedgeConfig",
    pilot_config: AutopilotConfig | None = None,
    risk_config: "RiskConfig | None" = None,
) -> Autopilot:
    """Run the autopilot loop. Returns the final Autopilot state.

    Args:
        series_def: SeriesDef for the asset being traded
        series_ticker: Kalshi series ticker (e.g., 'KXBTCD')
        hedge_config: HedgeScanner configuration
        pilot_config: Autopilot configuration (scan interval, etc.)
        risk_config: Optional RiskManager config for drawdown/sizing controls
    """
    import sys
    from .feed import CryptoFeed
    from .client import KalshiClient
    from .engine import AnalysisEngine, EngineConfig
    from .hedge import HedgeScanner

    # Initialize risk manager (persistent state survives restarts)
    risk_manager = None
    resolver = None
    if risk_config is not None:
        from .risk import RiskManager
        risk_manager = RiskManager(risk_config)
        print(f"  Risk: ${risk_manager.state.balance:.2f} balance, "
              f"peak ${risk_manager.state.peak_balance:.2f}")

    # Initialize outcome resolver for calibration
    try:
        from .calibrate import OutcomeResolver
        client = KalshiClient()
        resolver = OutcomeResolver(client)
        resolved = resolver.resolve_pending()
        if resolved > 0:
            print(f"  Resolved {resolved} past bets from Kalshi")
    except Exception:
        resolver = None

    # Initialize strategy and empirical engine
    strategy = None
    empirical = None
    try:
        from .strategy import BetStrategy
        from .probability import EmpiricalProbability
        empirical = EmpiricalProbability()
        strategy = BetStrategy(resolver)
        print(f"  Strategy: {strategy.mode.value} mode ({strategy.status()['samples']} samples)")
    except Exception as e:
        print(f"  [WARN] Strategy unavailable: {e}")

    pilot = Autopilot(pilot_config, risk_manager, resolver, strategy)
    feed = CryptoFeed()
    interval = pilot.cfg.scan_interval_seconds
    last_pair: "HedgePair | None" = None

    print()
    print(f"  Starting autopilot v3 with ${pilot.balance:.2f}")
    if risk_manager:
        print(f"  Risk: max DD {risk_manager.cfg.max_drawdown_pct:.0%}, "
              f"min WR {risk_manager.cfg.min_win_rate:.0%}")
        print(f"  Bet: dynamic (${risk_manager.cfg.min_bet_dollars:.2f}–"
              f"${risk_manager.cfg.max_bet_dollars:.2f} per leg)")
    else:
        print(f"  Bet: ${pilot.cfg.bet_per_pair_dollars:.0f}/pair "
              f"(${pilot.cfg.bet_per_leg_dollars:.0f}/leg)")
    print(f"  Scan interval: {interval}s  |  Ctrl+C to stop")
    print()

    try:
        while True:
            # Fetch fresh data
            try:
                price = feed.get(
                    series_def.asset,
                    series_def.coingecko_id,
                    series_def.binance_symbol,
                    force_fresh=pilot.cfg.force_fresh,
                )
                from .volatility import get_volatility as gv
                vol = gv(series_def.asset, series_def.binance_symbol)
            except Exception:
                vol = 0.60

            client = KalshiClient()
            markets_raw = client.get_markets(
                series_ticker=series_ticker, status="open", limit=100)

            engine = AnalysisEngine(EngineConfig())
            parsed = [engine._parse_market(m) for m in markets_raw]
            valid = [m for m in parsed if m is not None]

            scanner = HedgeScanner(hedge_config, empirical=empirical)
            pairs = scanner.scan(valid, price.price_usd, vol, series_ticker)

            # Step the autopilot
            status = pilot.step(pairs, price.price_usd, vol)
            last_pair = pairs[0] if pairs else last_pair

            # Render dashboard
            dashboard = format_autopilot_dashboard(
                pilot, status, last_pair, price.price_usd, vol, series_def.asset)
            # Clear and redraw
            sys.stdout.write("\033[2J\033[H")  # clear screen, home cursor
            sys.stdout.write(dashboard + "\n")
            sys.stdout.flush()

            if status["stopped"]:
                print(f"\n  AUTOPILOT STOPPED: {status['stopped_reason']}")
                break

            _time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n  Autopilot interrupted after {pilot.stats['scans']} scans.")
        print(f"  Final balance: ${pilot.balance:,.2f}  |  P&L: ${pilot.total_pnl:+,.2f}")
        print(f"  Open: {len(pilot.positions)}  |  Settled: {len(pilot.settled_positions)}")

    return pilot
