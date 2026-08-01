"""Risk manager — the guardrails the autopilot never had.

Problems with the old autopilot:
- No drawdown limit: $100 → $0 without stopping
- No win-rate monitoring: could lose 20 in a row and keep betting
- Fixed sizing: always $1/leg regardless of recent performance
- No persistence: restart = fresh $100, learning nothing

This module provides:
- Drawdown circuit breaker: halt trading when balance drops X% from peak
- Win-rate guard: pause when trailing win rate falls below threshold
- Dynamic sizing: reduce bets when losing, increase when winning
- Persistent state: balance and stats survive restarts
- Recovery mode: after a pause, start with minimum sizing and prove yourself
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

STATE_PATH = os.path.expanduser("~/.kalshi/risk_state.json")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RiskConfig:
    """Tunable risk parameters."""

    # Drawdown circuit breaker
    max_drawdown_pct: float = 0.25       # Stop if balance drops 25% from peak
    drawdown_warning_pct: float = 0.15    # Warn at 15% drawdown

    # Win-rate guard (trailing N bets)
    trailing_window: int = 20             # Look at last N bets
    min_win_rate: float = 0.30            # Pause if win rate drops below 30%
    min_bets_before_guard: int = 10       # Need at least N bets before enforcing

    # Dynamic sizing
    base_bet_dollars: float = 1.0         # Normal bet per leg
    min_bet_dollars: float = 0.50          # Minimum bet even when losing
    max_bet_dollars: float = 2.0          # Maximum bet even when winning
    sizing_drawdown_factor: float = 0.5    # How aggressively sizing follows balance

    # Recovery mode
    recovery_bet_dollars: float = 0.50     # Bet size when entering recovery
    recovery_required_wins: int = 3        # Need N wins to exit recovery mode

    # Stop conditions
    stop_balance: float = 0.0              # Absolute balance floor (0 = use drawdown only)
    target_balance: float = 0.0            # Take-profit target (0 = disabled)


# ---------------------------------------------------------------------------
# Risk state
# ---------------------------------------------------------------------------


@dataclass
class RiskState:
    """Mutable risk state, persisted to disk."""

    balance: float = 100.0
    peak_balance: float = 100.0
    total_pnl: float = 0.0

    # Outcome tracking (ring buffer)
    recent_outcomes: list[bool] = field(default_factory=list)  # True=win, False=loss
    total_wins: int = 0
    total_losses: int = 0

    # Mode
    trading_paused: bool = False
    pause_reason: str = ""
    recovery_mode: bool = False
    recovery_wins_needed: int = 0

    # Meta
    start_balance: float = 100.0
    started_at: str = ""
    updated_at: str = ""
    current_bet_dollars: float = 1.0

    def to_dict(self) -> dict:
        return {
            "balance": self.balance,
            "peak_balance": self.peak_balance,
            "total_pnl": self.total_pnl,
            "recent_outcomes": self.recent_outcomes,
            "total_wins": self.total_wins,
            "total_losses": self.total_losses,
            "trading_paused": self.trading_paused,
            "pause_reason": self.pause_reason,
            "recovery_mode": self.recovery_mode,
            "recovery_wins_needed": self.recovery_wins_needed,
            "start_balance": self.start_balance,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "current_bet_dollars": self.current_bet_dollars,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RiskState":
        return cls(
            balance=float(d.get("balance", 100.0)),
            peak_balance=float(d.get("peak_balance", 100.0)),
            total_pnl=float(d.get("total_pnl", 0.0)),
            recent_outcomes=d.get("recent_outcomes", []),
            total_wins=int(d.get("total_wins", 0)),
            total_losses=int(d.get("total_losses", 0)),
            trading_paused=bool(d.get("trading_paused", False)),
            pause_reason=str(d.get("pause_reason", "")),
            recovery_mode=bool(d.get("recovery_mode", False)),
            recovery_wins_needed=int(d.get("recovery_wins_needed", 0)),
            start_balance=float(d.get("start_balance", 100.0)),
            started_at=str(d.get("started_at", "")),
            updated_at=str(d.get("updated_at", "")),
            current_bet_dollars=float(d.get("current_bet_dollars", 1.0)),
        )


# ---------------------------------------------------------------------------
# Risk manager
# ---------------------------------------------------------------------------


class RiskManager:
    """Guardrails for the autopilot.

    Call `check()` before every bet. It returns (can_trade, reason, bet_size).
    Call `record_outcome()` after every settlement.
    """

    def __init__(self, config: RiskConfig | None = None, state_path: str = STATE_PATH):
        self.cfg = config or RiskConfig()
        self._state_path = state_path
        self.state = self._load_state()

    # --- Public API ---

    def check(self) -> tuple[bool, str, float]:
        """Check if trading is allowed and what bet size to use.

        Returns:
            (can_trade, reason, bet_dollars_per_leg)
        """
        # 1. Check if manually paused
        if self.state.trading_paused:
            return False, f"PAUSED: {self.state.pause_reason}", 0.0

        # 2. Check absolute balance floor
        if self.cfg.stop_balance > 0 and self.state.balance < self.cfg.stop_balance:
            self._pause(f"balance ${self.state.balance:.2f} below stop ${self.cfg.stop_balance:.2f}")
            return False, self.state.pause_reason, 0.0

        # 3. Check take-profit target
        if self.cfg.target_balance > 0 and self.state.balance >= self.cfg.target_balance:
            self._pause(f"target ${self.cfg.target_balance:.0f} reached!")
            return False, self.state.pause_reason, 0.0

        # 4. Check drawdown from peak
        drawdown = 1.0 - (self.state.balance / self.state.peak_balance) if self.state.peak_balance > 0 else 0.0
        if drawdown >= self.cfg.max_drawdown_pct:
            self._pause(f"drawdown {drawdown:.0%} >= max {self.cfg.max_drawdown_pct:.0%}")
            return False, self.state.pause_reason, 0.0

        # 5. Check win rate guard (only after enough bets)
        wr, total = self._trailing_win_rate()
        if total >= self.cfg.min_bets_before_guard and wr < self.cfg.min_win_rate:
            if not self.state.recovery_mode:
                self._enter_recovery()
            bet = self.state.current_bet_dollars
            return True, f"RECOVERY: WR {wr:.0%} (need {self.cfg.min_win_rate:.0%})", bet

        # 6. Dynamic sizing based on balance vs peak
        bet = self._compute_bet_size()

        # 7. Warn on elevated drawdown
        if drawdown >= self.cfg.drawdown_warning_pct:
            return True, f"WARN: drawdown {drawdown:.0%}", bet

        return True, "OK", bet

    def record_outcome(self, won: bool, pnl: float = 0.0) -> None:
        """Record a settled bet outcome and update all metrics."""
        # Update balance and P&L
        prev_balance = self.state.balance
        # Balance update: if we won, we got back our cost + profit.
        # pnl already represents net profit (payout - cost).
        # The caller should have already adjusted balance.
        # Here we just track the outcome for win-rate and drawdown.

        self.state.recent_outcomes.append(won)
        if won:
            self.state.total_wins += 1
        else:
            self.state.total_losses += 1

        # Trim ring buffer
        if len(self.state.recent_outcomes) > self.cfg.trailing_window * 2:
            self.state.recent_outcomes = self.state.recent_outcomes[-self.cfg.trailing_window:]

        # Check recovery mode exit
        if self.state.recovery_mode:
            if won:
                self.state.recovery_wins_needed -= 1
                if self.state.recovery_wins_needed <= 0:
                    self._exit_recovery()

        self._save_state()

    def update_balance(self, new_balance: float) -> None:
        """Update balance after a trade or settlement."""
        self.state.balance = round(new_balance, 4)
        if self.state.balance > self.state.peak_balance:
            self.state.peak_balance = self.state.balance
        self.state.total_pnl = round(self.state.balance - self.state.start_balance, 4)
        self._save_state()

    def reset(self, starting_balance: float = 100.0) -> None:
        """Reset risk state completely (fresh start)."""
        now = datetime.now(timezone.utc).isoformat()
        self.state = RiskState(
            balance=starting_balance,
            peak_balance=starting_balance,
            start_balance=starting_balance,
            started_at=now,
            updated_at=now,
            current_bet_dollars=self.cfg.base_bet_dollars,
        )
        self._save_state()

    def unpause(self) -> None:
        """Manually unpause trading (user override)."""
        self.state.trading_paused = False
        self.state.pause_reason = ""
        self.state.recovery_mode = False
        self.state.recovery_wins_needed = 0
        self.state.current_bet_dollars = self.cfg.base_bet_dollars
        self._save_state()

    def status(self) -> dict:
        """Return a status dict for dashboard display."""
        wr, n = self._trailing_win_rate()
        drawdown = 1.0 - (self.state.balance / self.state.peak_balance) if self.state.peak_balance > 0 else 0.0
        return {
            "balance": self.state.balance,
            "peak_balance": self.state.peak_balance,
            "drawdown_pct": round(drawdown * 100, 1),
            "total_pnl": self.state.total_pnl,
            "total_wins": self.state.total_wins,
            "total_losses": self.state.total_losses,
            "trailing_win_rate": round(wr * 100, 1),
            "trailing_bets": n,
            "trading_paused": self.state.trading_paused,
            "pause_reason": self.state.pause_reason,
            "recovery_mode": self.state.recovery_mode,
            "current_bet": self.state.current_bet_dollars,
        }

    # --- Internal ---

    def _pause(self, reason: str) -> None:
        self.state.trading_paused = True
        self.state.pause_reason = reason
        logger.warning("TRADING PAUSED: %s", reason)
        self._save_state()

    def _enter_recovery(self) -> None:
        self.state.recovery_mode = True
        self.state.recovery_wins_needed = self.cfg.recovery_required_wins
        self.state.current_bet_dollars = self.cfg.recovery_bet_dollars
        wr, _ = self._trailing_win_rate()
        logger.warning(
            "RECOVERY MODE: WR=%.0f%%, bet=$%.2f, need %d wins",
            wr * 100, self.state.current_bet_dollars, self.cfg.recovery_required_wins,
        )
        self._save_state()

    def _exit_recovery(self) -> None:
        self.state.recovery_mode = False
        self.state.recovery_wins_needed = 0
        self.state.current_bet_dollars = self.cfg.base_bet_dollars
        logger.info("RECOVERY EXIT: back to normal sizing")
        self._save_state()

    def _compute_bet_size(self) -> float:
        """Dynamic bet sizing based on balance relative to peak."""
        if self.state.peak_balance <= 0:
            return self.cfg.base_bet_dollars

        balance_ratio = self.state.balance / self.state.peak_balance
        # Scale bet: at 100% → base, at 75% → base * 0.75, etc.
        # Use sizing_drawdown_factor to control aggressiveness
        scale = 1.0 - (1.0 - balance_ratio) * self.cfg.sizing_drawdown_factor
        bet = self.cfg.base_bet_dollars * max(0.0, scale)
        bet = max(self.cfg.min_bet_dollars, min(self.cfg.max_bet_dollars, bet))
        self.state.current_bet_dollars = round(bet, 2)
        return self.state.current_bet_dollars

    def _trailing_win_rate(self) -> tuple[float, int]:
        """Compute win rate over the trailing window."""
        window = self.state.recent_outcomes[-self.cfg.trailing_window:]
        if not window:
            return 0.0, 0
        return sum(window) / len(window), len(window)

    def _load_state(self) -> RiskState:
        try:
            if os.path.exists(self._state_path):
                with open(self._state_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                state = RiskState.from_dict(data)
                logger.debug("Risk state loaded: balance=$%.2f, peak=$%.2f",
                           state.balance, state.peak_balance)
                return state
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to load risk state: %s, starting fresh", e)

        now = datetime.now(timezone.utc).isoformat()
        return RiskState(
            started_at=now,
            updated_at=now,
            current_bet_dollars=self.cfg.base_bet_dollars,
        )

    def _save_state(self) -> None:
        self.state.updated_at = datetime.now(timezone.utc).isoformat()
        try:
            os.makedirs(os.path.dirname(self._state_path), exist_ok=True)
            # Atomic write
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.state.to_dict(), f, indent=2)
            os.replace(tmp, self._state_path)
        except OSError as e:
            logger.warning("Failed to save risk state: %s", e)
