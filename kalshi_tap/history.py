"""Analysis history and paper-trading P&L tracker.

Persists every analysis run (dry or live) in SQLite so you can:
- Review past recommendations and their accuracy
- Track paper-trading P&L: what WOULD have happened
- Study which market conditions produced the best EV
- Build factual stats over time — no guessing, just data

Schema:
    analysis_runs   — one row per engine run (timestamp, series, spot, vol, totals)
    recommendations — one row per recommended bet, linked to its run
    outcomes        — resolved market outcomes (fetched from Kalshi after settlement)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import BetRecommendation

logger = logging.getLogger(__name__)

DB_PATH = os.path.expanduser("~/.kalshi/history.db")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    series_ticker   TEXT NOT NULL,
    asset           TEXT NOT NULL,
    spot_price      REAL NOT NULL,
    volatility      REAL NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'dry',
    markets_fetched INTEGER NOT NULL DEFAULT 0,
    recs_found      INTEGER NOT NULL DEFAULT 0,
    recs_placed     INTEGER NOT NULL DEFAULT 0,
    total_risk      REAL NOT NULL DEFAULT 0.0,
    total_ev        REAL NOT NULL DEFAULT 0.0,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS recommendations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL,
    ticker          TEXT NOT NULL,
    title           TEXT NOT NULL,
    strike          REAL NOT NULL,
    side            TEXT NOT NULL,
    price           REAL NOT NULL,
    market_prob     REAL NOT NULL,
    true_prob       REAL NOT NULL,
    expected_value  REAL NOT NULL,
    kelly_fraction  REAL NOT NULL,
    contracts       INTEGER NOT NULL,
    cost            REAL NOT NULL,
    confidence      TEXT NOT NULL,
    resolved        INTEGER NOT NULL DEFAULT 0,
    actual_outcome  TEXT,
    pnl             REAL,
    FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
);

CREATE TABLE IF NOT EXISTS outcomes (
    ticker          TEXT PRIMARY KEY,
    resolved_value  TEXT,
    resolved_at     TEXT,
    checked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_recs_run ON recommendations(run_id);
CREATE INDEX IF NOT EXISTS idx_recs_ticker ON recommendations(ticker);
CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON analysis_runs(timestamp);
"""


# ---------------------------------------------------------------------------
# History store
# ---------------------------------------------------------------------------

class HistoryStore:
    """Persistent store for analysis history and paper-trading P&L."""

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # --- Write ---

    def record_run(
        self,
        series_ticker: str,
        asset: str,
        spot_price: float,
        volatility: float,
        mode: str,
        markets_fetched: int,
        recommendations: list["BetRecommendation"],
        recs_placed: int = 0,
    ) -> int:
        """Persist an analysis run and its recommendations. Returns run_id."""
        total_risk = sum(r.bet_dollars for r in recommendations)
        total_ev = sum(r.expected_value * r.bet_dollars for r in recommendations)

        cur = self._conn.execute(
            """INSERT INTO analysis_runs
               (timestamp, series_ticker, asset, spot_price, volatility, mode,
                markets_fetched, recs_found, recs_placed, total_risk, total_ev)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                series_ticker,
                asset,
                spot_price,
                volatility,
                mode,
                markets_fetched,
                len(recommendations),
                recs_placed,
                round(total_risk, 4),
                round(total_ev, 4),
            ),
        )
        run_id = cur.lastrowid

        for rec in recommendations:
            self._conn.execute(
                """INSERT INTO recommendations
                   (run_id, ticker, title, strike, side, price, market_prob,
                    true_prob, expected_value, kelly_fraction, contracts, cost, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    rec.market.ticker,
                    rec.market.title,
                    rec.market.strike,
                    rec.side,
                    round(rec.price, 4),
                    round(rec.market_prob, 4),
                    round(rec.true_prob, 4),
                    round(rec.expected_value, 4),
                    round(rec.kelly_fraction, 4),
                    rec.bet_contracts,
                    round(rec.bet_dollars, 4),
                    rec.confidence,
                ),
            )

        self._conn.commit()
        logger.debug("Recorded run %d: %d recs, $%.2f risk, EV $%.2f",
                      run_id, len(recommendations), total_risk, total_ev)
        return run_id

    def record_outcome(self, ticker: str, resolved_value: str) -> None:
        """Record a settled market outcome for P&L calculation."""
        self._conn.execute(
            """INSERT OR REPLACE INTO outcomes (ticker, resolved_value, resolved_at, checked_at)
               VALUES (?, ?, ?, ?)""",
            (ticker, resolved_value, datetime.now(timezone.utc).isoformat(),
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

        # Update P&L for paper trades
        self._conn.execute(
            """UPDATE recommendations
               SET resolved = 1,
                   actual_outcome = ?,
                   pnl = CASE
                       WHEN side = actual_outcome THEN cost * (1.0 / price - 1.0)
                       ELSE -cost
                   END
               WHERE ticker = ? AND resolved = 0""",
            (resolved_value, ticker),
        )
        self._conn.commit()

    # --- Read ---

    def get_recent_runs(self, limit: int = 20) -> list[dict]:
        """Get the most recent analysis runs."""
        rows = self._conn.execute(
            "SELECT * FROM analysis_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(zip([c[0] for c in self._conn.execute(
            "SELECT * FROM analysis_runs LIMIT 0").description], row))
            for row in rows]

    def get_run_recommendations(self, run_id: int) -> list[dict]:
        """Get recommendations for a specific run."""
        rows = self._conn.execute(
            "SELECT * FROM recommendations WHERE run_id = ? ORDER BY expected_value DESC",
            (run_id,),
        ).fetchall()
        return [dict(zip([c[0] for c in self._conn.execute(
            "SELECT * FROM recommendations LIMIT 0").description], row))
            for row in rows]

    def get_stats(self) -> dict:
        """Get aggregate statistics across all runs."""
        return {
            "total_runs": self._conn.execute(
                "SELECT COUNT(*) FROM analysis_runs").fetchone()[0],
            "total_dry_runs": self._conn.execute(
                "SELECT COUNT(*) FROM analysis_runs WHERE mode='dry'").fetchone()[0],
            "total_live_runs": self._conn.execute(
                "SELECT COUNT(*) FROM analysis_runs WHERE mode='live'").fetchone()[0],
            "total_recs": self._conn.execute(
                "SELECT COUNT(*) FROM recommendations").fetchone()[0],
            "resolved_recs": self._conn.execute(
                "SELECT COUNT(*) FROM recommendations WHERE resolved=1").fetchone()[0],
            "paper_pnl": self._conn.execute(
                "SELECT COALESCE(SUM(pnl), 0) FROM recommendations WHERE resolved=1"
            ).fetchone()[0] or 0.0,
            "avg_ev": self._conn.execute(
                "SELECT AVG(expected_value) FROM recommendations"
            ).fetchone()[0] or 0.0,
            "best_ev": self._conn.execute(
                "SELECT MAX(expected_value) FROM recommendations"
            ).fetchone()[0] or 0.0,
            "total_theoretical_risk": self._conn.execute(
                "SELECT COALESCE(SUM(total_risk), 0) FROM analysis_runs"
            ).fetchone()[0] or 0.0,
            "last_run_ts": self._conn.execute(
                "SELECT MAX(timestamp) FROM analysis_runs"
            ).fetchone()[0],
        }

    def get_confidence_accuracy(self) -> dict:
        """Calculate accuracy by confidence level (for resolved bets only)."""
        rows = self._conn.execute("""
            SELECT confidence, COUNT(*) as total,
                   SUM(CASE WHEN pnl > 0 THEN 1 ELSE 0 END) as wins,
                   AVG(pnl) as avg_pnl
            FROM recommendations
            WHERE resolved = 1
            GROUP BY confidence
        """).fetchall()
        return {
            row[0]: {"total": row[1], "wins": row[2], "win_rate": row[2] / row[1] if row[1] else 0, "avg_pnl": row[3]}
            for row in rows
        }

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Paper trading P&L resolver
# ---------------------------------------------------------------------------

def resolve_paper_trades(store: HistoryStore, client=None) -> int:
    """Check settled Kalshi markets and update paper P&L.

    Queries Kalshi for the resolution status of tickers in our history
    that haven't been resolved yet. Updates outcomes and P&L.
    Returns number of newly resolved outcomes.
    """
    if client is None:
        try:
            from .client import KalshiClient
            client = KalshiClient()
        except Exception as e:
            logger.warning("Cannot resolve outcomes: %s", e)
            return 0

    # Get unresolved tickers
    rows = store._conn.execute(
        "SELECT DISTINCT ticker FROM recommendations WHERE resolved = 0"
    ).fetchall()
    tickers = [r[0] for r in rows]

    if not tickers:
        return 0

    resolved_count = 0
    for ticker in tickers:
        try:
            # Fetch market settlement status from Kalshi
            # (The exact endpoint may vary; this is the V2 pattern)
            data = client.get(f"/markets/{ticker}")
            result = data.get("market", {}).get("result", "")
            if result and result != "":
                store.record_outcome(ticker, result)
                resolved_count += 1
                logger.info("Resolved %s → %s", ticker, result)
        except Exception as e:
            logger.debug("Could not resolve %s: %s", ticker, e)

    return resolved_count


# Singleton
_store: HistoryStore | None = None


def get_store() -> HistoryStore:
    global _store
    if _store is None:
        _store = HistoryStore()
    return _store
