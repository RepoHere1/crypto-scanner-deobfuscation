"""Outcome resolver and model calibration — the feedback loop.

Core insight: Black-Scholes binary pricing is the WRONG model for Kalshi
prediction markets. The market prices reflect real-world consensus, not
risk-neutral measures. Our raw model systematically overestimates tail
probabilities, making cheap "lottery ticket" bets look like great value.

This module fixes that by:
1. Fetching REAL settlement outcomes from Kalshi (not guessing)
2. Storing every resolved bet's predicted vs actual outcome
3. Building calibration curves: "when we said X%, what actually happened?"
4. Producing calibrated probabilities that converge toward reality

Usage:
    resolver = OutcomeResolver(client)
    resolver.resolve_pending()           # fetch outcomes for all unresolved bets
    cal = resolver.build_calibration()   # returns {bucket: (predicted_mean, actual_rate)}
    cal_prob = resolver.calibrate(raw_probability)  # adjust raw -> calibrated
"""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import KalshiClient

logger = logging.getLogger(__name__)

DB_PATH = os.path.expanduser("~/.kalshi/history.db")
CALIBRATION_PATH = os.path.expanduser("~/.kalshi/calibration.json")

# Minimum samples per bucket to trust the calibration
MIN_SAMPLES_PER_BUCKET = 5
# Minimum total samples before using calibration at all
MIN_TOTAL_SAMPLES = 20


# ---------------------------------------------------------------------------
# Calibration data model
# ---------------------------------------------------------------------------


@dataclass
class CalibrationBucket:
    """One probability bucket in the calibration curve."""
    bin_low: float          # lower bound of predicted prob (inclusive)
    bin_high: float         # upper bound (exclusive)
    count: int              # number of resolved bets in this bin
    predicted_mean: float   # average predicted probability
    actual_rate: float      # actual win rate (observed frequency)


@dataclass
class CalibrationCurve:
    """Complete calibration curve built from real settlement data."""
    buckets: list[CalibrationBucket]
    total_samples: int
    built_at: str           # ISO timestamp
    brier_score: float      # overall Brier score (lower = better calibrated)
    reliability: float      # how much we can trust this calibration (0..1)

    def lookup(self, raw_prob: float) -> float:
        """Calibrate a raw probability using this curve.

        Uses linear interpolation between bucket midpoints.
        Falls back to identity at extremes when data is sparse.
        """
        if not self.buckets or self.total_samples < MIN_TOTAL_SAMPLES:
            return raw_prob

        # Find the two nearest buckets and interpolate
        below = None
        above = None
        for b in self.buckets:
            mid = (b.bin_low + b.bin_high) / 2
            if mid <= raw_prob:
                below = b
            if mid >= raw_prob and above is None:
                above = b

        # Edge cases
        if below is None:
            return self._blend(raw_prob, above)
        if above is None:
            return self._blend(raw_prob, below)
        if below is above:
            return self._blend(raw_prob, below)

        # Interpolate between below and above
        mid_below = (below.bin_low + below.bin_high) / 2
        mid_above = (above.bin_low + above.bin_high) / 2
        if mid_above <= mid_below:
            return self._blend(raw_prob, below)

        frac = (raw_prob - mid_below) / (mid_above - mid_below)
        cal_below = self._blend(mid_below, below)
        cal_above = self._blend(mid_above, above)
        return cal_below + frac * (cal_above - cal_below)

    def _blend(self, raw: float, bucket: CalibrationBucket) -> float:
        """Blend raw probability toward the calibrated rate, weighted by
        sample count and reliability."""
        if bucket.count < 1:
            return raw
        # Weight: more samples -> trust calibration more
        weight = min(1.0, bucket.count / (MIN_SAMPLES_PER_BUCKET * 3))
        weight *= self.reliability
        return raw + weight * (bucket.actual_rate - raw)


# ---------------------------------------------------------------------------
# Outcome resolver
# ---------------------------------------------------------------------------


class OutcomeResolver:
    """Fetch real Kalshi settlement outcomes and update the history DB.

    This is the "ground truth" injection point. Without this, the model
    never learns whether it was right or wrong.
    """

    def __init__(self, client: "KalshiClient | None" = None, db_path: str = DB_PATH):
        self._client = client
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    @property
    def client(self) -> "KalshiClient":
        if self._client is None:
            from .client import KalshiClient
            self._client = KalshiClient()
        return self._client

    # --- Public API ---

    def seed_calibration(self, series_ticker: str = "KXBTCD", limit: int = 50) -> int:
        """Seed calibration by fetching SETTLED Kalshi markets and recording
        what the model WOULD have predicted vs what ACTUALLY happened.

        This breaks the cold-start deadlock: no trades -> no settlements ->
        no calibration -> no trades. By seeding from settled markets directly,
        we bootstrap the calibration curve without needing paper trades.

        Returns number of newly recorded predictions.
        """
        try:
            markets = self.client.get_markets(
                series_ticker=series_ticker, status="settled", limit=limit)
        except Exception as e:
            logger.warning("Failed to fetch settled markets: %s", e)
            return 0

        if not markets:
            logger.info("No settled markets found for %s", series_ticker)
            return 0

        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        recorded = 0

        from .engine import AnalysisEngine, EngineConfig
        engine = AnalysisEngine(EngineConfig())

        for raw in markets:
            ticker = raw.get("ticker", "")
            if not ticker:
                continue

            # Skip if we already have this ticker resolved
            existing = conn.execute(
                "SELECT COUNT(*) FROM recommendations WHERE ticker=? AND resolved=1",
                (ticker,)).fetchone()[0]
            if existing > 0:
                continue

            outcome = (raw.get("yes_outcome") or raw.get("result") or "").lower()
            if not outcome:
                continue

            # Extract strike and side info from the market
            close_str = raw.get("close_time", "")
            strike = float(raw.get("floor_strike", 0))
            yes_bid = float(raw.get("yes_bid_dollars", 0))
            yes_ask = float(raw.get("yes_ask_dollars", 0))

            # Compute what BS model would have predicted
            # We don't have the exact spot at close time, so we estimate
            mid_price = (yes_bid + yes_ask) / 2 if (yes_bid > 0 and yes_ask > 0) else 0.5
            # Use mid as a rough true_prob estimate since we lack historical spot
            true_prob = mid_price if mid_price > 0 else 0.5

            # Record YES side
            conn.execute(
                "INSERT INTO recommendations "
                "(run_id, ticker, title, strike, side, price, market_prob, "
                " true_prob, expected_value, kelly_fraction, contracts, cost, "
                " confidence, resolved, actual_outcome, pnl) "
                "VALUES (-1, ?, ?, ?, 'yes', ?, ?, ?, 0, 0, 0, 0, 'seeded', 1, ?, 0)",
                (ticker, raw.get("title", ""), strike,
                 yes_ask if yes_ask > 0 else 0.5,
                 true_prob, true_prob, outcome))

            # Record NO side
            conn.execute(
                "INSERT INTO recommendations "
                "(run_id, ticker, title, strike, side, price, market_prob, "
                " true_prob, expected_value, kelly_fraction, contracts, cost, "
                " confidence, resolved, actual_outcome, pnl) "
                "VALUES (-1, ?, ?, ?, 'no', ?, ?, ?, 0, 0, 0, 0, 'seeded', 1, ?, 0)",
                (ticker, raw.get("title", ""), strike,
                 1.0 - (yes_ask if yes_ask > 0 else 0.5),
                 1.0 - true_prob, 1.0 - true_prob, outcome))

            recorded += 2

        conn.commit()
        conn.close()

        if recorded > 0:
            logger.info("Seeded %d calibration records from %d settled markets",
                       recorded, len(markets))

        return recorded

    def resolve_pending(self) -> int:
        """Fetch outcomes for all unresolved recommendations in the DB.

        Returns number of newly resolved bets.
        """
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")

        # Get all unique tickers from unresolved recommendations
        all_tickers = self._unresolved_tickers(conn)
        if not all_tickers:
            conn.close()
            return 0

        # Skip tickers checked recently (avoid re-checking stale old-analysis tickers)
        now = time.time()
        if not hasattr(self, '_ticker_checked_at'):
            self._ticker_checked_at: dict[str, float] = {}
        tickers = [t for t in all_tickers
                   if now - self._ticker_checked_at.get(t, 0) > 300]
        if not tickers:
            conn.close()
            return 0

        # Mark as checked
        for t in tickers:
            self._ticker_checked_at[t] = now

        logger.debug("Checking outcomes for %d tickers (%d skipped, checked recently)...",
                    len(tickers), len(all_tickers) - len(tickers))

        # Fetch outcomes from Kalshi, respecting rate limits
        outcomes: dict[str, str] = {}
        for i, ticker in enumerate(tickers):
            outcome = self._fetch_outcome(ticker)
            if outcome:
                outcomes[ticker] = outcome
            if i > 0 and i % 10 == 0:
                time.sleep(0.15)  # gentle rate limit: ~6 req/s

        # Update DB
        resolved = 0
        for ticker, outcome in outcomes.items():
            resolved += self._record_outcome(conn, ticker, outcome)

        conn.commit()
        conn.close()
        if resolved > 0:
            logger.info("Resolved %d recommendations (%d tickers checked)", resolved, len(tickers))
        else:
            logger.debug("No resolutions (%d tickers checked, no settled markets yet)", len(tickers))
        return resolved

    def build_calibration(self) -> CalibrationCurve:
        """Build a calibration curve from all resolved recommendations.

        Returns a CalibrationCurve that can be used to adjust raw model
        probabilities toward observed reality.
        """
        conn = sqlite3.connect(self._db_path)

        rows = conn.execute(
            "SELECT true_prob, actual_outcome FROM recommendations "
            "WHERE resolved = 1 AND actual_outcome IS NOT NULL"
        ).fetchall()

        conn.close()

        if len(rows) < MIN_TOTAL_SAMPLES:
            if not getattr(self, '_warned_cal', False):
                logger.warning(
                    "Only %d resolved samples (need %d). Calibration unreliable.",
                    len(rows), MIN_TOTAL_SAMPLES,
                )
                self._warned_cal = True
            return CalibrationCurve(
                buckets=[],
                total_samples=len(rows),
                built_at=datetime.now(timezone.utc).isoformat(),
                brier_score=float("inf"),
                reliability=0.0,
            )

        # Bin by predicted probability (10 bins: 0-0.1, 0.1-0.2, ...)
        bins: dict[int, list[tuple[float, int]]] = defaultdict(list)
        for true_prob_str, outcome_str in rows:
            p = float(true_prob_str)
            won = 1 if (outcome_str or "").lower() == "yes" else 0
            bin_idx = min(9, int(p * 10))
            bins[bin_idx].append((p, won))

        buckets: list[CalibrationBucket] = []
        total_se = 0.0  # sum of squared errors for Brier score

        for bin_idx in range(10):
            samples = bins.get(bin_idx, [])
            if not samples:
                continue
            probs = [s[0] for s in samples]
            wins = [s[1] for s in samples]
            count = len(samples)
            pred_mean = sum(probs) / count
            actual_rate = sum(wins) / count

            for p, w in samples:
                total_se += (p - w) ** 2

            buckets.append(CalibrationBucket(
                bin_low=bin_idx / 10,
                bin_high=(bin_idx + 1) / 10,
                count=count,
                predicted_mean=round(pred_mean, 4),
                actual_rate=round(actual_rate, 4),
            ))

        brier = total_se / len(rows)
        # Reliability: how much we trust this calibration
        # More samples + better Brier (lower) = more trust
        # Also check monotonicity: actual rates should increase with predicted
        mono = self._check_monotonicity(buckets)
        reliability = min(1.0,
            (len(rows) / 100) *           # 0→1 as samples approach 100
            max(0, 1 - brier) *           # 1→0 as Brier worsens (0.25 is random)
            mono                           # 0 or 1 depending on monotonicity
        )
        reliability = round(reliability, 3)

        curve = CalibrationCurve(
            buckets=buckets,
            total_samples=len(rows),
            built_at=datetime.now(timezone.utc).isoformat(),
            brier_score=round(brier, 4),
            reliability=reliability,
        )

        # Persist to disk for offline use
        self._save_curve(curve)

        logger.info(
            "Calibration built: %d samples, Brier=%.4f, reliability=%.3f",
            len(rows), brier, reliability,
        )
        for b in buckets:
            logger.debug(
                "  bin [%.1f-%.1f): n=%d pred=%.3f actual=%.3f",
                b.bin_low, b.bin_high, b.count, b.predicted_mean, b.actual_rate,
            )

        return curve

    def calibrate(self, raw_prob: float) -> float:
        """Calibrate a single raw probability using the persisted curve."""
        curve = self._load_curve()
        if curve is None:
            curve = self.build_calibration()
        return curve.lookup(raw_prob)

    # --- Internal ---

    def _unresolved_tickers(self, conn: sqlite3.Connection) -> list[str]:
        """Get distinct tickers from unresolved recommendations."""
        rows = conn.execute(
            "SELECT DISTINCT ticker FROM recommendations WHERE resolved = 0"
        ).fetchall()
        return [r[0] for r in rows]

    def _fetch_outcome(self, ticker: str) -> str | None:
        """Fetch settlement outcome for a single ticker from Kalshi."""
        try:
            data = self.client.get(f"/markets/{ticker}")
            market = data.get("market", data)
            status = market.get("status", "")

            if status not in ("settled", "closed", "resolved"):
                return None  # Not yet settled

            outcome = market.get("yes_outcome") or market.get("result") or ""
            return outcome.lower() if outcome else None
        except Exception as e:
            logger.debug("Failed to fetch outcome for %s: %s", ticker, e)
            return None

    def _record_outcome(self, conn: sqlite3.Connection, ticker: str, outcome: str) -> int:
        """Record a settlement outcome for all recommendations with this ticker.

        Returns number of recommendations updated.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Update all recommendations with this ticker
        rows = conn.execute(
            "SELECT id, side, cost FROM recommendations WHERE ticker = ? AND resolved = 0",
            (ticker,),
        ).fetchall()

        count = 0
        for rec_id, side, cost in rows:
            cost_val = float(cost or 0)
            won = (
                (side == "yes" and outcome == "yes") or
                (side == "no" and outcome == "no")
            )
            pnl = round((1.0 - cost_val) if won else (-cost_val), 4)

            conn.execute(
                "UPDATE recommendations SET resolved = 1, actual_outcome = ?, pnl = ? "
                "WHERE id = ?",
                (outcome, pnl, rec_id),
            )
            count += 1

        # Also update the outcomes table
        conn.execute(
            "INSERT OR REPLACE INTO outcomes (ticker, resolved_value, resolved_at, checked_at) "
            "VALUES (?, ?, ?, ?)",
            (ticker, outcome, now, now),
        )

        return count

    @staticmethod
    def _check_monotonicity(buckets: list[CalibrationBucket]) -> float:
        """Check if actual rates are monotonically increasing with predicted.

        Returns 1.0 if monotonic, a penalty otherwise.
        """
        if len(buckets) < 3:
            return 1.0
        rates = [b.actual_rate for b in buckets]
        inversions = 0
        pairs = 0
        for i in range(len(rates)):
            for j in range(i + 1, len(rates)):
                pairs += 1
                if rates[i] > rates[j]:
                    inversions += 1
        if pairs == 0:
            return 1.0
        # Kendall-like: fewer inversions = more monotonic
        tau = 1 - 2 * inversions / pairs
        return max(0.0, tau)

    def _save_curve(self, curve: CalibrationCurve) -> None:
        """Persist calibration curve to disk."""
        try:
            data = {
                "built_at": curve.built_at,
                "total_samples": curve.total_samples,
                "brier_score": curve.brier_score,
                "reliability": curve.reliability,
                "buckets": [
                    {
                        "bin_low": b.bin_low,
                        "bin_high": b.bin_high,
                        "count": b.count,
                        "predicted_mean": b.predicted_mean,
                        "actual_rate": b.actual_rate,
                    }
                    for b in curve.buckets
                ],
            }
            os.makedirs(os.path.dirname(CALIBRATION_PATH), exist_ok=True)
            with open(CALIBRATION_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.warning("Failed to save calibration: %s", e)

    def _load_curve(self) -> CalibrationCurve | None:
        """Load persisted calibration curve from disk."""
        try:
            if not os.path.exists(CALIBRATION_PATH):
                return None
            with open(CALIBRATION_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            if data.get("total_samples", 0) < MIN_TOTAL_SAMPLES:
                return None

            return CalibrationCurve(
                buckets=[
                    CalibrationBucket(
                        bin_low=b["bin_low"],
                        bin_high=b["bin_high"],
                        count=b["count"],
                        predicted_mean=b["predicted_mean"],
                        actual_rate=b["actual_rate"],
                    )
                    for b in data.get("buckets", [])
                ],
                total_samples=data["total_samples"],
                built_at=data["built_at"],
                brier_score=data["brier_score"],
                reliability=data["reliability"],
            )
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.debug("Failed to load calibration: %s", e)
            return None
