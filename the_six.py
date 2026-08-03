#!/usr/bin/env python3
"""THE SIX — a daily 6-bet sports-style strategy for Kalshi prediction markets.

Philosophy:
  Every day, pick the most active series (the "sport").  Its open markets
  are the "games".  Each game has a favorite (higher probability) and an
  underdog (lower probability).  THE SIX places exactly 6 bets, each $1,
  covering every logical combination of favorites and underdogs.

The six bets:
  1.  THE TRAITOR  — all favorites, but ONE game flipped to underdog
  2.  THE INSURGENT — all underdogs, but ONE game flipped to favorite
  3.  THE CHAOS     — random favorite/underdog per game
  4.  THE CHALK     — all favorites, no exceptions
  5.  THE LONGSHOT  — all underdogs, no exceptions
  6.  THE SNIPER    — single game, favorite side only

Usage:
    python3 the_six.py                 # dry-run with simulated markets
    python3 the_six.py --live           # real Kalshi (requires auth)
    python3 the_six.py --series KXETHD  # pick a specific series
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Market data model — mirrors Kalshi structure
# ---------------------------------------------------------------------------

@dataclass
class Game:
    """A single prediction market — one "game" in today's slate."""
    ticker: str
    title: str
    strike: float
    close_time: str
    yes_bid: float
    yes_ask: float
    no_bid: float
    no_ask: float

    @property
    def favored_side(self) -> str:
        """Which side is the favorite? 'yes' or 'no'."""
        return "yes" if self.yes_ask >= 0.50 else "no"

    @property
    def underdog_side(self) -> str:
        """Which side is the underdog?"""
        return "no" if self.favored_side == "yes" else "yes"

    @property
    def favored_price(self) -> float:
        """Price of the favored side (0.01–0.99)."""
        return self.yes_ask if self.favored_side == "yes" else self.no_ask

    @property
    def underdog_price(self) -> float:
        """Price of the underdog side."""
        return self.no_ask if self.favored_side == "yes" else self.yes_ask

    @property
    def favored_label(self) -> str:
        side = self.favored_side
        price = self.favored_price
        return f"{side.upper()} @ {price*100:.0f}c"

    @property
    def underdog_label(self) -> str:
        side = self.underdog_side
        price = self.underdog_price
        return f"{side.upper()} @ {price*100:.0f}c"

    def pick(self, side: str) -> tuple[str, float]:
        """Return (side_label, price) for a given side."""
        if side == "yes":
            return ("YES", self.yes_ask)
        return ("NO", self.no_ask)


# ---------------------------------------------------------------------------
# THE SIX strategy
# ---------------------------------------------------------------------------

@dataclass
class SixBet:
    """One of THE SIX bets."""
    name: str
    number: int
    description: str
    picks: list[dict] = field(default_factory=list)  # [{ticker, side, price, label}]
    total_cost: float = 1.00
    cost_per_pick: float = 0.0


class TheSix:
    """THE SIX daily betting strategy engine."""

    def __init__(self, games: list[Game], seed: int | None = None):
        if len(games) < 2:
            raise ValueError("THE SIX needs at least 2 games (open markets) today.")
        self.games = games
        self.rng = random.Random(seed)
        self.bets: list[SixBet] = []

    # ------------------------------------------------------------------
    # Bet builders
    # ------------------------------------------------------------------

    def _make_bet(self, number: int, name: str, desc: str, sides: list[str]) -> SixBet:
        """Build a SixBet from a list of side choices ('yes'/'no' per game)."""
        picks = []
        for game, side in zip(self.games, sides):
            label, price = game.pick(side)
            picks.append({
                "ticker": game.ticker,
                "strike": game.strike,
                "title": game.title[:50],
                "side": label,
                "price": price,
                "favored": "⭐" if side == game.favored_side else "🐶",
            })
        cost_per = round(1.00 / len(picks), 4) if picks else 0
        return SixBet(
            name=name, number=number, description=desc,
            picks=picks, total_cost=1.00, cost_per_pick=cost_per,
        )

    # --- Bet 1: THE TRAITOR ---
    def bet_traitor(self) -> SixBet:
        """All favorites except ONE random game flipped to underdog."""
        sides = [g.favored_side for g in self.games]
        traitor_idx = self.rng.randrange(len(self.games))
        sides[traitor_idx] = self.games[traitor_idx].underdog_side
        g = self.games[traitor_idx]
        desc = f"All favorites except {g.ticker} ({g.strike}) flipped to {g.underdog_side.upper()}"
        return self._make_bet(1, "THE TRAITOR", desc, sides)

    # --- Bet 2: THE INSURGENT ---
    def bet_insurgent(self) -> SixBet:
        """All underdogs except ONE random game flipped to favorite."""
        sides = [g.underdog_side for g in self.games]
        hero_idx = self.rng.randrange(len(self.games))
        sides[hero_idx] = self.games[hero_idx].favored_side
        g = self.games[hero_idx]
        desc = f"All underdogs except {g.ticker} ({g.strike}) flipped to {g.favored_side.upper()}"
        return self._make_bet(2, "THE INSURGENT", desc, sides)

    # --- Bet 3: THE CHAOS ---
    def bet_chaos(self) -> SixBet:
        """Random pick (favored or underdog) for each game."""
        sides = [self.rng.choice([g.favored_side, g.underdog_side]) for g in self.games]
        fav_count = sum(1 for i, s in enumerate(sides) if s == self.games[i].favored_side)
        dog_count = len(self.games) - fav_count
        desc = f"Random per game — {fav_count} favorites, {dog_count} underdogs"
        return self._make_bet(3, "THE CHAOS", desc, sides)

    # --- Bet 4: THE CHALK ---
    def bet_chalk(self) -> SixBet:
        """All favorites, no exceptions."""
        sides = [g.favored_side for g in self.games]
        return self._make_bet(4, "THE CHALK", "All favorites — chalk parade", sides)

    # --- Bet 5: THE LONGSHOT ---
    def bet_longshot(self) -> SixBet:
        """All underdogs, no exceptions."""
        sides = [g.underdog_side for g in self.games]
        return self._make_bet(5, "THE LONGSHOT", "All underdogs — chaos ticket", sides)

    # --- Bet 6: THE SNIPER ---
    def bet_sniper(self) -> SixBet:
        """Single game, favorite side only — pick the game with the strongest favorite."""
        # Strongest favorite = highest favored_price (closest to $1.00)
        best_idx = max(range(len(self.games)), key=lambda i: self.games[i].favored_price)
        g = self.games[best_idx]
        label, price = g.pick(g.favored_side)
        pick = {
            "ticker": g.ticker, "strike": g.strike, "title": g.title[:50],
            "side": label, "price": price, "favored": "⭐",
        }
        desc = f"Single snipe: {g.ticker} {g.favored_side.upper()} @ {price*100:.0f}c"
        return SixBet(
            name="THE SNIPER", number=6, description=desc,
            picks=[pick], total_cost=1.00, cost_per_pick=1.00,
        )

    # ------------------------------------------------------------------
    # Run all six
    # ------------------------------------------------------------------

    def run(self) -> list[SixBet]:
        """Generate all six bets."""
        self.bets = [
            self.bet_traitor(),
            self.bet_insurgent(),
            self.bet_chaos(),
            self.bet_chalk(),
            self.bet_longshot(),
            self.bet_sniper(),
        ]
        return self.bets


# ---------------------------------------------------------------------------
# Simulated markets for dry-run (no auth needed)
# ---------------------------------------------------------------------------

def simulate_todays_games(series_label: str = "BTC", num_games: int = 8) -> list[Game]:
    """Generate realistic-looking prediction markets for dry-run testing.

    Each "game" is a strike-level binary option: Will {asset} be above ${strike} today?
    Prices are derived from a spot price + normal distribution, producing a natural
    mix of favorites (high probability) and underdogs (low probability).
    """
    rng = random.Random(42)  # fixed seed for reproducibility

    if series_label.upper() == "BTC":
        spot = 87500.0
        unit = "$"
        step = 500.0
    elif series_label.upper() == "ETH":
        spot = 1950.0
        unit = "$"
        step = 50.0
    elif series_label.upper() == "SOL":
        spot = 128.0
        unit = "$"
        step = 5.0
    else:
        spot = 100.0
        unit = "$"
        step = 5.0

    games = []
    for i in range(num_games):
        strike = spot + (i - num_games // 2) * step
        # Probability the asset closes above strike — use a logistic-style curve
        # centered at spot with some noise
        z = (strike - spot) / (spot * 0.03)  # ~3% daily vol
        prob = 1.0 / (1.0 + 2.71828 ** z)  # sigmoid
        prob += rng.uniform(-0.08, 0.08)
        prob = max(0.02, min(0.98, prob))

        yes_ask = round(prob, 2)
        yes_bid = round(max(0.01, yes_ask - 0.02), 2)
        no_ask = round(1.0 - yes_bid, 2)
        no_bid = round(max(0.01, no_ask - 0.02), 2)

        close_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59Z")
        ticker = f"{series_label.upper()}-{strike:.0f}"

        games.append(Game(
            ticker=ticker,
            title=f"{series_label} above {unit}{strike:,.0f} today?",
            strike=strike,
            close_time=close_ts,
            yes_bid=yes_bid,
            yes_ask=yes_ask,
            no_bid=no_bid,
            no_ask=no_ask,
        ))

    # Sort by strike for clean display
    games.sort(key=lambda g: g.strike)
    return games


def fetch_real_games(series_ticker: str = "KXBTCD") -> list[Game]:
    """Fetch real open markets from Kalshi (requires auth)."""
    try:
        from kalshi_tap.client import KalshiClient
        client = KalshiClient()
        markets = client.get_markets(series_ticker=series_ticker, status="open")
    except Exception as e:
        print(f"[FAIL] Kalshi auth: {e}")
        print("       Falling back to simulated markets...")
        return simulate_todays_games()

    games = []
    for m in markets:
        try:
            games.append(Game(
                ticker=m.get("ticker", "?"),
                title=m.get("title", "?"),
                strike=float(m.get("strike", 0)),
                close_time=m.get("close_time", m.get("settlement_cutoff", "")),
                yes_bid=float(m.get("yes_bid", 0)),
                yes_ask=float(m.get("yes_ask", 0)),
                no_bid=float(m.get("no_bid", 0)),
                no_ask=float(m.get("no_ask", 0)),
            ))
        except (ValueError, TypeError):
            continue

    if len(games) < 2:
        print(f"[WARN] Only {len(games)} markets — need ≥2. Simulating fallback.")
        return simulate_todays_games()

    games.sort(key=lambda g: g.strike)
    return games


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

B = "\033[1m"
R = "\033[0m"
CY = "\033[96m"
GR = "\033[92m"
YE = "\033[93m"
MG = "\033[95m"
RD = "\033[91m"
BL = "\033[94m"
WH = "\033[97m"
DIM = "\033[2m"


def print_header(games: list[Game], series_label: str, live: bool):
    mode = f"{RD}LIVE{R}" if live else f"{CY}DRY-RUN{R}"
    fav_count = sum(1 for g in games if g.favored_side == "yes")
    dog_count = len(games) - fav_count
    print()
    print(f"{'='*66}")
    print(f"  {B}{WH}THE SIX{R} — {mode}  |  {series_label}  |  {len(games)} games today")
    print(f"  {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}{R}")
    print(f"  {GR}{fav_count} favorites{R} (YES)  |  {RD}{dog_count} underdogs{R} (NO)")
    print(f"{'='*66}")
    print()
    print(f"  {'Game':<18s} {'Strike':>10s}  {'YES':>8s}  {'NO':>8s}  {'Call':>12s}")
    print(f"  {'─'*18}  {'─'*10}  {'─'*8}  {'─'*8}  {'─'*12}")
    for g in games:
        call = f"{GR}FAVORED{R}" if g.favored_side == "yes" else f"{RD}UNDERDOG{R}"
        print(f"  {g.ticker:<18s} {g.strike:>10,.0f}  {g.yes_ask*100:>6.0f}c YES  {g.no_ask*100:>6.0f}c NO  {call}")
    print()


def print_bet(bet: SixBet):
    color = [None, CY, MG, YE, GR, RD, BL][bet.number]
    print(f"  {color}{B}BET {bet.number}: {bet.name}{R}")
    print(f"  {DIM}{bet.description}{R}")
    print(f"  {'─'*62}")
    for p in bet.picks:
        icon = p["favored"]
        print(f"    {icon} {p['ticker']:<18s} {p['side']:<4s} @ {p['price']*100:>5.0f}c  "
              f"({bet.cost_per_pick:.2f}¢)")
    print(f"  {'─'*62}")
    print(f"  {B}Total: ${bet.total_cost:.2f}{R}  |  {len(bet.picks)} legs  |  "
          f"{bet.cost_per_pick*100:.1f}¢ per leg")
    print()


def print_summary(bets: list[SixBet]):
    print(f"  {'='*66}")
    print(f"  {B}{WH}THE SIX — SUMMARY{R}")
    print(f"  {'='*66}")
    print()
    total_spent = sum(b.total_cost for b in bets)
    print(f"  Total laid:  ${total_spent:.2f} across {len(bets)} bets")
    print(f"  Total legs:  {sum(len(b.picks) for b in bets)}")
    print()
    print(f"  {DIM}All prices shown are ASK (what you'd pay to enter).{R}")
    print(f"  {DIM}Payouts determined at settlement. Run with --live to place real orders.{R}")
    print()


# ---------------------------------------------------------------------------
# State management — institute / pause / resume
# ---------------------------------------------------------------------------

import json
import os
from datetime import date, timedelta

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".six_state.json")


@dataclass
class SixDay:
    """One day's worth of THE SIX."""
    date: str                          # "2026-08-03"
    series: str                        # "KXBTCD"
    live: bool
    games: list[dict]                  # serialized Game list
    bets: list[dict]                   # serialized SixBet list
    status: str = "pending"            # pending | placed | settled
    placed_at: str = ""
    settled_at: str = ""


def _serialize_bet(bet: SixBet) -> dict:
    return {
        "name": bet.name, "number": bet.number, "description": bet.description,
        "picks": bet.picks, "total_cost": bet.total_cost,
        "cost_per_pick": bet.cost_per_pick,
    }


def _serialize_game(g: Game) -> dict:
    return {
        "ticker": g.ticker, "title": g.title, "strike": g.strike,
        "close_time": g.close_time,
        "yes_bid": g.yes_bid, "yes_ask": g.yes_ask,
        "no_bid": g.no_bid, "no_ask": g.no_ask,
    }


def _deserialize_games(raw: list[dict]) -> list[Game]:
    return [Game(**g) for g in raw]


def load_state() -> dict:
    """Load institute state from disk."""
    if not os.path.exists(STATE_FILE):
        return {"days": {}, "paused_until": ""}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"days": {}, "paused_until": ""}


def save_state(state: dict) -> None:
    """Persist institute state."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def institute(series: str, live: bool, num_games: int) -> dict:
    """Generate today's SIX + tomorrow's SIX.  Only ever 1 day ahead.

    Returns the updated state dict.
    """
    state = load_state()
    today_str = date.today().isoformat()
    tomorrow_str = (date.today() + timedelta(days=1)).isoformat()

    # Check if already instituted for today
    if today_str in state.get("days", {}):
        print(f"[SKIP] {today_str} already instituted.")
    else:
        _generate_day(state, today_str, series, live, num_games)

    # Tomorrow — only if today not yet settled
    today_status = state.get("days", {}).get(today_str, {}).get("status", "pending")
    if today_status == "settled":
        print(f"[SKIP] Today ({today_str}) already settled — nothing to institute.")
    elif tomorrow_str not in state.get("days", {}):
        _generate_day(state, tomorrow_str, series, live, num_games)
        # Pause after tomorrow — only 1 day ahead
        state["paused_until"] = today_str
        print(f"\n{'─'*66}")
        print(f"  {B}INSTITUTED{R}: today ({today_str}) + tomorrow ({tomorrow_str})")
        print(f"  {DIM}One day ahead only.  Paused until today's bets settle.{R}")
        print(f"  {DIM}Run: python3 the_six.py --watch   to check settlements.{R}")
        print(f"{'─'*66}")
    else:
        print(f"[PAUSED] Tomorrow ({tomorrow_str}) already queued. "
              f"Waiting for today's settlements.")

    save_state(state)
    return state


def _generate_day(state: dict, day_str: str, series: str, live: bool,
                  num_games: int) -> None:
    """Generate and store one day's SIX."""
    from datetime import datetime as dt

    if live:
        games = fetch_real_games(series)
    else:
        label_map = {
            "KXBTCD": "BTC", "KXETHD": "ETH", "KXSOLD": "SOL",
            "KXXRPD": "XRP", "KXDOGD": "DOGE", "KXADAD": "ADA",
        }
        label = label_map.get(series, "BTC")
        n = num_games or 8
        games = simulate_todays_games(series_label=label, num_games=n)

    if len(games) < 2:
        print(f"[FAIL] {day_str}: need ≥2 markets, got {len(games)}.")
        return

    seed = hash(day_str) & 0x7FFFFFFF
    six = TheSix(games, seed=seed)
    bets = six.run()

    series_label = games[0].ticker.split("-")[0] if games else "?"

    day = SixDay(
        date=day_str, series=series_label, live=live,
        games=[_serialize_game(g) for g in games],
        bets=[_serialize_bet(b) for b in bets],
        status="placed" if live else "pending",
        placed_at=dt.now(timezone.utc).isoformat() if live else "",
    )

    if "days" not in state:
        state["days"] = {}
    state["days"][day_str] = {
        "date": day.date, "series": day.series, "live": day.live,
        "games": day.games, "bets": day.bets, "status": day.status,
        "placed_at": day.placed_at, "settled_at": day.settled_at,
    }

    mode = f"{RD}LIVE{R}" if live else f"{CY}DRY-RUN{R}"
    print(f"\n{'='*66}")
    print(f"  {B}{WH}THE SIX{R} — {mode}  |  {day_str}  |  {series_label}  |  {len(games)} games")
    print(f"{'='*66}")

    # Print the bets
    for bet in bets:
        print_bet(bet)


def watch() -> int:
    """Check settlement state.  Unblock when today's bets are settled."""
    state = load_state()
    days = state.get("days", {})
    paused = state.get("paused_until", "")
    today_str = date.today().isoformat()

    if not days:
        print("[WATCH] No instituted days. Run --institute first.")
        return 1

    print(f"  {'='*66}")
    print(f"  {B}{WH}THE SIX — WATCH{R}")
    print(f"  {'='*66}")
    print()

    for d in sorted(days.keys()):
        day = days[d]
        status = day.get("status", "?")
        icon = {"pending": f"{YE}⏳{R}", "placed": f"{CY}▶{R}",
                "settled": f"{GR}✓{R}"}.get(status, f"{RD}?{R}")
        n_bets = len(day.get("bets", []))
        n_games = len(day.get("games", []))
        print(f"  {icon} {d}  |  {status.upper():8s}  |  "
              f"{n_games} games  |  {n_bets} bets  |  {day.get('series','?')}")

    if paused and paused >= today_str:
        print()
        print(f"  {YE}⏸  PAUSED{R} — waiting for {paused} to settle.")
        print(f"  {DIM}After settlement, run --institute again to advance.{R}")
    elif paused:
        print()
        print(f"  {GR}▶  UNBLOCKED{R} — {paused} is past. Run --institute to continue.")

    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="the-six",
        description="THE SIX — daily 6-bet sports-style strategy for Kalshi",
    )
    parser.add_argument("--live", action="store_true",
                        help="Place real bets on Kalshi (requires auth)")
    parser.add_argument("--series", type=str, default="KXBTCD",
                        help="Series ticker (default: KXBTCD)")
    parser.add_argument("--games", type=int, default=0,
                        help="Number of simulated games for dry-run (default: auto)")
    parser.add_argument("--institute", action="store_true",
                        help="Institute today + tomorrow's SIX (1 day ahead only)")
    parser.add_argument("--watch", action="store_true",
                        help="Check settlement state — unblock when today settles")
    args = parser.parse_args()

    # --watch mode (check state, don't run)
    if args.watch:
        return watch()

    # --institute mode (generate today + tomorrow, save state)
    if args.institute:
        institute(args.series, args.live, args.games)
        return 0

    # Default: single dry-run (original behavior)
    if args.live:
        games = fetch_real_games(args.series)
        live = True
    else:
        label_map = {
            "KXBTCD": "BTC", "KXETHD": "ETH", "KXSOLD": "SOL",
            "KXXRPD": "XRP", "KXDOGD": "DOGE", "KXADAD": "ADA",
        }
        label = label_map.get(args.series, "BTC")
        n = args.games or 8
        games = simulate_todays_games(series_label=label, num_games=n)
        live = False

    if len(games) < 2:
        print("[FAIL] Need at least 2 open markets to run THE SIX.")
        return 1

    series_label = games[0].ticker.split("-")[0] if games else "?"

    six = TheSix(games, seed=datetime.now().day)
    bets = six.run()

    print_header(games, series_label, live)
    for bet in bets:
        print_bet(bet)
    print_summary(bets)

    return 0


if __name__ == "__main__":
    sys.exit(main())
