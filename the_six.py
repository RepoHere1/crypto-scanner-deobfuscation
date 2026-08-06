#!/usr/bin/env python3
"""Kalshi auto strategy runner — THE-EASE.

Philosophy:
  Discover today's sports markets by category, pick the category with the
  most games, and build 5 combo tickets.  Each combo bets $1 across all
  games in the category: all favorites except one underdog, cycling the
  underdog through the 5 closest-odds games.  Buy only after the first
  game of the day reaches halftime.

  Dry-run mode queries real Kalshi production data — no simulations, no
  fake data.  Only the trade execution is skipped without --live.

Usage:
    python3 the_six.py                     # dry-run: show combos from live data
    python3 the_six.py --live --now         # place real bets immediately
    python3 the_six.py --daemon             # wait for 8 AM, then poll until gate
    python3 the_six.py --daemon --live      # daemon mode + place real orders
    python3 the_six.py --history            # show running total across all days
    python3 the_six.py --show-open          # Kalshi balance + positions
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Market data model
# ---------------------------------------------------------------------------

@dataclass
class Game:
    """A single prediction market — one game in today's slate."""
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
        return "yes" if self.yes_ask >= 0.50 else "no"

    @property
    def underdog_side(self) -> str:
        return "no" if self.favored_side == "yes" else "yes"

    @property
    def favored_price(self) -> float:
        return self.yes_ask if self.favored_side == "yes" else self.no_ask

    @property
    def underdog_price(self) -> float:
        return self.no_ask if self.favored_side == "yes" else self.yes_ask

    @property
    def odds_gap(self) -> float:
        """How close are the odds?  Smaller = more contested game."""
        return abs(self.yes_ask - self.no_ask)

    def pick(self, side: str) -> tuple[str, float]:
        if side == "yes":
            return ("YES", self.yes_ask)
        return ("NO", self.no_ask)


# ---------------------------------------------------------------------------
# THE-EASE strategy
# ---------------------------------------------------------------------------

# Kalshi event_ticker prefix → sport category name
SPORT_CATEGORIES: dict[str, str] = {
    "KXNBA":     "NBA",
    "KXMLB":     "MLB",
    "KXNFL":     "NFL",
    "KXNHL":     "NHL",
    "KXSOCCER":  "SOCCER",
    "KXEPL":     "EPL",
    "KXUFC":     "UFC",
    "KXTENNIS":  "TENNIS",
    "KXGOLF":    "GOLF",
    "KXF1":      "F1",
    "KXWNBA":    "WNBA",
    "KXNCAAFB":  "NCAAF",
    "KXNCAABB":  "NCAAB",
    "KXMMA":     "MMA",
    "KXCRICKET": "CRICKET",
    "KXBOXING":  "BOXING",
    "KXMOTOR":   "MOTORSPORT",
}

COMBO_PREFIXES = (
    "KXMVESPORTSMULTIGAMEEXTENDED",
    "KXMULTIGAMECOMBO",
)


def _extract_category(event_ticker: str) -> str:
    """Extract sport category from Kalshi event_ticker."""
    for prefix, name in SPORT_CATEGORIES.items():
        if event_ticker.startswith(prefix):
            return name
    return event_ticker.split("-")[0] if "-" in event_ticker else event_ticker[:6]


def _is_combo_market(m: dict) -> bool:
    """Check if a market is a Kalshi combo/bundle product."""
    et = (m.get("event_ticker", "") or "")
    return any(et.startswith(p) for p in COMBO_PREFIXES)


def _parse_game(m: dict, index: int) -> Game | None:
    """Parse a raw Kalshi market dict into a Game.  Returns None on failure."""
    try:
        raw_title = m.get("title", "?")
        title = raw_title[:55] + ("…" if len(raw_title) > 55 else "")
        return Game(
            ticker=m.get("ticker", "?"),
            title=title,
            strike=float(index),
            close_time=m.get("close_time", ""),
            yes_bid=float(m.get("yes_bid_dollars", m.get("yes_bid", 0))),
            yes_ask=float(m.get("yes_ask_dollars", m.get("yes_ask", 0))),
            no_bid=float(m.get("no_bid_dollars", m.get("no_bid", 0))),
            no_ask=float(m.get("no_ask_dollars", m.get("no_ask", 0))),
        )
    except (ValueError, TypeError):
        return None


def discover_by_category() -> tuple[str, list[Game], dict[str, int], bool]:
    """Discover sports markets grouped by category — LIVE Kalshi production data.

    Queries ALL open sports markets, groups by sport category, and picks
    the category with the most games (≥4 required).  No simulations ever.

    Returns (category_name, games_in_category, all_category_counts, live).
    """
    try:
        from kalshi_tap.client import KalshiClient
        client = KalshiClient()
        data = client.get("/markets?status=open&limit=500&category=sports")
        all_markets = data.get("markets", [])
    except Exception as e:
        print(f"[FAIL] Kalshi auth: {e}")
        return "", [], {}, False

    if not all_markets:
        print("[WARN] No open sports markets found on Kalshi.")
        return "", [], {}, False

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for m in all_markets:
        et = m.get("event_ticker", "") or ""
        cat = _extract_category(et)
        if not _is_combo_market(m):
            by_cat[cat].append(m)

    counts = {cat: len(ms) for cat, ms in by_cat.items()}
    ranked = sorted(by_cat.items(), key=lambda x: -len(x[1]))

    if not ranked:
        print("[WARN] No individual sports markets found (all are combo bundles?).")
        return "", [], counts, False

    best_cat, best_markets = ranked[0]

    if len(best_markets) < 4:
        print(f"[WARN] Top category '{best_cat}' has only {len(best_markets)} games.  Need ≥4.")
        print(f"       Categories: {counts}")
        return "", [], counts, False

    games: list[Game] = []
    for i, m in enumerate(best_markets):
        g = _parse_game(m, i)
        if g:
            games.append(g)

    def _vol_key(g: Game) -> float:
        return g.yes_ask

    games.sort(key=lambda g: (-_vol_key(g), g.close_time))
    games = games[:10]

    if len(games) < 4:
        print(f"[WARN] Parsed only {len(games)} valid games in '{best_cat}'.")
        return "", [], counts, False

    return best_cat, games, counts, True


# ── Combo ticket ──────────────────────────────────────────────────────────

@dataclass
class ComboTicket:
    """One combo betting ticket."""
    number: int
    closeness_rank: int
    label: str
    legs: list[dict] = field(default_factory=list)
    total_cost: float = 1.00
    cost_per_leg: float = 0.0

    @property
    def underdog_leg(self) -> dict | None:
        for leg in self.legs:
            if leg.get("role") == "underdog":
                return leg
        return None


class TheEase:
    """THE-EASE: 5 combo tickets, cycling the underdog through the closest-odds games.

    For a category with N games (N ≥ 4):
      1. Rank games by |yes_ask - no_ask| ascending (closest odds first).
      2. Combo 1: all favorites, but game at rank 1 → underdog.
      3. Combo 2: all favorites, but game at rank 2 → underdog.
      4. … repeat through rank 5.
      5. Each combo costs $1.00 total, split equally across all N legs.
    """

    CLOSENESS_LABELS = ["CLOSEST", "2ND-CLOSEST", "3RD-CLOSEST", "4TH-CLOSEST", "5TH-CLOSEST"]

    def __init__(self, games: list[Game]):
        if len(games) < 4:
            raise ValueError(f"THE-EASE needs ≥4 games, got {len(games)}")
        self.games = games
        self.tickets: list[ComboTicket] = []

    def run(self) -> list[ComboTicket]:
        ranked = sorted(self.games, key=lambda g: g.odds_gap)
        n_tickets = min(5, len(ranked))
        n_legs = len(self.games)

        tickets = []
        for i in range(n_tickets):
            underdog_game = ranked[i]
            label = self.CLOSENESS_LABELS[i]

            legs = []
            for g in self.games:
                if g is underdog_game:
                    side = g.underdog_side
                    price = g.underdog_price
                    role = "underdog"
                    icon = "🐶"
                else:
                    side = g.favored_side
                    price = g.favored_price
                    role = "favorite"
                    icon = "⭐"

                legs.append({
                    "ticker": g.ticker,
                    "title": g.title,
                    "side": side.upper(),
                    "price": price,
                    "role": role,
                    "icon": icon,
                    "odds_gap": g.odds_gap,
                    "close_time": g.close_time,
                })

            cost_per = round(1.00 / n_legs, 4)
            tickets.append(ComboTicket(
                number=i + 1,
                closeness_rank=i + 1,
                label=label,
                legs=legs,
                total_cost=1.00,
                cost_per_leg=cost_per,
            ))

        self.tickets = tickets
        return tickets


# ── Timing gate: wait for first game halftime ─────────────────────────────

GAME_DURATION_H = 2.5
HALFTIME_OFFSET_H = GAME_DURATION_H / 2


def halftime_gate(games: list[Game]) -> tuple[bool, str]:
    """Check if the earliest-starting game is past halftime.

    Estimate: game ends at close_time, duration ~2.5h:
      start ≈ close_time - 2.5h
      halftime ≈ close_time - 1.25h

    Returns (ready_bool, status_message).
    """
    if not games:
        return False, "No games to check"

    now = datetime.now(timezone.utc)
    earliest_ct: datetime | None = None

    for g in games:
        ct_str = g.close_time
        if not ct_str:
            continue
        try:
            ct = datetime.fromisoformat(ct_str.replace("Z", "+00:00"))
            if earliest_ct is None or ct < earliest_ct:
                earliest_ct = ct
        except (ValueError, TypeError):
            continue

    if earliest_ct is None:
        return False, "Cannot parse close times — gate open"

    halftime = earliest_ct - timedelta(hours=HALFTIME_OFFSET_H)

    if now >= halftime:
        return True, f"✓ Halftime passed ({halftime.strftime('%H:%M UTC')})"
    else:
        wait_secs = (halftime - now).total_seconds()
        if wait_secs < 60:
            return False, f"⏳ {int(wait_secs)}s until halftime"
        wait_min = int(wait_secs / 60)
        return False, f"⏳ ~{wait_min}min until halftime ({halftime.strftime('%H:%M UTC')})"


def wait_until_8am() -> None:
    """Block until 8:00 AM local time.  If past 8 AM, return immediately."""
    now_local = datetime.now()
    target = now_local.replace(hour=8, minute=0, second=0, microsecond=0)
    if target <= now_local:
        return  # already past 8 AM
    wait_secs = (target - now_local).total_seconds()
    wait_min = int(wait_secs / 60)
    print(f"\n  {CY}⏰ WAITING FOR 8 AM{R} — {wait_min}min until "
          f"{target.strftime('%H:%M')} local time…\n")
    time.sleep(wait_secs)


# ---------------------------------------------------------------------------
# Display helpers
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


def print_category_summary(counts: dict[str, int], chosen: str):
    """Print sport category breakdown."""
    print(f"\n  {B}{WH}SPORTS MARKETS BY CATEGORY{R}  {DIM}(live Kalshi data){R}")
    print(f"  {'─'*44}")
    ranked = sorted(counts.items(), key=lambda x: -x[1])
    for cat, n in ranked:
        marker = f" {GR}◀ SELECTED{R}" if cat == chosen else ""
        bar = "█" * min(n, 30)
        print(f"  {cat:<12s} {n:>3d} games  {DIM}{bar}{R}{marker}")
    print()


def print_game_slate(games: list[Game], category: str, live: bool):
    """Print the game slate for the chosen category."""
    mode = f"{RD}LIVE{R}" if live else f"{CY}DRY-RUN{R}"
    br = load_bankroll()
    bal = br["balance"]
    bal_color = GR if bal >= 50 else YE if bal >= 20 else RD
    print()
    print(f"  {'='*70}")
    print(f"  {B}{WH}THE-EASE{R} — {mode}  |  {category}  |  {len(games)} games today")
    print(f"  {DIM}{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}{R}")
    print(f"  {B}Bankroll:{R} {bal_color}${bal:,.2f}{R}  |  {B}Cost:{R} $5.00 (5 combos × $1)")
    print(f"  {'='*70}")
    print()
    print(f"  {'#':<3s} {'Game':<16s} {'YES':>7s} {'NO':>7s} {'Gap':>7s} {'Call':>14s}")
    print(f"  {'─'*3}  {'─'*16}  {'─'*7}  {'─'*7}  {'─'*7}  {'─'*14}")
    for i, g in enumerate(games):
        gap_str = f"{g.odds_gap*100:>5.0f}c"
        call = f"{GR}FAVORED{R}" if g.favored_side == "yes" else f"{RD}UNDERDOG{R}"
        print(f"  {i+1:<3d} {g.ticker[:15]:<16s} {g.yes_ask*100:>5.0f}c YES {g.no_ask*100:>5.0f}c NO {gap_str} {call}")
    print()


def print_ticket(ticket: ComboTicket):
    """Print one combo ticket."""
    color = [None, CY, MG, YE, GR, BL][ticket.number]
    ud = ticket.underdog_leg
    ud_ticker = ud["ticker"] if ud else "?"
    ud_gap = f"{ud['odds_gap']*100:.0f}c" if ud else "?"

    print(f"  {color}{B}COMBO {ticket.number}: {ticket.label}{R}  "
          f"{DIM}(underdog → {ud_ticker} gap {ud_gap}){R}")
    print(f"  {'─'*68}")
    for leg in ticket.legs:
        icon = leg["icon"]
        ticker = leg["ticker"][:14]
        side = leg["side"]
        price = leg["price"]
        role_tag = f"{RD}🐶 DOG{R}" if leg["role"] == "underdog" else f"{GR}⭐ FAV{R}"
        print(f"    {icon} {ticker:<14s} {side:<4s} @ {price*100:>5.0f}c  |  "
              f"${ticket.cost_per_leg:.2f}  {role_tag}")
    print(f"  {'─'*68}")
    print(f"  {B}Total: ${ticket.total_cost:.2f}{R}  |  "
          f"{len(ticket.legs)} legs × {ticket.cost_per_leg*100:.1f}c")
    print()


def print_ease_summary(tickets: list[ComboTicket]):
    """Print summary of all 5 combos."""
    br = load_bankroll()
    bal = br["balance"]
    bal_color = GR if bal >= 50 else YE if bal >= 20 else RD
    total = sum(t.total_cost for t in tickets)
    total_legs = sum(len(t.legs) for t in tickets)
    print(f"  {'='*70}")
    print(f"  {B}{WH}THE-EASE — SUMMARY{R}")
    print(f"  {'='*70}")
    print()
    print(f"  Tickets:       {len(tickets)}")
    print(f"  Total laid:    ${total:.2f}")
    print(f"  Total legs:    {total_legs}")
    print(f"  {B}Bankroll:{R}      {bal_color}${bal:,.2f}{R}")
    print()
    print(f"  {DIM}Data source: live Kalshi production API — no simulations.{R}")
    print(f"  {DIM}Gate: waits for 1st game halftime before buying.{R}")
    print()


# ---------------------------------------------------------------------------
# Live order placement
# ---------------------------------------------------------------------------

def place_ease_tickets(tickets: list[ComboTicket], client) -> dict:
    """Place all combo tickets on Kalshi.  1 contract per leg at ask price."""
    summary: dict = {"placed": 0, "failed": 0, "total_cost": 0.0, "orders": []}
    for ticket in tickets:
        for leg in ticket.legs:
            ticker = leg["ticker"]
            side = leg["side"].lower()
            price = leg["price"]
            price_cents = int(round(price * 100))
            if price_cents <= 0:
                continue
            if price_cents >= 100:
                price_cents = 99
            try:
                result = client.place_order(
                    ticker=ticker, side=side, count=1, price_cents=price_cents,
                )
                cost = price
                summary["placed"] += 1
                summary["total_cost"] += cost
                summary["orders"].append({
                    "ticker": ticker, "side": side, "price_cents": price_cents,
                    "cost": round(cost, 2), "status": "placed",
                    "order_id": result.get("order", {}).get("order_id", "?"),
                })
                print(f"  {GR}✓{R} {ticker} {side.upper():3s} @ {price_cents}c  "
                      f"(${cost:.2f})")
            except Exception as e:
                summary["failed"] += 1
                summary["orders"].append({
                    "ticker": ticker, "side": side, "price_cents": price_cents,
                    "cost": 0, "status": "failed", "error": str(e)[:80],
                })
                print(f"  {RD}✗{R} {ticker} {side.upper():3s} @ {price_cents}c  "
                      f"FAIL: {e}")
    return summary


# ---------------------------------------------------------------------------
# Bankroll
# ---------------------------------------------------------------------------

BANKROLL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".six_bankroll.json")


def load_bankroll() -> dict:
    if not os.path.exists(BANKROLL_FILE):
        now = datetime.now(timezone.utc).isoformat()
        br = {"balance": 100.00, "started_at": now, "total_spent": 0.0}
        save_bankroll(br)
        return br
    try:
        with open(BANKROLL_FILE) as f:
            return json.load(f)
    except Exception:
        now = datetime.now(timezone.utc).isoformat()
        br = {"balance": 100.00, "started_at": now, "total_spent": 0.0}
        save_bankroll(br)
        return br


def save_bankroll(state: dict) -> None:
    with open(BANKROLL_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def charge_bankroll(amount: float) -> dict:
    br = load_bankroll()
    br["balance"] = round(br["balance"] - amount, 2)
    br["total_spent"] = round(br.get("total_spent", 0) + amount, 2)
    save_bankroll(br)
    return br


# ---------------------------------------------------------------------------
# Daily run state — survives reboots
# ---------------------------------------------------------------------------

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".ease_state.json")


def load_ease_state() -> dict:
    """Load THE-EASE daily run state.  Survives reboots."""
    if not os.path.exists(STATE_FILE):
        return {"strategy": "THE-EASE", "runs": {}}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"strategy": "THE-EASE", "runs": {}}


def save_ease_state(state: dict) -> None:
    """Persist THE-EASE run state."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def record_daily_run(category: str, games_count: int, tickets: list[ComboTicket],
                     live: bool) -> dict:
    """Record today's run in the state file.  Returns updated state."""
    state = load_ease_state()
    today = date.today().isoformat()
    now_utc = datetime.now(timezone.utc).isoformat()
    total_spent = sum(t.total_cost for t in tickets)

    state["runs"][today] = {
        "category": category,
        "games": games_count,
        "combos": len(tickets),
        "spent": round(total_spent, 2),
        "live": live,
        "status": "live" if live else "dry_run",
        "placed_at": now_utc,
        # Store combo summary for history
        "underdogs": [t.underdog_leg["ticker"] if t.underdog_leg else "?"
                      for t in tickets],
        "ticket_count": len(tickets),
        "legs_per_ticket": len(tickets[0].legs) if tickets else 0,
    }
    save_ease_state(state)
    return state


def print_running_total():
    """Print running total across all days — survives reboots."""
    state = load_ease_state()
    runs = state.get("runs", {})
    br = load_bankroll()

    print(f"\n  {B}{WH}╔══════════════════════════════════════════════════════════════╗{R}")
    print(f"  {B}{WH}║  THE-EASE — RUNNING TOTAL  (persists across reboots)         ║{R}")
    print(f"  {B}{WH}╚══════════════════════════════════════════════════════════════╝{R}\n")

    if not runs:
        print(f"  {DIM}No runs recorded yet.{R}\n")
        return

    print(f"  {B}{'DATE':<12s} {'CAT':<10s} {'GAMES':>5s} {'TIX':>4s} {'SPENT':>7s} {'MODE':>8s}{R}")
    print(f"  {'─'*12}  {'─'*10}  {'─'*5}  {'─'*4}  {'─'*7}  {'─'*8}")

    total_spent = 0.0
    total_days = 0
    total_live = 0
    total_dry = 0

    for day in sorted(runs.keys()):
        r = runs[day]
        cat = r.get("category", "?")
        games = r.get("games", 0)
        tix = r.get("combos", r.get("ticket_count", 0))
        spent = r.get("spent", 0)
        live = r.get("live", False)
        mode_str = f"{RD}LIVE{R}" if live else f"{CY}DRY{R}"

        print(f"  {day:<12s} {cat:<10s} {games:>5d} {tix:>4d} ${spent:>6.2f} {mode_str}")

        total_spent += spent
        total_days += 1
        if live:
            total_live += 1
        else:
            total_dry += 1

    print(f"  {'─'*12}  {'─'*10}  {'─'*5}  {'─'*4}  {'─'*7}  {'─'*8}")
    print(f"  {B}{total_days} days{R}                                   "
          f"${total_spent:>6.2f}  {total_live} live / {total_dry} dry")

    bal = br["balance"]
    bal_color = GR if bal >= 50 else YE if bal >= 20 else RD
    started = br.get("started_at", "?")[:10]
    print()
    print(f"  {B}Bankroll:{R}    {bal_color}${bal:,.2f}{R}  (started {started})")
    print(f"  {B}Total spent:{R} ${br.get('total_spent', 0):,.2f}")
    print()


def today_already_ran() -> bool:
    """Check if today's run is already recorded."""
    state = load_ease_state()
    today = date.today().isoformat()
    return today in state.get("runs", {})


# ── Show open positions / balance ─────────────────────────────────────────

def show_open() -> None:
    """Display Kalshi balance and ALL open market positions."""
    try:
        from kalshi_tap.client import KalshiClient
        client = KalshiClient.from_env()
        b = client.get_balance()
        bal = float(b.get("balance_dollars", 0))
        port = float(b.get("portfolio_value", 0)) / 100
        bal_color = GR if bal >= 50 else YE if bal >= 20 else RD

        print(f"\n  {B}{WH}╔══════════════════════════════════════════════════════════════╗{R}")
        print(f"  {B}{WH}║  KALSHI FEED  —  Balance: {bal_color}${bal:,.2f}{R}{B}{WH}  |  "
              f"Position value: ${port:,.2f}  |  Total: ${bal + port:,.2f}  ║{R}")
        print(f"  {B}{WH}╚══════════════════════════════════════════════════════════════╝{R}\n")

        data = client.get("/portfolio/positions")
        positions = data.get("market_positions", [])

        active = [p for p in positions if abs(float(p.get("position_fp", 0) or 0)) > 0.01]
        active.sort(key=lambda p: abs(float(p.get("position_fp", 0) or 0)), reverse=True)

        if not active:
            print(f"  {DIM}No open positions.{R}\n")
        else:
            print(f"  {B}{'TICKER':<55s} {'SIDE':>5s} {'QTY':>8s} {'EXPOSURE':>10s}{R}")
            print(f"  {'─'*55}  {'─'*5}  {'─'*8}  {'─'*10}")
            for p in active:
                ticker = p.get("ticker", "?")
                pos = float(p.get("position_fp", 0) or 0)
                side = f"{GR}LONG{R}" if pos > 0 else f"{RD}SHORT{R}"
                qty = f"{abs(pos):.0f}"
                exposure = float(p.get("market_exposure_dollars", 0) or 0)
                display = ticker if len(ticker) <= 54 else ticker[:51] + "..."
                print(f"  {display:<55s} {side} {qty:>8s} ${exposure:>9,.2f}")
            print()

        br = load_bankroll()
        lc = GR if br["balance"] >= 50 else YE if br["balance"] >= 20 else RD
        print(f"  {DIM}Local bankroll: {lc}${br['balance']:,.2f}{R}{DIM}"
              f"  (since {br.get('started_at','?')[:10]}){R}\n")

    except Exception as e:
        print(f"  {RD}[AUTH REQUIRED]{R} {e}")


# ---------------------------------------------------------------------------
# Daemon runner
# ---------------------------------------------------------------------------

def run_once(live: bool, skip_gate: bool,
             category: str, games: list[Game], counts: dict[str, int],
             ) -> int:
    """Generate combos, print them, optionally place orders.  Returns 0 on success."""
    print_category_summary(counts, category)

    if len(games) < 4:
        print(f"[FAIL] Need ≥4 games in a category.  Top category '{category}' "
              f"has {len(games)}.")
        return 1

    # Timing gate
    if not skip_gate:
        ready, msg = halftime_gate(games)
        if not ready:
            print(f"\n  {YE}⏸  GATE CLOSED{R} — {msg}")
            return 2  # signal: gate not open yet
        else:
            print(f"\n  {GR}▶  GATE OPEN{R} — {msg}")
    else:
        ready = True
        print(f"\n  {YE}⏩  GATE SKIPPED{R}")

    # Generate combos
    ease = TheEase(games)
    tickets = ease.run()

    print_game_slate(games, category, live)
    for t in tickets:
        print_ticket(t)
    print_ease_summary(tickets)

    # Place orders if live
    if live and ready:
        from kalshi_tap.client import KalshiClient
        client = KalshiClient.from_env()
        print(f"\n  {RD}{'='*70}{R}")
        print(f"  {B}{WH}PLACING ORDERS{R} — 5 combos, 1 contract per leg at ask")
        print(f"  {RD}{'='*70}{R}\n")
        result = place_ease_tickets(tickets, client)
        total = result["total_cost"]
        br = charge_bankroll(total)
        bal_color = GR if br["balance"] >= 50 else YE if br["balance"] >= 20 else RD
        print(f"\n  {RD}{'='*70}{R}")
        print(f"  {B}PLACED:{R} {GR}{result['placed']}{R}  |  "
              f"{B}FAILED:{R} {RD}{result['failed']}{R}  |  "
              f"{B}Cost:{R} ${total:.2f}")
        print(f"  {B}Bankroll:{R} {bal_color}${br['balance']:,.2f}{R}")
        print(f"  {RD}{'='*70}{R}")
        print()

    # Record in state
    record_daily_run(category, len(games), tickets, live)
    print_running_total()

    return 0


def daemon_loop(live: bool, poll_secs: int = 60) -> int:
    """Daemon mode: wait for 8 AM, then poll until halftime gate opens.

    Survives reboots via .ease_state.json — if today already ran, skip.
    """
    print(f"\n  {B}{WH}╔══════════════════════════════════════════════════════════════╗{R}")
    print(f"  {B}{WH}║  THE-EASE DAEMON  —  {datetime.now().strftime('%Y-%m-%d %H:%M')}                     ║{R}")
    print(f"  {B}{WH}╚══════════════════════════════════════════════════════════════╝{R}")

    # Show running total on startup
    print_running_total()

    # Check if today already ran
    if today_already_ran():
        state = load_ease_state()
        today = date.today().isoformat()
        run = state["runs"][today]
        print(f"  {GR}✓ TODAY COMPLETE{R} — {run['status']} run at {run['placed_at'][:19]}")
        print(f"  {DIM}Daemon idle.  Will check again tomorrow at 8 AM.{R}\n")

        # Wait until midnight, then loop
        now = datetime.now()
        tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        wait_secs = (tomorrow - now).total_seconds()
        if wait_secs > 0 and wait_secs < 86400:
            print(f"  {DIM}Sleeping {int(wait_secs/3600)}h until midnight…{R}")
            time.sleep(min(wait_secs, 3600))  # sleep max 1h at a time
        # Fall through to re-check

    # Wait for 8 AM
    wait_until_8am()

    # Ensure bankroll exists
    load_bankroll()

    print(f"  {GR}▶  DAEMON ACTIVE{R} — polling Kalshi every {poll_secs}s\n")

    # Polling loop
    fail_streak = 0
    while True:
        # Check if somehow completed while we were polling
        if today_already_ran():
            state = load_ease_state()
            today = date.today().isoformat()
            run = state["runs"][today]
            print(f"\n  {GR}✓ RUN RECORDED{R} — {run['status']} ({run['placed_at'][:19]})")
            print(f"  {DIM}Daemon complete for today.  Will resume at 8 AM tomorrow.{R}\n")
            return 0

        try:
            category, games, counts, got_data = discover_by_category()
        except Exception as e:
            fail_streak += 1
            print(f"  {RD}[ERR]{R} Kalshi query failed: {e}")
            if fail_streak > 10:
                print(f"  {RD}[FATAL] Too many failures — exiting.{R}")
                return 1
            time.sleep(poll_secs * 2)
            continue

        fail_streak = 0

        if len(games) < 4:
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"  {YE}[{ts}]{R} Only {len(games)} games in '{category}' — retrying…")
            time.sleep(poll_secs)
            continue

        ready, msg = halftime_gate(games)
        ts = datetime.now().strftime('%H:%M:%S')

        if ready:
            print(f"\n  {GR}▶  GATE OPEN{R} at {ts} — {msg}")
            print_category_summary(counts, category)
            result = run_once(live, skip_gate=True, category=category,
                              games=games, counts=counts)
            if result == 0:
                return 0
            # If run_once failed, keep polling
        else:
            print(f"  {YE}[{ts}]{R} {msg}  |  {category} ({len(games)} games)")

        time.sleep(poll_secs)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="kalshi-auto",
        description="THE-EASE — 5-combo strategy with halftime gate (live Kalshi data only)",
    )
    parser.add_argument("--live", action="store_true",
                        help="Place real bets on Kalshi (after halftime gate)")
    parser.add_argument("--daemon", action="store_true",
                        help="Daemon mode: wait for 8 AM, poll until gate, run once")
    parser.add_argument("--history", action="store_true",
                        help="Show running total across all days")
    parser.add_argument("--show-open", action="store_true",
                        help="Display Kalshi balance and open positions")
    parser.add_argument("--loop", type=int, default=0, metavar="SECS",
                        help="Poll every SECS seconds until gate opens, then exit")
    parser.add_argument("--now", action="store_true",
                        help="Skip the halftime gate — run immediately")
    parser.add_argument("--poll", type=int, default=60, metavar="SECS",
                        help="Polling interval for daemon/loop mode (default: 60s)")
    args = parser.parse_args()

    # --history
    if args.history:
        print_running_total()
        return 0

    # --show-open
    if args.show_open:
        show_open()
        if not args.daemon and not args.loop and not args.live:
            return 0

    # --daemon
    if args.daemon:
        return daemon_loop(live=args.live, poll_secs=args.poll)

    # ── Single-shot mode ──────────────────────────────────────────────
    category, games, counts, got_data = discover_by_category()
    live = args.live and got_data

    if len(games) < 4:
        print(f"[FAIL] Need ≥4 games in a category.  Top category '{category}' "
              f"has {len(games)}.")
        print(f"  {DIM}Data source: live Kalshi production API.{R}")
        return 1

    # Timing gate
    ready = True
    if not args.now:
        ready, msg = halftime_gate(games)
        if not ready:
            print(f"\n  {YE}⏸  GATE CLOSED{R} — {msg}")
            if args.loop <= 0:
                print(f"  {DIM}Use --loop to poll until gate opens, or --now to skip.{R}")
                return 0
        else:
            print(f"\n  {GR}▶  GATE OPEN{R} — {msg}")
    else:
        print(f"\n  {YE}⏩  GATE SKIPPED{R} (--now flag)")

    # Generate combos
    ease = TheEase(games)
    tickets = ease.run()

    print_game_slate(games, category, live)
    for t in tickets:
        print_ticket(t)
    print_ease_summary(tickets)

    # Place orders if live and gate open
    if live and ready:
        from kalshi_tap.client import KalshiClient
        client = KalshiClient.from_env()
        print(f"\n  {RD}{'='*70}{R}")
        print(f"  {B}{WH}PLACING ORDERS{R} — 5 combos, 1 contract per leg at ask")
        print(f"  {RD}{'='*70}{R}\n")
        result = place_ease_tickets(tickets, client)
        total = result["total_cost"]
        br = charge_bankroll(total)
        bal_color = GR if br["balance"] >= 50 else YE if br["balance"] >= 20 else RD
        print(f"\n  {RD}{'='*70}{R}")
        print(f"  {B}PLACED:{R} {GR}{result['placed']}{R}  |  "
              f"{B}FAILED:{R} {RD}{result['failed']}{R}  |  "
              f"{B}Cost:{R} ${total:.2f}")
        print(f"  {B}Bankroll:{R} {bal_color}${br['balance']:,.2f}{R}")
        print(f"  {RD}{'='*70}{R}")
        print()

    # Record run
    record_daily_run(category, len(games), tickets, live)
    print_running_total()

    # Loop mode
    if args.loop > 0 and not (live and ready):
        poll = args.loop
        print(f"\n  {CY}⏱  LOOP MODE{R} — checking every {poll}s until gate opens…\n")
        while True:
            time.sleep(poll)
            category2, games2, counts2, _ = discover_by_category()
            if len(games2) < 4:
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"  {YE}[{ts}]{R} Only {len(games2)} games — retrying…")
                continue

            ready2, msg2 = halftime_gate(games2)
            ts = datetime.now().strftime('%H:%M:%S')
            if ready2:
                print(f"\n  {GR}▶  GATE OPEN{R} at {ts} — {msg2}")
                ease2 = TheEase(games2)
                tickets2 = ease2.run()
                print_category_summary(counts2, category2)
                print_game_slate(games2, category2, live)
                for t in tickets2:
                    print_ticket(t)
                print_ease_summary(tickets2)

                if live:
                    from kalshi_tap.client import KalshiClient
                    client = KalshiClient.from_env()
                    result2 = place_ease_tickets(tickets2, client)
                    total2 = result2["total_cost"]
                    br2 = charge_bankroll(total2)
                    bc2 = GR if br2["balance"] >= 50 else YE if br2["balance"] >= 20 else RD
                    print(f"\n  {B}PLACED:{R} {GR}{result2['placed']}{R}  |  "
                          f"{B}FAILED:{R} {RD}{result2['failed']}{R}  |  "
                          f"{B}Cost:{R} ${total2:.2f}")
                    print(f"  {B}Bankroll:{R} {bc2}${br2['balance']:,.2f}{R}")

                record_daily_run(category2, len(games2), tickets2, live)
                print_running_total()
                break
            else:
                print(f"  {YE}[{ts}]{R} {msg2}  |  {category2} ({len(games2)} games)")
    elif args.loop > 0:
        print(f"\n  {GR}✓ Done{R} — exiting.\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
