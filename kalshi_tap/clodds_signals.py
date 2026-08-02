"""CloddsBot signal consumer — bridges CloddsBot Opportunity Finder into Kalshi autopilot.

Polls http://localhost:18789/api/opportunities/scan for Kalshi-relevant opportunities
and converts them into ContrarianBet objects the autopilot can trade.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

CLODDS_API = "http://localhost:18789/api/opportunities"


@dataclass
class SignalBet:
    """A trading signal from CloddsBot, ready for autopilot consumption."""
    ticker: str
    side: str                     # "yes" or "no"
    market_price: float
    true_prob: float
    expected_value: float
    direction: str                # "bullish" or "bearish"
    source: str = "clodds"


def fetch_kalshi_opportunities(min_edge: float = 1.0, timeout: float = 5.0) -> list[dict]:
    """Fetch Kalshi opportunities from CloddsBot gateway."""
    url = f"{CLODDS_API}/scan"
    body = json.dumps({
        "platforms": ["kalshi"],
        "minEdge": min_edge,
        "limit": 20,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data.get("data", {}).get("opportunities", [])
    except Exception as e:
        logger.debug("CloddsBot API unavailable: %s", e)
        return []


def fetch_cross_opportunities(min_edge: float = 2.0, timeout: float = 5.0) -> list[dict]:
    """Fetch cross-platform opportunities (Kalshi vs others)."""
    url = f"{CLODDS_API}/scan"
    body = json.dumps({
        "minEdge": min_edge,
        "types": ["cross_platform", "edge"],
        "limit": 20,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data.get("data", {}).get("opportunities", [])
    except Exception as e:
        logger.debug("CloddsBot API unavailable: %s", e)
        return []


def opportunity_to_bets(opp: dict, kalshi_client=None) -> list[SignalBet]:
    """Convert a CloddsBot opportunity into SignalBet objects.

    Each opportunity has multiple markets; we extract Kalshi-market legs.
    """
    bets: list[SignalBet] = []
    for m in opp.get("markets", []):
        if m.get("platform") != "kalshi":
            continue
        price = m.get("price", 0)
        outcome = m.get("outcome", "YES")
        side = outcome.lower() if outcome.lower() in ("yes", "no") else "yes"
        true_prob = m.get("trueProbability", price)  # fallback
        edge = opp.get("edgePct", 0) / 100.0
        ev = edge if edge > 0 else 0.01

        bet = SignalBet(
            ticker=m.get("marketId", ""),
            side=side,
            market_price=price,
            true_prob=true_prob,
            expected_value=ev,
            direction="bullish" if side == "yes" else "bearish",
            source="clodds",
        )
        bets.append(bet)
    return bets


def get_clodds_signals(min_edge: float = 1.0, kalshi_client=None) -> list[SignalBet]:
    """Main entry point: fetch and convert CloddsBot signals."""
    all_bets: list[SignalBet] = []
    for opp in fetch_kalshi_opportunities(min_edge=min_edge):
        all_bets.extend(opportunity_to_bets(opp, kalshi_client))
    for opp in fetch_cross_opportunities(min_edge=2.0):
        all_bets.extend(opportunity_to_bets(opp, kalshi_client))
    if all_bets:
        logger.info("CloddsBot: %d signal bets from %d opportunities",
                     len(all_bets), len(all_bets))
    return all_bets
