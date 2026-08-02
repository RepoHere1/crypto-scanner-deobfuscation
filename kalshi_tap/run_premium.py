"""Premium Seller autopilot — sells overpriced tail risk on Kalshi binaries.

Replaces the broken directional-betting autopilot with a volatility
mean-reversion premium-selling strategy.
"""

from __future__ import annotations

import sys
import time as _time
from datetime import datetime, timezone

from .feed import CryptoFeed
from .client import KalshiClient
from .engine import AnalysisEngine, EngineConfig
from .premium_seller import PremiumSeller, PremiumSellerConfig, SellSignal


def _parse_markets(client: KalshiClient, engine: AnalysisEngine,
                   series_ticker: str = "KXBTCD") -> list:
    """Fetch and parse Kalshi markets."""
    markets_raw = client.get_markets(
        series_ticker=series_ticker, status="open", limit=100)
    parsed = [engine._parse_market(m) for m in markets_raw]
    return [m for m in parsed if m is not None]


def _format_dashboard(seller: PremiumSeller, btc_price: float,
                      vol: float, signals: list[SellSignal],
                      scan_num: int) -> str:
    """Render the premium seller dashboard."""
    s = seller.summary()
    lines = [
        "=" * 64,
        f"  PREMIUM SELLER v1  BTC ${btc_price:,.0f}  vol {vol*100:.0f}%  scan #{scan_num:04d}",
        f"  ${s['bankroll']:,.2f}  P&L ${s['total_pnl']:+,.2f}  "
        f"WR {s['win_rate']}  open {s['open']}  closed {s['closed']}",
        "=" * 64,
    ]

    if signals:
        lines.append(f"  signals ({len(signals)}):")
        for sig in signals[:3]:
            emoji = "🟢" if sig.score > 0.6 else "🟡"
            lines.append(
                f"    {emoji} NO {int(sig.no_price*100)}c @ ${sig.strike:,.0f} "
                f"({sig.otm_pct:.1f}% OTM, {sig.tte_minutes:.0f}m) "
                f"score={sig.score:.2f}"
            )
            lines.append(f"       {sig.reason}")
    else:
        lines.append("  waiting for vol spike...")

    if seller.positions:
        lines.append(f"  OPEN ({len(seller.positions)}):")
        for pos in seller.positions:
            lines.append(
                f"    #{pos.id} NO {int(pos.entry_price*100)}c @ ${pos.strike:,.0f} "
                f"| {pos.contracts}ct | cost ${pos.entry_cost:.2f} "
                f"| max profit ${pos.max_profit:.2f}"
            )

    if seller.closed_positions:
        recent = seller.closed_positions[-3:]
        lines.append(f"  LAST CLOSED ({len(recent)}):")
        for pos in recent:
            emoji = "WIN" if pos.pnl > 0 else "LOSS"
            lines.append(
                f"    #{pos.id} {emoji} P&L ${pos.pnl:+.4f} | "
                f"NO {int(pos.entry_price*100)}c @ ${pos.strike:,.0f}"
            )

    lines.append("=" * 64)
    return "\n".join(lines)


def run_premium_seller(
    series_ticker: str = "KXBTCD",
    starting_balance: float = 100.0,
    scan_interval: int = 15,
    force_fresh: bool = True,
):
    """Main loop for the premium seller strategy."""
    print(f"\n  PREMIUM SELLER — selling tail-risk premium on {series_ticker}")
    print(f"  Starting balance: ${starting_balance:.2f}")
    print(f"  Scan interval: {scan_interval}s  |  Ctrl+C to stop\n")

    feed = CryptoFeed()
    client = KalshiClient()
    engine = AnalysisEngine(EngineConfig())
    seller = PremiumSeller(
        config=PremiumSellerConfig(),
        bankroll=starting_balance,
    )

    scan_num = 0
    prev_price: float | None = None

    try:
        while True:
            scan_num += 1

            # Fetch BTC price
            try:
                from .series import SERIES
                btc = SERIES.get("KXBTCD")
                price = feed.get(btc.asset, btc.coingecko_id, btc.binance_symbol,
                                 force_fresh=force_fresh)
                from .volatility import get_volatility as gv
                vol = gv(btc.asset, btc.binance_symbol)
                current_price = price.price_usd
            except Exception:
                vol = 0.60
                current_price = prev_price or 63000.0

            # Calculate 15-minute change
            btc_change_15m = 0.0
            if prev_price and prev_price > 0:
                btc_change_15m = (current_price - prev_price) / prev_price * 100
            prev_price = current_price

            # Fetch markets
            try:
                markets = _parse_markets(client, engine, series_ticker)
            except Exception:
                markets = []

            # Scan for signals
            signals = seller.scan(markets, current_price, btc_change_15m)

            # Enter positions
            for sig in signals:
                if not seller.should_enter():
                    break
                pos = seller.enter(sig)
                if pos:
                    break  # One per scan

            # Check settlements
            seller.check_positions(client)

            # Dashboard
            dashboard = _format_dashboard(seller, current_price, vol, signals, scan_num)
            sys.stdout.write(dashboard + "\n")
            sys.stdout.flush()

            _time.sleep(scan_interval)

    except KeyboardInterrupt:
        s = seller.summary()
        print(f"\n\n  Premium Seller stopped after {scan_num} scans.")
        print(f"  Final balance: ${s['bankroll']:,.2f}  |  P&L: ${s['total_pnl']:+,.2f}")
        print(f"  Open: {s['open']}  |  Closed: {s['closed']}  |  WR: {s['win_rate']}")

    return seller
