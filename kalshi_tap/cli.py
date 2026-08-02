#!/usr/bin/env python3
"""KALSHI Tap — automated Kalshi trading for DAILY BTC markets.

Usage:
    kalshi-tap                    # Dry-run: analyze, show recommendations
    kalshi-tap --live             # Analyze AND place trades
    kalshi-tap --live --max 25    # Live with $25 max per market
    kalshi-tap -v                 # Verbose output
    kalshi-tap --setup            # Print API key setup instructions
    kalshi-tap --status           # Check API connectivity and balance
"""

from __future__ import annotations

import argparse
import logging
import os
import sys


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)-7s] %(message)s" if verbose else "%(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")


def format_price(price: float) -> str:
    return f"{price * 100:.0f}c"


def format_ev(ev: float) -> str:
    sign = "+" if ev > 0 else ""
    return f"{sign}{ev:.4f}"


def cmd_setup() -> int:
    print("=" * 62)
    print("  KALSHI TAP — Setup")
    print("=" * 62)
    print()
    print("You need a Kalshi API key pair to trade. Here is how:")
    print()
    print("1. Go to https://kalshi.com/settings/api")
    print("2. Click 'Generate API Key'")
    print("3. Save the key ID and private key PEM file")
    print()
    print("Then set these environment variables:")
    print()
    print("  export KALSHI_API_KEY_ID='your-key-id-here'")
    print("  export KALSHI_PRIVATE_KEY_PATH='/path/to/private_key.pem'")
    print()
    print("Add those to your ~/.bashrc to persist.")
    print()
    print("Verify with:")
    print("  kalshi-tap --status")
    print()
    return 0


def cmd_status() -> int:
    from kalshi_tap.client import KalshiClient, AuthError
    from kalshi_tap.btc_feed import BTCFeed

    key_id = os.environ.get("KALSHI_API_KEY_ID")
    key_path = os.environ.get("KALSHI_PRIVATE_KEY_PATH")

    if not key_id:
        print("[FAIL] KALSHI_API_KEY_ID not set")
        print("       Run: kalshi-tap --setup")
        return 1
    if not key_path:
        print("[FAIL] KALSHI_PRIVATE_KEY_PATH not set")
        print("       Run: kalshi-tap --setup")
        return 1
    if not os.path.exists(key_path):
        print(f"[FAIL] Private key not found: {key_path}")
        return 1

    print(f"[ OK ] Key ID: {key_id[:20]}...")
    print(f"[ OK ] Key file: {key_path}")

    try:
        feed = BTCFeed()
        price = feed.get_price()
        print(f"[ OK ] BTC: ${price.price_usd:,.0f} via {price.source}")
    except Exception as e:
        print(f"[WARN] BTC feed: {e}")

    try:
        client = KalshiClient()
        balance = client.get_balance()
        bal = balance.get("balance_dollars", balance.get("balance", "?"))
        print(f"[ OK ] Kalshi balance: ${bal}")
        print("[ OK ] Authentication verified")
    except AuthError as e:
        print(f"[FAIL] Auth failed: {e}")
        print("       Check your API key ID and private key path.")
        return 1
    except Exception as e:
        print(f"[WARN] Kalshi: {e}")

    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from kalshi_tap.client import KalshiClient, AuthError
    from kalshi_tap.feed import CryptoFeed
    from kalshi_tap.series import SERIES, get_default_series
    from kalshi_tap.engine import AnalysisEngine, EngineConfig

    # Resolve series
    series_ticker = args.series_ticker or "KXBTCD"
    series_def = None
    for s in SERIES:
        if s.ticker == series_ticker:
            series_def = s
            break
    if series_def is None:
        print(f"Unknown series: {series_ticker}")
        print(f"Available: {', '.join(s.ticker for s in SERIES)}")
        return 1

    print(f"[1/3] Fetching {series_def.asset} price...")
    try:
        feed = CryptoFeed()
        price = feed.get(series_def.asset, series_def.coingecko_id, series_def.binance_symbol)
        print(f"      {price}")
    except Exception as e:
        print(f"      [FAIL] {e}")
        return 1

    print("[2/3] Using default volatility (60%)...")
    vol = 0.60  # Default — can be overridden per asset in future
    print(f"      Annualized: {vol * 100:.0f}%")

    print(f"[3/3] Fetching {series_ticker} markets from Kalshi...")
    try:
        client = KalshiClient()
        markets_raw = client.get_markets(series_ticker=series_ticker, status="open")
        print(f"      {len(markets_raw)} markets found")
    except AuthError as e:
        print(f"      [FAIL] Auth: {e}")
        return 1
    except Exception as e:
        print(f"      [FAIL] {e}")
        return 1

    if not markets_raw:
        print()
        print(f"No open {series_ticker} markets found.")
        print("Check https://kalshi.com/markets/crypto for available markets.")
        return 0

    config = EngineConfig(max_bet_per_market_dollars=args.max_bet)
    engine = AnalysisEngine(config)
    recs = engine.analyze(markets_raw, price, volatility=vol)

    # Record to history
    try:
        from kalshi_tap.history import get_store
        store = get_store()
        store.record_run(
            series_ticker=series_ticker,
            asset=series_def.asset,
            spot_price=price.price_usd,
            volatility=vol,
            mode="live" if args.live else "dry",
            markets_fetched=len(markets_raw),
            recommendations=recs,
            recs_placed=len(recs) if args.live else 0,
        )
    except Exception:
        pass

    _print_recommendations(recs, live=args.live)

    if args.live and recs:
        print("[LIVE] Placing trades...")
        for rec in recs:
            try:
                price_cents = int(round(rec.price * 100))
                result = client.place_order(
                    ticker=rec.market.ticker,
                    side=rec.side,
                    count=rec.bet_contracts,
                    price_cents=price_cents,
                )
                oid = result.get("order_id", result.get("status", "?"))
                print(f"       ORDERED: {rec.side.upper()} {rec.market.ticker} "
                      f"x{rec.bet_contracts} @ {format_price(rec.price)} → {oid}")
            except Exception as e:
                print(f"       FAILED: {e}")

    return 0


def _print_recommendations(recs, live: bool = False) -> None:
    if not recs:
        print()
        print("No bets meet the EV threshold. Market looks efficiently priced.")
        return

    recs.sort(key=lambda r: r.expected_value, reverse=True)
    total_cost = 0.0
    total_ev = 0.0

    print()
    print("=" * 72)
    print(f"  RECOMMENDATIONS ({'LIVE' if live else 'DRY RUN'})")
    print("=" * 72)
    print()

    for i, rec in enumerate(recs, 1):
        conf_marker = {"high": "HI", "medium": "MED", "low": "LO"}.get(
            rec.confidence, "??"
        )
        print(f"  [{i}] [{conf_marker}] EV={format_ev(rec.expected_value)}")
        print(f"      {rec.market.title}")
        print(f"      Strike ${rec.market.strike:,.0f}  |  "
              f"Bet {rec.side.upper()} @ {format_price(rec.price)}  |  "
              f"{rec.bet_contracts} ct = ${rec.bet_dollars:.2f}")
        print(f"      Mkt P: {rec.market_prob:.1%}  True P: {rec.true_prob:.1%}  "
              f"Kelly: {rec.kelly_fraction:.3f}")
        print()

        total_cost += rec.bet_dollars
        total_ev += rec.expected_value * rec.bet_dollars

    print(f"  TOTAL: {len(recs)} bets | ${total_cost:.2f} risk | EV ~${total_ev:.2f}")
    print()
    if not live:
        print("  [DRY RUN] No trades placed. Use --live to execute.")
        print()


def _fetch_markets_and_scan(
    series_def,
    series_ticker: str,
    hcfg: "HedgeConfig",
    force_fresh: bool,
):
    """Core scan: fetch fresh price + markets + run hedge scanner. Returns (pairs, price, vol)."""
    from kalshi_tap.client import KalshiClient
    from kalshi_tap.feed import CryptoFeed
    from kalshi_tap.engine import AnalysisEngine, EngineConfig
    from kalshi_tap.hedge import HedgeScanner

    feed = CryptoFeed()
    price = feed.get(series_def.asset, series_def.coingecko_id, series_def.binance_symbol,
                     force_fresh=force_fresh)

    try:
        from kalshi_tap.volatility import get_volatility as gv
        vol = gv(series_def.asset, series_def.binance_symbol)
    except Exception:
        vol = 0.60

    client = KalshiClient()
    markets_raw = client.get_markets(series_ticker=series_ticker, status="open", limit=100)

    engine = AnalysisEngine(EngineConfig())
    parsed = [engine._parse_market(m) for m in markets_raw]
    valid = [m for m in parsed if m is not None]

    scanner = HedgeScanner(hcfg)
    pairs = scanner.scan(valid, price.price_usd, vol, series_ticker)
    return pairs, price, vol


def cmd_hedge(args: argparse.Namespace) -> int:
    """Scan for hedge pairs — complementary contrarian bets on different strikes."""
    from kalshi_tap.series import SERIES
    from kalshi_tap.hedge import HedgeConfig, format_hedge_results

    series_ticker = args.series_ticker or "KXBTCD"
    series_def = None
    for s in SERIES:
        if s.ticker == series_ticker:
            series_def = s
            break
    if series_def is None:
        print(f"Unknown series: {series_ticker}")
        print(f"Available: {', '.join(s.ticker for s in SERIES)}")
        return 1

    hcfg = HedgeConfig(
        max_contrarian_price=args.hedge_max_price / 100.0,
        min_true_prob=args.hedge_min_prob,
        min_ev=args.hedge_min_ev,
        min_payout_ratio=args.hedge_min_ratio,
        max_tte_minutes=args.hedge_max_tte,
        watch_alert_score=args.hedge_alert,
    )

    tte_label = f" (TTE ≤ {args.hedge_max_tte}m)" if args.hedge_max_tte > 0 else ""
    fresh_label = " [LIVE: no cache]" if args.hedge_no_cache else ""

    if args.hedge_autopilot:
        from kalshi_tap.autopilot import run_autopilot, AutopilotConfig
        from kalshi_tap.risk import RiskConfig
        pcfg = AutopilotConfig(
            starting_balance=args.hedge_bankroll,
            bet_per_leg_dollars=1.0,
            bet_per_pair_dollars=2.0,
            scan_interval_seconds=15,
            force_fresh=args.hedge_no_cache,
        )
        rcfg = RiskConfig(
            max_drawdown_pct=0.25,
            trailing_window=20,
            min_win_rate=0.30,
            base_bet_dollars=1.0,
            min_bet_dollars=0.50,
            max_bet_dollars=2.0,
        )
        run_autopilot(series_def, series_ticker, hcfg, pcfg, rcfg)
        return 0

    if args.hedge_watch:
        return _hedge_watch_loop(series_def, series_ticker, hcfg, args)
    else:
        print(f"[1/3] Fetching {series_def.asset} price{fresh_label}...")
        try:
            pairs, price, vol = _fetch_markets_and_scan(
                series_def, series_ticker, hcfg, args.hedge_no_cache)
            print(f"      {price}")
            print(f"[2/3] Volatility: {vol*100:.0f}% | Markets scanned{tte_label}")
            print(f"[3/3] Scanning for hedge pairs (max price {args.hedge_max_price}c)...")
            print(format_hedge_results(pairs))
            if not pairs:
                print("Try: --hedge-max-price 7 --hedge-min-prob 0.08")
                print("  or: --hedge-watch --hedge-max-tte 60 (monitor near-expiry)")
        except Exception as e:
            print(f"      [FAIL] {e}")
            return 1

    return 0


def _hedge_watch_loop(series_def, series_ticker: str, hcfg, args) -> int:
    """Continuous hedge monitor — scan every N seconds, highlight changes, alert top pairs."""
    import time as _time
    from datetime import datetime as _datetime

    interval = max(5, min(300, args.hedge_watch_interval))
    force_fresh = args.hedge_no_cache
    tte_label = f"TTE ≤ {args.hedge_max_tte}m" if args.hedge_max_tte > 0 else "all markets"

    print(f"\n{'='*64}")
    print(f"  HEDGE WATCH — {series_def.asset} {series_ticker}")
    print(f"  Refresh every {interval}s | {tte_label} | Max price {args.hedge_max_price}c")
    print(f"  Alert threshold: score ≥ {args.hedge_alert}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*64}\n")

    prev_top: list[str] = []  # top 5 ticker pairs from last scan
    scan_count = 0

    try:
        while True:
            scan_count += 1
            ts = _datetime.now().strftime("%H:%M:%S")
            sys.stdout.flush()  # ensure previous output is visible
            try:
                pairs, price, vol = _fetch_markets_and_scan(
                    series_def, series_ticker, hcfg, force_fresh)
            except Exception as e:
                print(f"  [{ts}] [ERR] {e}")
                _time.sleep(interval)
                continue

            # Determine what changed
            curr_top = [f"{p.bet_a.ticker}|{p.bet_b.ticker}" for p in pairs[:5]]
            new_pairs = [p for p in pairs[:3] if f"{p.bet_a.ticker}|{p.bet_b.ticker}" not in prev_top]
            dropped = [t for t in prev_top[:3] if t not in curr_top]

            # Alert on top-tier pairs
            alerts = [p for p in pairs if p.hedge_score >= hcfg.watch_alert_score]

            # Display
            if pairs:
                print(f"  [{ts}] #{scan_count:03d} {series_def.asset} ${price.price_usd:,.0f} "
                      f"vol {vol*100:.0f}% | {len(pairs)} pairs | "
                      f"top: {pairs[0].hedge_score:.4f}")
            else:
                print(f"  [{ts}] #{scan_count:03d} no pairs found")

            if pairs:
                # Show top 3 compact table
                for i, p in enumerate(pairs[:3], 1):
                    flag = " ★NEW" if p in new_pairs else ""
                    bar = f"p={p.joint_win_prob:.0%}"
                    print(f"       {i}. [{p.hedge_score:.4f}] "
                          f"{'↑' if p.bet_a.direction=='bullish' else '↓'}{p.bet_a.strike:,.0f} "
                          f"{p.bet_a.side.upper()}@{p.bet_a.price_cents}c  ×  "
                          f"{'↑' if p.bet_b.direction=='bullish' else '↓'}{p.bet_b.strike:,.0f} "
                          f"{p.bet_b.side.upper()}@{p.bet_b.price_cents}c  "
                          f"│ ${p.min_payout:.0f} win  {p.payout_ratio:.0f}x  {bar}{flag}")

            if new_pairs:
                print(f"       → NEW PAIR(S) detected this scan")

            if alerts:
                print(f"  ╔{'═'*60}╗")
                print(f"  ║  🚨 ALERT: {len(alerts)} pair(s) above score {hcfg.watch_alert_score}")
                for ap in alerts[:3]:
                    print(f"  ║  Score {ap.hedge_score:.4f} | "
                          f"${ap.min_payout:.0f} win {ap.payout_ratio:.0f}x | "
                          f"≥1: {ap.joint_win_prob:.0%} | "
                          f"{ap.bet_a.side.upper()} ${ap.bet_a.strike:,.0f}@{ap.bet_a.price_cents}c "
                          f"+ {ap.bet_b.side.upper()} ${ap.bet_b.strike:,.0f}@{ap.bet_b.price_cents}c")
                    print(f"  ║  {ap.description}")
                print(f"  ╚{'═'*60}╝")

            prev_top = curr_top
            _time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n  Stopped after {scan_count} scans.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="kalshi-tap",
        description="KALSHI Tap — automated Kalshi trading for crypto prediction markets",
    )
    parser.add_argument("--live", action="store_true",
                        help="Place real trades (default: dry-run only)")
    parser.add_argument("--max", type=float, default=50.0, dest="max_bet",
                        help="Maximum dollars per market bet (default: 50)")
    parser.add_argument("--series", type=str, default=None, dest="series_ticker",
                        help="Series ticker to trade (e.g. KXBTCD, KXETHD). Default: KXBTCD")
    parser.add_argument("--tui", action="store_true",
                        help="Launch interactive TUI dashboard")
    parser.add_argument("--hedge", action="store_true",
                        help="Scan for hedge pairs (contrarian bets on different strikes)")
    parser.add_argument("--hedge-watch", action="store_true",
                        help="Continuous hedge monitor — scan every N seconds")
    parser.add_argument("--hedge-watch-interval", type=int, default=15,
                        help="Seconds between watch scans (default: 15, min: 5)")
    parser.add_argument("--hedge-no-cache", action="store_true",
                        help="Bypass price cache — fetch fresh live data every scan")
    parser.add_argument("--hedge-max-tte", type=float, default=0.0,
                        help="Only scan markets closing within N minutes (0=all, try 60)")
    parser.add_argument("--hedge-max-price", type=float, default=5.0,
                        help="Max contrarian price in cents for hedge scan (default: 5)")
    parser.add_argument("--hedge-min-prob", type=float, default=0.03,
                        help="Min true probability for hedge bets (default: 0.03)")
    parser.add_argument("--hedge-min-ev", type=float, default=0.005,
                        help="Min EV threshold for hedge bets (default: 0.005)")
    parser.add_argument("--hedge-min-ratio", type=float, default=2.5,
                        help="Min payout ratio for hedge pairs (default: 2.5)")
    parser.add_argument("--hedge-alert", type=float, default=0.90,
                        help="Hedge score threshold for watch-mode alerts (default: 0.90)")
    parser.add_argument("--hedge-autopilot", action="store_true",
                        help="Autopilot dry-run: $100 bankroll, auto-trades top pairs until broke")
    parser.add_argument("--hedge-bankroll", type=float, default=100.0,
                        help="Starting bankroll for autopilot mode (default: 100)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose logging output")
    parser.add_argument("--setup", action="store_true",
                        help="Print API key setup instructions")
    parser.add_argument("--status", action="store_true",
                        help="Check API connectivity and balance")
    args = parser.parse_args()

    if args.setup:
        return cmd_setup()

    setup_logging(args.verbose)

    if args.status:
        return cmd_status()

    if args.hedge or args.hedge_watch or args.hedge_autopilot:
        return cmd_hedge(args)

    if args.tui:
        from kalshi_tap.tui import run_tui
        run_tui(series_ticker=args.series_ticker)
        return 0

    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
