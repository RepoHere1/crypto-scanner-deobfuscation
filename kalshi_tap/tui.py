"""KALSHI Tap TUI v2 — professional dashboard with history, animations, sparklines.

Tabs:
    Markets  — Live analysis with sparkline, recommendations, LIVE toggle
    History  — Past analysis runs with accuracy stats
    Stats    — Aggregate performance: P&L, win rate, EV distribution

Keybindings:
    Space   Toggle LIVE / DRY RUN
    R       Force refresh
    1/2/3   Switch tabs: Markets / History / Stats
    Tab     Cycle focus
    Q       Quit
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import ClassVar

_here = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_here)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Select,
    Static,
    Switch,
    TabbedContent,
    TabPane,
    LoadingIndicator,
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.css.query import NoMatches

from kalshi_tap.client import KalshiClient, AuthError, KalshiError
from kalshi_tap.feed import CryptoFeed, CryptoPrice, get_feed
from kalshi_tap.series import SERIES, SeriesDef, get_default_series
from kalshi_tap.engine import AnalysisEngine, EngineConfig, BetRecommendation
from kalshi_tap.history import HistoryStore, get_store, resolve_paper_trades
from kalshi_tap.volatility import get_volatility

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Professional dark theme CSS with animations
# ---------------------------------------------------------------------------

CSS = """
Screen {
    background: #0a0e14;
}

Header {
    background: #111820;
    color: #bfc7d5;
    dock: top;
    border-bottom: hkey #ff6b35;
}

/* ---- Tab navigation ---- */

TabbedContent {
    height: 1fr;
}

TabbedContent > TabPane {
    background: #0a0e14;
    padding: 0;
}

TabPane {
    background: #0a0e14;
}

/* ---- Control bar ---- */

#control-bar {
    height: 3;
    padding: 0 2;
    background: #141b24;
    border-bottom: solid #1e2a38;
    align: center middle;
}

#control-bar Label {
    margin-right: 1;
    color: #5c6e80;
}

#series-select {
    width: 22;
    margin-right: 3;
    background: #1a2330;
    color: #bfc7d5;
    border: solid #2a3a4e;
}

#series-select:focus {
    border: solid #ff6b35;
}

#live-container {
    width: 32;
    align: center middle;
}

#mode-indicator {
    width: 14;
    text-align: center;
    text-style: bold;
    padding: 0 1;
    border: solid #1e2a38;
}

#mode-indicator.dry {
    color: #00d4aa;
    background: #0d2818;
    border: solid #00cc6644;
}

#mode-indicator.live {
    color: #ffffff;
    background: #ff3333;
    border: solid #ff3333;
    text-style: bold;
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0% { opacity: 1.0; }
    50% { opacity: 0.7; }
    100% { opacity: 1.0; }
}

#live-switch {
    margin: 0 1;
}

#live-switch:on {
    color: #ff6b35;
}

#live-label {
    color: #5c6e80;
}

/* ---- Stats bar ---- */

#stats-bar {
    height: 3;
    padding: 0 2;
    background: #111820;
    border-bottom: solid #1e2a38;
    align: center middle;
}

#stats-bar Label {
    margin-right: 2;
    color: #5c6e80;
}

#stats-bar .value {
    color: #bfc7d5;
    text-style: bold;
}

#stats-bar .positive {
    color: #00d4aa;
}

#stats-bar .negative {
    color: #ff6b35;
}

.stat-spacer {
    width: 1;
    color: #1e2a38;
}

/* ---- Sparkline row ---- */

#sparkline-row {
    height: 5;
    padding: 0 2;
    background: #0d131c;
    border-bottom: solid #1e2a38;
}

#sparkline-placeholder {
    color: #2a3a4e;
    content-align: center middle;
    width: 100%;
    height: 100%;
}

/* ---- Recommendations table ---- */

#recs-table {
    height: 1fr;
    background: #0a0e14;
}

DataTable {
    background: #0a0e14;
    color: #bfc7d5;
}

DataTable > .datatable--header {
    background: #141b24;
    color: #5c6e80;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #ff6b3522;
}

/* EV color coding */
.ev-high { color: #00d4aa; text-style: bold; }
.ev-med  { color: #ffaa00; }
.ev-low  { color: #5c6e80; }

.conf-hi { color: #00d4aa; }
.conf-med { color: #ffaa00; }
.conf-lo { color: #5c6e80; }

/* ---- History tab ---- */

#history-stats {
    height: 3;
    padding: 0 2;
    background: #111820;
    border-bottom: solid #1e2a38;
    align: center middle;
}

#history-stats Label {
    margin-right: 2;
    color: #5c6e80;
}

#history-stats .value {
    color: #bfc7d5;
    text-style: bold;
}

.history-stat-box {
    padding: 0 1;
    margin-right: 1;
    border: solid #1e2a38;
    background: #141b24;
}

.history-stat-box Label {
    margin-right: 0;
}

.stat-positive { color: #00d4aa; }
.stat-negative { color: #ff6b35; }

#history-table {
    height: 1fr;
    background: #0a0e14;
}

/* ---- Stats tab ---- */

#stats-summary {
    height: auto;
    padding: 1 2;
    background: #141b24;
    border-bottom: solid #1e2a38;
}

#stats-summary Label {
    color: #bfc7d5;
    margin-right: 1;
}

#stats-detail {
    height: 1fr;
    padding: 1 2;
    background: #0a0e14;
    overflow-y: auto;
}

#stats-detail Static {
    color: #5c6e80;
    margin-bottom: 1;
}

/* ---- Footer ---- */

#footer-bar {
    height: 3;
    padding: 0 2;
    background: #111820;
    border-top: solid #1e2a38;
    align: center middle;
}

#footer-bar Label {
    color: #5c6e80;
    margin-right: 1;
}

#footer-bar .hotkey {
    color: #ff6b35;
    text-style: bold;
}

#footer-bar .spacer {
    color: #1e2a38;
    margin: 0 1;
}

#loading-indicator {
    dock: bottom;
    height: 1;
    background: #141b24;
}

Footer {
    background: #111820;
    color: #5c6e80;
}

/* ---- Error panel ---- */

#error-panel {
    padding: 1 2;
    background: #2d1111;
    color: #ff6b35;
    border: solid #ff6b3544;
    height: auto;
    display: none;
}

#error-panel.visible {
    display: block;
}

/* ---- Notifications ---- */

.-textual-notification {
    background: #141b24;
    border: solid #1e2a38;
}

.-textual-notification.-information {
    border-left: solid #00d4aa;
}

.-textual-notification.-warning {
    border-left: solid #ff6b35;
}
"""


# ---------------------------------------------------------------------------
# Sparkline widget (pure Unicode, no external deps)
# ---------------------------------------------------------------------------

SPARK_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 60) -> str:
    """Render a Unicode sparkline from a list of values."""
    if not values or len(values) < 2:
        return "no data"

    mn = min(values)
    mx = max(values)
    rng = mx - mn if mx != mn else 1

    # Downsample to width
    step = max(1, len(values) // width)
    sampled = values[::step][-width:]

    chars = []
    for v in sampled:
        idx = min(len(SPARK_CHARS) - 1, int((v - mn) / rng * (len(SPARK_CHARS) - 1)))
        chars.append(SPARK_CHARS[idx])

    return "".join(chars)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class KalshiTapApp(App):
    """Interactive Kalshi trading dashboard with history and analytics."""

    TITLE = "KALSHI Tap"
    SUB_TITLE = "Crypto prediction market analytics"
    CSS = CSS

    BINDINGS: ClassVar = [
        Binding("space", "toggle_live", "LIVE/DRY", priority=True),
        Binding("r", "refresh", "Refresh", priority=True),
        Binding("1", "focus_tab('markets-tab')", "Markets", priority=False),
        Binding("2", "focus_tab('history-tab')", "History", priority=False),
        Binding("3", "focus_tab('stats-tab')", "Stats", priority=False),
        Binding("q", "quit", "Quit", priority=True),
    ]

    # Reactive state
    live_mode: bool = reactive(False)
    current_series_idx: int = reactive(0)
    is_loading: bool = reactive(False)
    last_error: str = reactive("")
    last_refresh: str = reactive("--:--:--")
    recommendations: list[BetRecommendation] = reactive([])
    balance_str: str = reactive("---")
    price_str: str = reactive("---")
    vol_str: str = reactive("---")
    total_risk: str = reactive("---")
    total_ev: str = reactive("---")
    active_tab: str = reactive("markets-tab")
    history_stats: dict = reactive({})
    sparkline_str: str = reactive("")
    price_history: list[float] = []

    def __init__(self, series_ticker: str | None = None):
        super().__init__()
        if series_ticker:
            for i, s in enumerate(SERIES):
                if s.ticker == series_ticker:
                    self.current_series_idx = i
                    break
        self._store = get_store()

    @property
    def current_series(self) -> SeriesDef:
        return SERIES[self.current_series_idx]

    # --- Compose ---

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        # Control bar
        with Container(id="control-bar"):
            with Horizontal():
                yield Label("Series:")
                yield Select(
                    [(s.label, s.ticker) for s in SERIES],
                    value=SERIES[self.current_series_idx].ticker,
                    id="series-select",
                    allow_blank=False,
                )
                with Container(id="live-container"):
                    yield Label("DRY RUN", id="mode-indicator", classes="dry")
                    yield Switch(value=False, id="live-switch")
                    yield Label("LIVE", id="live-label")

        # Stats bar
        with Container(id="stats-bar"):
            with Horizontal():
                yield Label("Price:", classes="label")
                yield Label(self.price_str, id="price-value", classes="value")
                yield Label("│", classes="stat-spacer")
                yield Label("Balance:", classes="label")
                yield Label(self.balance_str, id="balance-value", classes="value")
                yield Label("│", classes="stat-spacer")
                yield Label("Vol:", classes="label")
                yield Label(self.vol_str, id="vol-value", classes="value")
                yield Label("│", classes="stat-spacer")
                yield Label("Refreshed:", classes="label")
                yield Label(self.last_refresh, id="refresh-time", classes="value")

        # Sparkline row
        with Container(id="sparkline-row"):
            yield Static("loading...", id="sparkline-placeholder")

        # Error panel
        yield Static("", id="error-panel")

        # Tabbed content
        with TabbedContent(initial="markets-tab"):
            with TabPane("Markets", id="markets-tab"):
                with VerticalScroll(id="recs-table"):
                    yield DataTable(id="recs-datatable")

            with TabPane("History", id="history-tab"):
                with Container(id="history-stats"):
                    with Horizontal():
                        yield Label("Runs:", classes="label")
                        yield Label("0", id="hist-runs", classes="value")
                        yield Label("  Resolved:", classes="label")
                        yield Label("0", id="hist-resolved", classes="value")
                        yield Label("  Paper P&L:", classes="label")
                        yield Label("$0.00", id="hist-pnl", classes="value")
                with VerticalScroll(id="history-table"):
                    yield DataTable(id="hist-datatable")

            with TabPane("Stats", id="stats-tab"):
                with Container(id="stats-summary"):
                    yield Label("Aggregate performance across all runs")
                with VerticalScroll(id="stats-detail"):
                    yield Static("Loading statistics...")

        # Footer bar
        with Container(id="footer-bar"):
            with Horizontal():
                yield Label("[1]", classes="hotkey")
                yield Label("Markets")
                yield Label("│", classes="spacer")
                yield Label("[2]", classes="hotkey")
                yield Label("History")
                yield Label("│", classes="spacer")
                yield Label("[3]", classes="hotkey")
                yield Label("Stats")
                yield Label("│", classes="spacer")
                yield Label("[SPACE]", classes="hotkey")
                yield Label("LIVE")
                yield Label("│", classes="spacer")
                yield Label("[R]", classes="hotkey")
                yield Label("Refresh")
                yield Label("│", classes="spacer")
                yield Label("Total:", classes="label")
                yield Label(self.total_risk, id="footer-risk", classes="value")
                yield Label("risk / EV", classes="label")
                yield Label(self.total_ev, id="footer-ev", classes="value")
                yield Label("│", classes="spacer")
                yield Label("[Q]", classes="hotkey")
                yield Label("Quit")

        yield Footer()

    # --- Mount ---

    def on_mount(self) -> None:
        table = self.query_one("#recs-datatable", DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "Strike", "Side", "Price", "EV", "Conf", "Ct", "Cost")

        hist_table = self.query_one("#hist-datatable", DataTable)
        hist_table.cursor_type = "row"
        hist_table.add_columns("Time", "Series", "Price", "Recs", "Risk", "EV", "Mode")

        self.set_interval(30, self.action_refresh)
        self.refresh_data()

    # --- Watch reactives ---

    def watch_live_mode(self, value: bool) -> None:
        indicator = self.query_one("#mode-indicator", Label)
        if value:
            indicator.update("⚡ LIVE")
            indicator.set_class(True, "live")
            indicator.set_class(False, "dry")
        else:
            indicator.update("DRY RUN")
            indicator.set_class(False, "live")
            indicator.set_class(True, "dry")

    def watch_last_error(self, error: str) -> None:
        try:
            panel = self.query_one("#error-panel", Static)
            if error:
                panel.update(f"ERROR: {error}")
                panel.set_class(True, "visible")
            else:
                panel.set_class(False, "visible")
        except NoMatches:
            pass

    # --- Actions ---

    def action_toggle_live(self) -> None:
        switch = self.query_one("#live-switch", Switch)
        switch.toggle()
        self.live_mode = switch.value
        if self.live_mode:
            self.notify("⚡ LIVE MODE — real orders will execute on refresh",
                        severity="warning", timeout=6)
        else:
            self.notify("DRY RUN — analysis only, no orders placed",
                        severity="information", timeout=3)

    def action_refresh(self) -> None:
        self.refresh_data()

    def action_focus_tab(self, tab_id: str) -> None:
        try:
            self.query_one(TabbedContent).active = tab_id
            self.active_tab = tab_id
            if tab_id in ("history-tab", "stats-tab"):
                self.refresh_history_tab()
        except Exception:
            pass

    # --- Data refresh (real API calls only) ---

    @work(exclusive=True, thread=True)
    def refresh_data(self) -> None:
        self.is_loading = True
        self.last_error = ""

        series = self.current_series
        feed = get_feed()
        mode = "live" if self.live_mode else "dry"

        try:
            price = feed.get(series.asset, series.coingecko_id, series.binance_symbol)
            self.price_history.append(price.price_usd)
            if len(self.price_history) > 120:
                self.price_history = self.price_history[-120:]
            self._update_ui(
                price_str=f"{series.asset} ${price.price_usd:,.0f}",
                sparkline_str=sparkline(self.price_history),
            )
        except Exception as e:
            self.last_error = f"Price feed: {e}"
            self.is_loading = False
            return

        # Real volatility
        try:
            from kalshi_tap.volatility import get_volatility as gv
            vol = gv(series.asset, series.binance_symbol)
        except Exception:
            vol = 0.60
        self._update_ui(vol_str=f"{vol*100:.0f}%")

        try:
            client = KalshiClient()
        except (ValueError, AuthError) as e:
            self.last_error = f"Auth: {e}"
            self.is_loading = False
            return

        try:
            balance = client.get_balance()
            bal = balance.get("balance_dollars", "?")
            pv = balance.get("portfolio_value", 0)
            self._update_ui(balance_str=f"${bal} (pv ${int(pv)/100:,.2f})")
        except Exception:
            self._update_ui(balance_str="err")

        try:
            markets_raw = client.get_markets(
                series_ticker=series.ticker, status="open", limit=100)
        except KalshiError as e:
            self.last_error = f"API: {e}"
            self.is_loading = False
            return

        if not markets_raw:
            self._update_ui(total_risk="0 markets", total_ev="---")
            self._update_table([])
            self.is_loading = False
            return

        try:
            config = EngineConfig(min_ev_threshold=0.02, max_bet_per_market_dollars=50.0)
            engine = AnalysisEngine(config)
            recs = engine.analyze(markets_raw, price, volatility=vol)
            recs.sort(key=lambda r: r.expected_value, reverse=True)

            self.recommendations = recs
            total_risk = sum(r.bet_dollars for r in recs)
            total_ev = sum(r.expected_value * r.bet_dollars for r in recs)

            self._update_ui(
                total_risk=f"${total_risk:,.2f}",
                total_ev=f"${total_ev:,.2f}",
            )
            self._update_table(recs)

            # RECORD to history
            self._store.record_run(
                series_ticker=series.ticker,
                asset=series.asset,
                spot_price=price.price_usd,
                volatility=vol,
                mode=mode,
                markets_fetched=len(markets_raw),
                recommendations=recs,
                recs_placed=len(recs) if self.live_mode else 0,
            )

        except Exception as e:
            self.last_error = f"Engine: {e}"
            self.is_loading = False
            return

        if self.live_mode and recs:
            self._execute_live_orders(client, recs)

        # Resolve paper trades
        try:
            resolve_paper_trades(self._store, client)
        except Exception:
            pass

        now = datetime.now().strftime("%H:%M:%S")
        self._update_ui(last_refresh=now)
        self.is_loading = False

        # Refresh history tab if visible
        if self.active_tab in ("history-tab", "stats-tab"):
            self.call_from_thread(self.refresh_history_tab)

    def _execute_live_orders(self, client, recs):
        placed = 0
        for rec in recs:
            try:
                price_cents = int(round(rec.price * 100))
                client.place_order(
                    ticker=rec.market.ticker,
                    side=rec.side,
                    count=rec.bet_contracts,
                    price_cents=price_cents,
                )
                placed += 1
            except Exception:
                pass
        self.call_from_thread(
            self.notify,
            f"LIVE: {placed}/{len(recs)} orders placed",
            severity="warning",
        )

    # --- History tab refresh ---

    def refresh_history_tab(self) -> None:
        """Update the History and Stats tabs with stored data."""
        runs = self._store.get_recent_runs(30)
        stats = self._store.get_stats()

        # Update history stats bar
        try:
            self.query_one("#hist-runs", Label).update(str(stats["total_runs"]))
            self.query_one("#hist-resolved", Label).update(str(stats["resolved_recs"]))
            pnl = stats["paper_pnl"]
            pnl_str = f"${pnl:,.2f}"
            pnl_widget = self.query_one("#hist-pnl", Label)
            pnl_widget.update(pnl_str)
            pnl_widget.set_class(pnl >= 0, "stat-positive")
            pnl_widget.set_class(pnl < 0, "stat-negative")
        except NoMatches:
            pass

        # Update history table
        try:
            hist_table = self.query_one("#hist-datatable", DataTable)
            hist_table.clear()
            for run in runs[:20]:
                ts = run["timestamp"][:16].replace("T", " ")
                hist_table.add_row(
                    ts,
                    run["series_ticker"],
                    f"${run['spot_price']:,.0f}",
                    str(run["recs_found"]),
                    f"${run['total_risk']:,.2f}",
                    f"${run['total_ev']:,.2f}",
                    run["mode"].upper(),
                )
        except NoMatches:
            pass

        # Update stats tab
        try:
            detail = self.query_one("#stats-detail", VerticalScroll)
            detail.remove_children()

            acc = self._store.get_confidence_accuracy()

            lines = [
                f"Total runs: {stats['total_runs']}  "
                f"(dry: {stats['total_dry_runs']}, live: {stats['total_live_runs']})",
                f"Total recommendations: {stats['total_recs']}  "
                f"(resolved: {stats['resolved_recs']})",
                f"Paper P&L: ${stats['paper_pnl']:,.2f}",
                f"Avg EV: {stats['avg_ev']:.4f}  |  "
                f"Best EV: {stats['best_ev']:.4f}",
                f"Total theoretical risk: ${stats['total_theoretical_risk']:,.2f}",
                f"Last run: {stats['last_run_ts']}",
                "",
                "--- Confidence Accuracy (resolved bets) ---",
            ]

            for level, data in acc.items():
                wr = data["win_rate"]
                lines.append(
                    f"  {level:6s}: {data['wins']}/{data['total']} wins "
                    f"({wr:.0%})  avg P&L ${data['avg_pnl']:,.2f}"
                )

            for line in lines:
                detail.mount(Static(line))
        except Exception:
            pass

    # --- UI updates ---

    def _update_ui(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def watch_price_str(self, v): self._set_label("price-value", v)
    def watch_balance_str(self, v): self._set_label("balance-value", v)
    def watch_vol_str(self, v): self._set_label("vol-value", v)
    def watch_last_refresh(self, v): self._set_label("refresh-time", v)
    def watch_total_risk(self, v): self._set_label("footer-risk", v)
    def watch_total_ev(self, v): self._set_label("footer-ev", v)

    def watch_sparkline_str(self, v):
        try:
            self.query_one("#sparkline-placeholder", Static).update(
                f"[bold #ff6b35]{v}[/]")
        except NoMatches:
            pass

    def _set_label(self, widget_id, text):
        try:
            self.query_one(f"#{widget_id}", Label).update(text)
        except NoMatches:
            pass

    # --- Table management ---

    def _update_table(self, recs):
        self.call_from_thread(self._sync_update_table, recs)

    def _sync_update_table(self, recs):
        table = self.query_one("#recs-datatable", DataTable)
        table.clear()
        for i, rec in enumerate(recs, 1):
            conf = {"high": "HI", "medium": "MED", "low": "LO"}.get(rec.confidence, "??")
            ev_str = f"+{rec.expected_value:.4f}"
            ev_cls = "ev-high" if rec.expected_value > 0.08 else (
                "ev-med" if rec.expected_value > 0.04 else "ev-low")
            conf_cls = f"conf-{rec.confidence[:2].lower()}"
            table.add_row(
                str(i),
                f"${rec.market.strike:,.0f}",
                rec.side.upper(),
                f"{rec.price * 100:.0f}c",
                f"[{ev_cls}]{ev_str}[/]",
                f"[{conf_cls}]{conf}[/]",
                str(rec.bet_contracts),
                f"${rec.bet_dollars:.2f}",
            )

    # --- Event handlers ---

    @on(Select.Changed, "#series-select")
    def on_series_changed(self, event: Select.Changed) -> None:
        ticker = str(event.value)
        for i, s in enumerate(SERIES):
            if s.ticker == ticker:
                self.current_series_idx = i
                break
        self.notify(f"Switched to {self.current_series.label}")
        self.price_history = []
        self.refresh_data()

    @on(Switch.Changed, "#live-switch")
    def on_live_switch_changed(self, event: Switch.Changed) -> None:
        self.live_mode = event.value

    @on(TabbedContent.TabActivated)
    def on_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        self.active_tab = str(event.pane.id) if event.pane else "markets-tab"
        if self.active_tab in ("history-tab", "stats-tab"):
            self.call_from_thread(self.refresh_history_tab)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def run_tui(series_ticker: str | None = None) -> None:
    app = KalshiTapApp(series_ticker=series_ticker)
    app.run()
