#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🔥 WALLETX — Live Crypto Dashboard  ·  orange/black/white      ║
╚══════════════════════════════════════════════════════════════════╝

Full terminal-UI wallet viewer with:
  - Split-panel layout (leaderboard + wallet detail)
  - Orange/black/white theme with gold accents
  - Button-style navigation bar
  - Live RPC balance data (no mocks, no simulation)
  - Keyboard navigation (n/p/j/k/arrows)
  - Export, refresh, funded-filter toggle
  - Contract/infrastructure filter (contract_filter.py)

Usage:
    walletx              # alias → this dashboard
    python3 ~/walletx_tui.py
    python3 ~/walletx_tui.py --funded-only --batch 24
"""
from __future__ import annotations

import argparse
import json
import os
import select
import sys
import termios
import time
import tty
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

HOME = os.path.expanduser("~")
sys.path.insert(0, HOME)

import wallet_view as wv
import wallet_forensic as wf

# ── Theme: orange / black / white ──────────────────────────────────
# 256-color orange: 208 (bright), 166 (medium), 130 (dark gold)
# Standard fallback: yellow (33) if 256-color unavailable
CLR = {
    "bg":       "\033[40m",
    "fg":       "\033[97m",
    "dim":      "\033[2;37m",
    "bold":     "\033[1;97m",
    "orange":   "\033[38;5;208m",
    "orange_b": "\033[1;38;5;208m",
    "gold":     "\033[38;5;220m",
    "gold_b":   "\033[1;38;5;220m",
    "green":    "\033[92m",
    "green_b":  "\033[1;92m",
    "red":      "\033[91m",
    "cyan":     "\033[96m",
    "white":    "\033[97m",
    "rst":      "\033[0m",
    "inv":      "\033[7m",
    "u":        "\033[4m",
    "hide_cur": "\033[?25l",
    "show_cur": "\033[?25h",
}
C = CLR  # shorthand

# ── Box-drawing chars ──────────────────────────────────────────────
BOX = {
    "h": "─", "v": "│",
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
    "ml": "╠", "mr": "╣",
    "t": "╤", "b": "╧", "c": "┼",
}
THIN = {"h": "─", "v": "│", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘"}

# ── State ──────────────────────────────────────────────────────────
_paint_lock = __import__("threading").Lock()
_last_paint = 0.0
_anim_frame = 0
_anim_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _box(width: int, content: List[str], style: dict = None) -> List[str]:
    """Wrap content in a box-drawing border of given width."""
    s = style or BOX
    lines = [f"{C['orange']}{s['tl']}{s['h'] * (width - 2)}{s['tr']}{C['rst']}"]
    for line in content:
        pad = width - 2 - _vlen(line)
        lines.append(f"{C['orange']}{s['v']}{C['rst']}{line}{' ' * max(0, pad)}{C['orange']}{s['v']}{C['rst']}")
    lines.append(f"{C['orange']}{s['bl']}{s['h'] * (width - 2)}{s['br']}{C['rst']}")
    return lines


def _vlen(s: str) -> int:
    """Visible length — strip ANSI escapes."""
    import re
    return len(re.sub(r'\033\[[0-9;]*m', '', str(s)))


def _pad(s: str, width: int, align: str = "<") -> str:
    """Pad string to visible width, accounting for ANSI escapes."""
    v = _vlen(s)
    if v >= width:
        return s[:width]
    if align == "^":
        left = (width - v) // 2
        return " " * left + s + " " * (width - v - left)
    if align == ">":
        return " " * (width - v) + s
    return s + " " * (width - v)


def _btn(key: str, label: str, active: bool = True) -> str:
    """Render a button: [key] LABEL in orange/white."""
    k = f"{C['orange_b']}{C['inv']} {key} {C['rst']}" if active else f"{C['dim']}[{key}]{C['rst']}"
    return f"{k} {C['bold'] if active else C['dim']}{label}{C['rst']}"


def _clear() -> None:
    sys.stdout.write(f"\033[H\033[J{C['hide_cur']}")
    sys.stdout.flush()


# ── Data loading ───────────────────────────────────────────────────
def _load_live_state(funded_only: bool, max_wallets: int = 0):
    """Load wallets, balances, prices from the live pipeline."""
    st = wf.ForensicState(max_wallets=max_wallets, funded_only=funded_only)
    try:
        st.snapshot(force_gather=True)
    except Exception:
        pass
    try:
        st.reload_balances()
    except Exception:
        pass
    try:
        st.rebuild_ranked()
    except Exception:
        pass
    try:
        prices = wv.get_usd_prices()
    except Exception:
        prices = {}
    return st, prices


def _render_header(st, prices, focus: int, funded_only: bool, live: bool, idle_left: float) -> str:
    """Render the top status bar."""
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    n = len(st.ranked or [])
    focus_idx = max(0, min(n - 1, focus)) if n else 0

    # Compute portfolio
    try:
        portfolio = 0.0
        any_usd = False
        for row in (st.ranked or []):
            total = float(row[0])
            w = row[4]
            usd = wv.wallet_usd_total(w, st.balances, prices)
            if usd is not None:
                portfolio += usd
                any_usd = True
    except Exception:
        portfolio = 0.0
        any_usd = False

    pf_str = wv.format_usd(portfolio, color=True) if any_usd else f"{C['dim']}—{C['rst']}"
    funded_tag = f"{C['green_b']}FUNDED{C['rst']}" if funded_only else f"{C['dim']}ALL{C['rst']}"
    live_tag = f"{C['green']}● LIVE{C['rst']}" if live else f"{C['dim']}○ CACHED{C['rst']}"
    n_str = f"{n} wallets"

    return (
        f" {C['orange_b']}🔥 WALLETX{C['rst']}"
        f"  {C['dim']}│{C['rst']}"
        f"  {live_tag}"
        f"  {C['dim']}│{C['rst']}"
        f"  {C['gold_b']}{n_str}{C['rst']}"
        f"  {C['dim']}│{C['rst']}"
        f"  {pf_str}"
        f"  {C['dim']}│{C['rst']}"
        f"  {funded_tag}"
        f"  {C['dim']}│{C['rst']}"
        f"  {C['dim']}{now}{C['rst']}"
    )


def _render_leaderboard(st, prices, focus: int, panel_w: int, n_rows: int) -> List[str]:
    """Render the left-panel leaderboard."""
    ranked = st.ranked or []
    n = len(ranked)
    if n == 0:
        return _box(panel_w, [f" {C['dim']}No wallets in memory yet.{C['rst']}",
                               f" {C['dim']}Scanner is still running...{C['rst']}"])

    # Show a window around focus
    half = n_rows // 2
    start = max(0, focus - half)
    end = min(n, start + n_rows)
    if end - start < n_rows:
        start = max(0, end - n_rows)

    # Header
    hdr = (f" {C['bold']}LEADERBOARD{C['rst']}"
           f"{' ' * (panel_w - 20)}"
           f"{C['dim']}#{focus + 1}/{n}{C['rst']}")
    lines = [hdr, f"{C['dim']}{'─' * (panel_w - 2)}{C['rst']}"]

    for i in range(start, end):
        row = ranked[i]
        total, pend, chk, ts, w = row
        typ = (w.get("type") or "?").upper()
        sc = float(total)
        usd = wv.wallet_usd_total(w, st.balances, prices)

        # Format balance compact
        if sc > 1e6:
            bal_s = f"{sc / 1e6:,.1f}M"
        elif sc > 1e3:
            bal_s = f"{sc / 1e3:,.1f}K"
        elif sc > 1:
            bal_s = f"{sc:,.2f}"
        elif sc > 1e-8:
            bal_s = f"{sc:.6f}"
        else:
            bal_s = f"{C['dim']}0{C['rst']}"

        # USD
        usd_s = wv.format_usd(usd, color=True) if usd is not None else f"{C['dim']}—{C['rst']}"

        # Indicator
        if i == focus:
            marker = f"{C['orange_b']}▶{C['rst']}"
        else:
            marker = " "

        # Color-code by balance
        if sc > 1e-12:
            idx_color = C['gold_b']
            bal_color = C['green']
        else:
            idx_color = C['dim']
            bal_color = C['dim']

        # Single line per wallet
        key_short = w.get("key", "") or ""
        if len(key_short) > 26:
            key_short = key_short[:24] + "…"
        idx_s = f"{idx_color}{i + 1:>3}{C['rst']}"
        line = (f"{marker} {idx_s} {C['bold']}{typ:<4}{C['rst']}"
                f" {bal_color}{bal_s:>14}{C['rst']}"
                f" {usd_s:>14}"
                f" {C['dim']}{key_short}{C['rst']}")
        lines.append(line)

    if end < n:
        lines.append(f" {C['dim']}  … +{n - end} more wallets below{C['rst']}")

    return _box(panel_w, lines)


def _render_detail(st, prices, focus: int, panel_w: int) -> List[str]:
    """Render the right-panel wallet detail."""
    ranked = st.ranked or []
    if not ranked or focus >= len(ranked):
        return _box(panel_w, [f" {C['dim']}Select a wallet to view details.{C['rst']}"])

    row = ranked[focus]
    total, pend, chk, ts, w = row
    try:
        wv.ensure_derived(w)
    except Exception:
        pass

    typ = (w.get("type") or "?").upper()
    key_full = w.get("key") or ""
    src = w.get("source") or "unknown"
    tstamp = w.get("timestamp") or ""
    sc = float(total)
    usd = wv.wallet_usd_total(w, st.balances, prices)
    usd_s = wv.format_usd(usd, color=True) if usd is not None else f"{C['dim']}—{C['rst']}"

    lines = [
        f" {C['bold']}WALLET DETAIL{C['rst']}"
        f"{' ' * (panel_w - 22)}"
        f"{C['orange_b']}RANK #{focus + 1}{C['rst']}",
        f"{C['dim']}{'─' * (panel_w - 2)}{C['rst']}",
    ]

    # Type and balance
    lines.append(f" {C['bold']}TYPE:{C['rst']}  {C['orange_b']}{typ}{C['rst']}"
                 f"    {C['bold']}BAL:{C['rst']}  {C['green_b']}{sc:,.8f}{C['rst']}"
                 f"    {C['bold']}USD:{C['rst']}  {usd_s}")

    # Key (full, wrapped)
    if key_full:
        lines.append(f" {C['dim']}{'─' * (panel_w - 2)}{C['rst']}")
        lines.append(f" {C['bold']}🔑 KEY (FULL):{C['rst']}")
        # Wrap key across lines
        key_w = panel_w - 4
        for i in range(0, len(key_full), key_w):
            chunk = key_full[i:i + key_w]
            lines.append(f" {C['gold']}{chunk}{C['rst']}")

    # Linked secrets
    linked_hex = w.get("_linked_hex") or ""
    linked_wif = w.get("_linked_wif") or ""
    linked_seed = w.get("_linked_seed") or ""
    linked_hexes = w.get("_linked_hexes") or []
    linked_wifs = w.get("_linked_wifs") or []
    linked_seeds = w.get("_linked_seeds") or []
    link_method = w.get("_link_method") or ""

    if linked_seed:
        lines.append(f" {C['bold']}🌱 SEED:{C['rst']} {C['gold']}{linked_seed}{C['rst']}")
    if linked_wif:
        lines.append(f" {C['bold']}🔐 WIF:{C['rst']}  {C['gold']}{linked_wif}{C['rst']}")
    if linked_hex and linked_hex != key_full:
        lines.append(f" {C['bold']}🔧 HEX:{C['rst']}  {C['gold']}{linked_hex}{C['rst']}")
    if link_method:
        lines.append(f" {C['dim']}link: {link_method}{C['rst']}")

    # Source
    lines.append(f" {C['dim']}{'─' * (panel_w - 2)}{C['rst']}")
    if len(src) > panel_w - 10:
        src = src[:panel_w - 13] + "…"
    lines.append(f" {C['bold']}SRC:{C['rst']}  {C['dim']}{src}{C['rst']}")
    if tstamp:
        lines.append(f" {C['bold']}TS:{C['rst']}   {C['dim']}{tstamp[:19]}{C['rst']}")

    # Addresses with balances
    try:
        rows = wf.wallet_addr_rows(w, st.balances, st.meta)
    except Exception:
        rows = []
    funded_addrs = [(r["chain"], r["address"], r.get("balance"), r.get("meta", {}))
                    for r in rows
                    if isinstance(r.get("balance"), (int, float)) and r.get("balance", 0) > 1e-12
                    and not r.get("noise")]

    if funded_addrs:
        lines.append(f" {C['dim']}{'─' * (panel_w - 2)}{C['rst']}")
        lines.append(f" {C['bold']}FUNDED ADDRESSES ({len(funded_addrs)}):{C['rst']}")
        for chain, addr, bal, meta in funded_addrs:
            live_tag = f"{C['green']}●{C['rst']}" if meta.get("live") else f"{C['dim']}○{C['rst']}"
            chain_u = chain.upper()
            # Truncate address for display
            addr_s = addr
            if len(addr) > 30:
                addr_s = addr[:14] + "…" + addr[-14:]
            # Format balance
            if bal > 1e6:
                bal_s = f"{bal / 1e6:,.1f}M"
            elif bal > 1:
                bal_s = f"{bal:,.2f}"
            else:
                bal_s = f"{bal:.8f}"
            u = wv.usd_value(chain, bal, prices)
            u_s = wv.format_usd(u, color=True) if u is not None else ""
            lines.append(f" {live_tag} {C['cyan']}{chain_u:<6}{C['rst']}"
                         f" {C['dim']}{addr_s}{C['rst']}"
                         f" {C['green']}{bal_s:>14}{C['rst']}"
                         f" {u_s}")
    else:
        lines.append(f" {C['dim']}No funded addresses (pending or zero).{C['rst']}")

    return _box(panel_w, lines)


def _render_buttons(funded_only: bool, live: bool, n: int, focus: int, idle_left: float) -> str:
    """Render the bottom button bar."""
    buttons = [
        _btn("n", "NEXT"),
        _btn("p", "PREV"),
        _btn("f", "FUNDED" if funded_only else "ALL"),
        _btn("r", "REFRESH"),
        _btn("e", "EXPORT"),
        _btn("q", "QUIT"),
    ]
    bar = "  ".join(buttons)
    # Status
    if idle_left > 0:
        mins = int(idle_left) // 60
        secs = int(idle_left) % 60
        status = f"{C['dim']}freeze {mins:02d}:{secs:02d}{C['rst']}"
    else:
        status = f"{C['green']}● free-run{C['rst']}"
    return f" {bar}   {status}"


def _render_screen(st, prices, focus: int, funded_only: bool, live: bool,
                   idle_left: float, frame: int, cols: int, lines_term: int) -> str:
    """Compose the full screen."""
    # Layout calculations
    panel_w_left = max(40, cols // 2 - 2)
    panel_w_right = cols - panel_w_left - 2
    n_rows_left = lines_term - 7  # header + buttons + padding

    spinner = _anim_chars[frame % len(_anim_chars)] if live else " "
    anim_tag = f"{C['orange_b']}{spinner}{C['rst']}"

    header = _render_header(st, prices, focus, funded_only, live, idle_left)
    leaderboard_lines = _render_leaderboard(st, prices, focus, panel_w_left, n_rows_left)
    detail_lines = _render_detail(st, prices, focus, panel_w_right)
    buttons = _render_buttons(funded_only, live, len(st.ranked or []), focus, idle_left)

    # Assemble
    output_lines = []
    # Top border
    output_lines.append(f"{C['orange']}{BOX['tl']}{BOX['h'] * (cols - 2)}{BOX['tr']}{C['rst']}")
    # Header row
    output_lines.append(f"{C['orange']}{BOX['v']}{C['rst']} {anim_tag}{header}{' ' * max(0, cols - 2 - _vlen(header) - len(anim_tag) - 2)}{C['orange']}{BOX['v']}{C['rst']}")
    # Divider
    output_lines.append(f"{C['orange']}{BOX['ml']}{BOX['h'] * (cols - 2)}{BOX['mr']}{C['rst']}")

    # Side-by-side panels
    max_detail_lines = len(leaderboard_lines)
    for i in range(max_detail_lines):
        left = leaderboard_lines[i] if i < len(leaderboard_lines) else ""
        right = detail_lines[i] if i < len(detail_lines) else ""
        # Pad left to panel width
        left_padded = _pad(left, panel_w_left)
        output_lines.append(f" {left_padded}  {right}")

    # Bottom divider
    output_lines.append(f"{C['orange']}{BOX['ml']}{BOX['h'] * (cols - 2)}{BOX['mr']}{C['rst']}")
    # Button bar
    output_lines.append(f"{C['orange']}{BOX['v']}{C['rst']} {buttons}{' ' * max(0, cols - 2 - _vlen(buttons) - 2)}{C['orange']}{BOX['v']}{C['rst']}")
    # Bottom border
    output_lines.append(f"{C['orange']}{BOX['bl']}{BOX['h'] * (cols - 2)}{BOX['br']}{C['rst']}")

    return "\n".join(output_lines) + C['hide_cur']


# ── Input ───────────────────────────────────────────────────────────
_stdin_fd: int = -1


def _set_fd(fd: int) -> None:
    global _stdin_fd
    _stdin_fd = fd


def _read_key(timeout: float = 0.0) -> Optional[str]:
    fd = _stdin_fd
    if fd < 0:
        fd = sys.stdin.fileno()
        _set_fd(fd)
    try:
        p = select.poll()
        p.register(fd, select.POLLIN)
        timeout_ms = max(1, int(timeout * 1000)) if timeout > 0 else 0
        events = p.poll(timeout_ms)
        if not events:
            return None
        raw = os.read(fd, 1)
        if not raw:
            return None
        return raw.decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None


# ── Main loop ───────────────────────────────────────────────────────
def run(args):
    focus = max(0, int(args.index))
    live = not args.cached
    batch = max(1, int(args.batch))
    funded_only = bool(args.funded_only)
    idle_sec = max(30.0, float(getattr(args, "idle_sec", 120.0)))
    poll_sec = max(0.12, float(getattr(args, "tick_sec", 0.35)))
    global _anim_frame

    # Set up terminal
    fd = sys.stdin.fileno()
    _set_fd(fd)
    old_term = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
    except termios.error:
        pass

    # Load initial state
    st, prices = _load_live_state(funded_only, max_wallets=args.max_wallets)
    if st.ranked:
        focus = max(0, min(len(st.ranked) - 1, focus))

    last_input = time.time()
    last_refresh = time.time()
    last_paint = 0.0
    cols = 80
    rows = 24

    try:
        while True:
            # Terminal size
            try:
                sz = os.get_terminal_size(fd)
                cols, rows = sz.columns, sz.lines
            except Exception:
                cols, rows = 80, 24

            now = time.time()
            idle_for = now - last_input
            idle_left = max(0.0, idle_sec - idle_for)
            timeout = min(poll_sec, max(0.08, idle_left)) if idle_left > 0 else min(poll_sec, 0.5)

            # Check for key
            key = _read_key(timeout=timeout)
            now = time.time()
            did_nav = False

            if key is not None:
                last_input = now
                if key in ("q", "Q", "\x03"):
                    break
                if key in ("n", "N", "j", "J", " ", "\r", "\n"):
                    focus += 1
                    did_nav = True
                elif key in ("p", "P", "k", "K", "b", "B"):
                    focus = max(0, focus - 1)
                    did_nav = True
                elif key in ("t", "T", "h", "H"):
                    focus = 0
                    did_nav = True
                elif key in ("f", "F"):
                    funded_only = not funded_only
                    focus = 0
                    st, prices = _load_live_state(funded_only, max_wallets=args.max_wallets)
                    did_nav = True
                elif key in ("r", "R"):
                    st, prices = _load_live_state(funded_only, max_wallets=args.max_wallets)
                    if st.ranked:
                        focus = max(0, min(len(st.ranked) - 1, focus))
                    last_input = time.time()
                    did_nav = True
                elif key in ("e", "E"):
                    if st.ranked:
                        focus = max(0, min(len(st.ranked) - 1, focus))
                        tw = st.ranked[focus][4]
                        tbal = st.ranked[focus][0]
                        try:
                            path = wf.export_dossier(tw, st.balances, st.meta, focus + 1, tbal)
                            # Show briefly
                            pass
                        except Exception:
                            pass
                    did_nav = True
                elif key == "\x1b":
                    k2 = _read_key(0.06)
                    if k2 == "[":
                        k3 = _read_key(0.06)
                        if k3 in ("C", "B"):  # right/down arrow
                            focus += 1
                            did_nav = True
                        elif k3 in ("D", "A"):  # left/up arrow
                            focus = max(0, focus - 1)
                            did_nav = True
                    elif k2 is None:
                        break

                # Drain any burst input
                while True:
                    k = _read_key(0.0)
                    if k is None:
                        break
                last_input = time.time()

            # Clamp focus
            if st.ranked:
                focus = max(0, min(len(st.ranked) - 1, focus))
                if did_nav:
                    try:
                        wv.ensure_derived(st.ranked[focus][4])
                    except Exception:
                        pass

            # Periodic data refresh (every 8s in free-run)
            idle_for_now = time.time() - last_input
            if idle_for_now >= idle_sec and (time.time() - last_refresh) >= 8.0:
                st, prices = _load_live_state(funded_only, max_wallets=args.max_wallets)
                if st.ranked:
                    focus = max(0, min(len(st.ranked) - 1, focus))
                last_refresh = time.time()

            # Paint (throttled to 15fps max)
            if did_nav or (time.time() - last_paint) >= 0.5:
                with _paint_lock:
                    _anim_frame += 1
                    screen = _render_screen(
                        st, prices, focus, funded_only, live,
                        max(0.0, idle_sec - (time.time() - last_input)),
                        _anim_frame, cols, rows,
                    )
                    sys.stdout.write(f"\033[H{screen}")
                    sys.stdout.flush()
                last_paint = time.time()

    except KeyboardInterrupt:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_term)
        except Exception:
            pass
        sys.stdout.write(f"\033[H\033[J{C['show_cur']}")
        sys.stdout.flush()
        print(f"{C['orange']}walletx — done{C['rst']}")


def main():
    ap = argparse.ArgumentParser(description="WalletX TUI Dashboard")
    ap.add_argument("--cached", action="store_true", help="no live RPC")
    ap.add_argument("--funded-only", action="store_true", help="only nonzero-balance wallets")
    ap.add_argument("--batch", type=int, default=24)
    ap.add_argument("--index", type=int, default=0, help="0-based focus rank")
    ap.add_argument("--max-wallets", type=int, default=0)
    ap.add_argument("--idle-sec", type=float, default=120.0)
    ap.add_argument("--tick-sec", type=float, default=0.35)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
