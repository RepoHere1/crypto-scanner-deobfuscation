#!/usr/bin/env python3
"""
Notification daemon — polls SQLite for new funded hits, fires Android notifications.

Spawned by dashgo.  Runs in background, checks every 30s for new balance hits
that haven't been notified yet, and fires termux-notification for each.

No truncation in notifications — shows full chain + short address + balance.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
sys.path.insert(0, str(HOME))

import balance_db as db

POLL_SEC = 30
MIN_BALANCE_FOR_NOTIFY = 0.0  # fire for any nonzero balance


def _notify(chain: str, address: str, balance: float) -> None:
    """Fire one Android notification via Termux:API."""
    try:
        bal_s = f"{balance:,.6f}" if balance < 1e6 else f"{balance/1e6:,.2f}M"
        addr_s = address[:10] + "..." + address[-8:] if len(address) > 20 else address
        os.system(
            f'termux-notification --id walletx_hit --title "💰 Funded: {chain.upper()}" '
            f'--content "{addr_s}: {bal_s}" --priority high '
            f'--alert-once --sound default >/dev/null 2>&1'
        )
    except Exception:
        pass


def main():
    print("[notify] WalletX notification daemon started")
    notified_total = 0

    while True:
        try:
            hits = db.get_unnotified_hits()
            if hits:
                ids = []
                for h in hits:
                    bal = h.get("balance", 0)
                    if bal >= MIN_BALANCE_FOR_NOTIFY:
                        _notify(h["chain"], h["address"], bal)
                        ids.append(h["id"])
                if ids:
                    db.mark_hits_notified(ids)
                    notified_total += len(ids)
                    print(f"[notify] fired {len(ids)} notifications (total: {notified_total})")
        except Exception as exc:
            print(f"[notify] error: {exc}", file=sys.stderr)
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
