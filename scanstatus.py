#!/usr/bin/env python3
"""
scanstatus.py - Standalone status helper for the scanning pipeline.

Prints service status, target counts, and recent output-file sizes.  This is a
thin wrapper around pipeline.py --status that also supports a compact
notification-friendly output mode.

Usage:
    python3 ~/scanstatus.py              # full status table
    python3 ~/scanstatus.py --compact    # one-line summary (good for notifications)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PIPELINE = Path.home() / "pipeline.py"


def compact_status() -> str:
    proc = subprocess.run(
        [sys.executable, str(PIPELINE), "--status"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = proc.stdout.splitlines()
    mass = "?"
    crypto = "?"
    total = "?"
    for line in lines:
        if line.startswith("Mass scan:"):
            mass = "running" if "RUNNING" in line else "stopped"
        elif line.startswith("Crypto scanner:"):
            crypto = "running" if "RUNNING" in line else "stopped"
        elif line.strip().startswith("total"):
            total = line.split()[-1]
    return f"mass={mass}, crypto={crypto}, targets={total}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Scanner pipeline status helper.")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print a one-line summary suitable for notifications.",
    )
    args = parser.parse_args()

    if args.compact:
        print(compact_status())
        return 0

    return subprocess.call([sys.executable, str(PIPELINE), "--status"])


if __name__ == "__main__":
    sys.exit(main())
