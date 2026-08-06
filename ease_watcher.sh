#!/data/data/com.termux/files/usr/bin/bash
# ease_watcher.sh — launch THE-EASE daemon with wake lock + logging
#
# Usage:
#   bash ease_watcher.sh            # dry-run daemon (live data, no trades)
#   LIVE=1 bash ease_watcher.sh     # live trading daemon
#
# On Termux:Boot, this script is called by 02_launch_ease.sh.
# Can also be run manually:  bash ~/ease_watcher.sh

set -euo pipefail

HOME_DIR="$HOME"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="$HOME_DIR/ease_daemon.log"
MAX_LOG_BYTES=$((512 * 1024))  # 512 KB max log size

cd "$HOME_DIR" || exit 1

# Rotate log if too large
if [ -f "$LOG_FILE" ]; then
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$size" -gt "$MAX_LOG_BYTES" ]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
    fi
fi

# Acquire wake lock so Android doesn't kill us
termux-wake-lock 2>/dev/null || true

echo "=== THE-EASE DAEMON STARTED $(date) ===" | tee -a "$LOG_FILE"
echo "  HOME: $HOME_DIR" | tee -a "$LOG_FILE"
echo "  LIVE: ${LIVE:-0}" | tee -a "$LOG_FILE"

# Build arguments
ARGS="--daemon --poll 60"
if [ "${LIVE:-0}" = "1" ]; then
    ARGS="$ARGS --live"
    echo "  MODE: LIVE TRADING" | tee -a "$LOG_FILE"
else
    echo "  MODE: DRY-RUN (live data, no trades)" | tee -a "$LOG_FILE"
fi

# Run the strategy daemon
echo "  Starting python3 the_six.py $ARGS ..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

python3 "$SCRIPT_DIR/the_six.py" $ARGS 2>&1 | tee -a "$LOG_FILE"

RC=${PIPESTATUS[0]}
echo "" | tee -a "$LOG_FILE"
echo "=== THE-EASE DAEMON EXITED (code=$RC) at $(date) ===" | tee -a "$LOG_FILE"

# Release wake lock
termux-wake-unlock 2>/dev/null || true

exit $RC
