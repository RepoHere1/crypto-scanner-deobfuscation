#!/data/data/com.termux/files/usr/bin/bash
#
# LAUNCH_ALL - Thin wrapper around pipeline.py
# Runs the full pipeline (targets -> paste box -> background scanners -> learn crawl -> summary)
# and optionally launches the live dashboard.
#

set -o pipefail

HOME_DIR="$HOME"
LOGFILE="$HOME_DIR/launch_all.log"
PID_DIR="$HOME_DIR/.run_pids"
DASHBOARD=false
DASHBOARD_INTERVAL=15

mkdir -p "$(dirname "$LOGFILE")" "$PID_DIR"

usage() {
    cat <<EOU
Usage: bash launch_all.sh [options]

Options:
  -d, --dashboard       Launch the live dashboard after starting services
  -i, --interval N      Dashboard refresh interval in seconds (default: 15)
  -h, --help            Show this help

Examples:
  bash launch_all.sh              # run pipeline and print summary
  bash launch_all.sh -d           # run pipeline + live dashboard
  bash launch_all.sh --dashboard --interval 5
EOU
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -d|--dashboard)
            DASHBOARD=true
            shift
            ;;
        -i|--interval)
            [ -n "${2:-}" ] || { echo "--interval requires a value"; exit 1; }
            DASHBOARD_INTERVAL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

notify() {
    local title="$1"
    local msg="$2"
    if command -v termux-notification >/dev/null 2>&1; then
        # Fire-and-forget; don't let a missing/unresponsive Termux:API hang the launcher
        (termux-notification --title "$title" --content "$msg" >/dev/null 2>&1 &) >/dev/null 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# WiFi resilience — pause if WiFi is down before starting the pipeline.
# When WiFi returns the pipeline continues from where it was; the
# background services (run_throttled.py, crypto_scanner.py) each have
# their own wait-for-Wifi logic too.
# ---------------------------------------------------------------------------
_wait_for_wifi_launch() {
    local check_count=0
    while ! curl -sf --connect-timeout 5 https://www.google.com >/dev/null 2>&1; do
        check_count=$((check_count + 1))
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [wifi] No connectivity detected."
        echo "  Waiting for WiFi to connect… (check #$check_count, retrying every 30s)"
        sleep 30
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [wifi] Connectivity OK — launching pipeline."
}

_wait_for_wifi_launch

# ---------------------------------------------------------------------------
# Run the unified pipeline
# ---------------------------------------------------------------------------
log "========================================"
log "LAUNCH_ALL - Running pipeline.py"
log "========================================"

python3 "$HOME_DIR/pipeline.py" | tee -a "$LOGFILE"
PIPE_STATUS="${PIPESTATUS[0]}"

if [ "$PIPE_STATUS" -ne 0 ]; then
    log "[!] pipeline.py exited with status $PIPE_STATUS"
    notify "Crypto Scanner" "Pipeline failed (status $PIPE_STATUS)"
    exit "$PIPE_STATUS"
fi

notify "Crypto Scanner" "Pipeline started; services running in background"

# ---------------------------------------------------------------------------
# Optional live dashboard
# ---------------------------------------------------------------------------
if [ "$DASHBOARD" = true ]; then
    if [ -f "$HOME_DIR/dashboard.py" ]; then
        echo ""
        echo "[*] Starting live dashboard (Ctrl+C stops dashboard; services keep running)..."
        sleep 1
        exec python3 "$HOME_DIR/dashboard.py" --watch --interval "$DASHBOARD_INTERVAL"
    else
        echo ""
        echo "[!] dashboard.py not found; run 'dashw' manually once it exists."
    fi
fi
