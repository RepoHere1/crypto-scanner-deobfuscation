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
ENCRYPT=false
KEEP_ORIGINALS=false

mkdir -p "$(dirname "$LOGFILE")" "$PID_DIR"

usage() {
    cat <<EOU
Usage: bash launch_all.sh [options]

Options:
  -d, --dashboard       Launch the live dashboard after starting services
  -i, --interval N      Dashboard refresh interval in seconds (default: 15)
  -e, --encrypt         Encrypt findings and offload to GitHub Gist
  --keep                Keep unencrypted originals after encryption (default: remove)
  -h, --help            Show this help

Examples:
  bash launch_all.sh                # run pipeline and print summary
  bash launch_all.sh -d             # run pipeline + live dashboard
  bash launch_all.sh --dashboard --interval 5
  bash launch_all.sh -e             # run pipeline then encrypt + offload
  bash launch_all.sh -d -e          # all of the above with dashboard
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
        -e|--encrypt)
            ENCRYPT=true
            shift
            ;;
        --keep)
            KEEP_ORIGINALS=true
            shift
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
# When WiFi returns the pipeline continues from where it was;
# Added a timeout mechanism to prevent indefinite hanging
# ---------------------------------------------------------------------------
_wait_for_wifi_launch() {
    local check_count=0
    local max_checks=10  # Limit to 5 minutes (10 * 30s)
    
    log "Checking for internet connectivity..."
    
    while ! curl -sf --connect-timeout 5 https://www.google.com >/dev/null 2>&1; do
        check_count=$((check_count + 1))
        
        if [ $check_count -ge $max_checks ]; then
            log "[!] Maximum connectivity checks reached ($max_checks). Proceeding anyway."
            echo "Warning: No internet connection detected, proceeding anyway..."
            return 0
        fi
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [wifi] No connectivity detected."
        echo "  Waiting for WiFi to connect… (check #$check_count/$max_checks, retrying every 30s)"
        sleep 30
    done
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [wifi] Connectivity OK — launching pipeline."
    log "[wifi] Connectivity OK — launching pipeline."
}

_wait_for_wifi_launch

# ---------------------------------------------------------------------------
# Run the unified pipeline
# ---------------------------------------------------------------------------
log "========================================"
log "LAUNCH_ALL - Running pipeline.py"
log "========================================"

# Try enhanced pipeline first, fall back to original if not available
if [ -f "$HOME_DIR/pipeline_enhanced.py" ]; then
    python3 "$HOME_DIR/pipeline_enhanced.py" | tee -a "$LOGFILE"
else
    python3 "$HOME_DIR/pipeline.py" | tee -a "$LOGFILE"
fi
PIPE_STATUS="${PIPESTATUS[0]}"

if [ "$PIPE_STATUS" -ne 0 ]; then
    log "[!] pipeline.py exited with status $PIPE_STATUS"
    notify "Crypto Scanner" "Pipeline failed (status $PIPE_STATUS)"
    exit "$PIPE_STATUS"
fi

notify "Crypto Scanner" "Pipeline started; services running in background"

# ---------------------------------------------------------------------------
# Optional encrypt + offload after pipeline completes
# ---------------------------------------------------------------------------
ENCRYPTED_GIST_URL=""
if [ "$ENCRYPT" = true ]; then
    log "========================================"
    log "ENCRYPT - Encrypting findings and offloading to GitHub"
    log "========================================"
    if [ -f "$HOME_DIR/encrypt_offload.py" ]; then
        ENCRYPT_FLAGS=""
        if [ "$KEEP_ORIGINALS" = true ]; then
            ENCRYPT_FLAGS="--keep"
        fi
        # Run encrypt_offload.py in a way that handles stdin properly
        if [ -t 0 ]; then
            # If running interactively, allow input
            python3 "$HOME_DIR/encrypt_offload.py" $ENCRYPT_FLAGS 2>&1 | tee -a "$LOGFILE"
        else
            # If not running interactively, try to run with no input
            echo "" | python3 "$HOME_DIR/encrypt_offload.py" $ENCRYPT_FLAGS 2>&1 | tee -a "$LOGFILE" || 
            python3 "$HOME_DIR/encrypt_offload.py" $ENCRYPT_FLAGS 2>&1 | tee -a "$LOGFILE" || 
            log "[!] encrypt_offload.py failed - may need interactive passphrase"
        fi
        
        ENCRYPT_STATUS="${PIPESTATUS[0]}"
        if [ "$ENCRYPT_STATUS" -ne 0 ]; then
            log "[!] encrypt_offload.py exited with status $ENCRYPT_STATUS"
        else
            # Extract Gist URL from dashboard log output for the notification
            ENCRYPTED_GIST_URL=$(grep -oP 'https://gist\.github\.com/\S+' "$LOGFILE" 2>/dev/null | tail -1)
            notify "Crypto Scanner" "Encryption complete"
        fi
    else
        log "[!] encrypt_offload.py not found; skipping encrypt step"
    fi
fi

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
