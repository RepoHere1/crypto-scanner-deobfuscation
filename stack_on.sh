#!/data/data/com.termux/files/usr/bin/bash
# Turn the full production stack ON and leave it running (no interactive dashboard).
set -o pipefail

HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/launch_all.log"
mkdir -p "$PID_DIR"

# Load tokens/keys
if [ -f "$HOME_DIR/.github_token" ]; then
  export GITHUB_TOKEN="$(head -1 "$HOME_DIR/.github_token" | tr -d '\r\n')"
  export GH_TOKEN="$GITHUB_TOKEN"
fi
# shellcheck disable=SC1090
[ -f "$HOME_DIR/.bashrc" ] && source "$HOME_DIR/.bashrc" 2>/dev/null || true
export ALCHEMY_API_KEY="${ALCHEMY_API_KEY:-}"
export ANKR_API_KEY="${ANKR_API_KEY:-}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

# SINGLETON — if stack already healthy, do not re-run full pipeline
_alive() { [ -f "$1" ] && kill -0 "$(tr -d ' \n\r' <"$1" 2>/dev/null)" 2>/dev/null; }
if _alive "$PID_DIR/keepalive.pid" && _alive "$PID_DIR/adaptive_scan.pid" && _alive "$PID_DIR/crypto_scanner.pid"; then
  if pgrep -f "mass_scan.py" >/dev/null 2>&1; then
    log "STACK already ON (keepalive+adaptive+mass+crypto) — skip bring-up"
    echo "[+] Stack already running. Use: keepstatus | walletview | dashw"
    python3 "$HOME_DIR/keepalive.py" --status 2>/dev/null || true
    exit 0
  fi
fi

log "========================================"
log "STACK_ON — production bring-up"
log "========================================"

# Keep the device awake while the stack is running
termux-wake-lock 2>/dev/null || true

# Connectivity (short)
if ! curl -sf --connect-timeout 5 https://www.google.com >/dev/null 2>&1; then
  log "[!] no connectivity probe — continuing anyway"
fi

# Refresh live hot targets (non-fatal if rate-limited)
log "[1/4] Live target generator"
python3 "$HOME_DIR/target_generator.py" >>"$LOG" 2>&1 || log "[!] target_generator non-zero"
python3 "$HOME_DIR/target_intelligence.py" >>"$LOG" 2>&1 || true

# Start pipeline services (mass + crypto + learn)
log "[2/4] Pipeline services"
if [ -f "$HOME_DIR/pipeline_enhanced.py" ]; then
  python3 "$HOME_DIR/pipeline_enhanced.py" >>"$LOG" 2>&1
  st=$?
else
  python3 "$HOME_DIR/pipeline.py" >>"$LOG" 2>&1
  st=$?
fi
log "pipeline exit=$st"

# Ensure crypto scanner on BOTH result streams if mass file exists
log "[3/4] Ensure crypto scanner"
if [ -f "$PID_DIR/crypto_scanner.pid" ] && kill -0 "$(cat "$PID_DIR/crypto_scanner.pid")" 2>/dev/null; then
  log "crypto_scanner already up pid=$(cat "$PID_DIR/crypto_scanner.pid")"
else
  # Prefer mass results if present else standard
  SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
  if [ ! -s "$SCAN_FILE" ]; then
    SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
  fi
  : >> "$SCAN_FILE"
  nohup python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" \
    >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
  echo $! > "$PID_DIR/crypto_scanner.pid"
  log "crypto_scanner started pid=$! file=$SCAN_FILE"
fi

# Lightweight watchdog — restarts crypto/mass if they die
log "[4/4] Watchdog"
cat > "$HOME_DIR/stack_watchdog.sh" <<'WD'
#!/data/data/com.termux/files/usr/bin/bash
HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/watchdog.log"
mkdir -p "$PID_DIR"
while true; do
  # crypto
  if [ ! -f "$PID_DIR/crypto_scanner.pid" ] || ! kill -0 "$(cat "$PID_DIR/crypto_scanner.pid" 2>/dev/null)" 2>/dev/null; then
    SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN_FILE" ] || SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN_FILE"
    nohup python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
    echo $! > "$PID_DIR/crypto_scanner.pid"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted crypto_scanner pid=$!" >>"$LOG"
  fi
  # adaptive / mass
  if [ ! -f "$PID_DIR/adaptive_scan.pid" ] || ! kill -0 "$(cat "$PID_DIR/adaptive_scan.pid" 2>/dev/null)" 2>/dev/null; then
    if [ ! -f "$PID_DIR/mass_scan.pid" ] || ! kill -0 "$(cat "$PID_DIR/mass_scan.pid" 2>/dev/null)" 2>/dev/null; then
      if [ -f "$HOME_DIR/adaptive_throttler.py" ]; then
        nohup python3 "$HOME_DIR/adaptive_throttler.py" >>"$HOME_DIR/adaptive_scan.log" 2>&1 &
        echo $! > "$PID_DIR/adaptive_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted adaptive pid=$!" >>"$LOG"
      elif [ -f "$HOME_DIR/run_throttled.py" ]; then
        nohup python3 "$HOME_DIR/run_throttled.py" >>"$HOME_DIR/run_throttled_out.log" 2>&1 &
        echo $! > "$PID_DIR/mass_scan.pid"
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] restarted mass pid=$!" >>"$LOG"
      fi
    fi
  fi
  sleep 60
done
WD
chmod 700 "$HOME_DIR/stack_watchdog.sh"
if [ -f "$PID_DIR/stack_watchdog.pid" ] && kill -0 "$(cat "$PID_DIR/stack_watchdog.pid")" 2>/dev/null; then
  log "watchdog already up"
else
  nohup bash "$HOME_DIR/stack_watchdog.sh" >>"$HOME_DIR/watchdog.log" 2>&1 &
  echo $! > "$PID_DIR/stack_watchdog.pid"
  log "watchdog pid=$!"
fi

# Multi-day keepalive (survives until reboot)
log "[+] Keepalive supervisor"
if [ -f "$PID_DIR/keepalive.pid" ] && kill -0 "$(cat "$PID_DIR/keepalive.pid")" 2>/dev/null; then
  log "keepalive already up pid=$(cat "$PID_DIR/keepalive.pid")"
else
  nohup python3 "$HOME_DIR/keepalive.py" >>"$HOME_DIR/keepalive.log" 2>&1 &
  echo $! > "$PID_DIR/keepalive.pid"
  log "keepalive pid=$!"
fi

log "STACK_ON complete — services left running"
echo ""
echo "[+] Stack is ON. Second window:"
echo "    watch2"
echo "    walletview"
echo "    dashw"
echo ""
# one-shot status
python3 "$HOME_DIR/watch2.py" --once 2>/dev/null || true
