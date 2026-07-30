#!/data/data/com.termux/files/usr/bin/bash
# Turn the full production stack ON and leave it running (no interactive dashboard).
set -o pipefail

HOME_DIR="$HOME"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/launch_all.log"
mkdir -p "$PID_DIR"
# Safer phone defaults — prevent Termux LMK from over-parallel scanners
export MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-1}"
export BALANCE_WORKERS="${BALANCE_WORKERS:-4}"
export SCAN_LINE_MAX_BYTES="${SCAN_LINE_MAX_BYTES:-65536}"
export SCAN_TEXT_MAX_CHARS="${SCAN_TEXT_MAX_CHARS:-24000}"
export SCAN_LINE_SLEEP="${SCAN_LINE_SLEEP:-0.01}"


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

# Refresh live hot targets in BACKGROUND (never block bring-up / crash Termux)
log "[1/4] Success atlas + live target generator (background)"
(
  # Learn from REAL funded hits first — drives adaptive queries/orgs for generator
  timeout 120 python3 "$HOME_DIR/success_attributor.py" >>"$HOME_DIR/success_attribution.log" 2>&1 || log "[!] success_attributor non-zero/timeout"
  timeout 180 python3 "$HOME_DIR/target_generator.py" >>"$LOG" 2>&1 || log "[!] target_generator non-zero/timeout"
  timeout 90 python3 "$HOME_DIR/learn_crawl.py" >>"$HOME_DIR/learn_run.log" 2>&1 || log "[!] learn_crawl non-zero/timeout"
  timeout 60 python3 "$HOME_DIR/target_intelligence.py" >>"$LOG" 2>&1 || true
  # Rebuild paste.txt from paste_box so mass_scan picks adaptive targets after reboot
  timeout 90 python3 "$HOME_DIR/paste_box.py" >>"$LOG" 2>&1 || true
) &

# Start pipeline services WITHOUT blocking on full pipeline orchestrator.
# Direct service spawn is enough; pipeline_enhanced can hang on rate-limits.
log "[2/4] Pipeline services (direct spawn, non-blocking)"
st=0
log "pipeline exit=$st (direct)"

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
  nohup setsid python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" \
    >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 </dev/null &
  echo $! > "$PID_DIR/crypto_scanner.pid"
  log "crypto_scanner started pid=$! file=$SCAN_FILE"
fi

# Lightweight watchdog — restarts crypto/mass if they die
log "[4/4] Watchdog"
# Prefer the maintained stack_watchdog.sh on disk (rotation + renice + mem guard).
# Only seed a minimal one if the file is missing.
if [ ! -f "$HOME_DIR/stack_watchdog.sh" ]; then
  cat > "$HOME_DIR/stack_watchdog.sh" <<'WD'
#!/data/data/com.termux/files/usr/bin/bash
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
PID_DIR="$HOME_DIR/.run_pids"
LOG="$HOME_DIR/watchdog.log"
mkdir -p "$PID_DIR"
termux-wake-lock >/dev/null 2>&1 || true
while true; do
  termux-wake-lock >/dev/null 2>&1 || true
  if ! pgrep -f "keepalive.py" >/dev/null 2>&1; then
    nohup setsid python3 "$HOME_DIR/keepalive.py" >>"$HOME_DIR/keepalive.log" 2>&1 </dev/null &
    echo $! > "$PID_DIR/keepalive.pid"
  fi
  if ! pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then
    SCAN_FILE="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN_FILE" ] || SCAN_FILE="$HOME_DIR/.trufflehog_results.jsonl"
    nohup setsid env BALANCE_WORKERS="${BALANCE_WORKERS:-4}" MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-1}" \
      python3 "$HOME_DIR/crypto_scanner.py" "$SCAN_FILE" >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 </dev/null &
    echo $! > "$PID_DIR/crypto_scanner.pid"
  fi
  if ! pgrep -f "adaptive_throttler.py" >/dev/null 2>&1 && ! pgrep -f "mass_scan.py" >/dev/null 2>&1; then
    nohup setsid env MASS_SCAN_JOBS="${MASS_SCAN_JOBS:-1}" python3 "$HOME_DIR/adaptive_throttler.py" \
      >>"$HOME_DIR/adaptive_scan.log" 2>&1 </dev/null &
    echo $! > "$PID_DIR/adaptive_scan.pid"
  fi
  sleep 45
done
WD
fi
chmod 700 "$HOME_DIR/stack_watchdog.sh"
if [ -f "$PID_DIR/stack_watchdog.pid" ] && kill -0 "$(cat "$PID_DIR/stack_watchdog.pid")" 2>/dev/null; then
  log "watchdog already up"
else
  nohup setsid bash "$HOME_DIR/stack_watchdog.sh" >>"$HOME_DIR/watchdog.log" 2>&1  </dev/null &
  echo $! > "$PID_DIR/stack_watchdog.pid"
  log "watchdog pid=$!"
fi

# Multi-day keepalive (survives until reboot)
log "[+] Keepalive supervisor"
if [ -f "$PID_DIR/keepalive.pid" ] && kill -0 "$(cat "$PID_DIR/keepalive.pid")" 2>/dev/null; then
  log "keepalive already up pid=$(cat "$PID_DIR/keepalive.pid")"
else
  nohup setsid python3 "$HOME_DIR/keepalive.py" >>"$HOME_DIR/keepalive.log" 2>&1  </dev/null &
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
