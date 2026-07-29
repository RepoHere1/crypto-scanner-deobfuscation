#!/data/data/com.termux/files/usr/bin/bash
# dashgo — open live dashboard IMMEDIATELY; ensure stack in background
set +e
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
cd "$HOME_DIR" || exit 1

# Load keys quietly
if [ -f "$HOME_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$HOME_DIR/.env"
  set +a
fi
if [ -z "${ALCHEMY_API_KEY:-}" ] && [ -f "$HOME_DIR/.bashrc" ]; then
  ALCHEMY_API_KEY="$(grep -oP 'ALCHEMY_API_KEY="\K[^"]+' "$HOME_DIR/.bashrc" 2>/dev/null | head -1)"
  export ALCHEMY_API_KEY
fi

echo "[dashgo] opening live dashboard now…"
echo "[dashgo] stack ensure = background (not blocking UI)"

# Background ensure — never blocks dashboard
(
  mkdir -p "$HOME_DIR/.run_pids"
  if ! pgrep -f "keepalive.py" >/dev/null 2>&1; then
    nohup python3 "$HOME_DIR/keepalive.py" >>"$HOME_DIR/keepalive.log" 2>&1 &
    echo $! > "$HOME_DIR/.run_pids/keepalive.pid"
  fi
  if ! pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then
    SCAN="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN" ] || SCAN="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN"
    nohup python3 "$HOME_DIR/crypto_scanner.py" "$SCAN" \
      >>"$HOME_DIR/crypto_scanner_scanner.log" 2>&1 &
    echo $! > "$HOME_DIR/.run_pids/crypto_scanner.pid"
  fi
  if ! pgrep -f "adaptive_throttler.py" >/dev/null 2>&1 && ! pgrep -f "mass_scan.py" >/dev/null 2>&1; then
    nohup python3 "$HOME_DIR/adaptive_throttler.py" >>"$HOME_DIR/adaptive_scan.log" 2>&1 &
    echo $! > "$HOME_DIR/.run_pids/adaptive_scan.pid"
  fi
  if ! pgrep -f "stack_watchdog.sh" >/dev/null 2>&1; then
    nohup bash "$HOME_DIR/stack_watchdog.sh" >>"$HOME_DIR/watchdog.log" 2>&1 &
    echo $! > "$HOME_DIR/.run_pids/stack_watchdog.pid"
  fi
  termux-wake-lock >/dev/null 2>&1 || true
) >/dev/null 2>&1 &

if [ ! -f "$HOME_DIR/dashboard.py" ]; then
  echo "[!] dashboard.py missing at $HOME_DIR/dashboard.py"
  exit 1
fi

printf '\033[H\033[J' 2>/dev/null || true
exec python3 "$HOME_DIR/dashboard.py" --watch --interval "${DASH_INTERVAL:-10}"
