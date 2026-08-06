#!/data/data/com.termux/files/usr/bin/bash
# dashgo — open live dashboard IMMEDIATELY; perpetual watchdog keeps all services alive
set +e
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
cd "$HOME_DIR" || exit 1

# ── Perpetual watchdog (master daemon — run once, all services stay alive forever) ──
if ! pgrep -f "perpetual_watchdog.sh" >/dev/null 2>&1; then
    setsid bash "$HOME_DIR/perpetual_watchdog.sh" >>"$HOME_DIR/perpetual_watchdog.log" 2>&1 < /dev/null &
    echo "[dashgo] Perpetual watchdog spawned (PID $!) — all 8 services will be kept alive forever"
fi

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

# Background ensure — detached from this TTY so closing/switching Termux
# sessions does not kill the stack (setsid + nohup).
(
  mkdir -p "$HOME_DIR/.run_pids"
  _bg() {
    # usage: _bg pidfile logfile envASSIGN... -- cmd args...
    local pidf="$1" logf="$2"; shift 2
    local envparts=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do envparts+=("$1"); shift; done
    [ "$1" = "--" ] && shift
    if [ "${#envparts[@]}" -gt 0 ]; then
      # shellcheck disable=SC2086
      nohup setsid env "${envparts[@]}" "$@" >>"$logf" 2>&1 < /dev/null &
    else
      nohup setsid "$@" >>"$logf" 2>&1 < /dev/null &
    fi
    echo $! > "$pidf"
  }
  # ── Paste box watcher (monitors paste_box.txt → auto-feeds pipeline) ──
  if ! pgrep -f "paste_box_watcher.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/paste_watcher.pid" "$HOME_DIR/paste_watcher.log" -- python3 "$HOME_DIR/paste_box_watcher.py"
    echo "[dashgo] paste box watcher spawned — drop files in ~/paste_box.txt"
  fi

  # ── WalletX web dashboard (waitress on :8080, auto-restart) ──
  if ! pgrep -f "walletx_server.py" >/dev/null 2>&1; then
    (
      while true; do
        echo "[dashgo-walletx] starting server..."
        python3 "$HOME_DIR/walletx_server.py" >>"$HOME_DIR/walletx_server.log" 2>&1
        echo "[dashgo-walletx] server stopped — restarting in 3s..."
        sleep 3
      done
    ) &
    echo $! > "$HOME_DIR/.run_pids/walletx_server.pid"
    echo "[dashgo] walletx web dashboard spawned → http://0.0.0.0:8080 (auto-restart enabled)"
  fi

  # ── Push notification daemon ──
  if ! pgrep -f "notify_hits.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/notify_hits.pid" "$HOME_DIR/notify_hits.log" -- python3 "$HOME_DIR/notify_hits.py"
    echo "[dashgo] notification daemon spawned"
  fi

  # ── Auto-decrypt vault files + feed scanner pipeline ──
  if [ -f "$HOME_DIR/auto_decrypt.py" ] && [ -f "$HOME_DIR/.encrypt_passphrase" ]; then
    echo "[dashgo] auto-decrypt vault ..."
    python3 "$HOME_DIR/auto_decrypt.py" >>"$HOME_DIR/auto_decrypt.log" 2>&1 &
  fi

  # ── Deobfuscation daemon (always-on preprocessor) ──
  if ! pgrep -f "deobfuscation_daemon.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/deobfuscation_daemon.pid" "$HOME_DIR/deobfuscation_daemon.log" -- python3 "$HOME_DIR/deobfuscation_daemon.py"
    echo "[dashgo] deobfuscation daemon spawned"
  fi

  # ── Daily funded email scheduler (polls for 9AM window) ──
  if ! pgrep -f "daily_funded_report.py" >/dev/null 2>&1; then
    # Run once immediately on cold start, then let keepalive handle periodic
    ( python3 "$HOME_DIR/daily_funded_report.py" --force >>"$HOME_DIR/daily_funded_report.log" 2>&1 ) &
  fi

  if ! pgrep -f "keepalive.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/keepalive.pid" "$HOME_DIR/keepalive.log" -- python3 "$HOME_DIR/keepalive.py"
  fi
  if ! pgrep -f "crypto_scanner.py" >/dev/null 2>&1; then
    SCAN="$HOME_DIR/.trufflehog_mass_results.jsonl"
    [ -s "$SCAN" ] || SCAN="$HOME_DIR/.trufflehog_results.jsonl"
    : >> "$SCAN"
    _bg "$HOME_DIR/.run_pids/crypto_scanner.pid" "$HOME_DIR/crypto_scanner_scanner.log" \
      "BALANCE_WORKERS=${BALANCE_WORKERS:-4}" -- python3 "$HOME_DIR/crypto_scanner.py" "$SCAN"
  fi
  if ! pgrep -f "adaptive_throttler.py" >/dev/null 2>&1 && ! pgrep -f "mass_scan.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/adaptive_scan.pid" "$HOME_DIR/adaptive_scan.log" \
      "MASS_SCAN_JOBS=${MASS_SCAN_JOBS:-1}" -- python3 "$HOME_DIR/adaptive_throttler.py"
  fi
  if ! pgrep -f "stack_watchdog.sh" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/stack_watchdog.pid" "$HOME_DIR/watchdog.log" -- bash "$HOME_DIR/stack_watchdog.sh"
  fi
  if ! pgrep -f "PoWo-dinosaurs_abandon_wealth.py" >/dev/null 2>&1; then
    _bg "$HOME_DIR/.run_pids/powo_scanner.pid" "$HOME_DIR/powo_scanner.log" \
      "ALCHEMY_API_KEY=${ALCHEMY_API_KEY}" -- python3 "$HOME_DIR/PoWo-dinosaurs_abandon_wealth.py"
    echo "[dashgo] 🦖 PoWo dinosaurs scanner spawned — hunting abandoned PoW accounts (chunk-fed from paste_box.txt)"
  fi
  termux-wake-lock >/dev/null 2>&1 || true
) >/dev/null 2>&1 &

if [ ! -f "$HOME_DIR/dashboard.py" ]; then
  echo "[!] dashboard.py missing at $HOME_DIR/dashboard.py"
  exit 1
fi

printf '\033[H\033[J' 2>/dev/null || true
exec python3 "$HOME_DIR/dashboard.py" --watch --interval "${DASH_INTERVAL:-10}"
