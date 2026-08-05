#!/data/data/com.termux/files/usr/bin/bash
# walletx_watchdog — keeps port 8080 alive forever. Cannot be killed by pkill.
# Run: bash ~/walletx_watchdog.sh &
set +e
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
cd "$HOME_DIR" || exit 1

echo "[watchdog] WalletX watchdog started (pid $$)"
echo "[watchdog] Monitoring http://0.0.0.0:8080 — auto-restart if dead"

restart_count=0
while true; do
    # Check if port 8080 is responding
    if curl -sf -m 3 http://0.0.0.0:8080/api/health >/dev/null 2>&1; then
        sleep 5
        continue
    fi
    restart_count=$((restart_count + 1))
    echo "[watchdog] #${restart_count} Port 8080 dead — restarting server..."
    # Kill any zombie processes on 8080
    fuser -k 8080/tcp 2>/dev/null
    sleep 2
    # Start fresh in a completely detached process
    setsid python3 "$HOME_DIR/walletx_server.py" >>"$HOME_DIR/walletx_server.log" 2>&1 < /dev/null &
    sleep 4
    if curl -sf -m 3 http://0.0.0.0:8080/api/health >/dev/null 2>&1; then
        echo "[watchdog] #${restart_count} Server restored OK"
    else
        echo "[watchdog] #${restart_count} Server still not responding — will retry"
    fi
done
