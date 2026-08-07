export PATH="$HOME/.local/bin:$PATH"

# Load ~/.env first (RPC APIs), then explicit exports
[ -f "$HOME/.env" ] && set -a && . "$HOME/.env" && set +a
# Alchemy API key used by crypto_scanner.py and paste_box.py
export ALCHEMY_API_KEY="mi8wM6xm7rRBMYTCjHfM5"

# One-liner launcher for all scanning services
alias go='bash "$HOME/launch_all.sh"'
alias godir='cd "$HOME" && bash launch_all.sh'
alias all='tmux new-session -d -s scans "bash launch_all.sh" && tmux attach-session -t scans'
alias scandir='cd "$HOME" && bash start_crypto_scanner.sh'
alias scan='python3 "$HOME/crypto_scanner.py" "$HOME/.trufflehog_results.jsonl"'
alias scanstop='pkill -f "crypto_scanner.py" || true'
alias scanmem='cat "$HOME/crypto_scanner_memory.jsonl" | tail -n 20'
alias scanstatus='python3 "$HOME/scanstatus.py"'
alias scanpipeline='python3 "$HOME/pipeline.py"'
alias scanstopall='python3 "$HOME/pipeline.py" --stop'

# Paste box helpers
alias pastebox='$EDITOR "$HOME/paste_box.txt"'
alias pastep='python3 "$HOME/paste_box.py" && cat "$HOME/paste.txt"'
alias pastestatus='echo "=== RPCs ==="; cat "$HOME/rpc_endpoints.jsonl" 2>/dev/null; echo "=== API keys ==="; cat "$HOME/api_keys.jsonl" 2>/dev/null'

# Live scan dashboard aliases
alias dash='python3 "$HOME/dashboard.py"'
alias dashw='python3 "$HOME/dashboard.py" --watch'
alias dashgo='bash "$HOME/dashgo.sh"'

alias walletview='python3 "$HOME/wallet_view.py" --watch --page-size 8 --page-sec 8'

# --- second window / stack control ---
alias watch2='python3 "$HOME/watch2.py"'
alias w2='python3 "$HOME/watch2.py"'
alias stackon='bash "$HOME/stack_on.sh"'
alias stackwatch='python3 "$HOME/watch2.py" -i 5'

# Multi-day keepalive (survives until reboot)
alias keepgo='python3 "$HOME/keepalive.py" --daemon'
alias keepstatus='python3 "$HOME/keepalive.py" --status'
alias keepstop='python3 "$HOME/keepalive.py" --stop'
alias dashall='bash "$HOME/dashgo.sh"'
alias dashscan='bash "$HOME/dashscan.sh"'

alias walletall='python3 "$HOME/wallet_view.py" --once --all --cached'
alias walletpage='python3 "$HOME/wallet_view.py" --once --cached --page'
# WalletX: FROZEN while you touch; free-run ONLY after 120s silence
alias walletforensic='python3 "$HOME/wallet_forensic.py" --idle-sec 120 --tick-sec 0.35 --batch 24'
alias wforensic='python3 "$HOME/wallet_forensic.py" --idle-sec 120 --tick-sec 0.35 --batch 24'
alias walletx='python3 "$HOME/walletx_tui.py" --funded-only --batch 24'
alias wforensic1='python3 "$HOME/wallet_forensic.py" --once --cached --funded-only'
alias walletxdump='python3 "$HOME/wallet_forensic.py" --once --cached --funded-only'

# KALSHI Tap — automated BTC daily trading (case-insensitive)
alias kalshi-tap='$HOME/bin/kalshi-tap'
alias 'Kalshi-Tap'='$HOME/bin/kalshi-tap'
alias 'Kalshi-tap'='$HOME/bin/kalshi-tap'
alias 'KALSHI-TAP'='$HOME/bin/kalshi-tap'
alias 'kal-tap'='$HOME/bin/kalshi-tap'
alias kslshi='$HOME/bin/kalshi-tap'
alias kalshi='$HOME/bin/kalshi-tap'
alias kalshitap='$HOME/bin/kalshi-tap'
alias kslshitap='$HOME/bin/kalshi-tap'
alias kalsi='$HOME/bin/kalshi-tap'
alias kalsitap='$HOME/bin/kalshi-tap'
alias kalsh='$HOME/bin/kalshi-tap'
alias kalshtap='$HOME/bin/kalshi-tap'
alias kashli='$HOME/bin/kalshi-tap'
alias kashlitap='$HOME/bin/kalshi-tap'

alias 'kslshi-tap'='$HOME/bin/kalshi-tap'

# Kalshi API credentials
export KALSHI_API_KEY_ID='dc817127-84ab-4451-bf34-c794c9dcfe98'
export KALSHI_PRIVATE_KEY_PATH="$HOME/.kalshi/private_key.pem"

# Shared aliases (safe to git)
[ -f "$HOME/shell_aliases.sh" ] && . "$HOME/shell_aliases.sh"


# keep-termux-alive: hold partial wake lock so Android is less eager to kill
# Termux when you switch apps / sessions. Background stack uses setsid + watchdog.
# Open windows/sessions are NOT closed by stack scripts (no pkill of interactive TTYs).
if [[ $- == *i* ]]; then
  command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock >/dev/null 2>&1 || true
  # Re-assert wake lock quietly every interactive shell start
  ( command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock ) >/dev/null 2>&1 &
fi
export PATH="$HOME/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"
