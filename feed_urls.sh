#!/data/data/com.termux/files/usr/bin/bash
# feed_urls.sh — quick path: append clean GitHub URLs into the IQ feeder.
# Usage:
#   feed_urls.sh https://github.com/owner/repo
#   feed_urls.sh owner/repo owner2/repo2
#   echo "owner/repo" | feed_urls.sh
#   feed_urls.sh list.txt
#   feed_urls.sh --restart url1 url2
set -euo pipefail
HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
RESTART=0
ARGS=()
for a in "$@"; do
  if [ "$a" = "--restart" ] || [ "$a" = "-r" ]; then
    RESTART=1
  else
    ARGS+=("$a")
  fi
done

# If stdin is a pipe and no file args, pass through stdin to feed_smooth
if [ ! -t 0 ]; then
  if [ "$RESTART" -eq 1 ]; then
    python3 "$HOME_DIR/feed_smooth.py" --restart "${ARGS[@]+"${ARGS[@]}"}"
  else
    python3 "$HOME_DIR/feed_smooth.py" --restart "${ARGS[@]+"${ARGS[@]}"}"
  fi
  exit $?
fi

if [ "$RESTART" -eq 1 ]; then
  exec python3 "$HOME_DIR/feed_smooth.py" --restart "${ARGS[@]+"${ARGS[@]}"}"
else
  # default: always restart so mass_scan actually eats new URLs
  exec python3 "$HOME_DIR/feed_smooth.py" --restart "${ARGS[@]+"${ARGS[@]}"}"
fi
