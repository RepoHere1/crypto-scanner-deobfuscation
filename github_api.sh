#!/data/data/com.termux/files/usr/bin/bash
# GitHub API helper - reads token from ~/.github_token
set -euo pipefail
TOKEN_FILE="$HOME/.github_token"
if [ ! -f "$TOKEN_FILE" ]; then
    echo "[!] Token file not found: $TOKEN_FILE" >&2
    exit 1
fi
TOKEN=$(tr -d '\n' < "$TOKEN_FILE")
if [ -z "$TOKEN" ]; then
    echo "[!] Token file is empty" >&2
    exit 1
fi
# Allow overriding URL, method, body
URL="${1:-https://api.github.com/user}"
METHOD="${2:-GET}"
BODY="${3:-}"
exec curl -s -S -X "$METHOD" \
    -H "Authorization: token $TOKEN" \
    -H 'Accept: application/vnd.github.v3+json' \
    -H 'User-Agent: RepoHere1-Termux' \
    ${BODY:+-d "$BODY"} \
    "$URL"
