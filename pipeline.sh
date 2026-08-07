#!/bin/bash
# =============================================================================
# pipeline.sh — Full secret-surface → recovery pipeline
#
# Usage:
#   ./pipeline.sh                          # Full pipeline with defaults
#   ./pipeline.sh --target 50000           # Smaller target
#   ./pipeline.sh --deep --check-balances  # Deep search + balance checking
#   ./pipeline.sh --topics darkweb         # Dark-web/onion only
#
# Pipeline stages:
#   1. 7000.py         → paste_box.txt         (surface discovery)
#   2. onion_scanner   → onion_scanner_results.jsonl  (decode/decrypt)
#   3. pow_recover     → pow_recover_manifest.jsonl   (coin recovery)
#   4. walletx import  → walletx database              (import to walletx)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Defaults ──────────────────────────────────────────────────────────
TARGET="${TARGET:-10000}"
TOPICS="${TOPICS:-all}"
ENGINES="${ENGINES:-github,gitlab,docker,bitbucket}"
DEEP="${DEEP:-}"
FRESH="${FRESH:-}"
CHECK_BALANCES="${CHECK_BALANCES:-}"
SKIP_7000="${SKIP_7000:-}"
SKIP_SCANNER="${SKIP_SCANNER:-}"
SKIP_RECOVER="${SKIP_RECOVER:-}"

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --topics) TOPICS="$2"; shift 2 ;;
        --engines) ENGINES="$2"; shift 2 ;;
        --deep) DEEP="--deep"; shift ;;
        --fresh) FRESH="--fresh"; shift ;;
        --check-balances) CHECK_BALANCES="--check-balances"; shift ;;
        --skip-7000) SKIP_7000="1"; shift ;;
        --skip-scanner) SKIP_SCANNER="1"; shift ;;
        --skip-recover) SKIP_RECOVER="1"; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   SECRET-SURFACE → RECOVERY PIPELINE                       ║"
echo "║   7000.py → onion_scanner → pow_recover → walletx          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target : ${TARGET}"
echo "  Topics : ${TOPICS}"
echo "  Engines: ${ENGINES}"
echo "  Deep   : ${DEEP:-no}"
echo "  Balances: ${CHECK_BALANCES:-no}"
echo ""

START_TIME=$(date +%s)

# ═══════════════════════════════════════════════════════════════════════
# STAGE 1: Surface Discovery (7000.py)
# ═══════════════════════════════════════════════════════════════════════
if [[ -z "$SKIP_7000" ]]; then
    echo "━━━ STAGE 1/4: Surface Discovery (7000.py) ━━━"
    echo ""

    CMD="python3 7000.py --target ${TARGET} --topics ${TOPICS} --engines ${ENGINES}"
    [[ -n "$DEEP" ]] && CMD="$CMD --deep"
    [[ -n "$FRESH" ]] && CMD="$CMD --fresh"

    echo "  \$ $CMD"
    echo ""
    eval "$CMD"

    echo ""
    echo "  ✅ Stage 1 complete — paste_box.txt written"
    echo ""

    # ── Onion→clearnet correlation ────────────────────────────────
    echo "  Running onion→clearnet correlation..."
    python3 -c "
from 7000 import correlate_onion_clearnet
correlations = correlate_onion_clearnet('paste_box.txt', 'onion_correlations.jsonl')
" 2>/dev/null || python3 -c "
import sys; sys.path.insert(0, '.')
exec(open('7000.py').read().split('def run(args)')[0] + '''
correlate_onion_clearnet(\"paste_box.txt\", \"onion_correlations.jsonl\")
''')
" 2>/dev/null || echo "  ⚠ correlation skipped (7000.py import issue — run manually)"
    echo ""
else
    echo "━━━ STAGE 1/4: SKIPPED (--skip-7000) ━━━"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# STAGE 2: Decode/Decrypt Pipeline (onion_scanner.py)
# ═══════════════════════════════════════════════════════════════════════
if [[ -z "$SKIP_SCANNER" ]]; then
    echo "━━━ STAGE 2/4: Decode/Decrypt (onion_scanner.py) ━━━"
    echo ""

    # Scan paste_box.txt output
    if [[ -f paste_box.txt ]]; then
        python3 onion_scanner.py \
            --input paste_box.txt \
            --type paste_box \
            --output onion_scanner_results.jsonl \
            ${DEEP:+--deep}
    fi

    # Also scan trufflehog results if available
    for th_file in .trufflehog_mass_results.jsonl .trufflehog_results.jsonl; do
        if [[ -f "$th_file" ]]; then
            echo ""
            echo "  Scanning trufflehog results: $th_file"
            python3 onion_scanner.py \
                --input "$th_file" \
                --type trufflehog \
                --output "onion_scanner_$(basename "$th_file" .jsonl).jsonl" \
                ${DEEP:+--deep}
        fi
    done

    echo ""
    echo "  ✅ Stage 2 complete — onion_scanner_results.jsonl written"
    echo ""
else
    echo "━━━ STAGE 2/4: SKIPPED (--skip-scanner) ━━━"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# STAGE 3: POW Coin Recovery (pow_recover.py)
# ═══════════════════════════════════════════════════════════════════════
if [[ -z "$SKIP_RECOVER" ]]; then
    echo "━━━ STAGE 3/4: POW Coin Recovery (pow_recover.py) ━━━"
    echo ""

    RECOVER_ARGS="--output pow_recover_manifest.jsonl"
    [[ -n "$CHECK_BALANCES" ]] && RECOVER_ARGS="$RECOVER_ARGS --check-balances"

    # Scan paste_box
    if [[ -f paste_box.txt ]]; then
        python3 pow_recover.py --input paste_box.txt $RECOVER_ARGS
    fi

    # Scan onion_scanner results
    if [[ -f onion_scanner_results.jsonl ]]; then
        python3 pow_recover.py \
            --input onion_scanner_results.jsonl \
            --output pow_recover_from_scanner.jsonl \
            $CHECK_BALANCES
    fi

    echo ""
    echo "  ✅ Stage 3 complete — pow_recover_manifest.jsonl written"
    echo ""
else
    echo "━━━ STAGE 3/4: SKIPPED (--skip-recover) ━━━"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════
# STAGE 4: Import to walletx
# ═══════════════════════════════════════════════════════════════════════
echo "━━━ STAGE 4/4: walletx Import ━━━"
echo ""

if [[ -f pow_recover_manifest.jsonl ]]; then
    MANIFEST_COUNT=$(wc -l < pow_recover_manifest.jsonl)
    echo "  Manifest entries: ${MANIFEST_COUNT}"
    echo ""
    echo "  To import into walletx:"
    echo "    cat pow_recover_manifest.jsonl | walletx import"
    echo "    walletx recover --manifest pow_recover_manifest.jsonl"
    echo ""
    echo "  Or with onion correlations:"
    echo "    cat onion_correlations.jsonl | walletx import"
    echo ""
else
    echo "  ⚠ No recovery manifest found — run with --check-balances for live results"
    echo ""
fi

# ── Summary ───────────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - START_TIME ))
echo "═══════════════════════════════════════════════════════════════"
echo "  PIPELINE COMPLETE — ${ELAPSED}s"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Output files:"
for f in paste_box.txt onion_scanner_results.jsonl pow_recover_manifest.jsonl onion_correlations.jsonl ffod.txt; do
    if [[ -f "$f" ]]; then
        SIZE=$(wc -c < "$f" 2>/dev/null || echo "?")
        LINES=$(wc -l < "$f" 2>/dev/null || echo "?")
        printf "    %-40s %6s lines  %8s bytes\n" "$f" "$LINES" "$SIZE"
    fi
done
echo ""
echo "  Next: walletx recover --manifest pow_recover_manifest.jsonl"
echo ""
