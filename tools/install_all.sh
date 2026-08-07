#!/bin/bash
# =============================================================================
# tools/install_all.sh — Install gitleaks, whispers, brainflayer, collider, bitcrack
#
# Usage:
#   source tools/install_all.sh    # source to export TOOL paths
#   bash tools/install_all.sh      # run directly
#
# Prerequisites: Termux pkg manager or apt
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR"
HOME_DIR="$(dirname "$SCRIPT_DIR")"
INSTALL_DIR="$HOME_DIR/.dashgo_tools"
BIN_DIR="$INSTALL_DIR/bin"
mkdir -p "$BIN_DIR" "$INSTALL_DIR"

GREEN='\033[92m'; RED='\033[91m'; YELLOW='\033[93m'; CYAN='\033[96m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

log()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[X]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }
step() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${RESET}\n"; }

# ── Ensure base deps via pkg ──────────────────────────────────────────
ensure_pkg_deps() {
    if command -v pkg &>/dev/null; then
        local needed=""
        command -v git      &>/dev/null || needed="$needed git"
        command -v go       &>/dev/null || needed="$needed golang"
        command -v clang    &>/dev/null || needed="$needed clang"
        command -v make     &>/dev/null || needed="$needed make"
        command -v cmake    &>/dev/null || needed="$needed cmake"
        command -v openssl  &>/dev/null || needed="$needed openssl"
        command -v autoconf &>/dev/null || needed="$needed autoconf"
        command -v automake &>/dev/null || needed="$needed automake"
        command -v libtool  &>/dev/null || needed="$needed libtool"
        command -v pip      &>/dev/null || command -v pip3 &>/dev/null || needed="$needed python-pip"
        if [[ -n "$needed" ]]; then
            log "Installing base deps via pkg:$needed"
            pkg install -y $needed 2>/dev/null || warn "Some pkg installs failed, continuing..."
        fi
    fi
}

# ── Ensure pip ─────────────────────────────────────────────────────────
ensure_pip() {
    if command -v pip3 &>/dev/null; then
        PIP="pip3"
    elif command -v pip &>/dev/null; then
        PIP="pip"
    else
        warn "pip not found, trying to install..."
        if command -v pkg &>/dev/null; then
            pkg install -y python-pip 2>/dev/null || true
        fi
        PIP="pip3"
        command -v pip3 &>/dev/null || PIP="pip"
    fi
    export PIP
    command -v "$PIP" &>/dev/null || { warn "Cannot get pip — Python tools will be skipped"; }
}

# ═══════════════════════════════════════════════════════════════════════════
# GITLEAKS
# ═══════════════════════════════════════════════════════════════════════════
install_gitleaks() {
    step "gitleaks — secret scanner"
    if command -v gitleaks &>/dev/null; then
        log "gitleaks already installed: $(gitleaks version 2>&1 | head -1)"
        GITLEAKS_BIN="gitleaks"
        export GITLEAKS_BIN
        return 0
    fi

    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Try pre-built binary (GitHub releases)
    local ver="8.18.4"
    local base="https://github.com/gitleaks/gitleaks/releases/download/v${ver}"
    case "$arch" in
        aarch64|arm64)   local bin_arch="arm64" ;;
        x86_64|amd64)    local bin_arch="x64" ;;
        armv7l)          local bin_arch="armv7" ;;
        *)               local bin_arch="" ;;
    esac

    if [[ -n "$bin_arch" ]]; then
        local url="${base}/gitleaks_${ver}_${os}_${bin_arch}.tar.gz"
        info "Downloading gitleaks $ver for $os/$bin_arch..."
        if curl -fsSL "$url" -o "$INSTALL_DIR/gitleaks.tar.gz" 2>/dev/null; then
            tar xzf "$INSTALL_DIR/gitleaks.tar.gz" -C "$BIN_DIR/" gitleaks 2>/dev/null && \
                chmod +x "$BIN_DIR/gitleaks" && \
                log "gitleaks binary installed to $BIN_DIR/gitleaks" && \
                GITLEAKS_BIN="$BIN_DIR/gitleaks" && \
                export GITLEAKS_BIN && \
                return 0
        fi
        warn "Pre-built download failed, trying go install..."
    fi

    # Fallback: go install
    if command -v go &>/dev/null; then
        info "Building gitleaks via go install..."
        if go install github.com/gitleaks/gitleaks/v8@latest 2>/dev/null; then
            GITLEAKS_BIN="$(go env GOPATH 2>/dev/null)/bin/gitleaks"
            [[ -x "$GITLEAKS_BIN" ]] && export GITLEAKS_BIN && log "gitleaks built: $GITLEAKS_BIN" && return 0
        fi
    fi

    warn "gitleaks install failed — will skip gitleaks scanning"
    GITLEAKS_BIN=""
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# WHISPERS
# ═══════════════════════════════════════════════════════════════════════════
install_whispers() {
    step "whispers — structured config scanner"
    ensure_pip
    if command -v whispers &>/dev/null; then
        log "whispers already installed: $(whispers --version 2>&1 | head -1)"
        WHISPERS_BIN="whispers"
        export WHISPERS_BIN
        return 0
    fi
    if [[ -n "${PIP:-}" ]]; then
        info "Installing whispers via $PIP..."
        if "$PIP" install whispers 2>&1 | tail -3; then
            WHISPERS_BIN="whispers"
            export WHISPERS_BIN
            log "whispers installed"
            return 0
        fi
    fi
    warn "whispers install failed — will skip"
    WHISPERS_BIN=""
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# BRAINFLAYER
# ═══════════════════════════════════════════════════════════════════════════
install_brainflayer() {
    step "brainflayer — brain wallet cracker"
    if command -v brainflayer &>/dev/null; then
        log "brainflayer already installed: $(brainflayer --help 2>&1 | head -1)"
        BRAINFLAYER_BIN="brainflayer"
        export BRAINFLAYER_BIN
        return 0
    fi

    local bf_dir="$INSTALL_DIR/brainflayer-build"
    local bf_bin="$bf_dir/brainflayer"

    # Check if we have compilation tools
    if ! command -v gcc &>/dev/null && ! command -v clang &>/dev/null; then
        warn "No C compiler (gcc/clang) — brainflayer requires compilation"
        BRAINFLAYER_BIN=""
        return 1
    fi

    info "Cloning and building brainflayer..."
    (
        mkdir -p "$bf_dir"
        cd "$bf_dir"

        # Clone dependencies
        [[ -d secp256k1 ]] || git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git 2>/dev/null
        [[ -d brainflayer ]] || git clone --depth 1 https://github.com/ryancdotorg/brainflayer.git 2>/dev/null

        # Build secp256k1
        if [[ -d secp256k1 ]] && [[ ! -f secp256k1/.libs/libsecp256k1.a ]]; then
            cd secp256k1
            ./autogen.sh 2>/dev/null || true
            ./configure --enable-module-recovery 2>/dev/null || true
            make -j$(nproc 2>/dev/null || echo 2) 2>/dev/null || true
            cd ..
        fi

        # Build brainflayer
        if [[ -d brainflayer ]]; then
            cd brainflayer
            if [[ -f ../secp256k1/.libs/libsecp256k1.a ]]; then
                make SECP256K1_INCLUDE=../secp256k1/include SECP256K1_LIB=../secp256k1/.libs/libsecp256k1.a 2>/dev/null || true
            else
                make 2>/dev/null || true
            fi
            if [[ -x brainflayer ]]; then
                cp brainflayer "$BIN_DIR/brainflayer" 2>/dev/null || true
                chmod +x "$BIN_DIR/brainflayer" 2>/dev/null || true
            fi
        fi
    ) 2>&1 | tail -5

    if [[ -x "$BIN_DIR/brainflayer" ]]; then
        BRAINFLAYER_BIN="$BIN_DIR/brainflayer"
        export BRAINFLAYER_BIN
        log "brainflayer built: $BRAINFLAYER_BIN"
        return 0
    fi

    warn "brainflayer build failed — will skip brain wallet cracking"
    BRAINFLAYER_BIN=""
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# LARGE BITCOIN COLLIDER
# ═══════════════════════════════════════════════════════════════════════════
install_collider() {
    step "Large Bitcoin Collider — weak key collision"
    if command -v LBC  &>/dev/null || command -v collider &>/dev/null; then
        log "Collider already available"
        COLLIDER_BIN="$(command -v LBC || command -v collider)"
        export COLLIDER_BIN
        return 0
    fi

    local col_dir="$INSTALL_DIR/collider-build"

    if ! command -v gcc &>/dev/null && ! command -v clang &>/dev/null; then
        warn "No C compiler — collider requires compilation"
        COLLIDER_BIN=""
        return 1
    fi

    info "Cloning Large Bitcoin Collider (CPU mode, best-effort)..."
    (
        mkdir -p "$col_dir"
        cd "$col_dir"
        [[ -d collider ]] || git clone --depth 1 https://github.com/JeanLucPons/LBC.git collider 2>/dev/null
        if [[ -d collider ]]; then
            cd collider
            # Try CPU-only build
            if [[ -f Makefile ]]; then
                make -j$(nproc 2>/dev/null || echo 2) 2>/dev/null || true
            elif [[ -f CMakeLists.txt ]]; then
                mkdir -p build && cd build
                cmake .. -DCMAKE_BUILD_TYPE=Release 2>/dev/null || true
                make -j$(nproc 2>/dev/null || echo 2) 2>/dev/null || true
                [[ -x LBC ]] && cp LBC "$BIN_DIR/collider"
            fi
            [[ -x LBC ]] && cp LBC "$BIN_DIR/collider" 2>/dev/null
            chmod +x "$BIN_DIR/collider" 2>/dev/null || true
        fi
    ) 2>&1 | tail -5

    if [[ -x "$BIN_DIR/collider" ]]; then
        COLLIDER_BIN="$BIN_DIR/collider"
        export COLLIDER_BIN
        log "Collider built: $COLLIDER_BIN"
        return 0
    fi

    warn "Collider build failed — will skip. Install manually for GPU-accelerated collision."
    COLLIDER_BIN=""
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# BITCRACK
# ═══════════════════════════════════════════════════════════════════════════
install_bitcrack() {
    step "BitCrack — GPU-accelerated private key brute-force"
    if command -v BitCrack &>/dev/null || command -v bitcrack &>/dev/null; then
        log "BitCrack already available"
        BITCRACK_BIN="$(command -v BitCrack || command -v bitcrack)"
        export BITCRACK_BIN
        return 0
    fi

    local bc_dir="$INSTALL_DIR/bitcrack-build"

    if ! command -v gcc &>/dev/null && ! command -v clang &>/dev/null; then
        warn "No C compiler — BitCrack requires compilation"
        BITCRACK_BIN=""
        return 1
    fi

    info "Cloning and building BitCrack (CPU-only fallback)..."
    (
        mkdir -p "$bc_dir"
        cd "$bc_dir"
        [[ -d BitCrack ]] || git clone --depth 1 https://github.com/brichard19/BitCrack.git 2>/dev/null
        if [[ -d BitCrack ]]; then
            cd BitCrack
            if [[ -f Makefile ]]; then
                make -j$(nproc 2>/dev/null || echo 2) 2>/dev/null || true
            elif [[ -f CMakeLists.txt ]]; then
                mkdir -p build && cd build
                cmake .. -DCMAKE_BUILD_TYPE=Release 2>/dev/null || true
                make -j$(nproc 2>/dev/null || echo 2) 2>/dev/null || true
            fi
            # Find the built binary
            local found_bin=$(find . -maxdepth 2 -type f -executable -name 'BitCrack' -o -name 'bitcrack' 2>/dev/null | head -1)
            if [[ -n "$found_bin" ]]; then
                cp "$found_bin" "$BIN_DIR/bitcrack" 2>/dev/null
                chmod +x "$BIN_DIR/bitcrack" 2>/dev/null || true
            fi
        fi
    ) 2>&1 | tail -5

    if [[ -x "$BIN_DIR/bitcrack" ]]; then
        BITCRACK_BIN="$BIN_DIR/bitcrack"
        export BITCRACK_BIN
        log "BitCrack built: $BITCRACK_BIN"
        return 0
    fi

    warn "BitCrack build failed — requires GPU (CUDA/OpenCL) for acceleration. Skipping."
    BITCRACK_BIN=""
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# MASTER INSTALLER
# ═══════════════════════════════════════════════════════════════════════════
install_all_tools() {
    echo -e "${BOLD}${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║   DASHGO TOOL INSTALLER                           ║"
    echo "║   gitleaks | whispers | brainflayer | collider |  ║"
    echo "║   bitcrack                                       ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    ensure_pkg_deps
    ensure_pip

    local total=5
    local ok=0

    install_gitleaks    && ((ok++)) || true
    install_whispers     && ((ok++)) || true
    install_brainflayer  && ((ok++)) || true
    install_collider     && ((ok++)) || true
    install_bitcrack     && ((ok++)) || true

    echo ""
    echo -e "${BOLD}═══ INSTALL SUMMARY ═══${RESET}"
    echo -e "  gitleaks:    ${GREEN}$([ -n "${GITLEAKS_BIN:-}" ] && echo "READY" || echo "SKIPPED")${RESET}"
    echo -e "  whispers:    ${GREEN}$([ -n "${WHISPERS_BIN:-}" ] && echo "READY" || echo "SKIPPED")${RESET}"
    echo -e "  brainflayer: ${GREEN}$([ -n "${BRAINFLAYER_BIN:-}" ] && echo "READY" || echo "SKIPPED")${RESET}"
    echo -e "  collider:    ${GREEN}$([ -n "${COLLIDER_BIN:-}" ] && echo "READY" || echo "SKIPPED")${RESET}"
    echo -e "  bitcrack:    ${GREEN}$([ -n "${BITCRACK_BIN:-}" ] && echo "READY" || echo "SKIPPED")${RESET}"
    echo -e "  ${BOLD}${ok}/${total} tools ready${RESET}"
    echo ""

    # Export paths for sourcing
    export INSTALL_DIR BIN_DIR
    export GITLEAKS_BIN="${GITLEAKS_BIN:-}"
    export WHISPERS_BIN="${WHISPERS_BIN:-}"
    export BRAINFLAYER_BIN="${BRAINFLAYER_BIN:-}"
    export COLLIDER_BIN="${COLLIDER_BIN:-}"
    export BITCRACK_BIN="${BITCRACK_BIN:-}"
    export DASHGO_TOOLS_READY=1
}

# Run if executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    install_all_tools
fi
