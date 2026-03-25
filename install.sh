#!/usr/bin/env bash
#
# SnareClaw — Universal Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/0xDefence/snareclaw-py/main/install.sh | bash
#
# Or:
#   wget -qO- https://raw.githubusercontent.com/0xDefence/snareclaw-py/main/install.sh | bash
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

PACKAGE="snareclaw"

print_banner() {
    echo ""
    echo -e "${RED}${BOLD}               █▀     ▀█${RESET}"
    echo -e "${RED}${BOLD}              ▐██ ▄█▄ ██▌${RESET}"
    echo -e "${RED}${BOLD}               ▀█ ● ● █▀${RESET}"
    echo -e "${RED}${BOLD}                ▀█████▀${RESET}"
    echo -e "${RED}${BOLD}                ▐█ █ █▌${RESET}"
    echo -e "${RED}${BOLD}                 ▀   ▀${RESET}"
    echo ""
    echo -e "${RED}${BOLD}  █▀▀ █▄ █ █▀█ █▀▄ █▀▀ █▀▀ █   █▀█ █   █${RESET}"
    echo -e "${RED}${BOLD}  ▀▀█ █ ▀█ █▀█ ██▀ █▀  █   █   █▀█ █ █ █${RESET}"
    echo -e "${RED}${BOLD}  ▀▀▀ ▀  ▀ ▀ ▀ ▀ ▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ ▀▀${RESET}"
    echo ""
    echo -e "  ${DIM}Ambient supply chain security monitor${RESET}"
    echo ""
}

info()  { echo -e "  ${DIM}$1${RESET}"; }
ok()    { echo -e "  ${GREEN}${BOLD}*${RESET} $1"; }
fail()  { echo -e "  ${RED}${BOLD}!${RESET} $1"; }

command_exists() { command -v "$1" &>/dev/null; }

print_banner

# ─── Detect best install method ──────────────────────────────────────

INSTALLED=false

# Method 1: Homebrew (macOS)
if command_exists brew && [[ "$OSTYPE" == "darwin"* ]]; then
    info "Detected Homebrew on macOS"
    info "Installing via: brew install snareclaw"
    echo ""
    if brew tap 0xDefence/tap 2>/dev/null && brew install snareclaw 2>/dev/null; then
        INSTALLED=true
    else
        info "Brew install failed, trying pip..."
    fi
fi

# Method 2: pipx (isolated, recommended)
if ! $INSTALLED && command_exists pipx; then
    info "Installing via pipx (isolated environment)..."
    echo ""
    if pipx install "$PACKAGE"; then
        INSTALLED=true
    fi
fi

# Method 3: pip with --user
if ! $INSTALLED; then
    PIP=""
    if command_exists pip3; then
        PIP="pip3"
    elif command_exists pip; then
        PIP="pip"
    fi

    if [[ -n "$PIP" ]]; then
        # Check Python version
        PY_VERSION=$($PIP --version 2>/dev/null | grep -oP 'python \K[0-9]+\.[0-9]+' || echo "0.0")
        PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

        if [[ "$PY_MAJOR" -ge 3 ]] && [[ "$PY_MINOR" -ge 10 ]]; then
            info "Installing via $PIP..."
            echo ""
            if $PIP install --user "$PACKAGE"; then
                INSTALLED=true
            fi
        else
            fail "Python 3.10+ required (found $PY_VERSION)"
        fi
    fi
fi

# Method 4: From source
if ! $INSTALLED; then
    if command_exists git && command_exists python3; then
        info "Installing from source..."
        echo ""
        TMPDIR=$(mktemp -d)
        git clone --depth 1 https://github.com/0xDefence/snareclaw-py.git "$TMPDIR/snareclaw-py"
        cd "$TMPDIR/snareclaw-py"
        python3 -m pip install --user .
        rm -rf "$TMPDIR"
        INSTALLED=true
    fi
fi

echo ""

if $INSTALLED; then
    ok "SnareClaw installed successfully!"
    echo ""
    info "Get started:"
    echo ""
    echo -e "  ${BOLD}snare${RESET}              Launch interactive mode"
    echo -e "  ${BOLD}snare status${RESET}       Check environment health"
    echo -e "  ${BOLD}snare scan .${RESET}       Scan current project"
    echo -e "  ${BOLD}snare watch${RESET}        Start real-time monitoring"
    echo ""
else
    fail "Installation failed."
    echo ""
    info "Please install manually:"
    echo ""
    echo "  pip install snareclaw"
    echo ""
    info "Requires Python 3.10+"
    echo ""
    exit 1
fi
