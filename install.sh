#!/usr/bin/env bash
# install.sh — One-command deployment for the DNS Orchestrator Bot + EchoCatcher
#
# Installs and configures:
#   • Go (latest stable, if not present)
#   • orchestrator-bot  →  /usr/local/bin/orchestrator-bot
#   • echocatcher       →  /usr/local/bin/echocatcher
#   • systemd service   →  orchestrator-bot.service (enabled + started)
#   • sudoers rule      →  /etc/sudoers.d/orchestrator-bot
#   • config.yaml       →  /opt/dns-orchestrator/config.yaml
#
# Usage:
#   # From the project root:
#   sudo bash install.sh
#
#   # Or as a one-liner:
#   bash <(curl -sSL https://raw.githubusercontent.com/alisouran/EchoFlare/master/install.sh)
#
# Requirements: Ubuntu 20.04+ / Debian 11+ with apt, curl, and internet access.

set -euo pipefail
IFS=$'\n\t'

# ─────────────────────────────────────────────────────────────────────────────
# Constants — edit REPO_URL before publishing
# ─────────────────────────────────────────────────────────────────────────────
readonly INSTALL_DIR="/opt/dns-orchestrator"
readonly CONFIG_FILE="${INSTALL_DIR}/config.yaml"
readonly LOG_DIR="/var/log/echocatcher"
readonly BOT_BIN="/usr/local/bin/orchestrator-bot"
readonly CATCHER_BIN="/usr/local/bin/echocatcher"
readonly SERVICE_NAME="orchestrator-bot"
readonly SUDOERS_FILE="/etc/sudoers.d/orchestrator-bot"
readonly GO_MIN_VERSION="1.22"
readonly REPO_URL="https://github.com/alisouran/EchoFlare.git"

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour codes
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'   # No Colour (reset)

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}  ℹ  $*${NC}"; }
success() { echo -e "${GREEN}  ✅ $*${NC}"; }
warn()    { echo -e "${YELLOW}  ⚠️  $*${NC}"; }
error()   { echo -e "${RED}  ❌ $*${NC}" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
            echo -e "${BOLD}${CYAN}  ▶  $*${NC}"; \
            echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
prompt()  { echo -en "${CYAN}  ➜  $*${NC}"; }   # no trailing newline — for read -r

# ─────────────────────────────────────────────────────────────────────────────
# Semver comparison: version_ge A B  →  true if A >= B
# Uses sort -V (GNU coreutils) which is available on all Ubuntu/Debian.
# ─────────────────────────────────────────────────────────────────────────────
version_ge() {
    [[ "$(printf '%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# Validated prompt helper — keeps asking until the user provides a non-empty value.
# Usage: read_required VARNAME "Prompt text"
# ─────────────────────────────────────────────────────────────────────────────
read_required() {
    local varname="$1"
    local prompt_text="$2"
    local value=""
    while [[ -z "$value" ]]; do
        prompt "${prompt_text}: "
        read -r value
        if [[ -z "$value" ]]; then
            warn "This field is required."
        fi
    done
    # Assign into the named variable in the caller's scope.
    printf -v "$varname" '%s' "$value"
}

# ─────────────────────────────────────────────────────────────────────────────
# 0. Print banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║   🌐  DNS Orchestrator Bot — Installer           ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. Root check
# ─────────────────────────────────────────────────────────────────────────────
[[ "${EUID}" -eq 0 ]] || error "This script must be run as root.  Try: sudo bash install.sh"
success "Running as root."

# ─────────────────────────────────────────────────────────────────────────────
# 2. System dependencies
# ─────────────────────────────────────────────────────────────────────────────
step "Installing system dependencies"

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    sudo \
    2>/dev/null

success "System packages ready."

# ─────────────────────────────────────────────────────────────────────────────
# 3. Go installation
# ─────────────────────────────────────────────────────────────────────────────
step "Checking Go installation"

NEED_GO=true
if command -v go &>/dev/null; then
    current_go=$(go version | awk '{print $3}' | tr -d 'go')
    if version_ge "${current_go}" "${GO_MIN_VERSION}"; then
        success "Go ${current_go} is already installed — skipping download."
        NEED_GO=false
    else
        warn "Go ${current_go} is below the minimum ${GO_MIN_VERSION} — will upgrade."
    fi
fi

if [[ "${NEED_GO}" == "true" ]]; then
    info "Fetching latest stable Go version..."
    GO_VER=$(curl -fsSL "https://go.dev/VERSION?m=text" | head -1)
    GO_URL="https://dl.google.com/go/${GO_VER}.linux-amd64.tar.gz"

    info "Downloading ${GO_VER} from dl.google.com ..."
    curl -fsSL --progress-bar "${GO_URL}" -o /tmp/go.tar.gz

    info "Installing ${GO_VER} to /usr/local/go ..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz

    # System-wide PATH profile (survives reboots and new shells).
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
    chmod 644 /etc/profile.d/golang.sh

    # Export for the current session so subsequent go commands work.
    export PATH=$PATH:/usr/local/go/bin

    success "$(go version) installed."
fi

# Verify go is runnable regardless of the path above.
command -v go &>/dev/null || error "Go binary not found in PATH even after install.  Check /usr/local/go/bin."

# ─────────────────────────────────────────────────────────────────────────────
# 4. Source resolution
#    Prefer the current directory if it contains the expected go.mod.
#    Otherwise clone from REPO_URL.
# ─────────────────────────────────────────────────────────────────────────────
step "Locating source code"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SRC_DIR="/opt/dns-orchestrator/src"
if [[ -d "${SRC_DIR}/.git" ]]; then
    info "Repository already cloned — fetching latest from origin..."
    # Use fetch + reset --hard so local divergence (e.g. a failed previous
    # update that left uncommitted changes) never blocks the update.
    git -C "${SRC_DIR}" fetch origin
    git -C "${SRC_DIR}" reset --hard origin/master
else
    info "Cloning repository to ${SRC_DIR}..."
    mkdir -p "${SRC_DIR}"
    git clone https://github.com/alisouran/EchoFlare.git "${SRC_DIR}"
fi
success "Source at: ${SRC_DIR}"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Configuration — detect update vs fresh install
# ─────────────────────────────────────────────────────────────────────────────
step "Configuration"

IS_UPDATE=false
CONFIG_BACKUP="/tmp/dns-orchestrator-config.bak"

if [[ -f "${CONFIG_FILE}" ]]; then
    IS_UPDATE=true
    info "Existing installation detected — keeping config unchanged, skipping prompts."

    # Back up the config first (disaster recovery).
    cp "${CONFIG_FILE}" "${CONFIG_BACKUP}"
    success "Config backed up to ${CONFIG_BACKUP}"

    # Extract the real values from the existing YAML so service files are
    # regenerated with the correct domain, not a placeholder.
    # Each grep uses "|| true" so a no-match never triggers set -e.
    BOT_TOKEN=$(grep -m1 'token:' "${CONFIG_FILE}" | sed 's/.*token:[[:space:]]*"\(.*\)".*/\1/' || true)
    ADMIN_ID=$(grep -m1 'owner_id:' "${CONFIG_FILE}" | awk '{print $2}' || true)
    # Domain lives under the scanner: section — match only indented domain: lines.
    SCAN_DOMAIN=$(grep -A10 '^scanner:' "${CONFIG_FILE}" | grep -m1 '^\ *domain:' | sed 's/.*domain:[[:space:]]*"\(.*\)".*/\1/' | tr -d '"' || true)

    # Validate — fall back to safe placeholder if extraction failed, but warn loudly.
    [[ -n "${BOT_TOKEN}" ]]   || { warn "Could not extract token from config — using placeholder.";   BOT_TOKEN="REPLACE_WITH_YOUR_BOT_TOKEN"; }
    [[ -n "${ADMIN_ID}" ]]    || { warn "Could not extract owner_id from config — using 0.";          ADMIN_ID="0"; }
    [[ -n "${SCAN_DOMAIN}" ]] || { warn "Could not extract scanner.domain from config — using placeholder."; SCAN_DOMAIN="scan.yourdomain.com"; }

    success "Extracted config: domain=${SCAN_DOMAIN}, admin_id=${ADMIN_ID}"
    success "Updating EchoFlare — existing config untouched."

elif [[ ! -t 0 ]]; then
    warn "Non-interactive shell detected (curl-pipe mode)."
    warn "A placeholder config will be written to ${CONFIG_FILE}."
    warn "Edit it and run: systemctl restart ${SERVICE_NAME}"
    BOT_TOKEN="REPLACE_WITH_YOUR_BOT_TOKEN"
    ADMIN_ID="0"
    SCAN_DOMAIN="scan.yourdomain.com"

else
    echo ""
    echo -e "  ${BOLD}You will need:${NC}"
    echo -e "  ${CYAN}•${NC} A Telegram Bot Token  — message ${CYAN}@BotFather${NC} → /newbot"
    echo -e "  ${CYAN}•${NC} Your Telegram User ID — message ${CYAN}@userinfobot${NC}"
    echo -e "  ${CYAN}•${NC} The scan subdomain    — e.g. ${CYAN}scan.yourdomain.com${NC}"
    echo ""

    read_required BOT_TOKEN   "Telegram Bot Token"
    read_required ADMIN_ID    "Telegram Admin User ID (numbers only)"
    read_required SCAN_DOMAIN "Scan domain (e.g. scan.yourdomain.com)"

    # Validate admin ID is a plain integer.
    [[ "${ADMIN_ID}" =~ ^[0-9]+$ ]] \
        || error "Admin ID must be a numeric Telegram user ID (no letters or symbols)."

    echo ""
    success "Configuration collected."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. Write config.yaml  (skipped on updates — backup is restored at step 10)
#    The bot's loadConfig() reads YAML — NOT a .env file.
# ─────────────────────────────────────────────────────────────────────────────
step "Writing config.yaml"

mkdir -p "${INSTALL_DIR}"
mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

if [[ "${IS_UPDATE}" == "true" ]]; then
    info "Update mode — skipping config write.  Backup saved to ${CONFIG_BACKUP} for manual recovery."
else
    # Write the YAML config.  Use single-quoted heredoc delimiter (<<'EOF') so that
    # the shell does NOT expand $BOT_TOKEN etc. inside the heredoc — those are
    # already expanded via the variables above and substituted correctly.
    cat > "${CONFIG_FILE}" <<EOF
# ============================================================
# DNS Orchestrator Bot — Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Edit and restart the service to apply changes:
#   systemctl restart ${SERVICE_NAME}
# ============================================================

telegram:
  token: "${BOT_TOKEN}"
  owner_id: ${ADMIN_ID}
  # Path to the user registry. Every user who messages the bot is stored here
  # so the admin can reach them all via /broadcast.
  users_file: "${INSTALL_DIR}/users.json"

services:
  vpn: "masterdnsvpn.service"
  scanner: "echocatcher.service"

scanner:
  # The authoritative zone EchoCatcher listens on.
  domain: "${SCAN_DOMAIN}"
  # EchoCatcher writes its results here; this file is sent to you after /scan.
  log_file: "${LOG_DIR}/working_dns.json"

health:
  ping_target: "8.8.8.8"
  interval: "5m"
  loss_threshold: 60
EOF

    # Restrict permissions — the token is a secret.
    chmod 600 "${CONFIG_FILE}"
    success "Config written to ${CONFIG_FILE} (mode 600)."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. Build binaries
# ─────────────────────────────────────────────────────────────────────────────
step "Building binaries"

cd "${SRC_DIR}"

info "Running go mod tidy..."
go mod tidy

info "Compiling orchestrator-bot..."
VERSION="rev-$(git rev-parse --short HEAD)"
BUILD_TIME="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
go build -trimpath -ldflags="-s -w -X 'main.AppVersion=${VERSION}' -X 'main.BuildTime=${BUILD_TIME}'" -o "${BOT_BIN}" ./bot/

info "Compiling echocatcher..."
go build -trimpath -ldflags="-s -w" -o "${CATCHER_BIN}" ./echocatcher/

chmod 755 "${BOT_BIN}" "${CATCHER_BIN}"

success "Binaries installed:"
success "  ${BOT_BIN}  ($(du -sh "${BOT_BIN}" | cut -f1))"
success "  ${CATCHER_BIN}  ($(du -sh "${CATCHER_BIN}" | cut -f1))"

# ─────────────────────────────────────────────────────────────────────────────
# 8. Create systemd service for the orchestrator bot
# ─────────────────────────────────────────────────────────────────────────────
step "Creating systemd services"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Server Orchestrator Telegram Bot
Documentation=${REPO_URL}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

# Bot runs as root so it can use systemctl directly.
# The sudoers rule below is defence-in-depth for future non-root deployments.
ExecStart=${BOT_BIN}

# Point the bot at its config file.
Environment=CONFIG=${CONFIG_FILE}

# Always restart on crash.
Restart=always
RestartSec=5s

# Write all output to the systemd journal (journalctl -u ${SERVICE_NAME} -f).
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Raise the open-file limit for high-concurrency DNS workloads.
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

success "Service file written to /etc/systemd/system/${SERVICE_NAME}.service"

# Create echocatcher.service — registered but NOT enabled.
# The bot starts/stops it on demand via systemctl; it must never auto-start on boot.
cat > "/etc/systemd/system/echocatcher.service" <<EOF
[Unit]
Description=EchoCatcher DNS Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CATCHER_BIN} -domain ${SCAN_DOMAIN} -log ${LOG_DIR}/working_dns.json -bind 0.0.0.0:53
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=echocatcher
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

success "echocatcher.service written (registered but NOT enabled — bot controls lifecycle via systemctl start/stop)."

# ─────────────────────────────────────────────────────────────────────────────
# 9. Sudoers — passwordless systemctl for the required services
#    Uses /etc/sudoers.d/ (drop-in directory, avoids touching /etc/sudoers).
# ─────────────────────────────────────────────────────────────────────────────
step "Configuring passwordless sudo for systemctl"

cat > "${SUDOERS_FILE}" <<'EOF'
# Generated by install.sh
# Allows the orchestrator-bot (running as root) to control the competing
# port-53 services without a password prompt.
# To edit: visudo -f /etc/sudoers.d/orchestrator-bot

# EchoCatcher (DNS scanner — started/stopped during /scan)
root ALL=(ALL) NOPASSWD: /bin/systemctl start echocatcher.service
root ALL=(ALL) NOPASSWD: /bin/systemctl stop echocatcher.service

# MasterDnsVPN (stopped before scan, restarted after)
root ALL=(ALL) NOPASSWD: /bin/systemctl start masterdnsvpn.service
root ALL=(ALL) NOPASSWD: /bin/systemctl stop masterdnsvpn.service
root ALL=(ALL) NOPASSWD: /bin/systemctl restart masterdnsvpn.service

# journalctl — used by /get_logs command
root ALL=(ALL) NOPASSWD: /usr/bin/journalctl
EOF

# sudo will reject sudoers files that are group/world writable.
chmod 440 "${SUDOERS_FILE}"

# Validate syntax — exits non-zero (and set -e aborts the script) if malformed.
visudo -c -f "${SUDOERS_FILE}" \
    || error "sudoers validation failed.  Check ${SUDOERS_FILE} manually."

success "Sudoers rule installed at ${SUDOERS_FILE} (validated OK)."

# ─────────────────────────────────────────────────────────────────────────────
# 10. Enable and start the orchestrator bot
# ─────────────────────────────────────────────────────────────────────────────
step "Starting ${SERVICE_NAME}"

systemctl daemon-reload

if [[ "${IS_UPDATE}" == "true" ]]; then
    # The config was never touched during an update (step 6 was skipped entirely),
    # so there is nothing to restore — the live file is already correct.
    # We keep the backup at ${CONFIG_BACKUP} for manual disaster recovery only.
    success "Config unchanged (update path skipped all writes)."
    systemctl restart "${SERVICE_NAME}"
else
    systemctl enable --now "${SERVICE_NAME}"
fi

# Give the process a moment to settle before checking.
sleep 2

if systemctl is-active --quiet "${SERVICE_NAME}"; then
    success "${SERVICE_NAME} is running."
else
    warn "${SERVICE_NAME} did not start cleanly."
    warn "Check the logs with:  journalctl -u ${SERVICE_NAME} -n 30 --no-pager"
    # Do not abort — the user can investigate and start manually.
fi

# ─────────────────────────────────────────────────────────────────────────────
# 11. Final success banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║   🚀  Installation Complete!                     ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Service status:${NC}"
echo -e "    systemctl status ${SERVICE_NAME}"
echo ""
echo -e "  ${BOLD}Live logs:${NC}"
echo -e "    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo -e "  ${BOLD}Config file:${NC}   ${CYAN}${CONFIG_FILE}${NC}"
echo -e "  ${BOLD}Bot binary:${NC}    ${CYAN}${BOT_BIN}${NC}"
echo -e "  ${BOLD}Catcher:${NC}       ${CYAN}${CATCHER_BIN}${NC}"
echo -e "  ${BOLD}Scan logs:${NC}     ${CYAN}${LOG_DIR}/${NC}"
echo ""

if [[ "${IS_UPDATE}" == "true" ]]; then
    echo -e "  ${GREEN}♻️  Update complete! Bot restarted with your existing config. ✈️${NC}"
elif [[ "${BOT_TOKEN}" == "REPLACE_WITH_YOUR_BOT_TOKEN" ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠️  Non-interactive install detected.${NC}"
    echo -e "  ${YELLOW}Edit the config and restart the service:${NC}"
    echo -e "    ${CYAN}nano ${CONFIG_FILE}${NC}"
    echo -e "    ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
    echo ""
else
    echo -e "  ${GREEN}Send ${BOLD}/help${NC}${GREEN} to your bot on Telegram to get started. ✈️${NC}"
fi
echo ""
