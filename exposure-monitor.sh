#!/usr/bin/env bash
#
# Scan for new hosts and check common exposures for fast findings
#

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Files
SUBS_FILE="subs.txt"
LIVE_FILE="live.txt"
FINDINGS_FILE="findings.txt"
NEW_SUBS_FILE="new_subs.txt"
NEW_LIVE_FILE="new_live.txt"
DOMAINS_FILE="domains.txt"
LOG_FILE="scanner.log"

# Config
NUCLEI_TEMPLATES="$HOME/Projects/nuclei-templates/http/exposures/"
NUCLEI_CONCURRENCY=30
NUCLEI_RATE_LIMIT=30
NUCLEI_BULK_SIZE=25
NOTIFY_ID="mars" # notify provider profile
HTTPX_THREADS=25
SLEEP="3600" # inter-cycle delay (s)

# Timestamped log for long unattended runs
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE" >&2; }

# Banner function
banner() {
    echo -e "${MAGENTA}"
    cat <<"EOF"
  ___  ___ __ _ _ _  _ _  ___ _ _
 (_-< / _/ _` | ' \| ' \/ -_) '_|
 /__/ \__\__,_|_||_|_||_\___|_|

  Exposure Monitor v1.0
      by olofmagn
EOF
    echo -e "${NC}"
}

# Check tools function
check_tools() {
    REQUIRED_TOOLS=("subfinder" "httpx" "nuclei" "notify" "anew")
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}Warning: $tool not found${NC}" >&2
            exit 1
        fi
    done
}

# Safe line count: 0 for missing/empty, never errors
count() { [ -f "$1" ] && wc -l <"$1" 2>/dev/null || echo 0; }

# Summary function
summary() {
    echo ""
    echo -e "${GREEN}===== MONITOR STOPPED =====${NC}"
    echo -e "Target set:  ${MAGENTA}${NOTIFY_ID}${NC}"
    echo -e "Subdomains:  ${MAGENTA}$(count "$SUBS_FILE")${NC}"
    echo -e "Live hosts:  ${MAGENTA}$(count "$LIVE_FILE")${NC}"
    echo -e "Findings:    ${MAGENTA}$(count "$FINDINGS_FILE")${NC}"
    echo -e "${GREEN}===========================${NC}"
}

# Scan cycle function
scan_cycle() {
    subfinder -dL "$DOMAINS_FILE" -all -silent | anew "$SUBS_FILE" >"$NEW_SUBS_FILE"
    if [ ! -s "$NEW_SUBS_FILE" ]; then
        log "no new subdomains this cycle"
        return 0
    fi
    log "new subdomains: $(count "$NEW_SUBS_FILE")"

    httpx -l "$NEW_SUBS_FILE" -t "$HTTPX_THREADS" -silent | anew "$LIVE_FILE" >"$NEW_LIVE_FILE"
    [ -s "$NEW_LIVE_FILE" ] || return 0
    log "new live hosts: $(count "$NEW_LIVE_FILE")"

    nuclei -l "$NEW_LIVE_FILE" \
        -t "$NUCLEI_TEMPLATES" \
        -c "$NUCLEI_CONCURRENCY" -rl "$NUCLEI_RATE_LIMIT" \
        -bulk-size "$NUCLEI_BULK_SIZE" \
        -exclude-tags headless,browser \
        -silent |
        anew "$FINDINGS_FILE" |
        notify -silent -id "$NOTIFY_ID"
}

# Run scan function
run_scan() {
    log "starting monitor target=$NOTIFY_ID interval=${SLEEP}s"
    while true; do
        scan_cycle
        sleep "$SLEEP"
    done
}

# Traps
trap 'log "shutting down"; summary; exit 0' INT TERM

check_tools
banner

# ===== Setup =====
[ -s "$DOMAINS_FILE" ] || {
    echo -e "${RED}ERROR: baseline missing/empty: $DOMAINS_FILE${NC}" >&2
    exit 1
}
[ -d "$NUCLEI_TEMPLATES" ] || {
    echo -e "${RED}ERROR: template dir not found: $NUCLEI_TEMPLATES${NC}" >&2
    exit 1
}

# ===== Scan =====
run_scan