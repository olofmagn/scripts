#!/usr/bin/env bash
#
# Scan archived PDF documents for information disclosure vulnerabilities
#

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Files
LOG_FILE="pdfscan.log"
TMP_PDF="/tmp/p.pdf"

# Config
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MAX_TIME="90"   # curl per-request timeout
RETRIES="2"     # curl retry attempts
RETRY_DELAY="3" # curl retry backoff
THROTTLE="1"    # inter-request delay

# Pattern (adjust as necessary)
PATTERN='NOT\s+FOR\s+(PUBLIC\s+RELEASE|DISTRIBUTION)|INTERNAL\s+USE\s+ONLY|\bCONFIDENTIAL\b|\bPROPRIETARY\b'

# Timestamped log for long unattended runs
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG_FILE" >&2; }

# Banner function
banner() {
    echo -e "${MAGENTA}"
    cat <<"EOF"
           _  __                  
  _ __  __| |/ _|___ __ __ _ _ _  
 | '_ \/ _` |  _(_-</ _/ _` | ' \ 
 | .__/\__,_|_| /__/\__\__,_|_||_|
 |_|  

  Archived PDF Marking Scanner v1.0
            by olofmagn
EOF
    echo -e "${NC}"
}

# Check tools function
check_tools() {
    REQUIRED_TOOLS=("pdftotext" "curl" "grep")
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}Warning: $tool not found${NC}" >&2
            exit 1
        fi
    done
}

# Safe line count function
count() { [ -f "$1" ] && wc -l <"$1" 2>/dev/null || echo 0; }

# Summary function
summary() {
    echo ""
    echo -e "${GREEN}===== SCAN COMPLETE =====${NC}"
    echo -e "Target:      ${MAGENTA}${DOMAIN}${NC}"
    echo -e "Candidates:  ${MAGENTA}$(count "$URL_FILE")${NC}"
    echo -e "Hits:        ${MAGENTA}$(count "$HITS_FILE")${NC}"
    echo -e "Findings:    ${MAGENTA}${FINDINGS_FILE}${NC}"
    echo -e "${GREEN}=========================${NC}"
}

# Cleanup function
cleanup() { rm -f "$TMP_PDF" 2>/dev/null; }

# Fetch candidates function
fetch_candidates() {
    log "querying CDX for $DOMAIN"
    curl -sG "https://web.archive.org/cdx/search/cdx" \
        --data-urlencode "url=$DOMAIN" \
        --data-urlencode "matchType=domain" \
        --data-urlencode "collapse=urlkey" \
        --data-urlencode "output=text" \
        --data-urlencode "fl=timestamp,original" \
        --data-urlencode "filter=mimetype:application/pdf" \
        >"$URL_FILE"
    log "candidates written: $(wc -l <"$URL_FILE") -> $URL_FILE"
}

# Fetch pdf function
fetch_pdf() {
    local arch="$1"
    : >"$TMP_PDF"
    curl -sL --max-time "$MAX_TIME" --retry "$RETRIES" --retry-delay "$RETRY_DELAY" \
        -A "$UA" -o "$TMP_PDF" "$arch"
    [ "$(head -c4 "$TMP_PDF")" = "%PDF" ]
}

# Scan pdf function
scan_pdf() {
    pdftotext -layout "$TMP_PDF" - 2>/dev/null | grep -Eioa "$PATTERN" | sort -u | paste -sd', ' -
}

# Record hit function
record_hit() {
    local arch="$1" url="$2" result="$3"
    {
        echo "URL: $arch"
        echo "Live: $url"
        echo "Match: $result"
        echo "---"
    } >>"$FINDINGS_FILE"
    echo "$url" >>"$HITS_FILE"
}

# Scan one function
scan_one() {
    local pos="$1" ts="$2" url="$3"
    local arch="https://web.archive.org/web/${ts}id_/${url}"
    log "$pos fetch $url"
    if ! fetch_pdf "$arch"; then
        log "    [-] not a pdf, skip"
        return 0
    fi
    local result
    result="$(scan_pdf)"
    if [ -z "$result" ]; then
        log "    [ ] no markings"
        return 0
    fi
    log "    [+] HIT: $result"
    record_hit "$arch" "$url" "$result"
}

# Run scan function
run_scan() {
    local total n=0 ts url
    total=$(wc -l <"$URL_FILE")
    log "starting scan candidates=$total file=$URL_FILE"
    while read -r ts url; do
        [ -n "$url" ] || continue
        n=$((n + 1))
        scan_one "($n/$total)" "$ts" "$url"
        sleep "$THROTTLE"
    done <"$URL_FILE"
    log "scan complete — see $FINDINGS_FILE / $HITS_FILE"
}

# Traps
trap cleanup EXIT
trap 'log "shutting down"; exit 0' INT TERM

TARGET="${1:-}"

# Help utility
if [[ -z "$TARGET" ]] || [[ "$TARGET" == "-h" ]] || [[ "$TARGET" == "--help" ]]; then
    echo "Usage: $0 <domain>    e.g. $0 target.com"
    exit 0
fi

# Strip scheme and any path
DOMAIN=$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*$##')

check_tools
banner

# ===== Setup =====
URL_FILE="out_${DOMAIN}.txt"
FINDINGS_FILE="findings_${DOMAIN}.txt"
HITS_FILE="urls_${DOMAIN}.txt"

# ===== Scan =====
[ -s "$URL_FILE" ] || fetch_candidates
[ -s "$URL_FILE" ] || {
    echo -e "${RED}ERROR: no candidates for $DOMAIN (CDX returned nothing)${NC}" >&2
    exit 1
}

run_scan
summary
