#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Banner function
banner() {
	echo -e "${MAGENTA}"
	cat <<"EOF"
┌─────────────────────────────────────────────┐
│                                             │
│        ╦╔═╗  ╔═╗╦╔╗╔╔╦╗╔═╗╦═╗               │
│        ║╚═╗  ╠╣ ║║║║ ║║║╣ ╠╦╝               │
│       ╚╝╚═╝  ╚  ╩╝╚╝═╩╝╚═╝╩╚═               │
│                                             │
│        JavaScript File Discovery v1.0       │
│                by olofmagn                  │
│                                             │
└─────────────────────────────────────────────┘
EOF
	echo -e "${NC}"
}

# Check tools function
check_tools() {
	REQUIRED_TOOLS=("urlfinder" "gau" "hakrawler" "katana" "httpx" "jsleak" "anew" "curl")
	for tool in "${REQUIRED_TOOLS[@]}"; do
		if ! command -v "$tool" &>/dev/null; then
			echo -e "${RED}Warning: $tool not found${NC}"
			exit 1
		fi
	done
}

# Summary function
summary() {
	echo ""
	echo -e "${GREEN}===== SCAN COMPLETE =====${NC}"
	echo -e "Target: ${CLEAN_TARGET}${NC}"
	echo -e "Total JS Files Found: ${MAGENTA}$(wc -l <"$OUTPUT_JS" 2>/dev/null || echo 0)${NC}"
	echo -e "Exposed Strings: ${MAGENTA}$(wc -l <"$EXPOSED_STRINGS" 2>/dev/null || echo 0)${NC}"
	echo -e "JSLeak Findings: ${MAGENTA}$(wc -l <"$JSLEAK_FINDINGS" 2>/dev/null || echo 0)${NC}"
	echo -e "Results Directory: ${MAGENTA}"$SCAN_DIR"${NC}"
	echo -e "${GREEN}=========================${NC}"
}

# Cleanup function
cleanup() {
	rm -f tmpfile_*.txt 2>/dev/null
}

trap cleanup EXIT

TARGET="$1"

# Help utility
if [[ -z "$TARGET" ]] || [[ "$TARGET" == "-h" ]] || [[ "$TARGET" == "--help" ]]; then
	echo "Usage: $0 <domain>"
	exit 0
fi

# Normalize URL
if [[ ! "$TARGET" =~ ^https?:// ]]; then
	TARGET="https://$TARGET"
fi

check_tools

banner

# ===== Setup =====

# Create scan directory
CLEAN_TARGET=$(echo "$TARGET" | sed 's|https\?://||')
SCAN_DIR="scan_${CLEAN_TARGET}_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$SCAN_DIR"
cd "$SCAN_DIR" || exit 1

OUTPUT_JS="alljs.txt"
EXPOSED_STRINGS="exposed_strings.txt"
JSLEAK_FINDINGS="jsleak_data.txt"

# ===== Scanning =====

# Urlfinder
(
	echo -e "${YELLOW}Enumerating javascript files using urlfinder${NC}"
	urlfinder -d "$TARGET" 2>/dev/null | grep -E "\.js$" >tmpfile_urlfinder.txt
	echo -e "${GREEN}urlfinder completed${NC}"
) &
# Gau
(
	echo -e "${YELLOW}Enumerating javascript files using gau${NC}"
	echo "$TARGET" | gau 2>/dev/null | grep -E "\.js$" >tmpfile_gau.txt
	echo -e "${GREEN}gau completed${NC}"
) &
# Hakrawler
(
	echo -e "${YELLOW}Enumerating javascript files using hakrawler${NC}"
	echo "$TARGET" | hakrawler -subs 2>/dev/null | grep -E "\.js$" >tmpfile_hakrawler.txt
	echo -e "${GREEN}hakrawler completed${NC}"
) &
# Katana
(
	echo -e "${YELLOW}Enumerating javascript files using katana${NC}"
	echo "$TARGET" | katana -d 3 -jc 2>/dev/null | grep -E "\.js$" >tmpfile_katana.txt
	echo -e "${GREEN}katana completed${NC}"
) &

# Wait for all background processes to finish
wait

# Merge all results
if ls tmpfile_*.txt >/dev/null 2>&1; then
	cat tmpfile_*.txt 2>/dev/null | anew "$OUTPUT_JS"
else
	echo -e "${YELLOW}Warning: No JS files found by any scanner.${NC}"
	touch "$OUTPUT_JS"
	summary
	exit 0
fi

# Check for common exposed strings
echo -e "${YELLOW}Check for common exposed strings${NC}"
cat "$OUTPUT_JS" | httpx -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -I -iE "(password|secret|credentials|private_key|ssh\.key|api_key|apikey|access\.key|access key|consumer_key|client\.secret|token|refresh_token|access_token|session|jwt|authorization|bearer|oauth|firebase|aws|azure|gcp|stripe|slack|github|sendgrid|twilio|paypal|discord|mongodb|postgres|mysql|redis|database|\.env|\.git)" | anew "$EXPOSED_STRINGS"
echo -e "${GREEN}Check completed${NC}"

# Check for links and vulnerable patterns using jsleak
echo -e "${YELLOW}Analyse using jsleak${NC}"
cat "$OUTPUT_JS" | jsleak -s -l -k | anew "$JSLEAK_FINDINGS"
echo -e "${GREEN}Analyse completed${NC}"

# Run summary
summary
