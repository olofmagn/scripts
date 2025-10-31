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
│  ╔═╗╦═╗╔═╗╦ ╦╦╦  ╦╔═╗╔═╗╦╔╗╔╔╦╗╔═╗╦═╗       │
│  ╠═╣╠╦╝║  ╠═╣║╚╗╔╝║╣ ╠╣ ║║║║ ║║║╣ ╠╦╝       │
│  ╩ ╩╩╚═╚═╝╩ ╩╩ ╚╝ ╚═╝╚  ╩╝╚╝═╩╝╚═╝╩╚═       │
│                                             │
│        Archive Discovery Tool v1.0          │
│               by olofmagn                   │
│                                             │
└─────────────────────────────────────────────┘
EOF
	echo -e "${NC}"
}

# Check tools function
check_tools() {
	REQUIRED_TOOLS=("curl" "uro" "anew")
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
	echo -e "Target: ${MAGENTA}"$TARGET"${NC}"
	echo -e "Files fetched: ${MAGENTA}$(wc -l <"$WAYBACK_DATA" 2>/dev/null || echo 0)${NC}"
	echo -e "Patterns matched: ${MAGENTA}$(wc -l <"$WAYBACK_FINDINGS" 2>/dev/null || echo 0)${NC}"
	echo -e "Results: ${MAGENTA}"$SCAN_DIR"${NC}"
	echo -e "${GREEN}=========================${NC}"
}

TARGET="$1"

# Check if target provided
if [[ -z "$TARGET" ]] || [[ "$TARGET" == "-h" ]] || [[ "$TARGET" == "--help" ]]; then
	echo "Usage: $0 <domain>"
	exit 0
fi

check_tools

banner

# ===== Setup =====

WAYBACK_DATA="wayback_data.txt"
WAYBACK_FINDINGS="wayback_findings.txt"

# Create scan directory
SCAN_DIR="scan_${TARGET}_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$SCAN_DIR"
cd "$SCAN_DIR" || exit 1

echo -e "${YELLOW}Enumerating data from the webarchive${NC}"

curl -s -L \
	-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
	-H "Accept: text/plain" \
	--connect-timeout 10 \
	--max-time 30 \
	--retry 3 \
	--retry-delay 10 \
	--retry-max-time 60 \
	--retry-all-errors \
	"https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey" \
	-o "$WAYBACK_DATA"

echo -e "${GREEN}Webarchive data fetch completed${NC}"

echo -e "${YELLOW}Analysing data from the webarchive${NC}"
cat "$WAYBACK_DATA" | uro | grep -Ei "\.(env|config|cfg|conf|cnf|properties|toml|yml|yaml|ini|ovpn|git|svn|key|pem|pub|asc|crt|p12|pfx|ppk|keystore|jks|secret|aws|s3cfg|sql|db|sqlite|sqlite3|mdb|accdb|dump|backup|bak|old|log|cache|json|xml|csv|txt|md|xls|xlsx|doc|docx|pdf|pptx|zip|tar|gz|tgz|bz2|xz|7z|rar|war|jar|apk|deb|rpm|iso|img|dmg|msi|bin|exe|dll|bat|sh|tmp|DS_Store)$" > "$WAYBACK_FINDINGS"
echo -e "${GREEN}Webarchive data enumeration completed${NC}"

# Run summary
summary
