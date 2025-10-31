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
│     ╔═╗╦ ╦╔╗ ╔═╗╦╔╗╔╔╦╗╔═╗╦═╗               │
│     ╚═╗║ ║╠╩╗╠╣ ║║║║ ║║║╣ ╠╦╝               │
│     ╚═╝╚═╝╚═╝╚  ╩╝╚╝═╩╝╚═╝╩╚═               │
│                                             │
│        Subdomain Discovery Tool v1.0        │
│                by olofmagn                  │
│                                             │
└─────────────────────────────────────────────┘
EOF
	echo -e "${NC}"
}

# Check_tools function
check_tools() {
	REQUIRED_TOOLS=("amass" "github-subdomains" "shodan" "assetfinder" "subfinder" "curl" "jq" "httpx" "anew")
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
	echo -e "Target: ${MAGENTA}$TARGET${NC}"
	echo -e "Total Subdomains: ${MAGENTA}$(wc -l <"$OUTPUT_SUBDOMAINS" 2>/dev/null || echo 0)${NC}"
	echo -e "Live Hosts: ${MAGENTA}$(wc -l <"$LIVE_HOSTS" 2>/dev/null || echo 0)${NC}"
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

# Create scan directory
SCAN_DIR="scan_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SCAN_DIR"
cd "$SCAN_DIR" || exit 1

OUTPUT_SUBDOMAINS="subdomains_${TARGET}.txt"
LIVE_HOSTS="live_hosts.txt"
UNCLEANED_AMASS="uncleaned_amass.txt"

# Load tokens
echo -e "${YELLOW}Loading tokens${NC}"
GITHUB_TOKEN="${GITHUB_TOKEN:-$(cat ~/.github_token 2>/dev/null)}"
SHODAN_TOKEN="${SHODAN_TOKEN:-$(cat ~/.shodan_token 2>/dev/null)}"
echo -e "${GREEN}Loading tokens completed${NC}"

# Clear output file
>"$OUTPUT_SUBDOMAINS"

# ===== Scanning =====

# Amass subdomains
(
	echo -e "${YELLOW}Enumerating amass subdomains${NC}"
	amass enum -active -brute -timeout 500 -silent -d "$TARGET" -o "$UNCLEANED_AMASS"
	awk '{print $1}' "$UNCLEANED_AMASS" | anew "$OUTPUT_SUBDOMAINS" && rm -f "$UNCLEANED_AMASS"
	echo -e "${GREEN}Amass completed${NC}"
) &

# Github subdomains
(
	echo -e "${YELLOW}Enumerating github subdomains${NC}"
	if [[ -n "$GITHUB_TOKEN" ]]; then
		github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" 2>/dev/null
		[[ -f "${TARGET}.txt" ]] && cat "${TARGET}.txt" | anew "$OUTPUT_SUBDOMAINS" && rm -f "${TARGET}.txt"
		echo -e "${GREEN}Github subdomains completed${NC}"
	fi
) &

# Shodan subdomains
(
	echo -e "${YELLOW}Enumerating shodan subdomains${NC}"
	[[ -n "$SHODAN_TOKEN" ]] && shodan domain "$TARGET" 2>/dev/null | awk -v target="$TARGET" 'NR>2 && $1!="" {print $1"."target}' | anew "$OUTPUT_SUBDOMAINS"
	echo -e "${GREEN}Shodan subdomains completed${NC}"
) &

#Assetfinder subdomains
(
	echo -e "${YELLOW}Enumerating assetfinder subdomains${NC}"
	assetfinder -subs-only "$TARGET" 2>/dev/null | anew "$OUTPUT_SUBDOMAINS"
	echo -e "${GREEN}Assetfinder subdomains completed${NC}"
) &

# Subfinder subdomains
(
	echo -e "${YELLOW}Enumerating subfinder subdomains${NC}"
	subfinder -d "$TARGET" -all -recursive -silent 2>/dev/null | anew "$OUTPUT_SUBDOMAINS"
	echo -e "${GREEN}Subfinder subdomains completed${NC}"
) &

# Crt subdomains
(
	echo -e "${YELLOW}Enumerating crt subdomains${NC}"
	curl -s "https://crt.sh/?q=%.$TARGET&output=json" 2>/dev/null | jq -r '.[].name_value' | sed 's/\*\.//g' | anew "$OUTPUT_SUBDOMAINS"
	echo -e "${GREEN}CRT subdomains completed${NC}"
) &

# Wait for all background processes to complete
wait

# Check live hosts
echo -e "${YELLOW}Checking livehosts${NC}"
cat "$OUTPUT_SUBDOMAINS" | httpx -silent | anew "$LIVE_HOSTS"
echo -e "${GREEN}Checking livehosts completed${NC}"

# Take screenshots
echo -e "${YELLOW}Taking screenshots${NC}"
cat "$LIVE_HOSTS" | httpx -screenshot -silent -system-chrome
echo -e "${GREEN}[✓] Screenshots completed and saved to ./screenshots/${NC}"

# Run summary
summary
