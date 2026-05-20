import requests
import argparse
import time
import json

from typing import List, Dict

"""
Simple rate-limit / abuse detection tester for password recovery endpoints
"""

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings()

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
NC = "\033[0m"

# Constants
RATE_LIMIT_CODES = {429, 403}

BANNER = rf"""
                                   _    __ _                 _           
  _ ____      ___ __ ___  ___  ___| |_ / _| | ___   ___   __| | ___ _ __ 
 | '_ \ \ /\ / / '__/ _ \/ __|/ _ \ __| |_| |/ _ \ / _ \ / _` |/ _ \ '__|
 | |_) \ V  V /| | |  __/\__ \  __/ |_|  _| | (_) | (_) | (_| |  __/ |   
 | .__/ \_/\_/ |_|  \___||___/\___|\__|_| |_|\___/ \___/ \__,_|\___|_|   
 |_|                                                                     

                Password Recovery Rate-limit Tester v1.0
                            by olofmagn
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rate-limit tester for password recovery endpoint"
    )

    parser.add_argument(
        "url",
        help="Base URL (e.g. https://target.com)"
    )

    parser.add_argument(
        "-e", 
        "--email", 
        required=True, 
        help="Target email"
    )

    parser.add_argument(
        "-c", 
        "--count", 
        type=int, 
        default=5, 
        help="Number of requests"
    )

    parser.add_argument(
        "-d", 
        "--delay", 
        type=float, 
        default=1.0, 
        help="Delay between requests"
    )

    parser.add_argument(
        "-p", 
        "--path", 
        required=True, 
        help="Endpoint path"
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        help="Custom header (format: 'Header-Name: value')",
    )

    parser.add_argument(
        "--show-len", 
        action="store_true", 
        help="Show response length"
    )

    return parser.parse_args()


def load_headers(header_args: List[str]) -> Dict[str, str]:
    """
    Load headers from CLI arguments and optional file

    Args:
    - header_args (List[str]): List of header strings from CLI arguments

    Returns:
    - Dict[str, str]: Dictionary of headers to be added to the session
    """

    headers = {}

    for header in header_args:
        try:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
        except ValueError:
            print(f"{YELLOW}[!] Invalid header format: {header} {NC}")
        except Exception as e:
            print(f"{RED}[!] An unexpected error occurred: {e}{NC}")

    return headers


def create_session(custom_headers: Dict[str, str]) -> requests.Session:
    """
    Create configured session object

    Returns:
    - requests.Session: Configured session object
    """

    session = requests.Session()
    session.verify = False

    # Set default headers
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/136.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
            "Content-Type": "application/json",
        }
    )

    session.headers.update(custom_headers)

    return session


def send_request(session: requests.Session, endpoint: str, email: str) -> Dict:
    """
    Send a single password recovery request and measure response
    Args:
    - session (requests.Session): Configured session object
    - endpoint (str): Full target endpoint URL
    - email (str): Target email address

    Returns:
    - Dict: Result containing status, time, length, and response snippet
    """

    try:
        start = time.perf_counter()

        r = session.post(endpoint, json={"email": email}, timeout=10)

        elapsed = round(time.perf_counter() - start, 3)

        return {
            "status": r.status_code,
            "time": elapsed,
            "length": len(r.text),
            "response": r.text[:200],
        }

    except requests.RequestException as e:
        return {"status": "error", "time": 0, "length": 0, "response": str(e)}


def detect_signals(results: List[Dict]) -> Dict[str, bool]:
    """
    Centralized detection logic for rate-limit signals

    Args:
    - results (List[Dict]): List of result dictionaries from send_request

    Returns:
    - Dict[str, bool]: Detected signals (e.g. hard_rl, soft_rl)
    """

    # Filter out errors
    valid_results = [r for r in results if r["status"] != "error"]
    baseline_len = valid_results[0]["length"] if valid_results else None

    # Hard rate limit
    hard_rl = any(r["status"] in RATE_LIMIT_CODES for r in results)

    # Soft rate limit
    soft_rl = baseline_len is not None and any(
        r["length"] != baseline_len for r in valid_results
    )

    return {
        "hard_rl": hard_rl,
        "soft_rl": soft_rl,
        "baseline_len": baseline_len,
        "times": [r["time"] for r in valid_results],
    }


def analyze(results: List[Dict]) -> None:
    """
    Analyze results using centralized detection logic
    """

    print(f"\n{GREEN}[*] Analysis Summary{NC}")

    # Run centralized detection
    signals = detect_signals(results)
    times = signals["times"]

    # Status distribution
    status_map = {}
    for r in results:
        status_map[r["status"]] = status_map.get(r["status"], 0) + 1

    print(f"{GREEN}Status distribution:{NC}")
    for k, v in status_map.items():
        print(f"  - {k}: {v}")

    # Hard rate limit
    if signals["hard_rl"]:
        print(f"{RED}[!] Rate limiting detected based on status codes{NC}")

    # Soft rate limit
    if signals["soft_rl"]:
        print(f"{RED}[!] Rate limiting detected based on response variation{NC}")

    # Timing analysis
    if times:
        print(f"\n{GREEN}Timing analysis:{NC}")
        print(f"  - min: {min(times)}s")
        print(f"  - max: {max(times)}s")
        print(f"  - avg: {sum(times) / len(times):.3f}s")

    # Final summary
    print_final_summary(results, times, signals)


def print_final_summary(
    results: List[Dict], times: List[float], signals: Dict[str, bool]
) -> None:
    """
    Print final summary of test results
    """

    print(f"\n{GREEN}[*] Final Summary{NC}")

    # Calculate totals
    total = len(results)
    errors = sum(1 for r in results if r["status"] == "error" or r["status"])
    rate_limited = sum(1 for r in results if r["status"] in RATE_LIMIT_CODES)

    # Filter successful requests
    success = total - errors

    print(f"{BLUE}Total requests:{NC} {total}")
    print(f"{GREEN}Successful:{NC} {success}")
    print(f"{RED}Errors:{NC} {errors}")
    print(f"{YELLOW}Rate-limited responses:{NC} {rate_limited}")

    print(f"\n{GREEN}Detection signals:{NC}")

    print(f"  - Hard rate limit (HTTP codes): {'YES' if signals['hard_rl'] else 'NO'}")
    print(f"  - Soft response variation: {'YES' if signals['soft_rl'] else 'NO'}")

    print(f"\n{GREEN}[+] Analysis complete{NC}")


def save_results(results: List[Dict], path: str, args: argparse.Namespace) -> None:
    """
    Save results to a JSON file

    Args:
    - results (List[Dict]): List of result dictionaries from send_request
    - path (str): File path to save the results
    """

    metadata = {
        "url": args.url,
        "path": args.path,
        "email": args.email,
        "count": args.count,
        "delay": args.delay,
    }

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"metadata": metadata, "results": results}, f, indent=2)
    except Exception as e:
        print(f"{RED}[!] Failed to save results: {e}{NC}")


def print_config(args, custom_headers) -> None:
    """
    Print the configuration summary before starting the test

    Args:
    - args: Parsed command-line arguments
    - custom_headers (Dict[str, str]): Custom headers for the requests
    """

    print(f"{BLUE}[*] Target: {args.url}{NC}")
    print(f"{BLUE}[*] Email: {args.email}{NC}")
    print(f"{BLUE}[*] Endpoint: {args.path}{NC}")
    print(f"{BLUE}[*] Headers: {custom_headers}{NC}")
    print(f"{BLUE}[*] Requests: {args.count} | Delay: {args.delay}s{NC}\n")


def print_result(i: int, res: Dict, show_len: bool = False) -> None:
    """
    Print the result of a single request in a formatted manner

    Args:
    - i (int): Request index
    - res (Dict): Result dictionary from send_request
    """

    len_part = f" Len={res['length']}" if show_len else ""
    print(f"[{i + 1}] Status={res['status']} Time={res['time']}s{len_part}")


def main():
    print(f"{RED}{BANNER}{NC}")

    args = parse_args()

    custom_headers = load_headers(args.header)

    print_config(args, custom_headers)

    session = create_session(custom_headers)

    endpoint = f"{args.url.rstrip('/')}/{args.path.lstrip('/')}"

    results = []

    print(f"{GREEN}[*] Starting test...{NC}\n")
    for i in range(args.count):
        res = send_request(session, endpoint, args.email)
        results.append(res)
        print_result(i, res, args.show_len)
        time.sleep(args.delay)

    analyze(results)

    save_results(results, "rate_limit_results.json", args)

    print(f"\n{GREEN}[+] Results saved to rate_limit_results.json{NC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] An unexpected error occurred: {e}{NC}")
        sys.exit(1)
