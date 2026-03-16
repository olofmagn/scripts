import requests
import argparse
import re
import json

from typing import List, Dict, Set


"""
A simple program that fetches JavaScript files for DWR service interfaces and extracts available methods
"""

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
NC = "\033[0m"

# Disable warnings
requests.packages.urllib3.disable_warnings()

# Pattern used to identify DWR calls
EXEC_PATTERN = re.compile(r"_execute\((.*?)\)")

BANNER = rf"""
     _               _____                                 
    | |             |  __ \                                
  __| |__      _____| |__) |___  __ _ _ __   ___ _ __     
 / _` |\ \ /\ / / __|  _  // _ \/ _` | '_ \ / _ \ '__|   
| (_| | \ V  V /\__ \ | \ \  __/ (_| | |_) |  __/ |      
 \__,_|  \_/\_/ |___/_|  \_\___|\__,_| .__/ \___|_|      
                                      | |                  
                                      |_|  

        DWR service harvesting tool v1.0
                  by olofmagn
"""


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments

    Returns:
    - argparse.Namespace: Parsed command-line arguments
    """

    parser = argparse.ArgumentParser(
        description="Extract DWR interface methods from JavaScript files"
    )

    parser.add_argument(
        "url", 
        help="Base interface URL (example: https://target/dwr/interface)"
    )

    parser.add_argument(
        "-o", 
        "--output", 
        default="dwr_endpoints.json", 
        help="Output JSON file"
    )

    parser.add_argument(
        "-i",
        "--interfaces",
        default=None,
        help="Path to text file containing interface names (one per line)",
    )

    return parser.parse_args()


def load_interfaces(file_path: str) -> List[str]:
    """
    Load DWR interface name from a text file

    Args:
    - file_path (str): Path to the file of the interface names

    Returns
    - List[str]: List of interface names
    """

    if file_path is None:
        print(
            f"{YELLOW}[!] No interface file provided, using built-in default interfaces{NC}"
        )
        # Default interfaces
        return [
            "UserService",
            "AnalyticsService",
            "CatalogService",
            "RecommendationService",
            "SignupService",
            "AccountService",
            "AuthService",
            "LoginService",
            "CartService",
            "OrderService",
            "PaymentService",
            "ProfileService",
            "AdminService",
            "ConfigService",
            "SystemService",
            "DebugService",
            "SearchService",
            "ProductService",
            "LookupService",
            "DocumentService",
            "DrawingBimService",
            "SecurityService",
            "SmartClientConfigService",
            "workflow",
        ]

    # Load interfaces from file
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{YELLOW}[!] Warning: '{file_path}' not found{NC}")
        return []


def create_session() -> requests.Session:
    """
    Create configured session object

    Returns
    - requests.Session: A configured session object for making HTTP requests
    """

    session = requests.Session()
    session.verify = False

    return session


def fetch_js(session: requests.Session, base_url: str, service: str) -> str | None:
    """
    Fetch the JavaScript file for a given DWR service interface

    Args:
    - session (request.Session): object for making HTTP requests
    - base_url (str): Base URL of the DWR interface
    - service (str): Name of the service interface

    Returns:
    - str: The content of the JavaScript file
    """

    url = f"{base_url.rstrip('/')}/{service}.js"

    try:
        r = session.get(url, timeout=6)

        if r.status_code == 200:
            return r.text
        else:
            print(f"{RED}[-] {url} returned HTTP {r.status_code}{NC}")

    except requests.RequestException as e:
        print(f"{RED}[-] Request failed for {url}: {e}{NC}")

    return None


def parse_calls(js_code: str) -> Dict[str, Set[str]]:
    """
    Parse the JavaScript code to extract DWR service and method names

    Args:
    - js_code (str): The JavaScript code as a string

    Returns:
    - Dict[str, Set[str]]: Dictionary where keys are service names and values are sets of method names
    """

    services = {}

    matches = EXEC_PATTERN.findall(js_code)

    for entry in matches:
        parts = [x.strip().strip("'\"") for x in entry.split(",")]

        if len(parts) < 3:
            continue

        svc = parts[1]
        method = parts[2]

        services.setdefault(svc, set()).add(method)

    return services


def pluralize(count: int, word: str) -> str:
    """
    Pluralize words based on count

    Args:
    - count (int): The number of items
    - word (str): The word to pluralize

    Returns:
    - str: The pluralized word with count
    """

    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def collect_endpoints(
    session: requests.Session, base_url: str, interfaces: List[str]
) -> Dict[str, Set[str]]:
    """
    Collect DWR service endpoints

    Args:
    - session (requests.Session): A configured session object for making HTTP requests
    - base_url (str): Base URL of the DWR interface
    - interfaces (List[str]): List of interface names to check

    Returns:
    - Dict[str, Set[str]]: Dictionary where keys are service names and values are sets
    """

    collected = {}

    for iface in interfaces:
        print(f"{BLUE}[*] Fetching {iface}.js{NC}")
        js = fetch_js(session, base_url, iface)

        if not js:
            continue

        parsed = parse_calls(js)

        for svc, methods in parsed.items():
            print(
                f"{GREEN}[+] Found {svc} with {pluralize(len(methods), 'method')}{NC}"
            )
            collected.setdefault(svc, set()).update(methods)

    return collected


def format_results(collected: Dict[str, Set[str]]) -> Dict[str, List[str]]:
    """
    Format the collected endpoints into a more readable format

    Args:
    - collected (Dict[str, Set[str]]): Dictionary where keys are service names and values are sets of method names

    Returns:
    - Dict[str, List[str]]: Dictionary where keys are service names and values are sorted lists of method names
    """

    return {
        k: sorted(list(v))
        for k, v in sorted(collected.items(), key=lambda x: len(x[1]), reverse=True)
    }


def save_results(results: Dict[str, List[str]], path: str) -> None:
    """
    Save the results to a JSON file

    Args:
    - results (Dict[str, List[str]]): Dictionary where keys are service names and values are lists of method names
    - path (str): Path to the output JSON file
    """

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except IOError as e:
        print(f"{RED}[!] Error saving results: {e}{NC}")
    except TypeError as e:
        print(f"{RED}[!] Error serializing results: {e}{NC}")


def print_summary(results: Dict[str, List[str]]) -> None:
    """
    Print a summary of the discovered services and their method counts

    Args:
    - results (Dict[str, List[str]]): Dictionary where keys are service names and values are lists of method names
    """

    print()  # Blank line before summary
    for svc, methods in results.items():
        print(f"{GREEN}{svc:<30} -> {pluralize(len(methods), 'method')}{NC}")


def main():
    print(f"{RED}{BANNER}{NC}")

    args = parse_args()

    session = create_session()

    interfaces = load_interfaces(args.interfaces)

    print(f"{BLUE}[*] Starting DWR enumeration against {args.url}{NC}")

    collected = collect_endpoints(session, args.url, interfaces)

    results = format_results(collected)

    print_summary(results)

    # Write only meaningful results
    if not results:
        print(f"{YELLOW}[!] No endpoints found, skipping output file{NC}")
        return

    save_results(results, args.output)

    print(f"\n{GREEN}[+] Results saved to {args.output}{NC}")


if __name__ == "__main__":
    main()
