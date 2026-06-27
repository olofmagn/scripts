
import sys
import argparse
import boto3

from botocore.exceptions import ClientError
from typing import Optional

"""
Minimal AWS credential validity checker PoC for exposed/leaked credentials
"""

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
NC = "\033[0m"

BANNER = rf"""
                          _               _    
   __ ___      _____  ___| |__   ___  ___| | __
  / _` \ \ /\ / / __|/ __| '_ \ / _ \/ __| |/ /
 | (_| |\ V  V /\__ \ (__| | | |  __/ (__|   < 
  \__,_| \_/\_/ |___/\___|_| |_|\___|\___|_|\_\
                                                
            AWS Credential Checker PoC v1.0
                   by olofmagn
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check whether an AWS access key pair is valid"
    )
    
    parser.add_argument(
        "-k",
        "--access-key-id",
        required=True,
        help="AWS access key id (AKIA.../ASIA...)",
    )
    
    parser.add_argument(
        "-s",
        "--secret-access-key",
        required=True,
        help="AWS secret access key",
    )
    
    parser.add_argument(
        "-t",
        "--session-token",
        help="Session token, required only for temporary ASIA credentials",
    )

    return parser.parse_args()


def is_valid(akid: str, secret: str, token: Optional[str] = None) -> bool:
    """
    Check if credential pair is valid
    
    Args:
    - akid (str): AWS access key id
    - secret (str): AWS secret access key
    - token (Optional[str]): AWS session token
    
    Returns:
    - bool: True if the credentials are valid
    """
    
    session = boto3.Session(
        aws_access_key_id=akid,
        aws_secret_access_key=secret,
        aws_session_token=token,
        region_name="us-east-1" # pin explicitly so ambient AWS_* env/config cannot inject a region
    )
    
    try:
        session.client("sts").get_caller_identity()
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        print(f"{RED}[!] Rejected by AWS: {code}{NC}")
        return False
    except Exception as e: 
        print(f"{RED}[!] Unexpected error occured {e}{NC}")
        return False

def main():
    print(f"{RED}{BANNER}{NC}")

    args = parse_args()

    # Trim whitespace/newlines
    akid = args.access_key_id.strip()
    secret = args.secret_access_key.strip()
    token = args.session_token.strip() if args.session_token else None

    print(f"{BLUE}[*] Checking {args.access_key_id} ...{NC}")
    
    # Check if valid credentials
    if is_valid(akid, secret, token):
        print(f"{GREEN}[+] Valid{NC}")
        sys.exit(0)
    else:
        print(f"{RED}[-] Invalid{NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
