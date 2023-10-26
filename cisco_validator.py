"""
Cisco IOX XE checker using Shodan search results

Inspired by the work of Fox IT
https://github.com/fox-it/cisco-ios-xe-implant-detection/tree/main

References:
- https://github.com/fox-it/cisco-ios-xe-implant-detection/tree/main
- https://www.bleepingcomputer.com/news/security/hackers-update-cisco-ios-xe-backdoor-to-hide-infected-devices/
"""

import sys
import argparse
import logging
import urllib3
import time
import json

#FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
FORMAT = "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)
logger = logging.getLogger("CiscoValidator")

AUTHORIZATION_HEADER_VALUE = "0ff4fbf0ecffa77ce8d3852a29263e263838e9bb"
SHODAN_MAIN = "http.html_hash:1076109428"
OUTPUT_FILE = "compromised_hosts.json"

try:
    import requests
except ImportError:
    raise ImportError(f"Could not find `requests`. Please run `pip install requests`")

try:
    import shodan
except ImportError:
    raise ImportError(f"Could not find `shodan`. Please run `pip install shodan`")


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_hex(hex_str : str) -> bool:
    """
    Checks if the given string is an haxadecimal number
    """
    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False
    
def run_shodan_search(key : str, query : list = None):
    """
    Run Shodan query
    """
    try:
        api = shodan.Shodan(key)
        query_str = SHODAN_MAIN
        if query:
            query_str = f"{ query_str } {' '.join(query)}"
        result = api.search(query_str)
        return result
    except Exception as e:
        logger.error(f"Error running Shodan search. { e }")

def is_compromised(url : str, timeout : int = 10) -> bool:
    """
    Test if the host is compromised
    """
    headers = {
        "Authorization": AUTHORIZATION_HEADER_VALUE,
        "User-Agent": f"{ __file__ } - Cisco validator"
    }

    try:
        response = requests.post(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        return is_hex(response.text)
    except Exception as e:
        logger.info(f"Error: { e }")
    return False 

def check_host(host : str):
    """
    Check specific host
    """
    urls = [
        f"http://{ host }/webui/logoutconfirm.html?logon_hash=1",
        f"https://{ host }/webui/logoutconfirm.html?logon_hash=1"
    ]
    
    potential_compromise = False
    for url in urls:
        logger.info(f"[!] Checking url { url }")
        if is_compromised(url):
            logger.warning(f"   WARNING: Possible implant found on { url }")
            potential_compromise = True
    
    if not potential_compromise:
        logger.info(f"[*] No sign of compromise for { host }")
    
    return potential_compromise

def main():
    """
    Checker
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Search and scan Cisco IOS XE device(s)"
    )
    parser.add_argument("-k", "--shodan-key", type=str, help="Shodan API key", required=True, dest="shodan_key")
    parser.add_argument("-q", "--query", action="append", help="Additional Shodan query parameters", dest="query", default=[])
    parser.add_argument("-o", "--output", help="File to store the list of compromised hosts", default=OUTPUT_FILE, dest="output_file")
    args = parser.parse_args()

    start_time = time.time()

    logger.info(f"[*] Cisco IOS XE Compromise checker")
    logger.info(f"[*] Start time: { start_time }")

    logger.info(f"[*] Running Shodan search with query '{ ' '.join(args.query) }'")
    result = run_shodan_search(args.shodan_key, args.query)

    logger.info(f"[*] Found { result['total'] } results")

    items = result["matches"]
    potential_compromised_hosts = []
    for item in items:
        logger.info(f"[*] Processing device { item['ip_str'] }")
        if check_host(item["ip_str"]):
            potential_compromised_hosts.append(item)
            logger.warning(f"   POTENTIAL COMPROMISE IN HOST { item['ip_str'] }\n\tISP: { item['isp'] }\n\tOrganization: { item['org'] }\n\tLocation: Country: { item['location']['country_name'] }. City: { item['location']['city'] }")
        time.sleep(2)

    logger.info(f"[*] Saving results to file")
    try:
        with open("compromised_hosts.json", "w") as file:
            file.write(json.dumps(potential_compromised_hosts, indent=4))
        logger.info(f"[!] Results recorded in file { args.output_file }")
    except Exception as e:
        logger.error(f"[*] Cannot write results to file")
    
    end_time = time.time()
    logger.info(f"[*] Finish time: { end_time }. Elapsed time: { end_time - start_time }")
    logger.info(f"[*] Cisco validation finished")

if __name__ == "__main__":
    sys.exit(main())