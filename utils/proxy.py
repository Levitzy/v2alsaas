# Proxy handling utilities

import os
import random
import requests
import time

from config import PROXIES_PATH
from utils.colors import success, error, info

# Global proxy list
PROXY_LIST = []


def load_proxies():
    """Load proxies from the proxies.txt file"""
    global PROXY_LIST
    try:
        if os.path.exists(PROXIES_PATH):
            with open(PROXIES_PATH, "r") as f:
                PROXY_LIST = [line.strip() for line in f if line.strip()]
            success(f"[+] Loaded {len(PROXY_LIST)} proxies")
            return len(PROXY_LIST) > 0
        else:
            error(
                "[!] No proxies found. Create a proxies.txt file with one proxy per line."
            )
            return False
    except Exception as e:
        error(f"[!] Error loading proxies: {e}")
        return False


def parse_proxy(proxy_str):
    """Parse a proxy string in format IP:PORT:USERNAME:PASSWORD"""
    try:
        parts = proxy_str.split(":")
        if len(parts) == 2:  # IP:PORT format
            ip, port = parts
            return {"http": f"http://{ip}:{port}", "https": f"http://{ip}:{port}"}
        elif len(parts) == 4:  # IP:PORT:USERNAME:PASSWORD format
            ip, port, username, password = parts
            auth_proxy = f"http://{username}:{password}@{ip}:{port}"
            return {"http": auth_proxy, "https": auth_proxy}
        else:
            error(f"[!] Invalid proxy format: {proxy_str}")
            return None
    except Exception as e:
        error(f"[!] Error parsing proxy {proxy_str}: {e}")
        return None


def get_random_proxy():
    """Get a random proxy from the list"""
    if not PROXY_LIST:
        return None

    proxy_str = random.choice(PROXY_LIST)
    return parse_proxy(proxy_str)


def test_proxy(proxy):
    """Test if a proxy is working"""
    if not proxy:
        return False

    try:
        session = requests.Session()
        session.proxies.update(proxy)

        # Test with multiple sites for reliability
        test_urls = [
            "https://httpbin.org/ip",
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
        ]

        for url in test_urls:
            try:
                response = session.get(url, timeout=10)
                if response.status_code == 200:
                    success(f"[+] Proxy working: {url}")
                    return True
            except:
                continue

        error(f"[!] Proxy test failed for all test URLs")
        return False

    except Exception as e:
        error(f"[!] Proxy test error: {e}")
        return False


def rotate_proxy(used_proxies=None):
    """Get a new proxy, avoiding recently used ones"""
    if not PROXY_LIST:
        return None

    if used_proxies is None:
        used_proxies = []

    available_proxies = [p for p in PROXY_LIST if p not in used_proxies]

    if not available_proxies:
        # If all proxies were used, start over but with a delay
        time.sleep(2)
        return parse_proxy(random.choice(PROXY_LIST))

    return parse_proxy(random.choice(available_proxies))
