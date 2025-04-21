# utils/proxy.py - Improved proxy handling

import os
import random
import requests
import time
import json
from datetime import datetime, timedelta

from config import PROXIES_PATH
from utils.colors import success, error, info

# Global proxy list and scoring
PROXY_LIST = []
PROXY_SCORES = {}  # Keep track of proxy reliability
PROXY_LAST_USED = {}  # Track when a proxy was last used
PROXY_USAGE_COUNT = {}  # Track how many times a proxy has been used


def load_proxies():
    """Load proxies from the proxies.txt file with enhanced validation"""
    global PROXY_LIST, PROXY_SCORES
    try:
        if os.path.exists(PROXIES_PATH):
            valid_proxies = []
            with open(PROXIES_PATH, "r") as f:
                lines = [line.strip() for line in f if line.strip()]

            # Validate format of each proxy
            for i, line in enumerate(lines):
                parts = line.split(":")
                if len(parts) not in (2, 4):  # IP:PORT or IP:PORT:USER:PASS
                    error(f"[!] Invalid proxy format on line {i+1}: {line}")
                    continue
                valid_proxies.append(line)

                # Initialize proxy scoring
                PROXY_SCORES[line] = 5  # Start with a neutral score (range 0-10)
                PROXY_LAST_USED[line] = None
                PROXY_USAGE_COUNT[line] = 0

            PROXY_LIST = valid_proxies
            success(f"[+] Loaded {len(PROXY_LIST)} proxies")
            return len(PROXY_LIST) > 0
        else:
            error(
                f"[!] No proxies found. Create a proxies.txt file with one proxy per line."
            )
            return False
    except Exception as e:
        error(f"[!] Error loading proxies: {e}")
        return False


def parse_proxy(proxy_str):
    """Parse a proxy string with improved error handling"""
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
    """Get a random proxy from the list with weighted selection"""
    if not PROXY_LIST:
        return None

    # Use weighted selection based on scores
    weights = [max(PROXY_SCORES.get(proxy, 1), 1) for proxy in PROXY_LIST]
    total = sum(weights)

    if total <= 0:
        # Fallback to random selection if scoring system fails
        proxy_str = random.choice(PROXY_LIST)
    else:
        # Weighted random selection
        r = random.uniform(0, total)
        upto = 0
        for i, w in enumerate(weights):
            if upto + w >= r:
                proxy_str = PROXY_LIST[i]
                break
            upto += w
        else:
            proxy_str = random.choice(PROXY_LIST)

    return parse_proxy(proxy_str)


def test_proxy(proxy):
    """Test if a proxy is working with multiple test services"""
    if not proxy:
        return False

    try:
        session = requests.Session()
        session.proxies.update(proxy)

        # Set timeout shorter for testing
        timeout = 10

        # Test with multiple sites for reliability
        test_urls = [
            "https://httpbin.org/ip",
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
        ]

        success_count = 0
        for url in test_urls:
            try:
                response = session.get(url, timeout=timeout)
                if response.status_code == 200:
                    success(f"[+] Proxy working: {url}")
                    success_count += 1
                    # Break after first success to speed up tests
                    if success_count >= 1:
                        break
            except:
                continue

        result = success_count > 0

        # Update the proxy score based on this test
        proxy_str = None
        for p in PROXY_LIST:
            proxy_data = parse_proxy(p)
            if proxy_data and proxy_data.get("http") == proxy.get("http"):
                proxy_str = p
                break

        if proxy_str:
            # Adjust score based on result
            if result:
                PROXY_SCORES[proxy_str] = min(10, PROXY_SCORES.get(proxy_str, 5) + 1)
            else:
                PROXY_SCORES[proxy_str] = max(0, PROXY_SCORES.get(proxy_str, 5) - 2)

        return result

    except Exception as e:
        error(f"[!] Proxy test error: {e}")
        return False


def test_proxy_for_facebook(proxy):
    """Test if a proxy works specifically for Facebook"""
    if not proxy:
        return False

    try:
        session = requests.Session()
        session.proxies.update(proxy)

        # Set user agent to appear like a normal browser
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
        )

        # Test with Facebook's domains
        test_urls = [
            "https://www.facebook.com/robots.txt",
            "https://m.facebook.com/robots.txt",
        ]

        for url in test_urls:
            try:
                response = session.get(url, timeout=10)
                if response.status_code == 200:
                    success(f"[+] Proxy working for Facebook: {url}")
                    return True
            except:
                continue

        error(f"[!] Proxy test failed for Facebook URLs")
        return False

    except Exception as e:
        error(f"[!] Proxy test error for Facebook: {e}")
        return False


def rotate_proxy(used_proxies=None):
    """Get a new proxy using an improved rotation strategy"""
    if not PROXY_LIST:
        return None

    if used_proxies is None:
        used_proxies = []

    # Filter out proxies with very low scores
    valid_proxies = [p for p in PROXY_LIST if PROXY_SCORES.get(p, 0) > 2]

    # If no valid proxies, use the full list as fallback
    if not valid_proxies:
        valid_proxies = PROXY_LIST

    # Prioritize:
    # 1. Proxies not recently used
    # 2. Proxies with higher scores
    # 3. Proxies used less frequently

    now = datetime.now()
    candidates = []

    for proxy in valid_proxies:
        if proxy in used_proxies:
            continue

        last_used = PROXY_LAST_USED.get(proxy)
        cooldown_factor = 1.0

        # Calculate a cooldown factor based on when this proxy was last used
        if last_used:
            time_since_use = (now - last_used).total_seconds()
            if time_since_use < 60:  # Used in the last minute
                cooldown_factor = 0.2
            elif time_since_use < 300:  # Used in the last 5 minutes
                cooldown_factor = 0.5
            else:
                cooldown_factor = 1.0

        # Calculate usage penalty (used less = better)
        usage_count = PROXY_USAGE_COUNT.get(proxy, 0)
        usage_penalty = max(0, 1.0 - (usage_count * 0.1))

        # Final score for proxy selection
        score = PROXY_SCORES.get(proxy, 5) * cooldown_factor * usage_penalty
        candidates.append((proxy, score))

    # Sort candidates by final score (higher is better)
    candidates.sort(key=lambda x: x[1], reverse=True)

    # If we have candidates, pick the best one
    if candidates:
        best_proxy = candidates[0][0]
        PROXY_LAST_USED[best_proxy] = now
        PROXY_USAGE_COUNT[best_proxy] = PROXY_USAGE_COUNT.get(best_proxy, 0) + 1
        return parse_proxy(best_proxy)

    # Fallback: if all proxies were recently used, pick the least recently used one
    if valid_proxies:
        least_recent = sorted(
            valid_proxies, key=lambda p: PROXY_LAST_USED.get(p, datetime(2000, 1, 1))
        )[0]

        PROXY_LAST_USED[least_recent] = now
        PROXY_USAGE_COUNT[least_recent] = PROXY_USAGE_COUNT.get(least_recent, 0) + 1
        return parse_proxy(least_recent)

    # Last resort
    return None


def update_proxy_status(proxy, success_status):
    """Update proxy score based on success or failure"""
    # Find the proxy string from the parsed proxy
    proxy_str = None
    http_proxy = proxy.get("http", "")

    for p in PROXY_LIST:
        parsed = parse_proxy(p)
        if parsed and parsed.get("http") == http_proxy:
            proxy_str = p
            break

    if not proxy_str:
        return

    # Update score
    current_score = PROXY_SCORES.get(proxy_str, 5)

    if success_status:
        # Success: Increase score
        new_score = min(10, current_score + 1)
    else:
        # Failure: Decrease score more significantly
        new_score = max(0, current_score - 2)

    PROXY_SCORES[proxy_str] = new_score

    # Log status
    if success_status:
        info(f"[+] Proxy performed well, new score: {new_score}/10")
    else:
        info(f"[+] Proxy failed, new score: {new_score}/10")
