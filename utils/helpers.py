# utils/helpers.py - Improved CAPTCHA detection

import re
import time
import random
from datetime import datetime

from utils.colors import info, error, success
from config import DELAY_BETWEEN_ATTEMPTS


def wait_with_jitter(min_time=1, max_time=3):
    """Wait a random amount of time with jitter to appear more human-like"""
    base_time = random.uniform(min_time, max_time)
    jitter = random.uniform(0, 0.5)  # Add up to 0.5 seconds of jitter
    time.sleep(base_time + jitter)


def simulate_human_behavior(session):
    """Simulate human behavior by adding typical behavior patterns"""
    # Add random pauses between requests
    wait_with_jitter(0.5, 2)

    # Set common headers that browsers typically send
    session.headers.update(
        {
            "DNT": "1",  # Do Not Track
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Pragma": "no-cache",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }
    )

    return session


def extract_hidden_fields(html):
    """Enhanced extraction of hidden form fields from HTML response"""
    hidden_fields = {}
    try:
        # Find all hidden input fields with improved pattern matching
        matches = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', html)

        for match in matches:
            name_match = re.search(r'name=["\']([^"\']+)["\']', match)
            value_match = re.search(r'value=["\']([^"\']*)["\']', match)

            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                hidden_fields[name] = value

        # Try alternative JSON-based extraction for modern Facebook
        json_fields = re.findall(r'"name":"([^"]+)","value":"([^"]*)"', html)
        for name, value in json_fields:
            if name not in hidden_fields:
                hidden_fields[name] = value

    except Exception as e:
        error(f"[!] Error extracting hidden fields: {e}")

    return hidden_fields


def extract_error_message(html):
    """Extract error messages from HTML response with improved patterns"""
    error_patterns = [
        r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]*id=["\']error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div id="error_box"[^>]*>(.*?)</div>',
        r'<div class="[^"]*error_message[^"]*">\s*([^<>]+)\s*</div>',
        r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</span>',
        r'errorMessage":"([^"]+)"',
        r'"error":{"message":"([^"]+)"',
    ]

    for pattern in error_patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        if matches:
            # Clean up the error message (remove HTML tags and extra whitespace)
            error_text = re.sub(r"<[^>]+>", " ", matches[0])
            error_text = " ".join(error_text.split())
            return error_text.strip()

    return "Unknown error occurred"


def extract_security_tokens(html):
    """Extract security tokens from HTML response with improved patterns"""
    tokens = {}

    # Common token patterns on Facebook (expanded)
    token_patterns = {
        "fb_dtsg": [
            r'name="fb_dtsg" value="([^"]+)"',
            r'"fb_dtsg":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"fb_dtsg"',
        ],
        "jazoest": [
            r'name="jazoest" value="([^"]+)"',
            r'"jazoest":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"jazoest"',
        ],
        "lsd": [
            r'name="lsd" value="([^"]+)"',
            r'"lsd":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"lsd"',
        ],
        "m_ts": [
            r'name="m_ts" value="([^"]+)"',
            r'"m_ts":"([^"]+)"',
        ],
        "li": [
            r'name="li" value="([^"]+)"',
            r'"li":"([^"]+)"',
        ],
        "__dyn": [
            r'name="__dyn" value="([^"]+)"',
            r'"__dyn":"([^"]+)"',
        ],
        "__csr": [
            r'name="__csr" value="([^"]+)"',
            r'"__csr":"([^"]+)"',
        ],
    }

    for token_name, patterns in token_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                tokens[token_name] = match.group(1)
                break

    return tokens


def get_timestamp():
    """Get current timestamp in Facebook format"""
    return int(time.time() * 1000)


def format_timestamp(timestamp=None):
    """Format timestamp for display"""
    if timestamp is None:
        timestamp = datetime.now()
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def detect_captcha(html):
    """Enhanced detection of CAPTCHA or security checkpoint challenges"""
    # More precise patterns to identify captchas and security checkpoints
    captcha_patterns = [
        # Explicit CAPTCHA indicators
        r'<div[^>]*id=["\']captcha',
        r'<div[^>]*class=["\'][^"\']*captcha',
        r'name=["\']captcha',
        r"captcha\.php",
        r"captcha_response",
        r"checkbox.captcha",
        # Security checkpoint indicators
        r"checkpoint",
        r"security\s+check",
        r"/recover/",
        r"suspended",
        r"suspicious\s+activity",
        r"unusual\s+activity",
        r"confirm\s+your\s+identity",
        r"confirm\s+.*?\s+account",
        r"verify\s+.*?\s+identity",
        r"verification\s+code",
        # Blocking indicators
        r"temporarily\s+blocked",
        r"unavailable\s+right\s+now",
        r"try\s+again\s+later",
        r"disabled",
        r"sorry\s+.*?\s+error",
        # Facebook-specific security check indicators
        r"security/captcha",
        r"security_check",
        r"checkpoint\.php",
        r"checkpoint/block",
    ]

    for pattern in captcha_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    # Also check URL redirects that indicate security measures
    url_indicators = [
        "checkpoint",
        "security",
        "captcha",
        "recover",
        "disabled",
        "suspended",
        "blocked",
    ]

    if any(indicator in html for indicator in url_indicators):
        return True

    return False


def handle_between_attempts(attempt, max_attempts):
    """Handle logic between registration attempts with improved waiting strategy"""
    if attempt < max_attempts - 1:
        info(f"[*] Waiting before next attempt...")
        min_time, max_time = DELAY_BETWEEN_ATTEMPTS

        # Increase wait time for each subsequent attempt to avoid rate limiting
        min_time += attempt * 2
        max_time += attempt * 3

        wait_with_jitter(min_time, max_time)
        return True
    return False


def extract_user_id(response, session):
    """Extract user ID from response or cookies with improved patterns"""
    user_id = "Unknown"

    # Check cookies first (most reliable)
    cookies = session.cookies.get_dict()
    if "c_user" in cookies:
        user_id = cookies.get("c_user")
        return user_id

    # Try to extract from URL
    url = response.url
    id_patterns = [
        r"id=(\d+)",
        r"user=(\d+)",
        r"uid=(\d+)",
        r"/profile\.php\?id=(\d+)",
        r"facebook\.com/(\d+)",
    ]

    for pattern in id_patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    # Try to extract from HTML content
    html = response.text
    html_patterns = [
        r'"userID":"(\d+)"',
        r'"user_id":"(\d+)"',
        r'"userId":"(\d+)"',
        r'"actorID":"(\d+)"',
        r'name="target" value="(\d+)"',
    ]

    for pattern in html_patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)

    # If all else fails, generate a placeholder ID
    if user_id == "Unknown":
        from utils.generators import generate_random_string

        user_id = f"FB{generate_random_string(10)}"

    return user_id
