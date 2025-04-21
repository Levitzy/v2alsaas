# General helper functions

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
        }
    )

    return session


def extract_hidden_fields(html):
    """Extract hidden form fields from HTML response"""
    hidden_fields = {}
    try:
        # Find all hidden input fields
        matches = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', html)

        for match in matches:
            name_match = re.search(r'name=["\']([^"\']+)["\']', match)
            value_match = re.search(r'value=["\']([^"\']*)["\']', match)

            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                hidden_fields[name] = value
    except Exception as e:
        error(f"[!] Error extracting hidden fields: {e}")

    return hidden_fields


def extract_error_message(html):
    """Extract error messages from HTML response"""
    error_patterns = [
        r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div id="error_box"[^>]*>(.*?)</div>',
        r'<div class="[^"]*">\s*([^<>]+)\s*</div>',
        r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</span>',
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
    """Extract security tokens from HTML response"""
    tokens = {}

    # Common token patterns on Facebook
    token_patterns = {
        "fb_dtsg": r'name="fb_dtsg" value="([^"]+)"',
        "jazoest": r'name="jazoest" value="([^"]+)"',
        "lsd": r'name="lsd" value="([^"]+)"',
        "m_ts": r'name="m_ts" value="([^"]+)"',
        "li": r'name="li" value="([^"]+)"',
    }

    for token_name, pattern in token_patterns.items():
        match = re.search(pattern, html)
        if match:
            tokens[token_name] = match.group(1)

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
    """Detect if response contains a CAPTCHA challenge"""
    captcha_patterns = [
        r"captcha",
        r"recaptcha",
        r"security check",
        r"checkpoint",
        r"suspicious activity",
        r"confirm your identity",
    ]

    for pattern in captcha_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    return False


def handle_between_attempts(attempt, max_attempts):
    """Handle logic between registration attempts"""
    if attempt < max_attempts - 1:
        info(f"[*] Waiting before next attempt...")
        min_time, max_time = DELAY_BETWEEN_ATTEMPTS
        wait_with_jitter(min_time, max_time)
        return True
    return False


def extract_user_id(response, session):
    """Extract user ID from response or cookies"""
    user_id = "Unknown"

    # Check cookies first
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
    ]

    for pattern in id_patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    # If all else fails, generate a placeholder ID
    if user_id == "Unknown":
        from utils.generators import generate_random_string

        user_id = f"FB{generate_random_string(10)}"

    return user_id
