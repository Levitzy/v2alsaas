# Security and anti-detection measures

import re
import random
import time
import json
import hashlib
from urllib.parse import urlparse

from utils.colors import error, info
from utils.helpers import extract_security_tokens, detect_captcha, wait_with_jitter
from config import get_random_browser_properties


def apply_anti_detection_measures(session, url, user_details):
    """Apply various anti-detection measures to the session"""

    # Get random browser properties for fingerprinting
    browser_props = get_random_browser_properties()

    # Parse URL to get domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Set consistent browser fingerprinting headers
    session.headers.update(
        {
            "Accept-Language": browser_props["language"],
            "Accept": browser_props["accept"],
            "Sec-Ch-Ua": '"Chromium";v="121", "Not A(Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{browser_props["platform"]}"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1",  # Do Not Track
        }
    )

    # Add required cookies for more human-like behavior
    session.cookies.set("locale", "en_US", domain=domain)

    # Generate consistent device ID based on user details
    device_id = user_details.get("device_id", "")
    device_hash = hashlib.md5(f"{device_id}{domain}".encode()).hexdigest()

    # Add some common cookies found in real browsers
    session.cookies.set("dpr", str(browser_props["pixel_ratio"]), domain=domain)
    session.cookies.set(
        "wd", browser_props["screen_resolution"].split("x")[0], domain=domain
    )

    # Add anti-bot detection evasion
    session.headers.update(
        {
            "User-Agent": session.headers.get("User-Agent", ""),
            "Referer": url,
        }
    )

    return session


def add_security_tokens(form_data, html_content):
    """Add security tokens to form data"""
    # Extract security tokens from the HTML
    tokens = extract_security_tokens(html_content)

    # Add tokens to form data if they exist
    for token_name, token_value in tokens.items():
        if token_value:
            form_data[token_name] = token_value

    # If we didn't get any tokens, use fallback method
    if not tokens:
        # Try alternative extraction methods
        try:
            # Look for JavaScript objects containing tokens
            js_tokens = re.findall(
                r'{\s*"token"\s*:\s*"([^"]+)"\s*,\s*"type"\s*:\s*"([^"]+)"\s*}',
                html_content,
            )
            for token, token_type in js_tokens:
                form_data[token_type] = token

            # Look for DTSGs
            dtsg_match = re.search(
                r'"DTSGInitialData"\s*,\s*\[\]\s*,\s*{\s*"token"\s*:\s*"([^"]+)"',
                html_content,
            )
            if dtsg_match:
                form_data["fb_dtsg"] = dtsg_match.group(1)

        except Exception as e:
            error(f"[!] Error extracting alternative tokens: {e}")

    # Add random request ID
    form_data["__req"] = "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6)
    )

    # Add timestamp
    form_data["__a"] = "1"
    form_data["__user"] = "0"  # For non-logged-in users

    return form_data


def handle_security_challenges(session, response):
    """Handle security challenges like CAPTCHA or checkpoint"""
    html_content = response.text

    # Check if we've hit a CAPTCHA or security checkpoint
    if detect_captcha(html_content):
        error("[!] CAPTCHA or security checkpoint detected")

        # Look for checkpoint type
        checkpoint_type = "unknown"
        if "captcha" in html_content.lower():
            checkpoint_type = "captcha"
        elif "suspicious" in html_content.lower():
            checkpoint_type = "suspicious_activity"
        elif "identity" in html_content.lower():
            checkpoint_type = "identity_confirmation"

        info(f"[*] Checkpoint type: {checkpoint_type}")

        # For now, we can't automatically solve CAPTCHAs
        # In a real implementation, you might use a CAPTCHA solving service
        return False, checkpoint_type

    # Check for other error conditions
    if "error" in response.url.lower() or "sorry" in response.url.lower():
        error("[!] Redirected to error page")
        return False, "error_page"

    # Success - no security challenges detected
    return True, None


def generate_fp_data(user_details):
    """Generate fingerprinting data to avoid detection"""
    # Create a deterministic but unique fingerprint for this user
    user_fp_seed = user_details["user_agent_hash"]

    # Generate hardware info
    cores = random.choice([2, 4, 6, 8, 12, 16])
    ram = random.choice([4, 8, 16, 32, 64])

    # Generate screen info based on typical resolutions
    resolution = random.choice(
        [
            [1366, 768],
            [1920, 1080],
            [1440, 900],
            [1536, 864],
            [1280, 720],
            [1600, 900],
            [2560, 1440],
            [3840, 2160],
        ]
    )

    # Device pixel ratio
    dpr = random.choice([1, 1.25, 1.5, 2, 2.5, 3])

    # Create fingerprint data
    fp_data = {
        "webgl_hashes": hashlib.md5(f"{user_fp_seed}webgl".encode()).hexdigest(),
        "canvas_hash": hashlib.md5(f"{user_fp_seed}canvas".encode()).hexdigest(),
        "audio_hash": hashlib.md5(f"{user_fp_seed}audio".encode()).hexdigest(),
        "user_agent_data": {
            "brands": [
                {"brand": "Chromium", "version": "121"},
                {"brand": "Not A(Brand", "version": "99"},
            ],
            "mobile": False,
            "platform": "Windows",
        },
        "device": {
            "cores": cores,
            "ram": ram,
            "resolution": resolution,
            "dpr": dpr,
            "touch_points": 0,
            "hardware_concurrency": cores,
            "device_memory": ram,
        },
        "timing": {
            "navigation_start": int(time.time() * 1000),
            "load_event_end": int(time.time() * 1000) + random.randint(500, 2000),
        },
    }

    return json.dumps(fp_data)


def simulate_realistic_form_filling(session, form_url, form_data, user_details):
    """Simulate realistic human form filling with proper timing"""
    # First, request the form page and let it load
    response = session.get(form_url, timeout=30)
    if response.status_code != 200:
        error(f"[!] Failed to load form page: {response.status_code}")
        return None

    # Wait like a human would after page load
    wait_with_jitter(1, 3)

    # Simulate typing each field with realistic timing
    fields_to_simulate = ["firstname", "lastname", "reg_email__", "reg_passwd__"]

    for field in fields_to_simulate:
        if field in form_data:
            # Add a "prefilled" marker to show the browser has this field filled
            session.cookies.set(
                f"filled_{field}", "1", domain=urlparse(form_url).netloc
            )
            # Wait between field fills
            wait_with_jitter(0.5, 1.5)

    # Final pause before submission
    wait_with_jitter(1, 2)

    # Add fingerprinting data
    fp_data = generate_fp_data(user_details)
    form_data["__browser_fps"] = fp_data

    return form_data
