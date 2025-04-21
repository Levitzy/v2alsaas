# facebook/security.py - Updated with improved evasion techniques

import re
import random
import time
import json
import hashlib
import base64
import os
from urllib.parse import urlparse
from datetime import datetime

from utils.colors import error, info
from utils.helpers import extract_security_tokens, detect_captcha, wait_with_jitter
from utils.generators import generate_random_string
from config import get_random_browser_properties


def apply_anti_detection_measures(session, url, user_details):
    """Apply enhanced anti-detection measures to the session"""

    # Get random browser properties for fingerprinting
    browser_props = get_random_browser_properties()

    # Parse URL to get domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Set consistent browser fingerprinting headers with more realistic values
    session.headers.update(
        {
            "Accept-Language": browser_props["language"],
            "Accept": browser_props["accept"],
            "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{browser_props["platform"]}"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1",  # Do Not Track
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    # Add common cookies that would normally exist in a browser session
    # This is critical for appearing more like a real browser
    session.cookies.set("locale", "en_US", domain=domain)
    session.cookies.set(
        "wd", browser_props["screen_resolution"].split("x")[0], domain=domain
    )
    session.cookies.set("dpr", str(browser_props["pixel_ratio"]), domain=domain)

    # Add Facebook-specific cookies that help appear as a returning visitor
    # These are similar to what real browsers would have from previous Facebook visits
    cookie_token = base64.b64encode(os.urandom(16)).decode("utf-8").replace("=", "")
    session.cookies.set("datr", cookie_token, domain=domain)
    session.cookies.set("sb", generate_random_string(24), domain=domain)

    # Add a semi-unique browser identifier
    browser_id = hashlib.md5(f"{user_details['user_agent_hash']}".encode()).hexdigest()[
        :16
    ]
    session.cookies.set("_fbp", f"fb.1.{int(time.time())}.{browser_id}", domain=domain)

    return session


def add_security_tokens(form_data, html_content):
    """Add improved security tokens to form data"""
    # Extract security tokens from the HTML
    tokens = extract_security_tokens(html_content)

    # Add tokens to form data if they exist
    for token_name, token_value in tokens.items():
        if token_value:
            form_data[token_name] = token_value

    # If we didn't get any tokens, use fallback method with deeper extraction
    if not tokens:
        # Try multiple alternative extraction methods
        try:
            # Look for JavaScript objects containing tokens
            js_tokens = re.findall(
                r'{\s*"token"\s*:\s*"([^"]+)"\s*,\s*"type"\s*:\s*"([^"]+)"\s*}',
                html_content,
            )
            for token, token_type in js_tokens:
                form_data[token_type] = token

            # Look for DTSGs (deeper patterns)
            dtsg_patterns = [
                r'"DTSGInitialData"\s*,\s*\[\]\s*,\s*{\s*"token"\s*:\s*"([^"]+)"',
                r'"fb_dtsg"\s*value="([^"]+)"',
                r'name="fb_dtsg"\s*value="([^"]+)"',
                r'"name":"fb_dtsg","value":"([^"]+)"',
            ]

            for pattern in dtsg_patterns:
                dtsg_match = re.search(pattern, html_content)
                if dtsg_match:
                    form_data["fb_dtsg"] = dtsg_match.group(1)
                    break

            # Look for jazoest (important for form validation)
            jazoest_match = re.search(r'name="jazoest"\s*value="([^"]+)"', html_content)
            if jazoest_match:
                form_data["jazoest"] = jazoest_match.group(1)

        except Exception as e:
            error(f"[!] Error extracting alternative tokens: {e}")

    # Add more realistic request metadata
    timestamp = str(int(time.time()))
    form_data["__req"] = "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6)
    )
    form_data["__a"] = "1"
    form_data["__user"] = "0"  # For non-logged-in users
    form_data["__rev"] = str(random.randint(1000000, 9999999))
    form_data["__s"] = "".join(
        random.choices("abcdefghijklmnopqrstuvwxyz0123456789:_", k=8)
    )
    form_data["__hsi"] = timestamp
    form_data["__comet_req"] = "0"
    form_data["__spin_r"] = timestamp
    form_data["__spin_t"] = timestamp

    return form_data


def handle_security_challenges(session, response):
    """Enhanced handling of security challenges like CAPTCHA or checkpoint"""
    html_content = response.text

    # Check if we've hit a CAPTCHA or security checkpoint with more precise detection
    captcha_detection = detect_captcha(html_content)
    if captcha_detection:
        error("[!] CAPTCHA or security checkpoint detected")

        # Look for checkpoint type with more specific detection
        checkpoint_type = "unknown"

        if re.search(
            r"(captcha|security\s+check|checkpoint)", html_content, re.IGNORECASE
        ):
            if "captcha" in html_content.lower():
                checkpoint_type = "captcha"
            elif (
                "suspicious" in html_content.lower()
                or "unusual" in html_content.lower()
            ):
                checkpoint_type = "suspicious_activity"
            elif (
                "identity" in html_content.lower() or "confirm" in html_content.lower()
            ):
                checkpoint_type = "identity_confirmation"
            elif "checkpoint" in html_content.lower():
                checkpoint_type = "general_checkpoint"

        info(f"[*] Checkpoint type: {checkpoint_type}")
        return False, checkpoint_type

    # Check for other error conditions with more precision
    if any(
        term in response.url.lower()
        for term in ["error", "sorry", "not_available", "blocked"]
    ):
        error("[!] Redirected to error page")
        return False, "error_page"

    # Success - no security challenges detected
    return True, None


def generate_fp_data(user_details):
    """Generate more realistic fingerprinting data to avoid detection"""
    # Create a deterministic but unique fingerprint for this user
    user_fp_seed = user_details["user_agent_hash"]

    # Get browser properties
    browser_props = get_random_browser_properties()

    # Generate hardware info with more realistic ranges
    cores = random.choice([2, 4, 6, 8, 12, 16])
    ram = random.choice([4, 8, 16, 32])

    # Generate screen info based on common resolutions
    resolution = random.choice(
        [
            [1366, 768],
            [1920, 1080],
            [1440, 900],
            [1536, 864],
            [1280, 720],
            [2560, 1440],
        ]
    )

    # Device pixel ratio based on device type
    if "iPhone" in user_details.get("user_agent", ""):
        dpr = random.choice([2, 3])
    elif "Android" in user_details.get("user_agent", ""):
        dpr = random.choice([1.5, 2, 2.5, 3])
    else:
        dpr = random.choice([1, 1.25, 1.5, 2])

    # More realistic timing values
    time_now = int(time.time() * 1000)
    navigation_time = time_now - random.randint(100, 500)
    dom_complete = navigation_time + random.randint(300, 800)
    load_event = dom_complete + random.randint(50, 200)

    # Create fingerprint data with more browser-like structure
    fp_data = {
        "webgl_hashes": {
            "vendor": hashlib.md5(f"{user_fp_seed}webgl_vendor".encode()).hexdigest(),
            "renderer": hashlib.md5(
                f"{user_fp_seed}webgl_renderer".encode()
            ).hexdigest(),
        },
        "canvas_hash": hashlib.md5(f"{user_fp_seed}canvas".encode()).hexdigest(),
        "audio_hash": hashlib.md5(f"{user_fp_seed}audio".encode()).hexdigest(),
        "user_agent_data": {
            "brands": [
                {"brand": "Chromium", "version": "122"},
                {"brand": "Google Chrome", "version": "122"},
                {"brand": "Not A(Brand", "version": "99"},
            ],
            "mobile": False,
            "platform": browser_props["platform"],
        },
        "device": {
            "cores": cores,
            "ram": ram,
            "resolution": resolution,
            "dpr": dpr,
            "touch_points": (
                0
                if "Windows" in browser_props["platform"]
                or "Macintosh" in browser_props["platform"]
                else 5
            ),
            "hardware_concurrency": cores,
            "device_memory": ram,
        },
        "timing": {
            "navigation_start": navigation_time,
            "fetch_start": navigation_time + random.randint(1, 10),
            "dom_interactive": navigation_time + random.randint(100, 300),
            "dom_complete": dom_complete,
            "load_event_end": load_event,
        },
        "language": browser_props["language"].split(",")[0],
        "timezone": -1
        * (
            datetime.now().utcoffset().total_seconds() / 60
            if datetime.now().utcoffset()
            else 0
        ),
        "has_touch": "Windows" not in browser_props["platform"]
        and "Macintosh" not in browser_props["platform"],
        "notification_permission": random.choice(["default", "denied"]),
    }

    return json.dumps(fp_data)


def simulate_realistic_form_filling(session, form_url, form_data, user_details):
    """Simulate more human-like form filling with improved timing and behavior"""
    try:
        # First, request the form page and let it load
        response = session.get(form_url, timeout=30)
        if response.status_code != 200:
            error(f"[!] Failed to load form page: {response.status_code}")
            return None

        # Wait like a human would after page load (more variable timing)
        wait_with_jitter(1.5, 4)

        # Simulate typing each field with realistic timing
        fields_to_simulate = [
            "firstname",
            "lastname",
            "reg_email__",
            "reg_email_confirmation__",
            "reg_passwd__",
        ]

        # Track the timing of simulated field interactions for fingerprinting
        field_timings = {}
        start_time = time.time() * 1000  # milliseconds

        for field in fields_to_simulate:
            if field in form_data:
                # Simulate field focus
                field_timings[f"{field}_focus"] = int(time.time() * 1000 - start_time)

                # Simulate typing delay based on field length
                typing_time = len(str(form_data[field])) * random.uniform(
                    80, 120
                )  # ms per character
                wait_with_jitter(typing_time / 1000, (typing_time + 300) / 1000)

                # Add a "prefilled" marker to show the browser has this field filled
                session.cookies.set(
                    f"filled_{field}", "1", domain=urlparse(form_url).netloc
                )

                # Record blur time
                field_timings[f"{field}_blur"] = int(time.time() * 1000 - start_time)

                # Add small delay between fields
                wait_with_jitter(0.3, 1.2)

        # Simulate selecting birthday fields if present
        birthday_fields = ["birthday_day", "birthday_month", "birthday_year"]
        for field in birthday_fields:
            if field in form_data:
                field_timings[f"{field}_change"] = int(time.time() * 1000 - start_time)
                wait_with_jitter(0.2, 0.8)

        # Simulate gender selection if present
        if "sex" in form_data:
            field_timings["sex_click"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.3, 1)

        # Final pause before submission (someone reading terms/reviewing form)
        wait_with_jitter(1.5, 3.5)

        # Add fingerprinting data enhanced with timing information
        user_details["field_timings"] = field_timings
        fp_data = generate_fp_data(user_details)
        form_data["__browser_fps"] = fp_data
        form_data["__user_interaction_timing"] = json.dumps(field_timings)

        return form_data

    except Exception as e:
        error(f"[!] Error in form filling simulation: {e}")
        return form_data
