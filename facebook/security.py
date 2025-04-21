# facebook/security.py - Updated with improved bypassing techniques

import re
import random
import time
import json
import hashlib
import base64
import os
from urllib.parse import urlparse
from datetime import datetime

from utils.colors import error, info, success
from utils.helpers import extract_security_tokens, wait_with_jitter
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
            "Sec-Ch-Ua-Mobile": (
                "?0" if "Mobile" not in browser_props["user_agent"] else "?1"
            ),
            "Sec-Ch-Ua-Platform": f'"{browser_props["platform"]}"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1" if random.random() < 0.7 else None,  # 70% chance to set DNT
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    # Add common cookies that would normally exist in a browser session
    session.cookies.set("locale", "en_US", domain=domain)
    session.cookies.set(
        "wd", browser_props["screen_resolution"].split("x")[0], domain=domain
    )
    session.cookies.set("dpr", str(browser_props["pixel_ratio"]), domain=domain)

    # Add Facebook-specific browser fingerprinting
    cookie_token = base64.b64encode(os.urandom(16)).decode("utf-8").replace("=", "")
    session.cookies.set("datr", cookie_token, domain=domain)
    session.cookies.set("fr", generate_random_string(24), domain=domain)

    # Modern Facebook uses these cookies for non-logged in visitors
    session.cookies.set("_js_datr", cookie_token, domain=domain)
    session.cookies.set("sb", generate_random_string(24), domain=domain)

    # Add browser timezone and locale info
    ts_ms = int(time.time() * 1000)
    session.cookies.set("tz", str(random.randint(-720, 720)), domain=domain)
    session.cookies.set(
        "_js_reg_fb_ref",
        f"https://www.facebook.com/?stype=lo&jlou=AfeDKoQcSW1-z-s2lqUz4jYa2D-IHh2Seyh_LYb9mRGNpbJUz64uVLMK{ts_ms}",
        domain=domain,
    )

    # Add essential cookies that real browsers would have
    session.cookies.set(
        "m_pixel_ratio", str(browser_props["pixel_ratio"]), domain=domain
    )
    session.cookies.set(
        "wd", str(browser_props["screen_resolution"].split("x")[0]), domain=domain
    )

    # Add more random device/browser fingerprinting values
    session.cookies.set("usida", generate_random_string(16), domain=domain)
    session.cookies.set("cppo", str(random.randint(1, 5)), domain=domain)

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
    if not tokens or len(tokens) < 2:  # Need at least fbdtsg and jazoest
        # Try multiple alternative extraction methods
        try:
            # Look for JavaScript objects containing tokens
            js_tokens = re.findall(
                r'{\s*"token"\s*:\s*"([^"]+)"\s*,\s*"type"\s*:\s*"([^"]+)"\s*}',
                html_content,
            )
            for token, token_type in js_tokens:
                form_data[token_type] = token

            # Common tokens needed for Facebook
            if "fb_dtsg" not in form_data:
                dtsg_patterns = [
                    r'"DTSGInitialData"\s*,\s*\[\]\s*,\s*{\s*"token"\s*:\s*"([^"]+)"',
                    r'"fb_dtsg"\s*value="([^"]+)"',
                    r'name="fb_dtsg"\s*value="([^"]+)"',
                    r'"name":"fb_dtsg","value":"([^"]+)"',
                    r'{\s*"name":"fb_dtsg",\s*"value":"([^"]+)"',
                    r'"token":"([^"]+)","type":"fb_dtsg"',
                    r'require\("DTSGInitData"\)\[\],\[\],{"token":"([^"]+)"',
                    r'name=\\"fb_dtsg\\" value=\\"([^\\]+)\\"',
                ]

                for pattern in dtsg_patterns:
                    dtsg_match = re.search(pattern, html_content)
                    if dtsg_match:
                        form_data["fb_dtsg"] = dtsg_match.group(1)
                        break

                # If still not found, use a default value as last resort
                if "fb_dtsg" not in form_data:
                    from utils.generators import generate_random_string

                    default_dtsg = generate_random_string(24)
                    form_data["fb_dtsg"] = default_dtsg
                    info(f"[*] Using fallback fb_dtsg token: {default_dtsg[:5]}...")

            # Jazoest token (critical for form validation)
            if "jazoest" not in form_data:
                jazoest_patterns = [
                    r'name="jazoest"\s*value="([^"]+)"',
                    r'"jazoest":"([^"]+)"',
                    r'{\s*"name":"jazoest",\s*"value":"([^"]+)"',
                    r'"token":"([^"]+)","type":"jazoest"',
                    r'name=\\"jazoest\\" value=\\"([^\\]+)\\"',
                ]

                for pattern in jazoest_patterns:
                    jazoest_match = re.search(pattern, html_content)
                    if jazoest_match:
                        form_data["jazoest"] = jazoest_match.group(1)
                        break

                # If jazoest not found, generate one (it's typically a number)
                if "jazoest" not in form_data:
                    # Facebook typically uses numeric values for jazoest
                    default_jazoest = "".join(random.choices("2578", k=8))
                    form_data["jazoest"] = default_jazoest
                    info(f"[*] Using fallback jazoest token: {default_jazoest}")

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

    # Modern Facebook expects these values
    form_data["__ccg"] = "EXCELLENT"
    form_data["__jssesw"] = "1"

    # Add form tracking
    form_data["lsd"] = form_data.get("fb_dtsg", "")[:8]

    return form_data


def handle_security_challenges(session, response):
    """Attempt to bypass security challenges instead of just detecting them"""
    html_content = response.text
    url = response.url

    # If this is just the standard identity confirmation page but not a real security check
    standard_identity_phrases = [
        "confirm your identity",
        "confirm your information",
        "provide your information",
        "verify your information",
    ]

    # Check if this is just a standard registration page with identity confirmation messaging
    # but not actually a security block
    if any(phrase in html_content.lower() for phrase in standard_identity_phrases):
        # Check if the page still has registration form elements
        form_elements = [
            'name="firstname"',
            'name="lastname"',
            'name="reg_email__"',
            'name="birthday_day"',
            "<select",
            'name="sex"',
            'type="submit"',
        ]

        if any(element in html_content for element in form_elements):
            # This appears to be a normal registration page with identity confirmation text
            # but not an actual challenge block - we can proceed
            info(
                "[*] Page contains identity confirmation language but still has registration form"
            )
            return True, None

    # Check for serious blocks that we can't bypass
    serious_blocks = [
        "suspicious activity detected",
        "account disabled",
        "try again later",
        "something went wrong",
        "we couldn't process",
        "temporarily blocked",
    ]

    if any(block in html_content.lower() for block in serious_blocks):
        block_type = next(
            (block for block in serious_blocks if block in html_content.lower()),
            "unknown_block",
        )
        info(f"[*] Serious security block detected: {block_type}")
        return False, "security_block"

    # Check for checkpoint URLs that definitely indicate a challenge
    checkpoint_indicators = [
        "checkpoint",
        "/checkpoint/",
        "?next=checkpoint",
        "login/checkpoint",
    ]
    if any(indicator in url for indicator in checkpoint_indicators):
        info(f"[*] Security checkpoint detected in URL: {url}")
        return False, "checkpoint"

    # Check if we're on a security verification page that we can't bypass
    security_indicators = [
        "verification code",
        "confirm your identity",
        "suspicious activity",
        "unusual login",
    ]

    if any(
        indicator.lower() in html_content.lower() for indicator in security_indicators
    ):
        # Check if we can extract a form to submit on this verification page
        form_in_challenge = re.search(r'<form[^>]*action="([^"]+)"', html_content)

        if form_in_challenge:
            info("[*] Found form in security challenge - might be able to proceed")
            # This is where you'd implement logic to fill out and submit the challenge form
            # For now, we'll still return False since we don't have the implementation yet
            return False, "security_verification"
        else:
            info("[*] Security verification required without submittable form")
            return False, "security_verification"

    # Default: assume no security challenges detected
    return True, None


def generate_fp_data(user_details):
    """Generate more realistic fingerprinting data to avoid detection"""
    # Create a deterministic but unique fingerprint for this user
    user_fp_seed = user_details.get("user_agent_hash", str(random.random()))

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

    # Create fingerprint data with more browser-like structure including modern properties
    fp_data = {
        "webgl_hashes": {
            "vendor": hashlib.md5(f"{user_fp_seed}webgl_vendor".encode()).hexdigest(),
            "renderer": hashlib.md5(
                f"{user_fp_seed}webgl_renderer".encode()
            ).hexdigest(),
        },
        "canvas_hash": hashlib.md5(f"{user_fp_seed}canvas".encode()).hexdigest(),
        "audio_hash": hashlib.md5(f"{user_fp_seed}audio".encode()).hexdigest(),
        "navigator": {
            "userAgent": browser_props.get("user_agent", ""),
            "language": browser_props["language"].split(",")[0],
            "languages": browser_props["language"].split(","),
            "platform": browser_props["platform"],
            "doNotTrack": "1" if random.random() < 0.3 else "unspecified",
            "hardwareConcurrency": cores,
            "deviceMemory": ram,
            "maxTouchPoints": (
                0
                if "Windows" in browser_props["platform"]
                or "Macintosh" in browser_props["platform"]
                else 5
            ),
        },
        "screen": {
            "width": resolution[0],
            "height": resolution[1],
            "colorDepth": random.choice([24, 30, 32]),
            "availWidth": resolution[0] - random.randint(0, 20),
            "availHeight": resolution[1] - random.randint(40, 80),
            "pixelDepth": random.choice([24, 30, 32]),
        },
        "timezone": {
            "offset": random.randint(-720, 720),  # Minutes from UTC
            "timezone": random.choice(
                ["America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney"]
            ),
        },
        "battery": {
            "charging": random.choice([True, False]),
            "level": round(random.uniform(0.1, 1.0), 2),
        },
        "plugins": random.randint(3, 8),
        "fonts": random.randint(35, 60),
        "timing": {
            "navigation_start": navigation_time,
            "fetch_start": navigation_time + random.randint(1, 10),
            "dom_interactive": navigation_time + random.randint(100, 300),
            "dom_complete": dom_complete,
            "load_event_end": load_event,
        },
        "os": {
            "name": (
                "Windows"
                if "Windows" in browser_props["platform"]
                else (
                    "macOS"
                    if "Macintosh" in browser_props["platform"]
                    else (
                        "Linux"
                        if "Linux" in browser_props["platform"]
                        else (
                            "Android"
                            if "Android" in browser_props["platform"]
                            else "iOS"
                        )
                    )
                )
            ),
            "version": (
                random.choice(["10", "11"])
                if "Windows" in browser_props["platform"]
                else (
                    random.choice(["10.15", "11.0", "12.0"])
                    if "Macintosh" in browser_props["platform"]
                    else (
                        random.choice(["11", "12", "13"])
                        if "Android" in browser_props["platform"]
                        else (
                            random.choice(["15.0", "16.0", "17.0"])
                            if "iPhone" in browser_props["platform"]
                            else "unknown"
                        )
                    )
                )
            ),
        },
        "connection": {
            "type": random.choice(["wifi", "4g", "3g", "unknown"]),
            "rtt": random.randint(5, 300),
            "downlink": round(random.uniform(1, 15), 1),
        },
        "viewport": {
            "width": resolution[0] - random.randint(20, 160),
            "height": resolution[1] - random.randint(60, 200),
        },
        "has_touch": "Windows" not in browser_props["platform"]
        and "Macintosh" not in browser_props["platform"],
        "notification_permission": random.choice(["default", "denied"]),
    }

    return json.dumps(fp_data)


def simulate_realistic_form_filling(session, form_url, form_data, user_details):
    """Simulate more human-like form filling with improved timing and behavior"""
    try:
        # First, request the form page and let it load
        info("[*] Simulating realistic form filling behavior...")

        # Wait like a human would after page load (more variable timing)
        wait_with_jitter(1.5, 3.5)

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
                    70, 110
                )  # ms per character (humans type at different speeds)
                wait_with_jitter(typing_time / 1000, (typing_time + 300) / 1000)

                # Add a "prefilled" marker to show the browser has this field filled
                session.cookies.set(
                    f"filled_{field}", "1", domain=urlparse(form_url).netloc
                )

                # Record blur time
                field_timings[f"{field}_blur"] = int(time.time() * 1000 - start_time)

                # Add small delay between fields (humans pause between fields)
                wait_with_jitter(0.3, 1.0)

        # Simulate selecting birthday fields if present
        birthday_fields = ["birthday_day", "birthday_month", "birthday_year"]
        for field in birthday_fields:
            if field in form_data:
                field_timings[f"{field}_change"] = int(time.time() * 1000 - start_time)
                wait_with_jitter(0.2, 0.7)

        # Simulate gender selection if present
        if "sex" in form_data:
            field_timings["sex_click"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.3, 0.9)

        # Simulate checking terms boxes
        if "terms" in form_data:
            field_timings["terms_click"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.2, 0.6)

        if "datause" in form_data:
            field_timings["datause_click"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.2, 0.5)

        # Final pause before submission (someone reading terms/reviewing form)
        wait_with_jitter(1.5, 3.0)

        # Add fingerprinting data enhanced with timing information
        user_details["field_timings"] = field_timings
        fp_data = generate_fp_data(user_details)
        form_data["__browser_fps"] = fp_data
        form_data["__user_interaction_timing"] = json.dumps(field_timings)

        # Add Facebook-specific form data fields expected in modern registration
        form_data["reg_instance"] = generate_random_string(16)
        form_data["platform_xmd"] = ""
        form_data["had_cp_prefilled"] = "false"
        form_data["had_password_prefilled"] = "false"
        form_data["is_voice_clip_supported"] = "true"
        form_data["is_smart_lock_supported"] = "true"
        form_data["bi_xrwh"] = "0"

        # Add terms acceptance
        form_data["terms"] = "on"
        form_data["datause"] = "on"
        form_data["acknowledge_understanding"] = "on"

        # Ensure critical modern Facebook fields are present
        current_time = int(time.time())
        if "encpass" not in form_data and "reg_passwd__" in form_data:
            form_data["encpass"] = (
                f"#PWD_BROWSER:0:{current_time}:{form_data['reg_passwd__']}"
            )

        if "reg_email_confirmation__" not in form_data and "reg_email__" in form_data:
            form_data["reg_email_confirmation__"] = form_data["reg_email__"]

        # Add standard form submission fields
        form_data["websubmit"] = "Sign Up"

        return form_data

    except Exception as e:
        error(f"[!] Error in form filling simulation: {e}")
        return form_data
