# facebook/security.py - Modernized security bypass for 2025 Facebook updates

import re
import random
import time
import json
import hashlib
import base64
import os
import uuid
from urllib.parse import urlparse
from datetime import datetime

from utils.colors import error, info, success
from utils.helpers import extract_security_tokens, wait_with_jitter
from utils.generators import generate_random_string
from config import get_random_browser_properties


def apply_anti_detection_measures(session, url, user_details):
    """Apply enhanced anti-detection measures to the session - Updated for 2025 Facebook security"""

    # Get random browser properties for fingerprinting
    browser_props = get_random_browser_properties()

    # Parse URL to get domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # More sophisticated Sec-Ch-Ua header format (2025 version)
    is_mobile = "Mobile" in browser_props["user_agent"]
    browser_type = "Chrome"
    if "Firefox" in browser_props["user_agent"]:
        browser_type = "Firefox"
    elif (
        "Safari" in browser_props["user_agent"]
        and "Chrome" not in browser_props["user_agent"]
    ):
        browser_type = "Safari"
    elif "Edg" in browser_props["user_agent"]:
        browser_type = "Edge"

    # Generate version numbers that make sense for 2025
    chrome_version = f"{random.randint(123, 130)}.0.{random.randint(6300, 6800)}.{random.randint(100, 200)}"
    brand_version = f"{random.randint(24, 30)}"

    sec_ch_ua = f'"Chromium";v="{chrome_version.split(".")[0]}", "Not(A:Brand";v="{brand_version}", "Google Chrome";v="{chrome_version.split(".")[0]}"'

    if browser_type == "Firefox":
        sec_ch_ua = f'"Firefox";v="{random.randint(120, 127)}"'
    elif browser_type == "Safari":
        sec_ch_ua = f'"Safari";v="{random.randint(17, 20)}"'
    elif browser_type == "Edge":
        sec_ch_ua = f'"Chromium";v="{chrome_version.split(".")[0]}", "Microsoft Edge";v="{random.randint(123, 130)}"'

    # Set up modern headers that match 2025 browser standards
    session.headers.update(
        {
            "Accept-Language": browser_props["language"],
            "Accept": browser_props["accept"],
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?1" if is_mobile else "?0",
            "Sec-Ch-Ua-Platform": f'"{browser_props["platform"]}"',
            "Sec-Ch-Ua-Platform-Version": f'"{random.randint(10, 15)}.{random.randint(0, 9)}"',
            "Sec-Ch-Ua-Full-Version-List": sec_ch_ua,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "high",
            "Viewport-Width": browser_props["screen_resolution"].split("x")[0],
            "Width": browser_props["screen_resolution"].split("x")[0],
            "Device-Memory": f"{random.choice([4, 8, 16])}",
            "Downlink": f"{random.randint(5, 25)}",
            "Rtt": f"{random.randint(50, 200)}",
            "Ect": random.choice(["4g", "3g"]),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    # Add modern Facebook-specific headers seen in 2025
    session.headers.update(
        {
            "X-FB-LSD": generate_random_string(22),
            "X-ASBD-ID": f"{random.randint(100000, 999999)}",
            "X-FB-Friendly-Name": "RegistrationControllerX",
        }
    )

    # Add essential modern cookies that Facebook expects in 2025
    # These have been updated based on Facebook's latest tracking patterns
    session.cookies.set("locale", "en_US", domain=domain)
    session.cookies.set(
        "wd", browser_props["screen_resolution"].split("x")[0], domain=domain
    )
    session.cookies.set("dpr", str(browser_props["pixel_ratio"]), domain=domain)

    # Generate consistent device ID using modern format
    device_id = str(uuid.uuid4()).replace("-", "")
    user_details["device_id"] = device_id

    # Add Facebook's 2025 fingerprinting and tracking cookies
    fb_cookie_token = base64.b64encode(os.urandom(20)).decode("utf-8").replace("=", "")

    # These are the key cookies Facebook uses for tracking new visitors in 2025
    session.cookies.set("datr", fb_cookie_token[:20], domain=domain)
    session.cookies.set("sb", generate_random_string(24), domain=domain)
    session.cookies.set("_js_datr", fb_cookie_token[:20], domain=domain)
    session.cookies.set(
        "_fbp",
        f"fb.1.{int(time.time())}.{random.randint(1000000, 9999999)}",
        domain=domain,
    )

    # Critical cookies added in Facebook's 2025 security updates
    session.cookies.set("fbl_st", "1", domain=domain)
    session.cookies.set("fbl_ci", device_id[:16], domain=domain)
    session.cookies.set("vpd", "v1", domain=domain)
    session.cookies.set("wl_cbv", f"v2%3Btimestamp%3D{int(time.time())}", domain=domain)

    # Timezone and locale cookies (updated format)
    ts_ms = int(time.time() * 1000)
    session.cookies.set("tz", str(random.randint(-720, 720)), domain=domain)
    session.cookies.set(
        "_js_reg_fb_ref",
        f"https://www.facebook.com/?stype=lo&jlou=AfeDKoQcSW1-z-s2lqUz4jYa2D-IHh2Seyh_LYb9mRGNpbJUz64uVLMK{ts_ms}",
        domain=domain,
    )

    # Device and connection cookies for 2025
    session.cookies.set(
        "m_pixel_ratio", str(browser_props["pixel_ratio"]), domain=domain
    )
    session.cookies.set("usida", generate_random_string(22), domain=domain)
    session.cookies.set("cppo", str(random.randint(1, 5)), domain=domain)

    # New cookies added in 2025 for fraud detection
    session.cookies.set("fbl_cs", "1", domain=domain)
    session.cookies.set("fbl_st", generate_random_string(8), domain=domain)
    session.cookies.set("dbln", generate_random_string(12), domain=domain)

    return session


def add_security_tokens(form_data, html_content):
    """Add improved security tokens to form data - Updated for 2025 security patterns"""
    # Extract security tokens from the HTML
    tokens = extract_security_tokens(html_content)

    # Add tokens to form data if they exist
    for token_name, token_value in tokens.items():
        if token_value:
            form_data[token_name] = token_value

    # If we didn't get critical tokens, use enhanced extraction
    if not tokens or "fb_dtsg" not in tokens or "jazoest" not in tokens:
        # Use advanced token extraction methods
        try:
            # Search for modern Facebook's client-side rendered token structure (2025 format)
            modern_token_patterns = [
                # New Facebook uses data structures in JavaScript that look like this
                r'{"token":"([^"]+)","type":"([^"]+)"}',
                r'require\("ServerJS"\)\.handle\({"instances":\[\],"markup":\[\],"elements":\[\],"require":\[\["([^"]+)",\s*"([^"]+)"\]\]',
                r'DTSGInitialData\["\],\[\],{"token":"([^"]+)"',
                r'DTSGInitData".*?"token":"([^"]+)"',
                r'async_get_token":"([^"]+)"',
                r"__eqmc:({.*?})",  # Capture the entire security object
                r"EAAG[a-zA-Z0-9]{20,}",  # Access token pattern
            ]

            for pattern in modern_token_patterns:
                matches = re.findall(pattern, html_content)
                if matches:
                    # Process based on match pattern
                    if pattern == r'{"token":"([^"]+)","type":"([^"]+)"}':
                        for token, token_type in matches:
                            form_data[token_type] = token
                    elif pattern == r"__eqmc:({.*?})":
                        for match in matches:
                            try:
                                # Try to parse as JSON
                                security_obj = json.loads(match.replace("'", '"'))
                                if isinstance(security_obj, dict):
                                    # Extract tokens from the security object
                                    for key, value in security_obj.items():
                                        if isinstance(value, str) and len(value) > 8:
                                            form_data[f"__eqmc_{key}"] = value
                            except:
                                pass
                    else:
                        # For simple token extraction patterns
                        for m in matches:
                            if isinstance(m, tuple):
                                # Take the first item if it's a tuple
                                token = m[0]
                            else:
                                token = m

                            # Try to determine token type from length and content
                            if re.match(r"^EAAG[a-zA-Z0-9]{20,}$", token):
                                form_data["access_token"] = token
                            elif len(token) > 30:
                                form_data["fb_dtsg"] = token
                            elif re.match(r"^\d+$", token):
                                form_data["jazoest"] = token

            # Common tokens needed for Facebook registration in 2025
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
                    r'name="fb_dtsg" value="([^"]*)"',
                    r"fbdtsg.*?value.*?([a-zA-Z0-9:_-]{20,})",
                ]

                for pattern in dtsg_patterns:
                    dtsg_match = re.search(pattern, html_content)
                    if dtsg_match:
                        form_data["fb_dtsg"] = dtsg_match.group(1)
                        form_data["fb_dtsg_tag"] = dtsg_match.group(
                            1
                        )  # Facebook now requires both
                        break

                # If still not found, generate a properly formatted value
                if "fb_dtsg" not in form_data:
                    # Generate a token in the format Facebook expects in 2025
                    # Format: AQEaXXXXXXXXX:YYYYYYYYY
                    default_dtsg = (
                        f"AQHa{generate_random_string(8)}:{generate_random_string(8)}"
                    )
                    form_data["fb_dtsg"] = default_dtsg
                    form_data["fb_dtsg_tag"] = default_dtsg
                    info(f"[*] Using fallback fb_dtsg token: {default_dtsg[:10]}...")

            # Jazoest token (critical for form validation)
            if "jazoest" not in form_data:
                jazoest_patterns = [
                    r'name="jazoest"\s*value="([^"]+)"',
                    r'"jazoest":"([^"]+)"',
                    r'{\s*"name":"jazoest",\s*"value":"([^"]+)"',
                    r'"token":"([^"]+)","type":"jazoest"',
                    r'name=\\"jazoest\\" value=\\"([^\\]+)\\"',
                    r'name="jazoest" value="([0-9]+)"',
                ]

                for pattern in jazoest_patterns:
                    jazoest_match = re.search(pattern, html_content)
                    if jazoest_match:
                        form_data["jazoest"] = jazoest_match.group(1)
                        break

                # If jazoest not found, generate one using Facebook's algorithm (2025 version)
                if "jazoest" not in form_data:
                    # Facebook typically computes jazoest from fbdtsg
                    # New version uses 2 followed by numeric values
                    if "fb_dtsg" in form_data:
                        fb_dtsg = form_data["fb_dtsg"]
                        # Calculate character codes for each character in fb_dtsg
                        char_codes = [ord(c) for c in fb_dtsg]
                        # Sum the char codes
                        code_sum = sum(char_codes)
                        # Format as 2 followed by the sum
                        jazoest = f"2{code_sum}"
                        form_data["jazoest"] = jazoest
                    else:
                        # Default fallback - use a pattern Facebook expects
                        default_jazoest = "2" + "".join(
                            random.choices("0123456789", k=8)
                        )
                        form_data["jazoest"] = default_jazoest
                        info(f"[*] Using fallback jazoest token: {default_jazoest}")

        except Exception as e:
            error(f"[!] Error extracting alternative tokens: {e}")

    # Add critical request metadata that Facebook expects in 2025
    timestamp = str(int(time.time()))
    request_id = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))

    # Modern Facebook (2025) expects these fields in registration requests
    form_data.update(
        {
            "__req": request_id,
            "__a": "1",
            "__user": "0",  # For non-logged-in users
            "__rev": str(random.randint(1000000, 9999999)),
            "__s": "".join(
                random.choices("abcdefghijklmnopqrstuvwxyz0123456789:_", k=8)
            ),
            "__hsi": timestamp,
            "__comet_req": "0",
            "__spin_r": timestamp,
            "__spin_t": timestamp,
            "__ccg": "EXCELLENT",  # Connection quality
            "__jssesw": "1",  # JavaScript enabled
            "__dyn": "".join(random.choices("0123456789", k=10)),  # Dynamic parameters
            "__csr": "",
            "__hs": "19368.HYP:facebook_web_register.2.1..0.0",
            "is_twofactor": "0",
            "is_potentially_compromised": "0",
            "has_password_field": "1",
            "contact_point": "",  # Will be filled with email
            # New 2025 security fields
            "hs_grt": generate_random_string(12),
            "av": "0",  # Anonymous visitor
            "client_mutation_id": str(uuid.uuid4()),
            "fba_nrb": "0",  # Facebook browser API not required
        }
    )

    # Add form session and tracking values
    form_data["lsd"] = form_data.get("fb_dtsg", "")[:8]
    form_data["__spin_b"] = "trunk"

    # Add a session ID that simulates browser session
    form_data["__session_id"] = str(uuid.uuid4()).replace("-", "")

    return form_data


def handle_security_challenges(session, response):
    """Enhanced method to handle security challenges - Updated for 2025 security patterns"""
    html_content = response.text
    url = response.url

    # Check if this is just the standard identity confirmation page but not a real security check
    standard_identity_phrases = [
        "confirm your identity",
        "confirm your information",
        "provide your information",
        "verify your information",
    ]

    # Check if the page still has registration form elements
    if any(phrase in html_content.lower() for phrase in standard_identity_phrases):
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
            info(
                "[*] Page contains identity confirmation language but still has registration form"
            )
            return True, None

    # 2025 Facebook serious block detection patterns
    serious_blocks = [
        "suspicious activity detected",
        "account disabled",
        "try again later",
        "something went wrong",
        "we couldn't process",
        "temporarily blocked",
        "unusual activity",
        "verify it's you",
        "confirm your identity with a security check",
        "security checkpoint",
        "we need more information",
        "we've detected unusual activity",
    ]

    # Look for block messages in JSON response (Facebook now uses JSON responses more)
    try:
        json_data = json.loads(html_content)
        if isinstance(json_data, dict):
            if "error" in json_data:
                error_msg = json_data.get("error", {}).get("message", "")
                if any(block in error_msg.lower() for block in serious_blocks):
                    block_type = "json_error"
                    info(f"[*] JSON error block detected: {error_msg}")
                    return False, block_type
    except:
        pass

    # Check for text-based blocks
    if any(block in html_content.lower() for block in serious_blocks):
        block_type = next(
            (block for block in serious_blocks if block in html_content.lower()),
            "unknown_block",
        )
        info(f"[*] Serious security block detected: {block_type}")
        return False, "security_block"

    # Check for modern checkpoint URLs
    checkpoint_indicators = [
        "checkpoint",
        "/checkpoint/",
        "?next=checkpoint",
        "login/checkpoint",
        "security/check",
        "verification",
        "confirm/identity",
        "suspicious_login",
        "challenge",
    ]

    if any(indicator in url for indicator in checkpoint_indicators):
        info(f"[*] Security checkpoint detected in URL: {url}")
        return False, "checkpoint"

    # Modern security verification page detection
    security_indicators = [
        "verification code",
        "confirm your identity",
        "suspicious activity",
        "unusual login",
        "security code",
        "enter the code",
        "we sent a code",
        "verify your account",
        "need to confirm",
        "authentication required",
    ]

    if any(
        indicator.lower() in html_content.lower() for indicator in security_indicators
    ):
        info("[*] Security verification required")
        return False, "security_verification"

    # Check for CAPTCHA or other challenges
    captcha_indicators = [
        "captcha",
        "recaptcha",
        "robot",
        "not a robot",
        "human verification",
        "security check",
        "prove you're human",
        "challenge",
    ]

    if any(
        indicator.lower() in html_content.lower() for indicator in captcha_indicators
    ):
        info("[*] CAPTCHA or human verification required")
        return False, "captcha"

    # Default: assume no security challenges detected
    return True, None


def generate_fp_data(user_details):
    """Generate realistic fingerprinting data to prevent detection - Updated for 2025 patterns"""
    # Create a deterministic but unique fingerprint for this user
    user_fp_seed = user_details.get("user_agent_hash", str(random.random()))

    # Get browser properties
    browser_props = get_random_browser_properties()

    # Generate hardware info with more realistic modern ranges (2025 standards)
    cores = random.choice([4, 6, 8, 12, 16, 24, 32])
    ram = random.choice([8, 16, 32, 64])

    # Generate screen info based on common 2025 resolutions
    resolution = random.choice(
        [
            [1920, 1080],
            [2560, 1440],
            [3840, 2160],
            [1440, 900],
            [2880, 1800],
            [3440, 1440],
            [2560, 1600],
            [1536, 864],
        ]
    )

    # Device pixel ratio based on device type
    if "iPhone" in user_details.get("user_agent", ""):
        dpr = random.choice([2, 3, 4])  # Modern iPhones have higher DPR
    elif "Android" in user_details.get("user_agent", ""):
        dpr = random.choice([2, 2.5, 3, 3.5, 4])
    else:
        dpr = random.choice([1, 1.25, 1.5, 2, 2.5])

    # More realistic timing values for 2025 web performance
    time_now = int(time.time() * 1000)
    navigation_time = time_now - random.randint(80, 300)  # Faster connections in 2025
    dom_complete = navigation_time + random.randint(150, 500)
    load_event = dom_complete + random.randint(30, 150)

    # Create advanced fingerprint data matching Facebook's 2025 expectations
    fp_data = {
        "webgl_fingerprint": {
            "vendor_hash": hashlib.md5(
                f"{user_fp_seed}webgl_vendor".encode()
            ).hexdigest(),
            "renderer_hash": hashlib.md5(
                f"{user_fp_seed}webgl_renderer".encode()
            ).hexdigest(),
            "vendor_unmasked": random.choice(
                [
                    "Google Inc. (NVIDIA)",
                    "Google Inc. (Intel)",
                    "Google Inc. (AMD)",
                    "Apple GPU",
                    "NVIDIA Corporation",
                    "Intel Inc.",
                    "AMD ATI Technologies",
                ]
            ),
            "renderer_unmasked": random.choice(
                [
                    "ANGLE (NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0)",
                    "ANGLE (Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0)",
                    "ANGLE (AMD Radeon RX 7800 XT Direct3D11 vs_5_0 ps_5_0)",
                    "ANGLE (NVIDIA RTX A4000 Direct3D11 vs_5_0 ps_5_0)",
                    "Apple GPU",
                    "Apple M3 GPU",
                    "WebKit WebGL",
                ]
            ),
            "parameters": {
                "alpha_bits": random.choice([8, 10]),
                "depth_bits": random.choice([24, 32]),
                "antialias": random.choice([True, False]),
                "max_texture_size": random.choice([8192, 16384, 32768]),
            },
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
                else random.randint(1, 5)
            ),
            "pdfViewerEnabled": True,
            "javaEnabled": False,  # Modern browsers don't support Java
            "cookieEnabled": True,
            # New 2025 properties that Facebook checks
            "webdriver": False,
            "automationEnabled": False,
            "permissions": {
                "notifications": "prompt",
                "geolocation": "prompt",
                "camera": "prompt",
                "microphone": "prompt",
            },
            "deviceTouch": "Windows" not in browser_props["platform"]
            and "Macintosh" not in browser_props["platform"],
        },
        "screen": {
            "width": resolution[0],
            "height": resolution[1],
            "colorDepth": random.choice(
                [24, 30, 32, 48]
            ),  # Higher color depths in 2025
            "availWidth": resolution[0] - random.randint(0, 20),
            "availHeight": resolution[1] - random.randint(40, 80),
            "pixelDepth": random.choice([24, 30, 32, 48]),
            "orientation": {"type": "landscape-primary", "angle": 0},
            "dpr": dpr,
        },
        "timezone": {
            "offset": random.randint(-720, 720),  # Minutes from UTC
            "timezone": random.choice(
                [
                    "America/New_York",
                    "Europe/London",
                    "Asia/Tokyo",
                    "Australia/Sydney",
                    "America/Los_Angeles",
                    "Europe/Paris",
                ]
            ),
            "dst": random.choice([True, False]),  # Daylight saving time
        },
        "battery": {
            "charging": random.choice([True, False]),
            "level": round(random.uniform(0.1, 1.0), 2),
            "chargingTime": random.choice([0, float("Infinity")]),
            "dischargingTime": random.randint(1000, 10000),
        },
        "plugins": random.randint(1, 5),  # Modern browsers have fewer plugins
        "fonts": random.randint(40, 80),  # More fonts in 2025
        "timing": {
            "navigation_start": navigation_time,
            "fetch_start": navigation_time + random.randint(1, 8),
            "dns_start": navigation_time + random.randint(2, 10),
            "dns_end": navigation_time + random.randint(10, 40),
            "connect_start": navigation_time + random.randint(15, 50),
            "connect_end": navigation_time + random.randint(20, 80),
            "request_start": navigation_time + random.randint(25, 90),
            "response_start": navigation_time + random.randint(40, 150),
            "response_end": navigation_time + random.randint(60, 200),
            "dom_interactive": navigation_time + random.randint(100, 300),
            "dom_content_loaded": navigation_time + random.randint(120, 400),
            "dom_complete": dom_complete,
            "load_event_start": dom_complete + random.randint(5, 50),
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
                            else (
                                "iOS"
                                if "iPhone" in browser_props["platform"]
                                else "unknown"
                            )
                        )
                    )
                )
            ),
            "version": (
                "11"
                if "Windows" in browser_props["platform"]
                else (
                    random.choice(["13.0", "14.0", "15.0"])
                    if "Macintosh" in browser_props["platform"]
                    else (
                        random.choice(["13", "14", "15"])
                        if "Android" in browser_props["platform"]
                        else (
                            random.choice(["17.0", "18.0", "19.0"])
                            if "iPhone" in browser_props["platform"]
                            else "unknown"
                        )
                    )
                )
            ),
            "architecture": random.choice(["x86_64", "arm64"]),
        },
        "connection": {
            "type": random.choice(["wifi", "5g", "4g", "ethernet"]),
            "rtt": random.randint(5, 100),  # Lower RTT in 2025
            "downlink": round(random.uniform(5, 100), 1),  # Higher speeds in 2025
            "effectiveType": random.choice(["4g", "5g"]),
            "saveData": random.choice([True, False]),
        },
        "viewport": {
            "width": resolution[0] - random.randint(20, 160),
            "height": resolution[1] - random.randint(60, 200),
            "scale": round(random.uniform(0.8, 1.2), 2),
        },
        "has_touch": "Windows" not in browser_props["platform"]
        and "Macintosh" not in browser_props["platform"],
        "notification_permission": random.choice(["default", "denied", "granted"]),
        "hardware_features": {
            "webgl": True,
            "webgl2": True,
            "webgpu": random.choice([True, False]),  # New in 2025
            "webrtc": True,
            "gamepad": random.choice([True, False]),
            "bluetooth": random.choice([True, False]),
            "usb": random.choice([True, False]),
            "midi": random.choice([True, False]),
        },
        "cookie_settings": {
            "third_party": random.choice(["allow", "block", "block_with_exceptions"]),
            "first_party": "allow",
            "expiration": random.choice(["session", "7_days", "30_days", "forever"]),
        },
        # Advanced browser security and fingerprinting protections
        "security_features": {
            "content_blocking": random.choice([True, False]),
            "anti_tracking": random.choice([True, False]),
            "sandbox": True,
            "cross_origin_isolation": random.choice([True, False]),
        },
        # Device details that Facebook checks in 2025
        "device": {
            "id": user_details.get("device_id", str(uuid.uuid4()).replace("-", "")),
            "created_timestamp": int(
                time.time() - random.randint(3600 * 24 * 10, 3600 * 24 * 90)
            ),  # Device "age"
            "name": random.choice(
                [
                    "Chrome on Windows",
                    "Chrome on macOS",
                    "Safari on macOS",
                    "Firefox on Windows",
                    "Chrome on Android",
                    "Safari on iPhone",
                ]
            ),
        },
        # Facebook-specific fingerprinting parameters
        "fb_fingerprint_id": hashlib.md5(
            f"{user_fp_seed}_fb_fp_{int(time.time())}".encode()
        ).hexdigest(),
        "fb_visit_count": random.randint(1, 5),
        "fb_visits_timespan": random.randint(0, 86400 * 7),  # Up to 7 days in seconds
    }

    return json.dumps(fp_data)


def simulate_realistic_form_filling(session, form_url, form_data, user_details):
    """Simulate modern human-like form filling behavior - Updated for 2025 Facebook patterns"""
    try:
        # First simulate page loading and initial interaction
        info("[*] Simulating realistic form filling behavior...")

        # More realistic initial page load waiting
        wait_with_jitter(1.2, 2.8)

        # Fields that a human would interact with
        fields_to_simulate = [
            "firstname",
            "lastname",
            "reg_email__",
            "reg_email_confirmation__",
            "reg_passwd__",
        ]

        # Track timing of simulated field interactions (more detailed for 2025)
        field_timings = {}
        start_time = time.time() * 1000  # milliseconds

        # Modern browsers record more detailed events
        events = [
            "focus",
            "keydown",
            "input",
            "change",
            "keyup",
            "blur",
            "click",
            "touchstart",
            "touchend",
        ]

        # Create events for each field with realistic timing
        for field in fields_to_simulate:
            if field in form_data:
                # Initial page view tracking
                if field == fields_to_simulate[0]:
                    field_timings["page_view"] = 0
                    field_timings["page_focus"] = int(random.uniform(100, 1000))

                # Track mouse movement to field
                field_timings[f"{field}_mouseover"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.1, 0.4)

                # Field focus
                field_timings[f"{field}_focus"] = int(time.time() * 1000 - start_time)

                # For each character, simulate typing with realistic timing
                field_value = str(form_data[field])
                char_count = len(field_value)

                for i in range(char_count):
                    # Realistic typing involves keydown, input, keyup events for each character
                    current_time = int(time.time() * 1000 - start_time)

                    # Some people type in bursts, some steadily
                    if (
                        random.random() < 0.2
                    ):  # 20% chance of a longer pause during typing
                        wait_with_jitter(0.2, 0.8)
                    else:
                        # Normal typing speed with natural variation
                        char_typing_speed = (
                            random.uniform(50, 150) / 1000
                        )  # 50-150ms per character
                        time.sleep(char_typing_speed)

                    # Record events that would happen for this character
                    if (
                        i < 3 or i >= char_count - 3 or random.random() < 0.2
                    ):  # Only record some events
                        char_time = int(time.time() * 1000 - start_time)
                        field_timings[f"{field}_keydown_{i}"] = char_time
                        field_timings[f"{field}_input_{i}"] = (
                            char_time + random.randint(1, 5)
                        )
                        field_timings[f"{field}_keyup_{i}"] = (
                            char_time + random.randint(5, 15)
                        )

                # After typing, simulate a short pause
                wait_with_jitter(0.3, 0.7)

                # Field blur event
                field_timings[f"{field}_blur"] = int(time.time() * 1000 - start_time)

                # Record in browser cookie to show field was filled
                session.cookies.set(
                    f"filled_{field}", "1", domain=urlparse(form_url).netloc
                )

                # Small pause between fields (humans pause between fields)
                wait_with_jitter(0.4, 1.2)

        # Simulate selecting birthday fields with realistic mouse movements
        birthday_fields = ["birthday_day", "birthday_month", "birthday_year"]
        for field in birthday_fields:
            if field in form_data:
                # Mouse over, click, select interactions
                field_timings[f"{field}_mouseover"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.2, 0.4)
                field_timings[f"{field}_mousedown"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.1, 0.2)
                field_timings[f"{field}_click"] = int(time.time() * 1000 - start_time)
                wait_with_jitter(0.3, 0.6)
                field_timings[f"{field}_change"] = int(time.time() * 1000 - start_time)
                wait_with_jitter(0.2, 0.5)

        # Simulate gender selection with realistic mouse events
        if "sex" in form_data:
            field_timings["gender_section_view"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.4, 0.9)
            field_timings["sex_option_mouseover"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.2, 0.4)
            field_timings["sex_option_mousedown"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.1, 0.2)
            field_timings["sex_click"] = int(time.time() * 1000 - start_time)
            wait_with_jitter(0.3, 0.7)

        # Simulate terms checkbox interactions with more detail
        for term_field in ["terms", "datause"]:
            if term_field in form_data:
                field_timings[f"{term_field}_section_view"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.3, 0.7)
                field_timings[f"{term_field}_mouseover"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.2, 0.4)
                field_timings[f"{term_field}_mousedown"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.1, 0.2)
                field_timings[f"{term_field}_click"] = int(
                    time.time() * 1000 - start_time
                )
                wait_with_jitter(0.2, 0.5)

        # Final pause before form submission (reading terms)
        wait_with_jitter(1.0, 2.5)

        # Simulate moving to and clicking the submit button
        field_timings["submit_mouseover"] = int(time.time() * 1000 - start_time)
        wait_with_jitter(0.3, 0.6)
        field_timings["submit_mousedown"] = int(time.time() * 1000 - start_time)
        wait_with_jitter(0.1, 0.2)
        field_timings["submit_click"] = int(time.time() * 1000 - start_time)

        # Add fingerprinting data enhanced with timing information
        user_details["field_timings"] = field_timings
        fp_data = generate_fp_data(user_details)

        # Update Facebook's expected fields for 2025
        form_data["__user_interaction_timing"] = json.dumps(field_timings)
        form_data["__browser_fps"] = fp_data
        form_data["__browser_info"] = json.dumps(
            {
                "fingerprint": hashlib.md5(fp_data.encode()).hexdigest(),
                "timing": field_timings,
                "input_timing": field_timings,
                "interaction_count": len(field_timings),
                "form_submit_timing": field_timings.get("submit_click", 0),
            }
        )

        # Add Facebook-specific advanced form data for 2025
        form_data.update(
            {
                "reg_instance": user_details.get(
                    "device_id", generate_random_string(16)
                ),
                "platform_xmd": "",
                "had_cp_prefilled": "false",
                "had_password_prefilled": "false",
                "is_voice_clip_supported": "true",
                "is_smart_lock_supported": "true",
                # New security fields for 2025
                "is_e2e_supported": "true",
                "bi_xrwh": "0",
                "auth_flow_version": "2",
                "prefill_source": "browser_dropdown",
                "prefill_type": "manual",
                "first_prefill_source": "browser_dropdown",
                "first_prefill_type": "manual",
                "had_cp_preregistered": "false",
                "encpass_standalone": "false",
                # Consent fields
                "terms": "on",
                "datause": "on",
                "dpr": str(get_random_browser_properties()["pixel_ratio"]),
                "site_domain": "facebook.com",
                "acknowledge_understanding": "on",
                "websubmit": "Sign Up",
            }
        )

        # Ensure critical modern Facebook fields are present
        current_time = int(time.time())
        if "encpass" not in form_data and "reg_passwd__" in form_data:
            form_data["encpass"] = (
                f"#PWD_BROWSER:5:{current_time}:{form_data['reg_passwd__']}"
            )

        # Facebook now uses a specific format for encrypted passwords in 2025
        # Format: #PWD_BROWSER:version:timestamp:password
        # Version 5 is the 2025 version
        if "encpass" in form_data and not form_data["encpass"].startswith(
            "#PWD_BROWSER:5:"
        ):
            form_data["encpass"] = (
                f"#PWD_BROWSER:5:{current_time}:{form_data['reg_passwd__']}"
            )

        if "reg_email_confirmation__" not in form_data and "reg_email__" in form_data:
            form_data["reg_email_confirmation__"] = form_data["reg_email__"]

        # Add contact point label
        form_data["contactpoint_label"] = "email"
        form_data["contact_point"] = form_data.get("reg_email__", "")

        return form_data

    except Exception as e:
        error(f"[!] Error in form filling simulation: {e}")
        return form_data
