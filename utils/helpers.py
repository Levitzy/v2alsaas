# utils/helpers.py - Improved extraction and debugging functions

import re
import time
import random
import json
from datetime import datetime
import base64

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
            "DNT": "1" if random.random() < 0.7 else "0",  # Do Not Track
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": random.choice(["max-age=0", "no-cache", "max-age=60"]),
            "Pragma": random.choice(["no-cache", ""]),
            "Sec-Fetch-Site": random.choice(["same-origin", "none"]),
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Priority": random.choice(["high", "u=1"]),
        }
    )

    return session


def extract_hidden_fields(html):
    """Enhanced extraction of hidden form fields from HTML response with debugging"""
    hidden_fields = {}
    extraction_methods = []

    try:
        # Method 1: Standard input field extraction
        matches = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', html)
        for match in matches:
            name_match = re.search(r'name=["\']([^"\']+)["\']', match)
            value_match = re.search(r'value=["\']([^"\']*)["\']', match)

            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                hidden_fields[name] = value

        if matches:
            extraction_methods.append("standard_inputs")

        # Method 2: JSON-based extraction for modern Facebook
        json_fields = re.findall(r'"name":"([^"]+)","value":"([^"]*)"', html)
        for name, value in json_fields:
            if name not in hidden_fields:
                hidden_fields[name] = value

        if json_fields:
            extraction_methods.append("json_fields")

        # Method 3: ServerJS data extraction
        serverjs_pattern = r'require\("ServerJS"\)\.handle\({(.+?)}\);'
        serverjs_matches = re.findall(serverjs_pattern, html, re.DOTALL)

        if serverjs_matches:
            extraction_methods.append("serverjs")
            for match in serverjs_matches:
                field_pattern = r'"name":"([^"]+)","value":"([^"]*)"'
                js_fields = re.findall(field_pattern, match)
                for name, value in js_fields:
                    if name not in hidden_fields:
                        hidden_fields[name] = value

        # Method 4: Modern Facebook's HTML embedded JSON
        json_blocks = re.findall(
            r'<script type="application/json"[^>]*>(.*?)</script>', html, re.DOTALL
        )

        if json_blocks:
            extraction_methods.append("json_blocks")
            for json_block in json_blocks:
                try:
                    # Clean up the JSON data
                    cleaned = json_block.replace("&quot;", '"').replace("\\", "\\\\")
                    cleaned = re.sub(r'\\(?!["\\/bfnrt])', r"\\\\", cleaned)

                    # Try to find input fields
                    field_pattern = r'"name":"([^"]+)","value":"([^"]*)"'
                    embedded_fields = re.findall(field_pattern, cleaned)

                    for name, value in embedded_fields:
                        if name not in hidden_fields:
                            hidden_fields[name] = value
                except:
                    pass

        # Method 5: Look for alternative form data structures
        form_data_pattern = r'name=\\?"([^"\\]+)\\?"[^>]+value=\\?"([^"\\]*)'
        form_matches = re.findall(form_data_pattern, html)

        if form_matches:
            extraction_methods.append("escaped_form_fields")
            for name, value in form_matches:
                if name not in hidden_fields and name.lower() != "submit":
                    hidden_fields[name] = value

        # Report which methods worked
        if extraction_methods:
            info(f"[*] Form field extraction methods: {', '.join(extraction_methods)}")
        else:
            info("[!] No form fields extracted via standard methods")

            # Last resort: Look for any form element to see if the page contains a form
            form_exists = (
                re.search(r"<form[^>]*>.+?</form>", html, re.DOTALL) is not None
            )
            if form_exists:
                info("[*] Form element found but couldn't extract fields")
            else:
                info("[!] No form element found on the page")

    except Exception as e:
        error(f"[!] Error extracting hidden fields: {e}")

    return hidden_fields


def extract_error_message(html):
    """Extract error messages from HTML response with improved patterns and debugging"""
    error_patterns = [
        # Standard error messages
        r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]*id=["\']error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div id="error_box"[^>]*>(.*?)</div>',
        r'<div class="[^"]*error_message[^"]*">\s*([^<>]+)\s*</div>',
        r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</span>',
        # Facebook-specific error patterns
        r'errorMessage":"([^"]+)"',
        r'"error":{"message":"([^"]+)"',
        r'"description":"([^"]+)".*?"is_fatal":true',
        r'<div class="[^"]*warningBox[^"]*">\s*([^<>]+)\s*</div>',
        r'<div class="[^"]*notification[^"]*">\s*([^<>]+)\s*</div>',
        # Modern FB errors
        r'error_text["\']>(.*?)</div>',
        r'flash_message["\']>(.*?)</div>',
        r'error_data.*?"text":"([^"]+)"',
        r'error_summary["\']>(.*?)</div>',
        r'feedback_error["\']>(.*?)</div>',
    ]

    for pattern in error_patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        if matches:
            # Clean up the error message (remove HTML tags and extra whitespace)
            error_text = re.sub(r"<[^>]+>", " ", matches[0])
            error_text = " ".join(error_text.split())
            return error_text.strip()

    # Try parsing as JSON
    try:
        # First check for a JSON response directly
        try:
            json_data = json.loads(html)
            if isinstance(json_data, dict):
                if "error" in json_data and "message" in json_data["error"]:
                    return json_data["error"]["message"]
                if "errors" in json_data and len(json_data["errors"]) > 0:
                    return json_data["errors"][0]["message"]
        except:
            pass

        # Look for embedded JSON in the HTML
        json_matches = re.findall(r'{"error":({.+?}),"jsmods":', html)
        if json_matches:
            for json_str in json_matches:
                try:
                    error_data = json.loads("{" + json_str + "}")
                    if "message" in error_data:
                        return error_data["message"]
                except:
                    continue
    except:
        pass

    # Try checking for common error phrases in the text
    common_errors = [
        "suspicious activity",
        "try again later",
        "something went wrong",
        "temporarily unavailable",
        "we're having trouble",
        "confirm your identity",
        "security check",
        "too many attempts",
        "rate limit",
    ]

    for phrase in common_errors:
        if phrase in html.lower():
            surrounding_text = re.search(r"[^>]*" + re.escape(phrase) + r"[^<]*", html)
            if surrounding_text:
                return surrounding_text.group(0).strip()
            return f"Detected: {phrase}"

    # If all else fails, look for any message inside a div
    # that might be an error but wasn't caught by the patterns
    general_message = re.search(r"<div[^>]*message[^>]*>([^<]+)</div>", html)
    if general_message:
        return general_message.group(1).strip()

    return "Unknown error occurred"


def extract_security_tokens(html):
    """Extract security tokens from HTML response with improved patterns and debugging"""
    tokens = {}

    # Common token patterns on Facebook (expanded)
    token_patterns = {
        "fb_dtsg": [
            r'name="fb_dtsg" value="([^"]+)"',
            r'"fb_dtsg":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"fb_dtsg"',
            r'DTSGInitData["\']],\[[^]]*\],{[^}]*"token":"([^"]+)"',
            r'<input type="hidden" name="fb_dtsg" value="([^"]+)"',
            r'"name":"fb_dtsg","value":"([^"]+)"',
            r'require\("DTSGInitData"\)\[\],\[\],{"token":"([^"]+)"',
        ],
        "jazoest": [
            r'name="jazoest" value="([^"]+)"',
            r'"jazoest":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"jazoest"',
            r'<input type="hidden" name="jazoest" value="([^"]+)"',
            r'"name":"jazoest","value":"([^"]+)"',
        ],
        "lsd": [
            r'name="lsd" value="([^"]+)"',
            r'"lsd":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"lsd"',
            r'<input type="hidden" name="lsd" value="([^"]+)"',
            r'"name":"lsd","value":"([^"]+)"',
        ],
        "m_ts": [
            r'name="m_ts" value="([^"]+)"',
            r'"m_ts":"([^"]+)"',
            r'<input type="hidden" name="m_ts" value="([^"]+)"',
            r'"name":"m_ts","value":"([^"]+)"',
        ],
        "li": [
            r'name="li" value="([^"]+)"',
            r'"li":"([^"]+)"',
            r'<input type="hidden" name="li" value="([^"]+)"',
            r'"name":"li","value":"([^"]+)"',
        ],
        "__dyn": [
            r'name="__dyn" value="([^"]+)"',
            r'"__dyn":"([^"]+)"',
            r'<input type="hidden" name="__dyn" value="([^"]+)"',
        ],
        "__csr": [
            r'name="__csr" value="([^"]+)"',
            r'"__csr":"([^"]+)"',
            r'<input type="hidden" name="__csr" value="([^"]+)"',
        ],
    }

    for token_name, patterns in token_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                tokens[token_name] = match.group(1)
                break

    # Modern Facebook implementation - check for JSON data
    json_data_patterns = [
        r'require\("ServerJS"\)\.handle\({(.+?)}\);',
        r'<script type="application/json"[^>]*>(.*?)</script>',
        r"new ServerJS\(\)\.handle\({(.+?)}\)",
    ]

    for pattern in json_data_patterns:
        json_matches = re.findall(pattern, html, re.DOTALL)

        for json_match in json_matches:
            try:
                # Clean up potential escaped content
                cleaned = json_match.replace('\\"', '"').replace("\\\\", "\\")

                # Look for tokens in the JSON data
                for token_name in ["fb_dtsg", "jazoest", "lsd", "__dyn", "__csr"]:
                    if token_name not in tokens:
                        token_pattern = (
                            r'"name":"' + token_name + r'","value":"([^"]+)"'
                        )
                        token_match = re.search(token_pattern, cleaned)
                        if token_match:
                            tokens[token_name] = token_match.group(1)
            except Exception as e:
                continue

    # Report which tokens were found
    token_names = list(tokens.keys())
    if token_names:
        token_info = ", ".join(token_names)
        info(f"[*] Security tokens found: {token_info}")
    else:
        info("[!] No security tokens found in the page")

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
    """Focuses on modern Facebook security measures (not captcha)"""
    # Modern Facebook security checks (not traditional captchas)
    security_indicators = [
        # Serious security blocks
        r"suspicious activity detected",
        r"account disabled",
        r"try again later",
        r"something went wrong",
        r"we couldn\'t process",
        r"temporarily blocked",
        r"rate limit",
        r"too many attempts",
        # Identity verification
        r"verification code",
        r"confirm your identity",
        r"security check",
        r"unusual login",
        # More modern Facebook terms
        r"we noticed unusual activity",
        r"we need more information",
        r"additional authentication",
        r"waiting for approval",
    ]

    for pattern in security_indicators:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    # Check for security-related redirects or URLs
    url_indicators = [
        "checkpoint",
        "security",
        "recover",
        "identify",
        "disabled",
        "suspended",
        "blocked",
        "confirm",
    ]

    if any(indicator in html for indicator in url_indicators):
        return True

    # Check for specific checkpoint divs and widgets
    checkpoint_indicators = [
        r'<div[^>]*id=["\']checkpoint',
        r'<div[^>]*class=["\'][^"\']*checkpoint',
        r"security_check_required",
        r"captcha_response",  # Some legacy implementations
        r"verification_method",
        r"security_challenge",
    ]

    for pattern in checkpoint_indicators:
        if re.search(pattern, html, re.IGNORECASE):
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

        # More random waiting to confuse rate limiters
        actual_wait = random.uniform(min_time, max_time)
        info(f"[*] Waiting {actual_wait:.1f} seconds...")

        # Split the wait into smaller chunks to avoid looking like a script
        chunk_size = random.uniform(1.0, 2.5)
        remaining = actual_wait

        while remaining > 0:
            this_chunk = min(chunk_size, remaining)
            time.sleep(this_chunk)
            remaining -= this_chunk

        return True
    return False


def extract_user_id(response, session):
    """Extract user ID from response or cookies with improved patterns and debugging"""
    user_id = "Unknown"

    # Check cookies first (most reliable)
    cookies = session.cookies.get_dict()
    if "c_user" in cookies:
        user_id = cookies.get("c_user")
        info(f"[*] Extracted user ID from cookies: {user_id}")
        return user_id

    # Try to extract from URL
    url = response.url
    id_patterns = [
        r"id=(\d+)",
        r"user=(\d+)",
        r"uid=(\d+)",
        r"/profile\.php\?id=(\d+)",
        r"facebook\.com/(\d+)",
        r"&id=(\d+)",
        r"\?id=(\d+)",
    ]

    for pattern in id_patterns:
        match = re.search(pattern, url)
        if match:
            user_id = match.group(1)
            info(f"[*] Extracted user ID from URL: {user_id}")
            return user_id

    # Try to extract from HTML content
    html = response.text
    html_patterns = [
        r'"userID":"(\d+)"',
        r'"user_id":"(\d+)"',
        r'"userId":"(\d+)"',
        r'"actorID":"(\d+)"',
        r'name="target" value="(\d+)"',
        r'"uid":"(\d+)"',
        r'"ACCOUNT_ID":"(\d+)"',
        r'"profile_id":"(\d+)"',
        r'"id":"(\d+)"[^}]*"type":"User"',
        r'entity_id":"(\d+)"',
    ]

    for pattern in html_patterns:
        match = re.search(pattern, html)
        if match:
            user_id = match.group(1)
            info(f"[*] Extracted user ID from HTML: {user_id}")
            return user_id

    # Check for encoded payloads that might contain the ID
    encoded_data_patterns = [
        r'encoded_user_id=([^&"]+)',
        r'user_id_base64=([^&"]+)',
    ]

    for pattern in encoded_data_patterns:
        match = re.search(pattern, html)
        if match:
            try:
                encoded_id = match.group(1)
                # Try to decode as base64
                decoded_id = base64.b64decode(encoded_id).decode("utf-8")
                if re.match(r"^\d+$", decoded_id):
                    user_id = decoded_id
                    info(f"[*] Extracted user ID from encoded data: {user_id}")
                    return user_id
            except:
                continue

    # If all else fails, generate a placeholder ID
    if user_id == "Unknown":
        from utils.generators import generate_random_string

        user_id = f"FB{generate_random_string(10)}"
        info(f"[*] Using placeholder user ID: {user_id}")

    return user_id
