# utils/helpers.py - Enhanced extraction and debugging functions for 2025 Facebook security

import re
import time
import random
import json
from datetime import datetime
import base64
import hashlib
import uuid

from utils.colors import info, error, success
from config import DELAY_BETWEEN_ATTEMPTS


def wait_with_jitter(min_time=1, max_time=3):
    """Wait a random amount of time with jitter to appear more human-like"""
    base_time = random.uniform(min_time, max_time)
    jitter = random.uniform(0, 0.5)  # Add up to 0.5 seconds of jitter
    time.sleep(base_time + jitter)


def simulate_human_behavior(session):
    """Simulate human behavior by adding modern browser behavior patterns"""
    # Add random pauses between requests
    wait_with_jitter(0.5, 2)

    # Set common headers that browsers typically send in 2025
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
            "Sec-Ch-Prefers-Color-Scheme": random.choice(["light", "dark"]),
            "Sec-Ch-Prefers-Reduced-Motion": random.choice(["no-preference", "reduce"]),
            "Sec-Ch-Prefers-Reduced-Transparency": "no-preference",
            "Sec-Ch-Ua-Full-Version-List": random.choice(
                [
                    '"Google Chrome";v="124.0.6367.85", "Chromium";v="124.0.6367.85", "Not-A.Brand";v="99.0.0.0"',
                    '"Microsoft Edge";v="124.0.2478.88", "Chromium";v="124.0.2478.88", "Not-A.Brand";v="99.0.0.0"',
                    '"Firefox";v="124.0"',
                    '"Safari";v="17.4"',
                ]
            ),
        }
    )

    # Add viewport width and device memory to better simulate real browsers
    viewport_width = random.choice([1280, 1366, 1536, 1920, 360, 390, 414])
    device_memory = random.choice([4, 8, 16])

    session.headers.update(
        {
            "Viewport-Width": str(viewport_width),
            "Device-Memory": str(device_memory),
        }
    )

    return session


def extract_hidden_fields(html):
    """Enhanced extraction of hidden form fields from HTML response (updated for 2025 Facebook)"""
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

        # Method 3: Modern React/GraphQL data extraction (2025)
        # Facebook now embeds form data in React props and GraphQL fragments
        react_props_pattern = r'<script\s+type="application/json"\s+[^>]*id="__REACT_PROPS__[^"]*">([^<]+)</script>'
        react_props_matches = re.findall(react_props_pattern, html)

        if react_props_matches:
            extraction_methods.append("react_props")
            for props_json in react_props_matches:
                try:
                    # Decode HTML entities
                    props_json = props_json.replace("&quot;", '"').replace("\\", "\\\\")
                    props_data = json.loads(props_json)

                    # Extract form fields from React props
                    if isinstance(props_data, dict):
                        # Extract from different possible locations in the props
                        for key in [
                            "formData",
                            "fields",
                            "hiddenFields",
                            "initialFields",
                        ]:
                            if key in props_data and isinstance(props_data[key], dict):
                                for field_name, field_value in props_data[key].items():
                                    if isinstance(field_value, str):
                                        hidden_fields[field_name] = field_value
                                    elif (
                                        isinstance(field_value, dict)
                                        and "value" in field_value
                                    ):
                                        hidden_fields[field_name] = field_value["value"]
                except Exception as e:
                    info(f"[*] Error parsing React props: {e}")

        # Method 4: ServerJS data extraction (modern Facebook 2025)
        serverjs_pattern = (
            r'(?:require\("ServerJS"\)\.handle|handleServerJS)\({(.+?)}\);'
        )
        serverjs_matches = re.findall(serverjs_pattern, html, re.DOTALL)

        if serverjs_matches:
            extraction_methods.append("serverjs")
            for match in serverjs_matches:
                field_pattern = r'"(?:name|field)":"([^"]+)","value":"([^"]*)"'
                js_fields = re.findall(field_pattern, match)
                for name, value in js_fields:
                    if name not in hidden_fields:
                        hidden_fields[name] = value

                # Look for Facebook's modern token format in ServerJS
                token_pattern = r'"token":"([^"]+)","type":"([^"]+)"'
                token_matches = re.findall(token_pattern, match)
                for token_value, token_type in token_matches:
                    if token_type not in hidden_fields:
                        hidden_fields[token_type] = token_value

        # Method 5: Modern Facebook's HTML embedded JSON (2025)
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

                    # Try to find input fields in common formats
                    field_patterns = [
                        r'"name":"([^"]+)","value":"([^"]*)"',
                        r'"field":"([^"]+)","value":"([^"]*)"',
                        r'"([^"]+)":{"__type":"FormField","value":"([^"]*)"',
                        r'"([^"]+)":{"defaultValue":"([^"]*)"',
                    ]

                    for pattern in field_patterns:
                        embedded_fields = re.findall(pattern, cleaned)
                        for name, value in embedded_fields:
                            if name not in hidden_fields:
                                hidden_fields[name] = value
                except Exception as e:
                    info(f"[*] Error parsing JSON block: {e}")

        # Method 6: Look for alternative form data structures in escaped strings
        form_data_patterns = [
            r'name=\\?"([^"\\]+)\\?"[^>]+value=\\?"([^"\\]*)',
            r'name=\\"([^\\"]+)\\"[^>]+value=\\"([^\\"]*)',
            r'"formFields":\s*\[([^\]]+)\]',
        ]

        for pattern in form_data_patterns:
            form_matches = re.findall(pattern, html)
            if form_matches:
                extraction_methods.append("escaped_form_fields")
                for match in form_matches:
                    if isinstance(match, tuple):
                        name, value = match
                        if name.lower() != "submit" and name not in hidden_fields:
                            hidden_fields[name] = value
                    elif isinstance(match, str):
                        # This is for the formFields array format
                        field_items = re.findall(
                            r'{"name":"([^"]+)","value":"([^"]*)"', match
                        )
                        for name, value in field_items:
                            if name not in hidden_fields:
                                hidden_fields[name] = value

        # Method 7: GraphQL variables and document IDs (2025 Facebook)
        graphql_patterns = [
            r'"docID":"([^"]+)"',
            r'"doc_id"\s*:\s*"([^"]+)"',
            r'"documentID":"([^"]+)"',
        ]

        for pattern in graphql_patterns:
            doc_id_matches = re.findall(pattern, html)
            if doc_id_matches and doc_id_matches[0]:
                hidden_fields["doc_id"] = doc_id_matches[0]
                extraction_methods.append("graphql_doc_id")

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
    """Extract error messages from HTML/JSON responses (updated for 2025 Facebook)"""
    # First try parsing as JSON since Facebook increasingly uses JSON responses
    try:
        json_data = json.loads(html)

        # Check structured error formats
        if isinstance(json_data, dict):
            # Format 1: Standard error object
            if "error" in json_data and isinstance(json_data["error"], dict):
                if "message" in json_data["error"]:
                    return json_data["error"]["message"]
                elif "description" in json_data["error"]:
                    return json_data["error"]["description"]

            # Format 2: GraphQL error array
            if (
                "errors" in json_data
                and isinstance(json_data["errors"], list)
                and len(json_data["errors"]) > 0
            ):
                error_messages = []
                for err in json_data["errors"]:
                    if "message" in err:
                        error_messages.append(err["message"])
                if error_messages:
                    return " | ".join(error_messages)

            # Format 3: Simple error message
            if "errorMessage" in json_data:
                return json_data["errorMessage"]

            # Format 4: Error summary and description
            if "errorSummary" in json_data and "errorDescription" in json_data:
                return f"{json_data['errorSummary']}: {json_data['errorDescription']}"

            # Format 5: Data with error inside
            if "data" in json_data and isinstance(json_data["data"], dict):
                for key in json_data["data"]:
                    if (
                        isinstance(json_data["data"][key], dict)
                        and "error" in json_data["data"][key]
                    ):
                        error_obj = json_data["data"][key]["error"]
                        if isinstance(error_obj, dict) and "message" in error_obj:
                            return error_obj["message"]
    except:
        # Not valid JSON, continue with HTML parsing
        pass

    # Standard error message patterns in HTML
    error_patterns = [
        # Standard error messages
        r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div[^>]*id=["\']error[^"\']*["\'][^>]*>(.*?)</div>',
        r'<div id="error_box"[^>]*>(.*?)</div>',
        r'<div class="[^"]*error_message[^"]*">\s*([^<>]+)\s*</div>',
        r'<span[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>(.*?)</span>',
        # Facebook-specific error patterns (2025)
        r'errorMessage":"([^"]+)"',
        r'"error":{"message":"([^"]+)"',
        r'"description":"([^"]+)".*?"is_fatal":true',
        r'<div class="[^"]*warningBox[^"]*">\s*([^<>]+)\s*</div>',
        r'<div class="[^"]*notification[^"]*">\s*([^<>]+)\s*</div>',
        # Modern FB errors (2025)
        r'error_text["\']>(.*?)</div>',
        r'flash_message["\']>(.*?)</div>',
        r'error_data.*?"text":"([^"]+)"',
        r'error_summary["\']>(.*?)</div>',
        r'feedback_error["\']>(.*?)</div>',
        # New 2025 error formats
        r'RegError["\']>(.*?)</div>',
        r'SecurityCheckError["\']>(.*?)</div>',
        r'FormError["\']>(.*?)</div>',
        r'ValidationError["\']>(.*?)</div>',
        r'errorBanner["\']>(.*?)</div>',
        r'errorContainer["\']>(.*?)</div>',
        r'"errorCode":(\d+),"errorMessage":"([^"]+)"',
    ]

    for pattern in error_patterns:
        matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
        if matches:
            # Clean up the error message (remove HTML tags and extra whitespace)
            if pattern.endswith('"'):  # JSON pattern
                error_text = matches[0]
            else:
                error_text = re.sub(r"<[^>]+>", " ", matches[0])
                error_text = " ".join(error_text.split())
            return error_text.strip()

    # Look for embedded JSON in the HTML that might contain errors
    json_matches = re.findall(
        r'{"error":({.+?})(?:,"jsmods"|,"payload"|,"require"|,"features")', html
    )
    if json_matches:
        for json_str in json_matches:
            try:
                error_data = json.loads("{" + json_str + "}")
                if "message" in error_data:
                    return error_data["message"]
                elif "description" in error_data:
                    return error_data["description"]
            except:
                continue

    # Check for common error phrases in the text
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
        "unusual activity",
        "registration is temporarily blocked",
        "automated request",
        "couldn't process your request",
        "too many accounts",
        "security checkpoint",
        "verification required",
        "robot check",
        "bot detection",
    ]

    for phrase in common_errors:
        if phrase in html.lower():
            surrounding_text = re.search(r"[^>]*" + re.escape(phrase) + r"[^<]*", html)
            if surrounding_text:
                return surrounding_text.group(0).strip()
            return f"Detected: {phrase}"

    # If all else fails, look for any message div that might be an error
    general_message = re.search(r"<div[^>]*message[^>]*>([^<]+)</div>", html)
    if general_message:
        return general_message.group(1).strip()

    return "Unknown error occurred"


def extract_security_tokens(html):
    """Extract security tokens from HTML response (updated for 2025 Facebook)"""
    tokens = {}

    # Common token patterns for 2025 Facebook
    token_patterns = {
        "fb_dtsg": [
            r'name="fb_dtsg" value="([^"]+)"',
            r'"fb_dtsg":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"fb_dtsg"',
            r'DTSGInitData["\']],\[[^]]*\],{[^}]*"token":"([^"]+)"',
            r'<input type="hidden" name="fb_dtsg" value="([^"]+)"',
            r'"name":"fb_dtsg","value":"([^"]+)"',
            r'require\("DTSGInitData"\)\[\],\[\],{"token":"([^"]+)"',
            r'"__fb_dtsg":{"__html":"([^"]+)"',
            r'"dtsg":{"token":"([^"]+)"',
            r'DTSGInitialData\["\],\[\],{"token":"([^"]+)"',
            r'"dtsg":\{"token":"([^"]+)"',
            # New 2025 formats
            r'fb_dtsg_tag":"([^"]+)"',
            r'name="fb_dtsg_ag" value="([^"]+)"',
        ],
        "jazoest": [
            r'name="jazoest" value="([^"]+)"',
            r'"jazoest":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"jazoest"',
            r'<input type="hidden" name="jazoest" value="([^"]+)"',
            r'"name":"jazoest","value":"([^"]+)"',
            # New 2025 formats
            r'"jazoest":{"token":"([^"]+)"',
            r'"jazoest_val":"([^"]+)"',
            r'"jazoest_data":"([^"]+)"',
        ],
        "lsd": [
            r'name="lsd" value="([^"]+)"',
            r'"lsd":"([^"]+)"',
            r'{\s*"token":"([^"]+)",\s*"type":"lsd"',
            r'<input type="hidden" name="lsd" value="([^"]+)"',
            r'"name":"lsd","value":"([^"]+)"',
            # New 2025 format
            r'"LSD",\[\],{"token":"([^"]+)"',
            r'"lsd_token":"([^"]+)"',
        ],
        "__spin_r": [
            r'name="__spin_r" value="([^"]+)"',
            r'"__spin_r":"([^"]+)"',
            r'"name":"__spin_r","value":"([^"]+)"',
        ],
        "__spin_t": [
            r'name="__spin_t" value="([^"]+)"',
            r'"__spin_t":"([^"]+)"',
            r'"name":"__spin_t","value":"([^"]+)"',
        ],
        # New 2025 tokens
        "client_mutation_id": [
            r'"client_mutation_id":"([^"]+)"',
            r'name="client_mutation_id" value="([^"]+)"',
        ],
        "fbdoctid": [
            r'"fbdoctid":"([^"]+)"',
            r'name="fbdoctid" value="([^"]+)"',
        ],
        "doc_id": [
            r'"doc_id":"([^"]+)"',
            r'name="doc_id" value="([^"]+)"',
            r'"documentID":"([^"]+)"',
        ],
    }

    for token_name, patterns in token_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                tokens[token_name] = match.group(1)
                break

    # Modern Facebook GraphQL implementation (2025) - extract from ServerJS data
    graphql_patterns = [
        r'require\("ServerJS"\)\.handle\({(.+?)}\);',
        r"handleServerJS\({(.+?)}\)",
        r'<script type="application/json"[^>]*data-sjs>(.*?)</script>',
        r'<script type="application/json"[^>]*id="__RELAY_DATA__">(.*?)</script>',
    ]

    for pattern in graphql_patterns:
        json_matches = re.findall(pattern, html, re.DOTALL)

        for json_match in json_matches:
            try:
                # Clean up potential escaped content
                cleaned = json_match.replace('\\"', '"').replace("\\\\", "\\")

                # Look for tokens in standard formats
                token_formats = [
                    r'"name":"([^"]+)","value":"([^"]+)"',
                    r'"type":"([^"]+)","token":"([^"]+)"',
                    r'"([^"]+)":{"token":"([^"]+)"',
                ]

                for format_pattern in token_formats:
                    token_matches = re.findall(format_pattern, cleaned)
                    for match in token_matches:
                        if len(match) == 2:
                            name, value = match
                            if name in [
                                "fb_dtsg",
                                "jazoest",
                                "lsd",
                                "__spin_r",
                                "__spin_t",
                                "client_mutation_id",
                                "fbdoctid",
                                "doc_id",
                            ]:
                                tokens[name] = value
            except Exception as e:
                continue

    # Look for modern Facebook's new 2025 authentication tokens in script tags
    script_tags = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
    for script in script_tags:
        # Look for access tokens (EAAG format used in 2025)
        access_token_match = re.search(r"EAAG[a-zA-Z0-9_-]{20,}", script)
        if access_token_match:
            tokens["access_token"] = access_token_match.group(0)

        # Look for fb_dtsg in JS variables
        fb_dtsg_js_match = re.search(r'fb_dtsg\s*=\s*["\']([^"\']+)["\']', script)
        if fb_dtsg_js_match and "fb_dtsg" not in tokens:
            tokens["fb_dtsg"] = fb_dtsg_js_match.group(1)

        # Look for other tokens in JS variables
        for token_name in ["jazoest", "lsd", "__spin_r", "__spin_t"]:
            token_js_match = re.search(
                f"{token_name}\\s*=\\s*[\"']([^\"']+)[\"']", script
            )
            if token_js_match and token_name not in tokens:
                tokens[token_name] = token_js_match.group(1)

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


def detect_security_challenge(html):
    """Detect modern Facebook security measures and challenges (2025)"""
    # Latest Facebook security indicators
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
        r"unusual activity",
        r"security check required",
        r"registration temporarily unavailable",
        r"registration limit reached",
        r"automated submissions detected",
        r"bot detection triggered",
        r"device verification",
        r"checkpoint",
        r"verify your device",
        # Identity verification
        r"verification code",
        r"confirm your identity",
        r"security check",
        r"unusual login",
        r"identity confirmation",
        r"prove you're human",
        r"additional verification",
        r"authentication challenge",
        # Modern Facebook security terms (2025)
        r"device verification required",
        r"network assessment",
        r"browser validation",
        r"behavior analysis",
        r"risk assessment",
        r"security module",
        r"challenge required",
        r"account protection",
        r"trust verification",
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
        "verify",
        "challenge",
        "protection",
        "risk",
        "assessment",
        "authenticity",
    ]

    if any(indicator in html for indicator in url_indicators):
        return True

    # Check for specific checkpoint divs and security widgets
    checkpoint_indicators = [
        r'<div[^>]*id=["\']checkpoint',
        r'<div[^>]*class=["\'][^"\']*checkpoint',
        r"security_check_required",
        r"captcha_response",
        r"verification_method",
        r"security_challenge",
        r"trustFactor",
        r"riskAssessment",
        r"behaviorScore",
        r"securityCheckpoint",
        r"identityCheck",
        r"deviceTrustCheck",
        r"registrationLimiter",
    ]

    for pattern in checkpoint_indicators:
        if re.search(pattern, html, re.IGNORECASE):
            return True

    # Modern Facebook often returns security challenges in JSON format
    try:
        json_obj = json.loads(html)
        if isinstance(json_obj, dict):
            # Check for security indicators in JSON response
            if "error" in json_obj:
                error_obj = json_obj["error"]
                if isinstance(error_obj, dict):
                    # Check error code ranges used for security challenges
                    if "code" in error_obj and isinstance(error_obj["code"], int):
                        # Facebook security error code ranges
                        security_error_ranges = [
                            (1300, 1399),  # Account security
                            (1357, 1359),  # Registration security
                            (1400, 1499),  # Checkpoint
                            (1600, 1699),  # Rate limiting
                            (2800, 2899),  # Authentication challenges
                        ]

                        for start, end in security_error_ranges:
                            if start <= error_obj["code"] <= end:
                                return True

                    # Check for security-related error messages
                    if "message" in error_obj and isinstance(error_obj["message"], str):
                        for indicator in security_indicators:
                            if re.search(
                                indicator, error_obj["message"], re.IGNORECASE
                            ):
                                return True

            # Check for specific security fields in Facebook's 2025 JSON schema
            security_json_fields = [
                "checkpoint_data",
                "security_checks",
                "risk_assessment",
                "trust_factors",
                "challenge_type",
                "verification_needed",
                "account_security",
                "registration_security",
                "security_requirement",
            ]

            for field in security_json_fields:
                if field in json_obj:
                    return True
    except:
        pass

    return False


def handle_between_attempts(attempt, max_attempts):
    """Enhanced waiting strategy between registration attempts to avoid detection"""
    if attempt < max_attempts - 1:
        info(f"[*] Waiting before next attempt...")
        min_time, max_time = DELAY_BETWEEN_ATTEMPTS

        # Increase wait time for each subsequent attempt to avoid rate limiting
        # Use an exponential backoff strategy for 2025 Facebook
        min_time += attempt * 3  # More aggressive base increase
        max_time += attempt * 5  # More aggressive ceiling increase

        # Add randomization factor - Facebook is sensitive to constant waiting patterns
        randomization = random.uniform(0.8, 1.2)  # Randomize by ±20%

        # Calculate actual wait with randomization
        actual_wait = random.uniform(min_time, max_time) * randomization
        info(f"[*] Waiting {actual_wait:.1f} seconds...")

        # Split the wait into smaller, variable chunks to mimic human behavior
        # Facebook can detect constant, uninterrupted waits
        total_waited = 0
        while total_waited < actual_wait:
            # Random chunk sizes to create natural pauses
            chunk_size = (
                random.uniform(0.7, 2.3)
                if total_waited < actual_wait * 0.7
                else random.uniform(0.3, 0.9)
            )
            chunk_size = min(chunk_size, actual_wait - total_waited)
            time.sleep(chunk_size)
            total_waited += chunk_size

            # Small chance to add a longer pause (simulating distraction)
            if random.random() < 0.1 and total_waited < actual_wait * 0.8:
                distraction_pause = random.uniform(1.5, 3.0)
                distraction_pause = min(distraction_pause, actual_wait - total_waited)
                time.sleep(distraction_pause)
                total_waited += distraction_pause

        return True
    return False


def extract_user_id(response, session):
    """Extract user ID from response or cookies (updated for 2025 Facebook)"""
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
        # New 2025 patterns
        r"/user/(\d+)",
        r"profile/(\d+)",
        r"viewer_id=(\d+)",
        r"account_id=(\d+)",
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
        # New 2025 patterns
        r'"subject_id":"(\d+)"',
        r'"ownerId":"(\d+)"',
        r'"accountId":"(\d+)"',
        r'"userIdentifier":"(\d+)"',
        r'"profileOwner":{"id":"(\d+)"',
        r'"registeredUser":{"id":"(\d+)"',
        r'"viewerId":"(\d+)"',
    ]

    for pattern in html_patterns:
        match = re.search(pattern, html)
        if match:
            user_id = match.group(1)
            info(f"[*] Extracted user ID from HTML: {user_id}")
            return user_id

    # Try to extract from JSON data if present
    try:
        json_data = json.loads(html)
        if isinstance(json_data, dict):
            # Check various JSON structures used by Facebook
            json_paths = [
                ["data", "user", "id"],
                ["data", "viewer", "id"],
                ["data", "account", "id"],
                ["data", "profile", "id"],
                ["data", "registration", "userID"],
                ["data", "mobileRegistration", "userID"],
                ["user", "id"],
                ["viewer", "id"],
                ["registration", "userID"],
                ["userInfo", "id"],
            ]

            for path in json_paths:
                current = json_data
                valid_path = True

                for key in path:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    else:
                        valid_path = False
                        break

                if (
                    valid_path
                    and isinstance(current, (str, int))
                    and str(current).isdigit()
                ):
                    user_id = str(current)
                    info(
                        f"[*] Extracted user ID from JSON path {'.'.join(path)}: {user_id}"
                    )
                    return user_id
    except:
        pass

    # Check for Facebook's Base64 encoded IDs
    encoded_data_patterns = [
        r'encoded_user_id=([^&"]+)',
        r'user_id_base64=([^&"]+)',
        r'b64_user_id=([^&"]+)',
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
        placeholder_id = f"FB{hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:10]}"
        info(f"[*] Using placeholder user ID: {placeholder_id}")
        return placeholder_id

    return user_id


def generate_browser_fingerprint():
    """Generate realistic browser fingerprint data to pass Facebook's security checks"""
    # Platform selection
    platform = random.choice(["Windows", "MacOS", "Android", "iOS"])

    if platform == "Windows":
        os_version = random.choice(["10", "11"])
        browser = random.choice(["Chrome", "Firefox", "Edge"])

        if browser == "Chrome":
            browser_version = f"{random.randint(120, 127)}.0.{random.randint(6000, 6999)}.{random.randint(100, 199)}"
        elif browser == "Firefox":
            browser_version = f"{random.randint(120, 127)}.0"
        else:  # Edge
            browser_version = f"{random.randint(120, 127)}.0.{random.randint(1000, 1999)}.{random.randint(40, 99)}"

    elif platform == "MacOS":
        os_version = f"{random.randint(13, 15)}.{random.randint(0, 6)}"
        browser = random.choice(["Chrome", "Safari", "Firefox"])

        if browser == "Chrome":
            browser_version = f"{random.randint(120, 127)}.0.{random.randint(6000, 6999)}.{random.randint(100, 199)}"
        elif browser == "Safari":
            browser_version = f"{random.randint(16, 19)}.{random.randint(0, 3)}"
        else:  # Firefox
            browser_version = f"{random.randint(120, 127)}.0"

    elif platform == "Android":
        os_version = f"{random.randint(11, 15)}"
        browser = random.choice(["Chrome", "Samsung Internet"])
        browser_version = f"{random.randint(120, 127)}.0.{random.randint(6000, 6999)}.{random.randint(100, 199)}"

    else:  # iOS
        os_version = f"{random.randint(16, 19)}.{random.randint(0, 6)}"
        browser = random.choice(["Safari", "Chrome"])

        if browser == "Safari":
            browser_version = f"{random.randint(16, 19)}.{random.randint(0, 3)}"
        else:  # Chrome
            browser_version = f"{random.randint(120, 127)}.0.{random.randint(6000, 6999)}.{random.randint(100, 199)}"

    # Generate screen properties based on platform
    if platform in ["Windows", "MacOS"]:
        screen_width = random.choice([1280, 1366, 1440, 1536, 1920, 2560, 3440, 3840])
        screen_height = random.choice([720, 768, 900, 1080, 1200, 1440, 1600, 2160])
        color_depth = random.choice([24, 30, 36, 48])
        pixel_ratio = random.choice([1, 1.25, 1.5, 2, 2.25, 2.5, 3])
    else:  # Mobile
        screen_width = random.choice([320, 360, 375, 390, 393, 412, 414, 428])
        screen_height = random.choice([640, 720, 800, 844, 851, 896, 915, 926])
        color_depth = 32
        pixel_ratio = random.choice([2, 2.5, 2.75, 3, 3.5, 4])

    # Generate hardware info
    cores = random.choice([2, 4, 6, 8, 10, 12, 16, 24, 32])
    memory = random.choice([2, 4, 8, 16, 32, 64])

    # Generate plugin and font counts
    plugins_count = (
        random.randint(0, 3) if platform in ["Android", "iOS"] else random.randint(1, 8)
    )
    fonts_count = (
        random.randint(10, 20)
        if platform in ["Android", "iOS"]
        else random.randint(30, 80)
    )

    # Generate hashes
    canvas_fp = hashlib.md5(
        f"{platform}{browser}{os_version}{screen_width}canvas".encode()
    ).hexdigest()
    webgl_fp = hashlib.md5(
        f"{platform}{browser}{os_version}{screen_width}webgl".encode()
    ).hexdigest()
    audio_fp = hashlib.md5(f"{platform}{browser}{os_version}audio".encode()).hexdigest()

    # Generate other browser features
    timezone_offset = random.randint(-720, 720)  # Minutes from GMT
    languages = (
        ["en-US", "en", "en-GB"] if random.random() < 0.7 else ["es-ES", "es", "en-US"]
    )
    do_not_track = random.choice([None, "1", "0"])

    # Return the fingerprint data
    return {
        "browser": {
            "name": browser,
            "version": browser_version,
            "userAgent": f"Mozilla/5.0 ({platform}; {os_version}) AppleWebKit/537.36 (KHTML, like Gecko) {browser}/{browser_version}",
            "language": languages[0],
            "languages": languages,
            "cookieEnabled": True,
            "doNotTrack": do_not_track,
        },
        "device": {
            "platform": platform,
            "os": {
                "name": platform,
                "version": os_version,
            },
            "screen": {
                "width": screen_width,
                "height": screen_height,
                "colorDepth": color_depth,
                "pixelDepth": color_depth,
                "availWidth": screen_width,
                "availHeight": screen_height - random.randint(20, 80),
                "orientation": (
                    "landscape" if screen_width > screen_height else "portrait"
                ),
            },
            "viewport": {
                "width": screen_width - random.randint(0, 20),
                "height": screen_height - random.randint(80, 150),
            },
            "pixelRatio": pixel_ratio,
            "hardwareConcurrency": cores,
            "deviceMemory": memory,
            "maxTouchPoints": (
                0 if platform in ["Windows", "MacOS"] else random.randint(1, 5)
            ),
        },
        "fingerprints": {
            "canvas": canvas_fp,
            "webgl": webgl_fp,
            "audio": audio_fp,
            "plugins": plugins_count,
            "fonts": fonts_count,
        },
        "connection": {
            "type": random.choice(["wifi", "4g", "5g", "ethernet"]),
            "downlink": (
                random.randint(5, 50)
                if platform in ["Windows", "MacOS"]
                else random.randint(2, 20)
            ),
            "rtt": random.randint(10, 100),
            "saveData": random.choice([True, False]),
        },
        "timezone": {
            "offset": timezone_offset,
        },
    }
