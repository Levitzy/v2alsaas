# Mobile web Facebook registration - Updated for 2025 security measures

import re
import random
import requests
import time
import json
import uuid
from urllib.parse import urlencode, quote_plus

from utils.colors import error, info, success, warn
from utils.helpers import (
    extract_hidden_fields,
    extract_error_message,
    extract_user_id,
    simulate_human_behavior,
    wait_with_jitter,
)
from utils.generators import generate_form_data, generate_random_string
from facebook.security import (
    apply_anti_detection_measures,
    add_security_tokens,
    handle_security_challenges,
    simulate_realistic_form_filling,
)
from facebook.account import print_success, save_account, verify_account_created
from config import FB_MOBILE_URL, MOBILE_USER_AGENTS, TIMEOUT


def register_facebook_mobile(email, user_details, proxies=None):
    """Register using mobile web interface with updated anti-detection for 2025 security"""
    try:
        # Create a session with modern mobile browser behavior
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)

        # Set modern mobile browser headers with up-to-date user agent
        user_agent = random.choice(MOBILE_USER_AGENTS)
        user_details["user_agent"] = user_agent

        # Modern mobile browser headers for 2025
        session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Priority": "high",
                "Sec-Ch-Ua-Mobile": "?1",
                "Viewport-Width": "412",
                "Device-Memory": "4",
                "Dpr": "2.625",
                "Downlink": "5",
                "Rtt": "100",
                "Ect": "4g",
            }
        )

        # Apply enhanced anti-detection measures specific to mobile (2025 version)
        session = apply_anti_detection_measures(session, FB_MOBILE_URL, user_details)

        # Override mobile-specific settings
        session.headers.update(
            {
                "Sec-Ch-Ua-Mobile": "?1",
                "Sec-Ch-Ua-Platform": '"Android"',
                "Sec-Ch-Ua-Platform-Version": '"13.0"',
            }
        )

        info(f"[*] Mobile web registration for {email}")

        # Step 1: Visit mobile homepage
        info("[*] Visiting mobile Facebook site...")
        homepage_response = session.get(FB_MOBILE_URL, timeout=TIMEOUT)

        if homepage_response.status_code != 200:
            error(f"[×] Failed to access mobile site: {homepage_response.status_code}")
            return False, None

        # Debug cookies after initial homepage visit
        cookies_after_homepage = session.cookies.get_dict()
        cookie_keys = list(cookies_after_homepage.keys())
        initial_cookies = (
            ", ".join(cookie_keys[:5]) + "..."
            if len(cookie_keys) > 5
            else ", ".join(cookie_keys)
        )
        info(f"[*] Initial mobile cookies: {initial_cookies}")

        # Add realistic delays between requests
        wait_with_jitter(2.5, 4.0)

        # Step 2: Access the mobile registration page - use the direct /reg/ endpoint instead
        reg_url = f"{FB_MOBILE_URL}/reg/"
        info(f"[*] Accessing mobile registration page: {reg_url}")

        # Use the homepage as referrer
        session.headers.update(
            {"Referer": FB_MOBILE_URL, "Sec-Fetch-Site": "same-origin"}
        )

        reg_response = session.get(reg_url, timeout=TIMEOUT)

        if reg_response.status_code != 200:
            # If /reg/ fails, try the alternate r.php endpoint
            reg_url = f"{FB_MOBILE_URL}/r.php"
            info(f"[*] Trying alternate mobile registration: {reg_url}")
            reg_response = session.get(reg_url, timeout=TIMEOUT)

            if reg_response.status_code != 200:
                error(
                    f"[×] Failed to access mobile registration: {reg_response.status_code}"
                )
                return False, None

        # Get HTML content for parsing
        html = reg_response.text

        # Extract a snippet for debugging
        debug_snippet = html[:500] + "..." if len(html) > 500 else html
        debug_snippet = re.sub(r"\s+", " ", debug_snippet)
        info(f"[*] Mobile page content snippet: {debug_snippet[:150]}...")

        # First check if the page has a registration form
        if (
            "create an account" not in html.lower()
            and "sign up" not in html.lower()
            and "registration" not in html.lower()
        ):
            warn("[!] Mobile registration form not detected on the page")

            # Try more aggressive form detection
            has_form = "<form" in html.lower() and 'method="post"' in html.lower()
            if not has_form:
                warn("[!] No form element detected, cannot proceed with registration")
                return False, None
            else:
                info("[*] Found a form element, attempting to use it")

        # Extract form action URL for submission
        form_action_match = re.search(
            r'<form[^>]*action="([^"]+)"[^>]*method="post"', html
        )
        if form_action_match:
            submit_url = form_action_match.group(1)
            if not submit_url.startswith("http"):
                submit_url = FB_MOBILE_URL + submit_url
            info(f"[*] Found mobile form submission URL: {submit_url}")
        else:
            # Fallback to proper static URL
            submit_url = f"{FB_MOBILE_URL}/reg/submit/"
            info(f"[*] Using fallback mobile form submission URL: {submit_url}")

        # Extract hidden fields from the form
        hidden_fields = extract_hidden_fields(html)

        if hidden_fields:
            debug_fields = (
                ", ".join(list(hidden_fields.keys())[:5]) + "..."
                if len(hidden_fields) > 5
                else ", ".join(hidden_fields.keys())
            )
            info(f"[*] Found mobile form fields: {debug_fields}")
        else:
            # Try direct extraction of specific fields
            info("[*] No hidden fields found, trying direct extraction...")

            # Look for common fields in the HTML
            hidden_fields = {}
            field_patterns = [
                (r'name="jazoest"\s+value="([^"]+)"', "jazoest"),
                (r'name="lsd"\s+value="([^"]+)"', "lsd"),
                (r'name="reg_instance"\s+value="([^"]+)"', "reg_instance"),
                (r'name="phstamp"\s+value="([^"]+)"', "phstamp"),
            ]

            for pattern, field_name in field_patterns:
                match = re.search(pattern, html)
                if match:
                    hidden_fields[field_name] = match.group(1)
                    info(f"[*] Extracted field {field_name}: {match.group(1)[:10]}...")

        # Prepare form data with explicit field population - FIX THE POPULATION ISSUE HERE
        form_data = {}

        # Add the user information - explicit population
        form_data["firstname"] = user_details["first_name"]
        form_data["lastname"] = user_details["last_name"]
        form_data["reg_email__"] = email
        form_data["reg_email_confirmation__"] = email
        form_data["reg_passwd__"] = user_details["password"]

        # Add birthday fields
        form_data["birthday_day"] = str(user_details["birthday"].day)
        form_data["birthday_month"] = str(user_details["birthday"].month)
        form_data["birthday_year"] = str(user_details["birthday"].year)

        # Add gender (1=female, 2=male)
        form_data["sex"] = "1" if user_details["gender"] == "F" else "2"

        # Add mobile-specific fields
        form_data.update(
            {
                "referrer": "mobile_basic_reg",
                "locale": "en_US",
                "is_mobile": "true",
                "mobile_rtt": "150",
                "connection_quality": "EXCELLENT",
                "device_based_login_experiments": "true",
                "skip_email_verification": "false",
                "reg_from_mobile": "true",
                "source": "mobile_registration_form",
                "websubmit": "Sign Up",
                # Terms acceptance
                "terms": "on",
                "datause": "on",
                # Additional fields
                "ns": "0",
                "did_skip": "true",
                "did_use_age": "true",
                "did_choose_custom_gender": "false",
                "name_suggest_elig": "false",
                "was_logged_out": "false",
                "multi_step_form": "0",
                "dpr": "2.625",
                "contactpoint_label": "email",
            }
        )

        # Add any hidden fields found on the form
        if hidden_fields:
            form_data.update(hidden_fields)

        # Generate critical security tokens if missing
        current_time = int(time.time())

        # Add encrypted password
        form_data["encpass"] = (
            f"#PWD_BROWSER:5:{current_time}:{user_details['password']}"
        )

        # Add jazoest if missing
        if "jazoest" not in form_data:
            # Generate a proper jazoest token
            value_to_hash = form_data.get("firstname", "") + form_data.get(
                "lastname", ""
            )
            jazoest_sum = (
                sum(ord(c) for c in value_to_hash) + 88
            )  # Facebook's algorithm
            form_data["jazoest"] = f"2{jazoest_sum}"

        # Add lsd if missing
        if "lsd" not in form_data:
            form_data["lsd"] = generate_random_string(10)

        # Add unique instance ID if missing
        if "reg_instance" not in form_data:
            form_data["reg_instance"] = generate_random_string(16)

        # Add device ID
        device_id = str(uuid.uuid4()).replace("-", "")
        form_data["device_id"] = device_id

        # Debug data to verify fields are properly populated
        debug_data = {
            "firstname": form_data.get("firstname", ""),
            "lastname": form_data.get("lastname", ""),
            "reg_email__": form_data.get("reg_email__", ""),
            "birthday": f"{form_data.get('birthday_day', '')}/{form_data.get('birthday_month', '')}/{form_data.get('birthday_year', '')}",
            "sex": form_data.get("sex", ""),
        }
        info(f"[*] Mobile form data to submit: {debug_data}")

        # Set up headers for the form submission
        form_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_MOBILE_URL,
            "Referer": reg_url,
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        # Add a realistic delay before submission - LONGER DELAY TO AVOID TRIGGERS
        wait_with_jitter(3.0, 5.0)

        # Submit the form
        info("[*] Submitting mobile registration form...")
        response = session.post(
            submit_url,
            data=form_data,
            headers=form_headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Debug response
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Check cookies for success
        cookies = session.cookies.get_dict()
        cookie_keys = list(cookies.keys())
        cookie_debug = (
            f"[*] Cookies received: {', '.join(cookie_keys[:5])}..."
            if len(cookie_keys) > 5
            else f"[*] Cookies received: {', '.join(cookie_keys)}"
        )
        info(cookie_debug)

        # Extract response snippet for debugging
        debug_response = (
            response.text[:500] + "..." if len(response.text) > 500 else response.text
        )
        debug_response = re.sub(r"\s+", " ", debug_response)
        info(f"[*] Mobile response content preview: {debug_response[:150]}...")

        # CRITICAL - Check for actual success indicators

        # 1. Check for c_user cookie - this is the most reliable indicator
        if "c_user" in cookies:
            user_id = cookies["c_user"]
            info(f"[+] Found c_user cookie with ID: {user_id}")

            # Generate Facebook profile URL
            profile_url = f"https://www.facebook.com/profile.php?id={user_id}"
            user_details["profile_url"] = profile_url

            success(f"[+] Mobile registration successful!")
            success(f"[+] Profile URL: {profile_url}")

            print_success(email, user_id, user_details)
            save_account(email, user_details, user_id)
            return True, user_id

        # 2. Check for confirmation URL indicators
        success_indicators = [
            "confirmemail",
            "checkpoint",
            "confirmation",
            "welcome",
            "reg_success",
            "save-device",
            "c_user=",
        ]

        if any(indicator in response.url for indicator in success_indicators):
            # Try to extract user ID from URL or content
            user_id = extract_user_id(response, session)

            # Only consider valid if we got a real user ID (not "0" or "Unknown")
            if user_id and user_id not in ["0", "Unknown"]:
                # Generate Facebook profile URL
                profile_url = f"https://www.facebook.com/profile.php?id={user_id}"
                user_details["profile_url"] = profile_url

                success(f"[+] Mobile registration successful via redirect!")
                success(f"[+] Profile URL: {profile_url}")

                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

        # 3. Check for specific success mentions in the HTML
        success_phrases = [
            "account created",
            "registration successful",
            "welcome to facebook",
            "check your email",
            "confirm your email",
            "sent you an email",
            "verification link",
        ]

        if any(phrase in response.text.lower() for phrase in success_phrases):
            # Try to extract user ID from response content
            user_id = extract_user_id(response, session)

            # Only consider valid if we got a real user ID (not "0" or "Unknown")
            if user_id and user_id not in ["0", "Unknown"]:
                # Generate Facebook profile URL
                profile_url = f"https://www.facebook.com/profile.php?id={user_id}"
                user_details["profile_url"] = profile_url

                success(f"[+] Mobile registration successful via content match!")
                success(f"[+] Profile URL: {profile_url}")

                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

        # If we reached here, registration likely failed - check for error messages
        error_text = extract_error_message(response.text)
        error(f"[×] Mobile registration error: {error_text}")

        # Improve error messages - don't mention CAPTCHA directly
        if (
            "email address that you" in response.text.lower()
            or "email already in use" in response.text.lower()
        ):
            error("[!] Email address is already registered with Facebook")
        elif "try again later" in response.text.lower():
            warn(
                "[!] Facebook is temporarily limiting registrations from this location"
            )
        elif "something went wrong" in response.text.lower():
            warn(
                "[!] Facebook encountered an issue processing this registration attempt"
            )
        elif (
            "suspicious" in response.text.lower() or "unusual" in response.text.lower()
        ):
            warn(
                "[!] Facebook's security system detected unusual registration patterns"
            )

        return False, None

    except requests.exceptions.RequestException as req_err:
        error(f"[×] Mobile network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Mobile error: {str(e)}")
        return False, None


# Helper function for extracting form data from mobile pages
def extract_modern_mobile_form_data(html):
    """Extract form data from modern Facebook mobile pages (2025 format)"""
    form_data = {}
    try:
        # Look for mobile-specific JSON configuration
        json_configs = re.findall(
            r'<script[^>]*>\s*(\{"require":.+?\})\s*</script>', html, re.DOTALL
        )
        for config in json_configs:
            try:
                # Clean up the JSON
                config = config.replace('\\"', '"').replace('\\"', '"')

                # Try to find form field definitions
                field_matches = re.findall(
                    r'"name":"([^"]+)","value":"([^"]*)"', config
                )
                for name, value in field_matches:
                    if name and name not in form_data:
                        form_data[name] = value
            except:
                continue

        # Look for mobile Facebook's inline JS form data
        js_patterns = [
            r'name:"([^"]+)",value:"([^"]*)"',
            r'"formData":\s*{([^}]+)}',
            r'"field_names":\s*\[([^\]]+)\]',
            r'"mobileRegistrationFields":\s*{([^}]+)}',
        ]

        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            if matches:
                if pattern == r'name:"([^"]+)",value:"([^"]*)"':
                    # Direct name-value pairs
                    for name, value in matches:
                        if name and name not in form_data:
                            form_data[name] = value
                elif (
                    pattern == r'"formData":\s*{([^}]+)}'
                    or pattern == r'"mobileRegistrationFields":\s*{([^}]+)}'
                ):
                    # Form data object
                    for form_data_str in matches:
                        pairs = re.findall(r'"([^"]+)":"([^"]*)"', form_data_str)
                        for name, value in pairs:
                            if name and name not in form_data:
                                form_data[name] = value
                elif pattern == r'"field_names":\s*\[([^\]]+)\]':
                    # Just field names, values will be empty
                    for field_list in matches:
                        fields = re.findall(r'"([^"]+)"', field_list)
                        for field in fields:
                            if field and field not in form_data:
                                form_data[field] = ""

        # Extract from mobile form - mobile forms look different
        input_fields = re.findall(r'<input[^>]*type=["\'][^"\']*["\'][^>]*>', html)
        for field in input_fields:
            name_match = re.search(r'name=["\']([^"\']+)["\']', field)
            value_match = re.search(r'value=["\']([^"\']*)["\']', field)

            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                form_data[name] = value

    except Exception as e:
        info(f"[*] Error extracting modern mobile form data: {e}")

    return form_data
