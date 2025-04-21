# Desktop web Facebook registration - Updated for 2025 security measures

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
from facebook.account import print_success, save_account
from config import FB_DESKTOP_URL, DESKTOP_USER_AGENTS, TIMEOUT


def register_facebook_desktop(email, user_details, proxies=None):
    """Register using desktop web interface with updated anti-detection for 2025 security"""
    try:
        # Create a session with modern browser behavior
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)

        # Set modern browser headers with up-to-date user agent
        user_agent = random.choice(DESKTOP_USER_AGENTS)
        user_details["user_agent"] = user_agent

        # Modern browser headers for 2025
        session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "max-age=0",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Priority": "high",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Viewport-Width": "1280",
                "Device-Memory": "8",
                "Dpr": "1.5",
                "Downlink": "10",
                "Rtt": "50",
            }
        )

        # Apply enhanced anti-detection measures (2025 version)
        session = apply_anti_detection_measures(session, FB_DESKTOP_URL, user_details)

        info(f"[*] Desktop web registration for {email}")

        # Step 1: Visit homepage with a more natural approach
        info("[*] Visiting Facebook homepage...")
        homepage_response = session.get(f"{FB_DESKTOP_URL}/", timeout=TIMEOUT)

        if homepage_response.status_code != 200:
            error(
                f"[×] Failed to access Facebook homepage: {homepage_response.status_code}"
            )
            return False, None

        # Debug cookies after initial homepage visit
        cookies_after_homepage = session.cookies.get_dict()
        cookie_keys = list(cookies_after_homepage.keys())
        initial_cookies = (
            ", ".join(cookie_keys[:5]) + "..."
            if len(cookie_keys) > 5
            else ", ".join(cookie_keys)
        )
        info(f"[*] Initial cookies: {initial_cookies}")

        # Add realistic delays between requests
        wait_with_jitter(2.5, 4.0)

        # Step 2: Access the registration page directly
        reg_url = f"{FB_DESKTOP_URL}/reg/"
        info(f"[*] Accessing registration page: {reg_url}")

        # Use the homepage as referrer to look more natural
        session.headers.update(
            {"Referer": FB_DESKTOP_URL, "Sec-Fetch-Site": "same-origin"}
        )

        reg_response = session.get(reg_url, timeout=TIMEOUT)

        if reg_response.status_code != 200:
            error(f"[×] Failed to access registration page: {reg_response.status_code}")
            return False, None

        # Get HTML content for parsing
        html = reg_response.text

        # Extract a snippet for debugging
        debug_snippet = html[:500] + "..." if len(html) > 500 else html
        debug_snippet = re.sub(r"\s+", " ", debug_snippet)
        info(f"[*] Page content snippet: {debug_snippet[:150]}...")

        # First check if the page has a registration form
        if "create an account" not in html.lower() and "sign up" not in html.lower():
            warn("[!] Registration form not detected on the page")
            return False, None

        # Step 3: Extract the form action URL
        form_action_match = re.search(
            r'<form[^>]*action="([^"]+)"[^>]*method="post"', html
        )
        if form_action_match:
            submit_url = form_action_match.group(1)
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found form submission URL: {submit_url}")
        else:
            # Fallback to static URL - use the reg.php endpoint which is more reliable
            submit_url = f"{FB_DESKTOP_URL}/reg/submit/"
            info(f"[*] Using fallback form submission URL: {submit_url}")

        # Extract hidden fields from the form
        hidden_fields = extract_hidden_fields(html)

        if hidden_fields:
            debug_fields = (
                ", ".join(list(hidden_fields.keys())[:5]) + "..."
                if len(hidden_fields) > 5
                else ", ".join(hidden_fields.keys())
            )
            info(f"[*] Found form fields: {debug_fields}")
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

        # Add standard form fields
        form_data["websubmit"] = "Sign Up"
        form_data["referrer"] = ""
        form_data["locale"] = "en_US"
        form_data["client_id"] = "1"
        form_data["terms"] = "on"
        form_data["datause"] = "on"
        form_data["ns"] = "0"
        form_data["did_skip"] = "true"
        form_data["name_suggest_elig"] = "false"
        form_data["did_use_age"] = "true"
        form_data["did_choose_custom_gender"] = "false"

        # Add any hidden fields found on the page
        if hidden_fields:
            form_data.update(hidden_fields)

        # Add security tokens - critical for Facebook to accept the form
        if "jazoest" not in form_data:
            # Generate a proper jazoest token
            value_to_hash = form_data.get("firstname", "") + form_data.get(
                "lastname", ""
            )
            jazoest_sum = (
                sum(ord(c) for c in value_to_hash) + 88
            )  # Facebook's algorithm
            form_data["jazoest"] = f"2{jazoest_sum}"

        if "lsd" not in form_data:
            # Generate a realistic LSD token
            form_data["lsd"] = generate_random_string(10)

        # Generate unique identifiers
        device_id = str(uuid.uuid4()).replace("-", "")
        request_id = generate_random_string(16)
        form_data["reg_instance"] = request_id
        current_time = int(time.time())

        # Add timestamp and encrypted password (Facebook's format)
        form_data["encpass"] = (
            f"#PWD_BROWSER:5:{current_time}:{user_details['password']}"
        )

        # Debug the form data to ensure fields are populated
        debug_data = {
            "firstname": form_data.get("firstname", ""),
            "lastname": form_data.get("lastname", ""),
            "reg_email__": form_data.get("reg_email__", ""),
            "birthday": f"{form_data.get('birthday_day', '')}/{form_data.get('birthday_month', '')}/{form_data.get('birthday_year', '')}",
            "sex": form_data.get("sex", ""),
        }
        info(f"[*] Form data to submit: {debug_data}")

        # Set up headers for the form submission
        form_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_DESKTOP_URL,
            "Referer": reg_url,
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Priority": "high",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        }

        # Add a natural delay before submission
        wait_with_jitter(3.0, 5.0)

        # Submit the form
        info("[*] Submitting registration form...")
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

        # Check cookies for success indicators
        cookies = session.cookies.get_dict()
        cookie_keys = list(cookies.keys())
        cookie_debug = (
            f"[*] Cookies received: {', '.join(cookie_keys[:5])}..."
            if len(cookie_keys) > 5
            else f"[*] Cookies received: {', '.join(cookie_keys)}"
        )
        info(cookie_debug)

        # Extract a snippet of the response for debugging
        debug_response = (
            response.text[:500] + "..." if len(response.text) > 500 else response.text
        )
        info(f"[*] Response content preview: {debug_response[:150]}...")

        # CRITICAL - Check for actual success indicators

        # 1. Check for c_user cookie - this is the most reliable indicator
        if "c_user" in cookies:
            user_id = cookies["c_user"]
            info(f"[+] Found c_user cookie with ID: {user_id}")

            # Generate Facebook profile URL
            profile_url = f"https://www.facebook.com/profile.php?id={user_id}"
            user_details["profile_url"] = profile_url

            success(f"[+] Desktop registration successful!")
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

                success(f"[+] Desktop registration successful via redirect!")
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

                success(f"[+] Desktop registration successful via content match!")
                success(f"[+] Profile URL: {profile_url}")

                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

        # If we reached here, registration likely failed - check for error messages
        error_text = extract_error_message(response.text)
        error(f"[×] Registration error: {error_text}")

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
        elif "cannot process your request" in response.text.lower():
            warn("[!] Facebook cannot process the request due to security measures")
        elif "something went wrong" in response.text.lower():
            warn("[!] Facebook encountered an issue with this registration")

        return False, None

    except requests.exceptions.RequestException as req_err:
        error(f"[×] Network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Error: {str(e)}")
        return False, None


# Helper functions remain the same
def extract_modern_form_data(html):
    """Extract form data from modern Facebook client-side rendered pages (2025 format)"""
    form_data = {}
    try:
        # Look for JSON configuration in script tags
        json_configs = re.findall(
            r"<script[^>]*>\s*(\{\"require\":\[.+?\})\s*</script>", html, re.DOTALL
        )
        for config in json_configs:
            try:
                # Clean up and normalize the JSON
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

        # Look for hardcoded form fields in JavaScript
        js_patterns = [
            r'name:"([^"]+)",value:"([^"]*)"',
            r'"formData":\s*{([^}]+)}',
            r'"field_names":\s*\[([^\]]+)\]',
        ]

        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            if matches:
                if pattern == r'name:"([^"]+)",value:"([^"]*)"':
                    # Direct name-value pairs
                    for name, value in matches:
                        if name and name not in form_data:
                            form_data[name] = value
                elif pattern == r'"formData":\s*{([^}]+)}':
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

        # Extract any hidden input fields the normal way as backup
        input_fields = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', html)
        for field in input_fields:
            name_match = re.search(r'name=["\']([^"\']+)["\']', field)
            value_match = re.search(r'value=["\']([^"\']*)["\']', field)

            if name_match:
                name = name_match.group(1)
                value = value_match.group(1) if value_match else ""
                form_data[name] = value

    except Exception as e:
        info(f"[*] Error extracting modern form data: {e}")

    return form_data
