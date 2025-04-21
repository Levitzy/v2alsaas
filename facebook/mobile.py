# Mobile web Facebook registration - Updated for 2025 security measures

import re
import random
import requests
import time
import json
import uuid
from urllib.parse import urlencode, quote_plus

from utils.colors import error, info, success
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

        # Step 1: Visit mobile homepage with natural approach
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
        wait_with_jitter(1.2, 2.5)

        # Step 2: Try multiple mobile registration entry points (2025 Facebook has several)
        mobile_reg_methods = [
            {"url": f"{FB_MOBILE_URL}/r.php", "desc": "legacy mobile registration"},
            {"url": f"{FB_MOBILE_URL}/reg/", "desc": "standard mobile registration"},
            {"url": f"{FB_MOBILE_URL}/signup", "desc": "modern mobile signup"},
            {
                "url": f"{FB_MOBILE_URL}/reg/spotlight/",
                "desc": "spotlight mobile registration",
            },
        ]

        reg_response = None
        reg_url = None
        successful_method = None

        for method in mobile_reg_methods:
            try:
                info(f"[*] Trying {method['desc']}: {method['url']}...")

                # Use the homepage as referrer to look more natural
                session.headers.update(
                    {"Referer": FB_MOBILE_URL, "Sec-Fetch-Site": "same-origin"}
                )

                method_response = session.get(method["url"], timeout=TIMEOUT)

                if method_response.status_code == 200:
                    reg_response = method_response
                    reg_url = method["url"]
                    successful_method = method["desc"]
                    info(f"[*] Successfully accessed {method['desc']}: {method['url']}")
                    break
                else:
                    info(
                        f"[*] {method['desc']} returned status code: {method_response.status_code}"
                    )
            except Exception as e:
                info(f"[*] Error trying {method['desc']}: {e}")
                continue

        if not reg_response or reg_response.status_code != 200:
            # Try one more approach - direct mobile API method
            info(
                "[*] Standard mobile registration pages failed, trying direct API approach..."
            )
            return direct_mobile_api_registration(session, email, user_details)

        # Get HTML content for parsing
        html = reg_response.text

        # Report which method worked and extract a snippet
        info(f"[*] Successfully accessed mobile registration via {successful_method}")

        # DEBUG: Save a small portion of the page to see what we're getting
        try:
            debug_snippet = html[:500] + "..." if len(html) > 500 else html
            debug_snippet = re.sub(r"\s+", " ", debug_snippet)
            info(f"[*] Mobile page content snippet: {debug_snippet[:150]}...")
        except Exception as e:
            info(f"[*] Couldn't extract debug snippet: {e}")

        # Step 3: Identify the form submission URL
        # Mobile Facebook uses different submission patterns

        # Method 1: Direct form action
        form_action = re.search(r'<form[^>]*action="([^"]+)"[^>]*method="post"', html)

        # Method 2: JavaScript API URL
        js_action = re.search(r'"submitURI":"([^"]+)"', html)

        # Method 3: Modern Mobile API endpoint
        api_action = re.search(r'"registrationGraphqlEndpoint":"([^"]+)"', html)

        # Process and select the submission URL
        if api_action:
            submit_url = api_action.group(1).replace("\\", "")
            if not submit_url.startswith("http"):
                submit_url = FB_MOBILE_URL + submit_url
            info(f"[*] Found mobile GraphQL submission URL: {submit_url}")
        elif form_action:
            submit_url = form_action.group(1)
            if not submit_url.startswith("http"):
                submit_url = FB_MOBILE_URL + submit_url
            info(f"[*] Found mobile form submission URL: {submit_url}")
        elif js_action:
            submit_url = js_action.group(1).replace("\\", "")
            if not submit_url.startswith("http"):
                submit_url = FB_MOBILE_URL + submit_url
            info(f"[*] Found JavaScript mobile submission URL: {submit_url}")
        else:
            # Default fallback - modern mobile endpoint in 2025
            submit_url = f"{FB_MOBILE_URL}/api/graphql/"
            info(f"[*] Using default mobile GraphQL submission URL: {submit_url}")

        # Extract form data and tokens
        hidden_fields = extract_hidden_fields(html)

        # Show debug info about fields found
        if hidden_fields:
            debug_fields = (
                ", ".join(list(hidden_fields.keys())[:5]) + "..."
                if len(hidden_fields) > 5
                else ", ".join(hidden_fields.keys())
            )
            info(f"[*] Found mobile form fields: {debug_fields}")
        else:
            info("[*] No hidden fields found in mobile registration page")

            # Try to extract modern mobile form data from JavaScript
            modern_form_data = extract_modern_mobile_form_data(html)
            if modern_form_data:
                hidden_fields = modern_form_data
                info(
                    f"[*] Extracted modern mobile form data with {len(hidden_fields)} fields"
                )
            else:
                info("[*] No modern form data found, trying direct mobile API...")

                # If still no form data, try direct API approach
                return direct_mobile_api_registration(session, email, user_details)

        # Prepare form data with user details for mobile
        form_data = generate_form_data(user_details, email, "mobile")

        # Add mobile-specific fields (2025 version)
        form_data.update(
            {
                "referrer": "mobile_basic_reg",
                "locale": "en_US",
                "multi_step_form": "1",
                "skip_suma": "0",
                "app_id": "",
                "contactpoint_label": "email",
                "is_mobile": "true",
                "viewport_width": "412",
                "pixel_ratio": "2.625",
                "connection_type": "4g",
                "connection_quality": "EXCELLENT",
                "device_platform": "android",
            }
        )

        # Merge hidden fields with form data
        form_data.update(hidden_fields)

        # Add security tokens - critical for modern Facebook
        form_data = add_security_tokens(form_data, html)

        # Generate unique request identifiers
        request_id = generate_random_string(16)
        device_id = str(uuid.uuid4()).replace("-", "")
        user_details["device_id"] = device_id
        current_time = int(time.time())

        # Add essential modern mobile fields
        form_data.update(
            {
                "reg_instance": request_id,
                "submission_request": "true",
                "encpass": f"#PWD_BROWSER:5:{current_time}:{user_details['password']}",  # Version 5 encryption
                "ccp": "2",
                "reg_impression_id": generate_random_string(16),
                "logger_id": generate_random_string(16),
                "frontend_env": "prod",
                "client_mutation_id": str(uuid.uuid4()),
                # Updated 2025 Facebook terms fields for mobile
                "terms": "on",
                "datause": "on",
                "dpr": "2.625",  # Mobile devices typically have higher DPR
                "execution_time": str(
                    int(time.time() * 1000)
                    - (int(time.time() * 1000) - random.randint(1000, 3000))
                ),
                "websubmit": "Sign Up",
                # Additional modern Facebook mobile fields
                "is_headless": "false",
                "is_touch": "true",
                "mobile_auth_flow": "native_account_creation",
                "is_notification_enabled": "false",
                "is_installation_event": "false",
                "mobile_app_version": "0",
            }
        )

        # Simulate realistic form filling with modern timing patterns
        form_data = simulate_realistic_form_filling(
            session, reg_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Check if this is a GraphQL endpoint
        is_graphql = "/api/graphql" in submit_url

        # Set up headers for form submission
        form_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_MOBILE_URL,
            "Referer": reg_url,
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors" if is_graphql else "navigate",
            "Sec-Fetch-Dest": "empty" if is_graphql else "document",
            "Priority": "high",
            "Accept": (
                "application/json, text/plain, */*"
                if is_graphql
                else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ),
            "X-FB-Friendly-Name": (
                "MobileRegistrationFormSubmitMutation" if is_graphql else None
            ),
            "X-FB-LSD": form_data.get("lsd", generate_random_string(10)),
            "X-ASBD-ID": "129477",
            "X-FB-Connection-Type": "MOBILE_UNKNOWN",
            "X-FB-Connection-Quality": "EXCELLENT",
            "X-FB-Client-Context": json.dumps({"deviceId": device_id}),
        }

        # Remove None values from headers
        form_headers = {k: v for k, v in form_headers.items() if v is not None}

        if is_graphql:
            # Modern mobile Facebook uses GraphQL for registration in 2025
            graphql_variables = {
                "input": {
                    "firstname": user_details["first_name"],
                    "lastname": user_details["last_name"],
                    "email": email,
                    "email_confirmation": email,
                    "encrypted_password": form_data["encpass"],
                    "birthday_day": int(user_details["birthday"].day),
                    "birthday_month": int(user_details["birthday"].month),
                    "birthday_year": int(user_details["birthday"].year),
                    "gender": "1" if user_details["gender"] == "F" else "2",
                    "registration_instance": form_data["reg_instance"],
                    "optIntoEmailMarketing": False,
                    "contactpoint_type": "email",
                    "client_mutation_id": form_data.get(
                        "client_mutation_id", str(uuid.uuid4())
                    ),
                    "device_id": device_id,
                    "jazoest": form_data.get("jazoest", ""),
                    "fb_dtsg": form_data.get("fb_dtsg", ""),
                    "lsd": form_data.get("lsd", ""),
                    "form_source": "mobile_registration_form",
                    "source": "mobile_reg",
                    "platform": "mobile",
                    "is_e2e_encryption_enabled": True,
                }
            }

            # Mobile GraphQL document ID (2025 version)
            doc_id = "5841363045952464"  # Mobile registration doc ID

            # Build GraphQL request
            graphql_data = {
                "doc_id": doc_id,
                "variables": json.dumps(graphql_variables),
                "fb_dtsg": form_data.get("fb_dtsg", ""),
                "jazoest": form_data.get("jazoest", ""),
                "lsd": form_data.get("lsd", ""),
                "__user": "0",
                "__a": "1",
                "__req": generate_random_string(4),
                "__rev": str(random.randint(1000000, 9999999)),
                "server_timestamps": "true",
            }

            # Use GraphQL form data
            submission_data = graphql_data
            form_headers["Content-Type"] = "application/x-www-form-urlencoded"

            info("[*] Using modern mobile GraphQL registration approach")
        else:
            # Use standard form submission approach
            submission_data = form_data
            debug_data = {
                k: form_data[k]
                for k in ["firstname", "lastname", "reg_email__"]
                if k in form_data
            }
            info(f"[*] Submitting mobile form with data: {debug_data}")

        # Step 4: Submit the registration form with modern approach
        info("[*] Submitting mobile registration form...")

        # More realistic pre-submission delay
        wait_with_jitter(0.5, 1.5)

        # Submit the form
        response = session.post(
            submit_url,
            data=submission_data,
            headers=form_headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Step 5: Enhanced result analysis with better debugging
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Debug cookies to check for success indicators
        cookies = session.cookies.get_dict()
        cookie_keys = list(cookies.keys())
        cookie_debug = (
            f"[*] Cookies received: {', '.join(cookie_keys[:5])}..."
            if len(cookie_keys) > 5
            else f"[*] Cookies received: {', '.join(cookie_keys)}"
        )
        info(cookie_debug)

        # Modern mobile Facebook often responds with JSON, especially for GraphQL
        try:
            json_response = response.json()
            info("[*] Received JSON response")

            # Check for registration success or redirect in JSON
            if "location" in json_response:
                redirect_url = json_response["location"]
                info(f"[*] Following redirect to: {redirect_url}")

                # Follow the redirect
                response = session.get(redirect_url, timeout=TIMEOUT)
                info(f"[*] New response URL: {response.url}")

            # Check for GraphQL response format
            elif "data" in json_response:
                graphql_data = json_response.get("data", {})
                if "mobileRegistration" in graphql_data:
                    registration_result = graphql_data["mobileRegistration"]

                    if registration_result.get("success") is True:
                        user_id = registration_result.get("userID") or "Unknown"
                        info(
                            f"[*] Mobile GraphQL registration successful with user ID: {user_id}"
                        )

                        # Handle success
                        success(f"[+] Mobile registration successful!")
                        print_success(email, user_id, user_details)
                        save_account(email, user_details, user_id)
                        return True, user_id

                    # Check for error or additional verification needed
                    elif "error" in registration_result:
                        error_msg = registration_result["error"].get(
                            "message", "Unknown error"
                        )
                        error(f"[×] Mobile GraphQL registration error: {error_msg}")

                    # Check for redirect URL in the GraphQL response
                    elif "redirectURL" in registration_result:
                        redirect_url = registration_result["redirectURL"]
                        info(
                            f"[*] Following mobile GraphQL redirect to: {redirect_url}"
                        )

                        # Follow the redirect
                        response = session.get(redirect_url, timeout=TIMEOUT)
                        info(f"[*] New response URL: {response.url}")

            # Facebook sometimes returns errors in a specific format
            elif "error" in json_response:
                error_data = json_response["error"]
                error_code = error_data.get("code", 0)
                error_msg = error_data.get("message", "Unknown error")
                error(f"[×] Mobile API error code {error_code}: {error_msg}")

                # Check for specific error types that require different handling
                if error_code in [
                    1357001,
                    1357003,
                    1357005,
                ]:  # Security or rate limit errors
                    error(
                        "[×] Security or rate limit triggered - waiting longer before retry"
                    )
                    wait_time = random.uniform(10, 15)
                    info(f"[*] Waiting {wait_time:.1f} seconds before next attempt")
                    time.sleep(wait_time)

                return False, None

        except ValueError:
            # Not JSON, continue with normal HTML response flow
            pass

        # Extract a snippet of the response for debugging
        debug_response = (
            response.text[:300] + "..." if len(response.text) > 300 else response.text
        )
        debug_response = re.sub(r"\s+", " ", debug_response)
        info(f"[*] Mobile response snippet: {debug_response[:150]}...")

        # Modern success indicators for mobile 2025
        success_indicators = [
            "confirmemail",
            "checkpoint",
            "welcome",
            "reg_success",
            "?next=",
            "home.php",
            "account_verified",
            "save-device",
            "login/save-device",
            "privacy_mutation_token",
            "c_user",
            "checkpoint/?next",
            "verification_method",
            "registration_confirmation",
            "registration/submitted/",
            "confirm_email",
            "welcome_interstitial",
            "reg_confirmed",
            "mobile_confirmation",
            "m.facebook.com/home",
        ]

        # Check for c_user cookie which indicates successful account creation
        cookie_success = "c_user" in cookies

        # Check for success in the response
        is_success = response.status_code in [200, 302] and (
            any(indicator in response.url for indicator in success_indicators)
            or cookie_success
            or any(indicator in response.text for indicator in success_indicators)
        )

        if is_success:
            # Extract user ID
            user_id = extract_user_id(response, session)

            # Handle success
            success(f"[+] Mobile registration successful!")
            print_success(email, user_id, user_details)
            save_account(email, user_details, user_id)

            # Try to follow up with a confirmation page visit if needed
            if "confirmemail" in response.url or "checkpoint" in response.url:
                try:
                    # Visit the confirmation page to complete the process
                    confirmation_response = session.get(response.url, timeout=TIMEOUT)
                    info("[*] Visited confirmation page")
                except Exception as e:
                    error(f"[!] Error visiting confirmation page: {e}")

            return True, user_id
        else:
            # Extract error message
            error_text = extract_error_message(response.text)
            error(f"[×] Mobile registration error: {error_text}")

            # Check for specific blocking messages for better debugging
            if any(
                block_term in error_text.lower()
                or block_term in response.url.lower()
                or block_term in response.text.lower()
                for block_term in [
                    "blocked",
                    "try again later",
                    "temporary",
                    "suspicious",
                    "too many",
                    "wait",
                    "unusual activity",
                    "security",
                    "rate limit",
                    "registration limit",
                    "too many accounts",
                    "automated",
                    "bot",
                    "captcha",
                    "verification",
                ]
            ):
                error("[×] Mobile registration blocked by Facebook security measures")

                # If we think it's rate limiting, wait longer before next attempt
                if any(
                    rate_term in error_text.lower()
                    or rate_term in response.text.lower()
                    for rate_term in [
                        "try again later",
                        "temporary",
                        "too many",
                        "wait",
                        "rate",
                        "limit",
                    ]
                ):
                    wait_time = random.uniform(8, 15)  # Longer wait for rate limiting
                    info(f"[*] Rate limiting detected, waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)

            return False, None

    except requests.exceptions.RequestException as req_err:
        error(f"[×] Mobile network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Mobile error: {e}")
        return False, None


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


def direct_mobile_api_registration(session, email, user_details):
    """Enhanced direct mobile API registration for 2025 Facebook security"""
    try:
        info("[*] Using direct mobile API registration method (2025 updated)")

        # Modern Facebook's mobile GraphQL API endpoint
        api_url = f"{FB_MOBILE_URL}/api/graphql/"

        # Generate necessary tokens
        request_id = generate_random_string(10)
        client_mutation_id = str(uuid.uuid4())
        device_id = user_details.get("device_id", str(uuid.uuid4()).replace("-", ""))
        timestamp = int(time.time())

        # Mobile GraphQL doc_id for registration (2025 version)
        doc_id = "5841363045952464"  # Mobile registration doc ID

        # Setup GraphQL variables for mobile registration
        variables = {
            "input": {
                "firstname": user_details["first_name"],
                "lastname": user_details["last_name"],
                "email": email,
                "email_confirmation": email,
                "encrypted_password": f"#PWD_BROWSER:5:{timestamp}:{user_details['password']}",
                "birthday_day": int(user_details["birthday"].day),
                "birthday_month": int(user_details["birthday"].month),
                "birthday_year": int(user_details["birthday"].year),
                "gender": "1" if user_details["gender"] == "F" else "2",
                "registration_instance": generate_random_string(16),
                "optIntoEmailMarketing": False,
                "contactpoint_type": "email",
                "client_mutation_id": client_mutation_id,
                "device_id": device_id,
                "create_security_checkpoints": False,
                "is_mobile_platform": True,
                "platform": "android",
                "flow_type": "mobile_registration",
                "source": "mobile_registration_form",
                "client_country_code": "US",
                "device_platform": "android",
                "is_enterprise_enrollee": False,
                "is_managed_device": False,
            }
        }

        # Generate a properly formatted jazoest for mobile
        jazoest_base = f"{device_id}{timestamp}"
        jazoest_sum = sum(ord(c) for c in jazoest_base)
        jazoest = f"2{jazoest_sum}"

        # Generate a valid fb_dtsg format for mobile (2025 pattern)
        fb_dtsg = f"AQHa{generate_random_string(8)}:{generate_random_string(8)}"

        # Prepare mobile API request data
        api_data = {
            "doc_id": doc_id,
            "variables": json.dumps(variables),
            "fb_dtsg": fb_dtsg,
            "jazoest": jazoest,
            "lsd": generate_random_string(10),
            "__user": "0",
            "__a": "1",
            "__req": request_id[:4],
            "__rev": str(random.randint(1000000, 9999999)),
            "__s": generate_random_string(8),
            "dpr": "2.625",  # Mobile DPR
            "__ccg": "EXCELLENT",
            "__hsi": str(timestamp),
            "__comet_req": "0",  # Not using Comet on mobile
            "fb_api_caller_class": "RelayModern",
            "fb_api_req_friendly_name": "MobileRegistrationFormSubmitMutation",
            "server_timestamps": "true",
        }

        # Set modern headers specific to mobile GraphQL API
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_MOBILE_URL,
            "Referer": f"{FB_MOBILE_URL}/r.php",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-FB-Friendly-Name": "MobileRegistrationFormSubmitMutation",
            "X-FB-LSD": api_data["lsd"],
            "X-ASBD-ID": "129477",
            "X-FB-Connection-Type": "MOBILE_4G",
            "X-FB-Connection-Quality": "EXCELLENT",
            "X-FB-Client-Context": json.dumps({"deviceId": device_id}),
            "X-FB-Device-Group": "mobile",
            "X-FB-Request-Analytics-Tags": "graphql",
            "Priority": "u=1, i",
            "Viewport-Width": "412",
            "Sec-Ch-Ua-Mobile": "?1",
            "Sec-Ch-Ua-Platform": '"Android"',
            "Sec-Ch-Ua-Platform-Version": '"13.0"',
        }

        # Submit the API request
        info("[*] Submitting mobile GraphQL registration mutation...")
        response = session.post(
            api_url,
            data=urlencode(api_data),
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        info(f"[*] Mobile API response status: {response.status_code}")

        # Check cookies for success
        cookies = session.cookies.get_dict()
        if "c_user" in cookies:
            user_id = cookies["c_user"]
            success(f"[+] Mobile API registration successful!")
            print_success(email, user_id, user_details)
            save_account(email, user_details, user_id)
            return True, user_id

        # Try to parse response as JSON
        try:
            result = response.json()

            # Check for GraphQL success response
            if "data" in result:
                if "mobileRegistration" in result["data"]:
                    registration_data = result["data"]["mobileRegistration"]

                    if registration_data.get("success") is True:
                        user_id = registration_data.get("userID", "Unknown")
                        success(f"[+] Mobile GraphQL registration successful!")
                        print_success(email, user_id, user_details)
                        save_account(email, user_details, user_id)
                        return True, user_id

                    elif "redirectURL" in registration_data:
                        # Need to follow a redirect for verification
                        redirect_url = registration_data["redirectURL"]
                        info(f"[*] Following mobile redirect to: {redirect_url}")

                        redirect_response = session.get(redirect_url, timeout=TIMEOUT)
                        if "c_user" in session.cookies.get_dict():
                            user_id = session.cookies.get_dict()["c_user"]
                            success(
                                f"[+] Mobile registration successful after redirect!"
                            )
                            print_success(email, user_id, user_details)
                            save_account(email, user_details, user_id)
                            return True, user_id

                # Alternative registration endpoints
                elif "registration" in result["data"]:
                    registration_data = result["data"]["registration"]

                    if registration_data.get("success") is True:
                        user_id = registration_data.get("userID", "Unknown")
                        success(f"[+] Mobile alternative registration successful!")
                        print_success(email, user_id, user_details)
                        save_account(email, user_details, user_id)
                        return True, user_id

            # Facebook sometimes returns a success indicator in other formats
            if result.get("success") is True:
                user_id = result.get("userID", "Unknown")
                success(f"[+] Mobile API registration successful!")
                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

            # Debug the JSON response
            debug_result = (
                str(result)[:150] + "..." if len(str(result)) > 150 else str(result)
            )
            info(f"[*] Mobile API response: {debug_result}")

            # Check for error message in the response
            if "errors" in result:
                error_messages = []
                for err in result["errors"]:
                    if "message" in err:
                        error_messages.append(err["message"])

                error_text = "; ".join(error_messages)
                error(f"[×] Mobile GraphQL error: {error_text}")

                # Handle rate limiting specifically
                if any(
                    term in error_text.lower()
                    for term in ["rate", "limit", "wait", "try again"]
                ):
                    wait_time = random.uniform(10, 20)
                    info(f"[*] Rate limiting detected, waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)

            elif "error" in result:
                error_data = result["error"]
                if isinstance(error_data, dict):
                    error_msg = error_data.get("message", "Unknown error")
                    error_code = error_data.get("code", 0)
                    error(f"[×] Mobile API error code {error_code}: {error_msg}")
                else:
                    error(f"[×] Mobile API error: {error_data}")

        except Exception as e:
            error(f"[×] Error parsing mobile API response: {e}")
            info(f"[*] Raw mobile response text: {response.text[:100]}...")

        # If we reach here, API registration failed
        error(f"[×] Mobile API registration failed")
        return False, None

    except Exception as e:
        error(f"[×] Mobile API registration error: {e}")
        return False, None
