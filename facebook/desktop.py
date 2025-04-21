# Desktop web Facebook registration - Updated for 2025 security measures

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
        wait_with_jitter(1.5, 3.0)

        # Step 2: Get the modern signup page - Facebook now uses different signup flows
        # Try several methods to find the working one
        signup_methods = [
            {"url": f"{FB_DESKTOP_URL}/reg/", "desc": "standard registration page"},
            {"url": f"{FB_DESKTOP_URL}/signup", "desc": "modern signup flow"},
            {
                "url": f"{FB_DESKTOP_URL}/reg/spotlight/",
                "desc": "spotlight registration",
            },
            {"url": f"{FB_DESKTOP_URL}/r.php", "desc": "legacy registration endpoint"},
        ]

        signup_response = None
        signup_url = None
        successful_method = None

        for method in signup_methods:
            try:
                info(f"[*] Trying {method['desc']}: {method['url']}...")

                # Use the homepage as referrer to look more natural
                session.headers.update(
                    {"Referer": FB_DESKTOP_URL, "Sec-Fetch-Site": "same-origin"}
                )

                method_response = session.get(method["url"], timeout=TIMEOUT)

                if method_response.status_code == 200:
                    signup_response = method_response
                    signup_url = method["url"]
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

        if not signup_response or signup_response.status_code != 200:
            # Try one more approach - direct API method
            info(
                "[*] Standard registration pages failed, trying direct API approach..."
            )
            return direct_api_registration(session, email, user_details)

        # Get the HTML content for parsing
        html = signup_response.text

        # Report which method worked and extract a snippet
        info(f"[*] Successfully accessed registration via {successful_method}")

        # DEBUG: Save a small portion of the page to see what we're getting
        try:
            debug_snippet = html[:500] + "..." if len(html) > 500 else html
            debug_snippet = re.sub(r"\s+", " ", debug_snippet)
            info(f"[*] Page content snippet: {debug_snippet[:150]}...")
        except Exception as e:
            info(f"[*] Couldn't extract debug snippet: {e}")

        # Step 3: Identify the form submission URL using multiple methods
        # Modern Facebook often hides the form submission URL in JavaScript

        # Method 1: Direct form action
        form_action = re.search(r'<form[^>]*action="([^"]+)"[^>]*method="post"', html)

        # Method 2: JavaScript resource
        js_action = re.search(r'"submitURI":"([^"]+)"', html)

        # Method 3: Facebook's modern signup handler
        modern_action = re.search(r'"registrationSubmitURI":"([^"]+)"', html)

        # Method 4: API endpoint
        api_action = re.search(r'"apiEndpoint":"([^"]+)"', html)

        # Process and select the submission URL
        if modern_action:
            submit_url = modern_action.group(1).replace("\\", "")
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found modern registration submission URL: {submit_url}")
        elif form_action:
            submit_url = form_action.group(1)
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found form submission URL: {submit_url}")
        elif js_action:
            submit_url = js_action.group(1).replace("\\", "")
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found JavaScript submission URL: {submit_url}")
        elif api_action:
            submit_url = api_action.group(1).replace("\\", "")
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found API submission URL: {submit_url}")
        else:
            # Default fallback - this is the standard endpoint in 2025
            submit_url = f"{FB_DESKTOP_URL}/api/graphql/"
            info(f"[*] Using default 2025 GraphQL submission URL: {submit_url}")

        # Extract form data and tokens
        hidden_fields = extract_hidden_fields(html)

        # Show debug info about what fields we found
        if hidden_fields:
            debug_fields = (
                ", ".join(list(hidden_fields.keys())[:5]) + "..."
                if len(hidden_fields) > 5
                else ", ".join(hidden_fields.keys())
            )
            info(f"[*] Found form fields: {debug_fields}")
        else:
            info("[*] No hidden fields found using standard methods")

            # Try to look for modern Facebook's client-side rendered form data
            # Facebook has moved more to client-side rendering in 2025
            modern_form_data = extract_modern_form_data(html)
            if modern_form_data:
                hidden_fields = modern_form_data
                info(f"[*] Extracted modern form data with {len(hidden_fields)} fields")
            else:
                info("[*] No modern form data found, trying alternate approach...")

                # If form fields not found, try a more direct API approach
                return direct_api_registration(session, email, user_details)

        # Prepare form data with user details
        form_data = generate_form_data(user_details, email, "desktop")

        # Merge hidden fields with form data
        form_data.update(hidden_fields)

        # Add security tokens - very important for 2025 Facebook
        form_data = add_security_tokens(form_data, html)

        # Generate unique request/submission identifiers
        request_id = generate_random_string(16)
        device_id = str(uuid.uuid4()).replace("-", "")
        user_details["device_id"] = device_id
        current_time = int(time.time())

        # Add essential fields needed by Facebook's 2025 registration system
        form_data.update(
            {
                "reg_instance": request_id,
                "submission_request": "true",
                "encpass": f"#PWD_BROWSER:5:{current_time}:{user_details['password']}",  # Version 5 encryption
                "ccp": "2",
                "reg_impression_id": generate_random_string(16),
                "ns": "0",
                "app_id": "0",
                "logger_id": generate_random_string(16),
                "frontend_env": "prod",
                "client_mutation_id": str(uuid.uuid4()),
                # Updated 2025 Facebook terms fields
                "terms": "on",
                "datause": "on",
                "dpr": str(random.choice([1, 1.5, 2, 2.5])),
                "contactpoint_label": "email",
                "execution_time": str(
                    int(time.time() * 1000)
                    - (int(time.time() * 1000) - random.randint(1500, 4000))
                ),
                "websubmit": "Sign Up",
                # Additional modern Facebook fields
                "is_headline_shown": "true",
                "age_step_input": "",
                "__user": "0",  # Non-logged in user
                "use_image_protection": "true",
                "context": "registration",
                "anti_detection_disabled": "false",
                # Email verification related flags
                "skip_email_confirmation": "false",
                "use_nonce_oauth": "true",
            }
        )

        # Simulate realistic form filling with modern timing patterns
        form_data = simulate_realistic_form_filling(
            session, signup_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Set up headers for the form submission with more browser-like behavior
        form_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_DESKTOP_URL,
            "Referer": signup_url,
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Priority": "high",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "X-FB-Friendly-Name": "RegistrationFormSubmitMutation",
            "X-FB-LSD": form_data.get("lsd", generate_random_string(10)),
            "X-ASBD-ID": "129477",
            "X-FB-Client-Context": json.dumps({"deviceId": device_id}),
        }

        # Check if modern GraphQL API is being used
        is_graphql = "/api/graphql" in submit_url

        if is_graphql:
            # Modern Facebook uses GraphQL for registration in 2025
            # Prepare a proper GraphQL request
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
                    "form_source": "registration_form",
                    "source": "registration",
                }
            }

            # Build the GraphQL request
            graphql_data = {
                "doc_id": "5763936226994235",  # This is the GraphQL document ID for registration
                "variables": json.dumps(graphql_variables),
                "fb_dtsg": form_data.get("fb_dtsg", ""),
                "jazoest": form_data.get("jazoest", ""),
                "lsd": form_data.get("lsd", ""),
                "__user": "0",
                "__a": "1",
                "__req": generate_random_string(4),
                "__rev": str(random.randint(1000000, 9999999)),
            }

            # Use GraphQL form data
            submission_data = graphql_data
            form_headers["Content-Type"] = "application/x-www-form-urlencoded"

            info("[*] Using modern GraphQL registration approach")
        else:
            # Use standard form submission approach
            submission_data = form_data
            debug_data = {
                k: form_data[k]
                for k in ["firstname", "lastname", "reg_email__"]
                if k in form_data
            }
            info(f"[*] Submitting form with data: {debug_data}")

        # Step 4: Submit the registration form with modernized approach
        info("[*] Submitting registration form...")

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

        # Step 5: Enhanced result analysis
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

        # Modern Facebook often responds with JSON, especially for GraphQL
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
                if "registration" in graphql_data:
                    registration_result = graphql_data["registration"]

                    if registration_result.get("success") is True:
                        user_id = registration_result.get("userID") or "Unknown"
                        info(
                            f"[*] GraphQL registration successful with user ID: {user_id}"
                        )

                        # Handle success
                        success(f"[+] Desktop registration successful!")
                        print_success(email, user_id, user_details)
                        save_account(email, user_details, user_id)
                        return True, user_id

                    # Check for error or additional verification needed
                    elif "error" in registration_result:
                        error_msg = registration_result["error"].get(
                            "message", "Unknown error"
                        )
                        error(f"[×] GraphQL registration error: {error_msg}")

                    # Check for redirect URL in the GraphQL response
                    elif "redirectURL" in registration_result:
                        redirect_url = registration_result["redirectURL"]
                        info(f"[*] Following GraphQL redirect to: {redirect_url}")

                        # Follow the redirect
                        response = session.get(redirect_url, timeout=TIMEOUT)
                        info(f"[*] New response URL: {response.url}")

            # Facebook sometimes returns errors in a specific format
            elif "error" in json_response:
                error_data = json_response["error"]
                error_code = error_data.get("code", 0)
                error_msg = error_data.get("message", "Unknown error")
                error(f"[×] API error code {error_code}: {error_msg}")

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
        info(f"[*] Response snippet: {debug_response[:150]}...")

        # Modern success indicators for 2025
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
            success(f"[+] Desktop registration successful!")
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
            error(f"[×] Registration error: {error_text}")

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
                error("[×] Registration blocked by Facebook security measures")

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
        error(f"[×] Network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Error: {e}")
        return False, None


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


def direct_api_registration(session, email, user_details):
    """Enhanced direct API registration for 2025 Facebook security"""
    try:
        info("[*] Using direct API registration method (2025 updated)")

        # Modern Facebook's GraphQL API endpoint for registration
        api_url = f"{FB_DESKTOP_URL}/api/graphql/"

        # Generate necessary modern tokens
        request_id = generate_random_string(10)
        client_mutation_id = str(uuid.uuid4())
        device_id = user_details.get("device_id", str(uuid.uuid4()).replace("-", ""))
        timestamp = int(time.time())

        # Modern GraphQL doc_id for registration (2025 version)
        doc_id = (
            "5763936226994235"  # This changes periodically, using a recent valid one
        )

        # Setup GraphQL variables for the registration mutation
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
                "flow_type": "registration",
                "source": "registration_form",
            }
        }

        # Generate a properly formatted jazoest
        jazoest_base = f"{device_id}{timestamp}"
        jazoest_sum = sum(ord(c) for c in jazoest_base)
        jazoest = f"2{jazoest_sum}"

        # Generate a valid fb_dtsg format (2025 pattern)
        fb_dtsg = f"AQHa{generate_random_string(8)}:{generate_random_string(8)}"

        # Prepare API request data
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
            "dpr": "1",
            "__ccg": "EXCELLENT",
            "__hsi": str(timestamp),
            "__comet_req": "1",
            "fb_api_caller_class": "RelayModern",
            "fb_api_req_friendly_name": "RegistrationFormSubmitMutation",
            "server_timestamps": "true",
        }

        # Set modern headers specific to GraphQL API
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_DESKTOP_URL,
            "Referer": f"{FB_DESKTOP_URL}/r.php",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-FB-Friendly-Name": "RegistrationFormSubmitMutation",
            "X-FB-LSD": api_data["lsd"],
            "X-ASBD-ID": "129477",
            "X-FB-Connection-Quality": "EXCELLENT",
            "Priority": "u=1, i",
            "X-FB-Client-Context": json.dumps({"deviceId": device_id}),
        }

        # Submit the API request
        info("[*] Submitting GraphQL registration mutation...")
        response = session.post(
            api_url,
            data=urlencode(api_data),
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        info(f"[*] API response status: {response.status_code}")

        # Check cookies for success
        cookies = session.cookies.get_dict()
        if "c_user" in cookies:
            user_id = cookies["c_user"]
            success(f"[+] API registration successful!")
            print_success(email, user_id, user_details)
            save_account(email, user_details, user_id)
            return True, user_id

        # Try to parse response as JSON
        try:
            result = response.json()

            # Check for GraphQL success response
            if "data" in result and "registration" in result["data"]:
                registration_data = result["data"]["registration"]

                if registration_data.get("success") is True:
                    user_id = registration_data.get("userID", "Unknown")
                    success(f"[+] GraphQL registration successful!")
                    print_success(email, user_id, user_details)
                    save_account(email, user_details, user_id)
                    return True, user_id

                elif "redirectURL" in registration_data:
                    # Need to follow a redirect for verification
                    redirect_url = registration_data["redirectURL"]
                    info(f"[*] Following redirect to: {redirect_url}")

                    redirect_response = session.get(redirect_url, timeout=TIMEOUT)
                    if "c_user" in session.cookies.get_dict():
                        user_id = session.cookies.get_dict()["c_user"]
                        success(f"[+] Registration successful after redirect!")
                        print_success(email, user_id, user_details)
                        save_account(email, user_details, user_id)
                        return True, user_id

            # Facebook sometimes returns a success indicator or error in other formats
            if result.get("success") is True:
                user_id = result.get("userID", "Unknown")
                success(f"[+] API registration successful!")
                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

            # Debug the JSON response
            debug_result = (
                str(result)[:150] + "..." if len(str(result)) > 150 else str(result)
            )
            info(f"[*] API response: {debug_result}")

            # Check for error message in the response
            if "errors" in result:
                error_messages = []
                for err in result["errors"]:
                    if "message" in err:
                        error_messages.append(err["message"])

                error_text = "; ".join(error_messages)
                error(f"[×] GraphQL error: {error_text}")

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
                    error(f"[×] API error code {error_code}: {error_msg}")
                else:
                    error(f"[×] API error: {error_data}")

        except Exception as e:
            error(f"[×] Error parsing API response: {e}")
            info(f"[*] Raw response text: {response.text[:100]}...")

        # If we reach here, API registration failed
        error(f"[×] API registration failed")
        return False, None

    except Exception as e:
        error(f"[×] API registration error: {e}")
        return False, None
