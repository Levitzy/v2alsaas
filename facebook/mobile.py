# Mobile web Facebook registration

import re
import random
import requests
import time
import json
from urllib.parse import urlencode

from utils.colors import error, info, success
from utils.helpers import (
    extract_hidden_fields,
    extract_error_message,
    extract_user_id,
    simulate_human_behavior,
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
    """Register using mobile web interface with improved approach and anti-detection"""
    try:
        # Create a session
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)

        # Set headers with random user agent
        user_agent = random.choice(MOBILE_USER_AGENTS)
        user_details["user_agent"] = user_agent  # Store for fingerprinting

        session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "max-age=0",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Priority": "high",
            }
        )

        # Apply anti-detection measures specific to mobile
        session = apply_anti_detection_measures(session, FB_MOBILE_URL, user_details)
        # Override some settings for mobile
        session.headers.update({"Sec-Ch-Ua-Mobile": "?1"})

        info(f"[*] Mobile web registration for {email}")

        # Step 1: Visit mobile site to get initial cookies (more naturally)
        info("[*] Visiting mobile Facebook site...")
        response = session.get(FB_MOBILE_URL, timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access mobile site: {response.status_code}")
            return False, None

        # Add realistic delay between requests
        time.sleep(random.uniform(1.0, 2.5))

        # Step 2: Try different registration URLs
        mobile_reg_urls = [
            f"{FB_MOBILE_URL}/r.php",  # Old style
            f"{FB_MOBILE_URL}/reg/",  # New style
            f"{FB_MOBILE_URL}/signup",  # Alternative
        ]

        # Try each URL until one works
        reg_response = None
        for url in mobile_reg_urls:
            info(f"[*] Trying registration URL: {url}...")

            # Add referrer to make it look more natural
            session.headers.update({"Referer": FB_MOBILE_URL})

            try:
                reg_response = session.get(url, timeout=TIMEOUT)
                if reg_response.status_code == 200:
                    reg_url = url
                    info(f"[*] Successfully accessed mobile registration page: {url}")
                    break
            except Exception as e:
                info(f"[*] Error accessing {url}: {e}")
                continue

        if not reg_response or reg_response.status_code != 200:
            error(f"[×] Failed to access any mobile registration page")
            return False, None

        # Get content for extraction and debugging
        html = reg_response.text

        # DEBUG: Check what type of page we're seeing
        debug_snippet = html[:1000] + "..." if len(html) > 1000 else html
        debug_snippet = re.sub(r"\s+", " ", debug_snippet)
        info(f"[*] Mobile page content snippet: {debug_snippet[:150]}...")

        # Try to find direct form action URL from the page
        form_action = re.search(r'<form[^>]*action="([^"]+)"[^>]*method="post"', html)
        if form_action:
            submit_url = form_action.group(1)
            if not submit_url.startswith("http"):
                if submit_url.startswith("/"):
                    submit_url = FB_MOBILE_URL + submit_url
                else:
                    submit_url = FB_MOBILE_URL + "/" + submit_url
            info(f"[*] Found form submission URL: {submit_url}")
        else:
            # Default fallback
            submit_url = f"{FB_MOBILE_URL}/reg/submit/"
            info(f"[*] Using default submission URL: {submit_url}")

        # Extract form data
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

            # If we can't find the form fields, try an alternative approach
            # Mobile pages may be heavily JavaScript-driven
            info("[*] Attempting direct mobile API registration...")
            return direct_mobile_api_registration(session, email, user_details)

        # Prepare form data with user details for mobile
        form_data = generate_form_data(user_details, email, "mobile")

        # Add mobile-specific fields
        form_data.update(
            {
                "referrer": "mobile_basic_reg",
                "locale": "en_US",
                "multi_step_form": "1",
                "skip_suma": "0",
                "app_id": "",
                "contactpoint_label": "email",
            }
        )

        # Merge hidden fields
        form_data.update(hidden_fields)

        # Add security tokens (critical for FB registration)
        form_data = add_security_tokens(form_data, html)

        # Simulate realistic form filling
        form_data = simulate_realistic_form_filling(
            session, reg_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Ensure modern Facebook required fields are present
        timestamp = int(time.time())
        if "encpass" not in form_data and "reg_passwd__" in form_data:
            form_data["encpass"] = (
                f"#PWD_BROWSER:0:{timestamp}:{form_data['reg_passwd__']}"
            )

        form_data.update(
            {"terms": "on", "datause": "on", "acknowledge_understanding": "on"}
        )

        # Step 4: Submit the registration form with improved headers
        headers = {
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

        # Debug: Show submission data
        try:
            debug_data = {
                k: form_data[k] for k in ["firstname", "lastname", "reg_email__"]
            }
            info(f"[*] Submitting mobile form with data: {debug_data}")
        except Exception:
            pass

        info("[*] Submitting mobile registration form...")
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Step 5: Analyze the result with detailed debugging
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Debug cookies to check for success
        cookies = session.cookies.get_dict()
        cookie_keys = list(cookies.keys())
        info(
            f"[*] Cookies received: {', '.join(cookie_keys[:5])}..."
            if len(cookie_keys) > 5
            else f"[*] Cookies received: {', '.join(cookie_keys)}"
        )

        # Try to detect if response is JSON
        try:
            json_response = response.json()
            info("[*] Received JSON response")
            info(f"[*] JSON keys: {list(json_response.keys())}")

            # Check for redirect URL in JSON
            if "location" in json_response:
                redirect_url = json_response["location"]
                info(f"[*] Following redirect to: {redirect_url}")

                # Follow the redirect
                response = session.get(redirect_url, timeout=TIMEOUT)
                info(f"[*] New response URL: {response.url}")
        except Exception:
            # Not JSON, continue with normal flow
            pass

        # Extract a snippet of the response for debugging
        debug_response = (
            response.text[:200] + "..." if len(response.text) > 200 else response.text
        )
        debug_response = re.sub(r"\s+", " ", debug_response)
        info(f"[*] Mobile response snippet: {debug_response}")

        # Enhanced success detection with multiple indicators
        success_indicators = [
            "confirmemail",
            "checkpoint",
            "welcome",
            "save-device",
            "login/save-device",
            "reg_success",
            "next=",
            "home.php",
            "privacy_mutation_token",
            "c_user",
        ]

        # Also check for c_user cookie which indicates successful account creation
        cookie_success = "c_user" in cookies

        if response.status_code in [200, 302] and (
            any(indicator in response.url for indicator in success_indicators)
            or cookie_success
        ):

            # Extract user ID
            user_id = extract_user_id(response, session)

            # Handle success
            success(f"[+] Mobile registration successful!")
            print_success(email, user_id, user_details)
            save_account(email, user_details, user_id)

            # Try to follow up with a confirmation visit if needed
            if "confirmemail" in response.url or "checkpoint" in response.url:
                try:
                    # Visit the confirmation page to complete the process
                    confirmation_response = session.get(response.url, timeout=TIMEOUT)
                    info("[*] Visited confirmation page")
                except Exception as e:
                    error(f"[!] Error visiting confirmation page: {e}")

            return True, user_id
        else:
            # Try to extract error message
            error_text = extract_error_message(response.text)
            error(f"[×] Registration error: {error_text}")

            # Check for specific failure patterns
            if any(
                pattern in response.text.lower()
                for pattern in ["suspicious", "security", "checkpoint"]
            ):
                error("[×] Security check triggered during registration")
            elif any(
                pattern in response.text.lower()
                for pattern in ["too many", "rate", "limit", "try again later"]
            ):
                error("[×] Rate limiting detected")
            elif any(
                pattern in response.text.lower()
                for pattern in ["confirm your identity", "verify"]
            ):
                error("[×] Account verification required")
            elif any(
                pattern in response.text.lower()
                for pattern in ["already exists", "already registered"]
            ):
                error("[×] Email already registered")
            else:
                error(
                    "[×] Unknown registration error - Facebook may have changed their registration flow"
                )

            # Wait longer if rate limited
            if any(
                rate_term in error_text.lower() or rate_term in response.text.lower()
                for rate_term in ["try again later", "temporary", "too many", "wait"]
            ):
                wait_time = random.uniform(5, 10)
                info(f"[*] Rate limiting detected, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)

            return False, None

    except requests.exceptions.RequestException as req_err:
        error(f"[×] Network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Error: {e}")
        return False, None


def direct_mobile_api_registration(session, email, user_details):
    """Attempt registration using direct mobile API method"""
    try:
        info("[*] Using direct mobile API registration method")

        # Facebook's mobile API endpoint for registration
        api_url = f"{FB_MOBILE_URL}/api/graphql/"

        # Generate necessary request identifiers
        request_id = generate_random_string(8)
        timestamp = int(time.time())

        # Prepare direct registration data optimized for mobile API
        api_data = {
            "firstname": user_details["first_name"],
            "lastname": user_details["last_name"],
            "reg_email__": email,
            "reg_email_confirmation__": email,
            "encpass": f"#PWD_BROWSER:0:{timestamp}:{user_details['password']}",
            "birthday_day": user_details["birthday"].day,
            "birthday_month": user_details["birthday"].month,
            "birthday_year": user_details["birthday"].year,
            "sex": "1" if user_details["gender"] == "F" else "2",
            "did_use_age": "true",
            "contactpoint_label": "email",
            "referrer": "mobile_basic_reg",
            "locale": "en_US",
            "client_country_code": "US",
            "terms": "on",
            "datause": "on",
            "reg_instance": generate_random_string(12),
            "submission_request": "true",
            "__a": "1",
            "__req": request_id,
            "__rev": str(random.randint(1000000, 9999999)),
            "__s": generate_random_string(8),
            "__user": "0",
            "__ccg": "MODERATE",
            "__jssesw": "1",
            "lsd": generate_random_string(10),
            "jazoest": "".join(random.choices("2578", k=8)),
            "logger_id": generate_random_string(16),
        }

        # Headers specific to mobile API request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_MOBILE_URL,
            "Referer": f"{FB_MOBILE_URL}/r.php",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-FB-Friendly-Name": "RegisterMutation",
            "X-FB-LSD": api_data["lsd"],
            "X-ASBD-ID": "129477",
            "X-FB-Connection-Quality": "EXCELLENT",
        }

        # Submit the API request
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
            if "success" in result and result["success"]:
                user_id = result.get("userID", "Unknown")
                success(f"[+] Mobile API registration successful!")
                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id

            # Debug the JSON response
            debug_result = (
                str(result)[:150] + "..." if len(str(result)) > 150 else str(result)
            )
            info(f"[*] API response: {debug_result}")
        except Exception as e:
            info(f"[*] Not a JSON response: {e}")

        # If we reach here, API registration failed
        error(f"[×] Mobile API registration failed")
        error_text = extract_error_message(response.text)
        error(f"[×] Error message: {error_text}")
        return False, None

    except Exception as e:
        error(f"[×] Mobile API registration error: {e}")
        return False, None
