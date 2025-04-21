# Desktop web Facebook registration

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
from config import FB_DESKTOP_URL, DESKTOP_USER_AGENTS, TIMEOUT


def register_facebook_desktop(email, user_details, proxies=None):
    """Register using desktop web interface with advanced anti-detection"""
    try:
        # Create a session
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)

        # Set advanced headers with random user agent
        user_agent = random.choice(DESKTOP_USER_AGENTS)
        user_details["user_agent"] = user_agent  # Store for fingerprinting

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
            }
        )

        # Apply anti-detection measures
        session = apply_anti_detection_measures(session, FB_DESKTOP_URL, user_details)

        info(f"[*] Desktop web registration for {email}")

        # Step 1: Visit homepage with a more natural approach
        info("[*] Visiting Facebook homepage...")
        response = session.get(f"{FB_DESKTOP_URL}/", timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access Facebook homepage: {response.status_code}")
            return False, None

        # Add realistic delays between requests
        time.sleep(random.uniform(1.0, 3.0))

        # Step 2: Try using a direct dedicated signup URL
        # Facebook often uses different registration paths
        signup_urls = [
            f"{FB_DESKTOP_URL}/reg/",
            f"{FB_DESKTOP_URL}/signup",
            f"{FB_DESKTOP_URL}/r.php",
        ]

        # Try different URLs until one works
        signup_response = None
        for url in signup_urls:
            info(f"[*] Trying registration URL: {url}...")
            # Add referrer to make it look more natural
            session.headers.update({"Referer": FB_DESKTOP_URL})

            try:
                signup_response = session.get(url, timeout=TIMEOUT)
                if signup_response.status_code == 200:
                    signup_url = url
                    info(f"[*] Successfully accessed registration page: {url}")
                    break
            except Exception as e:
                info(f"[*] Error accessing {url}: {e}")
                continue

        if not signup_response or signup_response.status_code != 200:
            error(f"[×] Failed to access any signup page")
            return False, None

        # Dump HTML content for debugging
        html = signup_response.text

        # DEBUG: Save a small portion of the page to see what we're getting
        try:
            debug_snippet = html[:1000] + "..." if len(html) > 1000 else html
            debug_snippet = re.sub(r"\s+", " ", debug_snippet)
            info(f"[*] Page content snippet: {debug_snippet[:150]}...")
        except Exception as e:
            info(f"[*] Couldn't extract debug snippet: {e}")

        # Try to find direct form action URL if it exists
        form_action = re.search(r'<form[^>]*action="([^"]+)"[^>]*method="post"', html)
        if form_action:
            submit_url = form_action.group(1)
            if not submit_url.startswith("http"):
                submit_url = FB_DESKTOP_URL + submit_url
            info(f"[*] Found form submission URL: {submit_url}")
        else:
            submit_url = f"{FB_DESKTOP_URL}/reg/submit/"
            info(f"[*] Using default submission URL: {submit_url}")

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
            info("[*] No hidden fields found in registration page")

            # Try alternate approach - direct API registration
            info("[*] Attempting direct API registration...")
            return direct_api_registration(session, email, user_details)

        # Prepare form data with user details
        form_data = generate_form_data(user_details, email, "desktop")

        # Merge hidden fields with form data
        form_data.update(hidden_fields)

        # Add security tokens - very important for Facebook
        form_data = add_security_tokens(form_data, html)

        # Essential fields needed by Facebook's modern registration
        current_time = int(time.time())
        form_data.update(
            {
                "reg_instance": generate_random_string(12),
                "submission_request": "true",
                "encpass": f"#PWD_BROWSER:0:{current_time}:{user_details['password']}",
                "ccp": "2",
                "reg_impression_id": generate_random_string(16),
                "ns": "0",
                "app_id": "0",
                "logger_id": generate_random_string(16),
                "terms": "on",
                "datause": "on",
                "contactpoint_label": "email",
                "websubmit": "Sign Up",
            }
        )

        # Simulate realistic form filling
        form_data = simulate_realistic_form_filling(
            session, signup_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Step 4: Submit the registration form with improved headers
        headers = {
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
        }

        # DEBUG: Print the submission URL and some key form fields
        try:
            debug_data = {
                k: form_data[k] for k in ["firstname", "lastname", "reg_email__"]
            }
            info(f"[*] Submitting form with data: {debug_data}")
        except Exception:
            pass

        info("[*] Submitting registration form...")
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Step 5: Analyze result with detailed debug info
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Debug cookies to check for success indicators
        cookies = session.cookies.get_dict()
        cookie_keys = list(cookies.keys())
        info(
            f"[*] Cookies received: {', '.join(cookie_keys[:5])}..."
            if len(cookie_keys) > 5
            else f"[*] Cookies received: {', '.join(cookie_keys)}"
        )

        # Try to detect if response is JSON (newer Facebook API might return JSON)
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

        # Enhanced success detection with multiple checks
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
            "c_user",  # Cookie indicating successful login
            "checkpoint/?next",  # Sometimes redirects here after successful registration
        ]

        # Also check for c_user cookie which indicates successful account creation
        cookie_success = "c_user" in cookies

        # Extract a snippet of the response for debugging
        debug_response = (
            response.text[:200] + "..." if len(response.text) > 200 else response.text
        )
        debug_response = re.sub(r"\s+", " ", debug_response)
        info(f"[*] Response snippet: {debug_response}")

        if response.status_code in [200, 302] and (
            any(indicator in response.url for indicator in success_indicators)
            or cookie_success
        ):

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

            # Check for specific blocking messages
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
                ]
            ):
                error("[×] Registration blocked by Facebook security measures")

            # If we think it's rate limiting, wait longer before next attempt
            if any(
                rate_term in error_text.lower() or rate_term in response.text.lower()
                for rate_term in [
                    "try again later",
                    "temporary",
                    "too many",
                    "wait",
                ]
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


def direct_api_registration(session, email, user_details):
    """Attempt registration using direct API method (bypassing normal form)"""
    try:
        info("[*] Using direct API registration method")

        # Facebook's API endpoint for registration
        api_url = f"{FB_DESKTOP_URL}/api/graphql/"

        # Generate necessary tokens
        request_id = generate_random_string(8)
        timestamp = int(time.time())

        # Prepare direct registration data
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
            "client_id": "1",
            "terms": "on",
            "datause": "on",
            "reg_instance": generate_random_string(12),
            "submission_request": "true",
            "__a": "1",
            "__req": request_id,
            "__rev": str(random.randint(1000000, 9999999)),
            "__s": generate_random_string(8),
            "__user": "0",
            "__ccg": "GOOD",
            "__jssesw": "1",
            "lsd": generate_random_string(8),
            "jazoest": "".join(random.choices("2578", k=8)),
            "logger_id": generate_random_string(16),
        }

        # Headers specific to API request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_DESKTOP_URL,
            "Referer": f"{FB_DESKTOP_URL}/r.php",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-FB-Friendly-Name": "RegisterMutation",
            "X-FB-LSD": api_data["lsd"],
        }

        # Submit the API request
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
            if "success" in result and result["success"]:
                user_id = result.get("userID", "Unknown")
                success(f"[+] API registration successful!")
                print_success(email, user_id, user_details)
                save_account(email, user_details, user_id)
                return True, user_id
        except:
            pass

        # If we reach here, API registration failed
        error(f"[×] API registration failed")
        error_text = extract_error_message(response.text)
        error(f"[×] Error message: {error_text}")
        return False, None

    except Exception as e:
        error(f"[×] API registration error: {e}")
        return False, None
