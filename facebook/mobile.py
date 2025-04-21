# Mobile web Facebook registration

import re
import random
import requests

from utils.colors import error, info
from utils.helpers import extract_hidden_fields, extract_error_message, extract_user_id
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
        session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        # Apply anti-detection measures specific to mobile
        session = apply_anti_detection_measures(session, FB_MOBILE_URL, user_details)
        # Override some settings for mobile
        session.headers.update({"Sec-Ch-Ua-Mobile": "?1"})

        info(f"[*] Mobile web registration for {email}")

        # Step 1: Visit mobile site to get initial cookies
        info("[*] Visiting mobile Facebook site...")
        response = session.get(FB_MOBILE_URL, timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access mobile site: {response.status_code}")
            return False, None

        # Step 2: Get the registration page
        reg_url = f"{FB_MOBILE_URL}/reg/"
        info("[*] Accessing mobile registration page...")
        response = session.get(reg_url, timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access signup page: {response.status_code}")
            return False, None

        # Check for security challenges
        passed, challenge_type = handle_security_challenges(session, response)
        if not passed:
            error(f"[×] Security challenge detected: {challenge_type}")
            return False, None

        # Step 3: Extract form data, CSRF tokens, etc.
        html = response.text

        # Get hidden fields
        hidden_fields = extract_hidden_fields(html)

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
                "code_challenge": "",
                "flow": "REGISTRATION",
            }
        )

        # Merge hidden fields
        form_data.update(hidden_fields)

        # Add security tokens
        form_data = add_security_tokens(form_data, html)

        # Simulate realistic form filling
        form_data = simulate_realistic_form_filling(
            session, reg_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Step 4: Submit the registration form
        submit_url = f"{FB_MOBILE_URL}/reg/submit/"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_MOBILE_URL,
            "Referer": reg_url,
        }

        info("[*] Submitting mobile registration form...")
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Step 5: Analyze the result
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Check for security challenges again
        passed, challenge_type = handle_security_challenges(session, response)
        if not passed:
            error(f"[×] Post-submission security challenge: {challenge_type}")
            return False, None

        # Check for success based on response URL
        success_indicators = [
            "confirmemail",
            "checkpoint",
            "welcome",
            "save-device",
            "login/save-device",
            "reg_success",
        ]

        if response.status_code == 200 and any(
            indicator in response.url for indicator in success_indicators
        ):
            # Extract user ID
            user_id = extract_user_id(response, session)

            # Handle success
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

            # Advanced handling for specific mobile errors
            if "SMS" in error_text or "confirmation" in error_text.lower():
                error("[×] SMS verification required - not supported")
            elif "already" in error_text.lower() and "exists" in error_text.lower():
                error("[×] Email already registered")
            elif any(
                block_term in error_text.lower()
                for block_term in [
                    "blocked",
                    "try again later",
                    "temporary",
                    "suspicious",
                ]
            ):
                error("[×] Registration blocked by Facebook security measures")

            return False, None

    except requests.exceptions.RequestException as req_err:
        error(f"[×] Network error: {req_err}")
        return False, None
    except Exception as e:
        error(f"[×] Error: {e}")
        return False, None
