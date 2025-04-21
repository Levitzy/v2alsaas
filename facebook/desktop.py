# Desktop web Facebook registration

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
        session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }
        )

        # Apply anti-detection measures
        session = apply_anti_detection_measures(session, FB_DESKTOP_URL, user_details)

        info(f"[*] Desktop web registration for {email}")

        # Step 1: Visit homepage to get initial cookies
        info("[*] Visiting Facebook homepage...")
        response = session.get(f"{FB_DESKTOP_URL}/", timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access Facebook homepage: {response.status_code}")
            return False, None

        # Step 2: Visit registration page and get tokens
        signup_url = f"{FB_DESKTOP_URL}/r.php"
        info("[*] Accessing registration page...")
        response = session.get(signup_url, timeout=TIMEOUT)

        if response.status_code != 200:
            error(f"[×] Failed to access signup page: {response.status_code}")
            return False, None

        # Check for security challenges
        passed, challenge_type = handle_security_challenges(session, response)
        if not passed:
            error(f"[×] Security challenge detected: {challenge_type}")
            return False, None

        # Step 3: Extract form data and tokens
        html = response.text

        # Get hidden fields from the form
        hidden_fields = extract_hidden_fields(html)

        # Prepare form data with user details
        form_data = generate_form_data(user_details, email, "desktop")

        # Merge hidden fields with form data
        form_data.update(hidden_fields)

        # Add security tokens
        form_data = add_security_tokens(form_data, html)

        # Simulate realistic form filling
        form_data = simulate_realistic_form_filling(
            session, signup_url, form_data, user_details
        )
        if not form_data:
            return False, None

        # Step 4: Submit the registration form
        submit_url = f"{FB_DESKTOP_URL}/reg/submit/"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": FB_DESKTOP_URL,
            "Referer": signup_url,
        }

        info("[*] Submitting registration form...")
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=True,
            timeout=TIMEOUT,
        )

        # Step 5: Analyze result
        info(f"[*] Response status: {response.status_code}")
        info(f"[*] Response URL: {response.url}")

        # Check for security challenges again
        passed, challenge_type = handle_security_challenges(session, response)
        if not passed:
            error(f"[×] Post-submission security challenge: {challenge_type}")
            return False, None

        # Check for success indicators
        success_indicators = [
            "confirmemail",
            "checkpoint",
            "welcome",
            "reg_success",
            "?next=",
            "home.php",
            "account_verified",
            "save-device",
        ]

        if response.status_code == 200 and any(
            indicator in response.url for indicator in success_indicators
        ):
            # Extract user ID
            user_id = extract_user_id(response, session)

            # Handle success
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
