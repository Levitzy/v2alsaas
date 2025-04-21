# Facebook Account Creator Configuration - Updated for 2025 Security Measures

import os
import random
import time
import uuid
import hashlib
from datetime import datetime

# Global settings
USE_PROXIES = False  # Default value, will be updated from user input
MAX_ATTEMPTS = 3
DELAY_BETWEEN_ATTEMPTS = (5, 8)  # Increased wait time range in seconds
TIMEOUT = 40  # Increased timeout for modern Facebook's slower responses

# Paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PROXIES_PATH = os.path.join(ROOT_DIR, "proxies.txt")
ACCOUNTS_PATH = os.path.join(ROOT_DIR, "facebook_accounts.txt")
EMAIL_PASS_PATH = os.path.join(ROOT_DIR, "email_pass.txt")

# Facebook URLs
FB_MOBILE_URL = "https://m.facebook.com"
FB_DESKTOP_URL = "https://www.facebook.com"

# Modern screen resolutions for 2025
SCREEN_RESOLUTIONS = [
    "1920x1080",
    "2560x1440",
    "3840x2160",  # 4K
    "1536x864",
    "1440x900",
    "1366x768",
    "3440x1440",  # Ultrawide
    "2880x1800",  # Retina
    "1920x1200",
    "2560x1600",
    "3000x2000",  # Surface
]

# Mobile screen resolutions for 2025
MOBILE_SCREEN_RESOLUTIONS = [
    "412x915",  # Pixel 7
    "390x844",  # iPhone 14
    "428x926",  # iPhone 14 Pro Max
    "393x873",  # Samsung S23
    "360x800",  # Common Android
    "375x812",  # iPhone 13 Mini
    "414x896",  # iPhone 11 Pro Max
    "412x892",  # Pixel 6
    "360x780",  # Budget Android
    "480x1024",  # Tablet
]

# Color settings
SUCCESS_COLOR = "\x1b[38;5;22m"
ERROR_COLOR = "\x1b[38;5;196m"
INFO_COLOR = "\x1b[38;5;33m"
RESET_COLOR = "\x1b[0m"

# Updated Mobile user agents (2025)
MOBILE_USER_AGENTS = [
    # Android devices
    "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14.1; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6412.101 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; SM-A756U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6409.53 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14.2; SM-G981U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.87 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6353.65 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14.5; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/124.0.6367.78 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; moto g power 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.110 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6408.22 Mobile Safari/537.36",
    # iOS devices
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.85 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/124.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/290.0.628252851 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
]

# Updated Desktop user agents (2025)
DESKTOP_USER_AGENTS = [
    # Windows Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.126 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6412.53 Safari/537.36",
    # macOS Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.126 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Apple M3 Mac OS X 14_6_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6412.53 Safari/537.36",
    # Windows Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # macOS Firefox
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:124.0) Gecko/20100101 Firefox/124.0",
    # macOS Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5_1) AppleWebKit/615.1.26 (KHTML, like Gecko) Version/18.4 Safari/615.1.26",
    "Mozilla/5.0 (Macintosh; Apple M3 Mac OS X 14_6_0) AppleWebKit/615.1.26 (KHTML, like Gecko) Version/18.5 Safari/615.1.26",
    # Windows Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.126 Safari/537.36 Edg/124.0.2478.95",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6412.53 Safari/537.36 Edg/125.0.2523.44",
    # Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.126 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

# Anti-detection settings - Updated for 2025
COMMON_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
]

# Modern Accept headers for 2025
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/jxl,*/*;q=0.8",
]

# Expected modern connection types for 2025
NETWORK_TYPES = [
    "wifi",
    "ethernet",
    "cellular",
    "4g",
    "5g",
    "unknown",
]

# Updated Security token fallback
DEFAULT_FORM_FIELDS = {
    "desktop": {
        "firstname": "",
        "lastname": "",
        "reg_email__": "",
        "reg_email_confirmation__": "",
        "reg_passwd__": "",
        "birthday_day": "",
        "birthday_month": "",
        "birthday_year": "",
        "sex": "",
        "websubmit": "Sign Up",
        "referrer": "",
        "name_suggest_elig": "false",
        "nsid": "",
        "reg_instance": "",
        "locale": "en_US",
        "client_id": "1",
        "cver": "regular",
        "terms": "on",
        "datause": "on",
        "acknowledge_understanding": "on",
        # New 2025 fields
        "is_hcaptcha_enabled": "false",
        "is_recaptcha_enabled": "false",
        "is_e2e_enabled": "true",
        "use_custom_gender": "false",
        "prefer_not_to_say": "false",
        "use_checkout_flow": "false",
        "use_video_call_confirm": "false",
        "skip_email_verification": "false",
        "source": "registration_form",
    },
    "mobile": {
        "firstname": "",
        "lastname": "",
        "reg_email__": "",
        "reg_email_confirmation__": "",
        "reg_passwd__": "",
        "birthday_day": "",
        "birthday_month": "",
        "birthday_year": "",
        "sex": "",
        "websubmit": "Sign Up",
        "referrer": "mobile_basic_reg",
        "locale": "en_US",
        "terms": "on",
        "datause": "on",
        "acknowledge_understanding": "on",
        # New 2025 mobile fields
        "is_mobile": "true",
        "mobile_platform": "android",
        "mobile_rtt": "150",
        "connection_quality": "EXCELLENT",
        "is_native_app": "false",
        "mobile_oauth_flow": "false",
        "skip_email_verification": "false",
        "reg_from_mobile": "true",
        "source": "mobile_registration_form",
    },
}

# Modernized secure password generation settings
PASSWORD_POLICIES = {
    "min_length": 10,
    "max_length": 16,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_special": True,
    "allowed_special": "!@#$%^&*()_+-=",
}


# Browser fingerprinting generation function
def get_random_browser_properties():
    """Generate random browser properties for fingerprinting evasion"""
    # Choose a platform first to create consistent properties
    platform = random.choice(["Windows", "Macintosh", "Linux", "Android", "iPhone"])

    # Set properties based on platform for better consistency
    if platform == "Windows":
        user_agent = random.choice(
            [ua for ua in DESKTOP_USER_AGENTS if "Windows" in ua]
        )
        pixel_ratio = random.choice([1, 1.25, 1.5, 2])
        color_depth = random.choice([24, 30])
        screen_resolution = random.choice(SCREEN_RESOLUTIONS)
    elif platform == "Macintosh":
        user_agent = random.choice(
            [ua for ua in DESKTOP_USER_AGENTS if "Macintosh" in ua]
        )
        pixel_ratio = random.choice([1, 2, 2.5])
        color_depth = 30
        screen_resolution = random.choice(
            [r for r in SCREEN_RESOLUTIONS if int(r.split("x")[0]) >= 1440]
        )
    elif platform == "Linux":
        user_agent = random.choice([ua for ua in DESKTOP_USER_AGENTS if "Linux" in ua])
        pixel_ratio = random.choice([1, 1.5, 2])
        color_depth = 24
        screen_resolution = random.choice(SCREEN_RESOLUTIONS)
    elif platform == "Android":
        user_agent = random.choice([ua for ua in MOBILE_USER_AGENTS if "Android" in ua])
        pixel_ratio = random.choice([2, 2.5, 3, 3.5])
        color_depth = 32
        screen_resolution = random.choice(MOBILE_SCREEN_RESOLUTIONS)
    else:  # iPhone/iOS
        user_agent = random.choice(
            [ua for ua in MOBILE_USER_AGENTS if "iPhone" in ua or "iPad" in ua]
        )
        pixel_ratio = random.choice([2, 3])
        color_depth = 32
        screen_resolution = random.choice(MOBILE_SCREEN_RESOLUTIONS)

    # Generate a hardware concurrency that makes sense
    hardware_concurrency = random.choice([2, 4, 6, 8, 12, 16])

    # Generate a device memory value that makes sense
    device_memory = random.choice([2, 4, 8, 16])

    # Generate a timezone offset
    timezone_offset = random.randint(-720, 720)  # Minutes from UTC

    # Generate a connection type that makes sense for the device
    if platform in ["Android", "iPhone"]:
        connection_type = random.choice(["wifi", "4g", "5g"])
        downlink = round(random.uniform(5, 50), 1)  # Mbps
        rtt = random.randint(30, 150)  # ms
    else:
        connection_type = random.choice(["wifi", "ethernet"])
        downlink = round(random.uniform(20, 100), 1)  # Mbps
        rtt = random.randint(5, 50)  # ms

    # Create a device fingerprint ID
    device_id = str(uuid.uuid4()).replace("-", "")

    # Create a canvas fingerprint
    canvas_fp = hashlib.md5(
        f"{platform}{screen_resolution}{int(time.time())}".encode()
    ).hexdigest()

    # Create a webgl fingerprint
    webgl_fp = hashlib.md5(
        f"{platform}{device_id}{int(time.time())}".encode()
    ).hexdigest()

    return {
        "screen_resolution": screen_resolution,
        "color_depth": color_depth,
        "pixel_ratio": pixel_ratio,
        "timezone_offset": timezone_offset,
        "language": random.choice(COMMON_LANGUAGES),
        "accept": random.choice(ACCEPT_HEADERS),
        "platform": platform,
        "user_agent": user_agent,
        "hardware_concurrency": hardware_concurrency,
        "device_memory": device_memory,
        "connection_type": connection_type,
        "downlink": downlink,
        "rtt": rtt,
        "device_id": device_id,
        "canvas_fp": canvas_fp,
        "webgl_fp": webgl_fp,
        "local_storage": random.choice([True, False]),
        "session_storage": True,
        "cookies_enabled": True,
        "do_not_track": random.choice([None, "1", "0"]),
        "touch_points": (
            0 if platform in ["Windows", "Macintosh", "Linux"] else random.randint(1, 5)
        ),
        "created_at": datetime.now().isoformat(),
    }
