# Random data generators for account creation

import random
import string
import uuid
import hashlib
import time
from faker import Faker
from datetime import datetime, timedelta

# Initialize Faker
fake = Faker()


def generate_random_string(length):
    """Generate a random string of specified length"""
    letters_and_digits = string.ascii_letters + string.digits
    return "".join(random.choice(letters_and_digits) for _ in range(length))


def generate_password(min_length=10, max_length=16):
    """Generate a strong password"""
    # Ensure password has at least one of each: uppercase, lowercase, digit, special
    password = random.choice(string.ascii_uppercase)
    password += random.choice(string.ascii_lowercase)
    password += random.choice(string.digits)
    password += random.choice("!@#$%^&*()_+-=")

    # Add more random characters to reach the minimum length
    remaining_length = random.randint(min_length - 4, max_length - 4)
    password += "".join(
        random.choice(string.ascii_letters + string.digits + "!@#$%^&*()_+-=")
        for _ in range(remaining_length)
    )

    # Shuffle the password
    password_list = list(password)
    random.shuffle(password_list)
    return "".join(password_list)


def generate_random_delay(min_sec=1, max_sec=2):
    """Generate a random delay between min_sec and max_sec"""
    return random.uniform(min_sec, max_sec)


def generate_device_id():
    """Generate a device ID for request tracking"""
    return str(uuid.uuid4())


def generate_user_details():
    """Generate random user details"""
    # Generate name
    first_name = fake.first_name()
    last_name = fake.last_name()

    # Generate gender (M/F format)
    gender = "F" if random.random() < 0.5 else "M"

    # Generate birthday (age between 18-45)
    birthday = fake.date_of_birth(minimum_age=18, maximum_age=45)

    # Generate password
    password = generate_password()

    # Generate device details for fingerprinting
    device_id = generate_device_id()

    # User agent hash for consistency in requests
    user_agent_hash = hashlib.md5(
        f"{first_name}{last_name}{str(time.time())}".encode()
    ).hexdigest()[:16]

    return {
        "first_name": first_name,
        "last_name": last_name,
        "gender": gender,
        "birthday": birthday,
        "password": password,
        "device_id": device_id,
        "user_agent_hash": user_agent_hash,
    }


def generate_form_data(user_details, email, form_type="desktop"):
    """Generate form data based on user details"""
    from config import DEFAULT_FORM_FIELDS

    # Get default form fields for the specified form type
    form_data = DEFAULT_FORM_FIELDS.get(form_type, {}).copy()

    # Format birthday
    birthday = user_details["birthday"]

    # Update form data with user details
    form_data.update(
        {
            "firstname": user_details["first_name"],
            "lastname": user_details["last_name"],
            "reg_email__": email,
            "reg_email_confirmation__": email,
            "reg_passwd__": user_details["password"],
            "birthday_day": str(birthday.day),
            "birthday_month": str(birthday.month),
            "birthday_year": str(birthday.year),
            "sex": "1" if user_details["gender"] == "F" else "2",
        }
    )

    return form_data


def generate_request_id():
    """Generate a unique request ID"""
    return generate_random_string(16)


def generate_browser_fingerprint():
    """Generate a consistent browser fingerprint"""
    canvas_hash = hashlib.md5(str(random.random()).encode()).hexdigest()
    webgl_hash = hashlib.md5(str(random.random()).encode()).hexdigest()
    audio_hash = hashlib.md5(str(random.random()).encode()).hexdigest()

    return {
        "canvas_hash": canvas_hash,
        "webgl_hash": webgl_hash,
        "audio_hash": audio_hash,
        "fonts": random.randint(30, 50),  # Number of "installed" fonts
        "plugins": random.randint(3, 8),  # Number of "installed" plugins
    }
