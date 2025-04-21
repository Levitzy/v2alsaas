# Color utilities for console output

from config import SUCCESS_COLOR, ERROR_COLOR, INFO_COLOR, RESET_COLOR

# Add a warning color (typically yellow/orange)
WARN_COLOR = "\x1b[38;5;208m"  # Orange color for warnings


def success(message):
    """Print a success message"""
    print(f"{SUCCESS_COLOR}{message}{RESET_COLOR}")


def error(message):
    """Print an error message"""
    print(f"{ERROR_COLOR}{message}{RESET_COLOR}")


def info(message):
    """Print an information message"""
    print(f"{INFO_COLOR}{message}{RESET_COLOR}")


def warn(message):
    """Print a warning message"""
    print(f"{WARN_COLOR}{message}{RESET_COLOR}")


def banner():
    """Print the application banner"""
    print(
        f"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓           
❖ › Channel :- @AnonymousSudan 
❖ › By      :- @AnonymousSudan
┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛                """
    )
    print("\x1b[38;5;208m⇼" * 60)
    print("\x1b[38;5;22m•" * 60)
    print("\x1b[38;5;22m•" * 60)
    print("\x1b[38;5;208m⇼" * 60)


def separator():
    """Print a separator line"""
    print("\x1b[38;5;208m⇼" * 60)
