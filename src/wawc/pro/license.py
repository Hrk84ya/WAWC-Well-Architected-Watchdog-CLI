"""License validation and Pro feature gating."""

import logging
import os
from functools import wraps
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


def check_license() -> bool:
    """
    Check if a valid Pro license exists.

    Checks:
    1. WAWC_LICENSE environment variable
    2. ~/.wawc/license file
    3. .wawc-license in current directory

    Returns:
        True if valid license found, False otherwise
    """
    # Check environment variable
    env_license = os.getenv("WAWC_LICENSE")
    if env_license and _validate_license_key(env_license):
        return True

    # Check user-level license file
    user_license = Path.home() / ".wawc" / "license"
    if user_license.exists():
        try:
            key = user_license.read_text().strip()
            if _validate_license_key(key):
                return True
        except Exception as e:
            logger.debug(f"Error reading user license: {e}")

    # Check project-level license file
    project_license = Path(".wawc-license")
    if project_license.exists():
        try:
            key = project_license.read_text().strip()
            if _validate_license_key(key):
                return True
        except Exception as e:
            logger.debug(f"Error reading project license: {e}")

    return False


def _validate_license_key(key: str) -> bool:
    """
    Validate license key format.

    Mock implementation - in production this would verify signature,
    expiration, etc.
    """
    # Simple mock validation
    if not key:
        return False

    # Accept any key starting with "WAWC-PRO-"
    if key.startswith("WAWC-PRO-"):
        return True

    return False


def require_pro(func: Callable) -> Callable:
    """
    Decorator to gate Pro features.

    If license is invalid, prints a friendly message and returns None.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not check_license():
            print("\n🔒 This is a Pro feature!")
            print("To unlock multi-region scanning, HTML/PDF reports, and more:")
            print("  1. Set WAWC_LICENSE environment variable")
            print("  2. Or create ~/.wawc/license file")
            print("  3. Or create .wawc-license in your project")
            print("\nVisit https://github.com/Hrk84ya/WAWC-Well-Architected-Watchdog-CLI for more information.\n")
            return None
        return func(*args, **kwargs)

    return wrapper
