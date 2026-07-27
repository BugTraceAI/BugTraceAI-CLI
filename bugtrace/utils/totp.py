"""
TOTP Generator - RFC 6238 Time-based One-Time Password.

Generates 6-digit TOTP codes from Base32-encoded secrets.
Compatible with Google Authenticator, Authy, and similar apps.

Author: BugtraceAI Team
"""

import hmac
import struct
import time
import re
from typing import Optional, Tuple
from bugtrace.utils.logger import get_logger

logger = get_logger("utils.totp")

# Base32 alphabet (RFC 4648)
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def base32_decode(encoded: str) -> bytes:
    """
    Decode a Base32-encoded string to bytes.

    Args:
        encoded: Base32 string (A-Z, 2-7, optional padding)

    Returns:
        Decoded bytes

    Raises:
        ValueError: If the string contains invalid characters
    """
    # Clean input: remove spaces, uppercase, strip padding
    encoded = encoded.strip().upper().replace(" ", "").rstrip("=")

    if not encoded:
        raise ValueError("Empty TOTP secret")

    # Validate characters
    if not re.match(r'^[A-Z2-7]+$', encoded):
        raise ValueError("Invalid Base32 characters in TOTP secret")

    # Decode
    bits = 0
    bit_count = 0
    result = bytearray()

    for char in encoded:
        idx = BASE32_ALPHABET.index(char)
        bits = (bits << 5) | idx
        bit_count += 5

        while bit_count >= 8:
            bit_count -= 8
            result.append((bits >> bit_count) & 0xFF)

    return bytes(result)


def validate_totp_secret(secret: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a TOTP secret.

    Args:
        secret: Base32-encoded TOTP secret

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not secret:
        return False, "TOTP secret is empty"

    secret = secret.strip().upper().replace(" ", "").rstrip("=")

    if not re.match(r'^[A-Z2-7]+$', secret):
        return False, "TOTP secret contains invalid Base32 characters"

    if len(secret) < 16:
        return False, "TOTP secret is too short (minimum 16 characters)"

    try:
        base32_decode(secret)
        return True, None
    except Exception as e:
        return False, f"Failed to decode TOTP secret: {e}"


def generate_totp(
    secret: str,
    timestamp: Optional[int] = None,
    period: int = 30,
    digits: int = 6
) -> dict:
    """
    Generate a TOTP code from a Base32-encoded secret.

    Implements RFC 6238 (TOTP) using HMAC-SHA1.

    Args:
        secret: Base32-encoded secret key
        timestamp: Unix timestamp (default: current time)
        period: Time step in seconds (default: 30)
        digits: Number of digits in OTP (default: 6)

    Returns:
        Dict with:
            - status: 'success' or 'error'
            - totp_code: The generated code (if success)
            - expires_in: Seconds until code expires (if success)
            - timestamp: ISO timestamp of generation
            - message: Status message
            - error: Error message (if error)
    """
    try:
        # Validate secret
        is_valid, error = validate_totp_secret(secret)
        if not is_valid:
            return {
                "status": "error",
                "error": error,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            }

        # Get current time
        if timestamp is None:
            timestamp = int(time.time())

        # Calculate time counter (RFC 6238)
        counter = timestamp // period

        # Decode secret
        key = base32_decode(secret)

        # Pack counter as 8-byte big-endian
        counter_bytes = struct.pack(">Q", counter)

        # Compute HMAC-SHA1
        hmac_digest = hmac.new(key, counter_bytes, "sha1").digest()

        # Dynamic truncation (RFC 4226)
        offset = hmac_digest[-1] & 0x0F
        truncated = struct.unpack(">I", hmac_digest[offset:offset + 4])[0]
        truncated &= 0x7FFFFFFF  # Clear high bit

        # Generate OTP
        otp = truncated % (10 ** digits)
        totp_code = str(otp).zfill(digits)

        # Calculate expiry
        expires_in = period - (timestamp % period)

        logger.debug(f"TOTP generated successfully, expires in {expires_in}s")

        return {
            "status": "success",
            "message": "TOTP code generated successfully",
            "totp_code": totp_code,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "expires_in": expires_in
        }

    except Exception as e:
        logger.error(f"TOTP generation failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        }


def get_totp_code(secret: str) -> Optional[str]:
    """
    Simple helper to get just the TOTP code.

    Args:
        secret: Base32-encoded TOTP secret

    Returns:
        6-digit TOTP code or None on error
    """
    result = generate_totp(secret)
    if result["status"] == "success":
        return result["totp_code"]
    return None
