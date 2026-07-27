"""
Auth Flow Parser - Interprets natural language login instructions.

Converts human-readable instructions to executable browser actions.

Author: BugtraceAI Team
"""

import re
from typing import List, Tuple, Optional
from bugtrace.utils.logger import get_logger

logger = get_logger("auth_flow_parser")


# Mapping of natural language patterns to actions
INSTRUCTION_PATTERNS = [
    # Navigation
    (r"navigate to (?:the )?(?:login )?url", "navigate"),
    (r"go to (?:the )?(?:login )?(?:page|url)", "navigate"),

    # Click SSO/Login button
    (r"click (?:on )?(?:the )?(?:sso|entraid|microsoft|entra.?id).*(?:button|sign.?in|link)", "click_sso"),
    (r"click (?:on )?(?:the )?(?:sign.?in|login|submit).*button", "click_submit"),
    (r"click (?:next|submit|continue)", "click_next"),
    (r"click sign in", "click_signin"),

    # Enter credentials
    (r"enter (?:the )?(?:email|username).*(?:field|input)?", "enter_username"),
    (r"enter (?:the )?password", "enter_password"),
    (r"enter (?:the )?(?:totp|mfa|otp|code|verification)", "enter_totp"),
    (r"type (?:the )?(?:email|username)", "enter_username"),
    (r"type (?:the )?password", "enter_password"),

    # TOTP generation hint (informational, triggers TOTP entry)
    (r"(?:use|generate|get).*totp.*(?:tool|code|secret)", "enter_totp"),
    (r"when prompted for (?:mfa|totp|2fa)", "enter_totp"),

    # Wait
    (r"wait (?:for )?(\d+)", "wait"),
]


def parse_natural_instruction(instruction: str) -> Tuple[str, Optional[str]]:
    """
    Parse a natural language instruction into an action type.

    Returns:
        Tuple of (action_type, extra_data)
    """
    instruction_lower = instruction.lower().strip()

    for pattern, action in INSTRUCTION_PATTERNS:
        match = re.search(pattern, instruction_lower)
        if match:
            # Extract wait time if present
            if action == "wait" and match.groups():
                return action, match.group(1)
            return action, None

    return "unknown", instruction


def convert_natural_flow_to_commands(
    login_flow: List[str],
    credentials: dict,
    login_url: str
) -> List[str]:
    """
    Convert natural language login flow to executable commands.

    Args:
        login_flow: List of natural language instructions
        credentials: Dict with username, password, totp_secret
        login_url: The login URL

    Returns:
        List of executable command strings
    """
    commands = []
    username = credentials.get("username", credentials.get("email", ""))
    totp_added = False  # Prevent duplicate TOTP steps

    for instruction in login_flow:
        action, extra = parse_natural_instruction(instruction)

        if action == "navigate":
            # Navigation is handled separately, skip
            continue

        elif action == "click_sso":
            commands.append("Click the 'Microsoft' button")
            commands.append("Wait for 3 seconds")

        elif action == "click_submit" or action == "click_next":
            commands.append("Click the 'Next' button")
            commands.append("Wait for 2 seconds")

        elif action == "click_signin":
            commands.append("Click the 'Sign in' button")
            commands.append("Wait for 3 seconds")

        elif action == "enter_username":
            commands.append(f"Type $username into the loginfmt field")

        elif action == "enter_password":
            commands.append(f"Type $password into the passwd field")

        elif action == "enter_totp":
            # Only add TOTP steps once (multiple natural language references to TOTP)
            if not totp_added:
                commands.append("Wait for 2 seconds")
                commands.append("Enter $totp in the otc field")
                commands.append("Click the 'Verify' button")
                commands.append("Wait for 3 seconds")
                totp_added = True
            else:
                logger.debug(f"Skipping duplicate TOTP instruction: {instruction}")

        elif action == "wait":
            seconds = extra or "3"
            commands.append(f"Wait for {seconds} seconds")

        elif action == "unknown":
            # Try to pass through if it looks like an existing command
            if any(kw in instruction.lower() for kw in ["type ", "click ", "enter ", "wait "]):
                commands.append(instruction)
            else:
                logger.debug(f"Skipping unrecognized instruction: {instruction}")

    return commands


def is_natural_language_flow(login_flow: List[str]) -> bool:
    """
    Detect if the login flow uses natural language or command syntax.

    Returns True if it appears to be natural language.
    """
    if not login_flow:
        return False

    # Check first few instructions
    natural_indicators = [
        "navigate", "go to", "enter the", "click on", "when prompted",
        "use the", "get a code", "submit"
    ]
    command_indicators = [
        "type $", "click the '", "enter $", "wait for"
    ]

    natural_count = 0
    command_count = 0

    for step in login_flow[:5]:
        step_lower = step.lower()
        if any(ind in step_lower for ind in natural_indicators):
            natural_count += 1
        if any(ind in step_lower for ind in command_indicators):
            command_count += 1

    return natural_count > command_count
