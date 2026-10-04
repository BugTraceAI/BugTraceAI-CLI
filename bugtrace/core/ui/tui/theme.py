"""Colors from BugTraceAI-WEB's default purple/coral theme."""
BACKGROUND = "#1A0F2E"
PANEL = "#2D1B4D"
PANEL_QUIET = "#24163B"
BORDER = "#59456F"
ELEVATED = "#3D2B5F"
ACCENT = "#FF7F50"
TEXT = "#F8F9FA"
SECONDARY = "#B0A8C0"
MUTED = "#8A7FA8"
SUCCESS = "#2ECC71"
WARNING = "#FFC107"
ERROR = "#FF3131"
AGENT_COLORS = {
    "sqli": "#ff6b6b", "xss": "#4dd2ff", "csti": "#c792ea", "xxe": "#ffd166",
    "idor": "#06d6a0", "ssrf": "#f78c6b", "lfi": "#83e765", "rce": "#ff5c8a",
    "jwt": "#82aaff", "ssti": "#ff8fab", "openredirect": "#ffb3c1",
}


def agent_key(name):
    return str(name).lower().removesuffix("_agent").removesuffix("agent").strip("_")
