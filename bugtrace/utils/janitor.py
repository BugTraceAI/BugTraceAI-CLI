import os
import subprocess
import time
from loguru import logger

def kill_process_by_name(name_filter: str):
    """Kills processes matching the name filter using pkill -f."""
    try:
        # Check if process exists first
        check = subprocess.run(["pgrep", "-f", name_filter], stdout=subprocess.DEVNULL)
        if check.returncode == 0:
            logger.warning(f"🧹 Janitor: Cleaning up stale process '{name_filter}'...")
            subprocess.run(["pkill", "-9", "-f", name_filter], check=False)
            return True
    except Exception as e:
        logger.error(f"Janitor failed to kill {name_filter}: {e}", exc_info=True)
    return False

def clean_environment():
    """
    Performs a deep clean of the runtime environment.
    Removes zombie browsers, hung scanners, and clears temp files.
    """
    logger.info("🧹 Janitor: Starting environment purge...")
    
    # 1. Kill Browsers (The usual suspects)
    kill_process_by_name("chrome")
    kill_process_by_name("chromium")
    kill_process_by_name("playwright")
    
    # 2. Kill External Scanners
    kill_process_by_name("gospider")
    kill_process_by_name("nuclei")
    kill_process_by_name("sqlmap")
    kill_process_by_name("go-idor-fuzzer")
    kill_process_by_name("go-ssrf-fuzzer")
    kill_process_by_name("go-lfi-fuzzer")
    kill_process_by_name("go-xss-fuzzer")
    
    # 3. Clear Temp Uploads (if localized)
    if os.path.exists("uploads"):
        try:
            for f in os.listdir("uploads"):
                os.remove(os.path.join("uploads", f))
            logger.info("🧹 Janitor: Uploads directory cleared.")
        except Exception as e:
            logger.warning(f"Janitor could not clear uploads: {e}")

    logger.info("✨ Environment implies readiness.")

if __name__ == "__main__":
    clean_environment()
