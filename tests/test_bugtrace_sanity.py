import pytest
from bugtrace.core.config import settings

def test_sanity():
    """Basic sanity check to ensure the bugtrace package imports correctly."""
    assert settings.APP_NAME == "BugtraceAI-CLI"
    print("✅ BugtraceAI package imported successfully.")

if __name__ == "__main__":
    test_sanity()
