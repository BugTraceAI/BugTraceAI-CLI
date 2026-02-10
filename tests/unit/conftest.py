"""
Shared fixtures for specialist discovery method tests.

HTML fixtures are stored as base64 to avoid escaping issues with quotes,
angle brackets, backslashes, and JSON values in Python source files.
This is consistent with the project's base64 payload transport pattern.
"""
import base64
import pytest
from unittest.mock import patch, Mock, AsyncMock


# ---------------------------------------------------------------------------
# Base64-encoded HTML fixtures
# ---------------------------------------------------------------------------

_RICH_HTML_B64 = (
    b"PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KICAgIDxtZXRhIGh0dHAtZXF1aXY9InJl"
    b"ZnJlc2giIGNvbnRlbnQ9IjU7dXJsPS9kYXNoYm9hcmQiPgo8L2hlYWQ+Cjxib2R5IG5nLWFw"
    b"cD0ibXlBcHAiPgogICAgPCEtLSBTdGFuZGFyZCBzZWFyY2ggZm9ybSAtLT4KICAgIDxmb3Jt"
    b"IGFjdGlvbj0iL3NlYXJjaCIgbWV0aG9kPSJHRVQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0"
    b"ZXh0IiBuYW1lPSJzZWFyY2hUZXJtIiB2YWx1ZT0iIj4KICAgICAgICA8aW5wdXQgdHlwZT0i"
    b"aGlkZGVuIiBuYW1lPSJjYXRlZ29yeSIgdmFsdWU9Ikp1aWNlIj4KICAgICAgICA8aW5wdXQg"
    b"dHlwZT0iaGlkZGVuIiBuYW1lPSJjc3JmX3Rva2VuIiB2YWx1ZT0iYWJjMTIzIj4KICAgICAg"
    b"ICA8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1lPSJ1c2VyX2lkIiB2YWx1ZT0iNDIiPgogICAg"
    b"ICAgIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9ImFjY291bnRfcmVmIiB2YWx1ZT0iYTFi"
    b"MmMzZDQtZTVmNi03ODkwLWFiY2QtZWYxMjM0NTY3ODkwIj4KICAgICAgICA8dGV4dGFyZWEg"
    b"bmFtZT0iY29tbWVudCI+PC90ZXh0YXJlYT4KICAgICAgICA8c2VsZWN0IG5hbWU9InNvcnQi"
    b"PgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJhc2MiPkFzY2VuZGluZzwvb3B0aW9uPgog"
    b"ICAgICAgIDwvc2VsZWN0PgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIG5hbWU9Imdv"
    b"IiB2YWx1ZT0iU2VhcmNoIj4KICAgICAgICA8aW5wdXQgdHlwZT0iYnV0dG9uIiBuYW1lPSJj"
    b"YW5jZWwiIHZhbHVlPSJDYW5jZWwiPgogICAgPC9mb3JtPgoKICAgIDwhLS0gRmlsZSB1cGxv"
    b"YWQgZm9ybSAtLT4KICAgIDxmb3JtIGFjdGlvbj0iL3VwbG9hZCIgbWV0aG9kPSJQT1NUIiBl"
    b"bmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIj4KICAgICAgICA8aW5wdXQgdHlwZT0iZmls"
    b"ZSIgbmFtZT0iZG9jdW1lbnQiIGFjY2VwdD0iLnhtbCwucGRmIj4KICAgICAgICA8aW5wdXQg"
    b"dHlwZT0iZmlsZSIgbmFtZT0iYXZhdGFyIiBhY2NlcHQ9Ii5wbmcsLmpwZyIgbXVsdGlwbGU+"
    b"CiAgICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXBsb2FkX3Rva2VuIiB2YWx1"
    b"ZT0idG9rMTIzIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0iZGVzY3JpcHRp"
    b"b24iIHZhbHVlPSIiPgogICAgICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIHZhbHVlPSJVcGxv"
    b"YWQiPgogICAgPC9mb3JtPgoKICAgIDwhLS0gTG9naW4gZm9ybSB3aXRoIHJlZGlyZWN0IHBh"
    b"cmFtcyAtLT4KICAgIDxmb3JtIGFjdGlvbj0iL2xvZ2luIiBtZXRob2Q9IlBPU1QiPgogICAg"
    b"ICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJ1c2VybmFtZSIgdmFsdWU9IiI+CiAgICAg"
    b"ICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBuYW1lPSJwYXNzd29yZCIgdmFsdWU9IiI+CiAg"
    b"ICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0icmVkaXJlY3RfdXJsIiB2YWx1ZT0i"
    b"L2Rhc2hib2FyZCI+CiAgICAgICAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iY2FsbGJh"
    b"Y2siIHZhbHVlPSJodHRwOi8vZXhhbXBsZS5jb20vY2IiPgogICAgICAgIDxpbnB1dCB0eXBl"
    b"PSJzdWJtaXQiIHZhbHVlPSJMb2dpbiI+CiAgICA8L2Zvcm0+CgogICAgPCEtLSBBZG1pbiBm"
    b"b3JtIHdpdGggY29tbWFuZC1saWtlIHBhcmFtcyAtLT4KICAgIDxmb3JtIGFjdGlvbj0iL2Fk"
    b"bWluL3Rvb2xzIiBtZXRob2Q9IlBPU1QiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBu"
    b"YW1lPSJjbWQiIHZhbHVlPSIiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJl"
    b"eGVjX3RhcmdldCIgdmFsdWU9IiI+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9"
    b"ImNvbmZpZyIgdmFsdWU9Int9Ij4KICAgICAgICA8aW5wdXQgdHlwZT0iaGlkZGVuIiBuYW1l"
    b"PSJkYXRhIiB2YWx1ZT0neyJrZXkiOiJ2YWwifSc+CiAgICAgICAgPGlucHV0IHR5cGU9InRl"
    b"eHQiIG5hbWU9InRlbXBsYXRlIiB2YWx1ZT0iIj4KICAgICAgICA8aW5wdXQgdHlwZT0idGV4"
    b"dCIgbmFtZT0iZmlsZV9wYXRoIiB2YWx1ZT0iaGVhZGVyLnBocCI+CiAgICA8L2Zvcm0+CgoK"
    b"ICAgIDwhLS0gRHJhZy1hbmQtZHJvcCB6b25lIC0tPgogICAgPGRpdiBkYXRhLXVwbG9hZD0i"
    b"L2FwaS91cGxvYWQvZHJvcCIgaWQ9ImRyb3B6b25lMSI+RHJvcCBmaWxlcyBoZXJlPC9kaXY+"
    b"CgogICAgPCEtLSBKUyB2YXJpYWJsZXMgLS0+CiAgICA8c2NyaXB0PgogICAgICAgIHZhciBz"
    b"ZWFyY2hUZXh0ID0gInVzZXJfcXVlcnkiOwogICAgICAgIHZhciBzZWxlY3RlZENhdGVnb3J5"
    b"ID0gIkp1aWNlIjsKICAgICAgICB2YXIgeCA9ICJhIjsKICAgIDwvc2NyaXB0PgoKICAgIDwh"
    b"LS0gSldUIGluIGxpbmsgLS0+CiAgICA8YSBocmVmPSIvYXBpL2RhdGE/dG9rZW49ZXlKaGJH"
    b"Y2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rr"
    b"d0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZRLlNm"
    b"bEt4d1JKU01lS0tGMlFUNGZ3cE1lSmYzNlBPazZ5SlZfYWRRc3N3NWMiPkFQSSBMaW5rPC9h"
    b"Pgo8L2JvZHk+CjwvaHRtbD4="
)

_MINIMAL_HTML_B64 = (
    b"PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8Ym9keT4KICAgIDxmb3JtIGFjdGlvbj0iL3NlYXJj"
    b"aCIgbWV0aG9kPSJHRVQiPgogICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJxIiB2"
    b"YWx1ZT0iIj4KICAgICAgICA8aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iR28iPgogICAg"
    b"PC9mb3JtPgo8L2JvZHk+CjwvaHRtbD4="
)

_EMPTY_HTML_B64 = (
    b"PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8Ym9keT4KICAgIDxwPldlbGNvbWUgdG8gb3VyIHNp"
    b"dGUuPC9wPgo8L2JvZHk+CjwvaHRtbD4="
)


def _decode(b64: bytes) -> str:
    return base64.b64decode(b64).decode("utf-8")


RICH_HTML = _decode(_RICH_HTML_B64)
MINIMAL_HTML = _decode(_MINIMAL_HTML_B64)
EMPTY_HTML = _decode(_EMPTY_HTML_B64)

# Standard test URL with query params
TEST_URL = "https://example.com/catalog?category=Juice&sort=asc"


# ---------------------------------------------------------------------------
# Autouse: patch ConductorV2 for all tests in tests/unit/
# BaseAgent.__init__ (base.py:27) does: from bugtrace.core.conductor import conductor
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_conductor():
    with patch("bugtrace.core.conductor.ConductorV2"):
        yield


# ---------------------------------------------------------------------------
# Browser mock fixtures (capture_state returns HTML fixtures)
# ---------------------------------------------------------------------------

def _make_browser_mock(html: str) -> AsyncMock:
    return AsyncMock(return_value={
        "text": html,
        "screenshot": "/tmp/fake_screenshot.png",
        "html": html,
    })


@pytest.fixture
def mock_browser_rich():
    mock = _make_browser_mock(RICH_HTML)
    with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
        yield mock


@pytest.fixture
def mock_browser_minimal():
    mock = _make_browser_mock(MINIMAL_HTML)
    with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
        yield mock


@pytest.fixture
def mock_browser_empty():
    mock = _make_browser_mock(EMPTY_HTML)
    with patch("bugtrace.tools.visual.browser.browser_manager.capture_state", mock):
        yield mock
