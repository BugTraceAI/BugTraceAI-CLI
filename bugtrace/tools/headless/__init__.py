"""Headless browser tools for dynamic analysis."""

from .dom_xss_detector import DOMXSSDetector, detect_dom_xss

__all__ = ["DOMXSSDetector", "detect_dom_xss"]
