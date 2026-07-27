"""Headless browser tools for dynamic analysis."""

from .dom_xss_detector import DOMXSSDetector, detect_dom_xss, detect_dom_xss_batch

__all__ = ["DOMXSSDetector", "detect_dom_xss", "detect_dom_xss_batch"]
