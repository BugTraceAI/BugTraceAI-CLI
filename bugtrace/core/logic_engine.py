from typing import List, Dict, Any, Optional
import re
from dataclasses import dataclass

@dataclass
class PatternMatch:
    pattern_id: str
    pattern_type: str
    confidence: float
    matched_text: str
    description: str

class LogicEngine:
    """
    Lightweight Logic Engine for fast Pattern Recognition in text/HTML.
    Inspired by Cognitive Logic Systems but optimized for speed using Regex.
    """
    
    def __init__(self):
        self.patterns = self._load_patterns()
        
    def _load_patterns(self) -> List[Dict[str, Any]]:
        """
        Defines the regex patterns to search for.
        """
        return [
            # SQL Injection Errors
            {
                "id": "sqli_mysql_error",
                "type": "sql_injection",
                "regex": r"(?i)(SQL syntax.*MySQL|Warning.*mysql_.*|valid MySQL result|MySqlException|You have an error in your SQL syntax)",
                "confidence": 0.9,
                "desc": "MySQL Error Message detected"
            },
            {
                "id": "sqli_postgres_error",
                "type": "sql_injection",
                "regex": r"(?i)(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.)",
                "confidence": 0.9,
                "desc": "PostgreSQL Error Message detected"
            },
             {
                "id": "sqli_generic_error",
                "type": "sql_injection",
                "regex": r"(?i)(SQL syntax errors|ODBC SQL Server Driver|Unclosed quotation mark|quoted string not properly terminated)",
                "confidence": 0.8,
                "desc": "Generic SQL Error Message detected"
            },
            
            # Information Disclosure / Debug Leaks
            {
                "id": "debug_django",
                "type": "info_disclosure",
                "regex": r"(?i)(Django Version|Exception Type:|TemplateDoesNotExist|MultiValueDictKeyError)",
                "confidence": 1.0,
                "desc": "Django Debug Page detected"
            },
            {
                "id": "debug_laravel",
                "type": "info_disclosure",
                "regex": r"(?i)(Whoops! There was an error|Laravel.*Ignition|Illuminate\\Database)",
                "confidence": 1.0,
                "desc": "Laravel Debug Page detected"
            },
            {
                "id": "stack_trace",
                "type": "info_disclosure",
                "regex": r"(?i)(at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.]+\.java:\d+\)|Traceback \(most recent call last\)|Stack trace:)",
                "confidence": 0.9,
                "desc": "Stack Trace detected"
            },

            # Sensitive Data Leaks
            {
                "id": "leaked_api_key",
                "type": "sensitive_data",
                "regex": r"(?i)(api_key|apikey|access_token|secret_key)[\"']?\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{20,}[\"']",
                "confidence": 0.8,
                "desc": "Potential API Key leaked"
            },
            {
                "id": "leaked_private_key",
                "type": "sensitive_data",
                "regex": r"-----BEGIN RSA PRIVATE KEY-----",
                "confidence": 1.0,
                "desc": "RSA Private Key leaked"
            },
            
            # Application Logic
            {
                "id": "login_page_indicator",
                "type": "fingerprint",
                "regex": r"(?i)(<input[^>]*password[^>]*>|name=\"login\"|name=\"user\"|text\" name=\"email\")",
                "confidence": 0.7,
                "desc": "Login Form detected"
            },
            {
                "id": "admin_panel_indicator",
                "type": "fingerprint",
                "regex": r"(?i)(admin dashboard|administration area|admin login|super user)",
                "confidence": 0.7,
                "desc": "Admin Interface detected"
            }
        ]

    def scan_text(self, text: str) -> List[PatternMatch]:
        """
        Scans the provided text for all defined patterns.
        Returns a list of PatternMatch objects.
        """
        matches = []
        if not text:
            return matches

        for pat in self.patterns:
            try:
                # Use re.search for single match checking (faster than findall if we just want presence)
                # Or findall if we want all occurrences. For logic, finding one is usually enough to flag.
                match = re.search(pat["regex"], text)
                if match:
                    # Extract a snippet
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 20)
                    snippet = text[start:end].replace('\n', ' ').strip()
                    
                    matches.append(PatternMatch(
                        pattern_id=pat["id"],
                        pattern_type=pat["type"],
                        confidence=pat["confidence"],
                        matched_text=snippet,
                        description=pat["desc"]
                    ))
            except Exception:
                continue
                
        return matches

# Singleton instance
logic_engine = LogicEngine()
