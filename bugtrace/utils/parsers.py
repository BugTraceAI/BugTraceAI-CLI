import re
from typing import Dict, List, Optional

class XmlParser:
    """
    Robust parser for extracting XML-like tags from untrusted text (e.g. LLM output).
    Designed to handle "noisy" inputs where data is embedded in conversational text.
    """

    @staticmethod
    def extract_tag(content: str, tag: str) -> Optional[str]:
        """
        Extracts content between <tag> and </tag>.
        
        Features:
        - Case-insensitive tag matching (<TAG>, <tag>, <Tag>)
        - DOTALL matching (captures content across newlines)
        - Non-greedy matching (finds the first valid block)
        - Strips whitespace from the result
        
        Args:
            content: The full text to search.
            tag: The tag name to look for (without brackets).
            
        Returns:
            Extracted content string or None if not found.
        """
        if not content:
            return None
            
        try:
            # Pattern 1: <tag>(content)</tag>
            # Escape tag to prevent regex injection or flag errors if tag has special chars
            safe_tag = re.escape(tag)
            pattern = f"<{safe_tag}>(.*?)</{safe_tag}>"
            match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            
            if match:
                return match.group(1).strip()
        except re.error:
            # Fallback if regex fails (e.g. global flags issue)
            pass
            
        # Pattern 2 (Fallback): <tag>(content) - Handles truncated responses
        # Only use if Pattern 1 failed and we see the start tag
        fallback_pattern = f"<{tag}>((?:(?!<{tag}>).)*)$"
        # Actually, simpler: just find the LAST occurrence of <tag> and take everything until the next <tag> or end
        # But for now, let's just use a more targeted fallback
        if f"<{tag}>" in content.lower() and f"</{tag}>" not in content.lower():
            start_index = content.lower().rfind(f"<{tag}>") + len(tag) + 2
            return content[start_index:].strip()
            
        return None

    @staticmethod
    def extract_tags(content: str, tags: List[str]) -> Dict[str, Optional[str]]:
        """
        Extracts multiple tags from content efficiently.
        
        Args:
            content: The full text to search.
            tags: List of tag names to extract.
            
        Returns:
            Dictionary mapping tag names to their extracted content (or None).
        """
        results = {}
        for tag in tags:
            results[tag] = XmlParser.extract_tag(content, tag)
        return results

    @staticmethod
    def extract_list(content: str, tag: str) -> List[str]:
        """
        Extracts ALL occurrences of a tag from content.
        Useful for lists of items (e.g. <vulnerability>...</vulnerability>).
        
        Args:
            content: The full text to search.
            tag: The tag name to search for.
            
        Returns:
            List of extracted contents.
        """
        if not content:
            return []
            
        # Pattern: <tag>(content)</tag>
        pattern = f"<{tag}>(.*?)</{tag}>"
        
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        return [m.strip() for m in matches]

# Self-test if run directly
if __name__ == "__main__":
    test_content = r"""
    Here is the payload you requested:
    
    <thought>
    The input filters single quotes. I will use backslash escape.
    </thought>
    
    <payload>
    \';alert(1)//
    </payload>
    
    <confidence>0.95</confidence>
    
    Hope this helps!
    """
    
    print("Testing XmlParser...")
    tags = ["thought", "payload", "confidence", "missing"]
    results = XmlParser.extract_tags(test_content, tags)
    
    expected = {
        "thought": "The input filters single quotes. I will use backslash escape.",
        "payload": "\\';alert(1)//",
        "confidence": "0.95",
        "missing": None
    }
    
    for k, v in results.items():
        print(f"[{k}]: {v}")
        if v == expected[k]:
            print("  -> OK")
        else:
            print(f"  -> FAIL (Expected: {expected[k]})")
