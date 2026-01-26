import re
from typing import Optional, List, Tuple
from dataclasses import dataclass

@dataclass
class InjectionContext:
    context_type: str  # HTML_TAG, ATTRIBUTE, SCRIPT, COMMENT
    quote_char: Optional[str] = None
    breakout_chars: Optional[str] = None
    surrounding_text: str = ""

class ContextAnalyzer:
    """
    Performs 'SAST'-like analysis on the HTTP response content to understand
    where our payload is reflected and how to escape it.
    """

    def analyze(self, source_code: str, marker: str) -> List[InjectionContext]:
        """
        Finds all occurrences of 'marker' in 'source_code' and determines their context.
        """
        contexts = []
        # Find all start indices of the marker
        start_indices = [m.start() for m in re.finditer(re.escape(marker), source_code)]
        
        for idx in start_indices:
            context = self._determine_context(source_code, idx, len(marker))
            contexts.append(context)
            
        return contexts

    def _determine_context(self, code: str, start_index: int, length: int) -> InjectionContext:
        # Get a chunk of context before and after
        prefix = code[max(0, start_index - 50):start_index]
        suffix = code[start_index + length : min(len(code), start_index + length + 50)]
        surrounding = f"{prefix}[MARKER]{suffix}"

        # 1. Check for Script Blocks
        # Simple heuristic: scan backwards for <script and forwards for </script
        # In a real parser we'd track state, but this local scan is often "good enough" for context-aware payloads
        # unless the file is massive and complex.
        
        # Check if inside a script tag roughly
        # This is limited; a true parser is better but slower. Let's do a reliable local regex check.
        # Check if we are inside a quote
        
        in_double = prefix.count('"') % 2 != 0
        in_single = prefix.count("'") % 2 != 0
        
        # Check basic HTML context tags
        # Scan strictly backwards for the last <tag or >
        last_open_carrot = prefix.rfind('<')
        last_close_carrot = prefix.rfind('>')
        
        is_inside_tag_def = last_open_carrot > last_close_carrot # e.g. <div [HERE] >
        
        # Script check: look for <script text before
        script_open = prefix.lower().rfind('<script')
        script_close = prefix.lower().rfind('</script')
        is_likely_in_script = script_open > script_close
        
        # Determine Context
        if is_likely_in_script:
            # We are in JS
            if in_double:
                return InjectionContext(
                    context_type="SCRIPT_STRING", 
                    quote_char='"', 
                    breakout_chars='";',
                    surrounding_text=surrounding
                )
            elif in_single:
                return InjectionContext(
                    context_type="SCRIPT_STRING", 
                    quote_char="'", 
                    breakout_chars="';",
                    surrounding_text=surrounding
                )
            else:
                return InjectionContext(
                    context_type="SCRIPT_CODE", 
                    breakout_chars=";",
                    surrounding_text=surrounding
                )

        if is_inside_tag_def:
            # We are inside an attribute or tag definition
            if in_double:
                return InjectionContext(
                    context_type="ATTRIBUTE", 
                    quote_char='"', 
                    breakout_chars='">', # Break attribute then tag
                    surrounding_text=surrounding
                )
            elif in_single:
                return InjectionContext(
                    context_type="ATTRIBUTE", 
                    quote_char="'", 
                    breakout_chars="'>", 
                    surrounding_text=surrounding
                )
            else:
                # Unquoted attribute value? e.g. value=MARKER
                return InjectionContext(
                    context_type="ATTRIBUTE", 
                    quote_char=None, 
                    breakout_chars='>', 
                    surrounding_text=surrounding
                )

        # HTML Body
        # Check for comments
        # Detect <!-- ... -->
        comment_open = prefix.rfind('<!--')
        comment_close = prefix.rfind('-->')
        if comment_open > comment_close:
             return InjectionContext(
                    context_type="COMMENT", 
                    breakout_chars='-->', 
                    surrounding_text=surrounding
                )

        return InjectionContext(
            context_type="HTML_TAG",
            breakout_chars='<', # Just start a tag
            surrounding_text=surrounding
        )
