import pytest
from bugtrace.utils.parsers import XmlParser

class TestXmlParser:
    def test_basic_extraction(self):
        content = "<tag>content</tag>"
        assert XmlParser.extract_tag(content, "tag") == "content"

    def test_case_insensitive_tags(self):
        content = "<TAG>content</TAG>"
        assert XmlParser.extract_tag(content, "tag") == "content"
        
        content = "<Tag>content</Tag>"
        assert XmlParser.extract_tag(content, "tag") == "content"

    def test_multiline_content(self):
        content = """<tag>
        line1
        line2
        </tag>"""
        extracted = XmlParser.extract_tag(content, "tag")
        assert "line1" in extracted
        assert "line2" in extracted

    def test_missing_tag(self):
        content = "<other>content</other>"
        assert XmlParser.extract_tag(content, "tag") is None

    def test_extract_multiple_tags(self):
        content = """
        <thought>thinking...</thought>
        <payload>alert(1)</payload>
        """
        tags = ["thought", "payload", "missing"]
        results = XmlParser.extract_tags(content, tags)
        
        assert results["thought"] == "thinking..."
        assert results["payload"] == "alert(1)"
        assert results["missing"] is None

    def test_noisy_llm_output(self):
        content = """
        Here is the output:
        ```xml
        <payload>alert(1)</payload>
        ```
        Hope this helps!
        """
        assert XmlParser.extract_tag(content, "payload") == "alert(1)"

    def test_nested_like_content_handling(self):
        # We expect it to grab everything between the first <tag> and the first </tag> encountered?
        # Or greedy? The regex is non-greedy `(.*?)`. 
        # So <tag><a>b</a></tag> -> <a>b</a>
        content = "<wrapper><b>inner</b></wrapper>"
        assert XmlParser.extract_tag(content, "wrapper") == "<b>inner</b>"

    def test_complex_payload_with_quotes(self):
        content = "<payload>'; DROP TABLE users; --</payload>"
        assert XmlParser.extract_tag(content, "payload") == "'; DROP TABLE users; --"

    def test_extract_list(self):
        content = """
        <item>Item 1</item>
        <item>Item 2</item>
        <other>Other</other>
        """
        items = XmlParser.extract_list(content, "item")
        assert len(items) == 2
        assert items[0] == "Item 1"
        assert items[1] == "Item 2"
        
        assert XmlParser.extract_list(content, "missing") == []
