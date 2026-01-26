"""
Unit tests for security tools modules (TASK-117).

Tests for:
- bugtrace/tools/external.py
- bugtrace/tools/interactsh.py
"""
import pytest
import json


class TestExternalToolsSecurity:
    """Tests for external.py security functions."""

    def test_validate_docker_image_trusted(self):
        """Test that trusted images pass validation."""
        from bugtrace.tools.external import _validate_docker_image

        assert _validate_docker_image("projectdiscovery/nuclei:latest") is True
        assert _validate_docker_image("projectdiscovery/nuclei") is True
        assert _validate_docker_image("googlesky/sqlmap:latest") is True
        assert _validate_docker_image("trickest/gospider") is True

    def test_validate_docker_image_untrusted(self):
        """Test that untrusted images are blocked."""
        from bugtrace.tools.external import _validate_docker_image

        assert _validate_docker_image("evil/malware:latest") is False
        assert _validate_docker_image("random/image") is False
        assert _validate_docker_image("alpine") is False

    def test_sanitize_output_removes_ansi(self):
        """Test ANSI escape code removal."""
        from bugtrace.tools.external import _sanitize_output

        # ANSI color codes
        dirty = "\x1b[31mRed Text\x1b[0m Normal"
        clean = _sanitize_output(dirty)
        assert "\x1b" not in clean
        assert "Red Text" in clean
        assert "Normal" in clean

    def test_sanitize_output_removes_control_chars(self):
        """Test control character removal."""
        from bugtrace.tools.external import _sanitize_output

        dirty = "Normal\x00\x01\x02Hidden\x7fText"
        clean = _sanitize_output(dirty)
        assert "\x00" not in clean
        assert "\x7f" not in clean
        assert "NormalHiddenText" in clean

    def test_sanitize_output_preserves_newlines(self):
        """Test that newlines are preserved."""
        from bugtrace.tools.external import _sanitize_output

        text = "Line 1\nLine 2\tTabbed"
        clean = _sanitize_output(text)
        assert "\n" in clean
        assert "\t" in clean

    def test_check_json_depth_valid(self):
        """Test valid JSON depth passes."""
        from bugtrace.tools.external import _check_json_depth

        # Depth 5 nested object
        obj = {"a": {"b": {"c": {"d": {"e": "value"}}}}}
        _check_json_depth(obj)  # Should not raise

    def test_check_json_depth_excessive(self):
        """Test excessive JSON depth raises error."""
        from bugtrace.tools.external import _check_json_depth, MAX_JSON_DEPTH

        # Create deeply nested object
        obj = "value"
        for _ in range(MAX_JSON_DEPTH + 5):
            obj = {"nested": obj}

        with pytest.raises(ValueError, match="JSON depth exceeds"):
            _check_json_depth(obj)

    def test_parse_tool_output_valid(self):
        """Test valid JSON parsing."""
        from bugtrace.tools.external import _parse_tool_output

        valid_json = '{"success": true, "data": {"key": "value"}}'
        result = _parse_tool_output(valid_json)
        assert result["success"] is True
        assert result["data"]["key"] == "value"

    def test_parse_tool_output_too_large(self):
        """Test oversized output is rejected."""
        from bugtrace.tools.external import _parse_tool_output

        large_output = "x" * 20_000_000  # 20MB
        with pytest.raises(ValueError, match="too large"):
            _parse_tool_output(large_output)

    def test_parse_tool_output_invalid_json(self):
        """Test invalid JSON raises error."""
        from bugtrace.tools.external import _parse_tool_output

        with pytest.raises(json.JSONDecodeError):
            _parse_tool_output("not valid json {")


class TestInteractshSecurity:
    """Tests for interactsh.py security functions."""

    def test_validate_server_trusted(self):
        """Test that trusted servers pass validation."""
        from bugtrace.tools.interactsh import validate_interactsh_server

        assert validate_interactsh_server("oast.fun") == "oast.fun"
        assert validate_interactsh_server("oast.pro") == "oast.pro"
        assert validate_interactsh_server("interact.sh") == "interact.sh"

    def test_validate_server_with_protocol(self):
        """Test protocol stripping works."""
        from bugtrace.tools.interactsh import validate_interactsh_server

        assert validate_interactsh_server("https://oast.fun") == "oast.fun"
        assert validate_interactsh_server("http://oast.pro") == "oast.pro"

    def test_validate_server_untrusted(self):
        """Test untrusted servers are rejected."""
        from bugtrace.tools.interactsh import validate_interactsh_server

        with pytest.raises(ValueError, match="Untrusted"):
            validate_interactsh_server("evil.attacker.com")

        with pytest.raises(ValueError, match="Untrusted"):
            validate_interactsh_server("my-oast-server.io")

    def test_validate_correlation_id_valid(self):
        """Test valid correlation IDs pass."""
        from bugtrace.tools.interactsh import validate_correlation_id

        valid_id = "a1b2c3d4e5f6a1b2c3d4"  # 20 hex chars
        assert validate_correlation_id(valid_id) == valid_id

        long_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"  # 40 hex chars
        assert validate_correlation_id(long_id) == long_id

    def test_validate_correlation_id_invalid(self):
        """Test invalid correlation IDs are rejected."""
        from bugtrace.tools.interactsh import validate_correlation_id

        # Too short
        with pytest.raises(ValueError, match="Invalid correlation ID"):
            validate_correlation_id("abc123")

        # Non-hex characters
        with pytest.raises(ValueError, match="Invalid correlation ID"):
            validate_correlation_id("g1h2i3j4k5l6m7n8o9p0")

        # Injection attempt
        with pytest.raises(ValueError, match="Invalid correlation ID"):
            validate_correlation_id("valid12345'; DROP TABLE--")


class TestExternalToolManagerMetrics:
    """Tests for tool metrics tracking."""

    def test_tool_info_returns_structure(self):
        """Test get_tool_info returns expected structure."""
        from bugtrace.tools.external import ExternalToolManager

        manager = ExternalToolManager()
        info = manager.get_tool_info()

        assert "versions" in info
        assert "run_counts" in info
        assert "last_run" in info
        assert "docker_available" in info

    def test_record_tool_run_increments_count(self):
        """Test that recording a run increments the counter."""
        from bugtrace.tools.external import ExternalToolManager

        manager = ExternalToolManager()

        manager._record_tool_run("test_tool")
        assert manager._tool_run_counts.get("test_tool") == 1

        manager._record_tool_run("test_tool")
        assert manager._tool_run_counts.get("test_tool") == 2

    def test_record_tool_run_updates_timestamp(self):
        """Test that recording a run updates the timestamp."""
        from bugtrace.tools.external import ExternalToolManager
        import time

        manager = ExternalToolManager()

        before = time.time()
        manager._record_tool_run("test_tool")
        after = time.time()

        assert before <= manager._tool_last_run["test_tool"] <= after
