"""Integration tests: Bedrock across all three dispatch forks (mocked boto3).

The mock lives at the _get_bedrock_client boundary so asyncio.to_thread runs. No
real AWS calls. Covers the main-fork model-shift, the thread fork, and both vision
entry points (asserting RAW image bytes reach the converse call).
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from bugtrace.core.llm_client import LLMClient
from bugtrace.core.conversation_thread import ConversationThread

pytestmark = pytest.mark.integration

M1 = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
M2 = "us.anthropic.claude-sonnet-4-5-20250101-v1:0"


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Converse")


def _ok(text):
    return {
        "output": {"message": {"content": [{"text": text}]}},
        "usage": {"inputTokens": 1, "outputTokens": 2, "totalTokens": 3},
    }


@pytest.fixture
def bedrock_client(monkeypatch):
    client = LLMClient()
    client.api_format = "bedrock"
    client.provider_id = "bedrock"
    client.models = [M1, M2]
    client.base_url = ""
    client._concurrency_cfg = {"default": 2}
    client._model_semaphores = {}
    client._rate_limiters = {}
    client._failover_providers = []
    return client


@pytest.mark.asyncio
async def test_main_fork_model_shift(bedrock_client, monkeypatch):
    """First model returns empty (shift), second succeeds; both audit-logged, one circuit success."""
    mock_boto = MagicMock()

    def converse(**kwargs):
        if kwargs["modelId"] == M1:
            # Permanent per-model failure -> shift sentinel -> audit ERROR + shift.
            raise _client_error("ValidationException")
        return _ok("second works")

    mock_boto.converse.side_effect = converse
    monkeypatch.setattr(bedrock_client, "_get_bedrock_client", lambda region: mock_boto)

    audit_calls = []

    async def fake_audit(module, model, prompt, response):
        audit_calls.append((model, response))

    monkeypatch.setattr(bedrock_client, "_audit_log", fake_audit)

    circuit = {"success": 0}
    monkeypatch.setattr(bedrock_client, "_record_circuit_success", lambda: circuit.__setitem__("success", circuit["success"] + 1))

    out = await bedrock_client.generate("prompt", "Mod", temperature=0.7, max_tokens=50)
    assert out == "second works"
    # Both models produced an audit entry (M1 error + M2 success)
    audited_models = [m for m, _ in audit_calls]
    assert M1 in audited_models and M2 in audited_models
    assert circuit["success"] == 1


@pytest.mark.asyncio
async def test_thread_fork(bedrock_client, monkeypatch):
    """Thread fork delegates to boto3 and records the assistant turn."""
    mock_boto = MagicMock()
    mock_boto.converse.return_value = _ok("threaded reply")
    monkeypatch.setattr(bedrock_client, "_get_bedrock_client", lambda region: mock_boto)

    async def fake_audit(*a, **k):
        return None

    monkeypatch.setattr(bedrock_client, "_audit_log", fake_audit)

    thread = ConversationThread(target_url="http://example.com")
    out = await bedrock_client.generate_with_thread("question?", thread, "URLMaster")
    assert out == "threaded reply"
    # The assistant turn was appended to the thread.
    api_msgs = thread.get_messages(format_for_api=True)
    assert any(m.get("role") == "assistant" and m.get("content") == "threaded reply" for m in api_msgs)


@pytest.mark.asyncio
async def test_vision_generate_with_image_sends_raw_bytes(bedrock_client, monkeypatch, tmp_path):
    """generate_with_image (Fork 3a): file path -> RAW bytes reach converse (not base64)."""
    img = tmp_path / "proof.png"
    raw = b"\x89PNG\r\n\x1a\nRAWIMAGEDATA"
    img.write_bytes(raw)

    mock_boto = MagicMock()
    mock_boto.converse.return_value = _ok("I see an alert box")
    monkeypatch.setattr(bedrock_client, "_get_bedrock_client", lambda region: mock_boto)

    async def fake_audit(*a, **k):
        return None

    monkeypatch.setattr(bedrock_client, "_audit_log", fake_audit)

    out = await bedrock_client.generate_with_image("describe", str(img), module_name="XSS")
    assert out == "I see an alert box"

    kwargs = mock_boto.converse.call_args.kwargs
    img_block = kwargs["messages"][0]["content"][1]["image"]
    assert img_block["format"] == "png"
    assert img_block["source"]["bytes"] == raw  # raw, not base64


@pytest.mark.asyncio
async def test_vision_analyze_visual_sends_raw_bytes(bedrock_client, monkeypatch):
    """analyze_visual (Fork 3b): in-memory bytes reach converse as raw, format jpeg."""
    raw = b"JPEGRAWSCREENSHOTBYTES"

    mock_boto = MagicMock()
    mock_boto.converse.return_value = _ok("screenshot analysis")
    monkeypatch.setattr(bedrock_client, "_get_bedrock_client", lambda region: mock_boto)

    async def fake_audit(*a, **k):
        return None

    monkeypatch.setattr(bedrock_client, "_audit_log", fake_audit)

    out = await bedrock_client.analyze_visual(raw, "what is here?", module_name="Recon")
    assert out == "screenshot analysis"

    kwargs = mock_boto.converse.call_args.kwargs
    img_block = kwargs["messages"][0]["content"][1]["image"]
    assert img_block["format"] == "jpeg"
    assert img_block["source"]["bytes"] == raw
