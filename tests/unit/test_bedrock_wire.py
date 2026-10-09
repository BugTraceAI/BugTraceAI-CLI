"""Unit tests: LLMBedrockMixin pure transforms + converse parse/usage/error.

Tests patch at the _get_bedrock_client boundary (returning a Mock whose .converse
returns/raises) so the asyncio.to_thread wrapper is exercised — never boto3 globally.
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from bugtrace.core.llm_client import LLMClient
from bugtrace.core.llm_shell.bedrock_wire import _bedrock_image_format, _BEDROCK_SHIFT
from bugtrace.core.exceptions import LLMRateLimitError, LLMTimeoutError

pytestmark = pytest.mark.unit

BEDROCK_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


@pytest.fixture
def client():
    return LLMClient()


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Converse")


# ──── _build_bedrock_converse_args (pure) ────


def test_build_args_system_user(client):
    messages = [
        {"role": "system", "content": "sys prompt"},
        {"role": "user", "content": "hello"},
    ]
    args = client._build_bedrock_converse_args(BEDROCK_ID, messages, 0.7, 1500)
    assert args["modelId"] == BEDROCK_ID
    assert args["system"] == [{"text": "sys prompt"}]
    assert args["messages"] == [{"role": "user", "content": [{"text": "hello"}]}]
    assert args["inferenceConfig"] == {"maxTokens": 1500, "temperature": 0.7}


def test_build_args_omits_system_when_absent(client):
    messages = [{"role": "user", "content": "hi"}]
    args = client._build_bedrock_converse_args(BEDROCK_ID, messages, 0.3, 100)
    assert "system" not in args


def test_build_args_multi_turn(client):
    messages = [
        {"role": "user", "content": "q1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "q2"},
    ]
    args = client._build_bedrock_converse_args(BEDROCK_ID, messages, 0.5, 200)
    assert [m["role"] for m in args["messages"]] == ["user", "assistant", "user"]
    assert args["messages"][1]["content"] == [{"text": "a1"}]


# ──── response parse + usage remap ────


def test_parse_bedrock_text_joins_blocks(client):
    data = {"output": {"message": {"content": [{"text": "a"}, {"text": "b"}]}}}
    assert client._parse_bedrock_text(data) == "a\nb"


def test_parse_bedrock_text_empty(client):
    assert client._parse_bedrock_text({"output": {"message": {"content": []}}}) == ""
    assert client._parse_bedrock_text({}) == ""


@pytest.mark.asyncio
async def test_bedrock_generate_usage_remap(client, monkeypatch):
    """Success path remaps inputTokens/outputTokens/totalTokens for telemetry."""
    client.api_format = "bedrock"
    mock_client = MagicMock()
    mock_client.converse.return_value = {
        "output": {"message": {"content": [{"text": "the answer"}]}},
        "usage": {"inputTokens": 11, "outputTokens": 22, "totalTokens": 33},
    }
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)

    captured = {}

    async def fake_update(data, model, module):
        captured["usage"] = data["usage"]

    monkeypatch.setattr(client, "_update_telemetry", fake_update)

    out = await client._bedrock_generate(
        BEDROCK_ID, [{"role": "user", "content": "q"}], "Mod", "q",
        0.7, 100, None, None, None,
    )
    assert out == "the answer"
    assert captured["usage"] == {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}
    assert mock_client.converse.called


@pytest.mark.asyncio
async def test_bedrock_generate_empty_output_shifts(client, monkeypatch):
    client.api_format = "bedrock"
    mock_client = MagicMock()
    mock_client.converse.return_value = {"output": {"message": {"content": []}}}
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)
    out = await client._bedrock_generate(
        BEDROCK_ID, [{"role": "user", "content": "q"}], "Mod", "q",
        0.7, 100, None, None, None,
    )
    assert out is None


# ──── error translation ────


@pytest.mark.asyncio
async def test_converse_throttling_raises_rate_limit(client, monkeypatch):
    mock_client = MagicMock()
    mock_client.converse.side_effect = _client_error("ThrottlingException")
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)
    with pytest.raises(LLMRateLimitError):
        await client._bedrock_converse_call(BEDROCK_ID, {"modelId": BEDROCK_ID})


@pytest.mark.asyncio
async def test_converse_model_timeout_raises_timeout(client, monkeypatch):
    mock_client = MagicMock()
    mock_client.converse.side_effect = _client_error("ModelTimeoutException")
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)
    with pytest.raises(LLMTimeoutError):
        await client._bedrock_converse_call(BEDROCK_ID, {"modelId": BEDROCK_ID})


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [
    "AccessDeniedException",
    "UnrecognizedClientException",
    "ValidationException",
    "ResourceNotFoundException",
])
async def test_converse_permanent_codes_return_shift(client, monkeypatch, code):
    mock_client = MagicMock()
    mock_client.converse.side_effect = _client_error(code)
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)
    result = await client._bedrock_converse_call(BEDROCK_ID, {"modelId": BEDROCK_ID})
    assert result[0] is _BEDROCK_SHIFT


@pytest.mark.asyncio
async def test_converse_unexpected_exception_returns_shift(client, monkeypatch):
    mock_client = MagicMock()
    mock_client.converse.side_effect = RuntimeError("boom")
    monkeypatch.setattr(client, "_get_bedrock_client", lambda region: mock_client)
    result = await client._bedrock_converse_call(BEDROCK_ID, {"modelId": BEDROCK_ID})
    assert result[0] is _BEDROCK_SHIFT


# ──── _bedrock_image_format (pure) ────


@pytest.mark.parametrize("path,expected", [
    ("shot.png", "png"),
    ("shot.PNG", "png"),
    ("shot.jpg", "jpeg"),
    ("shot.jpeg", "jpeg"),
    ("shot.JPEG", "jpeg"),
    ("shot.gif", "png"),
    ("noext", "png"),
])
def test_bedrock_image_format(path, expected):
    assert _bedrock_image_format(path) == expected
