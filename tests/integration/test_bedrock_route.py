"""Integration tests: the WEB server-side Bedrock test route (mocked boto3).

_test_bedrock must map boto3 exceptions to {success, message} and never raise an
unhandled 500. boto3 is patched at boto3.client (the local import inside the route).
"""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from bugtrace.api.routes.providers import test_provider_key as provider_test_route
from bugtrace.api.routes.providers import TestProviderRequest

pytestmark = pytest.mark.integration


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Converse")


@pytest.mark.asyncio
async def test_route_success(monkeypatch):
    mock_boto = MagicMock()
    mock_boto.converse.return_value = {"output": {"message": {"content": [{"text": "yes"}]}}}
    monkeypatch.setattr("boto3.client", lambda *a, **k: mock_boto)

    res = await provider_test_route(TestProviderRequest(provider="bedrock", region="us-east-1"))
    assert res["success"] is True


@pytest.mark.asyncio
async def test_route_invalid_credentials(monkeypatch):
    mock_boto = MagicMock()
    mock_boto.converse.side_effect = _client_error("AccessDeniedException")
    monkeypatch.setattr("boto3.client", lambda *a, **k: mock_boto)

    res = await provider_test_route(TestProviderRequest(provider="bedrock"))
    assert res["success"] is False
    assert "credentials" in res["message"].lower() or "permission" in res["message"].lower()


@pytest.mark.asyncio
async def test_route_model_not_in_region(monkeypatch):
    mock_boto = MagicMock()
    mock_boto.converse.side_effect = _client_error("ValidationException")
    monkeypatch.setattr("boto3.client", lambda *a, **k: mock_boto)

    res = await provider_test_route(TestProviderRequest(provider="bedrock"))
    assert res["success"] is False
    assert "region" in res["message"].lower()


@pytest.mark.asyncio
async def test_route_throttled(monkeypatch):
    mock_boto = MagicMock()
    mock_boto.converse.side_effect = _client_error("ThrottlingException")
    monkeypatch.setattr("boto3.client", lambda *a, **k: mock_boto)

    res = await provider_test_route(TestProviderRequest(provider="bedrock"))
    assert res["success"] is False
    assert "throttl" in res["message"].lower()


@pytest.mark.asyncio
async def test_route_no_credentials(monkeypatch):
    def boom(*a, **k):
        raise NoCredentialsError()

    mock_boto = MagicMock()
    mock_boto.converse.side_effect = boom
    monkeypatch.setattr("boto3.client", lambda *a, **k: mock_boto)

    res = await provider_test_route(TestProviderRequest(provider="bedrock"))
    assert res["success"] is False
