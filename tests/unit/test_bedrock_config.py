"""Unit tests: Bedrock config validators + preset region seeding.

The relaxed validate_model_name / validate_model_list must accept the Bedrock id
shape (dotted/segmented, optional ':' version suffix, no '/') on actually-decorated
fields and still reject garbage. REPORTING_MODEL is decorated by NEITHER validator,
so it is never used here.
"""

import json

import pytest

from bugtrace.core.config import Settings


BEDROCK_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

pytestmark = pytest.mark.unit


def test_validate_model_name_accepts_bedrock_id_on_default_model():
    s = Settings(DEFAULT_MODEL=BEDROCK_ID)
    assert s.DEFAULT_MODEL == BEDROCK_ID


def test_validate_model_name_still_accepts_openrouter_shape():
    s = Settings(DEFAULT_MODEL="anthropic/claude-haiku-4.5")
    assert s.DEFAULT_MODEL == "anthropic/claude-haiku-4.5"


def test_validate_model_name_rejects_garbage():
    with pytest.raises(ValueError):
        Settings(DEFAULT_MODEL="not a valid id!!")


def test_validate_model_list_accepts_bedrock_id_on_primary_models():
    s = Settings(PRIMARY_MODELS=BEDROCK_ID)
    assert s.PRIMARY_MODELS == BEDROCK_ID


def test_validate_model_list_accepts_mixed_and_rejects_garbage():
    # A comma list of two Bedrock ids is fine.
    s = Settings(WAF_DETECTION_MODELS=f"{BEDROCK_ID},{BEDROCK_ID}")
    assert BEDROCK_ID in s.WAF_DETECTION_MODELS
    with pytest.raises(ValueError):
        Settings(PRIMARY_MODELS="bad entry with spaces")


def test_bedrock_region_default_is_us_east_1():
    s = Settings()
    assert s.BEDROCK_REGION == "us-east-1"


def test_bedrock_region_lowercased_and_lenient():
    # A mismatched region shape warns but does NOT fail; value is lowercased.
    s = Settings(BEDROCK_REGION="US-EAST-1")
    assert s.BEDROCK_REGION == "us-east-1"
    s2 = Settings(BEDROCK_REGION="not-a-region")
    assert s2.BEDROCK_REGION == "not-a-region"


def test_preset_seeds_bedrock_region_only_when_not_overridden():
    # Default region + bedrock preset => seeded from preset region.
    s = Settings(PROVIDER="bedrock")
    s._load_provider_preset()
    preset = json.loads(
        (s.BASE_DIR / "bugtrace" / "data" / "providers" / "bedrock.json").read_text()
    )
    assert s.BEDROCK_REGION == preset["region"]


def test_preset_does_not_clobber_user_region():
    # An explicit non-default region is authoritative; the preset must not seed over it.
    s = Settings(PROVIDER="bedrock", BEDROCK_REGION="eu-west-1")
    s._load_provider_preset()
    assert s.BEDROCK_REGION == "eu-west-1"
