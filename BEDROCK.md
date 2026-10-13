# Amazon Bedrock (beta)

The CLI supports Bedrock Converse for text, conversation history, screenshot
validation and connectivity checks. The WEB Provider panel can configure this
CLI engine, including its source region and optional Bedrock API key.

**Validation status:** offline tests cover the real boto3/botocore 1.40.0
serializer and both bearer and SigV4 authentication with intercepted network
requests. A real AWS account check remains pending. Model access, IAM
permissions, quotas and credential renewal must be confirmed in your runtime.

## Configuration

Install the current CLI dependencies, including boto3 1.40.0 or newer. Select
Bedrock in Provider (F7), or set the configured provider:

```ini
[PROVIDER]
ACTIVE = bedrock
# Optional: otherwise use AWS_REGION, AWS_DEFAULT_REGION or the AWS profile.
# BEDROCK_REGION = eu-west-1
```

The CLI runtime can use its normal AWS role/profile credential chain without
a Bedrock API key. An optional bearer token is read from
`AWS_BEARER_TOKEN_BEDROCK`. Keep credentials in the runtime's environment or
local `.env`, rather than sharing them in a report or GitHub comment.

The preset uses `amazon.nova-pro-v1:0`. Your account and source region must
support the selected model. Use account-approved model IDs or inference-profile
IDs/ARNs in `[LLM_MODELS]` when needed. Explicit assignments now override preset
defaults; remove old assignments from another provider before selecting Bedrock,
or replace them with AWS-compatible models. Omitted slots inherit the preset.

For Docker, the CLI Compose services read their local `.env`. A host AWS profile
is not automatically available inside the container: supply a credential source
to the CLI container through your deployment configuration. Use the container's
effective AWS identity and region when validating access.

The WEB/CLI Provider panel loads the saved source region. A blank region clears
the BugTraceAI override and uses the runtime's AWS configuration. It supports
connection tests and saving with an AWS role/profile without entering a key.
An unsaved key test does not replace the active process credential.

## Reporting and regional routing

Bedrock's preset has no external provider fallback. Reporting enrichment also
blocks external provider fallback by default. Only enable
`BEDROCK_ALLOW_EXTERNAL_REPORTING_FAILOVER=true` when sending reporting data to
the configured secondary provider is permitted by your deployment policy.

A source region does not guarantee processing stays in that region. Inference
profiles can route requests across regions; choose the model/profile and AWS
policy appropriate to your account.

## Account validation

In the same runtime that will run scans:

1. Confirm its AWS identity has Bedrock Converse access to the selected model
   or inference profile in the chosen source region.
2. Select Bedrock and use the WEB/CLI Provider connection test, or
   `POST /api/provider/test` with `{"provider":"bedrock","region":"eu-west-1"}`.
3. Run a short scan of an authorized target and confirm text generation and
   screenshot validation for a model that supports images.
4. Record the CLI/WEB versions, SDK versions, region, model/profile IDs and
   authentication method. Share results and sanitized errors, never credentials.

This delivery covers the CLI and its WEB configuration panel. The separate
BugTraceAI-API engine and WEB's own assistant/ModelLab do not gain Bedrock support.

Thanks to [@sjimnar](https://github.com/sjimnar) for the Bedrock proposal and
contributions in [CLI #7](https://github.com/BugTraceAI/BugTraceAI-CLI/pull/7),
[WEB #2](https://github.com/BugTraceAI/BugTraceAI-WEB/pull/2) and
[documentation #16](https://github.com/BugTraceAI/BugTraceAI/pull/16).
