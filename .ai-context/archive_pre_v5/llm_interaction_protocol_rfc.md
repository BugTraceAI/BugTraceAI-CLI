# RFC 001: LLM Interaction Protocol - XML-Like Output Format

## 1. Context & Problem Statement

Currently, the BugTraceAI framework relies heavily on JSON for structured output from LLMs (e.g., `XSSAgent`, `SQLAgent`). While JSON is a standard data interchange format, it presents significant challenges when generating it via Large Language Models (LLMs):

1. **Syntactic Fragility**: A single missing comma, unescaped quote within a string, or trailing comma can break the entire JSON structure, causing the agent to fail.
2. **"Chatty" Models**: Many modern models (especially reasoning models like DeepSeek or O1) tend to wrap code/JSON in markdown blocks (```json ...```) or add conversational filler text before/after the data ("Here is the payload you requested...").
3. **Parsing Complexity**: We currently use complex regexes and fallback mechanisms (like brace balancing) to extract JSON from the noisy output. This adds maintenance overhead and creates points of failure.
4. **Token Overhead**: JSON syntax (`{ "key": "value" }`) adds unnecessary token overhead compared to simpler formats.

## 2. Proposed Solution: XML-Like Tagged Format

We propose migrating from strict JSON to a **Robust XML-Like Tagged Format** for all LLM outputs involving payload generation, reasoning, or structured data.

### The Format

Instead of a JSON object, the LLM will be instructed to output data wrapped in specific, custom tags.

**Example Prompt Instruction:**
> "Output your response using the following tags: `<payload>`, `<technique>`, and `<confidence>`. Do not use Markdown code blocks."

**Example Model Output:**

```xml
I have analyzed the sanitization map and found a weakness in the backslash handling.

<thought>
The target filters single quotes but allows backslashes. I will use the 'escape-the-escape' technique.
</thought>

<payload>
\';alert(1)//
</payload>

<technique>
Escape-the-escape bypass for JS context
</technique>

<confidence>
0.95
</confidence>
```

## 3. Benefits

1. **Extreme Robustness**: Parsing is done via simple Regex (`<tag>(.*?)</tag>`). This ignores all surrounding noise, conversational text, or markdown formatting.
2. **No Escaping Hell**: Unlike JSON, the content inside `<payload>` does not need to have its quotes escaped. If the payload is `'`, in JSON it must be `"'"`, which confuses models. In XML-like, it's just `<payload>'</payload>`.
3. **Streaming Compatible**: We can parse the tags as they stream in, allowing for real-time UI updates (e.g., showing the `<thought>` process while the `<payload>` is being generated).
4. **Simplified Prompts**: We don't need to give complex instructions about "valid JSON only" or "no trailing text".

## 4. Technical Implementation Strategy

### 4.1. New Parser Utility

We will create a centralized parser entity, likely within `bugtrace/core/llm_client.py` or a util module.

```python
import re

def parse_xml_tag(content: str, tag: str) -> str:
    """
    Robustly extracts content between <tag> and </tag>.
    Flags: DOTALL (matches newlines), IGNORECASE.
    """
    pattern = fk"<{tag}>(.*?)</{tag}>"
    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else None

def parse_xml_tags(content: str, tags: list[str]) -> dict:
    return {tag: parse_xml_tag(content, tag) for tag in tags}
```

### 4.2. Prompt Templates Update

Updating the system prompts for agents.

**Old (JSON):**

```text
Response format (JSON only):
{"bypass_payload": "...", "technique": "...", "confidence": 0.85}
```

**New (XML-Like):**

```text
Response format:
<bypass_payload>Your Payload Here</bypass_payload>
<technique>Technique Description</technique>
<confidence>0.85</confidence>
```

## 5. Standardization Guidelines for New Agents

To ensure consistency across the project when adopting this protocol:

1. **Tag Naming**: Use `snake_case` for all tags (e.g., `<sql_query>`, not `<SqlQuery>`).
2. **No Attributes**: Do not use XML attributes (e.g., `<step number="1">`). LLMs often hallucinate format or forget quotes. Use child tags if needed.
3. **Self-Closing Tags**: Avoid self-closing tags (`<br/>`). Always use full opening and closing pairs.
4. **Content CDATA**: Do not use `<![CDATA[...]]>`. The parser is robust enough to handle raw content as long as the closing tag doesn't appear inside.
5. **Prompt Instruction**: Always include the phrase: *"Use XML-like tags, NO Markdown blocks"* to prevent the model from wrapping the XML in ```xml ...```.

## 6. Migration Roadmap

1. **Phase 1: Foundation (Immediate)**
    * Implement `XmlParser` utility in `bugtrace/utils/parsers.py`.
    * Add unit tests for the parser with messy/noisy inputs.

2. **Phase 2: XSS Agent (High Priority)**
    * Update `_llm_generate_bypass` in `XSSAgent` to use the new format.
    * This resolves the recent issues with DeepSeek adding explanations after JSON.

3. **Phase 3: Rollout**
    * Update `SQLAgent`, `ExploitAgent`, and others iteratively.
    * Update `LLMClient` to transparently handle this if desired.

## 6. Conclusion

Moving to an XML-Like format addresses the root cause of our most frequent "AI Glue" errors. It treats the LLM output as a text stream containing data islands, rather than expecting a perfectly formed data structure, aligning better with the statistical nature of LLMs.
