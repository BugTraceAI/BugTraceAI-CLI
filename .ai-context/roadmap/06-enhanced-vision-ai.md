# Enhanced Vision AI - Feature Tasks

## Feature Overview
Strengthen our UNIQUE competitive advantage with multi-model ensemble, OCR, video recording, and visual regression.

**Why**: This is what competitors DON'T have - make it best-in-class
**Competitor Gap**: NONE - We are the only framework with Vision AI
**Phase**: 3 - Unique Differentiators
**Duration**: 3 weeks
**Effort**: $25k

---

## 🔵 Multi-Model Vision Ensemble

### FEATURE-062: Add Gemini Vision Model
**Complexity**: 🔵 MEDIUM (2 days)

```python
async def validate_with_gemini(self, screenshot_path):
    with open(screenshot_path, 'rb') as f:
        image_data = base64.b64encode(f.read()).decode()

    response = await llm_client.generate(
        prompt=f"Does this screenshot show evidence of XSS execution? Analyze carefully.",
        model="google/gemini-3-flash-preview",
        images=[image_data]
    )
    return self.parse_vision_response(response)
```

### FEATURE-063: Add GPT-4V Model
**Complexity**: 🔵 MEDIUM (2 days)

```python
async def validate_with_gpt4v(self, screenshot_path):
    response = await openai.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": "Is there evidence of XSS in this screenshot?"},
                {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_data}"}}
            ]
        }]
    )
    return response.choices[0].message.content
```

### FEATURE-064: Implement Ensemble Voting
**Complexity**: 🔵 MEDIUM (3 days)

```python
async def vision_ensemble_validation(self, screenshot_path, exploit_type):
    results = await asyncio.gather(
        self.validate_with_qwen(screenshot_path),
        self.validate_with_gemini(screenshot_path),
        self.validate_with_gpt4v(screenshot_path)
    )

    # Majority vote
    confirmations = sum(1 for r in results if r.confirmed)
    confidence = confirmations / len(results)

    return {
        "confirmed": confirmations >= 2,
        "confidence": confidence,
        "individual_results": results
    }
```

---

## 🟠 OCR + Screenshot Analysis

### FEATURE-065: Add Tesseract OCR Integration
**Complexity**: 🔵 MEDIUM (2 days)

```python
# pip install pytesseract pillow
import pytesseract
from PIL import Image

async def extract_text_from_screenshot(self, screenshot_path):
    image = Image.open(screenshot_path)
    text = pytesseract.image_to_string(image)
    return text
```

### FEATURE-066: Detect Domain Names in Screenshots
**Complexity**: 🔵 MEDIUM (2 days)

```python
async def validate_correct_domain(self, screenshot_path, expected_domain):
    text = await self.extract_text_from_screenshot(screenshot_path)

    # Check if expected domain appears
    if expected_domain in text:
        return True

    # Check for phishing/confusion attacks
    suspicious_domains = ["evil.com", "attacker.com"]
    for domain in suspicious_domains:
        if domain in text:
            logger.warning(f"Suspicious domain detected: {domain}")
            return False

    return True
```

### FEATURE-067: Validate CSRF Token Presence
**Complexity**: 🟣 QUICK (1 day)

```python
async def detect_csrf_token(self, screenshot_path):
    text = await self.extract_text_from_screenshot(screenshot_path)

    patterns = ["csrf_token", "_token", "authenticity_token"]
    for pattern in patterns:
        if pattern.lower() in text.lower():
            return True

    return False
```

---

## 🟠 Video Recording

### FEATURE-068: Record Exploit Execution
**Complexity**: 🟠 COMPLEX (1 week)

```python
# pip install playwright
async def record_exploit_video(self, url, payload):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        # Start recording
        await page.context.tracing.start(screenshots=True, snapshots=True)

        # Execute exploit
        await page.goto(f"{url}?payload={payload}")
        await asyncio.sleep(5)  # Record 5 seconds

        # Stop recording
        await page.context.tracing.stop(path=f"exploit_video_{timestamp}.zip")

    # Convert to video
    self.convert_trace_to_video(f"exploit_video_{timestamp}.zip")
```

### FEATURE-069: Convert Playwright Trace to MP4
**Complexity**: 🔵 MEDIUM (2 days)

```bash
# Use FFmpeg
ffmpeg -framerate 30 -pattern_type glob -i 'screenshots/*.png' -c:v libx264 exploit.mp4
```

---

## 🔵 Visual Regression Testing

### FEATURE-070: Screenshot Diffing
**Complexity**: 🔵 MEDIUM (3 days)

```python
# pip install imagehash pillow
from PIL import Image
import imagehash

async def compare_screenshots(self, before_path, after_path):
    before = Image.open(before_path)
    after = Image.open(after_path)

    hash_before = imagehash.average_hash(before)
    hash_after = imagehash.average_hash(after)

    diff = hash_after - hash_before

    if diff > 10:  # Significant difference
        return {"changed": True, "difference": diff}

    return {"changed": False, "difference": diff}
```

### FEATURE-071: Highlight Visual Differences
**Complexity**: 🔵 MEDIUM (2 days)

```python
# pip install pixelmatch
from pixelmatch import pixelmatch

def highlight_differences(before_path, after_path, output_path):
    before_img = Image.open(before_path).convert('RGB')
    after_img = Image.open(after_path).convert('RGB')

    width, height = before_img.size
    diff_img = Image.new('RGB', (width, height))

    mismatch = pixelmatch(
        before_img.tobytes(),
        after_img.tobytes(),
        diff_img.tobytes(),
        width,
        height,
        threshold=0.1
    )

    diff_img.save(output_path)
    return mismatch
```

---

## Summary

**Total Tasks**: 10 (Phase 3a - Vision AI)
**Estimated Effort**: 3 weeks
**Investment**: ~$25k

**Competitive Advantage**: UNIQUE - No competitor has Vision AI validation

**Models Used**:
1. Qwen3-VL-8B-Thinking (current)
2. Google Gemini 3 Flash (new)
3. GPT-4V (new)

**Cost Impact**:
- Vision API calls: ~$0.01 per screenshot
- 1,000 screenshots/month = $10/month additional
