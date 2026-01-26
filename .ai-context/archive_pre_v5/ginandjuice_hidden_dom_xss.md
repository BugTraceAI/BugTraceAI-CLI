# Hidden DOM XSS on Gin & Juice Shop (Blog Post)

**Target**: `https://ginandjuice.shop/blog/post?postId=3` (and potentially others)
**Vulnerability Type**: DOM-based Cross-Site Scripting (XSS)
**Parameter**: `back` (URL Query Parameter)
**Status**: Verified

## 📝 Vulnerability Description

The blog post page contains a specific "Back to Blog" button that is **hidden** by default (`display: none`) on certain posts. This button has an `onclick` event handler that is vulnerable to DOM-based XSS.

### The Vulnerable Code

HTML Source:

```html
<div class="is-linkback" style="display: none;">
    <a onclick="event.preventDefault(); location = new URLSearchParams(location.search).get('back') || '/blog'">
        Back to Blog
    </a>
</div>
```

The vulnerability lies in:
`location = new URLSearchParams(location.search).get('back')`

This allows an attacker to control the window location using the `back` URL parameter. If `back` is set to a `javascript:` URI, the JavaScript will execute when the line runs.

## 🕵️ Exploitation Requirements

1. **Navigation**: Victim must visit a URL with the malicious payload.
    * Example: `https://ginandjuice.shop/blog/post?postId=3&back=javascript:alert(1)`
2. **Interaction**: The "Back to Blog" element must be clicked.
    * **Obstacle**: The element is hidden (`display: none`).
    * **Bypass**: The user (or an attacker with script access) must unhide the element via the Browser Console or a separate injection.

## 🚀 Reproduction Steps (Walkthrough)

1. **Navigate to the vulnerable page**:
    Open the following URL in your browser:

    ```
    https://ginandjuice.shop/blog/post?postId=3&back=javascript:alert('XSS_POC')
    ```

2. **Open Developer Tools**:
    Press `F12` or Right Click -> Inspect. Go to the **Console** tab.

3. **Unhide the Button**:
    Paste and run the following JavaScript command to reveal the hidden button:

    ```javascript
    document.querySelector('.is-linkback').style.display = 'block';
    ```

4. **Execute the Attack**:
    * You will see a "Back to Blog" link appear (likely at the top or bottom of the post).
    * **Click** the link.
    * **Result**: An alert box with `XSS_POC` should appear.

## 🛡️ Remediation

* **Sanitize Input**: Validate that the `back` parameter is a relative path (starts with `/`) or a whitelisted URL, and strictly reject protocols like `javascript:` or `data:`.
* **Remove Dead Code**: If the "Back to Blog" button is hidden and unused, remove it from the DOM entirely.
