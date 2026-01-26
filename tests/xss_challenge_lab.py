#!/usr/bin/env python3
"""
XSS Challenge Lab for BugtraceAI-CLI Testing

A local Flask server with multiple XSS challenges of varying difficulty.
This allows controlled testing of the XSSAgent without external dependencies.

Challenges:
1. Level 1 (Easy): Direct reflection, no filtering
2. Level 2 (Medium): Basic HTML encoding, attribute context
3. Level 3 (Hard): JavaScript context, partial filtering
4. Level 4 (Expert): DOM XSS, no direct reflection
5. Level 5 (Nightmare): Multiple encoding, CSP bypass needed

Usage:
    python tests/xss_challenge_lab.py
    # Server runs on http://localhost:5555

Author: BugtraceAI Team
Date: 2026-01-08
"""

from flask import Flask, request, render_template_string, make_response
import html
import re
import urllib.parse

app = Flask(__name__)

# ============================================================================
# TEMPLATES
# ============================================================================

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Challenge Lab - Level {{ level }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #e94560; }
        .challenge { background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .level { background: #e94560; color: white; padding: 5px 15px; border-radius: 20px; font-size: 14px; }
        form { margin: 20px 0; }
        input[type="text"] { padding: 10px; width: 300px; border: none; border-radius: 4px; }
        button { padding: 10px 20px; background: #e94560; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .result { background: #0f3460; padding: 15px; border-radius: 8px; margin-top: 20px; }
        .hint { color: #888; font-size: 12px; margin-top: 10px; }
        a { color: #e94560; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 XSS Challenge Lab</h1>
        <p><span class="level">Level {{ level }}: {{ difficulty }}</span></p>
        
        <div class="challenge">
            <h2>{{ title }}</h2>
            <p>{{ description }}</p>
            
            <form method="GET" action="">
                <input type="text" name="{{ param_name }}" placeholder="Enter your input..." value="{{ user_input }}">
                <button type="submit">Submit</button>
            </form>
            
            {% if result %}
            <div class="result">
                <h3>Result:</h3>
                {{ result | safe }}
            </div>
            {% endif %}
            
            <p class="hint">Hint: {{ hint }}</p>
        </div>
        
        <p>
            {% for i in range(1, 6) %}
            <a href="/level{{ i }}">Level {{ i }}</a> |
            {% endfor %}
            <a href="/">Home</a>
        </p>
    </div>
</body>
</html>
"""

INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Challenge Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #e94560; }
        .levels { display: grid; gap: 15px; }
        .level-card { background: #16213e; padding: 20px; border-radius: 8px; }
        .level-card h3 { color: #e94560; margin-top: 0; }
        a { color: #0f3460; background: #e94560; padding: 8px 15px; border-radius: 4px; text-decoration: none; display: inline-block; margin-top: 10px; }
        .difficulty { font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 XSS Challenge Lab</h1>
        <p>Test your XSS skills (or your XSSAgent) against these challenges!</p>
        
        <div class="levels">
            <div class="level-card">
                <h3>Level 1: Direct Reflection</h3>
                <p class="difficulty">⭐ Easy</p>
                <p>No filtering at all. Your input is directly reflected in HTML.</p>
                <a href="/level1">Start Challenge</a>
            </div>
            
            <div class="level-card">
                <h3>Level 2: Attribute Context</h3>
                <p class="difficulty">⭐⭐ Medium</p>
                <p>Input reflected inside an HTML attribute. Need to escape the attribute.</p>
                <a href="/level2">Start Challenge</a>
            </div>
            
            <div class="level-card">
                <h3>Level 3: JavaScript Context</h3>
                <p class="difficulty">⭐⭐⭐ Hard</p>
                <p>Input reflected inside a JavaScript string. Need proper JS escaping.</p>
                <a href="/level3">Start Challenge</a>
            </div>
            
            <div class="level-card">
                <h3>Level 4: DOM XSS</h3>
                <p class="difficulty">⭐⭐⭐⭐ Expert</p>
                <p>No server-side reflection. Client-side JavaScript processes the input.</p>
                <a href="/level4">Start Challenge</a>
            </div>
            
            <div class="level-card">
                <h3>Level 5: Filtered Nightmare</h3>
                <p class="difficulty">⭐⭐⭐⭐⭐ Nightmare</p>
                <p>Multiple filters: &lt;script&gt; blocked, event handlers filtered, but bypassable.</p>
                <a href="/level5">Start Challenge</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)


@app.route('/level1')
def level1():
    """Level 1: Direct Reflection (Easy)"""
    user_input = request.args.get('q', '')
    
    # NO FILTERING - Direct reflection
    result = f"You searched for: {user_input}" if user_input else ""
    
    return render_template_string(BASE_TEMPLATE,
        level=1,
        difficulty="Easy",
        title="Direct Reflection",
        description="Your input is directly reflected in the page. No filtering applied.",
        param_name="q",
        user_input=user_input,
        result=result,
        hint="Try: <script>alert(1)</script>"
    )


@app.route('/level2')
def level2():
    """Level 2: Attribute Context (Medium)"""
    user_input = request.args.get('name', '')
    
    # Reflected in attribute - quotes escaped, but not angle brackets
    safe_input = user_input.replace('"', '&quot;')
    result = f'<img src="avatar.png" alt="{safe_input}" onerror="this.src=\'default.png\'">' if user_input else ""
    
    return render_template_string(BASE_TEMPLATE,
        level=2,
        difficulty="Medium",
        title="Attribute Context",
        description="Your input is reflected inside an HTML attribute (alt tag).",
        param_name="name",
        user_input=user_input,
        result=result,
        hint="Think about breaking out of the attribute context..."
    )


@app.route('/level3')
def level3():
    """Level 3: JavaScript Context (Hard)"""
    user_input = request.args.get('msg', '')
    
    # Reflected in JavaScript - single quotes escaped, but not backslash
    safe_input = user_input.replace("'", "\\'")
    result = f"""
    <script>
        var message = '{safe_input}';
        document.write('<p>Message: ' + message + '</p>');
    </script>
    """ if user_input else ""
    
    return render_template_string(BASE_TEMPLATE,
        level=3,
        difficulty="Hard",
        title="JavaScript Context",
        description="Your input is reflected inside a JavaScript string variable.",
        param_name="msg",
        user_input=user_input,
        result=result,
        hint="The escape sequence might be vulnerable..."
    )


@app.route('/level4')
def level4():
    """Level 4: DOM XSS (Expert)"""
    # No server-side reflection at all!
    result = """
    <div id="output"></div>
    <script>
        // DOM XSS - input from URL hash or search params
        var params = new URLSearchParams(window.location.search);
        var data = params.get('data') || '';
        
        // Vulnerable: directly setting innerHTML
        document.getElementById('output').innerHTML = 'Your data: ' + data;
    </script>
    """
    
    return render_template_string(BASE_TEMPLATE,
        level=4,
        difficulty="Expert",
        title="DOM XSS",
        description="No server-side reflection. The vulnerability is purely client-side.",
        param_name="data",
        user_input=request.args.get('data', ''),
        result=result,
        hint="Look at the JavaScript source. innerHTML is dangerous..."
    )


@app.route('/level5')
def level5():
    """Level 5: Filtered Nightmare"""
    user_input = request.args.get('payload', '')
    
    # Multiple filters (but all bypassable)
    filtered = user_input
    
    # Filter 1: Remove <script> tags (case insensitive)
    filtered = re.sub(r'<script[^>]*>.*?</script>', '', filtered, flags=re.IGNORECASE | re.DOTALL)
    filtered = re.sub(r'<script', '', filtered, flags=re.IGNORECASE)
    
    # Filter 2: Remove common event handlers
    filtered = re.sub(r'on\w+\s*=', '', filtered, flags=re.IGNORECASE)
    
    # Filter 3: Remove javascript: protocol
    filtered = re.sub(r'javascript:', '', filtered, flags=re.IGNORECASE)
    
    result = f"Filtered output: {filtered}" if user_input else ""
    
    return render_template_string(BASE_TEMPLATE,
        level=5,
        difficulty="Nightmare",
        title="Filtered Nightmare",
        description="Multiple filters applied. <script>, event handlers, and javascript: are blocked.",
        param_name="payload",
        user_input=user_input,
        result=result,
        hint="Filters can be bypassed with encoding, case variations, or alternative vectors..."
    )


# ============================================================================
# ADDITIONAL ENDPOINTS FOR TESTING
# ============================================================================

@app.route('/api/search')
def api_search():
    """JSON endpoint that reflects input - for testing JSON context XSS"""
    query = request.args.get('q', '')
    response = make_response(f'{{"query": "{query}", "results": []}}')
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/reflected')
def reflected():
    """Simple reflected endpoint for quick testing"""
    q = request.args.get('q', '')
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {q}</p>
    </body>
    </html>
    """


if __name__ == '__main__':
    print("=" * 60)
    print("🎯 XSS Challenge Lab Starting...")
    print("=" * 60)
    print()
    print("Available challenges:")
    print("  http://localhost:5555/          - Index")
    print("  http://localhost:5555/level1    - Easy (Direct reflection)")
    print("  http://localhost:5555/level2    - Medium (Attribute context)")
    print("  http://localhost:5555/level3    - Hard (JavaScript context)")
    print("  http://localhost:5555/level4    - Expert (DOM XSS)")
    print("  http://localhost:5555/level5    - Nightmare (Filtered)")
    print("  http://localhost:5555/reflected - Quick test endpoint")
    print()
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5555, debug=False)
