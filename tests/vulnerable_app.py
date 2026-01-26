from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/attribute_xss", response_class=HTMLResponse)
async def attribute_xss(q: str = ""):
    # Vulnerable: Reflects input into attribute without enough escaping for breaking out of context
    # We use single quotes for the attribute to vary the test
    return f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <input type='text' value='{q}'>
        </body>
    </html>
    """

@app.get("/js_xss", response_class=HTMLResponse)
async def js_xss(q: str = ""):
    # Vulnerable: Reflects input into JS block
    return f"""
    <html>
        <body>
            <h1>JS Test</h1>
            <script>
                var searchTerm = "{q}";
                console.log(searchTerm);
            </script>
        </body>
    </html>
    """
