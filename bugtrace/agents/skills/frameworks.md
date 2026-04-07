# Security Expert Knowledge Base: Frameworks

## React

- **Primary Sinks**: `dangerouslySetInnerHTML`, `ref` manipulation, dynamic `href`/`src` attributes.
- **Bypass Patterns**:
  - Unsanitized HTML through third-party libraries (e.g. `react-markdown` with `escapeHtml={false}`).
  - Custom renderers that bypass the virtual DOM's auto-escaping.
- **Defense**: React auto-escapes all strings in the virtual DOM. Vulnerabilities only occur when explicitly opting out or using unsafe props.

## Vue.js

- **Primary Sinks**: `v-html`, dynamic attribute bindings.
- **Bypass Patterns**:
  - `v-html` with untrusted input.
  - Server-Side Rendering (SSR) hydration mismatches where data injected into the template is re-interpreted on the client.
- **Defense**: Use `v-text` or curly braces `{{ }}` for safe interpolation.

## AngularJS (Legacy 1.x)

- **Primary Sinks**: Expression interpolation `{{ }}`, `$sce.trustAsHtml`.
- **CRITICAL**: Template Injection is common. Even if you are inside an attribute like `value="PROBE"`, you can attempt `{{7*7}}`.
- **Sandbox Escape**: Older versions require sandbox escapes to access `constructor`.
- **Example**: `{{constructor.constructor('alert(1)')()}}`

## Angular (Modern 2+)

- **Primary Sinks**: `[innerHTML]`, `[outerHTML]`, `DomSanitizer.bypassSecurityTrust...`
- **Defense**: Angular has a build-in sanitizer. You must explicitly call `bypassSecurityTrustHtml` to create a vulnerability.

## Svelte

- **Primary Sinks**: `{@html}`, dynamic attributes.
- **Defense**: Never pass untrusted HTML to `{@html}`.
