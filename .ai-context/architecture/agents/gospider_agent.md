# GoSpiderAgent - El Crawler Inteligente

> **Fase**: 2 (Discovery)  
> **Rol**: Web Crawling & Endpoint Discovery  
> **Clase**: `bugtrace.agents.discovery.gospider_agent.GoSpiderAgent`  
> **Archivo**: `bugtrace/agents/discovery/gospider_agent.py`

---

## Overview

**GoSpiderAgent** es el agente responsable de **crawlear aplicaciones web** para descubrir:
- URLs y endpoints
- Parámetros GET/POST
- Forms (inputs, hidden fields)
- JavaScript files (para análisis de DOM)
- APIs (REST, GraphQL)
- Subdominios adicionales

Usa **GoSpider**, un crawler ultra-rápido escrito en Go, combinado con **inteligencia artificial** para:
1. Priorizar qué URLs crawlear (evita rabbit holes)
2. Detectar parámetros interesantes vía análisis de JS
3. Extraer API endpoints de código JavaScript
4. Identificar attack surface (forms, inputs, file uploads)

### 🎯 **Objetivos del Crawling**

| Objetivo | Método | Output |
|----------|--------|--------|
| **URL Discovery** | Recursivo, depth-limited | Lista de URLs únicas |
| **Parameter Extraction** | Forms + URL params + JS analysis | Lista de parámetros testables |
| **JavaScript Analysis** | Static analysis de .js files | API endpoints, secrets |
| **Form Detection** | HTML parsing | Inputs, file uploads, hidden fields |
| **Subdomain Discovery** | Links internos + JS | Subdominios adicionales |

---

## Arquitectura del Crawler

```
┌─────────────────────────────────────────────────────────────────┐
│           GOSPIDER AGENT WORKFLOW (Intelligent Crawling)        │
└─────────────────────────────────────────────────────────────────┘

Input: Seed URLs (de SubdomainAgent o user)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: GOSPIDER CRAWLING (30-120s)                            │
├────────────────────────────────────────────────────────────────┤
│  ⚡ GoSpider (Fast Go-based crawler)                            │
│  • Recursive crawling (depth: 3-5)                             │
│  • Concurrent requests (threads: 20)                           │
│  • JavaScript rendering (optional, con headless chrome)        │
│  • Smart filtering (avoid PDFs, images, videos)                │
│                                                                │
│  Command:                                                      │
│  gospider -s <URL>                                             │
│    --depth 3                                                   │
│    --concurrent 20                                             │
│    --timeout 10                                                │
│    --js                      # Parse JavaScript files          │
│    --subs                    # Include subdomains              │
│    -o output.txt                                               │
│                                                                │
│  Output: Raw list of URLs, JS files, forms                     │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: AI-POWERED JS ANALYSIS (5-15s)                         │
├────────────────────────────────────────────────────────────────┤
│  🤖 LLM Analysis (Claude 3.5 Haiku - fast model)               │
│  • Descarga archivos .js encontrados                           │
│  • Analiza código JavaScript estáticamente                     │
│  • Extrae:                                                     │
│    - API endpoints (/api/v1/users, /graphql)                   │
│    - Hardcoded secrets (API keys, tokens)                      │
│    - Hidden parameters (admin=true, debug=1)                   │
│    - DOM sinks (innerHTML, eval, location.href)                │
│                                                                │
│  Ejemplo de extraction:                                        │
│  JS code:                                                      │
│    fetch('/api/v1/users?id=' + userId)                         │
│  →                                                             │
│  Extracted:                                                    │
│    - Endpoint: /api/v1/users                                   │
│    - Parameter: id (numeric)                                   │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: FORM ANALYSIS & PARAMETER EXTRACTION                   │
├────────────────────────────────────────────────────────────────┤
│  • Parsea HTML de URLs crawleadas                              │
│  • Detecta <form> tags                                         │
│  • Extrae inputs:                                              │
│    - Text inputs                                               │
│    - Hidden inputs (pueden tener tokens)                       │
│    - File uploads                                              │
│    - Textareas                                                 │
│  • Analiza URL query parameters                                │
│  • Deduplica parámetros por nombre                             │
│                                                                │
│  Output: Lista de parámetros testables con metadata            │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 4: SMART FILTERING & PRIORITIZATION                       │
├────────────────────────────────────────────────────────────────┤
│  🤖 AI Prioritization (optional)                               │
│  • Prioriza URLs con parámetros (más attack surface)           │
│  • Descarta estáticos sin parámetros (/about, /contact)        │
│  • Da prioridad alta a:                                        │
│    - /admin, /api, /graphql                                    │
│    - Forms con file upload                                     │
│    - Endpoints con parámetro 'id'                              │
│                                                                │
│  Output: URLs priorizadas → ReflectionDetector / NucleiAgent   │
└────────────────────────────────────────────────────────────────┘
```

---

## GoSpider Integration

### Command Construction

```python
def build_gospider_command(
    self,
    url: str,
    depth: int = 3,
    concurrent: int = 20,
    timeout: int = 10,
    js_analysis: bool = True
) -> List[str]:
    """
    Construye comando GoSpider optimizado.
    
    Args:
        url: Seed URL para crawling
        depth: Profundidad de crawling (default: 3)
        concurrent: Threads concurrentes (default: 20)
        timeout: Timeout por request (default: 10s)
        js_analysis: Analizar JavaScript files (default: True)
    
    Returns:
        Command list para subprocess
    """
    
    cmd = [
        'gospider',
        '-s', url,
        
        # Crawling params
        '--depth', str(depth),
        '--concurrent', str(concurrent),
        '--timeout', str(timeout),
        
        # Content types
        '--js',                    # Parse JavaScript
        '--subs',                  # Include subdomains
        '--sitemap',               # Parse sitemap.xml
        '--robots',                # Parse robots.txt
        
        # Output
        '-o', f'/tmp/gospider_{uuid.uuid4()}.txt',
        '--json',                  # JSON output
        
        # Headers
        '--header', 'User-Agent: Mozilla/5.0 (BugTraceAI/2.0)',
        
        # Filters
        '--blacklist', '*.jpg,*.png,*.gif,*.pdf,*.mp4',  # Ignore binaries
        
        # Performance
        '--no-redirect',           # Don't follow redirects (evita loops)
    ]
    
    return cmd
```

### GoSpider Output Parsing

```python
class GoSpiderResultParser:
    """
    Parsea output de GoSpider y extrae URLs, params, forms.
    """
    
    def parse(self, gospider_output: str) -> CrawlResult:
        """
        Parsea output de GoSpider.
        
        GoSpider output format:
        [url] - https://example.com/product?id=123
        [form] - https://example.com/login (method: POST)
        [javascript] - https://example.com/static/app.js
        [linkfinder] - /api/v1/users (found in app.js)
        """
        
        urls = []
        forms = []
        js_files = []
        api_endpoints = []
        
        for line in gospider_output.split('\n'):
            if '[url]' in line:
                url = line.split(' - ')[1]
                urls.append(url)
            
            elif '[form]' in line:
                form_match = re.search(r'\- (.*?)\s+\(method:\s+(\w+)\)', line)
                if form_match:
                    forms.append({
                        'url': form_match.group(1),
                        'method': form_match.group(2)
                    })
            
            elif '[javascript]' in line:
                js_url = line.split(' - ')[1]
                js_files.append(js_url)
            
            elif '[linkfinder]' in line:
                endpoint = line.split(' - ')[1].split(' (')[0]
                api_endpoints.append(endpoint)
        
        return CrawlResult(
            urls=list(set(urls)),              # Deduplicate
            forms=forms,
            js_files=list(set(js_files)),
            api_endpoints=list(set(api_endpoints))
        )
```

---

## AI-Powered JavaScript Analysis

### Extracción de API Endpoints

```python
class JSAnalyzer:
    """
    Analiza archivos JavaScript para extraer endpoints y secrets.
    """
    
    async def analyze_js_file(self, js_url: str) -> JSAnalysisResult:
        """
        Descarga y analiza archivo JS con LLM.
        
        Args:
            js_url: URL del archivo JavaScript
        
        Returns:
            JSAnalysisResult con endpoints, secrets, DOM sinks
        """
        
        # Descargar JS file
        response = await self.http_client.get(js_url)
        js_code = response.text
        
        # Si es muy grande (>500KB), truncar
        if len(js_code) > 500_000:
            js_code = js_code[:500_000] + "\n... [truncated]"
        
        # LLM Analysis
        prompt = f"""
Analyze this JavaScript code for security-relevant information.

JAVASCRIPT CODE:
```javascript
{js_code}
```

EXTRACT:
1. API Endpoints (fetch(), axios.get(), XMLHttpRequest)
2. Hardcoded secrets (API keys, tokens, passwords)
3. Parameters (query params, body params)
4. DOM sinks (innerHTML, eval, document.write, location.href)

OUTPUT (JSON):
{{
  "endpoints": [
    {{"url": "/api/v1/users", "method": "GET", "params": ["id", "filter"]}},
    ...
  ],
  "secrets": [
    {{"type": "api_key", "value": "sk_live_...", "line": 42}},
    ...
  ],
  "dom_sinks": [
    {{"sink": "innerHTML", "line": 156, "source": "location.hash"}},
    ...
  ]
}}
"""
        
        result = await self.llm.complete(prompt, model="anthropic/claude-3.5-haiku")
        
        return JSAnalysisResult(**json.loads(result))
```

### Regex-Based Extraction (Fallback)

Si el LLM no está disponible, usa regex patterns:

```python
class RegexExtractor:
    """
    Fallback: extrae endpoints vía regex si LLM no disponible.
    """
    
    # Patterns para API endpoints
    API_PATTERNS = [
        r"fetch\(['\"]([^'\"]+)['\"]",              # fetch('/api/users')
        r"axios\.(get|post|put|delete)\(['\"]([^'\"]+)['\"]",  # axios.get('/api')
        r"\.open\(['\"](\w+)['\"],\s*['\"]([^'\"]+)['\"]",     # xhr.open('GET', '/api')
        r"/api/[a-zA-Z0-9/_-]+",                    # Generic /api/ paths
        r"/graphql",                                 # GraphQL endpoints
    ]
    
    # Patterns para secrets
    SECRET_PATTERNS = {
        'api_key': r"(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([^'\"]{20,})['\"]",
        'bearer_token': r"Bearer\s+([a-zA-Z0-9._-]{20,})",
        'aws_key': r"AKIA[0-9A-Z]{16}",
        'jwt': r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    }
    
    def extract_endpoints(self, js_code: str) -> List[str]:
        """Extrae endpoints vía regex."""
        endpoints = []
        
        for pattern in self.API_PATTERNS:
            matches = re.findall(pattern, js_code)
            endpoints.extend(matches)
        
        return list(set(endpoints))
    
    def extract_secrets(self, js_code: str) -> List[dict]:
        """Extrae secrets vía regex."""
        secrets = []
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                secrets.append({
                    'type': secret_type,
                    'value': match if isinstance(match, str) else match[1],
                })
        
        return secrets
```

---

## Form Analysis & Parameter Extraction

```python
class FormAnalyzer:
    """
    Analiza forms HTML y extrae inputs testables.
    """
    
    def analyze_html(self, html: str, url: str) -> List[Form]:
        """
        Parsea HTML y extrae todos los forms.
        
        Args:
            html: HTML content
            url: URL donde se encontró el form (para action resolution)
        
        Returns:
            Lista de Forms con inputs
        """
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form_tag in soup.find_all('form'):
            # Extract form metadata
            action = form_tag.get('action', url)  # Default: same URL
            method = form_tag.get('method', 'GET').upper()
            
            # Resolve relative URLs
            if not action.startswith('http'):
                action = urljoin(url, action)
            
            # Extract inputs
            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required'),
                }
                
                # File upload detection
                if input_data['type'] == 'file':
                    input_data['accepts'] = input_tag.get('accept', '*')
                
                inputs.append(input_data)
            
            forms.append(Form(
                url=url,
                action=action,
                method=method,
                inputs=inputs
            ))
        
        return forms
```

---

## Smart URL Prioritization

```python
class URLPrioritizer:
    """
    Prioriza URLs según attack surface potencial.
    """
    
    # Patrones de alta prioridad
    HIGH_PRIORITY_PATTERNS = [
        r'/admin',
        r'/api',
        r'/graphql',
        r'/upload',
        r'\?id=',
        r'\?user_id=',
        r'\?file=',
        r'\?url=',
    ]
    
    # Patrones de baja prioridad (estáticos)
    LOW_PRIORITY_PATTERNS = [
        r'/about',
        r'/contact',
        r'/privacy',
        r'/terms',
        r'\.css$',
        r'\.jpg$',
        r'\.png$',
    ]
    
    def prioritize(self, urls: List[str]) -> List[PrioritizedURL]:
        """
        Asigna prioridad a cada URL.
        
        Returns:
            Lista de URLs ordenadas por prioridad (alta → baja)
        """
        prioritized = []
        
        for url in urls:
            priority = self._calculate_priority(url)
            
            prioritized.append(PrioritizedURL(
                url=url,
                priority=priority,
                reason=self._get_priority_reason(url, priority)
            ))
        
        # Ordenar por prioridad (descendente)
        return sorted(prioritized, key=lambda x: x.priority, reverse=True)
    
    def _calculate_priority(self, url: str) -> int:
        """
        Calcula prioridad (0-100).
        
        100 = Máxima prioridad (ej: /admin?id=1)
        0 = Baja prioridad (ej: /about)
        """
        score = 50  # Base score
        
        # High priority patterns
        for pattern in self.HIGH_PRIORITY_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                score += 20
        
        # Low priority patterns
        for pattern in self.LOW_PRIORITY_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                score -= 30
        
        # Tiene parámetros?
        if '?' in url:
            score += 15
        
        # Tiene múltiples parámetros?
        param_count = url.count('=')
        score += param_count * 5
        
        return max(0, min(100, score))  # Clamp 0-100
```

---

## Configuración

```yaml
discovery:
  gospider:
    enabled: true
    
    # GoSpider binary
    binary_path: "/usr/local/bin/gospider"
    
    # Crawling parameters
    depth: 3                       # Profundidad máxima
    concurrent: 20                 # Threads concurrentes
    timeout: 10                    # Timeout por request
    
    # Content analysis
    analyze_javascript: true       # Analizar .js files
    include_subdomains: true       # Crawl subdomains
    parse_sitemap: true            # Parse sitemap.xml
    parse_robots: true             # Parse robots.txt
    
    # AI Analysis
    ai_js_analysis: true           # Usar LLM para analizar JS
    ai_model: "anthropic/claude-3.5-haiku"  # Fast model
    
    # Filtering
    blacklist_extensions:
      - "jpg"
      - "png"
      - "gif"
      - "pdf"
      - "mp4"
      - "zip"
    
    max_urls: 10000                # Límite de URLs (evita crawling infinito)
    
    # Prioritization
    use_smart_prioritization: true
    
    # Performance
    follow_redirects: false        # Evita loops
    max_response_size: 10485760    # 10 MB max (evita descargar archivos gigantes)
```

---

## Métricas de Rendimiento

### Tiempos de Crawling

| Site Size | Depth | URLs Found | Tiempo |
|-----------|-------|------------|--------|
| Small (10-50 pages) | 3 | 50-100 | 30-60s |
| Medium (100-500 pages) | 3 | 500-1000 | 2-5 min |
| Large (1000+ pages) | 3 | 5000-10000 | 10-20 min |

### Estadísticas Típicas

```
Crawl de sitio mediano (200 páginas):
├─ Tiempo total: 3 minutos
├─ URLs encontradas: 850
├─ Forms detectados: 12
├─ JS files analizados: 35
├─ API endpoints extraídos: 68
├─ Secrets encontrados: 3 (API keys en JS)
└─ Parámetros únicos: 145

Post-prioritization:
├─ Alta prioridad: 120 URLs (APIs, forms, params)
├─ Media prioridad: 500 URLs
└─ Baja prioridad: 230 URLs (estáticos)
```

---

## Ventajas de GoSpider

✅ **Ultra-rápido** (escrito en Go)  
✅ **JavaScript-aware** (extrae endpoints de JS)  
✅ **Multi-threaded** (20+ threads concurrentes)  
✅ **Sitemap/Robots support**  
✅ **JSON output** (fácil de parsear)

---

## Limitaciones

❌ **No ejecuta JavaScript** (algunos endpoints solo visibles con JS rendering)  
  → Solución: Usar Playwright en casos específicos  
❌ **Puede perderse en sites muy grandes** (infinitos)  
  → Solución: Límite de 10,000 URLs  
❌ **SPAs (React, Vue)** requieren rendering  
  → Solución: Analizar bundles JS con AI

---

## Referencias

- **GoSpider GitHub**: https://github.com/jaeles-project/gospider
- **LinkFinder**: https://github.com/GerbenJavado/LinkFinder (inspiración para JS analysis)

---

*Última actualización: 2026-02-01*  
*Versión: 2.0.0 (Phoenix Edition)*
