# NucleiAgent - El Scanner de Vulnerabilidades Extensible

> **Fase**: 2 (Discovery)  
> **Rol**: Detección masiva de vulnerabilidades conocidas  
> **Clase**: `bugtrace.agents.discovery.nuclei_agent.NucleiAgent`  
> **Archivo**: `bugtrace/agents/discovery/nuclei_agent.py`

---

## Overview

**NucleiAgent** es el agente que orquesta **Nuclei**, el scanner de vulnerabilidades basado en templates más popular de la comunidad. Con **6000+ templates** de la comunidad, Nuclei detecta vulnerabilidades conocidas, misconfigurations, y exposiciones.

A diferencia de scanners tradicionales que reinventan la rueda, NucleiAgent aprovecha el ecosistema de templates de Nuclei y lo integra inteligentemente en el pipeline de BugTraceAI.

### 🎯 **Tipos de Vulnerabilidades Detectadas**

| Categoría | Templates | Ejemplos |
|-----------|-----------|----------|
| **CVEs** | 3500+ | Log4Shell, Spring4Shell, ProxyShell |
| **Exposures** | 1500+ | .git, .env, backup files, admin panels |
| **Misconfigurations** | 800+ | CORS, CSP, Security Headers |
| **Web Vulnerabilities** | 600+ | XSS, SQLi, SSRF, LFI (low-hanging fruit) |
| **Technologies** | 400+ | WordPress, Joomla, Drupal plugins |
| **Network** | 200+ | Open ports, services, banners |

---

## Arquitectura de Template-Based Scanning

Nuclei usa un modelo **declarativo** basado en YAML templates:

```
┌─────────────────────────────────────────────────────────────────┐
│              NUCLEI AGENT WORKFLOW (Template-Based)              │
└─────────────────────────────────────────────────────────────────┘

Input: Target URLs (de CrawlerAgent)
│
▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 1: TEMPLATE SELECTION (AI-Assisted)                       │
├────────────────────────────────────────────────────────────────┤
│  🤖 LLM Analysis (opcional)                                    │
│  • Analiza tech stack detectado (WordPress, React, etc.)       │
│  • Selecciona templates relevantes                             │
│  • Prioriza CVEs recientes (últimos 90 días)                   │
│                                                                 │
│  Ejemplo: Si detecta WordPress 5.8                             │
│    → Selecciona templates: wordpress/, cves/CVE-2021-*         │
│                                                                 │
│  Output: Lista de templates a ejecutar (~500-1000 templates)   │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 2: NUCLEI EXECUTION                                       │
├────────────────────────────────────────────────────────────────┤
│  ⚡ Nuclei Scanner                                             │
│  • Multi-threaded execution (rate: 150 req/s)                  │
│  • Smart retries con exponential backoff                       │
│  • Automatic payload mutations                                 │
│  • Custom headers injection                                    │
│                                                                 │
│  Command:                                                       │
│  nuclei -u <URL>                                               │
│    -t <templates>                                              │
│    -rate-limit 150                                             │
│    -bulk-size 50                                               │
│    -retries 2                                                  │
│    -timeout 10                                                 │
│    -json -o output.json                                        │
│                                                                 │
│  Timeout: 5 minutos (con templates seleccionados)              │
└────────────┬───────────────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────────────┐
│ STEP 3: RESULT PARSING & DEDUPLICATION                         │
├────────────────────────────────────────────────────────────────┤
│  • Parsear JSON output de Nuclei                               │
│  • Filtrar false positives conocidos (blacklist)               │
│  • Deduplicar findings idénticos                               │
│  • Enriquecer con CVE metadata (CVSS, CWE)                     │
│  • Clasificar severidad (INFO/LOW/MEDIUM/HIGH/CRITICAL)        │
│                                                                 │
│  Output: Suspected Vectors → ThinkingConsolidationAgent        │
└────────────────────────────────────────────────────────────────┘
```

---

## Template System

### Ejemplo de Template Nuclei

```yaml
# nuclei-templates/cves/CVE-2021-44228.yaml (Log4Shell)
id: CVE-2021-44228

info:
  name: Apache Log4j RCE (Log4Shell)
  author: pdteam
  severity: critical
  description: Apache Log4j2 JNDI features do not protect against attacker controlled LDAP
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.0
    cwe-id: CWE-502

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      User-Agent: "${jndi:ldap://{{interactsh-url}}}"
      X-Api-Version: "${jndi:ldap://{{interactsh-url}}}"
      Referer: "${jndi:ldap://{{interactsh-url}}}"
    
    matchers:
      - type: word
        part: interactsh_protocol  # DNS lookup detected
        words:
          - "dns"
```

### Categorías de Templates

```
nuclei-templates/
├── cves/                    # 3500+ CVE templates
│   ├── 2024/               # CVEs de 2024
│   ├── 2023/               # CVEs de 2023
│   └── ...
├── vulnerabilities/         # 600+ web vulns generales
│   ├── xss/
│   ├── sqli/
│   ├── ssrf/
│   └── lfi/
├── exposures/               # 1500+ info disclosures
│   ├── configs/            # .git, .env, web.config
│   ├── backups/            # backup.zip, db.sql
│   └── logs/               # error.log, debug.log
├── technologies/            # 400+ CMS/framework specific
│   ├── wordpress/
│   ├── joomla/
│   └── drupal/
├── misconfiguration/        # 800+ misconfigs
│   ├── cors/
│   ├── csp/
│   └── ssl/
└── network/                 # 200+ network scans
    ├── services/
    └── detection/
```

---

## AI-Assisted Template Selection

```python
class TemplateSelector:
    """
    Selecciona templates relevantes según tech stack detectado.
    """
    
    async def select_templates(
        self,
        url: str,
        tech_stack: TechStack
    ) -> List[str]:
        """
        Selecciona templates inteligentemente.
        
        Sin AI: 6000+ templates → 30-60 minutos
        Con AI: 500-1000 templates → 3-5 minutos
        """
        
        selected = []
        
        # 1. Templates base (siempre)
        selected.extend([
            'exposures/',          # Info disclosures
            'misconfiguration/',   # Security headers, CORS
            'cves/2024/',          # CVEs recientes
            'cves/2023/',
        ])
        
        # 2. Technology-specific
        if 'WordPress' in tech_stack.cms:
            selected.extend([
                'technologies/wordpress/',
                'cves/*wordpress*',
            ])
        
        if 'React' in tech_stack.frameworks:
            selected.extend([
                'vulnerabilities/xss/',  # React tiene issues con XSS
            ])
        
        if 'Spring' in tech_stack.frameworks:
            selected.extend([
                'cves/*spring*',
                'vulnerabilities/java/',
            ])
        
        # 3. WAF detection
        if tech_stack.waf:
            # Evitar templates ruidosos que triggerean WAF
            selected = [t for t in selected if 'brute-force' not in t]
        
        return selected
```

---

## Nuclei Command Construction

```python
def build_nuclei_command(
    self,
    url: str,
    templates: List[str],
    rate_limit: int = 150,
    timeout: int = 10
) -> List[str]:
    """
    Construye comando Nuclei optimizado.
    
    Args:
        url: Target URL
        templates: Lista de templates a usar
        rate_limit: Requests por segundo (default: 150)
        timeout: Timeout por request (default: 10s)
    
    Returns:
        Command list para subprocess
    """
    
    cmd = [
        'nuclei',
        '-u', url,
        '-t', ','.join(templates),
        
        # Performance
        '-rate-limit', str(rate_limit),
        '-bulk-size', '50',              # Parallel bulk processing
        '-c', '50',                       # 50 concurrent templates
        
        # Retries
        '-retries', '2',
        '-timeout', str(timeout),
        
        # Output
        '-json',                          # JSON output para parseo
        '-o', f'/tmp/nuclei_{uuid.uuid4()}.json',
        
        # Stealth
        '-header', 'User-Agent: Mozilla/5.0...',  # Bypass bot detection
        
        # Interactsh (for OOB detection)
        '-interactsh-server', 'oast.bugtrace.internal',
        
        # Disable update check
        '-duc',
        
        # Silent mode
        '-silent',
    ]
    
    return cmd
```

---

## Result Parsing

```python
class NucleiResultParser:
    """
    Parsea resultados de Nuclei y los convierte a Findings.
    """
    
    def parse(self, nuclei_json: dict) -> Finding:
        """
        Convierte output JSON de Nuclei a Finding de BugTraceAI.
        
        Nuclei JSON:
        {
          "template-id": "CVE-2021-44228",
          "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "classification": {
              "cvss-score": 10.0,
              "cwe-id": ["CWE-502"]
            }
          },
          "matched-at": "https://example.com",
          "extracted-results": ["ldap://attacker.com"],
          "type": "http",
          "curl-command": "curl -X GET ..."
        }
        """
        
        return Finding(
            vuln_type=self._map_to_vuln_type(nuclei_json['template-id']),
            url=nuclei_json['matched-at'],
            severity=nuclei_json['info']['severity'].upper(),
            cve=self._extract_cve(nuclei_json['template-id']),
            cwe=nuclei_json['info']['classification']['cwe-id'][0],
            cvss_score=nuclei_json['info']['classification'].get('cvss-score', 0.0),
            description=nuclei_json['info']['name'],
            evidence={
                'nuclei_template': nuclei_json['template-id'],
                'curl_reproduction': nuclei_json.get('curl-command'),
                'extracted_data': nuclei_json.get('extracted-results', []),
            },
            source='nuclei',
            confidence=0.9,  # Nuclei templates son authoritative
            status='SUSPECTED',  # Algunos requieren validación manual
        )
    
    def _map_to_vuln_type(self, template_id: str) -> str:
        """
        Mapea template ID a tipo de vulnerabilidad.
        """
        if 'xss' in template_id.lower():
            return 'XSS'
        elif 'sqli' in template_id.lower():
            return 'SQLi'
        elif 'ssrf' in template_id.lower():
            return 'SSRF'
        elif 'rce' in template_id.lower():
            return 'RCE'
        elif 'lfi' in template_id.lower():
            return 'LFI'
        elif 'exposure' in template_id:
            return 'INFO_DISCLOSURE'
        elif 'cve' in template_id.lower():
            return 'CVE'
        else:
            return 'MISCONFIGURATION'
```

---

## Interactsh Integration (OOB Detection)

Nuclei usa **Interactsh** para detectar vulnerabilidades Out-of-Band (SSRF, XXE, Blind RCE):

```yaml
# Template con Interactsh
requests:
  - method: GET
    path:
      - "{{BaseURL}}/api?url={{interactsh-url}}"
    
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"   # HTTP callback recibido → SSRF confirmado
```

**Cómo funciona**:
1. Nuclei genera URL única: `abc123.oast.bugtrace.internal`
2. Inyecta en payload: `?url=http://abc123.oast.bugtrace.internal`
3. Si el servidor vulnerable hace request → Interactsh lo detecta
4. Nuclei marca como vulnerable

---

## Deduplicación & Filtrado

```python
def deduplicate_and_filter(self, findings: List[Finding]) -> List[Finding]:
    """
    Deduplica y filtra false positives conocidos.
    """
    
    # False Positives conocidos
    FALSE_POSITIVE_PATTERNS = [
        'waf-detect',           # Detección de WAF no es vulnerabilidad
        'tech-detect',          # Tech detection no es vuln
        'http-missing-headers', # Headers missing es info, no vuln
    ]
    
    # Filtrar FPs
    filtered = [
        f for f in findings
        if not any(fp in f.evidence['nuclei_template'] for fp in FALSE_POSITIVE_PATTERNS)
    ]
    
    # Deduplicar por (template-id, url_path)
    seen = set()
    deduplicated = []
    
    for finding in filtered:
        key = (
            finding.evidence['nuclei_template'],
            urlparse(finding.url).path
        )
        
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    
    return deduplicated
```

---

## Configuración

```yaml
discovery:
  nuclei:
    enabled: true
    
    # Nuclei binary
    binary_path: "/usr/local/bin/nuclei"
    templates_path: "/root/nuclei-templates"
    
    # Template selection
    use_ai_selection: true              # AI selecciona templates relevantes
    template_categories:
      - "exposures"
      - "cves/2024"
      - "cves/2023"
      - "misconfiguration"
      - "vulnerabilities"
    
    # Performance
    rate_limit: 150                     # Requests/segundo
    concurrency: 50                     # Templates concurrentes
    timeout: 10                         # Timeout por request
    retries: 2
    
    # Interactsh (OOB detection)
    interactsh_enabled: true
    interactsh_server: "oast.bugtrace.internal"
    
    # Output
    output_format: "json"
    save_curl_commands: true            # Para reproducción
    
    # Filtering
    severity_threshold: "low"           # Mínimo severity: info/low/medium/high/critical
    exclude_templates:
      - "waf-detect"
      - "tech-detect"
    
    # Stealth
    random_user_agent: true
    custom_headers:
      X-Scanner: "BugTraceAI/2.0"
```

---

## Métricas de Rendimiento

### Tiempos de Ejecución

| Templates | URLs | Tiempo | Findings Avg |
|-----------|------|--------|--------------|
| 6000+ (todos) | 1 | 30-60 min | 5-10 |
| 1000 (seleccionados) | 1 | 5-8 min | 4-8 |
| 500 (AI-selected) | 1 | 3-5 min | 3-6 |

### Estadísticas de Detección

```
Scan típico de 100 URLs:
├─ Templates ejecutados: 500 (AI-selected)
├─ Requests totales: ~50,000
├─ Tiempo total: ~25 minutos
├─ Findings raw: 120
├─ Post-deduplication: 45
└─ Post-filtering: 32

Categorías de findings:
├─ CVEs: 8 (25%)
├─ Exposures: 15 (47%)
├─ Misconfigurations: 7 (22%)
└─ Vulnerabilities: 2 (6%)
```

---

## Ventajas de Nuclei

✅ **6000+ templates** de la comunidad  
✅ **Actualización constante** (nuevos CVEs daily)  
✅ **Declarativo** (YAML fácil de escribir)  
✅ **Multi-protocol** (HTTP, DNS, TCP, etc.)  
✅ **Interactsh integration** (OOB detection)  
✅ **Fast** (150 req/s con rate limiting)  

---

## Limitaciones

❌ **False Positives** en algunos templates  
❌ **Requiere template updates** constantes  
❌ **No valida deep logic** (solo pattern matching)  
❌ **Ruidoso** si no se filtra bien (triggerea WAF)  

---

## Referencias

- **Nuclei GitHub**: https://github.com/projectdiscovery/nuclei
- **Nuclei Templates**: https://github.com/projectdiscovery/nuclei-templates
- **Interactsh**: https://github.com/projectdiscovery/interactsh
- **Template Guide**: https://docs.projectdiscovery.io/templates/introduction

---

*Última actualización: 2026-02-01*  
*Versión: 2.0.0 (Phoenix Edition)*
