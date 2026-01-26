# Vertical Agent Architecture (URLMasterAgent)
## The Core of BugtraceAI-CLI v1.2 Phoenix Edition

**Last Updated**: 2026-01-02 22:55
**Status**: ✅ PRODUCTION READY - Default Architecture

---

## 🎯 OVERVIEW

The **Vertical Agent Architecture** is the default operating mode of BugtraceAI-CLI. It assigns one **URLMasterAgent** per discovered URL, where each agent autonomously analyzes and exploits vulnerabilities using a comprehensive skill system.

### Key Concepts

```
┌──────────────────────────────────────────────────────────────────┐
│                    VERTICAL ARCHITECTURE                          │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   TeamOrchestrator                                                │
│         │                                                         │
│         ├── VisualCrawler (Phase 1: Discovery)                   │
│         │         │                                               │
│         │         └── Discovers URLs: [url1, url2, url3, ...]    │
│         │                                                         │
│         └── URLMasterAgents (Phase 2: Parallel Analysis)         │
│                   │                                               │
│                   ├── URLMaster-abc123 → /login.php              │
│                   ├── URLMaster-def456 → /search.php?q=test      │
│                   ├── URLMaster-ghi789 → /products.php?cat=1     │
│                   └── URLMaster-jkl012 → /admin/                 │
│                                                                   │
│   Each URLMaster has:                                            │
│     - ConversationThread (persistent context)                    │
│     - 15 Skills (recon, exploit_xss, exploit_sqli, etc.)        │
│     - LLM-driven decision making                                 │
│     - Access to ManipulatorOrchestrator                         │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📁 FILE STRUCTURE

```
bugtrace/
├── agents/
│   └── url_master.py          # URLMasterAgent + 15 Skills (1100+ lines)
├── core/
│   ├── team.py                # TeamOrchestrator (vertical mode logic)
│   ├── conversation_thread.py # Persistent context per URL
│   └── llm_client.py          # LLM with thread support
├── tools/
│   ├── manipulator/
│   │   ├── orchestrator.py    # ManipulatorOrchestrator (THE CORE)
│   │   ├── controller.py      # RequestController (rate limit, circuit breaker)
│   │   ├── models.py          # MutableRequest, MutationStrategy
│   │   └── specialists/       # PayloadAgent, EncodingAgent
│   ├── exploitation/
│   │   ├── sqli.py            # SQLInjectionDetector
│   │   ├── csti.py            # CSTIDetector (SSTI)
│   │   ├── xxe.py             # XXEDetector
│   │   ├── header_injection.py # HeaderInjectionDetector
│   │   ├── proto.py           # PrototypePollutionDetector
│   │   └── mutation.py        # MutationEngine (AI WAF bypass)
│   ├── visual/
│   │   ├── browser.py         # BrowserManager (Playwright)
│   │   └── crawler.py         # VisualCrawler
│   └── external.py            # SQLMap, Nuclei, GoSpider (Docker)
```

---

## 🔧 URLMasterAgent

### Core Responsibility
One URLMasterAgent is spawned per discovered URL. It runs autonomously, using the LLM to decide which skills to execute based on context.

### Constructor
```python
class URLMasterAgent:
    def __init__(self, target_url: str, orchestrator=None):
        self.url = target_url
        self.thread = ConversationThread(target_url)  # Persistent context
        self.skills = self._register_skills()         # 15 skills available
        self.findings: List[Dict] = []
```

### Skill Registry (15 Skills)

```python
def _register_skills(self) -> Dict[str, Any]:
    return {
        # Basic skills
        "recon": ReconSkill(self),
        "analyze": AnalyzeSkill(self),
        "browser": BrowserSkill(self),
        "report": ReportSkill(self),
        
        # Exploitation skills (using ManipulatorOrchestrator & detectors)
        "exploit_xss": XSSSkill(self),
        "exploit_sqli": SQLiSkill(self),
        "exploit_lfi": LFISkill(self),
        "exploit_xxe": XXESkill(self),
        "exploit_header": HeaderInjectionSkill(self),
        "exploit_ssti": CSTISkill(self),
        "exploit_proto": PrototypePollutionSkill(self),
        
        # External tool skills (Docker-based)
        "tool_sqlmap": SQLMapSkill(self),
        "tool_nuclei": NucleiSkill(self),
        "tool_gospider": GoSpiderSkill(self),
        
        # Advanced AI skills
        "mutate": MutationSkill(self)
    }
```

### Execution Loop

```python
async def run(self) -> Dict:
    """
    Main execution loop - LLM decides what to do.
    """
    while self.iteration < max_iterations and not self.is_complete:
        # 1. Build prompt with context
        prompt = self._build_iteration_prompt()
        
        # 2. Get LLM decision
        response = await llm_client.generate_with_thread(prompt, self.thread)
        
        # 3. Parse action
        action = self._parse_action(response)
        
        # 4. Execute skill
        if action["type"] == "skill":
            result = await self._execute_skill(action["skill"], action["params"])
            self.skills_used.append(action["skill"])
        
        # 5. Check completion
        if action["type"] == "complete":
            self.is_complete = True
    
    return self._generate_summary()
```

---

## 🛠️ SKILLS IN DETAIL

### Basic Skills

| Skill | Description | Tool Used |
|-------|-------------|-----------|
| `recon` | Crawl URL, discover inputs/forms | VisualCrawler |
| `analyze` | LLM analysis of page content | AnalysisAgent |
| `browser` | Take screenshots, get content | BrowserManager |
| `report` | Generate JSON report | - |

### Exploitation Skills

| Skill | Description | Tool Used |
|-------|-------------|-----------|
| `exploit_xss` | XSS with WAF bypass | ManipulatorOrchestrator |
| `exploit_sqli` | SQLi (error/boolean-based) | sqli_detector + Manipulator |
| `exploit_lfi` | Local File Inclusion | Manual payloads + browser |
| `exploit_xxe` | XML External Entity | xxe_detector |
| `exploit_header` | CRLF/Header Injection | header_detector |
| `exploit_ssti` | Template Injection | csti_detector |
| `exploit_proto` | Prototype Pollution | proto_detector |

### External Tool Skills (Docker Required)

| Skill | Description | Docker Image |
|-------|-------------|--------------|
| `tool_sqlmap` | Heavy SQLi confirmation | googlesky/sqlmap |
| `tool_nuclei` | Template-based CVE scan | projectdiscovery/nuclei |
| `tool_gospider` | Deep crawling | trickest/gospider |

### Advanced Skills

| Skill | Description | Tool Used |
|-------|-------------|-----------|
| `mutate` | AI-powered WAF bypass | MutationEngine (LLM) |

---

## 🔄 CONVERSATION THREAD

Each URLMasterAgent has a **ConversationThread** that maintains persistent context.

```python
class ConversationThread:
    def __init__(self, target_url: str):
        self.thread_id = f"thread_{uuid.uuid4().hex[:12]}"
        self.target_url = target_url
        self.messages: List[Dict] = []      # Full conversation history
        self.metadata: Dict = {}            # Discovered data
        self.payload_attempts: List[Dict] = []  # Attack history
    
    def add_message(self, role: str, content: str):
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_context_summary(self) -> str:
        """Returns formatted context for LLM."""
        return f"""
        Target: {self.target_url}
        Discovered Inputs: {len(self.metadata.get('inputs_found', []))}
        Payloads Attempted: {len(self.payload_attempts)}
        Successful Payloads: {len([p for p in self.payload_attempts if p['success']])}
        """
```

### Thread Persistence
Threads are saved to `logs/thread_{id}.json` for debugging and session resume.

---

## 🎯 MANIPULATOR ORCHESTRATOR

The **ManipulatorOrchestrator** is the central intelligence for HTTP exploitation.

### Architecture
```
ManipulatorOrchestrator
├── PayloadAgent (generates XSS/SQLi/etc payloads)
├── EncodingAgent (WAF bypass transformations)
└── RequestController (rate limiting, circuit breaker)
```

### Usage in XSSSkill
```python
class XSSSkill(BaseSkill):
    async def execute(self, url: str, params: Dict) -> Dict:
        from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
        from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
        
        manipulator = ManipulatorOrchestrator(rate_limit=0.3)
        
        request = MutableRequest(
            method="GET",
            url=url,
            params={"param_name": "original_value"}
        )
        
        success = await manipulator.process_finding(
            request,
            strategies=[
                MutationStrategy.PAYLOAD_INJECTION,
                MutationStrategy.BYPASS_WAF
            ]
        )
        
        if success:
            # XSS confirmed!
```

### Success Detection
```python
# In ManipulatorOrchestrator._try_mutation()
if "alert(1)" in body:        # XSS reflected
    return True
if "root:x:0:0" in body:      # LFI/RCE
    return True
if "SQL syntax" in body:      # SQLi error
    return True
```

---

## 🚀 CLI USAGE

### Default (Vertical Mode)
```bash
python -m bugtrace "http://target.com"
```

### With Options
```bash
python -m bugtrace "http://target.com" \
    --max-urls 20 \
    --max-depth 3
```

### Legacy Horizontal Mode
```bash
python -m bugtrace "http://target.com" --horizontal
```

---

## 📊 EXAMPLE OUTPUT

```
[2026-01-02 22:34:20] INFO  Target: http://testphp.vulnweb.com
[2026-01-02 22:34:20] INFO  Architecture: Vertical (URLMasterAgent per URL)
[2026-01-02 22:34:21] INFO  Phase 1: Crawling...
[2026-01-02 22:34:25] INFO  Discovered 8 URLs to analyze

[2026-01-02 22:34:26] INFO  [URLMaster-3c0f95ae] Started: /artists.php?artist=3
[2026-01-02 22:34:26] INFO  [URLMaster-4687c678] Started: /listproducts.php?cat=4
[2026-01-02 22:34:30] INFO  [URLMaster-3c0f95ae] Executing skill: exploit_sqli
[2026-01-02 22:34:32] INFO  [URLMaster-3c0f95ae] ✅ SQLi detected via sqli_detector
[2026-01-02 22:34:35] INFO  [URLMaster-3c0f95ae] Executing skill: exploit_xss
[2026-01-02 22:34:36] INFO  Manipulator: Exploited successfully! Payload: {'artist': '<script>alert(1)</script>'}
[2026-01-02 22:34:36] INFO  [URLMaster-3c0f95ae] ✅ XSS confirmed on param: artist
```

---

## 📈 METRICS

### Test Results on testphp.vulnweb.com

| Vulnerability | URL | Detected By |
|---------------|-----|-------------|
| SQLi | `artists.php?artist=3` | sqli_detector |
| SQLi | `listproducts.php?cat=4` | sqli_detector |
| XSS | `artists.php?artist=` | ManipulatorOrchestrator |
| XSS | `listproducts.php?cat=` | ManipulatorOrchestrator |

### Performance
- **8 URLs analyzed** in ~3 minutes
- **4 vulnerabilities** confirmed
- **100% true positive rate** (no false positives)

---

## 🔧 CONFIGURATION

### bugtraceaicli.conf
```ini
[SCAN]
MAX_DEPTH = 2
MAX_URLS = 25
MAX_CONCURRENT_URL_AGENTS = 10

[SAFE_MODE]
ENABLED = false

[OPENROUTER]
API_KEY = your_key_here
PRIMARY_MODEL = qwen/qwen-2.5-coder-32b-instruct
VISION_MODEL = qwen/qwen-2.5-vl-72b-instruct
```

---

## 📚 SEE ALSO

- [http_manipulator.md](http_manipulator.md) - ManipulatorOrchestrator details
- [feature_inventory.md](feature_inventory.md) - All exploitation tools
- [evaluation_methodology.md](evaluation_methodology.md) - Testing methodology

---

**Total Lines of Code in URLMasterAgent**: ~1100
**Total Skills**: 15
**Architecture**: Event-driven, LLM-orchestrated, fully autonomous
