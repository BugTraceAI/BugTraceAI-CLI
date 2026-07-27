import asyncio
from datetime import datetime
from typing import Set, List
from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.tools.visual.crawler import visual_crawler
from bugtrace.memory.manager import memory_manager
from bugtrace.tools.external import external_tools
from bugtrace.core.llm_client import llm_client
from bugtrace.tools.visual.browser import browser_manager
from bugtrace.utils.logger import get_logger

logger = get_logger("agents.recon")

class ReconAgent(BaseAgent):
    """
    Reconnaissance Agent - Attack Surface Discovery.
    Maps all inputs, URLs, and potential vulnerabilities.
    
    EVENT BUS INTEGRATION (Phase 1 - COMPLETED):
    - Publishes: "new_input_discovered" (to ExploitAgent)
    - Subscribes: "pattern_detected" (optional feedback from ExploitAgent)
    """
    def __init__(self, target: str, max_depth: int = 2, max_pages: int = 15, event_bus=None):
        super().__init__("Recon-1", "Discovery", event_bus=event_bus, agent_id="recon_1")
        self.target = target
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
    
    def _setup_event_subscriptions(self):
        """
        OPTIONAL: Subscribe to pattern_detected for feedback loop.
        Not critical for Phase 1.
        """
        # Optional: self.event_bus.subscribe("pattern_detected", self.handle_pattern_feedback)
        logger.info(f"[{self.name}] Event subscriptions setup (none for Phase 1)")
    
    def _cleanup_event_subscriptions(self):
        """Cleanup event subscriptions on agent stop."""
        # Optional: self.event_bus.unsubscribe("pattern_detected", self.handle_pattern_feedback)
        logger.info(f"[{self.name}] Event cleanup complete")
        
    async def run_loop(self):
        await self.check_pause()
        self.think(f"Initiating visual intelligence on {self.target}")

        page_analysis_text, page_state = await self._run_visual_analysis()
        await self._emit_target_discovery(page_state)

        crawl_results = await self._run_visual_crawl()
        await self._process_crawl_results(crawl_results)

        await self._run_contextual_path_discovery(page_analysis_text)
        await self._run_external_intelligence()

        dashboard.log(f"[{self.name}] Primary Recon Complete. Monitoring mode.", "INFO")

        # Phase 4: Continuous Monitoring
        while self.running:
            await self.check_pause()
            await asyncio.sleep(5)

    async def _run_visual_analysis(self):
        """Phase 0: Visual Deep Analysis (Thinking Vision)."""
        page_analysis_text = ""
        page_state = None

        try:
            page_state = await browser_manager.capture_state(self.target)
            self.think("Analyzing landing page beauty and security surface")

            screenshot_path = page_state.get('screenshot', '')
            if not screenshot_path:
                return page_analysis_text, page_state

            with open(screenshot_path, 'rb') as f:
                screenshot_bytes = f.read()

            vision_prompt = self._build_vision_prompt()
            page_analysis_text = await llm_client.analyze_visual(screenshot_bytes, vision_prompt)

            if page_analysis_text:
                dashboard.log(f"[{self.name}] Visual Intel: {page_analysis_text[:60]}...", "SUCCESS")
        except Exception as e:
            self.think(f"Visual analysis skipped: {e}")

        return page_analysis_text, page_state

    def _build_vision_prompt(self):
        """Build vision analysis prompt from config or default."""
        default_prompt = "Perform a security-oriented analysis of this page. Identify tech stack, cms, and potential hidden admin or api paths."

        if not self.system_prompt:
            return default_prompt

        import re
        parts = re.split(r'#+\s+Path Prediction Prompt', self.system_prompt, flags=re.IGNORECASE)
        vision_part = parts[0]
        return re.sub(r'#+\s+(RECON_AGENT|Visual Intelligence Prompt)', '', vision_part, flags=re.IGNORECASE).strip()

    async def _emit_target_discovery(self, page_state):
        """Emit discovery event for the main target."""
        if not page_state:
            return

        await self.event_bus.emit("new_url_discovered", {
            "url": self.target,
            "html": page_state.get('html', ''),
            "screenshot": page_state.get('screenshot', ''),
            "discovered_by": self.name,
            "timestamp": datetime.now().isoformat()
        })
        logger.info(f"[{self.name}] 📢 EVENT EMITTED: new_url_discovered | {self.target}")

    async def _run_visual_crawl(self):
        """Phase 1: Visual Crawl."""
        dashboard.log(f"[{self.name}] Starting visual scan on {self.target}...", "INFO")

        crawl_results = await visual_crawler.crawl(
            self.target,
            max_pages=self.max_pages,
            max_depth=self.max_depth
        )

        self.think(f"Crawl complete. Processing {len(crawl_results.get('urls', []))} URLs")
        memory_manager.store_crawler_findings(crawl_results)

        return crawl_results

    async def _process_crawl_results(self, crawl_results):
        """Process and emit events for discovered inputs and tokens."""
        await self._emit_input_discoveries(crawl_results.get('inputs', []))
        await self._emit_token_discoveries(crawl_results.get('tokens', []))

        url_count = len(crawl_results.get('urls', []))
        input_count = len(crawl_results.get('inputs', []))

        dashboard.log(f"[{self.name}] Found {url_count} URLs, {input_count} Inputs", "SUCCESS")
        dashboard.add_finding(
            "Attack Surface",
            f"Discovered {input_count} inputs across {url_count} URLs",
            "INFO"
        )

    async def _emit_input_discoveries(self, inputs_found):
        """Emit new_input_discovered events for each input."""
        for input_data in inputs_found:
            await self.event_bus.emit("new_input_discovered", {
                "url": input_data.get('url', self.target),
                "input": {
                    "name": input_data.get('name', 'unknown'),
                    "type": input_data.get('type', 'text'),
                    "id": input_data.get('id', ''),
                    "tag": input_data.get('tag', 'input'),
                    "placeholder": input_data.get('placeholder', ''),
                    "value": input_data.get('value', '')
                },
                "discovered_by": self.name,
                "timestamp": datetime.now().isoformat(),
                "phase": "Visual Crawl"
            })

            logger.info(
                f"[{self.name}] 📢 EVENT EMITTED: new_input_discovered | "
                f"{input_data.get('name', 'unknown')} ({input_data.get('type', 'text')}) at {input_data.get('url', self.target)}"
            )

        logger.info(f"[{self.name}] Emitted {len(inputs_found)} new_input_discovered events")

    async def _emit_token_discoveries(self, tokens_found):
        """Emit auth_token_found events for detected tokens."""
        if not tokens_found:
            return

        dashboard.log(f"[{self.name}] 🔐 Discovered {len(tokens_found)} potential AUTH TOKENS", "WARN")
        logger.info(f"[{self.name}] Emitting {len(tokens_found)} auth_token_found events")

        for t in tokens_found:
            await self.event_bus.emit("auth_token_found", {
                "url": t.get('url'),
                "token": t.get('token'),
                "location": t.get('location'),
                "context": t.get('context'),
                "discovered_by": self.name,
                "timestamp": datetime.now().isoformat()
            })

    async def _run_contextual_path_discovery(self, page_analysis_text):
        """Phase 2: Contextual Path Discovery."""
        self.think("Generating contextual hidden paths for fuzzing...")
        potential_paths = await self._generate_contextual_paths(page_analysis_text)

        for path in potential_paths:
            full_url = f"{self.target.rstrip('/')}{path}"
            memory_manager.store_crawler_findings({"urls": [full_url], "inputs": []})
            dashboard.log(f"[{self.name}] Ingested Potential Path: {path}", "DEBUG")

    async def _run_external_intelligence(self):
        """Phase 3: External Intelligence (GoSpider + Nuclei)."""
        session_data = await browser_manager.get_session_data()
        cookies = session_data.get("cookies", [])

        # GoSpider: Deep crawler with session
        spider_urls = await external_tools.run_gospider(self.target, cookies=cookies)
        if spider_urls:
            self.think(f"GoSpider augmented knowledge with {len(spider_urls)} new URLs")
            memory_manager.store_crawler_findings({"urls": spider_urls, "inputs": []})

        # Nuclei: Vulnerability Scanner with session
        nuclei_res = await external_tools.run_nuclei(self.target, cookies=cookies)
        if nuclei_res:
            dashboard.log(f"[{self.name}] Nuclei found {len(nuclei_res)} items", "INFO") 

    async def _generate_contextual_paths(self, analysis_context: str) -> List[str]:
        """
        Generates a list of potential paths based on the technology stack identified + standard list.
        """
        # 1. Standard Critical Paths (Always check)
        paths = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/admin", "/login"]

        # 2. LLM Hallucinated Paths (Good kind of hallucination - Prediction)
        if not analysis_context:
            return list(set(paths))

        llm_paths = await self._generate_llm_predicted_paths(analysis_context)
        paths.extend(llm_paths)
        return list(set(paths))

    async def _generate_llm_predicted_paths(self, analysis_context: str) -> List[str]:
        """Generate LLM-predicted paths based on analysis context."""
        prompt = self._build_path_prediction_prompt(analysis_context)
        suggestion = await llm_client.generate(prompt, module_name="Recon-PathPred")

        if not suggestion:
            return []

        return self._extract_paths_from_suggestion(suggestion)

    def _build_path_prediction_prompt(self, analysis_context: str) -> str:
        """Build prompt for path prediction."""
        import re

        if self.system_prompt and re.search(r'#+\s+Path Prediction Prompt', self.system_prompt, flags=re.IGNORECASE):
            parts = re.split(r'#+\s+Path Prediction Prompt', self.system_prompt, flags=re.IGNORECASE)
            template = parts[1].strip()
            return template.replace("{analysis_context}", analysis_context)

        return f"""
        Based on this analysis of a web application: "{analysis_context}"
        Suggest 5 likely hidden URL paths that might exist (e.g. specific admin panels, API docs, dev endpoints).
        Return ONLY the paths, one per line. Start with /.
        """

    def _extract_paths_from_suggestion(self, suggestion: str) -> List[str]:
        """Extract valid paths from LLM suggestion."""
        paths = []
        for line in suggestion.splitlines():
            clean = line.strip()
            if clean.startswith("/") and " " not in clean:
                paths.append(clean)
        return paths
