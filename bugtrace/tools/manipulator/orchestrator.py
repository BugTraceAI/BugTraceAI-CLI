import asyncio
from typing import List, Optional
from bugtrace.utils.logger import logger
from .models import MutableRequest, MutationStrategy, AgentFeedback, FeedbackStatus
from .controller import RequestController
from .specialists.implementations import PayloadAgent, EncodingAgent
from bugtrace.core.ui import dashboard

class ManipulatorOrchestrator:
    """
    Coordinates the HTTP manipulation campaign.
    """
    def __init__(self, rate_limit: float = 0.5):
        self.controller = RequestController(rate_limit=rate_limit)
        self.payload_agent = PayloadAgent()
        self.encoding_agent = EncodingAgent()
        
    async def process_finding(self, base_request: MutableRequest, strategies: List[MutationStrategy] = None):
        """
        Main entry point to verify or exploit a finding.
        Returns: (success_bool, successful_mutation_request)
        """
        if strategies is None:
            strategies = [MutationStrategy.PAYLOAD_INJECTION]

        logger.info(f"Manipulator: Starting campaign on {base_request.url} with strategies {strategies}")

        # Phase 1: Payload Generation
        request_count = 0
        async for mutation in self.payload_agent.generate_mutations(base_request, strategies):
            request_count += 1
            if request_count % 20 == 0:
                logger.info(f"Manipulator progress: {request_count} mutations tested")
            
            success = await self._try_mutation(mutation)
            if success:
                logger.info(f"Manipulator: Exploited successfully! URL: {mutation.url} Params: {mutation.params}")
                return True, mutation
            
            # Phase 2: Reactive Encoding (WAF Bypass)
            if MutationStrategy.BYPASS_WAF in strategies:
                async for encoded_mutation in self.encoding_agent.generate_mutations(mutation, strategies):
                    success_enc = await self._try_mutation(encoded_mutation)
                    if success_enc:
                        logger.info(f"Manipulator: Exploited with WAF Bypass! URL: {encoded_mutation.url} Params: {encoded_mutation.params}")
                        return True, encoded_mutation
        
        logger.info("Manipulator: Campaign finished without confirmation.")
        return False, None

    def _extract_potential_payloads(self, request: MutableRequest) -> List[str]:
        """Extract all potential payloads from request params, data, and JSON."""
        potential_payloads = list(request.params.values())

        if isinstance(request.data, dict):
            potential_payloads.extend(request.data.values())
        elif isinstance(request.data, str):
            potential_payloads.append(request.data)

        if request.json_payload:
            potential_payloads.extend(self._get_json_values(request.json_payload))

        return potential_payloads

    def _get_json_values(self, data):
        """Recursively extract all values from JSON structure."""
        vals = []
        if isinstance(data, dict):
            for v in data.values():
                vals.extend(self._get_json_values(v))
        elif isinstance(data, list):
            for item in data:
                vals.extend(self._get_json_values(item))
        else:
            vals.append(data)
        return vals

    def _check_xss_indicators(self, body: str, potential_payloads: List[str]) -> bool:
        """Check for XSS indicators in response body."""
        if "BUGTRACE-XSS-CONFIRMED" in body:
            return True

        if any(indicator in body for indicator in [
            "BUGTRACE-XSS",
            "<script>document.write",
            "document.body.innerHTML"
        ]):
            return True

        for val in potential_payloads:
            str_val = str(val)
            if "alert(" in str_val and str_val in body:
                return True

        return False

    def _check_lfi_indicators(self, body: str) -> bool:
        """Check for LFI/RCE indicators in response body."""
        return any(indicator in body for indicator in ["root:x:0:0", "/bin/bash", "[font]"])

    def _check_sqli_indicators(self, body: str) -> bool:
        """Check for SQL injection error indicators in response body."""
        sql_errors = [
            "SQL syntax", "mysql_fetch", "Warning: mysql",
            "Unclosed quotation mark", "quoted string not properly terminated",
            "PostgreSQL query failed", "ODBC SQL Server Driver",
            "Microsoft OLE DB Provider for SQL Server", "java.sql.SQLException",
            "SQLite/JDBCDriver", "System.Data.SqlClient.SqlException"
        ]
        return any(error.lower() in body.lower() for error in sql_errors)

    async def _try_mutation(self, request: MutableRequest) -> bool:
        """
        Requests execution of a single mutation and analyzes the result.
        Returns True if successful exploit detected.
        """
        try:
            payload_sample = str(request.params)[:80]
            dashboard.set_current_payload(payload=payload_sample, vector="HTTP Mutation", status="Testing")
        except Exception as e:
            logger.debug(f"Dashboard update failed: {e}")

        status_code, body, duration = await self.controller.execute(request)

        if status_code in (403, 406):
            self.encoding_agent.record_failure(request)
            return False

        potential_payloads = self._extract_potential_payloads(request)
        success_detected = (
            self._check_xss_indicators(body, potential_payloads) or
            self._check_lfi_indicators(body) or
            self._check_sqli_indicators(body)
        )

        if success_detected:
            self.encoding_agent.record_success(request)
            return True

        return False

    async def shutdown(self):
        await self.controller.close()
