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

    async def _try_mutation(self, request: MutableRequest) -> bool:
        """
        Requests execution of a single mutation and analyzes the result.
        Returns True if successful exploit detected.
        """
        # Update Dashboard
        try:
            payload_sample = str(request.params)[:80]
            dashboard.set_current_payload(payload=payload_sample, vector="HTTP Mutation", status="Testing")
        except:
            pass

        status_code, body, duration = await self.controller.execute(request)
        
        # 1. Check for WAF 
        if status_code == 403 or status_code == 406:
            self.encoding_agent.record_failure(request)
            return False
            
        # 2. Check for XSS reflection
        success_detected = False
        # Collect all possible injected values from params, data, and json_payload
        potential_payloads = list(request.params.values())
        if isinstance(request.data, dict):
            potential_payloads.extend(request.data.values())
        elif isinstance(request.data, str):
            potential_payloads.append(request.data)
        
        if request.json_payload:
            # Simple recursive search for values in JSON
            def get_json_values(data):
                vals = []
                if isinstance(data, dict):
                    for v in data.values():
                        vals.extend(get_json_values(v))
                elif isinstance(data, list):
                    for item in data:
                        vals.extend(get_json_values(item))
                else:
                    vals.append(data)
                return vals
            potential_payloads.extend(get_json_values(request.json_payload))

        for val in potential_payloads:
            str_val = str(val)
            
            # Primary: Look for BUGTRACE marker (reliable vision validation)
            if "BUGTRACE-XSS-CONFIRMED" in body:
                success_detected = True
                break
            
            # Secondary: XSS payload reflected (various detection methods)
            if any(indicator in body for indicator in [
                "BUGTRACE-XSS",           # Our marker
                "<script>document.write",  # Our visible injection
                "document.body.innerHTML", # DOM manipulation
            ]):
                success_detected = True
                break
            
            # Tertiary: Traditional alert detection (backup)
            if "alert(" in str_val and str_val in body:
                success_detected = True
                break
            
        # 3. Check for LFI/RCE indicator
        if not success_detected:
            if "root:x:0:0" in body or "/bin/bash" in body or "[font]" in body:
                success_detected = True
            
        # 4. Check for SQLi Errors (expanded list)
        if not success_detected:
            sql_errors = [
                "SQL syntax", "mysql_fetch", "Warning: mysql", 
                "Unclosed quotation mark", "quoted string not properly terminated",
                "PostgreSQL query failed", "ODBC SQL Server Driver",
                "Microsoft OLE DB Provider for SQL Server", "java.sql.SQLException",
                "SQLite/JDBCDriver", "System.Data.SqlClient.SqlException"
            ]
            for error in sql_errors:
                if error.lower() in body.lower():
                    success_detected = True
                    break

        if success_detected:
            self.encoding_agent.record_success(request)
            return True

        return False

    async def shutdown(self):
        await self.controller.close()
