import asyncio
from pathlib import Path
from loguru import logger
from bugtrace.core.job_manager import JobManager, JobStatus
from bugtrace.core.executor import ToolExecutor
from bugtrace.agents.gospider_agent import GoSpiderAgent
from bugtrace.agents.xss_agent import XSSAgent
from bugtrace.agents.csti_agent import CSTIAgent
from bugtrace.agents.sqlmap_agent import SQLMapAgent
from bugtrace.agents.fileupload_agent import FileUploadAgent
from bugtrace.agents.idor_agent import IDORAgent
from bugtrace.agents.ssrf_agent import SSRFAgent
from bugtrace.agents.xxe_agent import XXEAgent
from bugtrace.agents.jwt_agent import JWTAgent
from bugtrace.agents.analysis_agent import DASTySASTAgent
from bugtrace.core.state import get_state_manager

# Q-Learning WAF Strategy Router (singleton)
from bugtrace.tools.waf import strategy_router


class Reactor:
    """
    The V4 Orchestrator. 
    Event-driven, State-based, Resumable.
    """
    
    def __init__(self, target: str, resume: bool = False):
        self.target = target
        self.job_manager = JobManager("state/jobs.db")
        
        if not resume:
            # Seed the initial job if not resuming
            self.job_manager.add_job("RECON", target, priority=100)
            
        # Recovery mechanism
        self.job_manager.reset_running_jobs()

    async def run(self):
        """Main Reactor loop - Process jobs in parallel."""
        from bugtrace.core.config import settings
        logger.info(f"⚛️ Reactor Initialized for {self.target}")

        # Parallel processing control
        max_parallel = 30  # Parallel slots for Analysis + Specialists
        semaphore = asyncio.Semaphore(max_parallel)
        active_tasks: set = set()
        self.running = True

        try:
            while self.running:
                # Check for new jobs (now atomic via UPDATE...RETURNING)
                job = self.job_manager.get_next_job()
                if not job:
                    # If no jobs and no active tasks, we are done
                    if not active_tasks:
                        logger.success("⚛️ Reactor: All jobs finished.")
                        break
                    # Wait for at least one task to complete before checking again
                    if active_tasks:
                        done, active_tasks = await asyncio.wait(
                            active_tasks,
                            timeout=2.0,
                            return_when=asyncio.FIRST_COMPLETED
                        )
                    else:
                        await asyncio.sleep(2)
                    continue

                async def worker(j):
                    async with semaphore:
                        # TASK-10: Job processing timeout to prevent hanging jobs
                        job_timeout = getattr(settings, 'JOB_PROCESSING_TIMEOUT', 3600)  # Default 1 hour
                        try:
                            await asyncio.wait_for(self._process_job(j), timeout=job_timeout)
                        except asyncio.TimeoutError:
                            logger.error(f"Job {j['id']} timed out after {job_timeout}s")
                            try:
                                self.job_manager.complete_job(
                                    j['id'],
                                    {"error": f"Job timed out after {job_timeout} seconds"},
                                    JobStatus.TIMEOUT,
                                    error=f"Timeout after {job_timeout}s"
                                )
                            except Exception as db_err:
                                logger.error(f"Failed to update job timeout status: {db_err}")
                        except Exception as e:
                            logger.error(f"Worker Error for job {j['id']}: {e}")
                            # Ensure job is marked as FAILED on unhandled exception
                            try:
                                self.job_manager.complete_job(
                                    j['id'],
                                    {"error": str(e)},
                                    JobStatus.FAILED,
                                    error=str(e)
                                )
                            except Exception as db_err:
                                logger.error(f"Failed to update job status: {db_err}")

                task = asyncio.create_task(worker(job))
                active_tasks.add(task)

                # Periodically clean up completed tasks to prevent memory leak
                # This replaces unreliable done_callback approach
                done_tasks = {t for t in active_tasks if t.done()}
                active_tasks -= done_tasks

                # Control dispatch speed
                await asyncio.sleep(0.1)
        finally:
            # Wait for remaining tasks before shutdown
            if active_tasks:
                logger.info(f"⚛️ Reactor: Waiting for {len(active_tasks)} active tasks...")
                await asyncio.gather(*active_tasks, return_exceptions=True)
            # Ensure Q-Learning data is persisted on shutdown
            self._shutdown()

    def _shutdown(self):
        """Persist learned data and cleanup resources."""
        try:
            strategy_router.force_save()
            logger.info("⚛️ Reactor: Q-Learning WAF strategies saved.")
        except Exception as e:
            logger.warning(f"Failed to save Q-Learning data: {e}")

    async def _process_job(self, job: dict):
        """Dispatches the job to the correct Worker."""
        j_type = job['type']
        target = job['target']
        params = job['params']
        
        logger.info(f"⚙️ Processing Job {job['id']}: [{j_type}] -> {target}")
        
        result = {}
        status = JobStatus.COMPLETED
        
        if j_type == "RECON":
            # RECON WORKER (Logic Ported from GoSpiderAgent)
            agent = GoSpiderAgent(target, Path(f"reports/jobs/job_{job['id']}"))
            urls = await agent._fallback_discovery() # Use our new robust fallback
            
            result = {"urls": urls}
            
            # REACTIVE LOGIC: Create Analysis Jobs for found URLs
            for u in urls:
                self.job_manager.add_job("ANALYSIS", u, priority=50)
            status = JobStatus.COMPLETED
                
        elif j_type == "ANALYSIS":
            # DAST + SAST: 5-Approach Analysis (Correcto)
            logger.info(f"🧠 Running DAST+SAST Analysis on {target}")

            # Crear directorio para este análisis
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)

            # Obtener state_manager (necesario para DASTAgent)
            state_manager = get_state_manager(self.target)

            # Tech profile básico (se puede mejorar con Nuclei más adelante)
            tech_profile = {"frameworks": [], "server": "unknown"}

            # Ejecutar DASTySASTAgent
            try:
                dast = DASTySASTAgent(target, tech_profile, job_report_dir, state_manager=state_manager)
                analysis_result = await dast.run()

                vulnerabilities = analysis_result.get("vulnerabilities", [])
                result = {"vulnerabilities": vulnerabilities}

                # REACTIVE LOGIC: Crear jobs SOLO para lo que DAST sugiere
                from urllib.parse import urlparse, parse_qs
                
                for vuln in vulnerabilities:
                    v_type = (vuln.get("type") or "").upper()
                    param = vuln.get("parameter")
                    confidence = float(vuln.get("confidence", 0))

                    # Solo procesar vulnerabilidades con confianza >= 0.1 for maximum Dojo coverage
                    if confidence < 0.1:
                        logger.debug(f"Skipping low-confidence vuln: {v_type} ({confidence})")
                        continue

                    # Prep URL parsing
                    parsed = urlparse(target)
                    val = None

                    # Mapeo de tipo de vulnerabilidad a job type
                    if "SQL" in v_type:
                        self.job_manager.add_job("ATTACK_SQLI", target, {"param": param}, priority=90)
                    elif "XSS" in v_type or "SCRIPT" in v_type:
                        self.job_manager.add_job("ATTACK_XSS", target, {"param": param}, priority=85)
                    elif "XXE" in v_type or "XML" in v_type:
                        self.job_manager.add_job("ATTACK_XXE", target, priority=90)
                    elif "SSRF" in v_type or "SERVER-SIDE REQUEST" in v_type:
                        self.job_manager.add_job("ATTACK_SSRF", target, {"param": param}, priority=85)
                    elif "IDOR" in v_type or "OBJECT REFERENCE" in v_type or "ACCESS CONTROL" in v_type:
                        if parsed.query:
                            q_params = parse_qs(parsed.query)
                            if param in q_params:
                                val = q_params[param][0]
                        
                        # Fallback: if val is still None, try to find a number in the path that matches the 'context'
                        if val is None:
                            import re
                            # Only search in the path part of the URL
                            path_numbers = re.findall(r'/(\d+)', parsed.path)
                            if path_numbers:
                                val = path_numbers[0] # Take the first number in path as a guess
                                
                        self.job_manager.add_job("ATTACK_IDOR", target, {"param": param, "value": val}, priority=80)
                    elif "JWT" in v_type or "TOKEN" in v_type:
                        if parsed.query:
                            q_params = parse_qs(parsed.query)
                            if param in q_params:
                                self.job_manager.add_job("ATTACK_JWT", target, {"token": q_params[param][0]}, priority=90)
                    elif "LFI" in v_type or "TRAVERSAL" in v_type:
                        self.job_manager.add_job("ATTACK_LFI", target, {"param": param}, priority=80) 
                    elif "CSTI" in v_type or "TEMPLATE" in v_type:
                        self.job_manager.add_job("ATTACK_CSTI", target, {"param": param}, priority=85)
                    elif any(kw in v_type for kw in ["CMD", "SHELL", "COMMAND", "RCE", "EVAL"]):
                        self.job_manager.add_job("ATTACK_RCE", target, {"param": param}, priority=95)
                    elif "UPLOAD" in v_type or "FILE" in v_type:
                        self.job_manager.add_job("ATTACK_UPLOAD", target, priority=90)
                    elif "HEADER" in v_type or "CRLF" in v_type:
                        # Header injection already handled by DASTySAST usually, but specialists can follow up
                        logger.success(f"🔓 Header Injection suspected by DAST on {target}")
                    else:
                        logger.debug(f"Unknown vuln type from DAST: {v_type}")
                status = JobStatus.COMPLETED

            except Exception as e:
                logger.error(f"DAST+SAST Analysis failed: {e}")
                result = {"error": str(e), "vulnerabilities": []}
                status = JobStatus.FAILED
        
        elif j_type == "ATTACK_XSS":
            # ATTACK WORKER (Real XSSAgent V3)
            target_param = params.get('param')
            logger.info(f"⚔️ Launching XSS Specialist on {target} param '{target_param}'")
            
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                agent = XSSAgent(
                    url=target,
                    params=[target_param] if target_param else None,
                    report_dir=job_report_dir,
                    headless=True
                )
                agent_result = await agent.run_loop()
                
                findings = agent_result.get('findings', [])
                if findings:
                    logger.success(f"🔥 VULNERABILITY CONFIRMED: Found {len(findings)} XSS on {target}")
                    result = {"findings": [f.to_dict() if hasattr(f, 'to_dict') else str(f) for f in findings]}
                    
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in findings:
                        state_manager.add_finding(
                            url=target,
                            type="Confirmed XSS",
                            description=getattr(f, 'description', "Cross-Site Scripting vulnerability confirmed by XSSAgent."),
                            severity="High",
                            parameter=getattr(f, 'parameter', target_param),
                            payload=getattr(f, 'payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No XSS found on {target} ({target_param})")
                    result = {"findings": []}
                    
                if hasattr(agent, 'cleanup'):
                    await agent.cleanup()
                    
            except Exception as e:
                logger.error(f"XSS Agent Crash: {e}")
                status = JobStatus.FAILED
                result = {"error": str(e)}

        elif j_type == "ATTACK_SQLI":
            # SQL WORKER
            target_param = params.get('param')
            logger.info(f"💉 Launching SQLi Specialist on {target} param '{target_param}'")
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                agent = SQLMapAgent(target, [target_param] if target_param else [], job_report_dir)
                sql_result = await agent.run() 
                
                findings = sql_result.get('findings', [])
                if findings:
                    logger.success(f"💉 SQLi CONFIRMED on {target}")
                    result = {"findings": findings}
                    
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in findings:
                        state_manager.add_finding(
                            url=target,
                            type="Confirmed SQL Injection",
                            description=f.get('reasoning', "SQL Injection vulnerability confirmed by SQLMapAgent."),
                            severity="Critical",
                            parameter=f.get('parameter', target_param),
                            payload=f.get('payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No SQLi found on {target}")
                    result = {"findings": []}
            except Exception as e:
                logger.error(f"SQLi Agent Crash: {e}")
                status = JobStatus.FAILED
                result = {"error": str(e)}

        elif j_type == "ATTACK_IDOR":
            p = params.get('param')
            val = params.get('value')
            logger.info(f"🆔 Launching IDOR Specialist on {target} param '{p}'")
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)
            try:
                # IDORAgent expects params as List[Dict] with 'parameter' and 'original_value' keys
                idor_params = [{"parameter": p, "original_value": val or "1"}] if p else []
                agent = IDORAgent(target, params=idor_params, report_dir=job_report_dir)
                res = await agent.run_loop()

                findings = res.get("findings", [])
                if findings:
                    logger.success(f"🆔 IDOR CONFIRMED on {target}")
                    result = {"findings": findings, "vulnerable": True}

                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in findings:
                        state_manager.add_finding(
                            url=target,
                            type="Confirmed IDOR",
                            description=f.get('description', "IDOR vulnerability confirmed by IDORAgent."),
                            severity=f.get('severity', "Medium"),
                            parameter=f.get('parameter', p),
                            payload=f.get('payload', val),
                            evidence=f.get('evidence', str(f)),
                            validated=f.get('validated', False)
                        )
                else:
                    logger.info(f"🛡️ No IDOR found on {target} ({p})")
                    result = {"findings": [], "vulnerable": False}
                status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"IDOR Agent Crash: {e}")
                import traceback
                logger.error(traceback.format_exc())
                status = JobStatus.FAILED
                result = {"error": str(e)}

        elif j_type == "ATTACK_SSRF":
            p = params.get('param')
            logger.info(f"🌐 Launching SSRF Specialist on {target} param '{p}'")
            try:
                from bugtrace.agents.ssrf_agent import SSRFAgent
                # SSRFAgent expects params as List[str]
                agent = SSRFAgent(target, params=[p] if p else None)
                res = await agent.run_loop()
                if res.get("vulnerable"):
                    logger.success(f"🌐 SSRF CONFIRMED on {target}")
                    result = res
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in res.get("findings", []):
                        state_manager.add_finding(
                            url=target,
                            type=f"Confirmed SSRF",
                            description=f.get('description', "SSRF vulnerability confirmed by SSRFAgent."),
                            severity=f.get('severity', "HIGH"),
                            parameter=p,
                            payload=f.get('payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No SSRF on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"SSRF Agent Crash: {e}")
                status = JobStatus.FAILED

        elif j_type == "ATTACK_XXE":
            logger.info(f"📄 Launching XXE Specialist on {target}")
            try:
                from bugtrace.agents.xxe_agent import XXEAgent
                agent = XXEAgent(target)
                res = await agent.run_loop()
                if res.get("vulnerable"):
                    logger.success(f"📄 XXE CONFIRMED on {target}")
                    result = res
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in res.get("findings", []):
                        state_manager.add_finding(
                            url=target,
                            type=f"Confirmed XXE",
                            description=f.get('description', "XXE vulnerability confirmed by XXEAgent."),
                            severity=f.get('severity', "CRITICAL"),
                            parameter="Request Body",
                            payload=f.get('payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No XXE on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"XXE Agent Crash: {e}")
                status = JobStatus.FAILED

        elif j_type == "ATTACK_JWT":
            token = params.get('token')
            logger.info(f"🔑 Launching JWT Specialist on {target}")
            try:
                from bugtrace.agents.jwt_agent import run_jwt_analysis
                res = await run_jwt_analysis(token, target)
                vulns = res.get("findings", [])
                if vulns: 
                    logger.success(f"🔑 JWT CONFIRMED on {target}")
                    result = {"findings": vulns}
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in vulns:
                        state_manager.add_finding(
                            url=target,
                            type=f"Confirmed {f.get('type', 'JWT Vulnerability')}",
                            description=f.get('description', "JWT vulnerability confirmed by JWTAgent."),
                            severity=f.get('severity', "HIGH"),
                            parameter=f.get('parameter', 'token'),
                            payload=f.get('payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No JWT vulnerabilities found on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"JWT Agent Crash: {e}")
                import traceback
                logger.error(traceback.format_exc())
                status = JobStatus.FAILED
                result = {"error": str(e)}

        elif j_type == "ATTACK_UPLOAD":
            # UPLOAD WORKER
            logger.info(f"📂 Launching File Upload Specialist on {target}")
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                agent = FileUploadAgent(url=target) 
                upload_result = await agent.run_loop()
                
                if upload_result.get("vulnerable"):
                     logger.success(f"📂 RCE CONFIRMED via File Upload on {target}")
                     result = upload_result
                     
                     # Persist to state
                     state_manager = get_state_manager(self.target)
                     for f in upload_result.get('findings', []):
                         state_manager.add_finding(
                             url=target,
                             type="Confirmed File Upload Vulnerability",
                             description=f.get('vulnerability', "Unrestricted File Upload confirmed by FileUploadAgent."),
                             severity="Critical",
                             payload=f.get('method', ""),
                             evidence=f.get('exploit_url', str(f)),
                             validated=True
                         )
                     status = JobStatus.COMPLETED
                else:
                     logger.info(f"🛡️ No File Upload Vuln on {target}")
                     result = {"findings": []}
                     
            except Exception as e:
                logger.error(f"Upload Agent Crash: {e}")
                status = JobStatus.FAILED
                result = {"error": str(e)}
            
        elif j_type == "ATTACK_RCE":
            target_param = params.get('param')
            logger.info(f"💣 Launching RCE Specialist on {target} param '{target_param}'")
            try:
                from bugtrace.agents.rce_agent import RCEAgent
                agent = RCEAgent(target, target_param)
                res = await agent.run_loop()
                
                if res.get("vulnerable"):
                    logger.success(f"💣 RCE CONFIRMED on {target}")
                    result = res
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in res.get("findings", []):
                        state_manager.add_finding(
                            url=target,
                            type=f"Confirmed {f.get('type', 'RCE')}",
                            description=f.get('description', "RCE confirmed by RCEAgent."),
                            severity="CRITICAL",
                            parameter=target_param,
                            payload=f.get('payload', ""),
                            evidence=f.get('evidence', str(f)),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No RCE on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"RCE Agent Crash: {e}")
                status = JobStatus.FAILED
                result = {"error": str(e)}

        elif j_type == "ATTACK_LFI":
            target_param = params.get('param')
            logger.info(f"📂 Launching LFI Specialist on {target} param '{target_param}'")
            try:
                from bugtrace.agents.lfi_agent import LFIAgent
                # LFIAgent expects params as List[str]
                agent = LFIAgent(target, params=[target_param] if target_param else None)
                res = await agent.run_loop()
                
                if res.get("vulnerable"):
                    logger.success(f"📂 LFI CONFIRMED on {target}")
                    result = res
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in res.get("findings", []):
                        state_manager.add_finding(
                            url=target,
                            type=f.get('type', "LFI / Path Traversal"),
                            description=f.get('description', "LFI confirmed by LFIAgent."),
                            severity=f.get('severity', "Critical"),
                            parameter=target_param,
                            payload=f.get('payload', ""),
                            evidence=f.get('evidence', str(f)),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No LFI on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"LFI Agent Crash: {e}")
                status = JobStatus.FAILED

        elif j_type == "ATTACK_CSTI":
            target_param = params.get('param')
            logger.info(f"🧪 Launching CSTI Specialist on {target} param '{target_param}'")
            
            job_report_dir = Path(f"reports/jobs/job_{job['id']}")
            job_report_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                from bugtrace.agents.csti_agent import CSTIAgent
                agent = CSTIAgent(
                    url=target,
                    params=[target_param] if target_param else None,
                    report_dir=job_report_dir
                )
                csti_result = await agent.run_loop()
                
                findings = csti_result.get('findings', [])
                if findings:
                    logger.success(f"🧪 CSTI CONFIRMED on {target}")
                    result = {"findings": findings}
                    
                    # Persist to state
                    state_manager = get_state_manager(self.target)
                    for f in findings:
                        state_manager.add_finding(
                            url=target,
                            type="Confirmed CSTI",
                            description=f.get('evidence', {}).get('description', "Client-Side Template Injection confirmed by CSTIAgent."),
                            severity=f.get('severity', "High"),
                            parameter=f.get('parameter', target_param),
                            payload=f.get('payload', ""),
                            evidence=str(f),
                            validated=True
                        )
                    status = JobStatus.COMPLETED
                else:
                    logger.info(f"🛡️ No CSTI on {target}")
                    result = {"findings": []}
                    status = JobStatus.COMPLETED
            except Exception as e:
                logger.error(f"CSTI Agent Crash: {e}")
                status = JobStatus.FAILED
                result = {"error": str(e)}
                
        else:
            logger.warning(f"Unknown Job Type: {j_type}")
            status = JobStatus.FAILED

        # 3. Complete Job
        self.job_manager.complete_job(job['id'], result, status)
