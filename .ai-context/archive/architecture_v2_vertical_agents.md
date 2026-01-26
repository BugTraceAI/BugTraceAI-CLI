# Vertical Agent Architecture Redesign

## Problem Statement

The current architecture uses **horizontal agents** (ReconAgent, AnalysisAgent, ExploitAgent, SkepticalAgent) where each agent processes ALL URLs independently. This causes:

1. **Context Loss**: Each LLM call is stateless - no memory of previous attempts
2. **Fragmented Flow**: Information passes through events with minimal context
3. **No Conversational Thread**: The LLM doesn't remember what it tried before
4. **Inefficient Exploitation**: Can't iterate intelligently on payloads

## Proposed Architecture

Transform to **vertical agents per URL** where one `URLMasterAgent` owns an entire URL's lifecycle and maintains a conversational thread while delegating to specialized sub-agents.

```
┌─────────────────────────────────────────────────────────────────┐
│                      TeamOrchestrator                           │
│                   (Spawns URLMasterAgents)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
   ╔═══════════════╗  ╔═══════════════╗  ╔═══════════════╗
   ║ URLMaster:    ║  ║ URLMaster:    ║  ║ URLMaster:    ║
   ║ url1.com      ║  ║ url2.com      ║  ║ url3.com      ║
   ║               ║  ║               ║  ║               ║
   ║ [Conv Thread] ║  ║ [Conv Thread] ║  ║ [Conv Thread] ║
   ╚═══════════════╝  ╚═══════════════╝  ╚═══════════════╝
          │                   │                   │
          ▼                   ▼                   ▼
   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
   │ Sub-agents: │     │ Sub-agents: │     │ Sub-agents: │
   │ • Recon     │     │ • Recon     │     │ • Recon     │
   │ • XSS       │     │ • XSS       │     │ • XSS       │
   │ • SQLi      │     │ • SQLi      │     │ • SQLi      │
   │ • Validate  │     │ • Validate  │     │ • Validate  │
   └─────────────┘     └─────────────┘     └─────────────┘
```

---

## Proposed Changes

### Core Infrastructure

#### [NEW] [conversation_thread.py](file:///home/ubuntu/Dev/Projects/Bugtraceai-CLI/bugtrace/core/conversation_thread.py)

New class to manage conversational context:

```python
class ConversationThread:
    """Manages a persistent conversation thread for an LLM session."""
    
    thread_id: str              # Unique ID (URL hash)
    messages: List[Dict]        # Full message history
    metadata: Dict              # target, tech_stack, waf, etc.
    created_at: datetime
    last_activity: datetime
    
    def add_message(role: str, content: str)
    def get_messages() -> List[Dict]
    def add_tool_result(tool_name: str, result: Any)
    def summarize_if_needed()  # Compact when too long
    def to_dict() / from_dict()  # Persistence
```

---

#### [MODIFY] [llm_client.py](file:///home/ubuntu/Dev/Projects/Bugtraceai-CLI/bugtrace/core/llm_client.py)

Add thread-aware generation:

```python
# Current (stateless):
async def generate(self, prompt: str, module_name: str, ...) -> str

# New (thread-aware):
async def generate_with_thread(
    self, 
    prompt: str, 
    thread: ConversationThread,  # ← Maintains context
    module_name: str,
    ...
) -> str:
    # Build messages from thread history + new prompt
    messages = thread.get_messages()
    messages.append({"role": "user", "content": prompt})
    
    # Send full history to LLM
    response = await self._call_llm(messages)
    
    # Add response to thread
    thread.add_message("assistant", response)
    
    return response
```

---

### New Agent

#### [NEW] [url_master.py](file:///home/ubuntu/Dev/Projects/Bugtraceai-CLI/bugtrace/agents/url_master.py)

The central orchestrator agent per URL:

```python
class URLMasterAgent:
    """
    Vertical agent that owns one URL's complete analysis lifecycle.
    Maintains conversational thread and delegates to sub-agents.
    """
    
    def __init__(self, target_url: str, team_orchestrator):
        self.url = target_url
        self.thread = ConversationThread(thread_id=hash(target_url))
        self.sub_agents = {
            "recon": ReconSkill(),
            "xss": XSSSkill(), 
            "sqli": SQLiSkill(),
            "validate": ValidateSkill()
        }
        
    async def run(self):
        """Main loop - LLM decides what to do next."""
        while not self.is_complete():
            # Ask LLM what to do next (with full context)
            decision = await llm_client.generate_with_thread(
                prompt=self._build_decision_prompt(),
                thread=self.thread,
                module_name="URLMaster"
            )
            
            # Parse decision and execute
            action = self._parse_action(decision)
            result = await self._execute_action(action)
            
            # Add result to thread
            self.thread.add_tool_result(action.name, result)
    
    async def _execute_action(self, action):
        """Delegate to appropriate sub-agent."""
        if action.type == "recon":
            return await self.sub_agents["recon"].execute(self.url, action.params)
        elif action.type == "xss":
            return await self.sub_agents["xss"].execute(self.url, action.params)
        # ... etc
```

---

### Refactor Existing Agents to Skills

#### [MODIFY] [recon.py](file:///home/ubuntu/Dev/Projects/Bugtraceai-CLI/bugtrace/agents/recon.py)

Extract recon logic into a callable skill:

```python
# Keep existing ReconAgent for backwards compatibility

# Add new skill class
class ReconSkill:
    """Recon functionality as a callable skill for URLMasterAgent."""
    
    async def execute(self, url: str, params: Dict) -> Dict:
        """Execute recon and return structured results."""
        # Use existing crawl logic
        crawler = VisualCrawler()
        inputs = await crawler.crawl(url)
        
        return {
            "urls_found": [...],
            "inputs_found": [...],
            "tech_stack": [...],
            "status": "complete"
        }
```

Similar pattern for:
- `XSSSkill` from ExploitAgent XSS logic
- `SQLiSkill` from ExploitAgent SQLi logic  
- `ValidateSkill` from SkepticalAgent logic

---

#### [MODIFY] [team.py](file:///home/ubuntu/Dev/Projects/Bugtraceai-CLI/bugtrace/core/team.py)

Update orchestrator to spawn URLMasterAgents:

```python
class TeamOrchestrator:
    
    async def start(self, target: str):
        # Option 1: Single URL mode
        if self.mode == "single":
            master = URLMasterAgent(target, self)
            await master.run()
        
        # Option 2: Multi-URL mode (parallel)
        else:
            urls = await self._discover_urls(target)
            masters = [URLMasterAgent(url, self) for url in urls]
            await asyncio.gather(*[m.run() for m in masters])
```

---

## Benefits of New Architecture

| Before | After |
|--------|-------|
| Context lost between calls | Full conversation history |
| Agents don't share context | URLMaster has everything |
| Can't iterate on failures | LLM remembers what failed |
| Fixed workflow | LLM decides workflow |
| Hard to debug | One log per URL |

---

## Verification Plan

### Automated Tests

Since this is a major architectural change, we need integration tests:

```bash
# Run existing test suite to ensure no regression
cd /home/ubuntu/Dev/Projects/Bugtraceai-CLI
source .venv/bin/activate
python -m pytest tests/ -v  # If tests exist
```

### Manual Verification

1. **Test ConversationThread persistence:**
   ```bash
   python -c "
   from bugtrace.core.conversation_thread import ConversationThread
   thread = ConversationThread('test_url')
   thread.add_message('user', 'Hello')
   thread.add_message('assistant', 'Hi there')
   print(thread.get_messages())  # Should show 2 messages
   "
   ```

2. **Test URLMasterAgent basic flow:**
   ```bash
   python -c "
   import asyncio
   from bugtrace.agents.url_master import URLMasterAgent
   
   async def test():
       master = URLMasterAgent('http://testphp.vulnweb.com', None)
       # Just test initialization
       print(f'Thread ID: {master.thread.thread_id}')
       print(f'Sub-agents: {list(master.sub_agents.keys())}')
   
   asyncio.run(test())
   "
   ```

3. **E2E Scan Test (after implementation):**
   ```bash
   source .venv/bin/activate
   python -m bugtrace "http://testphp.vulnweb.com" --max-depth 1 --max-urls 3
   # Check logs for "URLMaster" entries and conversation flow
   ```

### User Manual Testing

After implementation, the user should:
1. Run a scan and check `logs/bugtrace.jsonl` for conversation thread logs
2. Verify that the LLM references previous attempts in its responses
3. Check that `validated_findings.json` is generated with proper context

---

## Implementation Order

1. **Phase 1**: Create `ConversationThread` class (core/conversation_thread.py)
2. **Phase 2**: Add `generate_with_thread()` to LLMClient
3. **Phase 3**: Create `URLMasterAgent` with basic loop  
4. **Phase 4**: Extract skills from existing agents (ReconSkill, XSSSkill, etc.)
5. **Phase 5**: Update TeamOrchestrator to use new architecture
6. **Phase 6**: Testing and validation

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Higher token cost | Implement context summarization when thread gets long |
| Backwards compatibility | Keep existing agents working in parallel during migration |
| Complexity | Start with minimal URLMaster, add features incrementally |
| Debugging difficulty | Add extensive logging per thread |

---

## User Review Required

> [!IMPORTANT]
> This is a significant architectural change. Before proceeding:
> 1. Do you approve this general direction?
> 2. Should we keep backwards compatibility with current agents?
> 3. Any preferences on implementation order?
