"""
ConversationThread: Persistent message history for LLM conversations.

Part of the Vertical Agent Architecture - each URL gets its own conversation thread
that maintains full context across all LLM interactions.

Author: BugtraceAI-CLI Team
Created: 2026-01-02
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("core.conversation_thread")


class ConversationThread:
    """
    Manages a persistent conversation thread for an LLM session.
    
    Each URL gets its own thread that maintains:
    - Full message history (user/assistant/tool)
    - Metadata (target, tech stack, WAF, etc.)
    - Tool call results
    
    This enables the LLM to:
    - Remember what it already tried
    - Build on previous analysis
    - Iterate intelligently on exploits
    """
    
    MAX_MESSAGES = 50  # Summarize when exceeded
    
    def __init__(self, target_url: str, thread_id: Optional[str] = None):
        """
        Initialize a conversation thread for a target URL.
        
        Args:
            target_url: The URL this thread is managing
            thread_id: Optional custom thread ID (defaults to URL hash)
        """
        self.target_url = target_url
        self.thread_id = thread_id or self._generate_thread_id(target_url)
        self.messages: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "target": target_url,
            "tech_stack": [],
            "waf_detected": None,
            "inputs_found": [],
            "vulnerabilities_found": [],
            "payloads_tried": {},
            "payloads_blocked": [],
        }
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        
        # Initialize with system context
        self._add_system_context()
        
        logger.info(f"ConversationThread created: {self.thread_id} for {target_url}")
    
    def _generate_thread_id(self, url: str) -> str:
        """Generate unique thread ID from URL."""
        return f"thread_{hashlib.md5(url.encode()).hexdigest()[:12]}"
    
    def _add_system_context(self):
        """Add initial system message with role and context."""
        system_message = {
            "role": "system",
            "content": f"""You are an expert penetration tester analyzing {self.target_url}.

Your objective is to find and validate security vulnerabilities through systematic testing.

You have access to the following tools:
- recon: Crawl and discover URLs, inputs, technology stack
- analyze: Analyze code/responses for vulnerability patterns
- exploit_xss: Test XSS payloads with browser verification
- exploit_sqli: Test SQL injection with various techniques
- exploit_other: Test other vulnerabilities (XXE, SSRF, LFI, etc.)
- browser: Take screenshots, interact with page
- validate: Confirm vulnerability with vision model

IMPORTANT RULES:
1. Always reference your previous findings when making decisions
2. If a payload was blocked, try evasion techniques
3. Document your reasoning before each action
4. Validate findings before reporting them
5. Be systematic - don't repeat failed attempts

Current session started: {self.created_at.isoformat()}
"""
        }
        self.messages.append(system_message)
    
    def add_message(self, role: str, content: str) -> None:
        """
        Add a message to the conversation.
        
        Args:
            role: "user", "assistant", or "system"
            content: Message content
        """
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        }
        self.messages.append(message)
        self.last_activity = datetime.now()
        
        # Check if we need to summarize
        if len(self.messages) > self.MAX_MESSAGES:
            self._summarize_history()
        
        logger.debug(f"[{self.thread_id}] Added {role} message ({len(content)} chars)")
    
    def add_tool_result(self, tool_name: str, result: Any, success: bool = True) -> None:
        """
        Add a tool execution result to the conversation.
        
        Args:
            tool_name: Name of the tool executed
            result: Result data (will be JSON serialized)
            success: Whether the tool succeeded
        """
        # Format result for LLM consumption
        if isinstance(result, dict):
            result_str = json.dumps(result, indent=2, default=str)
        else:
            result_str = str(result)
        
        # Truncate if too long
        if len(result_str) > 2000:
            result_str = result_str[:2000] + "\n... [truncated]"
        
        message = {
            "role": "tool",
            "name": tool_name,
            "content": result_str,
            "success": success,
            "timestamp": datetime.now().isoformat()
        }
        self.messages.append(message)
        self.last_activity = datetime.now()
        
        logger.debug(f"[{self.thread_id}] Added tool result: {tool_name} (success={success})")
    
    def get_messages(self, format_for_api: bool = True) -> List[Dict]:
        """
        Get all messages in the thread.
        
        Args:
            format_for_api: If True, format for OpenRouter API (role/content only)
        
        Returns:
            List of messages
        """
        if format_for_api:
            # Convert to OpenRouter format
            api_messages = []
            for msg in self.messages:
                if msg["role"] == "tool":
                    # Format tool results as assistant messages
                    api_messages.append({
                        "role": "assistant",
                        "content": f"[Tool: {msg['name']}]\n{msg['content']}"
                    })
                else:
                    api_messages.append({
                        "role": msg["role"],
                        "content": msg["content"]
                    })
            return api_messages
        return self.messages
    
    def update_metadata(self, key: str, value: Any) -> None:
        """Update thread metadata."""
        self.metadata[key] = value
        logger.debug(f"[{self.thread_id}] Updated metadata: {key}")
    
    def add_to_metadata_list(self, key: str, value: Any) -> None:
        """Add item to a metadata list (e.g., inputs_found)."""
        if key not in self.metadata:
            self.metadata[key] = []
        if value not in self.metadata[key]:
            self.metadata[key].append(value)
    
    def record_payload_attempt(self, vuln_type: str, payload: str, success: bool) -> None:
        """
        Record a payload attempt for tracking.
        
        Args:
            vuln_type: Type of vulnerability (XSS, SQLi, etc.)
            payload: The payload tested
            success: Whether it worked
        """
        if vuln_type not in self.metadata["payloads_tried"]:
            self.metadata["payloads_tried"][vuln_type] = []
        
        self.metadata["payloads_tried"][vuln_type].append({
            "payload": payload,
            "success": success,
            "timestamp": datetime.now().isoformat()
        })
        
        if not success:
            self.metadata["payloads_blocked"].append(payload)
    
    def get_context_summary(self) -> str:
        """
        Get a summary of current context for prompts.
        
        Returns:
            Formatted context string
        """
        summary = f"""
## Current Context for {self.target_url}

**Tech Stack**: {', '.join(self.metadata.get('tech_stack', ['Unknown']))}
**WAF Detected**: {self.metadata.get('waf_detected', 'None')}
**Inputs Found**: {len(self.metadata.get('inputs_found', []))}
**Vulnerabilities Found**: {len(self.metadata.get('vulnerabilities_found', []))}
**Payloads Tried**: {sum(len(v) for v in self.metadata.get('payloads_tried', {}).values())}
**Blocked Payloads**: {len(self.metadata.get('payloads_blocked', []))}

**Last Activity**: {self.last_activity.isoformat()}
"""
        return summary.strip()
    
    def _summarize_history(self) -> None:
        """
        Summarize old messages to stay within context limits.
        Keeps system message and last N messages, summarizes the rest.
        """
        if len(self.messages) <= self.MAX_MESSAGES:
            return
        
        logger.info(f"[{self.thread_id}] Summarizing history ({len(self.messages)} messages)")
        
        # Keep system message (first) and last 20 messages
        system_msg = self.messages[0] if self.messages[0]["role"] == "system" else None
        recent_msgs = self.messages[-20:]
        old_msgs = self.messages[1:-20] if system_msg else self.messages[:-20]
        
        # Create summary of old messages
        summary_parts = []
        for msg in old_msgs:
            if msg["role"] == "assistant":
                # Extract key decisions
                content = msg.get("content", "")[:200]
                summary_parts.append(f"- Assistant: {content}...")
            elif msg["role"] == "tool":
                summary_parts.append(f"- Tool {msg.get('name', 'unknown')}: {'✓' if msg.get('success') else '✗'}")
        
        summary_content = f"""[CONVERSATION SUMMARY - {len(old_msgs)} messages summarized]

Key actions taken:
{chr(10).join(summary_parts[:15])}
{'...' if len(summary_parts) > 15 else ''}

Continue from here with the recent context below.
"""
        
        summary_msg = {
            "role": "system",
            "content": summary_content,
            "timestamp": datetime.now().isoformat()
        }
        
        # Rebuild messages list
        new_messages = []
        if system_msg:
            new_messages.append(system_msg)
        new_messages.append(summary_msg)
        new_messages.extend(recent_msgs)
        
        self.messages = new_messages
        logger.info(f"[{self.thread_id}] History summarized: {len(self.messages)} messages remaining")
    
    def to_dict(self) -> Dict:
        """Serialize thread for persistence."""
        return {
            "thread_id": self.thread_id,
            "target_url": self.target_url,
            "messages": self.messages,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ConversationThread":
        """Deserialize thread from persistence."""
        thread = cls(data["target_url"], data["thread_id"])
        thread.messages = data["messages"]
        thread.metadata = data["metadata"]
        thread.created_at = datetime.fromisoformat(data["created_at"])
        thread.last_activity = datetime.fromisoformat(data["last_activity"])
        return thread
    
    def save(self, directory: Optional[Path] = None) -> Path:
        """
        Save thread to disk.
        
        Args:
            directory: Directory to save to (defaults to logs/)
        
        Returns:
            Path to saved file
        """
        save_dir = directory or settings.LOG_DIR
        save_dir = Path(save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        
        filepath = save_dir / f"{self.thread_id}.json"
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        
        logger.info(f"[{self.thread_id}] Saved to {filepath}")
        return filepath
    
    @classmethod
    def load(cls, filepath: Path) -> "ConversationThread":
        """Load thread from disk."""
        with open(filepath) as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def __repr__(self) -> str:
        return f"ConversationThread(id={self.thread_id}, messages={len(self.messages)}, target={self.target_url})"
