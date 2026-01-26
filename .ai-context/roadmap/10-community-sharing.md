# Community & Knowledge Sharing - Feature Tasks (Opt-In Only)

## Feature Overview
Build community features: replay/export system, plugin marketplace, Discord integration.

**Why**: Learn from Decepticon's success with replay system
**Phase**: 5 - Future (Optional Features)
**Duration**: 2 weeks
**Effort**: $15k

**⚠️ CRITICAL PRIVACY WARNING**:
- All sharing features are **OPT-IN ONLY** and **DISABLED BY DEFAULT**
- User must explicitly consent before any data leaves their machine
- Scan exports must be manually anonymized by user before sharing
- **Bug hunters should NEVER share scans of private targets**

---

## 🔵 Replay/Export System (LOCAL ONLY)

### FEATURE-090: Export Scan Results (Local Only)
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P3 (Future)

**Description**: Export scan for user's own backup/analysis (NOT for sharing)

**Implementation**:
```python
# bugtrace/cli/commands/export.py
@click.command()
@click.argument('scan_id')
@click.option('--output', default='scan_export.json')
@click.option('--include-sensitive', is_flag=True, help='Include URLs (default: false)')
def export(scan_id, output, include_sensitive):
    """
    Export scan results to JSON (LOCAL USE ONLY)

    ⚠️  WARNING: By default, this removes target URLs and sensitive data.
    ⚠️  Use --include-sensitive only for your own backup, NEVER share!
    """
    scan = db.get_scan(scan_id)

    if include_sensitive:
        click.confirm(
            "⚠️  You are about to export SENSITIVE data (URLs, targets).\n"
            "   This should ONLY be used for your own backup.\n"
            "   NEVER share this file publicly.\n"
            "   Continue?",
            abort=True
        )
        export_data = scan.to_dict()  # Full export
    else:
        export_data = anonymize_scan(scan)  # Safe for backup

    with open(output, 'w') as f:
        json.dump(export_data, f, indent=2)

    click.echo(f"✅ Scan exported to {output}")

    if not include_sensitive:
        click.echo("ℹ️  Target URLs were removed for privacy (use --include-sensitive for full backup)")

# Usage
./bugtraceai-cli export abc-123 --output my_backup.json
```

**Safety Features**:
- Default: Remove target URLs, domain names, IP addresses
- Require explicit `--include-sensitive` flag for full export
- Confirmation prompt before exporting sensitive data
- Warning messages about privacy

---

### FEATURE-091: Anonymize Scan Data for Sharing
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P3 (Future)

**Description**: Safely anonymize scans for educational/research purposes

**Implementation**:
```python
# bugtrace/export/anonymizer.py
import hashlib
import re

class ScanAnonymizer:
    def anonymize_scan(self, scan):
        """
        Remove all identifying information from scan data.
        Safe for sharing in educational contexts (e.g., blog posts, research).
        """
        return {
            "scan_id": self._hash(scan.id),  # Hash IDs
            "timestamp": scan.started_at.isoformat(),
            "duration_seconds": scan.duration,
            "findings": [
                {
                    "id": self._hash(f.id),
                    "type": f.type,
                    "severity": f.severity,
                    "payload_used": f.payload_used,
                    "reflection_context": f.reflection_context,
                    "confidence_score": f.confidence_score,
                    "visual_validated": f.visual_validated,
                    # ❌ Remove: url, target_url, domain, ip_address
                    # ❌ Remove: attack_url, vuln_parameter (might contain domain)
                    # ❌ Remove: proof screenshots (might show URL)
                }
                for f in scan.findings
            ],
            "agents_run": scan.agents,
            "llm_cost_usd": scan.llm_cost,
            "
_note": "All identifying information removed. Safe for public sharing."
        }

    def _hash(self, value):
        """One-way hash for anonymization"""
        return hashlib.sha256(str(value).encode()).hexdigest()[:16]

# Usage
anonymizer = ScanAnonymizer()
safe_export = anonymizer.anonymize_scan(scan)

with open('blog_post_data.json', 'w') as f:
    json.dump(safe_export, f)
```

**What's Removed**:
- ❌ Target URLs
- ❌ Domain names
- ❌ IP addresses
- ❌ Parameter names (might reveal target)
- ❌ Proof screenshots
- ✅ Keeps: Payloads, vulnerability types, techniques (educational value)

---

### FEATURE-095: Scan Replay (Local Analysis)
**Complexity**: 🔵 MEDIUM (2 days)
**Priority**: P3 (Future)

**Description**: Replay exported scans for local analysis (not for sharing)

**Implementation**:
```python
@click.command()
@click.argument('export_file')
def replay(export_file):
    """
    Replay a previously exported scan (LOCAL ANALYSIS ONLY)

    This is for reviewing your OWN past scans, not for importing
    scans from others (which would be a security risk).
    """
    with open(export_file) as f:
        scan_data = json.load(f)

    # Display scan results in terminal
    console = Console()

    console.print(f"\n[bold]🔍 Scan Replay[/bold]")
    console.print(f"Duration: {scan_data['duration_seconds']:.1f}s")
    console.print(f"Findings: {len(scan_data['findings'])}\n")

    for finding in scan_data['findings']:
        color = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }.get(finding['severity'], "white")

        console.print(f"[{color}]● {finding['type']}[/{color}] - {finding['severity']}")
        console.print(f"  Payload: {finding['payload_used']}")
        console.print(f"  Confidence: {finding['confidence_score']:.2%}\n")

# Usage
./bugtraceai-cli replay my_backup.json
```

---

## 🟠 Plugin Marketplace (LOCAL-FIRST)

### FEATURE-092: Plugin System Architecture
**Complexity**: 🟠 COMPLEX (1 week)
**Priority**: P3 (Future)

**Description**: Local plugin system for custom agents (no remote marketplace initially)

**Implementation**:
```python
# bugtrace/plugins/base.py
from abc import ABC, abstractmethod
from pathlib import Path

class Plugin(ABC):
    """Base class for BugTraceAI plugins"""

    name: str
    version: str
    author: str
    description: str

    @abstractmethod
    def install(self):
        """Install plugin dependencies"""
        pass

    @abstractmethod
    def uninstall(self):
        """Clean up plugin resources"""
        pass

    @abstractmethod
    def get_agent(self):
        """Return agent instance"""
        pass

# Example: Custom fuzzer plugin
class CustomFuzzerPlugin(Plugin):
    name = "advanced-fuzzer"
    version = "1.0.0"
    author = "your-name"
    description = "Custom fuzzing logic for specific vulnerability"

    def install(self):
        # Install dependencies
        subprocess.run(["pip", "install", "-r", "requirements.txt"])

    def get_agent(self):
        return AdvancedFuzzerAgent()

# Plugin loading
class PluginManager:
    def __init__(self):
        self.plugins_dir = Path.home() / ".bugtrace" / "plugins"
        self.plugins = {}

    def load_local_plugins(self):
        """Load plugins from ~/.bugtrace/plugins/"""
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_dir():
                plugin = self._load_plugin(plugin_dir)
                self.plugins[plugin.name] = plugin

    def _load_plugin(self, plugin_dir):
        # Import plugin.py from directory
        spec = importlib.util.spec_from_file_location(
            "plugin",
            plugin_dir / "plugin.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Plugin()

# Usage
pm = PluginManager()
pm.load_local_plugins()

for name, plugin in pm.plugins.items():
    agent = plugin.get_agent()
    await reactor.register_agent(agent)
```

**Plugin Directory Structure**:
```
~/.bugtrace/plugins/
├── advanced-fuzzer/
│   ├── plugin.py         # Main plugin class
│   ├── requirements.txt  # Dependencies
│   ├── README.md         # Documentation
│   └── agent.py          # Agent implementation
└── custom-validator/
    └── ...
```

---

### FEATURE-093: Local Plugin Catalog (No Remote Server)
**Complexity**: 🔵 MEDIUM (3 days)
**Priority**: P4 (Nice-to-have)

**Description**: Browse plugins via **local catalog file** (not remote server)

**Implementation**:
```bash
# List installed plugins (local only)
bugtraceai-cli plugins list

# Install from local directory
bugtraceai-cli plugins install ~/my-custom-plugin/

# Install from GitHub (user manually specifies)
bugtraceai-cli plugins install --git https://github.com/user/bugtrace-plugin-fuzzer

# Remove plugin
bugtraceai-cli plugins remove advanced-fuzzer
```

**No Remote Marketplace Initially**:
- ❌ No phone home to plugin server
- ❌ No automatic plugin discovery
- ✅ User manually installs from local dir or GitHub URL
- ✅ Plugins run in sandboxed environment (future: use Docker)

**Future (Phase 6+)**: Optional community marketplace with:
- User opt-in required
- Plugin signatures/verification
- Sandboxed execution

---

## 🟣 Discord Integration (User Webhooks)

### FEATURE-094: Webhook Notifications
**Complexity**: 🟣 QUICK (1 day)
**Priority**: P2

**Description**: Send notifications to user's own Discord/Slack webhooks

**Implementation**:
```python
# bugtrace/integrations/discord.py
import httpx

async def notify_discord(webhook_url, finding):
    """
    Send finding to user's Discord webhook.
    User provides their own webhook URL - no central BugTraceAI server.
    """
    color = {
        "CRITICAL": 0xff0000,  # Red
        "HIGH": 0xffa500,      # Orange
        "MEDIUM": 0xffff00,    # Yellow
        "LOW": 0x00ff00        # Green
    }.get(finding.severity, 0x808080)

    payload = {
        "content": f"🚨 **{finding.severity}** vulnerability found!",
        "embeds": [{
            "title": f"{finding.type} Vulnerability",
            "description": finding.details,
            "color": color,
            "fields": [
                {"name": "Confidence", "value": f"{finding.confidence_score:.0%}", "inline": True},
                {"name": "Validated", "value": "✅ Yes" if finding.visual_validated else "❌ No", "inline": True},
                {"name": "Payload", "value": f"```{finding.payload_used[:100]}```", "inline": False}
            ],
            "footer": {"text": "BugTraceAI-CLI"}
        }]
    }

    async with httpx.AsyncClient() as client:
        await client.post(webhook_url, json=payload)

# Configuration
[NOTIFICATIONS]
DISCORD_WEBHOOK=https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE
SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR_WEBHOOK_HERE
NOTIFY_ON_CRITICAL=true
NOTIFY_ON_HIGH=true
NOTIFY_ON_MEDIUM=false
```

**Privacy-Safe**:
- ✅ User provides their own webhook URL
- ✅ No central BugTraceAI notification server
- ✅ Notifications go directly to user's Discord/Slack
- ⚠️ User should avoid sending sensitive target URLs in notifications

---

## Summary

**Total Tasks**: 5 (Phase 5 - Future/Optional)
**Estimated Effort**: 2 weeks
**Investment**: ~$15k
**Priority**: P3-P4 (Low priority, future work)

**Privacy Compliance**: ✅ Conditional
- Scan export: Local only by default, requires explicit consent for sensitive data
- Plugin system: Local-first, no remote marketplace initially
- Discord notifications: User's own webhooks, no central server
- ❌ No federated learning
- ❌ No public scan sharing
- ❌ No telemetry

**Key Principles**:
1. **Default: Local Only** - All data stays on machine
2. **Opt-In for Sharing** - Explicit consent required
3. **Anonymization First** - Remove identifying info before any export
4. **User Control** - User decides what to share and when
5. **No Central Servers** - No BugTraceAI servers collecting data

**Recommended Use Cases**:
- ✅ Export for personal backup
- ✅ Anonymized data for blog posts/research
- ✅ Custom plugins for your own workflow
- ✅ Notifications to your own Discord/Slack
- ❌ Sharing scans of private bug bounty targets
- ❌ Public vulnerability database (inappropriate for bug hunters)

**Future (Phase 6+)**:
If there's strong community demand, could add:
- Optional plugin marketplace (opt-in, verified plugins)
- Educational vulnerability database (anonymized data only)
- Research paper dataset (with strict anonymization)

But these are NOT priorities for bug hunters who need privacy-first tools.
