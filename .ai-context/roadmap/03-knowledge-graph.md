# Knowledge Graph & Memory - Feature Tasks (Local-First)

## Feature Overview
Add persistent memory across scans using LanceDB enhancement and optional Neo4j knowledge graph.

**Why**: Learn from previous scans, track entity relationships
**Competitor Gap**: PentAGI (Neo4j graph, multi-layer memory)
**Phase**: 2 - Competitive Parity
**Duration**: 2-3 weeks
**Effort**: $20k

**⚠️ PRIVACY REQUIREMENT**: All memory storage is **100% local**. LanceDB and Neo4j run on bug hunter's machine/VPC.

---

## PHASE A: Lance DB Enhancement (Week 1)

### FEATURE-023: Store Successful Payload Patterns
**Complexity**: 🔵 MEDIUM (3 days)

```python
# bugtrace/memory/payload_store.py
class PayloadMemory:
    def store_success(self, vuln_type, payload, context):
        self.lance_db.insert({
            "type": vuln_type,
            "payload": payload,
            "context": context,  # HTML/JS/attr
            "success_count": 1,
            "embedding": self._embed(payload)
        })

    def retrieve_similar(self, context, limit=5):
        query_vector = self._embed(context)
        return self.lance_db.search(query_vector).limit(limit)
```

### FEATURE-024: Track WAF Bypass Strategies
**Complexity**: 🔵 MEDIUM (2 days)

```python
# bugtrace/memory/waf_memory.py
class WAFBypassMemory:
    def remember_success(self, domain, waf_type, strategy, payload):
        self.lance_db.insert({
            "domain_hash": hashlib.sha256(domain.encode()).hexdigest()[:16],
            "waf_type": waf_type,
            "strategy": strategy,
            "payload_pattern": self._anonymize(payload),
            "timestamp": datetime.utcnow()
        })

    def recall_strategies(self, waf_type):
        # Get best strategies for this WAF
        return self.lance_db.query(
            f"waf_type = '{waf_type}' ORDER BY timestamp DESC LIMIT 10"
        )
```

### FEATURE-025: Remember Authentication Flows
**Complexity**: 🔵 MEDIUM (2 days)

```python
# bugtrace/memory/auth_memory.py
class AuthFlowMemory:
    def store_flow(self, domain, flow_steps, cookies):
        self.lance_db.insert({
            "domain": domain,
            "flow": flow_steps,  # ["GET /login", "POST /auth", "GET /dashboard"]
            "cookie_names": list(cookies.keys()),
            "success": True
        })
```

---

## PHASE B: Neo4j Integration (Weeks 2-3, Optional)

### FEATURE-026: Setup Neo4j Connection
**Complexity**: 🔵 MEDIUM (1 day)

```python
from neo4j import GraphDatabase

class KnowledgeGraph:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
        )

    def create_domain_node(self, domain, tech_stack):
        with self.driver.session() as session:
            session.run("""
                MERGE (d:Domain {name: $domain})
                SET d.technologies = $tech_stack
            """, domain=domain, tech_stack=tech_stack)
```

### FEATURE-027: Map Entity Relationships
**Complexity**: 🟠 COMPLEX (1 week)

```cypher
// Domain has WAF
CREATE (d:Domain {name: "example.com"})-[:HAS_WAF]->(w:WAF {type: "cloudflare"})

// Domain has Vulnerability
CREATE (d)-[:HAS_VULN]->(v:Vulnerability {type: "XSS", severity: "HIGH"})

// Vulnerability exploited by Payload
CREATE (v)-[:EXPLOITED_BY]->(p:Payload {text: "<script>alert(1)</script>"})

// XSS leads to Session Hijack
CREATE (v1:Vulnerability {type: "XSS"})-[:LEADS_TO]->(v2:Vulnerability {type: "SESSION_HIJACK"})
```

### FEATURE-028: Query Attack Chains
**Complexity**: 🔵 MEDIUM (3 days)

```python
def find_attack_chain(self, start_vuln, end_impact):
    query = """
    MATCH path = (start:Vulnerability {type: $start})-[:LEADS_TO*]->(end:Impact {type: $end})
    RETURN path
    ORDER BY length(path) ASC
    LIMIT 5
    """
    return self.driver.session().run(query, start=start_vuln, end=end_impact)
```

### FEATURE-029: Track Parameter Patterns
**Complexity**: 🔵 MEDIUM (2 days)

```cypher
// Parameter naming patterns predict vulnerability types
(p:Parameter {name: "id"})-[:INDICATES]->(v:VulnType {type: "IDOR"})
(p:Parameter {name: "userId"})-[:INDICATES]->(v:VulnType {type: "IDOR"})
(p:Parameter {name: "search"})-[:INDICATES]->(v:VulnType {type: "XSS"})
```

---

## PHASE C: Multi-Scan Memory

### FEATURE-030: "What Worked Last Time?"
**Complexity**: 🔵 MEDIUM (2 days)

```python
# bugtrace/memory/scan_memory.py
async def prepare_scan(self, domain):
    # Recall previous successful strategies
    memory = self.memory_store.recall(domain)

    if memory:
        logger.info(f"Found memory for {domain}")
        logger.info(f"- Best WAF bypass: {memory.waf_bypass_strategy}")
        logger.info(f"- Successful payloads: {len(memory.payloads)}")
        logger.info(f"- Parameter patterns: {memory.param_patterns}")

        # Pre-load successful payloads
        self.agent_config.update({
            "preferred_payloads": memory.payloads,
            "known_waf": memory.waf_type,
            "bypass_strategy": memory.waf_bypass_strategy
        })
```

### FEATURE-031: Cross-Domain Pattern Learning
**Complexity**: 🟠 COMPLEX (1 week)

```python
# Learn patterns across domains
class PatternLearner:
    def learn_parameter_patterns(self):
        # Analyze all scans
        results = self.db.query("""
            SELECT vuln_parameter, type
            FROM findings
            WHERE validated = true
        """)

        # Find patterns
        patterns = {}
        for param, vuln_type in results:
            if param not in patterns:
                patterns[param] = {}
            patterns[param][vuln_type] = patterns[param].get(vuln_type, 0) + 1

        # "id" → 85% IDOR, "search" → 70% XSS
        return patterns
```

### FEATURE-032: ~~Federated Learning~~ ❌ REMOVED (Privacy Violation)

**Status**: ❌ REMOVED - Violates local-first privacy principles

**Why Removed**: Sharing data to community servers (even anonymized) could leak target fingerprints and is inappropriate for bug hunters working on private targets.

**Alternative**: All learning happens locally. No data leaves the machine.

---

## Advanced Features

### FEATURE-033: Semantic Similarity Search
**Complexity**: 🔵 MEDIUM (3 days)

```python
# Find similar vulnerabilities
similar = self.lance_db.search(
    embedding=vuln_embedding,
    query="XSS in search parameter"
).limit(10)
```

### FEATURE-034: Temporal Queries
**Complexity**: 🟣 QUICK (1 day)

```python
# What changed in the last week?
changes = self.knowledge_graph.query("""
    MATCH (d:Domain {name: $domain})-[:HAS_VULN]->(v:Vulnerability)
    WHERE v.discovered_at > datetime() - duration('P7D')
    RETURN v
""")
```

### FEATURE-035: Confidence Scoring from History
**Complexity**: 🔵 MEDIUM (2 days)

```python
# Use historical data to boost confidence
def calculate_confidence(self, finding):
    base_confidence = finding.confidence_score

    # Check if similar finding was validated before
    similar = self.memory_store.find_similar(finding)
    if similar and similar.validated:
        boost = 0.15
    else:
        boost = 0.0

    return min(1.0, base_confidence + boost)
```

### FEATURE-036: Auto-Tuning from Memory
**Complexity**: 🟠 COMPLEX (1 week)

```python
# Automatically adjust thresholds based on history
class AdaptiveConfig:
    def tune_skeptical_thresholds(self):
        # Analyze false positive rate per vuln type
        fp_rates = self.analyze_historical_fps()

        # Adjust thresholds
        for vuln_type, fp_rate in fp_rates.items():
            if fp_rate > 0.3:  # Too many FPs
                self.increase_threshold(vuln_type)
            elif fp_rate < 0.05:  # Very few FPs
                self.decrease_threshold(vuln_type)
```

### FEATURE-037: Memory Cleanup
**Complexity**: 🟣 QUICK (1 day)

```python
# Delete old, unused memories
def cleanup_memory(self):
    # Remove patterns not used in 6 months
    self.lance_db.delete("last_used < date('now', '-6 months')")

    # Archive old graphs
    self.neo4j.query("DETACH DELETE (n) WHERE n.archived = true")
```

---

## Summary

**Total Tasks**: 14 (Federated Learning removed)
- Phase A (LanceDB): 3 tasks, 1 week
- Phase B (Neo4j LOCAL, optional): 4 tasks, 2 weeks
- Phase C (Multi-scan): 2 tasks (local only)
- Advanced: 5 tasks (nice-to-have)

**Estimated Effort**: 2-3 weeks
**Investment**: ~$20k

**Competitive Gap Closed**: PentAGI (Neo4j knowledge graph, multi-layer memory - local)

**Infrastructure** (100% LOCAL):
```yaml
# ~/.bugtrace/docker-compose.yml
services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "127.0.0.1:7474:7474"  # ⚠️ Browser (localhost only)
      - "127.0.0.1:7687:7687"  # ⚠️ Bolt (localhost only)
    environment:
      NEO4J_AUTH: neo4j/bugtrace123
      NEO4J_dbms_memory_heap_max__size: 2G  # Fits in 8GB VPC
    volumes:
      - ~/.bugtrace/neo4j:/data  # Local storage
    restart: unless-stopped

# Cost: $0/month (runs locally)
```

**Resource Usage (8GB VPC)**:
- Neo4j: ~2GB RAM
- LanceDB: Disk-based, minimal RAM (~200MB)
- Total: ~2.2GB ✅

**Privacy Compliance**: ✅ 100% Local
- LanceDB: Local `.lance` files in `~/.bugtrace/lancedb/`
- Neo4j: Local Docker container (localhost only)
- No federated learning (removed)
- No data leaves machine
