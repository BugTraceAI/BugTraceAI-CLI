# Database Persistence & Deduplication System

## 🎯 Overview

BugtraceAI-CLI now implements **complete database persistence** with:
- ✅ Individual URL scan storage
- ✅ Automatic deduplication
- ✅ Historical context for LLM
- ✅ Vector store ready for embeddings
- ✅ Normalized vulnerability types

## 📊 Architecture

```
URLMasterAgent.run()
    │
    ├─ 1. DEDUPLICATION CHECK
    │   └─ db.get_findings_for_target(url)
    │      ├─ Found historical findings? 
    │      │   └─ Add to thread metadata for LLM context
    │      └─ Optional: Skip if recently scanned
    │
    ├─ 2. EXECUTE SKILLS
    │   └─ Accumulate findings in self.findings
    │
    └─ 3. PERSIST RESULTS
        ├─ Save URL report (markdown/json/html)
        ├─ db.save_scan_result(url, findings)  ← NEW
        └─ Check historical findings count
```

## 🗄️ Database Schema

### SQL Tables (SQLite)

```sql
-- Targets (distinct URLs)
CREATE TABLE target (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    created_at TIMESTAMP
);

-- Scans (each execution)
CREATE TABLE scan (
    id INTEGER PRIMARY KEY,
    target_id INTEGER REFERENCES target(id),
    timestamp TIMESTAMP,
    status TEXT  -- 'COMPLETED', 'FAILED', etc.
);

-- Findings (individual vulnerabilities)
CREATE TABLE finding (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER REFERENCES scan(id),
    type TEXT,  -- 'SQLI', 'XSS', etc. (normalized)
    severity TEXT,  -- 'CRITICAL', 'HIGH', etc.
    details TEXT,
    payload_used TEXT,
    confidence_score FLOAT,
    visual_validated BOOLEAN,
    attack_url TEXT,
    vuln_parameter TEXT
);
```

### Vector Store (LanceDB)

```
data/lancedb/
└── findings_embeddings/
    ├── finding_id
    ├── type
    ├── url
    ├── parameter
    ├── payload (truncated)
    ├── vector (768d embedding)
    └── timestamp
```

## 🔧 Implementation Details

### 1. Vulnerability Type Normalization

**Problem**: Skills were saving "SQLi", "SQL Injection", "XSS", etc. with inconsistent casing.

**Solution**: `normalize_vuln_type()` function in `schemas/models.py`

```python
from bugtrace.schemas.models import normalize_vuln_type, VulnType

# All variants map to canonical enum
normalize_vuln_type("SQLi")           → VulnType.SQLI
normalize_vuln_type("SQL Injection")  → VulnType.SQLI
normalize_vuln_type("sql")            → VulnType.SQLI

# Applied automatically in save_scan_result()
vuln_type = normalize_vuln_type(finding_data.get("type"))
```

**Supported mappings**:
- SQLi, SQL Injection, SQLINJECTION → `SQLI`
- XSS, Cross-Site Scripting → `XSS`
- RCE, Remote Code Execution → `RCE`
- SSTI, CSTI, Template Injection → `CSTI`
- etc.

### 2. URLMasterAgent Persistence

**Location**: `bugtrace/agents/url_master.py:_generate_summary()`

#### A. Deduplication (Start of scan)

```python
async def run(self):
    # Check if URL was scanned before
    db = get_db_manager()
    historical_findings = db.get_findings_for_target(self.url)
    scan_count = db.get_scan_count(self.url)
    
    if historical_findings:
        logger.info(f"Found {scan_count} previous scans, {len(historical_findings)} findings")
        
        # Add to LLM context
        self.thread.update_metadata("previous_scans", scan_count)
        self.thread.update_metadata("known_vulnerabilities", [
            {
                "type": f.get("type"),
                "parameter": f.get("parameter"),
                "severity": f.get("severity")
            } for f in historical_findings[:10]
        ])
```

#### B. Persistence (End of scan)

```python
def _generate_summary(self):
    summary = {...}
    
    # Generate file reports
    url_reporter.create_url_report(...)
    
    # NEW: Save to database
    if self.findings:
        db = get_db_manager()
        scan_id = db.save_scan_result(
            target_url=self.url,
            findings=self.findings  # Automatically normalized
        )
        
        logger.info(f"Saved {len(self.findings)} findings (scan_id: {scan_id})")
        summary['db_scan_id'] = scan_id
    
    return summary
```

### 3. DatabaseManager Methods

#### save_scan_result()
```python
db.save_scan_result(target_url, findings)
```
- Creates/retrieves Target record
- Creates Scan record (timestamp, status)
- Normalizes and saves all Findings
- Returns scan_id

#### get_findings_for_target()
```python
historical = db.get_findings_for_target(url)
```
- Returns list of all findings across all scans for that URL
- Includes: type, severity, payload, parameter, scan_date
- Used for deduplication and context

#### get_scan_count()
```python
count = db.get_scan_count(url)
```
- Returns number of times URL was scanned
- Helpful for deciding if re-scan is needed

#### store_finding_embedding() [Future]
```python
db.store_finding_embedding(finding, embedding_vector)
```
- Stores finding with vector embedding in LanceDB
- Enables semantic similarity search
- **Note**: Requires embedding model integration

## 📈 Benefits

### 1. No Duplicate Work
```
First scan of http://example.com?id=1
  → Finds SQLi in 'id' parameter
  → Saves to DB

Second scan (same URL)
  → Checks DB first
  → Sees previous SQLi finding
  → LLM knows: "Already found SQLi in 'id', try other params"
  → Skips redundant testing
```

### 2. Historical Context for LLM

Thread metadata now includes:
```json
{
  "previous_scans": 3,
  "known_vulnerabilities": [
    {"type": "SQLI", "parameter": "id", "severity": "HIGH"},
    {"type": "XSS", "parameter": "search", "severity": "MEDIUM"}
  ]
}
```

LLM can make smarter decisions:
- "This parameter was already tested for SQLi"
- "Focus on new injection points"
- "Previous scan found XSS, try advanced bypasses"

### 3. Cross-Scan Intelligence

```python
# Scan 1: Find vulnerabilities
scan1_findings = [...] # SQLi, XSS

# Scan 2: Query historical data
historical = db.get_findings_for_target(url)
# → Knows what was found in Scan 1
# → Avoids re-testing same things
# → Focuses on what changed
```

### 4. Reporting & Analytics

```sql
-- All findings for a target
SELECT * FROM finding
JOIN scan ON finding.scan_id = scan.id
JOIN target ON scan.target_id = target.id
WHERE target.url = 'http://example.com';

-- Vulnerability trends over time
SELECT type, COUNT(*), AVG(confidence_score)
FROM finding
GROUP BY type;

-- Most vulnerable targets
SELECT target.url, COUNT(finding.id) as vuln_count
FROM target
JOIN scan ON target.id = scan.target_id
JOIN finding ON scan.id = finding.scan_id
GROUP BY target.url
ORDER BY vuln_count DESC;
```

## 🔄 Data Flow

```
1. TeamOrchestrator spawns URLMasterAgent for each URL

2. URLMasterAgent.run()
   ├─ DEDUPLICATION
   │   └─ Query: db.get_findings_for_target(url)
   │       └─ Add historical context to thread
   │
   ├─ EXECUTE SKILLS
   │   └─ Find new vulnerabilities
   │
   └─ PERSIST
       ├─ File: url_reports/{hash}/
       │   ├─ analysis_dast_sast.md
       │   ├─ vulnerabilities.md
       │   └─ vulnerabilities.json
       │
       └─ Database: db.save_scan_result()
           └─ Normalizes types & saves

3. TeamOrchestrator (optional second save)
   └─ Aggregates all findings
   └─ db.save_scan_result(target, all_findings)
```

## 🚀 Usage Examples

### Check if URL was scanned

```python
from bugtrace.core.database import get_db_manager

db = get_db_manager()
findings = db.get_findings_for_target("http://example.com?id=1")

if findings:
    print(f"Found {len(findings)} previous findings:")
    for f in findings:
        print(f"  - {f['type']} in {f['parameter']} ({f['severity']})")
else:
    print("No previous scans for this URL")
```

### Save scan results manually

```python
findings = [
    {
        "type": "SQL Injection",  # Will be normalized to SQLI
        "severity": "HIGH",
        "payload": "1' OR '1'='1",
        "parameter": "id",
        "url": "http://example.com?id=1",
        "confidence": 0.95,
        "conductor_validated": True
    }
]

scan_id = db.save_scan_result("http://example.com", findings)
print(f"Saved with scan_id: {scan_id}")
```

### Query vulnerability statistics

```python
# Get all SQLi findings
from bugtrace.core.database import get_db_manager
from sqlmodel import Session, select
from bugtrace.schemas.db_models import FindingTable, VulnType

db = get_db_manager()
with db.get_session() as session:
    statement = select(FindingTable).where(FindingTable.type == VulnType.SQLI)
    sqli_findings = session.exec(statement).all()
    
    print(f"Total SQLi findings: {len(sqli_findings)}")
```

## ⚠️ Important Notes

### Enum Consistency
**ALWAYS use normalized types**. The database schema uses strict enums:
- ✅ `SQLI` (correct)
- ❌ `SQLi` (will cause errors on read)

Normalization happens automatically in `save_scan_result()`, but if manually inserting:
```python
from bugtrace.schemas.models import normalize_vuln_type
vuln_type = normalize_vuln_type("SQL Injection")  # → VulnType.SQLI
```

### Vector Store (Future Enhancement)

The vector store methods are **ready but not fully integrated**:
- `store_finding_embedding()` - Stores finding with embedding
- `search_similar_findings()` - Semantic search (not implemented yet)

**To complete**:
1. Add embedding model (e.g., sentence-transformers)
2. Generate embeddings for findings
3. Implement similarity search in `search_similar_findings()`

### Thread Safety

DatabaseManager uses connection pooling. Safe for concurrent URLMasterAgents.

## 📋 Verification

Check database contents:

```bash
# Shell
cd /home/ubuntu/Dev/Projects/Bugtraceai-CLI

# Python script
python3 -c "
from bugtrace.core.database import get_db_manager
db = get_db_manager()

# Count records
from sqlmodel import Session, select, text
with db.get_session() as s:
    targets = s.exec(text('SELECT COUNT(*) FROM target')).one()
    scans = s.exec(text('SELECT COUNT(*) FROM scan')).one()
    findings = s.exec(text('SELECT COUNT(*) FROM finding')).one()
    print(f'Targets: {targets}, Scans: {scans}, Findings: {findings}')
"
```

## 🎯 Summary

| Feature | Status | Details |
|---------|--------|---------|
| SQL Database | ✅ Complete | SQLite with 3 tables |
| Individual URL Saves | ✅ Complete | Each URLMasterAgent persists |
| Deduplication | ✅ Complete | Historical query before scan |
| Type Normalization | ✅ Complete | Auto-normalize to enum |
| LLM Context | ✅ Complete | Historical findings in thread |
| Vector Store | ⚠️ Partial | Structure ready, needs embeddings |
| Similarity Search | ❌ Future | Needs embedding model integration |

---

**Author**: BugtraceAI-CLI Team  
**Version**: 2.0.1  
**Last Updated**: 2026-01-05
