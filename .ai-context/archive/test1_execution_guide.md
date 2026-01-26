# Test 1 Execution Guide - testphp.vulnweb.com
## Baseline vs Validated Scan Comparison | 2026-01-01

---

## 🎯 OBJECTIVE

Compare BugtraceAI performance with and without Conductor V2 validation against a simple, well-documented vulnerable target.

**Target**: http://testphp.vulnweb.com/  
**Duration**: ~15 minutes  
**Expected Outcome**: Demonstrate FP reduction with minimal overhead

---

## 📋 PRE-TEST CHECKLIST

### 1. Verify Target Accessibility
```bash
# Test target is reachable
curl -I http://testphp.vulnweb.com/

# Expected: HTTP/1.1 200 OK
# If 404 or timeout, target may be down - wait or use alternative
```

### 2. Verify System Status
```bash
# Check BugtraceAI imports
cd /home/ubuntu/Dev/Projects/Bugtraceai-CLI
python3 -c "from bugtrace.core.conductor import conductor; print('Conductor V2: OK')"

# Expected: "Conductor V2: OK"
```

### 3. Clean Previous State
```bash
# Clear old logs and reports (optional)
rm -rf logs/execution_*.log
rm -rf reports/report_http_testphp*

# Reset conductor stats (restart ensures clean state)
# This happens automatically on import
```

---

## 🔬 PART 1: BASELINE SCAN (No Validation)

### Goal
Measure performance WITHOUT Conductor V2 validation to establish baseline FP rate.

### Step 1.1: Disable Validation (Temporary)

**Option A**: Environment Variable (Recommended)
```bash
export BUGTRACE_DISABLE_VALIDATION=true
```

**Option B**: Code Modification (if env var not supported)
```python
# In bugtrace/agents/exploit.py and skeptic.py
# Comment out validation calls (TEMPORARY):

# is_valid, reason = conductor.validate_finding(finding_data)
# if not is_valid:
#     logger.warning(f"Finding BLOCKED: {reason}")
#     return

# Replace with direct emit:
await self.event_bus.emit("vulnerability_detected", finding_data)
```

### Step 1.2: Run Baseline Scan
```bash
# Start scan
python -m bugtrace scan http://testphp.vulnweb.com/ \
  --mode offensive \
  --safe-mode false

# Scan will run for ~5-8 minutes
```

### Step 1.3: Monitor Progress
```bash
# In another terminal, tail logs
tail -f logs/execution_*.log | grep -E "(EVENT|Finding|BLOCKED)"
```

### Step 1.4: Collect Baseline Results

**After scan completes, record**:

```bash
# Count total findings
grep -c "vulnerability_detected" logs/execution_*.log

# Count by type
grep "vulnerability_detected.*SQLi" logs/execution_*.log | wc -l
grep "vulnerability_detected.*XSS" logs/execution_*.log | wc -l

# View all findings
grep "vulnerability_detected" logs/execution_*.log > baseline_findings.log
```

**Manual Classification** (Use Ground Truth):
```
Ground Truth (testphp.vulnweb.com):
✅ SQLi: /listproducts.php?cat=1
✅ SQLi: /artists.php?artist=1  
✅ XSS: /search.php?test=...
✅ File Inclusion: /showimage.php?file=...

Total Expected TP: 4-6 vulnerabilities
```

**Fill this template**:
```yaml
Baseline Results:
  Target: http://testphp.vulnweb.com/
  Duration: ____ minutes
  Total Findings: ____
  
  Classification:
    True Positives:
      - SQLi listproducts.php: [ YES / NO ]
      - SQLi artists.php: [ YES / NO ]
      - XSS search.php: [ YES / NO ]
      - File Inclusion: [ YES / NO ]
      Total TP: ____
    
    False Positives:
      - WAF blocks (403): ____
      - Generic errors (500): ____
      - Other: ____
      Total FP: ____
  
  Metrics:
    FP Rate: ____ % (FP / Total)
    Precision: ____ % (TP / Total)
```

### Step 1.5: Save Baseline Report
```bash
# Save report for comparison
cp reports/report_http_testphp_*/engagement_data.json baseline_report.json

# Save baseline metrics
echo "Baseline Scan - $(date)" > baseline_metrics.txt
grep -E "(Finding|vulnerability_detected)" logs/execution_*.log >> baseline_metrics.txt
```

---

## ✅ PART 2: VALIDATED SCAN (With Conductor V2)

### Goal
Measure performance WITH Conductor V2 validation, compare to baseline.

### Step 2.1: Enable Validation
```bash
# Remove environment variable
unset BUGTRACE_DISABLE_VALIDATION

# OR revert code changes from Step 1.1 Option B
```

### Step 2.2: Clean State
```bash
# Clear logs from baseline scan
rm logs/execution_*.log

# Conductor stats will reset on restart
```

### Step 2.3: Run Validated Scan
```bash
# Start scan (same target, same parameters)
python -m bugtrace scan http://testphp.vulnweb.com/ \
  --mode offensive \
  --safe-mode false

# Scan will run for ~5-8 minutes (similar to baseline)
```

### Step 2.4: Monitor Validation
```bash
# Watch for blocked findings
tail -f logs/execution_*.log | grep -E "(BLOCKED|validation)"

# Expected to see:
# [22:45:01] Finding BLOCKED: ... (reason)
```

### Step 2.5: Collect Validated Results

**After scan completes**:

```bash
# Count total findings
grep -c "vulnerability_detected" logs/execution_*.log

# Count blocked findings
grep -c "Finding BLOCKED" logs/execution_*.log

# Get conductor statistics
python3 -c "
from bugtrace.core.conductor import conductor
stats = conductor.get_statistics()
print('Validations Run:', stats['validations_run'])
print('Passed:', stats['findings_passed'])
print('Blocked:', stats['findings_blocked'])
print('FP Blocks by Pattern:', stats['fp_blocks_by_pattern'])
"
```

**Fill this template**:
```yaml
Validated Results:
  Target: http://testphp.vulnweb.com/
  Duration: ____ minutes
  Total Findings: ____
  
  Validation Stats:
    Validations Run: ____
    Passed: ____
    Blocked: ____
    
  Classification:
    True Positives:
      - SQLi listproducts.php: [ YES / NO ]
      - SQLi artists.php: [ YES / NO ]
      - XSS search.php: [ YES / NO ]
      - File Inclusion: [ YES / NO ]
      Total TP: ____
    
    False Positives:
      - (Should be minimal): ____
      Total FP: ____
  
  Blocked Findings (Review manually):
    - ____ findings blocked
    - Reasons: _______________
    - Were they valid blocks? [ YES / NO ]
  
  Metrics:
    FP Rate: ____ % (FP / Total)
    Precision: ____ % (TP / Total)
    Validation Overhead: ____ % ((Validated_Duration - Baseline_Duration) / Baseline_Duration * 100)
```

### Step 2.6: Review Blocked Findings
```bash
# Extract all blocked findings
grep "Finding BLOCKED" logs/execution_*.log > blocked_findings.log

# Manual review: Were these correct blocks?
cat blocked_findings.log

# For each blocked finding, verify:
# 1. Was it a real vulnerability? (FN - bad!)
# 2. Was it a false positive? (Correct block - good!)
```

---

## 📊 PART 3: COMPARISON & ANALYSIS

### Step 3.1: Create Comparison Table

**Template**:
```markdown
| Metric                  | Baseline | Validated | Change    | Target  | Pass/Fail |
|-------------------------|----------|-----------|-----------|---------|-----------|
| Total Findings          | ____     | ____      | ____ %    | N/A     | N/A       |
| True Positives          | ____     | ____      | ____ %    | ≥ TP_base| ____      |
| False Positives         | ____     | ____      | ____ %    | < FP_base| ____      |
| FP Rate                 | ____ %   | ____ %    | ____ pp   | < 10%   | ____      |
| Precision               | ____ %   | ____ %    | ____ pp   | ≥ 90%   | ____      |
| Scan Duration           | ____ min | ____ min  | + ____ %  | < +20%  | ____      |
| Validation Overhead     | N/A      | ____ ms   | N/A       | < 50ms  | ____      |
```

### Step 3.2: Calculate Metrics

```python
# Example calculation:
TP_base = 5  # True positives in baseline
FP_base = 10  # False positives in baseline
Total_base = TP_base + FP_base

TP_val = 5  # True positives in validated
FP_val = 2  # False positives in validated  
Total_val = TP_val + FP_val

# Metrics
FP_Rate_base = (FP_base / Total_base) * 100  # = 66.7%
FP_Rate_val = (FP_val / Total_val) * 100     # = 28.6%

Precision_base = (TP_base / Total_base) * 100  # = 33.3%
Precision_val = (TP_val / Total_val) * 100     # = 71.4%

Improvement_FP = ((FP_base - FP_val) / FP_base) * 100  # = 80% reduction
Improvement_Precision = ((Precision_val - Precision_base) / Precision_base) * 100  # = 114% increase
```

### Step 3.3: Success Criteria Check

```yaml
Critical Criteria (Must Pass):
  ✅ FP Rate < 10%: [ PASS / FAIL ]
  ✅ Precision ≥ 90%: [ PASS / FAIL ]
  ✅ No False Negatives (TP_val ≥ TP_base): [ PASS / FAIL ]
  ✅ Validation Overhead < 20%: [ PASS / FAIL ]

Important Criteria (Should Pass):
  ✅ FP reduction ≥ 50%: [ PASS / FAIL ]
  ✅ Precision improvement ≥ 20pp: [ PASS / FAIL ]

Overall Test 1 Result: [ PASS / FAIL ]
```

---

## 📋 DELIVERABLES

### 1. Results Summary (`test1_results.md`)
```markdown
# Test 1 Results - testphp.vulnweb.com

## Executive Summary
- Target: http://testphp.vulnweb.com/
- Date: 2026-01-01
- Baseline FP Rate: ____ %
- Validated FP Rate: ____ %
- **FP Reduction: ____ %** 🎯

## Detailed Results
[Comparison table from Step 3.1]

## Key Findings
1. Validation correctly blocked ____ false positives
2. All ____ true positives retained (no false negatives)
3. Validation overhead: ____ ms average
4. Most common FP pattern blocked: ________

## Conclusion
[ PASS / FAIL ] - Conductor V2 validation [ EFFECTIVE / INEFFECTIVE ]
```

### 2. Raw Data Files
- `baseline_findings.log` - All baseline detections
- `validated_findings.log` - All validated detections
- `blocked_findings.log` - All blocked findings with reasons
- `conductor_stats.json` - Conductor V2 statistics

### 3. Comparison Charts (Optional)
```bash
# Generate simple visualization
python3 << EOF
import matplotlib.pyplot as plt

metrics = ['FP Rate', 'Precision']
baseline = [66.7, 33.3]  # Example values
validated = [28.6, 71.4]

x = range(len(metrics))
width = 0.35

fig, ax = plt.subplots()
ax.bar([i - width/2 for i in x], baseline, width, label='Baseline')
ax.bar([i + width/2 for i in x], validated, width, label='Validated')

ax.set_ylabel('Percentage')
ax.set_title('Test 1: Baseline vs Validated')
ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.legend()

plt.savefig('test1_comparison.png')
print('Chart saved: test1_comparison.png')
EOF
```

---

## 🚨 TROUBLESHOOTING

### Issue 1: Target Unavailable
```
Error: curl: (7) Failed to connect to testphp.vulnweb.com
```

**Solution**:
- Wait 5-10 minutes and retry
- Check if site is up: https://www.isitdownrightnow.com/testphp.vulnweb.com.html
- Alternative: Use local DVWA/Juice Shop

### Issue 2: No Findings Detected
```
Scan completed: 0 vulnerabilities found
```

**Solution**:
- Verify ReconAgent discovered inputs
- Check logs for crawling errors
- Ensure safe-mode is disabled
- Try direct URL: `http://testphp.vulnweb.com/listproducts.php?cat=1`

### Issue 3: All Findings Blocked
```
All findings were blocked by validation
```

**Solution**:
- Review blocked_findings.log for reasons
- Check if thresholds too strict (confidence < 0.6)
- Verify evidence was collected (screenshot, error messages)
- May indicate FP detection working TOO well (good problem!)

### Issue 4: Import Errors
```
ModuleNotFoundError: No module named 'bugtrace.core.conductor'
```

**Solution**:
```bash
cd /home/ubuntu/Dev/Projects/Bugtraceai-CLI
python3 -c "import sys; sys.path.insert(0, '.'); from bugtrace.core.conductor import conductor"
```

---

## ⏱️ TIMELINE

```
00:00 - Pre-Test Checklist (5 min)
00:05 - Baseline Scan (8 min)
00:13 - Baseline Analysis (2 min)
00:15 - Validated Scan (8 min)
00:23 - Validated Analysis (2 min)
00:25 - Comparison & Report (5 min)
00:30 - COMPLETE
```

**Total**: ~30 minutes

---

## ✅ READY TO START?

**Final Checklist**:
- [ ] Target accessible (`curl -I http://testphp.vulnweb.com/`)
- [ ] Conductor V2 imported successfully
- [ ] Clean logs/reports directory
- [ ] Templates ready for data collection
- [ ] Time allocated (~30 min)

**Next Step**: Execute Part 1 (Baseline Scan)

---

**Last Updated**: 2026-01-01 22:40  
**Test Status**: Ready for execution  
**Estimated Duration**: 30 minutes
