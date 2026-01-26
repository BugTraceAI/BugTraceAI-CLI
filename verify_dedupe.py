import os, re
from collections import defaultdict

# Find the latest report directory
report_dirs = [d for d in os.listdir('reports/') if d != '.gitkeep']
if not report_dirs:
    print("❌ No report directory found!")
    exit(1)
    
report_dir = sorted(report_dirs)[-1]
report_path = f'reports/{report_dir}/raw_findings.md'

if not os.path.exists(report_path):
    print(f"❌ {report_path} does not exist!")
    exit(1)

with open(report_path, 'r') as f:
    content = f.read()

findings = []
# Updated regex to be more robust
# Matches lines like: "### 1. XSS on msg"
# Then looks for URL line
for match in re.finditer(r'^### \d+\. (.+?) on (.+?)\n', content, re.MULTILINE):
    vtype, param = match.groups()
    vtype = vtype.strip()
    param = param.strip()
    
    # Try to find URL in subsequent lines
    # This is a bit simplified, assumes URL is close
    start = match.end()
    snippet = content[start:start+500]
    url_match = re.search(r'- \*\*URL:\*\* `(.+?)`', snippet)
    
    if url_match:
        url = url_match.group(1).strip()
        findings.append((vtype, param, url))
    else:
        print(f"⚠️ Could not find URL for {vtype} on {param}")

# Check for duplicates
dupes = defaultdict(list)
for i, f in enumerate(findings, 1):
    dupes[f].append(i)

duplicates = {k: v for k, v in dupes.items() if len(v) > 1}

if duplicates:
    print(f"❌ FAIL: {len(duplicates)} duplicates found")
    for (vtype, param, url), indices in duplicates.items():
        print(f"  {vtype} on '{param}' appeared {len(indices)} times")
else:
    print(f"✅ PASS: No duplicates! {len(findings)} unique findings")
    for f in findings:
        print(f"  - {f}")
