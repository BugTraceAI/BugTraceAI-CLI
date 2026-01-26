import sqlite3
import os

db_path = "/home/ubuntu/Dev/Projects/BugTraceAI/BugTraceAI-CLI/bugtrace.db"
conn = sqlite3.connect(db_path)
curr = conn.cursor()

print("SSRF Findings in Scan 8:")
curr.execute("SELECT id, type, status, attack_url, payload_used, details FROM finding WHERE scan_id=8 AND type='SSRF'")
rows = curr.fetchall()
for row in rows:
    print(row)

conn.close()
