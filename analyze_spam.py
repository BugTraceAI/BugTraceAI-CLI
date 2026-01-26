import sqlite3
from collections import Counter

conn = sqlite3.connect('bugtrace.db')
cursor = conn.cursor()

# Get the problematic scan ID (the latest one)
cursor.execute("SELECT MAX(id) FROM scan")
scan_id = cursor.fetchone()[0]

print(f"Analyzing Scan ID: {scan_id}")

# Count findings by Type
cursor.execute(f"SELECT type, count(*) as count FROM finding WHERE scan_id={scan_id} GROUP BY type ORDER BY count DESC")
print("\n--- Findings by Type ---")
for row in cursor.fetchall():
    print(f"{row[0]}: {row[1]}")

# Count findings by Parameter (to see if one param is spammed)
cursor.execute(f"SELECT vuln_parameter, count(*) as count FROM finding WHERE scan_id={scan_id} GROUP BY vuln_parameter ORDER BY count DESC LIMIT 5")
print("\n--- Top Spammed Parameters ---")
for row in cursor.fetchall():
    print(f"{row[0]}: {row[1]}")

conn.close()
