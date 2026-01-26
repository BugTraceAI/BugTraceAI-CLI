import sqlite3

conn = sqlite3.connect('bugtrace.db')
cursor = conn.cursor()
cursor.execute("SELECT count(*) FROM finding WHERE scan_id=(SELECT MAX(id) FROM scan)")
print(f"Total Findings: {cursor.fetchone()[0]}")
cursor.execute("SELECT type, severity, status FROM finding WHERE scan_id=(SELECT MAX(id) FROM scan) ORDER BY id DESC LIMIT 5")
print("\nRecent Findings:")
for row in cursor.fetchall():
    print(f"- {row[0]} ({row[1]}): {row[2]}")
conn.close()
