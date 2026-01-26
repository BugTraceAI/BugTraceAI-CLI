import sqlite3
import json

conn = sqlite3.connect('bugtrace.db')
cursor = conn.cursor()
cursor.execute("SELECT id, type, status, severity, validated FROM finding WHERE scan_id=20")
rows = cursor.fetchall()
print(json.dumps(rows, indent=2))
conn.close()
