import sqlite3
import json

conn = sqlite3.connect('bugtrace.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()
cursor.execute("SELECT * FROM finding WHERE scan_id=20 LIMIT 1")
row = cursor.fetchone()
if row:
    print(json.dumps(dict(row), indent=2, default=str))
else:
    print("No findings yet")
conn.close()
