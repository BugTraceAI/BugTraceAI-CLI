import sqlite3
import json

conn = sqlite3.connect('bugtrace.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
rows = cursor.fetchall()
print("Tables:", rows)
conn.close()
