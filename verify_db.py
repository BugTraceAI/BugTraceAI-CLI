import sys
import sqlite3

try:
    conn = sqlite3.connect('bugtrace.db')
    cursor = conn.cursor()
    # Try singular table name first
    try:
        cursor.execute("SELECT id, type, parameter, status, visual_validated FROM finding")
    except sqlite3.OperationalError:
        # Fallback to plural if that failed
        cursor.execute("SELECT id, type, parameter, status, visual_validated FROM findings")
        
    rows = cursor.fetchall()
    
    print(f"\n{'ID':<5} | {'Type':<10} | {'Param':<15} | {'Status':<25} | {'VisValid':<10}")
    print("-" * 80)
    
    count = 0
    for row in rows:
        count += 1
        # Convert None to string for safe printing
        r = [str(x) if x is not None else 'None' for x in row]
        print(f"{r[0]:<5} | {r[1]:<10} | {r[2]:<15} | {r[3]:<25} | {r[4]:<10}")
        
    print(f"\nTotal Findings: {count}")
    conn.close()
        
except Exception as e:
    print(f"Error accessing DB: {e}")
