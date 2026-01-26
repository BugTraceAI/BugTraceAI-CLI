import sqlite3

def check_scan_8():
    try:
        conn = sqlite3.connect('bugtrace.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, type, severity, status, attack_url, payload_used FROM finding WHERE scan_id = 8")
        rows = cursor.fetchall()
        print(f"Scan 8 Findings ({len(rows)} total):")
        for row in rows:
            print(f"  {row}")
            
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_scan_8()
