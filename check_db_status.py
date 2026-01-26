import sqlite3

def check_db():
    try:
        conn = sqlite3.connect('bugtrace.db')
        cursor = conn.cursor()
        
        # List tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables: {tables}")
        
        # Count rows in each table
        for table in tables:
            t_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {t_name}")
            count = cursor.fetchone()[0]
            print(f"Table {t_name}: {count} rows")
            
            # If it's finding table, show some data
            if t_name == 'finding':
                # Fetch recent findings
                cursor.execute("SELECT id, scan_id, type, severity, status, attack_url FROM finding ORDER BY id DESC LIMIT 10")
                rows = cursor.fetchall()
                print("\nRecent Findings:")
                for row in rows:
                    print(f"  {row}")
                    
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_db()
