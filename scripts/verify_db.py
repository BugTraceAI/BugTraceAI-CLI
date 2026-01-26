import lancedb
from pathlib import Path
import pyarrow as pa

def verify():
    db_path = Path("bugtrace/logs/lancedb")
    if not db_path.exists():
        print("DB Path not found")
        return

    db = lancedb.connect(str(db_path))
    try:
        tbl = db.open_table("observations")
        arrow_tbl = tbl.to_arrow()
        print(f"Table 'observations' has {len(arrow_tbl)} rows.")
        # print(arrow_tbl)
    except Exception as e:
        print(f"Failed to read table: {e}")

if __name__ == "__main__":
    verify()
