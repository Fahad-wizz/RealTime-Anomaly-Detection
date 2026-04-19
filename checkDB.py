import sqlite3
from pathlib import Path


for path in [Path("database.db"), Path("database_runtime.db")]:
    print(f"\nInspecting {path} ...")
    if not path.exists():
        print("File does not exist.")
        continue

    try:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cur.fetchall()]
        print("Tables:", tables)

        if "users" in tables:
            cur.execute("SELECT username FROM users")
            print("Users:", [row[0] for row in cur.fetchall()])
        else:
            print("Users table not found.")
        conn.close()
    except Exception as exc:
        print(f"Could not read {path}: {exc}")

print("\nIf the app is using the in-memory SQLite fallback, this script will not show live app data.")
