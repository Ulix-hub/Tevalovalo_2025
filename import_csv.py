import csv
import sqlite3

DB_FILE = "codes.db"
CSV_FILE = "codes.csv"

with sqlite3.connect(DB_FILE) as conn:
    cursor = conn.cursor()
    with open(CSV_FILE, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            cursor.execute(
                "INSERT OR IGNORE INTO codes (Code, Used, BuyerName) VALUES (?, ?, ?)",
                (row["Code"].strip(), row.get("Used", "No").strip(), row.get("BuyerName", "").strip())
            )
    conn.commit()
    print("CSV import completed ✅")
