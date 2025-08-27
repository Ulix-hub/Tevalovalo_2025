import sqlite3
import csv

DB_FILE = "codes.db"
CSV_FILE = "codes.csv"

# Create DB and table
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS codes (
    Code TEXT PRIMARY KEY,
    Used TEXT DEFAULT 'No',
    BuyerName TEXT
)
""")

# Import CSV
with open(CSV_FILE, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        cursor.execute(
            "INSERT OR IGNORE INTO codes (Code, Used, BuyerName) VALUES (?, ?, ?)",
            (row['Code'].strip(), row.get('Used', 'No').strip(), row.get('BuyerName', '').strip())
        )
conn.commit()
conn.close()
