import os
import csv
import sqlite3
from threading import Lock
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_FILE = "codes.db"
CSV_FILE = "codes.csv"
lock = Lock()  # Prevent race conditions

# ---------- Database Initialization ----------
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT
            )
        """)
        conn.commit()

# ---------- Import codes from CSV ----------
def import_codes_from_csv():
    if not os.path.exists(CSV_FILE):
        print(f"{CSV_FILE} not found")
        return
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        with open(CSV_FILE, newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                cursor.execute(
                    "INSERT OR IGNORE INTO codes (Code, Used, BuyerName) VALUES (?, ?, ?)",
                    (row["Code"].strip(), row["Used"].strip(), row.get("BuyerName", "").strip())
                )
        conn.commit()
    print(f"Codes imported from {CSV_FILE} ✅")

# ---------- Validate code endpoint ----------
@app.route("/validate", methods=["POST"])
def validate():
    data = request.json
    user_code = data.get("code", "").strip()
    buyer_name = data.get("buyer", "").strip()

    if not user_code:
        return jsonify({"valid": False, "reason": "empty_code"}), 400

    with lock:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT Used FROM codes WHERE Code = ?", (user_code,))
            row = cursor.fetchone()

            if row:
                if row[0].lower() == "no":
                    # Mark as used
                    cursor.execute(
                        "UPDATE codes SET Used = 'Yes', BuyerName = ? WHERE Code = ?",
                        (buyer_name, user_code)
                    )
                    conn.commit()
                    return jsonify({"valid": True, "reason": "success"})
                else:
                    return jsonify({"valid": False, "reason": "already_used"})
            else:
                return jsonify({"valid": False, "reason": "not_found"})

# ---------- Home endpoint ----------
@app.route("/")
def home():
    return "Access Code Validator is running 🚀"

# ---------- App startup ----------
if __name__ == "__main__":
    init_db()
    import_codes_from_csv()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
