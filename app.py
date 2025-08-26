from flask import Flask, request, jsonify
import sqlite3
import os
import csv
from threading import Lock

app = Flask(__name__)

DB_FILE = "codes.db"
CSV_FILE = "codes.csv"
lock = Lock()  # prevent race conditions

# Initialize DB and import CSV if needed
def init_db():
    db_exists = os.path.exists(DB_FILE)
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT
            )
        """)
        conn.commit()

        # If DB didn't exist before, import CSV
        if not db_exists and os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                for row in reader:
                    code = row["Code"].strip()
                    used = row.get("Used", "No").strip()
                    buyer = row.get("BuyerName", "").strip()
                    cursor.execute("""
                        INSERT OR IGNORE INTO codes (Code, Used, BuyerName)
                        VALUES (?, ?, ?)
                    """, (code, used, buyer))
            conn.commit()

# Validate code endpoint
@app.route("/validate", methods=["POST"])
def validate():
    try:
        data = request.json
        if not data:
            return jsonify({"valid": False, "reason": "invalid_json"}), 400

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
    except Exception as e:
        print("Error:", e)
        return jsonify({"valid": False, "reason": "server_error"}), 500

@app.route("/")
def home():
    return "Access Code Validator is running 🚀"

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
