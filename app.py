import os
import csv
import sqlite3
from flask import Flask, request, jsonify
from threading import Lock

# -------------------------
# Config
# -------------------------
DB_FILE = "codes.db"
CSV_FILE = "codes.csv"

app = Flask(__name__)
lock = Lock()  # Prevent race conditions

# -------------------------
# Initialize Database
# -------------------------
def init_db():
    try:
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

            # Import CSV only if DB is empty
            cursor.execute("SELECT COUNT(*) FROM codes")
            count = cursor.fetchone()[0]

            if count == 0:
                if os.path.exists(CSV_FILE):
                    with open(CSV_FILE, newline="", encoding="utf-8") as file:
                        reader = csv.DictReader(file)
                        for row in reader:
                            cursor.execute(
                                "INSERT OR IGNORE INTO codes (Code, Used, BuyerName) VALUES (?, ?, ?)",
                                (row["Code"].strip(), row["Used"].strip(), row.get("BuyerName", "").strip())
                            )
                    conn.commit()
                    print(f"Imported {CSV_FILE} into database.")
                else:
                    print(f"{CSV_FILE} not found. Skipping import.")
            else:
                print("Database already initialized.")
    except Exception as e:
        print("Error initializing DB:", e)

# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    return "Access Code Validator is running 🚀"

@app.route("/validate", methods=["POST"])
def validate():
    data = request.json
    user_code = data.get("code", "").strip()
    buyer_name = data.get("buyer", "").strip()

    if not user_code:
        return jsonify({"valid": False, "reason": "empty_code"}), 400

    with lock:
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT Used FROM codes WHERE Code = ?", (user_code,))
                row = cursor.fetchone()

                if row:
                    if row[0].lower() == "no":
                        # Mark code as used
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
            print("Error validating code:", e)
            return jsonify({"valid": False, "reason": "server_error"}), 500

# -------------------------
# Run App
# -------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
