from flask import Flask, request, jsonify
import sqlite3
import os
from threading import Lock

app = Flask(__name__)
DB_FILE = "codes.db"
lock = Lock()  # Prevent race conditions

# Initialize DB if not exists
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

# Validate code
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

@app.route("/")
def home():
    return "Access Code Validator is running 🚀"

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
