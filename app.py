from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
from threading import Lock
import csv
import random
from datetime import datetime, timedelta
import traceback

app = Flask(__name__)
CORS(app)  # Allow all origins

DB_FILE = "codes.db"
CSV_FILE = "codes.csv"
lock = Lock()  # Prevent race conditions

# ------------------- Database Initialization -------------------
def init_db():
    """Create table and load codes from CSV."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT,
                Expiry TEXT
            )
        """)
        conn.commit()

        # Load codes from CSV into DB
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                for row in reader:
                    code = row["Code"].strip()
                    used = row.get("Used", "No").strip()
                    buyer = row.get("BuyerName", "").strip()
                    expiry = row.get("Expiry")
                    if not expiry:
                        expiry = (datetime.now() + timedelta(days=30)).isoformat()
                    cursor.execute("""
                        INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry)
                        VALUES (?, ?, ?, ?)
                    """, (code, used, buyer, expiry))
            conn.commit()

# ------------------- Access Code Validation -------------------
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
                cursor.execute("SELECT Used, Expiry FROM codes WHERE Code = ?", (user_code,))
                row = cursor.fetchone()

                if row:
                    used, expiry_str = row
                    expiry = datetime.fromisoformat(expiry_str)

                    now = datetime.now()
                    if used.lower() == "yes":
                        return jsonify({"valid": False, "reason": "already_used"})
                    if expiry < now:
                        return jsonify({"valid": False, "reason": "expired"})

                    # Mark code as used and update buyer
                    cursor.execute("""
                        UPDATE codes SET Used = 'Yes', BuyerName = ?, Expiry = ?
                        WHERE Code = ?
                    """, (buyer_name, expiry.isoformat(), user_code))
                    conn.commit()

                    return jsonify({"valid": True, "expiry": expiry.isoformat(), "reason": "success"})
                else:
                    return jsonify({"valid": False, "reason": "not_found"})
    except Exception as e:
        print("Error:", e)
        traceback.print_exc()
        return jsonify({"valid": False, "reason": "server_error"}), 500

# ------------------- Housie90 Ticket Generation -------------------
@app.route("/api/tickets", methods=["GET"])
def generate_tickets():
    try:
        count = int(request.args.get("cards", 1))
    except:
        count = 1

    all_cards = [generate_ticket() for _ in range(count)]
    return jsonify({"cards": all_cards})

def generate_ticket():
    """
    Generate a single Housie90 ticket:
    - 3 rows x 9 columns
    - Each row has exactly 5 numbers
    - Correct column ranges
    """
    ticket = [[0]*9 for _ in range(3)]
    columns = [
        list(range(1,10)), list(range(10,20)), list(range(20,30)),
        list(range(30,40)), list(range(40,50)), list(range(50,60)),
        list(range(60,70)), list(range(70,80)), list(range(80,91))
    ]

    for col in columns:
        random.shuffle(col)

    row_columns = [random.sample(range(9), 5) for _ in range(3)]

    for r in range(3):
        for c in row_columns[r]:
            ticket[r][c] = columns[c].pop()

    return ticket

# ------------------- Home -------------------
@app.route("/")
def home():
    return "Access Code Validator & Housie90 API running 🚀"

# ------------------- Run Server -------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
