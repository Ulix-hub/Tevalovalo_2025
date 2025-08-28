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

# -------- Strong CORS (works with Netlify) --------
CORS(
    app,
    resources={r"/*": {"origins": "*"}},  # you can restrict to your Netlify origin later
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["Content-Type"],
    max_age=86400,
)

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp

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

        # Load codes from CSV into DB (idempotent)
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                for row in reader:
                    code = (row.get("Code") or "").strip()
                    if not code:
                        continue
                    used = (row.get("Used") or "No").strip()
                    buyer = (row.get("BuyerName") or "").strip()
                    expiry = row.get("Expiry")
                    if not expiry or not expiry.strip():
                        expiry = (datetime.now() + timedelta(days=30)).isoformat()
                    cursor.execute("""
                        INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry)
                        VALUES (?, ?, ?, ?)
                    """, (code, used, buyer, expiry))
            conn.commit()

# ------------------- Health / Fingerprint -------------------
@app.route("/whoami")
def whoami():
    return jsonify({
        "service": os.environ.get("RENDER_SERVICE_NAME", "unknown"),
        "url": os.environ.get("RENDER_EXTERNAL_URL", "n/a"),
        "time": datetime.now().isoformat()
    })

# ------------------- Access Code Validation -------------------
@app.route("/validate", methods=["POST"])
def validate():
    try:
        data = request.get_json(silent=True) or {}
        user_code = (data.get("code") or "").strip()
        buyer_name = (data.get("buyer") or "").strip()

        if not user_code:
            return jsonify({"valid": False, "reason": "empty_code"}), 400

        with lock:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT Used, Expiry FROM codes WHERE Code = ?", (user_code,))
                row = cursor.fetchone()

                if not row:
                    return jsonify({"valid": False, "reason": "not_found"})

                used, expiry_str = row
                # If expiry_str is None or bad, default to +30 days
                try:
                    expiry = datetime.fromisoformat(expiry_str) if expiry_str else (datetime.now() + timedelta(days=30))
                except Exception:
                    expiry = datetime.now() + timedelta(days=30)

                now = datetime.now()
                if str(used).lower() == "yes":
                    return jsonify({"valid": False, "reason": "already_used"})
                if expiry < now:
                    return jsonify({"valid": False, "reason": "expired"})

                # Mark code as used and update buyer (keep same expiry)
                cursor.execute("""
                    UPDATE codes SET Used = 'Yes', BuyerName = ?, Expiry = ?
                    WHERE Code = ?
                """, (buyer_name, expiry.isoformat(), user_code))
                conn.commit()

                return jsonify({"valid": True, "expiry": expiry.isoformat(), "reason": "success"})
    except Exception as e:
        print("Error:", e)
        traceback.print_exc()
        return jsonify({"valid": False, "reason": "server_error"}), 500

# ------------------- Housie90 Ticket Generation -------------------
@app.route("/api/tickets", methods=["GET"])
def generate_tickets():
    try:
        count = int(request.args.get("cards", 1))
    except Exception:
        count = 1

    # Keep a sane limit
    if count < 1:
        count = 1
    elif count > 60:
        count = 60

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

    # choose 5 columns per row
    row_columns = [random.sample(range(9), 5) for _ in range(3)]

    for r in range(3):
        for c in row_columns[r]:
            ticket[r][c] = columns[c].pop()

    # Optional: sort numbers per column (common housie style)
    for c in range(9):
        col_vals = [ticket[r][c] for r in range(3) if ticket[r][c] != 0]
        col_vals.sort()
        i = 0
        for r in range(3):
            if ticket[r][c] != 0:
                ticket[r][c] = col_vals[i]
                i += 1

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
