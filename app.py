from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, os, re, csv, random, traceback
from threading import Lock
from datetime import datetime, timedelta

app = Flask(__name__)

# ---- CORS ----
CORS(
    app,
    resources={r"/*": {"origins": "*"}},  # restrict to your Netlify origin later
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key"],
    expose_headers=["Content-Type"],
    max_age=86400,
)

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Key"
    return resp

# ---- DB / CSV (persistent if you set DB_FILE env, e.g. /var/data/codes.db) ----
DB_FILE = os.environ.get("DB_FILE", "codes.db")
CSV_FILE = os.environ.get("CODES_CSV", "codes.csv")
lock = Lock()

def normalize_code(s: str) -> str:
    """Uppercase, trim, and allow only A-Z 0-9 _ -"""
    s = (s or "").strip().upper()
    return re.sub(r"[^A-Z0-9_-]", "", s)

def init_db():
    """Create table and idempotently load codes from CSV (if present)."""
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT,
                Expiry TEXT
            )
        """)
        conn.commit()

        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    code = normalize_code(row.get("Code"))
                    if not code:
                        continue
                    used = (row.get("Used") or "No").strip()
                    buyer = (row.get("BuyerName") or "").strip()
                    expiry = (row.get("Expiry") or "").strip()
                    if not expiry:
                        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
                    c.execute("""
                        INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry)
                        VALUES (?, ?, ?, ?)
                    """, (code, used, buyer, expiry))
            conn.commit()

# Ensure DB exists on import (works with gunicorn/Render)
init_db()

# ---- Health / info ----
@app.route("/whoami")
def whoami():
    return jsonify({
        "service": os.environ.get("RENDER_SERVICE_NAME", "local"),
        "env": os.environ.get("RENDER_EXTERNAL_URL", "n/a"),
        "version": "v2",
        "time": datetime.utcnow().isoformat() + "Z",
        "db_file": DB_FILE
    })

@app.route("/")
def home():
    return "Access Code Validator & Housie90 API running 🚀"

# ---- VALIDATE (single-use; GET supported for quick tests) ----
@app.route("/validate", methods=["POST", "GET"])
def validate():
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            user_code = normalize_code(data.get("code"))
            buyer_name = (data.get("buyer") or "").strip()
        else:
            user_code = normalize_code(request.args.get("code"))
            buyer_name = (request.args.get("buyer") or "").strip()

        if not user_code:
            return jsonify({"valid": False, "reason": "empty_code"}), 400

        with lock, sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            # Case-insensitive match
            c.execute("SELECT Used, Expiry FROM codes WHERE UPPER(Code)=UPPER(?)", (user_code,))
            row = c.fetchone()
            if not row:
                return jsonify({"valid": False, "reason": "not_found"})
            used, expiry_str = row

            # parse expiry; default +30d
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z","")) if expiry_str else (datetime.utcnow() + timedelta(days=30))
            except Exception:
                expiry = datetime.utcnow() + timedelta(days=30)

            if str(used or "No").strip().lower() == "yes":
                return jsonify({"valid": False, "reason": "already_used"})
            if expiry <= datetime.utcnow():
                return jsonify({"valid": False, "reason": "expired"})

            # mark used on successful validation
            c.execute("""
                UPDATE codes SET Used='Yes', BuyerName=?, Expiry=?
                WHERE UPPER(Code)=UPPER(?)
            """, (buyer_name, expiry.isoformat() + "Z", user_code))
            conn.commit()

        return jsonify({"valid": True, "expiry": expiry.isoformat() + "Z", "reason": "success"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"valid": False, "reason": "server_error"}), 500

# ---- ADMIN (manage codes) ----
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # set to UKE202501 in Render env

def _auth_ok(req):
    return ADMIN_KEY and req.headers.get("X-Admin-Key") == ADMIN_KEY

@app.route("/admin/add_code", methods=["POST"])
def admin_add_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = normalize_code(data.get("code"))
    buyer = (data.get("buyer") or "").strip()
    days = int(data.get("days") or 30)
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO codes (Code, Used, BuyerName, Expiry)
            VALUES (?, 'No', ?, ?)
            ON CONFLICT(Code) DO UPDATE SET Used='No', BuyerName=excluded.BuyerName, Expiry=excluded.Expiry
        """, (code, buyer, expiry))
        conn.commit()
    return jsonify({"ok": True, "code": code, "expiry": expiry})

@app.route("/admin/add_codes_bulk", methods=["POST"])
def admin_add_codes_bulk():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    days = int(data.get("days") or 30)
    buyer = (data.get("buyer") or "Batch").strip()
    codes_list = data.get("codes")
    if not codes_list and data.get("text"):
        codes_list = [line for line in data["text"].splitlines() if line.strip()]
    if not codes_list: return jsonify({"ok": False, "error": "no_codes_provided"}), 400

    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"
    added, normalized = 0, []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for raw in codes_list:
            code = normalize_code(raw)
            if not code: continue
            normalized.append(code)
            c.execute("""
                INSERT INTO codes (Code, Used, BuyerName, Expiry)
                VALUES (?, 'No', ?, ?)
                ON CONFLICT(Code) DO UPDATE SET Used='No', BuyerName=excluded.BuyerName, Expiry=excluded.Expiry
            """, (code, buyer, expiry))
            added += 1
        conn.commit()
    return jsonify({"ok": True, "count": added, "expiry": expiry, "codes": normalized})

@app.route("/admin/reset_code", methods=["POST"])
def admin_reset_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = normalize_code(data.get("code"))
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE codes SET Used='No' WHERE UPPER(Code)=UPPER(?)", (code,))
        if c.rowcount == 0:
            return jsonify({"ok": False, "error": "not_found"}), 404
        conn.commit()
    return jsonify({"ok": True, "code": code, "status": "reset"})

@app.route("/admin/list_codes", methods=["GET"])
def admin_list_codes():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    limit = int(request.args.get("limit", 200))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT Code, Used, BuyerName, Expiry FROM codes ORDER BY Code LIMIT ?", (limit,))
        rows = [{"Code": a, "Used": b, "BuyerName": d, "Expiry": e} for (a,b,d,e) in c.fetchall()]
    return jsonify({"ok": True, "rows": rows, "count": len(rows)})

# ---- Housie90 Tickets ----
@app.route("/api/tickets", methods=["GET"])
def api_tickets():
    try:
        count = int(request.args.get("cards", 1))  # "cards" == strips
    except Exception:
        count = 1
    count = max(1, min(count, 60))

    # Return 6 tickets per "card"/strip to match your UI
    all_tickets = []
    for _ in range(count):
        for __ in range(6):
            all_tickets.append(generate_ticket())
    return jsonify({"cards": all_tickets})

def generate_ticket():
    """Single ticket: 3x9, 5 numbers per row, proper column ranges."""
    ticket = [[0]*9 for _ in range(3)]
    columns = [
        list(range(1,10)), list(range(10,20)), list(range(20,30)),
        list(range(30,40)), list(range(40,50)), list(range(50,60)),
        list(range(60,70)), list(range(70,80)), list(range(80,91))
    ]
    for col in columns:
        random.shuffle(col)
    # choose 5 columns per row
    row_cols = [random.sample(range(9), 5) for _ in range(3)]
    for r in range(3):
        for c in row_cols[r]:
            ticket[r][c] = columns[c].pop()
    # sort numbers per column (style)
    for c in range(9):
        vals = [ticket[r][c] for r in range(3) if ticket[r][c] != 0]
        vals.sort()
        i = 0
        for r in range(3):
            if ticket[r][c] != 0:
                ticket[r][c] = vals[i]; i += 1
    return ticket

# ---- Run ----
if __name__ == "__main__":
    # Already called once on import; harmless to call again locally
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
