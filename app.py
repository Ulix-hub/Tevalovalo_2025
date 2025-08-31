from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import sqlite3, os, re, csv, random, secrets, io, traceback
from threading import Lock
from datetime import datetime, timedelta

app = Flask(__name__)

# ---- CORS ----
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key", "X-Device-Id"],
    expose_headers=["Content-Type"],
    max_age=86400,
)

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Key, X-Device-Id"
    return resp

# ---- DB ----
DB_FILE = os.environ.get("DB_FILE", "codes.db")
CSV_FILE = os.environ.get("CODES_CSV", "codes.csv")
MAX_DEVICES_DEFAULT = int(os.environ.get("MAX_DEVICES_DEFAULT", "1"))
lock = Lock()

def normalize_code(s: str) -> str:
    s = (s or "").strip().upper()
    return re.sub(r"[^A-Z0-9_-]", "", s)

def init_db():
    db_dir = os.path.dirname(DB_FILE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # Main codes table (with MaxDevices)
        c.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT,
                Expiry TEXT,
                MaxDevices INTEGER DEFAULT 1
            )
        """)
        # Activation table: one row per (Code, DeviceID)
        c.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                Code TEXT NOT NULL,
                DeviceID TEXT NOT NULL,
                FirstSeen TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (Code, DeviceID),
                FOREIGN KEY (Code) REFERENCES codes(Code) ON DELETE CASCADE
            )
        """)
        # Try to add MaxDevices if older DB exists without it
        try:
            c.execute("SELECT MaxDevices FROM codes LIMIT 1")
        except sqlite3.OperationalError:
            c.execute("ALTER TABLE codes ADD COLUMN MaxDevices INTEGER DEFAULT 1")
        conn.commit()

        # Optional: seed from CSV
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
                    maxdev = int((row.get("MaxDevices") or MAX_DEVICES_DEFAULT) or 1)
                    if not expiry:
                        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
                    c.execute(
                        """INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                           VALUES (?, ?, ?, ?, ?)""",
                        (code, used, buyer, expiry, maxdev)
                    )
            conn.commit()

init_db()

# ---- Health ----
@app.get("/whoami")
def whoami():
    return jsonify({
        "service": os.environ.get("RENDER_SERVICE_NAME", "local"),
        "env": os.environ.get("RENDER_EXTERNAL_URL", "n/a"),
        "version": "v3-device-bind",
        "time": datetime.utcnow().isoformat() + "Z",
        "db_file": DB_FILE
    })

@app.get("/")
def home():
    return "Access Code Validator & Housie90 API (Device-Bound) 🚀"

# ---- VALIDATE (device-bound, monthly expiry supported) ----
MASTER_CODE = os.environ.get("MASTER_CODE", "").strip()

def _get_max_devices(row):
    try:
        return int(row["MaxDevices"] if isinstance(row, sqlite3.Row) else row[4])
    except Exception:
        return MAX_DEVICES_DEFAULT

@app.route("/validate", methods=["POST", "GET"])
def validate():
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            user_code = normalize_code(data.get("code"))
            buyer_name = (data.get("buyer") or "").strip()
            device_id = (data.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()
        else:
            user_code = normalize_code(request.args.get("code"))
            buyer_name = (request.args.get("buyer") or "").strip()
            device_id = (request.args.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()

        if not user_code:
            return jsonify({"valid": False, "reason": "empty_code"}), 400
        if not device_id:
            return jsonify({"valid": False, "reason": "missing_device_id"}), 400

        # Support master code for testing/support; binds to device but ignores DB
        if MASTER_CODE and user_code == normalize_code(MASTER_CODE):
            return jsonify({
                "valid": True,
                "token": f"master-{device_id}",
                "expires_at": (datetime.utcnow()+timedelta(days=3650)).isoformat()+"Z",
                "device_registered": True,
                "reason": "master"
            })

        with lock, sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            row = c.execute("SELECT Code, Used, BuyerName, Expiry, MaxDevices FROM codes WHERE UPPER(Code)=UPPER(?)", (user_code,)).fetchone()
            if not row:
                return jsonify({"valid": False, "reason": "not_found"}), 404

            # Expiry check
            expiry_str = row["Expiry"]
            try:
                expiry = datetime.fromisoformat((expiry_str or "").replace("Z","")) if expiry_str else (datetime.utcnow() + timedelta(days=30))
            except Exception:
                expiry = datetime.utcnow() + timedelta(days=30)
            if expiry <= datetime.utcnow():
                return jsonify({"valid": False, "reason": "expired"}), 400

            # Is this device already activated for this code?
            already = c.execute("SELECT 1 FROM activations WHERE Code=? AND DeviceID=?", (row["Code"], device_id)).fetchone()
            if already:
                # idempotent: allow reuse on the same device
                return jsonify({
                    "valid": True,
                    "token": f"lic-{row['Code']}-{device_id}",
                    "expires_at": expiry.isoformat()+"Z",
                    "device_registered": True,
                    "reason": "ok_same_device"
                })

            # Count distinct devices
            cnt = c.execute("SELECT COUNT(*) FROM activations WHERE Code=?", (row["Code"],)).fetchone()[0]
            max_devices = _get_max_devices(row)
            if cnt >= max_devices:
                return jsonify({"valid": False, "reason": "device_limit"}), 403

            # Register this device
            c.execute("INSERT OR IGNORE INTO activations (Code, DeviceID, FirstSeen) VALUES (?, ?, ?)", (row["Code"], device_id, datetime.utcnow().isoformat()+"Z"))
            # Mark used on first activation for backwards compatibility
            if str(row["Used"] or "No").strip().lower() != "yes":
                c.execute("UPDATE codes SET Used='Yes', BuyerName=COALESCE(?, BuyerName) WHERE Code=?", (buyer_name, row["Code"]))
            conn.commit()

            return jsonify({
                "valid": True,
                "token": f"lic-{row['Code']}-{device_id}",
                "expires_at": expiry.isoformat()+"Z",
                "device_registered": True,
                "reason": "ok_new_device"
            })
    except Exception:
        traceback.print_exc()
        return jsonify({"valid": False, "reason": "server_error"}), 500

# ---- ADMIN (existing + new) ----
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def _auth_ok(req):
    return ADMIN_KEY and req.headers.get("X-Admin-Key") == ADMIN_KEY

@app.post("/admin/add_code")
def admin_add_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = normalize_code(data.get("code"))
    buyer = (data.get("buyer") or "").strip()
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or MAX_DEVICES_DEFAULT)
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            """INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
               VALUES (?, 'No', ?, ?, ?)
               ON CONFLICT(Code) DO UPDATE SET Used='No', BuyerName=excluded.BuyerName, Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices""",            (code, buyer, expiry, max_devices)
        )
        conn.commit()
    return jsonify({"ok": True, "code": code, "expiry": expiry, "max_devices": max_devices})

@app.post("/admin/new_codes")  # ?n=20&days=30&prefix=TV&buyer=Uli&max_devices=1
def admin_new_codes():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    n      = int(request.args.get("n", 10))
    days   = int(request.args.get("days", 30))
    prefix = request.args.get("prefix")
    buyer  = request.args.get("buyer", "")
    max_devices = int(request.args.get("max_devices", MAX_DEVICES_DEFAULT))
    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"

    def _make_code(prefix=None):
        body = (secrets.token_urlsafe(5).replace("_","" ).replace("-","").upper())[:10]
        return f"{prefix}-{body}" if prefix else body

    made = []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for _ in range(n):
            code = _make_code(prefix)
            c.execute(
                "INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry, MaxDevices) VALUES (?, 'No', ?, ?, ?)",
                (code, buyer, expiry, max_devices)
            )
            made.append(code)
        conn.commit()
    return jsonify({"ok": True, "count": len(made), "expiry": expiry, "max_devices": max_devices, "codes": made})

@app.post("/admin/reset_code")
def admin_reset_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = normalize_code(data.get("code"))
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE codes SET Used='No' WHERE UPPER(Code)=UPPER(?)", (code,))
        c.execute("DELETE FROM activations WHERE UPPER(Code)=UPPER(?)", (code,))
        conn.commit()
    return jsonify({"ok": True, "code": code, "status": "reset"})

@app.get("/admin/list_codes")
def admin_list_codes():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    limit = int(request.args.get("limit", 200))
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT Code, Used, BuyerName, Expiry, MaxDevices FROM codes ORDER BY Code LIMIT ?", (limit,))
        rows = [dict(r) for r in c.fetchall()]
    return jsonify({"ok": True, "rows": rows, "count": len(rows)})

@app.get("/admin/stats")
def admin_stats():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        total = c.execute("SELECT COUNT(*) FROM codes").fetchone()[0]
        used  = c.execute("SELECT COUNT(*) FROM codes WHERE lower(Used)='yes'").fetchone()[0]
        activ = c.execute("SELECT COUNT(*) FROM activations").fetchone()[0]
        return jsonify({"ok": True, "total": total, "used": used, "unused": total-used, "activations": activ})

@app.get("/admin/export_csv")
def admin_export_csv():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Code","Used","BuyerName","Expiry","MaxDevices"])
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for row in c.execute("SELECT Code, Used, BuyerName, Expiry, MaxDevices FROM codes ORDER BY Code"):
            writer.writerow(row)
    csv_bytes = output.getvalue().encode("utf-8")
    return Response(csv_bytes, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=codes_export.csv"})

# ---- Tickets (unchanged) ----
@app.get("/api/tickets")
def api_tickets():
    try:
        count = int(request.args.get("cards", 1))
    except Exception:
        count = 1
    count = max(1, min(count, 60))
    all_tickets = []
    for _ in range(count):
        for __ in range(6):
            all_tickets.append(generate_ticket())
    return jsonify({"cards": all_tickets})

def generate_ticket():
    ticket = [[0]*9 for _ in range(3)]
    columns = [
        list(range(1,10)), list(range(10,20)), list(range(20,30)),
        list(range(30,40)), list(range(40,50)), list(range(50,60)),
        list(range(60,70)), list(range(70,80)), list(range(80,91))
    ]
    for col in columns: random.shuffle(col)
    row_cols = [random.sample(range(9), 5) for _ in range(3)]
    for r in range(3):
        for c in row_cols[r]:
            ticket[r][c] = columns[c].pop()
    for c in range(9):
        vals = [ticket[r][c] for r in range(3) if ticket[r][c] != 0]
        vals.sort()
        i = 0
        for r in range(3):
            if ticket[r][c] != 0:
                ticket[r][c] = vals[i]; i += 1
    return ticket

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
