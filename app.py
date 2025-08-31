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

# ---- DB / config ----
DB_FILE = os.environ.get("DB_FILE", "codes.db")
CSV_FILE = os.environ.get("CODES_CSV", "codes.csv")
MAX_DEVICES_DEFAULT = int(os.environ.get("MAX_DEVICES_DEFAULT", "1"))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
MASTER_CODE = (os.environ.get("MASTER_CODE") or "").strip()

lock = Lock()

def normalize_code(s: str) -> str:
    s = (s or "").strip().upper()
    return re.sub(r"[^A-Z0-9_-]", "", s)

# === Secure code helpers (checksum + canonical form) ===
ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # avoid I, O, 0, 1

def _checksum(text: str) -> str:
    s = 0
    for ch in text:
        s = (s * 31 + ord(ch)) % len(ALPH)
    return ALPH[s % len(ALPH)]

def make_secure_code(prefix: str = "", groups: int = 4, group_len: int = 4, add_check: bool = True):
    """
    Returns (canonical, display)
    display: PREFIX-XXXX-XXXX-XXXX-C
    canonical: PREFIXXXXXXXXXXXXXC  (uppercase, no dashes)
    """
    prefix = (prefix or "").upper().replace("-", "").strip()
    groups = max(3, groups)       # at least 3 groups incl. checksum
    group_len = max(4, group_len) # at least 4 chars per group
    body_len = (groups - 1) * group_len   # last "group" is checksum
    body = "".join(secrets.choice(ALPH) for _ in range(body_len))
    core = prefix + body
    chk = _checksum(core) if add_check else ""

    parts = []
    if prefix:
        parts.append(prefix)
    for i in range(0, len(body), group_len):
        parts.append(body[i : i + group_len])
    if add_check:
        parts.append(chk)

    display = "-".join(parts)
    canonical = re.sub(r"[^A-Z0-9]", "", display.upper())
    return canonical, display

def display_to_canonical(s: str) -> str:
    """Uppercase and strip any non [A-Z0-9] (removes dashes/spaces)."""
    return re.sub(r"[^A-Z0-9]", "", (s or "").upper())

def init_db():
    db_dir = os.path.dirname(DB_FILE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # Main codes table (canonical Code, with MaxDevices)
        c.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT,
                Expiry TEXT,
                MaxDevices INTEGER DEFAULT 1
            )
        """)
        # Device activations
        c.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                Code TEXT NOT NULL,
                DeviceID TEXT NOT NULL,
                FirstSeen TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (Code, DeviceID),
                FOREIGN KEY (Code) REFERENCES codes(Code) ON DELETE CASCADE
            )
        """)
        # Helpful indexes
        c.execute("CREATE INDEX IF NOT EXISTS idx_activations_code ON activations(Code)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_codes_expiry ON codes(Expiry)")

        # Try to add MaxDevices if older DB existed
        try:
            c.execute("SELECT MaxDevices FROM codes LIMIT 1")
        except sqlite3.OperationalError:
            c.execute("ALTER TABLE codes ADD COLUMN MaxDevices INTEGER DEFAULT 1")
        conn.commit()

        # Optional seed from CSV (legacy)
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw = row.get("Code")
                    code = display_to_canonical(raw)
                    if not code:
                        continue
                    used = (row.get("Used") or "No").strip()
                    buyer = (row.get("BuyerName") or "").strip()
                    expiry = (row.get("Expiry") or "").strip()
                    maxdev = int((row.get("MaxDevices") or MAX_DEVICES_DEFAULT) or 1)
                    if not expiry:
                        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
                    c.execute("""
                        INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                        VALUES (?, ?, ?, ?, ?)
                    """, (code, used, buyer, expiry, maxdev))
            conn.commit()

init_db()

# ---- Health ----
@app.get("/whoami")
def whoami():
    return jsonify({
        "service": os.environ.get("RENDER_SERVICE_NAME", "local"),
        "env": os.environ.get("RENDER_EXTERNAL_URL", "n/a"),
        "version": "v4-secure-codes",
        "time": datetime.utcnow().isoformat() + "Z",
        "db_file": DB_FILE
    })

@app.get("/")
def home():
    return "Access Code Validator & Housie90 API (Device-Bound, Secure Codes) 🚀"

# ---- Helpers ----
def _auth_ok(req):
    return ADMIN_KEY and req.headers.get("X-Admin-Key") == ADMIN_KEY

def _get_max_devices(row):
    try:
        return int(row["MaxDevices"] if isinstance(row, sqlite3.Row) else row[4])
    except Exception:
        return MAX_DEVICES_DEFAULT

# ---- VALIDATE (device-bound; supports legacy + secure codes) ----
@app.route("/validate", methods=["POST", "GET"])
def validate():
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            raw_code = (data.get("code") or "")
            buyer_name = (data.get("buyer") or "").strip()
            device_id = (data.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()
        else:
            raw_code = (request.args.get("code") or "")
            buyer_name = (request.args.get("buyer") or "").strip()
            device_id = (request.args.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()

        if not raw_code:
            return jsonify({"valid": False, "reason": "empty_code"}), 400
        if not device_id:
            return jsonify({"valid": False, "reason": "missing_device_id"}), 400

        user_code = display_to_canonical(raw_code)

        # Master code (binds to device, 10y)
        if MASTER_CODE and user_code == display_to_canonical(MASTER_CODE):
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

            # Look up canonical first
            row = c.execute("SELECT Code, Used, BuyerName, Expiry, MaxDevices FROM codes WHERE Code = ?", (user_code,)).fetchone()
            if not row:
                # Fallback legacy normalization
                row = c.execute("SELECT Code, Used, BuyerName, Expiry, MaxDevices FROM codes WHERE UPPER(Code)=UPPER(?)", (normalize_code(raw_code),)).fetchone()
                if not row:
                    return jsonify({"valid": False, "reason": "not_found"}), 404

            # Expiry
            expiry_str = row["Expiry"]
            try:
                expiry = datetime.fromisoformat((expiry_str or "").replace("Z","")) if expiry_str else (datetime.utcnow() + timedelta(days=30))
            except Exception:
                expiry = datetime.utcnow() + timedelta(days=30)
            if expiry <= datetime.utcnow():
                return jsonify({"valid": False, "reason": "expired"}), 400

            # Already activated on this device?
            already = c.execute("SELECT 1 FROM activations WHERE Code=? AND DeviceID=?", (row["Code"], device_id)).fetchone()
            if already:
                return jsonify({
                    "valid": True,
                    "token": f"lic-{row['Code']}-{device_id}",
                    "expires_at": expiry.isoformat()+"Z",
                    "device_registered": True,
                    "reason": "ok_same_device"
                })

            # Device limit
            cnt = c.execute("SELECT COUNT(*) FROM activations WHERE Code=?", (row["Code"],)).fetchone()[0]
            max_devices = _get_max_devices(row)
            if cnt >= max_devices:
                return jsonify({"valid": False, "reason": "device_limit"}), 403

            # Register this device
            c.execute("INSERT OR IGNORE INTO activations (Code, DeviceID, FirstSeen) VALUES (?, ?, ?)",
                      (row["Code"], device_id, datetime.utcnow().isoformat()+"Z"))
            # Mark used on first activation
            if str(row["Used"] or "No").strip().lower() != "yes":
                c.execute("UPDATE codes SET Used='Yes', BuyerName=COALESCE(?, BuyerName) WHERE Code=?",
                          (buyer_name, row["Code"]))
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

# ---- ADMIN: secure code generator (GET or POST JSON; no 415) ----
@app.route("/admin/new_codes_secure", methods=["POST", "GET"])
def admin_new_codes_secure():
    if not _auth_ok(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    payload = request.get_json(silent=True) or {}
    args = request.args

    def pick(key, default=None, caster=lambda x: x):
        val = args.get(key)
        if val is None:
            val = payload.get(key)
        if val is None:
            return default
        try:
            return caster(val)
        except Exception:
            return default

    n           = pick("n", 10, int)
    n           = max(1, min(n, 2000))
    days        = pick("days", 30, int)
    prefix      = (pick("prefix", "", str) or "").strip().upper()
    groups      = pick("groups", 4, int)
    group_len   = pick("group_len", 4, int)
    buyer       = (pick("buyer", "", str) or "").strip()
    max_devices = pick("max_devices", MAX_DEVICES_DEFAULT, int)

    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"

    made = []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for _ in range(n):
            canonical, display = make_secure_code(prefix=prefix, groups=groups, group_len=group_len, add_check=True)
            c.execute("""
                INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                VALUES (?, 'No', ?, ?, ?)
                ON CONFLICT(Code) DO UPDATE SET 
                    Used='No', BuyerName=excluded.BuyerName, 
                    Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices
            """, (canonical, buyer, expiry, max_devices))
            made.append({"display": display, "canonical": canonical})
        conn.commit()

    return jsonify({
        "ok": True,
        "count": len(made),
        "expiry": expiry,
        "max_devices": max_devices,
        "codes": made
    })

# ---- ADMIN: legacy add/reset/list/export/stats (kept) ----
@app.post("/admin/add_code")
def admin_add_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    raw = data.get("code")
    code = display_to_canonical(raw)
    buyer = (data.get("buyer") or "").strip()
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or MAX_DEVICES_DEFAULT)
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
            VALUES (?, 'No', ?, ?, ?)
            ON CONFLICT(Code) DO UPDATE SET 
                Used='No', BuyerName=excluded.BuyerName, 
                Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices
        """, (code, buyer, expiry, max_devices))
        conn.commit()
    return jsonify({"ok": True, "code": code, "expiry": expiry, "max_devices": max_devices})

@app.post("/admin/reset_code")
def admin_reset_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = display_to_canonical(data.get("code"))
    if not code: return jsonify({"ok": False, "error": "missing_code"}), 400
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("UPDATE codes SET Used='No' WHERE Code=?", (code,))
        c.execute("DELETE FROM activations WHERE Code=?", (code,))
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
