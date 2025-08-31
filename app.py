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

# ===== Secure code alphabet + helpers (Base32 w/out 0/1/I/O) =====
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 symbols
ALPH_LEN = len(ALPHABET)
CHAR_TO_VAL = {ch: i for i, ch in enumerate(ALPHABET)}

def luhn_mod_n_check_index(values, n=ALPH_LEN):
    """
    Luhn mod N checksum index for a list of digit indexes in base N.
    Generalized Luhn (double from right; sum of digits in base N).
    """
    factor = 2
    total = 0
    for v in reversed(values):
        addend = factor * v
        addend = (addend // n) + (addend % n)
        total += addend
        factor = 1 if factor == 2 else 2
    return (-total) % n

def make_secure_code(prefix="", groups=4, group_len=4, add_check=True):
    """
    Builds a display code like: TV-7XGM-Q2HN-8R3K-L  (L = check char)
    Returns (canonical_no_hyphens_no_prefix, display_with_hyphens_and_optional_prefix)
    """
    # total body length = groups*group_len; reserve last char for check if add_check=True
    payload_len = groups * group_len - (1 if add_check else 0)
    vals = [secrets.randbelow(ALPH_LEN) for _ in range(payload_len)]
    if add_check:
        chk = luhn_mod_n_check_index(vals)
        vals.append(chk)

    body = "".join(ALPHABET[v] for v in vals)
    chunks = [body[i:i+group_len] for i in range(0, len(body), group_len)]
    display = "-".join(chunks)
    display = f"{prefix.strip().upper()}-{display}" if prefix else display

    canonical = display.replace("-", "")
    if prefix:
        canonical = canonical[len(prefix):]  # strip prefix portion from canonical
    return canonical, display

# ===== Normalization =====
def normalize_code(s: str) -> str:
    """
    Normalize user-provided code:
    - Uppercase
    - Strip ALL non-alphanumerics (hyphens/spaces removed)
    Works for existing simple codes and new secure codes.
    """
    s = (s or "").strip().upper()
    return re.sub(r"[^A-Z0-9]", "", s)

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

        # Optional: seed from CSV (normalize for canonical storage)
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_code = row.get("Code")
                    code = normalize_code(raw_code)
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
        "version": "v4-secure-codes",
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

@app.route("/admin/new_codes_secure", methods=["POST", "GET"])
def admin_new_codes_secure():
    if not _auth_ok(request): 
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    # ✅ Never trigger 415: parse JSON only if present, and silently
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

    n           = pick("n", 1, int)
    n           = max(1, min(n, 2000))      # safety cap
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
            canonical, display = make_secure_code(
                prefix=prefix, groups=groups, group_len=group_len, add_check=True
            )
            # store canonical (no hyphens, no prefix)
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
        "days": days,
        "expiry": expiry,
        "max_devices": max_devices,
        "codes": made
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
    # store canonical form
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
               ON CONFLICT(Code) DO UPDATE SET Used='No', BuyerName=excluded.BuyerName, Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices""",
            (code, buyer, expiry, max_devices)
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
            # keep legacy behavior (store as-is) for backward compatibility
            c.execute(
                "INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry, MaxDevices) VALUES (?, 'No', ?, ?, ?)",
                (code, buyer, expiry, max_devices)
            )
            made.append(code)
        conn.commit()
    return jsonify({"ok": True, "count": len(made), "expiry": expiry, "max_devices": max_devices, "codes": made})

# NEW: Production-grade codes (hard to guess, with check digit). Stores canonical; returns pretty display.
@app.route("/admin/new_codes_secure", methods=["POST", "GET"])
def admin_new_codes_secure():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403

    try:
        n = int(request.args.get("n") or (request.json or {}).get("n") or 1)
    except:
        n = 1
    n = max(1, min(n, 2000))  # safety cap

    try:
        days = int(request.args.get("days") or (request.json or {}).get("days") or 30)
    except:
        days = 30

    prefix = (request.args.get("prefix") or (request.json or {}).get("prefix") or "").strip().upper()
    groups = int(request.args.get("groups") or 4)
    group_len = int(request.args.get("group_len") or 4)
    buyer  = (request.args.get("buyer") or (request.json or {}).get("buyer") or "").strip()
    max_devices = int(request.args.get("max_devices") or (request.json or {}).get("max_devices") or MAX_DEVICES_DEFAULT)

    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"

    made = []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for _ in range(n):
            canonical, display = make_secure_code(prefix=prefix, groups=groups, group_len=group_len, add_check=True)
            # store canonical (no hyphens, no prefix) so validation is robust
            c.execute("""
                INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                VALUES (?, 'No', ?, ?, ?)
                ON CONFLICT(Code) DO UPDATE SET Used='No', BuyerName=excluded.BuyerName, Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices
            """, (canonical, buyer, expiry, max_devices))
            made.append({"display": display, "canonical": canonical})
        conn.commit()

    return jsonify({"ok": True, "count": len(made), "days": days, "expiry": expiry, "max_devices": max_devices, "codes": made})

@app.post("/admin/reset_code")
def admin_reset_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    raw = data.get("code")
    if not raw: return jsonify({"ok": False, "error": "missing_code"}), 400
    norm = normalize_code(raw)
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # match regardless of hyphens in stored codes
        c.execute("UPDATE codes SET Used='No' WHERE UPPER(REPLACE(Code,'-',''))=UPPER(?)", (norm,))
        c.execute("DELETE FROM activations WHERE UPPER(REPLACE(Code,'-',''))=UPPER(?)", (norm,))
        conn.commit()
    return jsonify({"ok": True, "code": norm, "status": "reset"})

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

