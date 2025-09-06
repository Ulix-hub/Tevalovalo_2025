# app.py
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

# ---- DB/ENV ----
DB_FILE = os.environ.get("DB_FILE", "codes.db")
CSV_FILE = os.environ.get("CODES_CSV", "codes.csv")
MAX_DEVICES_DEFAULT = int(os.environ.get("MAX_DEVICES_DEFAULT", "1"))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")
MASTER_CODE = os.environ.get("MASTER_CODE", "").strip()
lock = Lock()

# ===== Secure code alphabet + helpers (Base32 w/out 0/1/I/O) =====
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 symbols
ALPH_LEN = len(ALPHABET)

def luhn_mod_n_check_index(values, n=ALPH_LEN):
    factor, total = 2, 0
    for v in reversed(values):
        addend = factor * v
        addend = (addend // n) + (addend % n)
        total += addend
        factor = 1 if factor == 2 else 2
    return (-total) % n

def make_secure_code(prefix="", groups=4, group_len=4, add_check=True):
    """
    Returns (canonical_without_prefix_or_hyphens, display_with_prefix)
    Example display: TV-7XGM-Q2HN-8R3K-L   (last char is a check)
    """
    payload_len = groups * group_len - (1 if add_check else 0)
    vals = [secrets.randbelow(ALPH_LEN) for _ in range(payload_len)]
    if add_check:
        vals.append(luhn_mod_n_check_index(vals))
    body = "".join(ALPHABET[v] for v in vals)
    chunks = [body[i:i+group_len] for i in range(0, len(body), group_len)]
    display = "-".join(chunks)
    display = f"{prefix.strip().upper()}-{display}" if prefix else display
    canonical = re.sub(r"[^A-Z0-9]", "", display)
    if prefix:
        canonical = canonical[len(prefix):]
    return canonical, display

# ===== Normalization / Canonicalization =====
SECURE_BODY_LEN = 16  # length of the secure code body

def normalize_code(s: str) -> str:
    s = (s or "").strip().upper()
    return re.sub(r"[^A-Z0-9]", "", s)

SECURE_BODY_LEN = 16  # keep

def to_canonical(code_str: str) -> str:
    """
    Accepts DISPLAY or raw. If the code has a short letter prefix like 'TV-',
    drop just that prefix, then uppercase, strip non-alphanumerics.
    If longer than 16, keep LAST 16; else keep as-is (so 3x4=12 stays 12).
    """
    raw = (code_str or "").strip()
    if not raw:
        return ""
    # If it looks like PREFIX-xxxx..., drop only the first segment if it's letters
    if "-" in raw:
        first, *rest = raw.split("-")
        if first.isalpha() and 1 <= len(first) <= 4:
            raw = "-".join(rest)
    s = re.sub(r"[^A-Za-z0-9]", "", raw).upper()
    return s[-SECURE_BODY_LEN:] if len(s) > SECURE_BODY_LEN else s

# ---- DB init (with CSV UPSERT in canonical form) ----
def init_db():
    db_dir = os.path.dirname(DB_FILE)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS codes (
                Code TEXT PRIMARY KEY,
                Used TEXT DEFAULT 'No',
                BuyerName TEXT,
                Expiry TEXT,
                MaxDevices INTEGER DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS activations (
                Code TEXT NOT NULL,
                DeviceID TEXT NOT NULL,
                FirstSeen TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (Code, DeviceID),
                FOREIGN KEY (Code) REFERENCES codes(Code) ON DELETE CASCADE
            )
        """)
        try:
            c.execute("SELECT MaxDevices FROM codes LIMIT 1")
        except sqlite3.OperationalError:
            c.execute("ALTER TABLE codes ADD COLUMN MaxDevices INTEGER DEFAULT 1")
        conn.commit()

        # Seed/refresh from CSV (UPSERT), storing canonical Code
        if os.path.exists(CSV_FILE):
            with open(CSV_FILE, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_code = row.get("Code")
                    code = to_canonical(raw_code)
                    if not code:
                        continue
                    used   = (row.get("Used") or "No").strip()
                    buyer  = (row.get("BuyerName") or "").strip()
                    expiry = (row.get("Expiry") or "").strip()
                    try:
                        maxdev = int((row.get("MaxDevices") or MAX_DEVICES_DEFAULT) or 1)
                    except Exception:
                        maxdev = MAX_DEVICES_DEFAULT
                    if not expiry:
                        expiry = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"

                    c.execute("""
                        INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(Code) DO UPDATE SET
                          Used       = excluded.Used,
                          BuyerName  = excluded.BuyerName,
                          Expiry     = excluded.Expiry,
                          MaxDevices = excluded.MaxDevices
                    """, (code, used, buyer, expiry, maxdev))
            conn.commit()

init_db()

# ---- Health ----
@app.get("/whoami")
def whoami():
    return jsonify({
        "service": os.environ.get("RENDER_SERVICE_NAME", "local"),
        "env": os.environ.get("RENDER_EXTERNAL_URL", "n/a"),
        "version": "v7-canonical-upsert",
        "time": datetime.utcnow().isoformat() + "Z",
        "db_file": DB_FILE
    })

@app.get("/")
def home():
    return "Access Code Validator & Housie90 API (Device-Bound) 🚀"

# ---- Helpers ----
def _auth_ok(req):
    return ADMIN_KEY and req.headers.get("X-Admin-Key") == ADMIN_KEY

def _get_max_devices(row):
    try:
        return int(row["MaxDevices"] if isinstance(row, sqlite3.Row) else row[4])
    except Exception:
        return MAX_DEVICES_DEFAULT

# ---- VALIDATE (device-bound; single implementation, two paths) ----
@app.route("/validate", methods=["POST", "GET"])
@app.route("/api/validate", methods=["POST", "GET"])
def validate():
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            raw_code  = data.get("code")
            buyer     = (data.get("buyer") or "").strip()
            device_id = (data.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()
        else:
            raw_code  = request.args.get("code")
            buyer     = (request.args.get("buyer") or "").strip()
            device_id = (request.args.get("device_id") or "").strip() or (request.headers.get("X-Device-Id") or "").strip()

        code = to_canonical(raw_code)
        raw_norm = normalize_code(raw_code)

        if not code:
            return jsonify({"valid": False, "reason": "empty_code"}), 404
        if not device_id:
            return jsonify({"valid": False, "reason": "missing_device_id"}), 400

        # Master code (binds to device; long expiry)
        if MASTER_CODE and code == to_canonical(MASTER_CODE):
            return jsonify({
                "valid": True,
                "token": f"master-{device_id}",
                "expires_at": (datetime.utcnow()+timedelta(days=3650)).isoformat()+"Z",
                "device_registered": True,
                "reason": "master"
            }), 200

        with lock, sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Exact canonical match
            row = c.execute("""
            SELECT Code, Used, BuyerName, Expiry, MaxDevices
            FROM codes
            WHERE UPPER(REPLACE(Code,'-','')) = UPPER(?)
            OR UPPER(REPLACE(Code,'-','')) = UPPER(substr(?, -length(REPLACE(Code,'-',''))))
            LIMIT 1
            """, (code, raw_norm)).fetchone()

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
            already = c.execute("SELECT 1 FROM activations WHERE Code=? AND DeviceID=?",
                                (row["Code"], device_id)).fetchone()
            if already:
                return jsonify({
                    "valid": True,
                    "token": f"lic-{row['Code']}-{device_id}",
                    "expires_at": expiry.isoformat()+"Z",
                    "device_registered": True,
                    "reason": "ok_same_device"
                }), 200

            # Device limit
            cnt = c.execute("SELECT COUNT(*) FROM activations WHERE Code=?", (row["Code"],)).fetchone()[0]
            max_devices = _get_max_devices(row)
            if cnt >= max_devices:
                return jsonify({"valid": False, "reason": "device_limit"}), 403

            # Register device + mark used
            c.execute("INSERT OR IGNORE INTO activations (Code, DeviceID, FirstSeen) VALUES (?, ?, ?)",
                      (row["Code"], device_id, datetime.utcnow().isoformat()+"Z"))
            if str(row["Used"] or "No").strip().lower() != "yes":
                c.execute("UPDATE codes SET Used='Yes', BuyerName=COALESCE(?, BuyerName) WHERE Code=?",
                          (buyer, row["Code"]))
            conn.commit()

            return jsonify({
                "valid": True,
                "token": f"lic-{row['Code']}-{device_id}",
                "expires_at": expiry.isoformat()+"Z",
                "device_registered": True,
                "reason": "ok_new_device"
            }), 200

    except Exception:
        traceback.print_exc()
        return jsonify({"valid": False, "reason": "server_error"}), 500

# ---- ADMIN endpoints ----
@app.post("/admin/add_code")
def admin_add_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    code = to_canonical(data.get("code"))
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

@app.post("/admin/new_codes")  # legacy simple codes (now stored canonical)
def admin_new_codes():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    n      = int(request.args.get("n", 10))
    days   = int(request.args.get("days", 30))
    prefix = request.args.get("prefix")
    buyer  = request.args.get("buyer", "")
    max_devices = int(request.args.get("max_devices", MAX_DEVICES_DEFAULT))
    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"

    def _make_code(prefix=None):
        body = (secrets.token_urlsafe(5).replace("_","").replace("-","").upper())[:10]
        return f"{prefix}-{body}" if prefix else body

    made = []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for _ in range(n):
            raw = _make_code(prefix)
            code = to_canonical(raw)
            c.execute("""
                INSERT OR IGNORE INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                VALUES (?, 'No', ?, ?, ?)
            """, (code, buyer, expiry, max_devices))
            made.append(raw)
        conn.commit()
    return jsonify({"ok": True, "count": len(made), "expiry": expiry, "max_devices": max_devices, "codes": made})
@app.post("/admin/bulk_add")
def admin_bulk_add():
    if not _auth_ok(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    raw_codes    = data.get("codes") or []
    buyer        = (data.get("buyer") or "").strip()
    days         = int(data.get("days") or 30)
    max_devices  = int(data.get("max_devices") or MAX_DEVICES_DEFAULT)

    if not isinstance(raw_codes, list) or not raw_codes:
        return jsonify({"ok": False, "error": "no_codes"}), 400

    expiry = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z"

    added, skipped = [], []
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        for raw in raw_codes:
            try:
                code = to_canonical(raw)
                raw_norm = normalize_code(raw_code)

                if not code:
                    skipped.append({"raw": raw, "reason": "empty"})
                    continue
                c.execute("""
                    INSERT INTO codes (Code, Used, BuyerName, Expiry, MaxDevices)
                    VALUES (?, 'No', ?, ?, ?)
                    ON CONFLICT(Code) DO UPDATE SET
                        Used='No', BuyerName=excluded.BuyerName,
                        Expiry=excluded.Expiry, MaxDevices=excluded.MaxDevices
                """, (code, buyer, expiry, max_devices))
                added.append(code)
            except Exception as e:
                skipped.append({"raw": raw, "reason": str(e)})
        conn.commit()

    return jsonify({
        "ok": True,
        "added": len(added),
        "skipped": skipped,
        "expiry": expiry,
        "max_devices": max_devices
    })
@app.route("/admin/new_codes_secure", methods=["POST", "GET"])
def admin_new_codes_secure():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403

    payload = request.get_json(silent=True) or {}
    q = request.args

    def pick(key, default=None, caster=lambda x: x):
        val = q.get(key)
        if val is None: val = payload.get(key)
        if val is None: return default
        try: return caster(val)
        except Exception: return default

    n           = max(1, min(pick("n", 1, int), 2000))
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
        "days": days,
        "expiry": expiry,
        "max_devices": max_devices,
        "codes": made
    })

@app.post("/admin/reset_code")
def admin_reset_code():
    if not _auth_ok(request): return jsonify({"ok": False, "error": "unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    raw = data.get("code")
    if not raw: return jsonify({"ok": False, "error": "missing_code"}), 400
    norm = to_canonical(raw)
    with lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
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

# ---- Tickets (strict) ----
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
            all_tickets.append(generate_ticket_strict())
    return jsonify({"cards": all_tickets})

def generate_ticket_strict():
    cols = [
        list(range(1,10)), list(range(10,20)), list(range(20,30)),
        list(range(30,40)), list(range(40,50)), list(range(50,60)),
        list(range(60,70)), list(range(70,80)), list(range(80,91))
    ]
    for c in cols: random.shuffle(c)

    counts = [1]*9
    extras = 15 - sum(counts)  # 6 to distribute
    while extras > 0:
        i = random.randrange(9)
        if counts[i] < 3:
            counts[i] += 1
            extras -= 1

    rows = [[0]*9 for _ in range(3)]
    row_used = [0,0,0]

    # place columns with 3
    for ci, cnt in enumerate(counts):
        if cnt == 3:
            for r in range(3):
                rows[r][ci] = 1
                row_used[r] += 1

    # columns with 2
    for ci, cnt in enumerate(counts):
        if cnt == 2:
            options = sorted(range(3), key=lambda r: (row_used[r], random.random()))
            placed = 0
            for r in options:
                if row_used[r] < 5:
                    rows[r][ci] = 1
                    row_used[r] += 1
                    placed += 1
                    if placed == 2: break

    # columns with 1
    for ci, cnt in enumerate(counts):
        if cnt == 1:
            options = sorted(range(3), key=lambda r: (row_used[r], random.random()))
            for r in options:
                if row_used[r] < 5:
                    rows[r][ci] = 1
                    row_used[r] += 1
                    break

    # patch any short row
    for r in range(3):
        while row_used[r] < 5:
            cands = [ci for ci in range(9) if rows[r][ci] == 0 and sum(rows[rr][ci] for rr in range(3)) < 3]
            if not cands:
                break
            ci = random.choice(cands)
            rows[r][ci] = 1
            row_used[r] += 1

    ticket = [[0]*9 for _ in range(3)]
    for ci in range(9):
        r_idxs = [r for r in range(3) if rows[r][ci] == 1]
        need = len(r_idxs)
        nums = sorted([cols[ci].pop() for _ in range(need)])
        r_idxs.sort()
        for k, r in enumerate(r_idxs):
            ticket[r][ci] = nums[k]
    return ticket

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))





