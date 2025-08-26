# app.py (production-ready with mark-as-used)
import csv, io, time, re, requests, logging
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

# Published Google Sheet CSV link
CSV_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vSCJvn8DmAWLGevKcvihGNEaZcLPALkhy7BT3rJtH_F_LSaZwIiT5YM52E_sbFV_V2ffX7g--UUElCw/pub?output=csv"

# Normalize input: uppercase, remove non-alphanumerics
def norm(s: str) -> str:
    return re.sub(r'[^A-Z0-9]', '', (s or '').strip().upper())

# Cache to avoid frequent downloads
_CACHE = {"ts": 0, "ttl": 60, "rows": [], "cols": {}}

def fetch_rows():
    now = time.time()
    if now - _CACHE["ts"] < _CACHE["ttl"] and _CACHE["rows"]:
        return _CACHE["rows"], _CACHE["cols"]

    r = requests.get(CSV_URL, timeout=10)
    r.raise_for_status()
    content = r.content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    rows = [dict(row) for row in reader]
    cols = {k.lower(): k for k in (reader.fieldnames or [])}

    _CACHE.update({"ts": now, "rows": rows, "cols": cols})
    return rows, cols

app = Flask(__name__)

# Enable CORS
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.get("/")
def root():
    return jsonify({"ok": True, "hint": "Use /validate?code=XXXXXX"})

@app.get("/debug")
def debug():
    try:
        rows, cols = fetch_rows()
    except Exception as e:
        return jsonify({"ok": False, "error": "sheet_unreachable", "detail": str(e)}), 502
    headers = list(rows[0].keys()) if rows else []
    code_col = cols.get("code")
    sample_codes = [r.get(code_col, "") for r in rows[:5]] if (rows and code_col) else []
    return jsonify({"ok": True, "headers": headers, "count": len(rows), "sample_codes": sample_codes})

@app.get("/validate")
def validate():
    raw_input = (request.args.get("code") or "")
    code = norm(raw_input)
    mark_used = request.args.get("mark") in ("1", "true", "yes")

    if not code:
        return jsonify({"valid": False, "reason": "missing_code"}), 400

    try:
        rows, cols = fetch_rows()
    except Exception:
        return jsonify({"valid": False, "reason": "sheet_unreachable"}), 502

    code_col  = cols.get("code")
    used_col  = cols.get("used")
    buyer_col = cols.get("buyername") or cols.get("buyer")

    if not code_col or not used_col:
        return jsonify({"valid": False, "reason": "bad_headers"}), 500

    for row in rows:
        if norm(row.get(code_col, "")) == code:
            used_val = (row.get(used_col, "").strip().lower())
            if used_val == "no":
                response = {
                    "valid": True,
                    "code": raw_input.strip(),
                    "used": "no",
                    "buyer": (row.get(buyer_col, "").strip() if buyer_col else "")
                }
                logging.info(f"Code VALID: {code} | Buyer: {response['buyer']} | mark_used={mark_used}")
                if mark_used:
                    row[used_col] = "Yes"
                    logging.info(f"Code marked as used: {code}")
                return jsonify(response)
            else:
                logging.info(f"Code already used: {code}")
                return jsonify({"valid": False, "reason": "used"})
    logging.info(f"Code not found: {code}")
    return jsonify({"valid": False, "reason": "not_found"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

