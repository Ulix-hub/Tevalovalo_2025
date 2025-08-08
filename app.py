import csv, io, time
import requests
from flask import Flask, request, jsonify

CSV_URL = "https://docs.google.com/spreadsheets/d/e/2PACX-1vSjPEP-QR6_f4gj6Ot0aykyd2y-ko2VCxnEDIpo-rbYgldhCuqr3wMg8U5Mq98Jnv6MLJjl3X95zkFF/pub?gid=0&single=true&output=csv"
CODE_COL = "Code"
USED_COL = "Used"        # "no" or "yes"
BUYER_COL = "BuyerName"  # optional

_CACHE = {"ts": 0, "ttl": 60, "rows": []}  # 60s cache

def fetch_rows():
    now = time.time()
    if now - _CACHE["ts"] < _CACHE["ttl"] and _CACHE["rows"]:
        return _CACHE["rows"]
    r = requests.get(CSV_URL, timeout=10)
    r.raise_for_status()
    content = r.content.decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(content))
    rows = [dict(row) for row in reader]
    _CACHE.update({"ts": now, "rows": rows})
    return rows

app = Flask(__name__)

@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.get("/")
def root():
    return jsonify({"ok": True, "hint": "Use /validate?code=XXXXXX"})

@app.get("/validate")
def validate():
    code = (request.args.get("code") or "").strip()
    if not code:
        return jsonify({"valid": False, "reason": "missing_code"}), 400
    try:
        rows = fetch_rows()
    except Exception:
        return jsonify({"valid": False, "reason": "sheet_unreachable"}), 502

    for row in rows:
        if row.get(CODE_COL, "").strip() == code:
            used = row.get(USED_COL, "").strip().lower()
            if used == "no":
                return jsonify({"valid": True, "code": code, "used": "no", "buyer": row.get(BUYER_COL, "").strip()})
            return jsonify({"valid": False, "reason": "used"})
    return jsonify({"valid": False, "reason": "not_found"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
