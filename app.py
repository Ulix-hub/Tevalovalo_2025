from flask import Flask, request, jsonify
import csv
import os

app = Flask(__name__)

CODES_FILE = "codes.csv"

# Load codes from CSV
def load_codes():
    codes = []
    if os.path.exists(CODES_FILE):
        with open(CODES_FILE, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                codes.append(row)
    return codes

# Save codes back to CSV
def save_codes(codes):
    with open(CODES_FILE, mode="w", newline="", encoding="utf-8") as file:
        fieldnames = ["Code", "Used", "BuyerName"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(codes)

@app.route("/validate", methods=["POST"])
def validate():
    data = request.json
    user_code = data.get("code", "").strip()
    buyer_name = data.get("buyer", "").strip()

    if not user_code:
        return jsonify({"valid": False, "reason": "empty_code"}), 400

    codes = load_codes()

    for row in codes:
        if row["Code"].strip() == user_code:
            if row["Used"].strip().lower() == "no":
                # Mark as used
                row["Used"] = "Yes"
                if buyer_name:
                    row["BuyerName"] = buyer_name
                save_codes(codes)
                return jsonify({"valid": True, "reason": "success"})
            else:
                return jsonify({"valid": False, "reason": "already_used"})
    
    return jsonify({"valid": False, "reason": "not_found"})

@app.route("/")
def home():
    return "Access Code Validator is running 🚀"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
