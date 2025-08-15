from flask import Flask, request, jsonify
import whois
from datetime import datetime

app = Flask(__name__)

def domain_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "referral_url": w.referral_url,
            "name_servers": w.name_servers,
            "status": w.status,
            "creation_date": _format_date(w.creation_date),
            "expiration_date": _format_date(w.expiration_date),
            "updated_date": _format_date(w.updated_date),
            "emails": w.emails,
            "raw": str(w)
        }
    except Exception as e:
        return {"error": str(e)}

def _format_date(date_val):
    if isinstance(date_val, list):
        return [d.strftime("%Y-%m-%d %H:%M:%S") for d in date_val if isinstance(d, datetime)]
    elif isinstance(date_val, datetime):
        return date_val.strftime("%Y-%m-%d %H:%M:%S")
    return str(date_val)

@app.route("/")
def check_domain():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Please provide domain parameter, e.g. /?domain=example.com"}), 400
    info = domain_info(domain)
    return jsonify(info)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083)
