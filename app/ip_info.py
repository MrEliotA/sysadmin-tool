from flask import Blueprint, request, jsonify
import socket
import requests

app = Blueprint('ip_info', __name__)

def get_ip_info(target):
    try:
        # Resolve hostname to IP if needed
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": "Invalid domain or IP"}

    try:
        # Fetch info from ip-api.com
        url = f"http://ip-api.com/json/{ip_address}?fields=66846719"
        response = requests.get(url, timeout=5)
        data = response.json()
    except Exception as e:
        return {"error": str(e)}

    return {
        "ip": ip_address,
        "reverse_dns": get_reverse_dns(ip_address),
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
        "timezone": data.get("timezone"),
        "zip": data.get("zip"),
        "raw": data
    }

def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

@app.route("/")
def check_ip():
    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Please provide target parameter, e.g. /?target=example.com"}), 400
    info = get_ip_info(target)
    return jsonify(info)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
