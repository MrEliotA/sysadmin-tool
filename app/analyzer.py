from flask import Blueprint, request, jsonify
import socket
import requests
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage
#from config.py import ALIENVAULT_API_KEY
ALIENVAULT_API_KEY = "Y0fa1fd334ace3f185c9a495746273d907788763b586dc6872f0dd213d8c1dc44"
app = Blueprint('analyzer', __name__)

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    110, 111, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 514, 515, 587, 636, 873,
    993, 995, 1080, 1194, 1352, 1433, 1434, 1521, 1723, 2049,
    2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 6379, 8080]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", 
    "X-Frame-Options", "X-Content-Type-Options", 
    "Referrer-Policy", "Permissions-Policy"
]

# ---- tools ----
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def port_scan(domain):
    open_ports = []
    ip = get_ip(domain)
    if not ip:
        return open_ports
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    sock.sendall(b"HEAD / HTTP/1.0")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    pass
                open_ports.append({"port": port, "state": "open", "banner": banner})
            sock.close()
        except:
            continue
    return open_ports

def http_info(url):
    try:
        r = requests.get(url, timeout=5)
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "server": r.headers.get("Server"),
            "x_powered_by": r.headers.get("X-Powered-By")
        }
    except Exception as e:
        return {"error": str(e)}

def detect_technologies(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        return list(wappalyzer.analyze(webpage))
    except Exception:
        return []

def get_security_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        return {h: headers.get(h, "missing") for h in SECURITY_HEADERS}
    except:
        return {}

def get_subdomains(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    subs = []
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            subs = list({d["hostname"] for d in data.get("passive_dns", []) if "hostname" in d})
    except:
        pass
    return subs

def check_vulnerabilities(open_ports):
    vulns = []
    for port in open_ports:
        if "Apache" in port.get("banner",""):
            vulns.append({"service": "Apache", "cve": "CVE-2021-41773"})
    return vulns

# ---- API Flask ----
@app.route("/analyze")
def analyze():
    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Please provide ?target=example.com"}), 400

    if not target.startswith("http"):
        url = f"http://{target}"
    else:
        url = target

    domain = urlparse(url).netloc
    ip = get_ip(domain)
    open_ports = port_scan(domain)

    return jsonify({
        "target": domain,
        "ip": ip,
        "open_ports": open_ports,
        "http_info": http_info(url),
        "technologies": detect_technologies(url),
        "subdomains": get_subdomains(domain),
        "security_headers": get_security_headers(url),
        "vulnerabilities": check_vulnerabilities(open_ports)
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})
