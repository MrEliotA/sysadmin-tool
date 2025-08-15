from flask import Flask, request, jsonify
import socket
import requests
from Wappalyzer import Wappalyzer, WebPage

app = Flask(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 3389, 5900, 8080, 8443, 9000, 10000, 1433, 1521, 5432, 27017
]

def scan_ports_with_banner(host):
    open_ports_info = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            if sock.connect_ex((host, port)) == 0:
                banner = grab_banner(sock)
                open_ports_info.append({
                    "port": port,
                    "banner": banner
                })
            sock.close()
        except:
            pass
    return open_ports_info

def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "No banner received"
    except:
        return "Banner grab failed"

def get_http_info(url):
    try:
        r = requests.get(url, timeout=5)
        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server", "N/A"),
            "content_type": r.headers.get("Content-Type", "N/A"),
            "page_title": extract_title(r.text)
        }
    except:
        return {"error": "Unable to fetch HTTP info"}

def extract_title(html):
    start = html.find("<title>")
    end = html.find("</title>")
    if start != -1 and end != -1:
        return html[start+7:end].strip()
    return "N/A"

def detect_technologies(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        return list(wappalyzer.analyze(webpage))
    except Exception as e:
        return {"error": str(e)}

@app.route("/techscan")
def techscan():
    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Please provide target parameter"}), 400

    ip = None
    try:
        ip = socket.gethostbyname(target)
    except:
        pass

    url = "http://" + target
    result = {
        "target": target,
        "ip": ip,
        "open_ports": scan_ports_with_banner(target),
        "http_info": get_http_info(url),
        "technologies": detect_technologies(url)
    }
    return jsonify(result)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
