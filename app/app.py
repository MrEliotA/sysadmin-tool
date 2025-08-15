from flask import Flask, request, jsonify
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
from Wappalyzer import Wappalyzer, WebPage

app = Flask(__name__)

# ---- تنظیمات عمومی ----
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 27017, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200, 10000
]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "test", "dev", "admin", "webmail", "portal", "api",
    "beta", "cpanel", "cdn", "blog", "app", "staging", "secure", "shop", "store", "dashboard", "login",
    "help", "support", "forum", "download", "static", "assets", "news", "images", "img", "video",
    "videos", "media", "docs", "documentation", "status", "monitor", "tracking", "reports", "report", "files",
    "file", "upload", "uploads", "services", "service", "server", "gateway", "billing", "invoice", "account",
    "accounts", "auth", "authentication", "single-sign-on", "sso", "calendar", "chat", "cms", "devops", "git",
    "svn", "jira", "confluence", "data", "db", "database", "proxy", "vpn", "backup", "backups",
    "m", "mobile", "old", "new", "internal", "intranet", "extranet", "partner", "partners", "affiliate",
    "cdn1", "cdn2", "node", "nodes", "edge", "edge1", "edge2", "gateway1", "gateway2", "api1",
    "api2", "sandbox", "test1", "test2", "qa", "qa1", "demo", "demo1", "demo2", "stage"
]


# ---- ابزارها ----
def resolve_ip(target: str):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def _try_banner(sock: socket.socket, port: int) -> str:
    try:
        # بعضی سرویس‌ها بلافاصله بنر می‌دهند
        sock.settimeout(1.0)
        try:
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            pass

        # تلاش برای HTTP/HEAD فقط روی پورت‌های رایج وب
        if port in (80, 8080, 8443, 8000, 9000, 10000):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return data.decode(errors="ignore").strip()
            except Exception:
                pass

        # تلاش ساده: ارسال CRLF
        try:
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            pass

        return "No banner received"
    except Exception:
        return "Banner grab failed"

def _scan_one_port(host: str, port: int):
    info = {"port": port, "state": "closed", "banner": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        res = sock.connect_ex((host, port))
        if res == 0:
            info["state"] = "open"
            info["banner"] = _try_banner(sock, port)
        sock.close()
    except Exception:
        pass
    return info

def scan_ports_with_banners(host: str, max_workers: int = 60):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_scan_one_port, host, p) for p in COMMON_PORTS]
        for f in as_completed(futures):
            results.append(f.result())
    # فقط پورت‌های open را برگردان معقول‌تر است
    return [r for r in results if r["state"] == "open"]

def get_http_info(url: str):
    try:
        r = requests.get(url, timeout=6)
        return {
            "status_code": r.status_code,
            "server": r.headers.get("Server", "N/A"),
            "content_type": r.headers.get("Content-Type", "N/A"),
            "page_title": _extract_title(r.text),
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {"error": f"Unable to fetch HTTP info: {e}"}

def _extract_title(html: str):
    start = html.lower().find("<title>")
    end = html.lower().find("</title>")
    if start != -1 and end != -1:
        return html[start+7:end].strip()
    return "N/A"

def detect_technologies(url: str):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        techs = wappalyzer.analyze(webpage)
        # مجموعه به لیست
        return sorted(list(techs))
    except Exception as e:
        return {"error": str(e)}

def scan_subdomains(domain: str, max_workers: int = 30):
    found = []
    def _resolve(sub):
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            return fqdn
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_resolve, s) for s in COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
    return found

def check_security_headers(url: str):
    try:
        r = requests.get(url, timeout=6)
        report = {}
        for h in SECURITY_HEADERS:
            val = r.headers.get(h)
            report[h] = val if val else "Missing"
        return report
    except Exception as e:
        return {"error": f"Unable to fetch headers: {e}"}

_service_version_regex = re.compile(r"([A-Za-z0-9._\-]+)[/ ]([0-9][A-Za-z0-9._\-]*)")

def parse_service_and_version(banner: str):
    if not banner or banner.startswith("Banner grab failed"):
        return None
    m = _service_version_regex.search(banner)
    if m:
        # مثال: "Apache/2.4.57" -> service: Apache, version: 2.4.57
        return {"service": m.group(1), "version": m.group(2)}
    return None

def fetch_cves_for_services(services: list, max_results: int = 5):
    """
    services: [{"service": "...", "version": "..."}]
    از API رایگان cve.circl.lu استفاده می‌کنیم:
      https://cve.circl.lu/api/search/<product>/<version>
    توجه: این API همیشه vendor/product دقیق نمی‌خواهد، اما ممکن است روی بعضی سرویس‌ها نتیجه کم بدهد.
    """
    out = []
    for sv in services:
        svc = sv["service"]
        ver = sv["version"]
        try:
            url = f"https://cve.circl.lu/api/search/{svc}/{ver}"
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data:
                    out.append({
                        "service": svc,
                        "version": ver,
                        "cves": data[:max_results]
                    })
        except Exception:
            pass
    return out

# ---- API ----
@app.route("/analyze")
def analyze():
    """
    نمونه استفاده:
      /analyze?target=example.com
    """
    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Please provide ?target=example.com"}), 400

    ip = resolve_ip(target)
    url_http = f"http://{target}"

    # موازی‌سازی بعضی مراحل
    with ThreadPoolExecutor(max_workers=6) as ex:
        fut_ports = ex.submit(scan_ports_with_banners, target)
        fut_http = ex.submit(get_http_info, url_http)
        fut_tech = ex.submit(detect_technologies, url_http)
        fut_subs = ex.submit(scan_subdomains, target)
        fut_sec  = ex.submit(check_security_headers, url_http)

        open_ports = fut_ports.result()
        http_info  = fut_http.result()
        techs      = fut_tech.result()
        subdomains = fut_subs.result()
        sec_heads  = fut_sec.result()

    # استخراج سرویس/ورژن از بنرها برای CVE lookup
    sv_pairs = []
    seen = set()
    for item in open_ports:
        banner = item.get("banner") or ""
        parsed = parse_service_and_version(banner)
        if parsed:
            key = (parsed["service"], parsed["version"])
            if key not in seen:
                seen.add(key)
                sv_pairs.append(parsed)

    cve_info = fetch_cves_for_services(sv_pairs)

    return jsonify({
        "target": target,
        "ip": ip,
        "open_ports": open_ports,            # [{port, banner}]
        "http_info": http_info,              # status, headers, title
        "technologies": techs,               # list or {"error": ...}
        "subdomains": subdomains,            # list
        "security_headers": sec_heads,       # dict
        "vulnerabilities": cve_info          # [{service, version, cves: [...]}]
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    # پورت پیش‌فرض این ماژول
    app.run(host="0.0.0.0", port=8086)
