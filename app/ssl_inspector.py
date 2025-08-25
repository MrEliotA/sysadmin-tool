from flask import Blueprint, request, jsonify
import socket, ssl, datetime, time, requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# SSL Labs API URL
SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze"

# Create Blueprint for SSL Inspector
app = Blueprint('ssl_inspector', __name__)

# ---------- Local certificate (direct TLS) ----------
def get_local_ssl_info(domain: str):
    """Fetch the local SSL certificate of the given domain"""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=domain)
        conn.settimeout(7.0)
        conn.connect((domain, 443))
        cert_bin = conn.getpeercert(True)
        conn.close()

        cert = x509.load_der_x509_certificate(cert_bin, default_backend())

        def _name_to_dict(name: x509.Name):
            items = {}
            for attr in name:
                key = getattr(attr.oid, "_name", None) or attr.oid.dotted_string
                items[key] = attr.value
            return items

        # Signature hash algorithm (safe)
        try:
            sig_hash = cert.signature_hash_algorithm.name
        except Exception:
            sig_hash = "unknown"

        # Public key type + size
        pk = cert.public_key()
        pk_type = type(pk).__name__
        pk_size = getattr(pk, "key_size", None)

        # Access not_valid_before and not_valid_after directly
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        
        # Ensure both dates are timezone-aware
        now_utc = datetime.datetime.now(datetime.timezone.utc)  # Make `now_utc` aware
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)  # Ensure `not_after` is aware

        # Calculate days remaining until certificate expiration
        days_remaining = (not_after - now_utc).days

        return {
            "subject": _name_to_dict(cert.subject),
            "issuer": _name_to_dict(cert.issuer),
            "serial_number": str(cert.serial_number),
            "version": cert.version.name,
            "not_valid_before": not_before.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "not_valid_after": not_after.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "days_remaining": days_remaining,
            "signature_algorithm": sig_hash,
            "public_key_type": pk_type,
            "public_key_size": pk_size,
        }

    except Exception as e:
        return {"error": f"Local SSL check failed: {str(e)}"}

# ---------- SSL Labs (poll until READY/ERROR) ----------
def fetch_ssllabs_raw(domain: str, max_wait_seconds: int = 120):
    """Fetch the SSL Labs analysis for the domain"""
    base = SSL_LABS_API
    params = {
        "host": domain,
        "all": "done",
        "fromCache": "on",
        "ignoreMismatch": "on",
    }
    deadline = time.time() + max_wait_seconds
    while True:
        try:
            r = requests.get(base, params=params, timeout=15)
            r.raise_for_status()
            data = r.json()
            status = data.get("status")
            if status in ("READY", "ERROR") or time.time() > deadline:
                return data
            time.sleep(5)
        except requests.exceptions.RequestException as e:
            return {"error": f"SSL Labs request failed: {str(e)}"}

def _grade_rank(g: str):
    """Assign rank to SSL grade"""
    order = {
        "A+": 0, "A": 1, "A-": 2, "B": 3, "C": 4, "D": 5, "E": 6, "F": 7,
        "T": 8,  # Trust issues / no grade
        None: 9
    }
    return order.get(g, 9)

def summarize_ssllabs(data: dict):
    """Summarize the SSL Labs response"""
    if not isinstance(data, dict):
        return {"error": "Invalid SSL Labs response"}

    if data.get("status") == "ERROR":
        return {"status": "ERROR", "message": data.get("statusMessage", "Unknown error")}

    endpoints = data.get("endpoints") or []
    if not endpoints:
        return {"status": data.get("status", "UNKNOWN"), "message": data.get("statusMessage", "No endpoints")}

    grades = []
    protocols = set()
    vulns = set()

    for ep in endpoints:
        g = ep.get("grade")
        if g:
            grades.append(g)

        details = ep.get("details") or {}

        # Protocols like [{"name":"TLS","version":"1.3"}, ...]
        for p in details.get("protocols", []) or []:
            name = p.get("name")
            ver = p.get("version")
            if name and ver:
                protocols.add(f"{name} {ver}")

        # Vulnerability flags of interest
        if details.get("heartbleed"):
            vulns.add("Heartbleed")
        if details.get("freak"):
            vulns.add("FREAK")
        if details.get("poodle"):
            vulns.add("POODLE (SSLv3)")
        if details.get("poodleTls"):
            vulns.add("POODLE (TLS)")
        if details.get("vulnBeast"):
            vulns.add("BEAST")
        if details.get("supportsRc4"):
            vulns.add("RC4 supported (weak)")

        # Legacy/weak protocol presence
        proto_names = {p.get("version") for p in details.get("protocols", []) if p.get("version")}
        if "1.0" in proto_names:
            vulns.add("TLS 1.0 enabled (legacy)")
        if "1.1" in proto_names:
            vulns.add("TLS 1.1 enabled (legacy)")
        # SSLv2/3م
        if any(v in ("2.0", "3.0") for v in proto_names):
            vulns.add("SSLv2/SSLv3 enabled (insecure)")

        # Insecure renegotiation?
        if details.get("renegSupport") == 2:
            vulns.add("Insecure renegotiation")

    overall_grade = None
    if grades:
        overall_grade = sorted(grades, key=_grade_rank, reverse=True)[0]

    return {
        "status": data.get("status"),
        "overall_grade": overall_grade,
        "grades": sorted(set(grades), key=_grade_rank),
        "protocols": sorted(protocols),
        "vulnerabilities": sorted(vulns),
    }

# ---------- Flask routes ----------
@app.route("/ssl", methods=["GET"])
def ssl_endpoint():
    """SSL endpoint for fetching SSL info and SSL Labs data"""
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Please provide ?domain=example.com"}), 400

    # Local certificate info
    try:
        local_info = get_local_ssl_info(domain)
    except Exception as e:
        local_info = {"error": f"Local SSL check failed: {str(e)}"}

    # Fetch SSL Labs data
    try:
        raw = fetch_ssllabs_raw(domain)
        summary = summarize_ssllabs(raw)
    except Exception as e:
        summary = {"error": f"SSL Labs fetch failed: {str(e)}"}

    return jsonify({
        "domain": domain,
        "local_certificate": local_info,
        "ssl_labs_summary": summary
    })

@app.route("/health")
def health():
    """Health check route"""
    return jsonify({"status": "ok"})
