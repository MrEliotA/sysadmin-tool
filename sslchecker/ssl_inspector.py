import ssl
import socket
from datetime import datetime
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)



def parse_certificate(cert_der):
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    
    # گرفتن کلید عمومی به شکل PEM
    try:
        public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    except Exception as e:
        public_key_pem = f"Error extracting public key: {e}"

    return {
        "subject": {attr.oid._name: attr.value for attr in cert.subject},
        "issuer": {attr.oid._name: attr.value for attr in cert.issuer},
        "serial_number": str(cert.serial_number),
        "not_before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
        "not_after": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
        "days_left": (cert.not_valid_after - datetime.utcnow()).days,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key": public_key_pem,
        "extensions": {ext.oid._name: str(ext.value) for ext in cert.extensions}
    }


def get_ssl_chain(hostname, port=443, timeout=5):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert_info = parse_certificate(der_cert)

                # بررسی زنجیره گواهی (chain)
                chain = []
                if hasattr(ssock, "get_peer_cert_chain"):
                    for c in ssock.get_peer_cert_chain():
                        chain.append(parse_certificate(c.public_bytes(ssl.Encoding.DER)))

                return {
                    "hostname": hostname,
                    "version": ssock.version(),
                    "cipher": ssock.cipher()[0],
                    "key_size": ssock.cipher()[2],
                    "peer_certificate": cert_info,
                    "certificate_chain": chain
                }

    except Exception as e:
        return {"error": str(e)}

@app.route("/")
def ssl_check():
    hostname = request.args.get("domain")
    if not hostname:
        return jsonify({"error": "Domain parameter is required, e.g. /?domain=example.com"}), 400

    info = get_ssl_chain(hostname)
    return jsonify(info)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082)
