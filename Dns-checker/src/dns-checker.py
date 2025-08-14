from flask import Flask, request, jsonify
import dns.resolver

app = Flask(__name__)

# لیست DNS سرورهای پیش‌فرض
DNS_SERVERS = {
    "Google DNS": "8.8.8.8",
    "Cloudflare DNS": "1.1.1.1",
    "Quad9 DNS": "9.9.9.9"
}

# رکوردهایی که بررسی می‌کنیم
RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']

# لیست DNS عمومی برای propagation check
PUBLIC_DNS = [
    '1.1.1.1',       # Cloudflare
    '8.8.8.8',       # Google
    '9.9.9.9',       # Quad9
    '208.67.222.222',# OpenDNS
    '8.26.56.26',    # Comodo Secure DNS
]

@app.route('/health')
def health_check():
    """بررسی سلامت سرویس"""
    return jsonify({"status": "ok", "message": "DNS Checker is running"}), 200

@app.route('/')
def check_dns():
    """بررسی رکوردهای مختلف DNS از چند سرور"""
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain parameter is required, e.g. /?domain=example.com"}), 400

    results = {}
    for name, server in DNS_SERVERS.items():
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        server_results = {}
        for record_type in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, record_type)
                if record_type == 'MX':
                    server_results[record_type] = [f"{r.exchange} {r.preference}" for r in answers]
                elif record_type == 'TXT':
                    server_results[record_type] = [b''.join(r.strings).decode('utf-8') for r in answers]
                else:
                    server_results[record_type] = [r.to_text() for r in answers]
            except Exception as e:
                server_results[record_type] = f"Error: {str(e)}"
        results[name] = server_results

    return jsonify({"domain": domain, "results": results})

@app.route('/propagation')
def check_propagation():
    """بررسی انتشار رکورد در DNS های عمومی"""
    domain = request.args.get('domain')
    record_type = request.args.get('type', 'A')
    if not domain:
        return jsonify({"error": "Domain parameter is required, e.g. /propagation?domain=example.com"}), 400

    propagation = {}
    for server in PUBLIC_DNS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        try:
            answers = resolver.resolve(domain, record_type)
            propagation[server] = [r.to_text() for r in answers]
        except Exception as e:
            propagation[server] = f"Error: {str(e)}"

    return jsonify({"domain": domain, "record_type": record_type, "propagation": propagation})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
