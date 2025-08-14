from flask import Flask, request, jsonify
import dns.resolver

app = Flask(__name__)

# DNS سرورهایی که میخوایم تست کنیم
DNS_SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9"
}

@app.route("/")
def dns_check():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    results = {}
    for provider, server in DNS_SERVERS.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            answers = resolver.resolve(domain, "A")
            results[provider] = [str(r) for r in answers]
        except Exception as e:
            results[provider] = f"Error: {e}"

    return jsonify(results)

@app.route("/propagation")
def propagation_check():
    domain = request.args.get("domain")
    record_type = request.args.get("type", "A")

    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    results = {}
    for provider, server in DNS_SERVERS.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            answers = resolver.resolve(domain, record_type)
            results[provider] = [str(r) for r in answers]
        except Exception as e:
            results[provider] = f"Error: {e}"

    return jsonify({
        "domain": domain,
        "record_type": record_type,
        "results": results
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
