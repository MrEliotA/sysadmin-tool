from flask import Flask, request, jsonify
import dns.resolver
import dns.exception

app = Flask(__name__)

# ریزالورهای اصلی برای بخش /  (نام خوانا برای گزارش)
DNS_SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
}

# ریزالورهای گسترده برای propagation (می‌تونی کم/زیاد کنی)
PUBLIC_DNS = [
    "1.1.1.1",         # Cloudflare
    "8.8.8.8",         # Google
    "9.9.9.9",         # Quad9
    "208.67.222.222",  # OpenDNS
    "8.26.56.26",      # Comodo
]

# رکوردهایی که همزمان بررسی می‌کنیم
DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

def _safe_txt_to_string(r):
    """تبدیل TXT به استرینگ؛ با سازگاری نسخه‌های مختلف dnspython."""
    try:
        if hasattr(r, "strings") and r.strings:
            return "".join([s.decode("utf-8", "ignore") for s in r.strings])
        # fallback
        return r.to_text().strip('"')
    except Exception:
        return r.to_text()

def resolve_all_records(resolver: dns.resolver.Resolver, domain: str, record_types):
    results = {}
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "TXT":
                records = [_safe_txt_to_string(r) for r in answers]
            elif rtype == "MX":
                records = [f"{r.preference} {r.exchange.to_text()}" for r in answers]
            else:
                records = [r.to_text() for r in answers]
            results[rtype] = records
        except dns.resolver.NoAnswer:
            results[rtype] = []  # رکورد موجود نیست
        except dns.resolver.NXDOMAIN:
            results[rtype] = ["NXDOMAIN"]
        except dns.resolver.NoNameservers as e:
            results[rtype] = [f"NoNameservers: {e}"]
        except dns.exception.Timeout:
            results[rtype] = ["Timeout"]
        except Exception as e:
            results[rtype] = [f"Error: {e}"]
    return results

def build_resolver(nameserver_ip: str) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)  # از resolv.conf سیستم نخواند
    r.nameservers = [nameserver_ip]
    r.timeout = 2.0
    r.lifetime = 3.0
    return r

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/")
def dns_all():
    """
    دریافت همه‌ی رکوردها از چند ریزالور اصلی.
    ورودی: ?domain=example.com
    انتخابی: ?types=A,AAAA,MX  (اختیاری؛ اگر ندهید همه‌ی انواع پیش‌فرض برگردانده می‌شود)
    """
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter is required, e.g. /?domain=example.com"}), 400

    # امکان فیلتر رکوردها (اختیاری)
    types_param = request.args.get("types")
    if types_param:
        record_types = [t.strip().upper() for t in types_param.split(",") if t.strip()]
    else:
        record_types = DEFAULT_RECORD_TYPES

    servers_out = {}
    for label, ip in DNS_SERVERS.items():
        resolver = build_resolver(ip)
        servers_out[label] = resolve_all_records(resolver, domain, record_types)

    return jsonify({
        "domain": domain,
        "record_types": record_types,
        "servers": servers_out
    })

@app.route("/propagation")
def propagation():
    """
    بررسی انتشار (propagation) برای همه‌ی رکوردها روی چند DNS عمومی.
    ورودی: ?domain=example.com
    انتخابی: ?types=A,AAAA,... (اختیاری؛ در صورت عدم ارسال، همه‌ی انواع پیش‌فرض)
    """
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter is required, e.g. /propagation?domain=example.com"}), 400

    types_param = request.args.get("types")
    if types_param:
        record_types = [t.strip().upper() for t in types_param.split(",") if t.strip()]
    else:
        record_types = DEFAULT_RECORD_TYPES

    out = {}
    for ip in PUBLIC_DNS:
        resolver = build_resolver(ip)
        out[ip] = resolve_all_records(resolver, domain, record_types)

    return jsonify({
        "domain": domain,
        "record_types": record_types,
        "servers": out
    })

if __name__ == "__main__":
    # با Dockerfile قبلی: CMD ["python", "dns_checker.py"]
    app.run(host="0.0.0.0", port=8080)
