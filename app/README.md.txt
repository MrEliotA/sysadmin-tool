Domain Inspector — Lightweight OSINT 

A minimal front-end (static SPA served by Nginx) for a Python/Flask OSINT API.
Enter a domain/IP and the UI fetches and displays:

DNS (Cloudflare & Google resolvers, one record per line)

SSL (days left, grade, certificate details)

IP info (ordered, friendly key/value)

Domain (WHOIS) info (ordered with keys)

Analyze (technologies, open ports + banners, subdomains)

DNS Propagation (per-resolver records, green when in consensus, red when differing)

The UI is RTL-friendly and includes quick copy buttons and an optional ?q= autorun.