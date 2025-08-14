FROM php:8.2-cli

# ابزارهای لازم
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/ /app/

# پورت قابل تنظیم
ENV PORT=8080

# Healthcheck (اپ ساده‌مون مسیر /health دارد)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:${PORT}/health || exit 1

# اجرای سرور داخلی PHP
CMD ["sh", "-lc", "php -S 0.0.0.0:${PORT} index.php"]
