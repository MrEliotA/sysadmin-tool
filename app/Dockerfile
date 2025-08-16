FROM python:3.12-bookworm

WORKDIR /app

# بهینه‌سازی APT: استفاده از HTTPS + mirror آلمان به عنوان fallback
RUN set -eux; \
    # اگر فایل debian.sources وجود داشت → https کن
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
        sed -i 's|http://security.debian.org|https://security.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    # اگه همچنان مشکل بود، یک sources.list جدید بسازیم (mirror آلمان)
    echo "deb https://ftp.de.debian.org/debian bookworm main contrib non-free" > /etc/apt/sources.list; \
    echo "deb https://ftp.de.debian.org/debian bookworm-updates main contrib non-free" >> /etc/apt/sources.list; \
    echo "deb https://security.debian.org/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list; \
    # آپدیت و نصب پکیج‌ها با retry
    apt-get -o Acquire::Retries=5 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# نصب پکیج‌های پایتون
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی سورس
COPY . .

EXPOSE 8086

CMD ["python", "app.py"]
