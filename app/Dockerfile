FROM python:3.12-bookworm

WORKDIR /app

#  APT:   HTTPS + mirror   fallback
RUN set -eux; \
    #   debian.sources   → https 
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources && \
        sed -i 's|http://security.debian.org|https://security.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    # sources.list germany mirrot
    echo "deb https://ftp.de.debian.org/debian bookworm main contrib non-free" > /etc/apt/sources.list; \
    echo "deb https://ftp.de.debian.org/debian bookworm-updates main contrib non-free" >> /etc/apt/sources.list; \
    echo "deb https://security.debian.org/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list; \
    # retry
    apt-get -o Acquire::Retries=5 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# pythin 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY . .

EXPOSE 8086

CMD ["python", "app.py"]
