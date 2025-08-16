FROM python:3.11-slim

WORKDIR /app

# نصب وابستگی‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کد
COPY ssl_inspector.py .

EXPOSE 8082
CMD ["python", "ssl_inspector.py"]
