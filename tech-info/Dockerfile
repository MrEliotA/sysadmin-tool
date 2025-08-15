FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tech_scanner.py .

EXPOSE 8085

CMD ["python", "tech_scanner.py"]
