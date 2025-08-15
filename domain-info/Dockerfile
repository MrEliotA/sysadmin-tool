FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY domain_info.py /app/

EXPOSE 8083

CMD ["python", "domain_info.py"]
