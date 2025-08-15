FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY ip_info.py /app/

EXPOSE 8084

CMD ["python", "ip_info.py"]
