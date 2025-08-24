# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy the requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire app
COPY ./app /app

# Expose port
EXPOSE 8080

# Set entry point to run the Flask app
CMD ["python", "run.py"]
