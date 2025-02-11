FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Optionally create a directory for logs
RUN mkdir -p /app/logs

EXPOSE 5000

CMD ["python", "app.py"]
