# SentinelASM - Production Dockerfile
FROM python:3.12-slim AS base

# Nmap is required by the port-scanning module (python-nmap wraps the nmap
# binary, it does not ship it).
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/instance /app/logs /app/reports

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1 \
    PORT=8000

EXPOSE 8000

# 4 workers is a sane default for small/medium deployments; tune via
# GUNICORN_WORKERS at runtime if needed.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120", "app:app"]
