# Multi-stage lightweight Python container for F5 APM Demo Portal
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install curl for health checking
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application script and certificates
COPY scripts/portal_app.py ./scripts/portal_app.py
COPY certs/ ./certs/

# Expose backend port
EXPOSE 8000

# Native healthcheck matching F5 BIG-IP LTM monitor
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Create non-root user
RUN useradd -u 1000 -m appuser && chown -R appuser:appuser /app
USER appuser

# Start the portal application
CMD ["python3", "scripts/portal_app.py"]
