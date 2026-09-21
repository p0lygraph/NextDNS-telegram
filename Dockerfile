FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Set environment variables for Python in containers
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_DATA_DIR=/app/data

# Create non-root user and persistent data directory
RUN adduser -D -u 1000 appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Install dependencies and harden runtime container by removing package managers
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true && \
    rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/bin/pip* /root/.cache

# Copy application source code
COPY --chown=appuser:appuser nextdns_manager/ /app/nextdns_manager/
COPY --chown=appuser:appuser nextdns_manager_gui.py /app/

# Switch to non-root user for security
USER appuser

# Expose data directory as volume
VOLUME ["/app/data"]

# Run headless daemon
ENTRYPOINT ["python", "nextdns_manager_gui.py", "--headless"]
