# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
# PLAYWRIGHT_BROWSERS_PATH: shared location so the non-root user can find Chromium
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# curl is used by HEALTHCHECK
# libatomic1 is required by Playwright's bundled Node driver (missing from slim/trixie images)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies (+ production WSGI server)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Install Playwright Chromium + OS dependencies into the shared path
RUN playwright install --with-deps chromium && \
    chmod -R a+rX /ms-playwright

# Copy application files
COPY . .

# Create necessary directories and non-root user for security
RUN mkdir -p /app/forensics_input /app/report_files /app/temp && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/api/dp-forensic/health || exit 1

# Run the application with gunicorn (production WSGI server)
# - 1 worker: FILE_REGISTRY in api.py is in-process memory; multiple workers
#   would break download lookups. Threads provide concurrency instead.
# - 600s timeout: report generation / PDF rendering can be long-running.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", \
     "--timeout", "600", "--access-logfile", "-", "api:app"]
