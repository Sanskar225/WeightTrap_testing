# WEIGHTTRAP — Production Container Specification
FROM python:3.11-slim

LABEL maintainer="WEIGHTTRAP AI Security Team"
LABEL description="Autonomous Control Plane for AI-Native Financial Infrastructure"
LABEL version="1.2.0"

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Expose FastAPI REST API port
EXPOSE 8000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start FastAPI control plane server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
