FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Phase 4 Enterprise features
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    nmap \
    libpcap-dev \
    tcpdump \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium 2>/dev/null || true

# Copy application code
COPY . .

# Create required directories
RUN mkdir -p database chromadb_data screenshots skills

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Run the application
CMD ["python", "main.py"]
