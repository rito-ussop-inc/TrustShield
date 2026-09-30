# TrustShield Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Install frontend dependencies (if building frontend)
WORKDIR /app/frontend
COPY frontend/package.json .
CO/frontend/package-lock.json* 2>/dev/null || true
RUN npm ci

# Copy frontend source
COPY frontend/ .

# Build frontend (optional, for serving static files)
RUN npm run build

# Expose port
EXPOSE 8000

# Command to run
WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]