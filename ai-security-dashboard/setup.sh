#!/bin/bash
set -e

echo "=========================================="
echo "AI Security Intelligence Dashboard Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "\n${GREEN}[1/5]${NC} Setting up backend..."

# Create Python virtual environment if it doesn't exist
if [ ! -d "backend/venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv backend/venv
fi

# Activate virtual environment and install dependencies
source backend/venv/bin/activate
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Install Playwright browsers
echo "Installing Playwright browsers..."
playwright install chromium

echo -e "\n${GREEN}[2/5]${NC} Setting up frontend..."

cd frontend

# Install Node dependencies
if [ ! -d "node_modules" ]; then
    echo "Installing Node dependencies..."
    npm install
fi

cd ..

echo -e "\n${GREEN}[3/5]${NC} Creating database directory..."
mkdir -p database

echo -e "\n${GREEN}[4/5]${NC} Copying skills module..."
cp backend/threat_scraper.py skills/threat_scraper.py 2>/dev/null || true

echo -e "\n${GREEN}[5/5]${NC} Setup complete!"
echo ""
echo "=========================================="
echo "To start the application:"
echo ""
echo "Option 1 - Using Docker Compose (recommended):"
echo "  docker-compose up -d"
echo ""
echo "Option 2 - Manual startup:"
echo "  # Terminal 1 - Backend:"
echo "  source backend/venv/bin/activate"
echo "  cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "  # Terminal 2 - Frontend:"
echo "  cd frontend && npm run dev"
echo ""
echo "Access the dashboard at: http://localhost:3000"
echo "API documentation at: http://localhost:8000/docs"
echo "=========================================="
