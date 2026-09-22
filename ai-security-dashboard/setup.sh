#!/bin/bash

# AI Security Dashboard - Setup Script
# Enterprise-Grade Autonomous PC Operations Suite
# Zero-configuration startup with self-healing

set -e

echo "=============================================="
echo "AI Security Dashboard - Setup & Launch"
echo "Enterprise-Grade Autonomous PC Operations Suite"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PYTHON_CMD="python3"
PIP_CMD="pip3"
NODE_CMD="node"
NPM_CMD="npm"

# Self-healing retry configuration
MAX_RETRIES=3
RETRY_DELAY=5

# Function to print colored messages
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_info() { echo "→ $1"; }

# Function to check command availability
check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function with retry logic
retry_command() {
    local cmd="$1"
    local description="$2"
    local attempt=1
    
    while [ $attempt -le $MAX_RETRIES ]; do
        print_info "Attempting: $description (Attempt $attempt/$MAX_RETRIES)"
        
        if eval "$cmd"; then
            print_success "$description completed successfully"
            return 0
        fi
        
        print_warning "Attempt $attempt failed. Retrying in ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
        attempt=$((attempt + 1))
    done
    
    print_error "$description failed after $MAX_RETRIES attempts"
    return 1
}

# Check system dependencies
print_info "Checking system dependencies..."

# Check Python
if ! check_command "$PYTHON_CMD"; then
    PYTHON_CMD="python"
    if ! check_command "$PYTHON_CMD"; then
        print_error "Python not found. Please install Python 3.8+"
        exit 1
    fi
fi
print_success "Python found: $($PYTHON_CMD --version)"

# Check pip
if ! check_command "$PIP_CMD"; then
    PIP_CMD="pip"
    if ! check_command "$PIP_CMD"; then
        print_error "pip not found. Please install pip"
        exit 1
    fi
fi
print_success "pip found: $($PIP_CMD --version)"

# Check Node.js (optional, for frontend)
if check_command "$NODE_CMD"; then
    print_success "Node.js found: $($NODE_CMD --version)"
else
    print_warning "Node.js not found. Frontend development will be limited."
fi

# Install Playwright browsers
print_info "Installing Playwright browsers..."
retry_command "$PYTHON_CMD -m playwright install chromium" "Playwright browser installation" || {
    print_warning "Playwright browser installation failed. Will continue without it."
}

# Install backend dependencies
print_info "Installing backend Python dependencies..."
cd "$(dirname "$0")/backend"
retry_command "$PIP_CMD install -r requirements.txt" "Backend dependencies installation" || {
    print_error "Failed to install backend dependencies"
    exit 1
}
cd ..

# Install frontend dependencies (if Node.js available)
if check_command "$NODE_CMD"; then
    print_info "Installing frontend dependencies..."
    cd "$(dirname "$0")/frontend"
    retry_command "$NPM_CMD install" "Frontend dependencies installation" || {
        print_warning "Frontend dependencies installation failed"
    }
    cd ..
fi

# Create necessary directories
print_info "Creating data directories..."
mkdir -p backend/data
mkdir -p screenshots
mkdir -p skills
print_success "Directories created"

# Initialize database
print_info "Initializing database..."
$PYTHON_CMD -c "
import sys
sys.path.insert(0, '.')
from backend.services.database import DatabaseManager
db = DatabaseManager()
db.initialize()
print('Database initialized successfully')
" || print_warning "Database initialization had issues"

# Generate .env file from template if it doesn't exist
if [ ! -f ".env" ]; then
    print_info "Creating .env file..."
    cat > .env << 'EOF'
# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-in-production-abc123xyz789

# Notification Channels (optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=

# Default notification channels
NOTIFICATION_CHANNELS=discord
EOF
    print_success ".env file created"
fi

# Print summary
echo ""
echo "=============================================="
print_success "Setup completed successfully!"
echo "=============================================="
echo ""
echo "Default Credentials:"
echo "  Admin:  admin / admin123"
echo "  Viewer: viewer / viewer123"
echo ""
echo "To start the application:"
echo "  Option 1 - Docker Compose:"
echo "    docker-compose up -d"
echo ""
echo "  Option 2 - Direct Run:"
echo "    cd backend && python main.py"
echo ""
echo "API Documentation:"
echo "  http://localhost:8000/docs"
echo ""
echo "Frontend (after building):"
echo "  http://localhost:3000"
echo "=============================================="

exit 0
