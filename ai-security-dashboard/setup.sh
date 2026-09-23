#!/bin/bash

# Sayanox Sentinel OS - Setup Script
# Autonomous System Security, PC Operations & Threat Mitigation Platform

set -e

echo "========================================"
echo "Sayanox Sentinel OS - Setup Script"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_info() { echo -e "${YELLOW}→ $1${NC}"; }

# Check if running as root (required for some features)
if [ "$EUID" -ne 0 ]; then 
    print_info "Running without root privileges. Some features may be limited."
fi

# Create required directories
print_info "Creating required directories..."
mkdir -p backend/auth
mkdir -p backend/notifications
mkdir -p backend/terminal
mkdir -p backend/browser
mkdir -p database
mkdir -p chromadb_data
mkdir -p screenshots
mkdir -p skills

# Install system dependencies
print_info "Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-pip python3-venv curl wget scrot || true
elif command -v yum &> /dev/null; then
    yum install -y python3-pip python3-virtualenv curl wget || true
elif command -v apk &> /dev/null; then
    apk add --no-cache python3 py3-pip curl wget scrot || true
fi

# Install Playwright browsers
print_info "Installing Playwright browsers..."
cd backend
if [ -f requirements.txt ]; then
    pip3 install -q -r requirements.txt 2>/dev/null || pip install -q -r requirements.txt
fi
python3 -m playwright install chromium 2>/dev/null || python -m playwright install chromium 2>/dev/null || true
cd ..

# Create .env file with defaults
print_info "Creating environment configuration..."
if [ ! -f .env ]; then
    cat > .env << 'ENVEOF'
# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-in-production-$(date +%s)
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Notification Channels (optional - leave empty to disable)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
ENVEOF
    print_success "Created .env file with default configuration"
else
    print_info ".env file already exists, skipping..."
fi

# Initialize database
print_info "Initializing SQLite database..."
python3 << 'PYEOF'
import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'database', 'security_dashboard.db') if '__file__' in dir() else 'database/security_dashboard.db'
os.makedirs(os.path.dirname(db_path), exist_ok=True)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create tables
cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        cpu_percent REAL,
        memory_percent REAL,
        memory_used_gb REAL,
        memory_total_gb REAL,
        network_sent_mb REAL,
        network_recv_mb REAL,
        disk_usage_percent REAL,
        process_count INTEGER
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        source TEXT,
        severity TEXT,
        description TEXT,
        url TEXT,
        published_date TEXT,
        detected_at TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS skills_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        code_path TEXT,
        created_at TEXT NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        username TEXT,
        details TEXT,
        risk_level TEXT
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS webhook_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT
    )
''')

conn.commit()
conn.close()
print("Database initialized successfully")
PYEOF

print_success "Database initialized"

# Build frontend
print_info "Building frontend application..."
cd frontend
if [ -f package.json ]; then
    npm install --silent 2>/dev/null || npm install 2>/dev/null || true
    npm run build --silent 2>/dev/null || npm run build 2>/dev/null || true
fi
cd ..
print_success "Frontend built"

# Verify installation
print_info "Verifying installation..."
errors=0

# Check Python files
for file in backend/main.py backend/auth/jwt_auth.py backend/notifications/webhook_notifier.py backend/terminal/engine.py backend/browser/engine.py; do
    if [ -f "$file" ]; then
        print_success "Found: $file"
    else
        print_error "Missing: $file"
        ((errors++))
    fi
done

# Check Node files
if [ -f "frontend/src/App.tsx" ]; then
    print_success "Found: frontend/src/App.tsx"
else
    print_error "Missing: frontend/src/App.tsx"
    ((errors++))
fi

if [ -f "docker-compose.yml" ]; then
    print_success "Found: docker-compose.yml"
else
    print_error "Missing: docker-compose.yml"
    ((errors++))
fi

# Summary
echo ""
echo "========================================"
if [ $errors -eq 0 ]; then
    print_success "Setup completed successfully!"
    echo ""
    echo "To start the application:"
    echo "  Option 1 (Docker): docker-compose up -d"
    echo "  Option 2 (Manual):"
    echo "    cd backend && python main.py"
    echo "    cd frontend && npm run dev"
    echo ""
    echo "Access the dashboard at:"
    echo "  Frontend: http://localhost:3000"
    echo "  Backend API: http://localhost:8000"
    echo "  API Docs: http://localhost:8000/docs"
    echo ""
    echo "Default credentials:"
    echo "  Admin: admin / admin123"
    echo "  Viewer: viewer / viewer123"
else
    print_error "Setup completed with $errors errors"
    exit 1
fi
