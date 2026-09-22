# Sayanox Sentinel OS v3.0.0

## Autonomous System Security, PC Operations & Threat Mitigation Platform

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/fastapi-0.100+-green)
![React](https://img.shields.io/badge/react-18.x-blue)

---

## Overview

**Sayanox Sentinel OS** is an enterprise-grade, full-stack autonomous security platform that provides real-time system monitoring, threat detection, automated remediation, and remote PC control capabilities. Built with FastAPI backend, React frontend, and powered by AI-driven automation engines.

### Key Capabilities

- 🔒 **Real-time System Monitoring** - CPU, RAM, Disk, Network metrics via WebSockets
- 💻 **Interactive Web Terminal** - Full CLI access via Xterm.js with secure WebSocket connection
- 🛡️ **Threat Detection** - Automated CVE scraping from NVD/CISA with severity classification
- ⚡ **Autonomous Remediation** - Auto-kill suspicious processes, block malicious IPs
- 🔥 **Firewall Control** - Native iptables/netsh integration for IP blocking
- 🌐 **Browser Automation** - Playwright-powered screenshots and web interaction
- 📱 **Multi-Channel Alerts** - Telegram, Discord, Slack webhook notifications
- 🔐 **JWT Authentication** - RBAC with Admin/Viewer roles
- 📊 **File Integrity Monitoring** - Watchdog/inotify-based critical file protection
- ☁️ **Cloud Backup** - S3, GCS, Azure Blob, SFTP synchronization
- 🧠 **Persistent Memory** - SQLite + ChromaDB vector storage for threat patterns

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SAYANOX SENTINEL OS                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   React UI  │  │  FastAPI    │  │   Playwright Browser    │ │
│  │  (Port 3000)│◄─┤  (Port 8000)│◄─┤   Automation Engine     │ │
│  │  Xterm.js   │  │  WebSocket  │  │   (Screenshots, DOM)    │ │
│  └─────────────┘  └──────┬──────┘  └─────────────────────────┘ │
│                          │                                      │
│  ┌───────────────────────┼──────────────────────────────────┐  │
│  │                       ▼                                  │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │  │
│  │  │   SQLite    │ │  ChromaDB   │ │   System Control    │ │  │
│  │  │  Database   │ │ Vector Store│ │   (Process, Net)    │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │  │
│  │                                                          │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │  │
│  │  │     FIM     │ │Remediation  │ │    Notification     │ │  │
│  │  │  (Watchdog) │ │   Engine    │ │   Gateway           │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+ (optional, for frontend development)
- Docker & Docker Compose (recommended)
- Playwright browsers (auto-installed)

### Installation

#### Option 1: Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/your-org/sayanox-sentinel-os.git
cd sayanox-sentinel-os

# Configure environment variables
cp .env.example .env
# Edit .env with your JWT secret and notification tokens

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

#### Option 2: Direct Installation

```bash
# Run setup script
chmod +x setup.sh
./setup.sh

# Start backend
cd backend
python main.py

# In another terminal, start frontend
cd frontend
npm install
npm run dev
```

---

## Default Credentials

| Role   | Username | Password   | Permissions                              |
|--------|----------|------------|------------------------------------------|
| Admin  | admin    | admin123   | Full terminal access, process killing, firewall edit |
| Viewer | viewer   | viewer123  | Metrics & threat tables only             |

⚠️ **IMPORTANT**: Change default credentials in production!

---

## Environment Variables

### Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET_KEY` | Yes | `sayanox-super-secret-jwt-key...` | JWT signing key (CHANGE IN PRODUCTION!) |
| `DATABASE_URL` | No | `sqlite:///data/security_dashboard.db` | Database connection string |

### Notification Channels

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Target chat ID for alerts |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `NOTIFICATION_CHANNELS` | Comma-separated list: `discord,telegram,slack` |

### Cloud Backup (Optional)

| Variable | Description |
|----------|-------------|
| `CLOUD_BACKUP_ENABLED` | Enable/disable cloud backup (`true`/`false`) |
| `S3_BUCKET` | AWS S3 bucket name |
| `S3_ACCESS_KEY` | AWS access key ID |
| `S3_SECRET_KEY` | AWS secret access key |
| `GCS_BUCKET` | Google Cloud Storage bucket |
| `AZURE_CONTAINER` | Azure Blob container name |
| `AZURE_CONNECTION_STRING` | Azure storage connection string |
| `SFTP_HOST` | SFTP server hostname |
| `SFTP_USER` | SFTP username |
| `SFTP_PASSWORD` | SFTP password |

### File Integrity Monitoring

| Variable | Description |
|----------|-------------|
| `FIM_CRITICAL_PATHS` | Comma-separated paths to monitor |
| `AUTO_REMEDIATION_ENABLED` | Enable autonomous threat response |
| `CPU_THRESHOLD` | CPU alert threshold percentage (default: 90) |
| `MEMORY_THRESHOLD` | Memory alert threshold percentage (default: 90) |

---

## API Documentation

Once running, access interactive API docs at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

#### Authentication
```
POST   /api/v1/auth/login          # Get JWT token
POST   /api/v1/auth/register       # Register new user
GET    /api/v1/auth/me             # Get current user
```

#### System Metrics
```
GET    /api/v1/metrics/current     # Current system metrics
GET    /api/v1/metrics/history     # Historical metrics
WS     /ws/metrics                 # Real-time WebSocket stream
```

#### Threat Management
```
GET    /api/v1/threats/recent      # Recent threats
GET    /api/v1/threats/stats       # Threat statistics
POST   /api/v1/threats/remediate   # Trigger remediation
```

#### System Control (Admin Only)
```
POST   /api/v1/system/kill-process # Kill process by PID
POST   /api/v1/system/block-ip     # Block IP via firewall
POST   /api/v1/system/unblock-ip   # Unblock IP
GET    /api/v1/system/processes    # List running processes
GET    /api/v1/system/network      # Network connections
```

#### Browser Automation
```
POST   /api/v1/browser/screenshot  # Capture screenshot
POST   /api/v1/browser/navigate    # Navigate to URL
GET    /api/v1/browser/status      # Browser status
```

#### File Integrity Monitoring
```
GET    /api/v1/fim/events          # FIM event log
POST   /api/v1/fim/configure       # Configure monitored paths
```

#### Backup
```
POST   /api/v1/backup/create       # Create backup
GET    /api/v1/backup/list         # List available backups
POST   /api/v1/backup/restore      # Restore from backup
```

---

## Project Structure

```
sayanox-sentinel-os/
├── backend/
│   ├── main.py                 # FastAPI application entry point
│   ├── requirements.txt        # Python dependencies
│   ├── models/
│   │   └── schemas.py          # Pydantic models
│   ├── routers/
│   │   ├── auth.py             # Authentication routes
│   │   ├── metrics.py          # Metrics endpoints
│   │   ├── threats.py          # Threat management
│   │   ├── system.py           # System control APIs
│   │   ├── browser.py          # Browser automation
│   │   ├── fim.py              # File integrity monitoring
│   │   ├── remediation.py      # Autonomous remediation
│   │   ├── backup.py           # Backup service
│   │   └── notifications.py    # Alert configuration
│   ├── services/
│   │   ├── database.py         # SQLite manager
│   │   ├── metrics_collector.py # System metrics
│   │   ├── threat_scraper.py   # CVE/NVD scraper
│   │   ├── system_control.py   # Process/network control
│   │   ├── browser_automation.py # Playwright wrapper
│   │   ├── notification_service.py # Multi-channel alerts
│   │   ├── fim_service.py      # File integrity monitoring
│   │   ├── remediation_engine.py # Auto-remediation logic
│   │   └── backup_service.py   # Cloud/local backup
│   └── middleware/
│       ├── auth.py             # JWT authentication
│       └── security.py         # Rate limiting, audit logging
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main React component
│   │   ├── components/
│   │   │   ├── MetricCard.jsx
│   │   │   ├── MetricsChart.jsx
│   │   │   ├── ThreatTable.jsx
│   │   │   ├── Terminal.jsx    # Xterm.js terminal
│   │   │   └── ActionCenter.jsx # Control panel
│   │   ├── hooks/
│   │   │   └── useWebSocket.js
│   │   └── services/
│   │       └── api.js          # API client
│   ├── package.json
│   └── vite.config.js
├── skills/                     # Persistent skill modules
│   ├── __init__.py
│   ├── threat_scraper.py
│   └── copy_to_persistent.py
├── backup/                     # Backup storage directory
├── screenshots/                # Browser screenshots
├── docker-compose.yml          # Docker orchestration
├── setup.sh                    # Zero-config setup script
└── README.md                   # This file
```

---

## Core Features Deep Dive

### 1. Interactive Web Terminal

The built-in terminal provides full CLI access to the host system:
- Xterm.js-powered terminal emulator
- Secure WebSocket connection with JWT authentication
- Command history and tab completion
- Session management for multiple concurrent users
- Audit logging of all executed commands

### 2. Autonomous Remediation Engine

Automatically responds to detected threats:
- Monitors system metrics and threat alerts
- Triggers pre-approved isolation rules
- Kills suspicious processes exceeding resource thresholds
- Blocks malicious IPs from threat intelligence feeds
- Logs all actions for audit compliance

### 3. File Integrity Monitoring (FIM)

Real-time monitoring of critical files:
- Uses watchdog (Linux) / ReadDirectoryChangesW (Windows)
- Detects modifications, deletions, and permission changes
- Configurable monitoring paths via environment variables
- Instant alerts on unauthorized changes
- Integration with remediation engine for auto-response

### 4. Browser Automation

Playwright-powered web interaction:
- Headless Chromium browser instances
- Screenshot capture with configurable viewport
- DOM element interaction and form filling
- Navigation history and session management
- Visual logs streamed to React UI

### 5. Multi-Channel Notifications

Alert delivery to multiple platforms:
- **Telegram**: Bot-based direct messages
- **Discord**: Webhook to channels
- **Slack**: Incoming webhook integration
- Configurable per-severity routing
- Rate-limited to prevent spam

### 6. Cloud Backup

Automated backup to cloud providers:
- **AWS S3**: Bucket-based storage with encryption
- **Google Cloud Storage**: GCS native integration
- **Azure Blob**: Container-based backup
- **SFTP**: Traditional file transfer
- Encrypted compression before upload
- Scheduled automatic backups

---

## Security Considerations

### Authentication & Authorization

- JWT tokens with configurable expiration
- Role-Based Access Control (RBAC):
  - **Admin**: Full system access including terminal, process kill, firewall
  - **Viewer**: Read-only metrics and threat data
- Rate limiting on sensitive endpoints
- Command sanitization for OS-level operations

### Network Security

- CORS configuration for cross-origin requests
- WebSocket connection validation
- Firewall rule auditing
- IP allowlisting capability

### Data Protection

- Encrypted backup compression
- Secure credential storage (environment variables)
- Audit logging for all security events
- SQLite database with WAL mode for integrity

---

## Troubleshooting

### Common Issues

#### Backend won't start
```bash
# Check Python version
python --version  # Must be 3.8+

# Install dependencies manually
cd backend
pip install -r requirements.txt

# Check database permissions
chmod 755 backend/data
```

#### Playwright browsers missing
```bash
python -m playwright install chromium
python -m playwright install-deps
```

#### Frontend build fails
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### Docker permission errors
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo
sudo docker-compose up -d
```

### Viewing Logs

```bash
# Docker logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Direct run logs
tail -f backend/data/app.log
```

---

## Development

### Running Tests

```bash
cd backend
pytest tests/ -v

# With coverage
pytest tests/ --cov=backend --cov-report=html
```

### Hot Reload

Backend (with auto-reload):
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Frontend (Vite dev server):
```bash
cd frontend
npm run dev
```

### Adding New Skills

Create skill modules in `.skills/` directory:

```python
# .skills/my_custom_skill.py
from backend.services.database import DatabaseManager

def execute(db: DatabaseManager, **kwargs):
    """Custom skill implementation"""
    # Your logic here
    return {"status": "success", "data": result}
```

---

## API Examples

### Authenticate and Get Token

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Get Current Metrics

```bash
curl "http://localhost:8000/api/v1/metrics/current" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Kill a Process

```bash
curl -X POST "http://localhost:8000/api/v1/system/kill-process" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pid": 1234}'
```

### Block an IP Address

```bash
curl -X POST "http://localhost:8000/api/v1/system/block-ip" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "Suspicious activity"}'
```

### Create Backup

```bash
curl -X POST "http://localhost:8000/api/v1/backup/create" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Python: Follow PEP 8 with Black formatting
- JavaScript/React: ESLint + Prettier configuration
- Commits: Conventional Commits specification

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Support

- **Documentation**: https://docs.sayanox.io
- **Issues**: https://github.com/your-org/sayanox-sentinel-os/issues
- **Discussions**: https://github.com/your-org/sayanox-sentinel-os/discussions

---

## Changelog

### v3.0.0 - Sayanox Sentinel OS Release

- ✨ Rebranded to Sayanox Sentinel OS
- 🆕 Added autonomous remediation engine
- 🆕 File Integrity Monitoring (FIM) with watchdog
- 🆕 Cloud backup support (S3, GCS, Azure, SFTP)
- 🆕 Dynamic firewall integration (iptables/netsh)
- 🆕 Enhanced RBAC with command sanitization
- 🆕 Remote GUI streaming capability
- 🔧 Updated Docker Compose with host mounts
- 🔧 Improved setup.sh with self-healing

### v2.0.0 - PC Operations Suite

- Interactive web terminal (Xterm.js)
- Process management and network inspection
- Browser automation with Playwright
- Multi-channel notifications

### v1.0.0 - Initial Release

- Real-time system metrics
- Threat detection and scraping
- Basic React dashboard

---

**Built with ❤️ by the Sayanox Team**
