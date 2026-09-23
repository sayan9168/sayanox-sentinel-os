# Sayanox Sentinel OS

**Autonomous System Security, PC Operations & Threat Mitigation Platform**

A full-stack, autonomous platform for real-time system monitoring, security threat intelligence, firewall control, file integrity monitoring (FIM), and automated remediation.

## Features

- **Real-time System Metrics**: CPU, Memory, Network I/O, Disk usage via WebSocket streaming
- **Security Threat Intelligence**: Automated scraping from CISA and NVD sources
- **Autonomous Remediation Engine**: Self-healing capabilities for detected threats
- **File Integrity Monitoring (FIM)**: Real-time file change detection and baseline auditing
- **Firewall Control**: IP blocking/unblocking with persistent rule management
- **MCP Tool Integration**: System health checks, network scans, process listing, security audits
- **Responsive Dark-themed UI**: Cyber-aesthetic design with TailwindCSS and Lucide icons
- **Persistent Storage**: SQLite database for metrics history, threat logs, and audit trails
- **Reusable Skills Module**: Modular scraper that can be executed independently

## Architecture

```
ai-security-dashboard/
├── backend/
│   ├── main.py              # FastAPI application with WebSocket support
│   ├── threat_scraper.py    # Playwright-based security threat scraper
│   ├── mcp_tools.py         # MCP tool wrappers for system checks
│   ├── requirements.txt     # Python dependencies
│   ├── Dockerfile           # Backend container configuration
│   ├── auth/                # JWT authentication module
│   ├── fim/                 # File Integrity Monitoring service
│   ├── firewall/            # Firewall management module
│   ├── remediation/         # Autonomous remediation engine
│   ├── backup/              # Backup service
│   ├── gui/                 # GUI streaming module
│   ├── browser/             # Browser automation
│   ├── terminal/            # Terminal engine
│   └── notifications/       # Webhook notifier (Telegram, Discord, Slack)
├── frontend/
│   ├── src/
│   │   ├── App.tsx          # Main React application
│   │   ├── main.tsx         # React entry point
│   │   └── index.css        # TailwindCSS styles
│   ├── package.json         # Node dependencies
│   ├── vite.config.ts       # Vite configuration
│   ├── tailwind.config.js   # TailwindCSS configuration
│   └── Dockerfile           # Frontend container configuration
├── database/
│   └── security_dashboard.db  # SQLite database (created on first run)
├── skills/
│   └── threat_scraper.py    # Reusable scraper skill module
├── tests/
│   ├── test_backend.py      # Pytest test suite
│   └── requirements.txt     # Test dependencies
├── docker-compose.yml       # Docker Compose configuration
└── setup.sh                 # One-click setup script
```

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
cd ai-security-dashboard
docker-compose up -d
```

Access:
- Dashboard: http://localhost:3000
- API Docs: http://localhost:8000/docs

### Option 2: Manual Setup

```bash
cd ai-security-dashboard
chmod +x setup.sh
./setup.sh
```

Then start services:

**Terminal 1 - Backend:**
```bash
source backend/venv/bin/activate
cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend && npm run dev
```

## API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/api/v1/metrics` | GET | Latest system metrics |
| `/api/v1/metrics/history` | GET | Historical metrics |
| `/api/v1/threats` | GET | List threat alerts |
| `/api/v1/threats` | POST | Add new threat |
| `/api/v1/skills` | GET | List logged skills |
| `/ws/metrics` | WebSocket | Real-time metrics stream |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Login and receive JWT tokens |
| `/api/v1/auth/refresh` | POST | Refresh access token |
| `/api/v1/auth/logout` | POST | Logout and invalidate tokens |

### Remediation Engine Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/remediation/rules` | GET | Get all remediation rules |
| `/api/v1/remediation/rules/{rule_id}/toggle` | POST | Enable/disable a rule |
| `/api/v1/remediation/log` | GET | Get remediation action log |
| `/api/v1/threats/auto-remediate` | POST | Trigger auto-remediation |

### File Integrity Monitoring (FIM) Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/fim/watch` | POST | Add path to FIM monitoring |
| `/api/v1/fim/baseline` | POST | Create/update baseline hashes |
| `/api/v1/fim/audit` | GET | Get FIM audit log |
| `/api/v1/fim/status` | GET | Get FIM service status |
| `/api/v1/fim/start` | POST | Start FIM service |
| `/api/v1/fim/stop` | POST | Stop FIM service |

### Firewall Control Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/firewall/block` | POST | Block an IP address |
| `/api/v1/firewall/unblock` | POST | Unblock an IP address |
| `/api/v1/firewall/rules` | GET | Get all firewall rules |

### Backup & Recovery Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/backup/create` | POST | Create system backup |
| `/api/v1/backup/list` | GET | List available backups |
| `/api/v1/backup/restore/{backup_id}` | POST | Restore from backup |

### GUI Streaming Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/gui/stream` | GET | Get GUI video stream URL |
| `/api/v1/gui/screenshot` | POST | Capture screenshot |
| `/api/v1/gui/control` | POST | Send keyboard/mouse input |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET_KEY` | Secret key for JWT token signing | Auto-generated |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token expiration time | 30 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiration time | 7 |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for notifications | (empty) |
| `TELEGRAM_CHAT_ID` | Telegram chat ID for notifications | (empty) |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL for notifications | (empty) |
| `SLACK_WEBHOOK_URL` | Slack webhook URL for notifications | (empty) |

## Running Tests

```bash
cd tests
pip install -r requirements.txt
pytest test_backend.py -v
```

## Technologies

**Backend:**
- FastAPI with async support
- WebSocket for real-time streaming
- Playwright for web scraping
- SQLite for persistent storage
- psutil for system metrics
- JWT authentication

**Frontend:**
- React 18 with TypeScript
- Vite for build tooling
- TailwindCSS for styling
- Recharts for data visualization
- Lucide React for icons

**DevOps:**
- Docker & Docker Compose
- Automated setup scripts

## License

MIT License
