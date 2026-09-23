# Sayanox Sentinel OS - Phase 4 Enterprise Edition

**Autonomous System Security, PC Operations & Threat Mitigation Platform**

A full-stack, enterprise-grade platform for real-time system monitoring, AI-powered threat detection, deception technology (honeypot), network analysis, firewall control, file integrity monitoring (FIM), and automated remediation.

## 🚀 Phase 4 Enterprise Upgrades

- **ML Anomaly Detection**: Isolation Forest algorithm learns normal system behavior and flags deviations
- **Honeypot Worker**: Deception technology that binds to decoy ports (23, 3389, etc.) and triggers automatic firewall blocks
- **Deep Packet Sniffing**: Real-time network traffic analysis using Scapy with WebSocket streaming
- **Nmap Integration**: Network vulnerability scanning with service/version detection and OS fingerprinting
- **PWA Support**: Progressive Web App with service worker for offline-capable dashboard

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
│   ├── anomaly/             # ML Anomaly Detection (Phase 4)
│   │   └── detector.py      # Isolation Forest implementation
│   ├── honeypot/            # Deception Technology (Phase 4)
│   │   └── worker.py        # Honeypot listener on decoy ports
│   ├── network/             # Network Analysis (Phase 4)
│   │   └── scanner.py       # Scapy sniffer + Nmap scanner
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
├── .skills/
│   └── sayanox_phase4_verified_build.py  # Phase 4 verification module
├── skills/
│   └── threat_scraper.py    # Reusable scraper skill module
├── tests/
│   ├── test_backend.py      # Pytest test suite
│   └── requirements.txt     # Test dependencies
├── docker-compose.yml       # Docker Compose configuration
└── setup.sh                 # One-click setup script
```

## Installation

### Prerequisites

**Phase 4 Dependencies** (required for ML, Honeypot, and Network modules):

```bash
# Install libpcap for Scapy packet capture
sudo apt-get install -y libpcap-dev python3-dev

# Install Nmap for network scanning
sudo apt-get install -y nmap

# Install Python dependencies
pip install scapy python-nmap scikit-learn numpy
```

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

## Phase 4 Module Details

### ML Anomaly Detector (`backend/anomaly/detector.py`)

Uses **Isolation Forest** algorithm to detect behavioral anomalies in system metrics:

- **Features Monitored**: CPU%, Memory%, Disk Usage, Process Count
- **Training**: Auto-trains after collecting 50+ samples
- **Detection**: Real-time scoring with severity levels (normal, low, medium, high, critical)
- **Configuration**:
  - `contamination`: Expected anomaly rate (default: 0.1)
  - `n_estimators`: Number of isolation trees (default: 100)
  - `threshold`: Anomaly score threshold (default: -0.5)

```python
# Check anomaly detector status
GET /api/v1/anomaly/status

# Trigger manual training
POST /api/v1/anomaly/train?min_samples=50

# Reset model
POST /api/v1/anomaly/reset
```

### Honeypot Worker (`backend/honeypot/worker.py`)

Deception technology that monitors decoy ports and automatically blocks attackers:

- **Default Decoy Ports**: 23 (Telnet), 2323, 4444 (Metasploit), 5555, 6666, 8080, 9999
- **Custom Ports**: Add any port via API
- **Auto-Response**: Triggers firewall block via callback integration
- **Logging**: Full connection attempt logging with timestamps and source IPs

```python
# Check honeypot status
GET /api/v1/honeypot/status

# Start honeypot on specific ports
POST /api/v1/honeypot/start
{
  "ports": [23, 3389]  # RDP port added
}

# View connection logs
GET /api/v1/honeypot/logs?limit=100

# Add custom decoy port
POST /api/v1/honeypot/port/add?port=3389
```

### Packet Sniffer & Nmap Scanner (`backend/network/scanner.py`)

Network traffic analysis and vulnerability scanning:

**Packet Sniffer (Scapy)**:
- Captures IP packets in real-time
- Extracts TCP/UDP/ICMP protocol details
- Streams packets via WebSocket for live viewing
- Requires `libpcap` and root/admin privileges

**Nmap Scanner**:
- Quick scan (common ports)
- Full scan (ports 1-1024 with service detection)
- Network range scanning (CIDR notation)
- OS and service version detection

```python
# Get captured packets
GET /api/v1/network/packets?limit=100

# WebSocket for live packet stream
WS /ws/packets

# Perform Nmap scan
POST /api/v1/network/scan
{
  "host": "192.168.1.1",
  "scan_type": "quick",  // or "full" or "custom"
  "ports": "21,22,80,443",
  "arguments": "-sV -O"
}

# Scan network range
POST /api/v1/network/scan/network-range?network=192.168.1.0/24&ports=22,80,443
```

## API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API health check (returns 200 OK) |
| `/api/v1/metrics` | GET | Latest system metrics |
| `/api/v1/metrics/history` | GET | Historical metrics |
| `/api/v1/threats` | GET | List threat alerts |
| `/api/v1/threats` | POST | Add new threat |
| `/api/v1/skills` | GET | List logged skills |
| `/ws/metrics` | WebSocket | Real-time metrics stream |
| `/ws/packets` | WebSocket | Live packet capture stream |

### Phase 4 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/anomaly/status` | GET | ML anomaly detector status |
| `/api/v1/anomaly/train` | POST | Train ML model manually |
| `/api/v1/anomaly/reset` | POST | Reset anomaly detection model |
| `/api/v1/honeypot/status` | GET | Honeypot worker status |
| `/api/v1/honeypot/start` | POST | Start honeypot on decoy ports |
| `/api/v1/honeypot/stop` | POST | Stop honeypot |
| `/api/v1/honeypot/logs` | GET | Get honeypot connection logs |
| `/api/v1/honeypot/port/add` | POST | Add decoy port |
| `/api/v1/honeypot/port/remove` | DELETE | Remove decoy port |
| `/api/v1/network/packets` | GET | Get captured packets |
| `/api/v1/network/sniffer/start` | POST | Start packet sniffer |
| `/api/v1/network/sniffer/stop` | POST | Stop packet sniffer |
| `/api/v1/network/sniffer/status` | GET | Sniffer status |
| `/api/v1/network/scan` | POST | Perform Nmap scan |
| `/api/v1/network/scan/history` | GET | Scan history |
| `/api/v1/network/scan/network-range` | POST | Scan network range |

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
| `/api/v1/backup/restore` | POST | Restore from backup |

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

## Running Phase 4 Verification

To verify the Phase 4 build status:

```bash
cd ai-security-dashboard/backend
PYTHONPATH=/workspace/ai-security-dashboard/backend python /workspace/ai-security-dashboard/.skills/sayanox_phase4_verified_build.py
```

This will:
1. Import and validate all Phase 4 modules
2. Check ML model configuration
3. Verify honeypot port bindings
4. Confirm Scapy and Nmap availability
5. Generate a comprehensive verification report

## Technologies

**Backend:**
- FastAPI with async support
- WebSocket for real-time streaming
- Playwright for web scraping
- SQLite for persistent storage
- psutil for system metrics
- JWT authentication
- **scikit-learn** for ML anomaly detection (Phase 4)
- **Scapy** for packet capture (Phase 4)
- **python-nmap** for network scanning (Phase 4)

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
