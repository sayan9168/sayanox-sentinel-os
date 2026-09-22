# AI-Powered System Resource & Security Intelligence Dashboard

A full-stack, autonomous dashboard for real-time system monitoring, security threat intelligence, and automated web scraping.

## Features

- **Real-time System Metrics**: CPU, Memory, Network I/O, Disk usage via WebSocket streaming
- **Security Threat Intelligence**: Automated scraping from CISA and NVD sources
- **MCP Tool Integration**: System health checks, network scans, process listing, security audits
- **Responsive Dark-themed UI**: Cyber-aesthetic design with TailwindCSS and Lucide icons
- **Persistent Storage**: SQLite database for metrics history and threat logs
- **Reusable Skills Module**: Modular scraper that can be executed independently

## Architecture

```
ai-security-dashboard/
├── backend/
│   ├── main.py              # FastAPI application with WebSocket support
│   ├── threat_scraper.py    # Playwright-based security threat scraper
│   ├── mcp_tools.py         # MCP tool wrappers for system checks
│   ├── requirements.txt     # Python dependencies
│   └── Dockerfile           # Backend container configuration
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

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/api/v1/metrics` | GET | Latest system metrics |
| `/api/v1/metrics/history` | GET | Historical metrics |
| `/api/v1/threats` | GET | List threat alerts |
| `/api/v1/threats` | POST | Add new threat |
| `/api/v1/skills` | GET | List logged skills |
| `/ws/metrics` | WebSocket | Real-time metrics stream |

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
