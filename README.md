# Sayanox Sentinel OS

### Autonomous AI-powered system security & PC operations suite

Real-time metrics · Web terminal · ML anomaly detection · FIM · Firewall · Honeypot · Remediation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Stack](https://img.shields.io/badge/Stack-FastAPI%20%2B%20React-green)](#)

> **Note on the name:** This is **not** a from-scratch operating system kernel.  
> It is a **security operations suite** that monitors and controls a host PC/server (metrics, terminal, firewall, FIM, honeypots, anomaly detection).

---

## What it does

| Module | Purpose |
|--------|---------|
| **Live metrics** | CPU, RAM, disk, network via `psutil` + WebSockets |
| **Web terminal** | Browser shell (Xterm.js) for remote ops |
| **ML anomaly detection** | Isolation Forest on host behavior |
| **FIM** | File integrity monitoring with hashes |
| **Firewall manager** | Rule control (iptables/UFW style integration) |
| **Honeypot worker** | Decoy listeners + auto-block hooks |
| **Network scanner** | Local discovery / nmap-assisted checks |
| **Remediation engine** | Automated response playbooks |
| **JWT + RBAC** | Admin / Operator / Viewer roles |
| **Backup service** | Host backup helpers |
| **Notifications** | Webhook alerts |

---

## Repository layout

```text
sayanox-sentinel-os/
├── README.md
├── .github/workflows/
└── ai-security-dashboard/          ← main application
    ├── backend/                     FastAPI + security modules
    │   ├── main.py
    │   ├── anomaly/
    │   ├── auth/
    │   ├── fim/
    │   ├── firewall/
    │   ├── honeypot/
    │   ├── network/
    │   ├── terminal/
    │   ├── remediation/
    │   └── …
    ├── frontend/                    React (Vite) dashboard
    ├── database/
    ├── docker-compose.yml
    └── README.md                    Detailed app docs
```

---

## Quick start

```bash
git clone https://github.com/sayan9168/sayanox-sentinel-os.git
cd sayanox-sentinel-os/ai-security-dashboard

# Recommended: Docker
docker compose up --build

# Or run backend + frontend separately (see ai-security-dashboard/README.md)
```

Typical local endpoints:

- Frontend: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`

### Host dependencies (for network modules)

```bash
# Ubuntu/Debian
sudo apt-get install -y libpcap-dev nmap
```

---

## Tech stack

| Layer | Tech |
|-------|------|
| Backend | FastAPI, Python 3.11+, WebSockets |
| Frontend | React (Vite), Tailwind, Recharts, Xterm.js |
| ML | scikit-learn (Isolation Forest) |
| Host ops | psutil, scapy, nmap integration |
| Deploy | Docker Compose |

---

## Security & ethics

- Run only on machines **you own** or are **explicitly authorized** to manage.
- Firewall bans, honeypots, and packet capture can affect networks — use carefully.
- Treat JWT secrets and webhook URLs as sensitive; never commit real `.env` values.

---

## Status (honest)

- **Strengths:** Broad module coverage, real backend structure, Docker path, security-ops focus.
- **Gaps for star growth:** Root README previously oversold “OS” / “production-ready”; nested app folder can confuse newcomers; needs screenshots, short demo GIF, and pinned topics on GitHub.
- Best audience: home-lab admins, security students, people who want a self-hosted SOC-lite dashboard.

More detail: [`ai-security-dashboard/README.md`](ai-security-dashboard/README.md)

---

## Author

[Sayan Mahata](https://github.com/sayan9168) (Sayan the researcher)  
Sayanox Private Limited

MIT License — see repository license file if present.
