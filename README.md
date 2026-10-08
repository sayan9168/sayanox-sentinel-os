# Sayanox Sentinel OS

### Autonomous AI-powered system security & PC operations suite

Real-time metrics · Web terminal · ML anomaly detection · FIM · Firewall · Honeypot · Remediation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![security](https://img.shields.io/badge/topic-security-red)](#)
[![homelab](https://img.shields.io/badge/topic-homelab-blue)](#)
[![monitoring](https://img.shields.io/badge/topic-monitoring-green)](#)
[![honeypot](https://img.shields.io/badge/topic-honeypot-orange)](#)

<p align="center">
  <img src="docs/banner.svg" alt="Sayanox Sentinel — Security Operations Suite" width="100%">
</p>

> **Note on the name:** This is **not** a from-scratch operating system kernel.  
> It is a **security operations suite** that monitors and controls a host PC/server.

---

## 📂 Where is the app? (start here)

**All runnable code lives in one folder:**

| Path | What it is |
|------|------------|
| **[`ai-security-dashboard/`](ai-security-dashboard/)** | ✅ **Main application** — backend + frontend + Docker |
| [`ai-security-dashboard/backend/`](ai-security-dashboard/backend/) | FastAPI API, modules, ML, honeypot, FIM… |
| [`ai-security-dashboard/frontend/`](ai-security-dashboard/frontend/) | React (Vite) dashboard UI |
| [`ai-security-dashboard/docker-compose.yml`](ai-security-dashboard/docker-compose.yml) | One-command local stack |
| [`ai-security-dashboard/README.md`](ai-security-dashboard/README.md) | Full module & API docs |

```bash
# Clone → enter the app folder → run
git clone https://github.com/sayan9168/sayanox-sentinel-os.git
cd sayanox-sentinel-os/ai-security-dashboard
docker compose up --build
```

Then open:

- **Dashboard:** http://localhost:3000  
- **API docs:** http://localhost:8000/docs  

---

## 📸 Screenshots / demo

Banner above ships with the repo. **Product screenshots** go in [`docs/screenshots/`](docs/screenshots/) — after you capture them, they show here:

<!-- Uncomment after adding real files:
![Dashboard](docs/screenshots/dashboard.png)
![Web terminal](docs/screenshots/terminal.png)
![Demo GIF](docs/screenshots/demo.gif)
-->

**How to add (2 minutes):**

1. Run the stack (`cd ai-security-dashboard && docker compose up --build`)
2. Screenshot dashboard / terminal / honeypot panel
3. Save as `docs/screenshots/dashboard.png` (and optional `demo.gif`)
4. Uncomment the image lines above and push

See [`docs/screenshots/README.md`](docs/screenshots/README.md).

---

## Topics (GitHub Discoverability)

Recommended repository topics (set in GitHub UI → **About** → ⚙ → Topics):

`fastapi` · `security` · `homelab` · `monitoring` · `honeypot` · `python` · `react` · `docker` · `anomaly-detection` · `fim`

*(MCP cannot set topics automatically — pin them once in the repo settings.)*

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
├── README.md                      ← you are here
├── docs/
│   ├── banner.svg                 ← README banner
│   └── screenshots/               ← drop dashboard.png / demo.gif here
├── .github/workflows/
└── ai-security-dashboard/        ★ MAIN APP — always start here
    ├── backend/                   FastAPI + security modules
    ├── frontend/                  React (Vite) dashboard
    ├── docker-compose.yml
    └── README.md                  Detailed app docs
```

---

## Host dependencies (network modules)

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

## Author

[Sayan Mahata](https://github.com/sayan9168) (Sayan the researcher)  
Sayanox Private Limited

MIT License — see repository license file if present.
