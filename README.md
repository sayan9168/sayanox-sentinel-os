# SAYANOX SENTINEL OS

### Autonomous AI-Powered System Security & PC Operations Suite

```
  ███████╗███████╗██╗  ██╗██╗   ██╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     
  ╚══███╔╝██╔════╝██║  ██║██║   ██║██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
    ███╔╝ ███████╗███████║██║   ██║█████╗         ██║   ██║   ██║██║   ██║██║     
   ███╔╝  ╚════██║██╔══██║██║   ██║██╔══╝         ██║   ██║   ██║██║   ██║██║     
  ███████╗███████║██║  ██║╚██████╔╝███████╗       ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                          S E C U R I T Y   |   A U T O M A T I O N   |   A I
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

---

## 📖 Project Overview

**Sayanox Sentinel OS** is a production-ready, autonomous platform designed to bridge the critical gap between raw system telemetry, remote terminal control, and proactive AI-driven threat mitigation. 

Unlike traditional monitoring tools that simply alert you *after* an incident, Sayanox leverages machine learning and automated response agents to detect anomalies in real-time and neutralize threats before they compromise system integrity. Built with a **DevSecOps**-first mindset, it provides a unified dashboard for managing PC operations, enforcing security policies, and maintaining total situational awareness of your infrastructure.

**Key Focus Areas:**
*   🤖 **Automation:** Self-healing workflows and autonomous response agents.
*   🛡️ **DevSecOps:** Integrated security scanning and compliance monitoring within the deployment pipeline.
*   🚀 **Proactive Security:** Behavioral analysis and honeypot decoys to catch attackers early.

---

## 🔥 Advanced Phase 5 Features (Fear-Inducing Edition)

Phase 5 adds military-grade autonomous defense modules that go far beyond typical dashboards:

### 💀 Ransomware Canary Guardian
Plants cryptographic **honeypot canary files** across protected directories and runs a real-time watchdog combining four detection layers:
*   **Canary Tripwire** — any modification/deletion of a `.sayanox_canary.dat` file is an instant critical alert.
*   **Shannon Entropy Analysis** — freshly-written files are scanned for near-maximal byte entropy (>0.95), the fingerprint of encrypted payloads.
*   **Encryption Storm Detection** — per-process file-modification velocity tracking; 50+ unique files rewritten in 10 seconds triggers automatic lockdown.
*   **Extension Sweep** — mass-renames to known ransomware extensions (`.locked`, `.crypt`, `.wcry`, ...) are flagged immediately.

On confirmed detection it executes an autonomous kill-chain: evidence snapshot → lockdown flag → incident correlation → firewall escalation. Includes a `simulate_storm()` red-team drill API.

### 🚨 AI Kill Switch (Tiered Panic Button)
A hardware-inspired emergency stop for the entire autonomous stack with a 4-level degradation ladder:

| Level | Action | Effect |
| :--- | :--- | :--- |
| L1 | `PAUSE_WORKERS` | Stop FIM, sniffer, honeypot background jobs |
| L2 | `NETWORK_ISOLATE` | Firewall-block all non-loopback traffic |
| L3 | `HALT_PROCESSES` | Terminate automation processes |
| L4 | `FULL_FREEZE` | Disable every remediation rule (safe mode) |

L2+ activation requires a **salted-hash PIN** (dual-key protection so a stolen viewer token can't brick the machine). Every activation, rejection and stand-down is written to an **immutable SQLite audit ledger** for post-incident forensics.

### 🧬 Threat Intelligence NLP Engine
Pure-Python (zero external LLM dependency) intel analytics pipeline:
*   **IOC Extraction** — CVE IDs, IPv4, URLs, domains, SHA-256 hashes, emails, and named threat actors (APTxx, Lazarus, LockBit...).
*   **CVSS Estimation** — heuristic severity scoring from exploit keywords ("wormable", "RCE", "in the wild").
*   **MITRE ATT&CK Mapping** — curated keyword taxonomy maps raw text to techniques (T1566 Phishing, T1486 Data Encrypted for Impact, ...).
*   **TF-IDF Deduplication** — cosine-similarity clustering collapses duplicate intel feeds automatically.

### 🔗 Incident Correlation Engine
Fuses isolated signals (honeypot hits, FIM violations, ML anomalies, canary trips) into high-level **incidents** using sliding-window attack-chain analysis:
*   Events correlate by source IP, file path prefix, or process name.
*   Kill-chain scoring escalates severity as incidents progress RECON → INITIAL ACCESS → EXECUTION → PERSISTENCE → EXFILTRATION → IMPACT.
*   Bayesian log-odds confidence per incident + auto-generated SOC narrative timelines.
*   Incidents auto-close after a configurable quiet TTL.

---

## 🚀 Advanced Phase 4 Features

Sayanox Sentinel OS distinguishes itself with cutting-edge modules designed for modern threat landscapes:

### 🧠 ML Anomaly Detection
Powered by **`scikit-learn` (Isolation Forest)**, our engine dynamically monitors CPU, RAM, and Network trends. It learns baseline behavior over time and instantly flags behavioral irregularities that signature-based antiviruses miss, such as crypto-mining spikes or data exfiltration patterns.

### 🛡️ Autonomous Honeypot Worker
Deploy intelligent decoys on high-risk ports (e.g., `23` Telnet, `3389` RDP). The Honeypot Worker captures unauthorized connection attempts, logs attacker fingerprints, and **auto-triggers firewall bans** via IPTables/UFW without human intervention.

### 🌐 Mobile PWA Support
Take command from anywhere. The platform features a fully installable **Progressive Web App (PWA)** with an optimized, responsive mobile UI. Get push notifications for critical alerts and execute remote terminal commands directly from your smartphone.

### 🔍 Packet Sniffer & Vulnerability Scanner
*   **Native Packet Analysis:** Real-time raw packet stream analysis via WebSockets using **`scapy`**, allowing deep inspection of network traffic.
*   **Active Subnet Scanning:** Integrated **`nmap`** automation to discover devices, open ports, and potential vulnerabilities across your local network segment.

---

## ⚙️ Core Features

*   **Integrated Web Terminal:** Full-shell access via **Xterm.js** directly in the browser, supporting SSH key management and session persistence.
*   **Real-time File Integrity Monitoring (FIM):** Cryptographic hashing watchdogs that alert on unauthorized file modifications in critical system directories.
*   **Live OS Metrics Streaming:** High-frequency telemetry (CPU, Memory, Disk I/O, Network) visualized in real-time using **`psutil`**.
*   **Dynamic OS Firewall Management:** Granular control over inbound/outbound rules with a RESTful API interface.
*   **Secure Authentication:** Enterprise-grade **JWT Authentication** with Role-Based Access Control (RBAC) to separate Admin, Operator, and Viewer privileges.

---

## 🏗️ Architecture & Tech Stack

![Architecture Diagram Placeholder](https://via.placeholder.com/800x400?text=Sayanox+Sentinel+OS+Architecture+Diagram)
*(Visual representation of Frontend ↔️ API Gateway ↔️ Backend Services ↔️ Database/Redis)*

| Layer | Technologies |
| :--- | :--- |
| **Backend Core** | FastAPI, Python 3.11+, Uvicorn, WebSockets |
| **Data & Cache** | SQLite (Persistent), Redis (Pub/Sub & Caching) |
| **Frontend** | React (Vite), TailwindCSS, Recharts, Xterm.js |
| **AI & Agents** | Scikit-Learn, Playwright, Hermes Skill Memory |
| **Infrastructure** | Docker Compose, Nginx Reverse Proxy |

---

## 📦 Installation & Setup

Get Sayanox Sentinel OS running in minutes using our containerized deployment.

### Prerequisites
Ensure the following are installed on your host machine:
*   **Docker** & **Docker Compose**
*   **Native Dependencies** (for Network Modules):
    *   `libpcap` (Required for Scapy/Packet Sniffing)
    *   `nmap` (Required for Vulnerability Scanning)
    *   *Ubuntu/Debian:* `sudo apt-get install libpcap-dev nmap`
    *   *Arch/Manjaro:* `sudo pacman -S libpcap nmap`

### Quick Start

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-org/sayanox-sentinel-os.git
    cd sayanox-sentinel-os
    ```

2.  **Configure Environment**
    Create your `.env` file based on the example provided.
    ```bash
    cp .env.example .env
    # Edit .env to set JWT_SECRET, Webhook URLs, and Admin Credentials
    ```

3.  **Run Setup Script**
    Execute the automated setup script to build images and boot services.
    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```

4.  **Access the Platform**
    *   **Frontend Dashboard:** `http://localhost:3000`
    *   **Backend API Docs:** `http://localhost:8000/docs`
    *   **Mobile PWA:** Access via `http://<your-ip>:3000` on mobile devices.

---

## 📡 API Documentation Sneak Peek

Sayanox exposes a robust RESTful API and WebSocket streams for integration.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System liveness check and service status. |
| `POST` | `/firewall/block` | Dynamically add an IP to the blocklist. |
| `WS` | `/ws/metrics` | Stream live OS performance metrics. |
| `WS` | `/ws/anomaly` | Receive real-time ML anomaly alerts. |
| `GET` | `/scan/vulnerability` | Trigger an Nmap scan on a target subnet. |
| `POST` | `/auth/login` | Authenticate and retrieve JWT access token. |
| `GET` | `/api/v1/ransomware/status` | Ransomware canary guardian health & stats. |
| `POST` | `/api/v1/ransomware/watch` | Protect a directory (plants canary files). |
| `POST` | `/api/v1/ransomware/sweep` | Force an immediate entropy/canary sweep. |
| `POST` | `/api/v1/killswitch/activate` | Engage the tiered AI kill switch (PIN-gated). |
| `GET` | `/api/v1/killswitch/ledger` | Immutable kill-switch audit trail. |
| `POST` | `/api/v1/nlp/analyze` | IOC extraction + CVSS estimate + MITRE mapping. |
| `POST` | `/api/v1/incidents/ingest` | Fuse a raw security event into an incident. |
| `GET` | `/api/v1/incidents` | Ranked incidents with kill-chain narratives. |

---

## 🤝 Development & Contributing

We welcome contributions from the community! Whether it's fixing a bug, adding a new skill to the Hermes memory, or improving the UI.

1.  **Fork** the repository.
2.  **Create a Feature Branch:** `git checkout -b feature/amazing-feature`
3.  **Commit Changes:** `git commit -m 'Add amazing feature'`
4.  **Push:** `git push origin feature/amazing-feature`
5.  **Open a Pull Request.**

**Running Tests:**
```bash
docker-compose run --rm backend pytest
```

---

## 📄 License & Contact

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Author:**  
👤 **sayan**  
*[Link to Portfolio/GitHub]*

---
*Built with ❤️ and ☕ by the Sayanox Team.*
