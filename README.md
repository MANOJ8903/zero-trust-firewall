# 🔒 AI-Enabled Zero Trust Network Firewall

## 📌 Project Overview
An AI-powered Zero Trust Network Firewall that analyzes every network packet using a threat scoring engine. No user or device is trusted by default — every request is verified, scored, and either allowed, monitored, inspected, or blocked in real time.

---

## 🏗️ Project Structure
```
zero-trust-firewall/
├── backend/
│   ├── main.py              ← FastAPI server + AI Threat Engine
│   ├── requirements.txt     ← Python dependencies
│   └── Dockerfile           ← Container configuration
├── frontend/
│   └── index.html           ← Dashboard UI (cyberpunk style)
├── nginx/
│   └── default.conf         ← Reverse proxy configuration
├── docker-compose.yml       ← One-command deployment
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI (Python) |
| AI Engine | Heuristic Threat Scoring Model |
| Frontend | HTML + CSS + JavaScript |
| Container | Docker + Docker Compose |
| Reverse Proxy | Nginx |
| API Docs | Swagger UI (auto-generated) |

---

## 🚀 Quick Start (Local — Windows)

### 1. Extract the ZIP
Right-click `zero-trust-firewall.zip` → Extract All

### 2. Open in VS Code
```
File → Open Folder → select zero-trust-firewall
```

### 3. Open Terminal in VS Code
```
Ctrl + `
```

### 4. Create Virtual Environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### 5. Install Dependencies
```powershell
pip install fastapi uvicorn pydantic python-multipart httpx
```

### 6. Run the Backend Server
```powershell
cd backend
python main.py
```

### 7. Open the Dashboard
Open `frontend/index.html` in your browser, or install the **Live Server** VS Code extension and click **Go Live**.

---

## 🌐 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Server health check |
| `/api/analyze` | POST | Analyze a network packet with AI |
| `/api/simulate` | POST | Simulate 5 real attack scenarios |
| `/api/dashboard/stats` | GET | Get all dashboard statistics |
| `/api/logs` | GET | Get recent traffic logs |
| `/api/alerts` | GET | Get active threat alerts |
| `/api/blocked-ips` | GET | Get list of auto-blocked IPs |
| `/api/policies` | GET | Get firewall policy rules |
| `/docs` | GET | Interactive Swagger API docs |

---

## 🤖 AI Threat Detection Features

- **Threat Scoring** — Every packet scored 0–100
- **Port Anomaly Detection** — Flags suspicious ports (4444, 22, 3389, 31337...)
- **Payload Analysis** — Detects abnormally large or empty payloads
- **IP Reputation Check** — Blocks known malicious IP ranges
- **DNS Amplification Detection** — Catches UDP/53 flood attacks
- **TCP SYN Scan Detection** — Identifies port scanning behavior
- **Auto IP Blocking** — Critical threats are auto-blocked instantly
- **Confidence Scoring** — Each decision includes a confidence percentage

---

## 🔒 Zero Trust Policy Engine

| Policy | Action |
|---|---|
| Block Tor Exit Nodes | BLOCK |
| Allow Internal Subnet | ALLOW |
| Rate Limit SSH | RATE_LIMIT |
| Block Port Scan | BLOCK |
| Zero Trust MFA Required | MFA |

---

## 📊 Threat Verdict Levels

| Score | Verdict | Threat Level |
|---|---|---|
| 0 – 19 | ✅ ALLOW | SAFE |
| 20 – 39 | 🔵 MONITOR | LOW |
| 40 – 69 | 🟡 INSPECT | MEDIUM |
| 70 – 100 | 🔴 BLOCK | CRITICAL |

---

## 🧪 Test the API (PowerShell)

```powershell
# Health check
curl http://localhost:8000/

# Simulate attacks
curl -X POST http://localhost:8000/api/simulate

# Analyze a packet manually
curl -X POST http://localhost:8000/api/analyze `
  -H "Content-Type: application/json" `
  -d '{"source_ip":"45.33.32.156","destination_ip":"10.0.0.1","port":4444,"protocol":"TCP","payload_size":1024,"user_agent":"nmap"}'

# View stats
curl http://localhost:8000/api/dashboard/stats

# View blocked IPs
curl http://localhost:8000/api/blocked-ips
```

---

## 🐳 Deploy with Docker

```powershell
# Build and run all services
docker-compose up --build

# Frontend → http://localhost:3000
# Backend → http://localhost:8000
# API Docs → http://localhost:8000/docs
```

---

## ☁️ Hosting on AWS EC2

```bash
# 1. Launch Ubuntu 22.04 EC2 (t2.medium)
# 2. Open ports: 22, 80, 443, 8000 in Security Groups
# 3. SSH into your instance

ssh -i your-key.pem ubuntu@your-ec2-ip

# 4. Install Docker
sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl start docker

# 5. Clone and run
git clone https://github.com/yourname/zero-trust-firewall
cd zero-trust-firewall
docker-compose up -d

# 6. Add SSL (free)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## 🆓 Free Hosting Options

| Service | What to Deploy | URL |
|---|---|---|
| Render.com | Backend (FastAPI) | render.com |
| Vercel | Frontend (HTML) | vercel.com |
| Supabase | Database | supabase.com |
| Hugging Face Spaces | AI Model | huggingface.co |

---

## 👨‍💻 Author- [Manoj Kumar](https://github.com/MANOJ8903)
**Project:** AI-Enabled Zero Trust Network Firewall
**Stack:** Python · FastAPI · Docker · Nginx · HTML/CSS/JS
**Principle:** Never Trust. Always Verify. ✅
