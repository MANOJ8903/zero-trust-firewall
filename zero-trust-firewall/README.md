# AI-Enabled Zero Trust Network Firewall

## Project Structure
```
zero-trust-firewall/
├── backend/
│   ├── app.py            ← Flask REST API server
│   ├── ai_engine.py      ← AI threat detection model
│   └── policy_engine.py  ← Zero trust policy rules
├── frontend/
│   └── index.html        ← Dashboard UI
├── requirements.txt
└── README.md
```

## Setup & Run

### 1. Install dependencies
```bash
pip install flask
```

### 2. Start the server
```bash
cd backend
python app.py
```

### 3. Open Dashboard
Visit: http://localhost:5000

## API Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | System status & KPIs |
| `/api/logs` | GET | Live traffic logs |
| `/api/analyze` | POST | Analyze a packet |
| `/api/policies` | GET | Firewall policies |
| `/api/policies/<id>/toggle` | POST | Toggle a policy |
| `/api/threats/summary` | GET | Threat analytics |

## Hosting (Production)
See HOSTING.md for full AWS/GCP deployment guide.
