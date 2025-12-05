# PoC Validator V0 Demo

> Automatically validate security vulnerabilities by running exploits in isolated sandboxes.

![PoC Validator](https://img.shields.io/badge/Status-V0%20Demo-brightgreen) ![Target](https://img.shields.io/badge/Target-OWASP%20Juice%20Shop-orange)

## 🎯 What it Does

PoC Validator takes security scanner alerts and **proves** which vulnerabilities are actually exploitable by:

1. 📄 **Parsing** vulnerability reports
2. 🔍 **Analyzing** code to verify the flaw exists
3. ⚡ **Finding** or generating exploits
4. 🐳 **Running** exploits in Docker sandboxes
5. ⚖️ **Judging** results with LLM to deliver a verdict

**Verdicts:**
- ✅ **VALID** - Confirmed exploitable, prioritize patching
- ❌ **INVALID** - Not exploitable, likely false positive
- ⚠️ **NEEDS REVIEW** - Requires manual security review

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker

### 1. Clone and Setup

```bash
cd poc_validator

# Backend
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create .env with your OpenRouter API key
echo "OPENROUTER_API_KEY=your-key-here" > .env

# Frontend
cd ../frontend
npm install
```

### 2. Start Services

```bash
# Terminal 1: Start Juice Shop target
docker run -d -p 3000:3000 bkimminich/juice-shop

# Terminal 2: Start backend
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000

# Terminal 3: Start frontend
cd frontend
npm run dev -- -p 3001
```

### 3. Open App
- Frontend: http://localhost:3001
- Backend API: http://localhost:8000
- Juice Shop: http://localhost:3000

## 🧪 Try It Out

1. Go to http://localhost:3001/validate
2. Click "SQLi" quick fill button
3. Click "Start Validation"
4. Watch the 5-agent pipeline process
5. See the verdict!

## 📁 Project Structure

```
poc_validator/
├── backend/
│   ├── main.py              # FastAPI app
│   ├── agents/              # 5-agent system
│   │   ├── report_parser.py
│   │   ├── code_analyzer.py
│   │   ├── poc_discoverer.py
│   │   ├── sandbox_executor.py
│   │   └── llm_judge.py
│   └── services/
│       ├── openrouter.py    # LLM API
│       └── docker_sandbox.py
├── frontend/
│   └── app/
│       ├── page.tsx         # Landing
│       ├── validate/        # Submit form
│       └── results/         # Dashboard
└── docker-compose.yml
```

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/validate` | Submit vulnerability |
| GET | `/api/validate/{id}` | Get validation status |
| GET | `/api/validations` | List all validations |

## 🛡️ Target: OWASP Juice Shop

This demo uses [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) as the target - a real, intentionally vulnerable web application with 100+ documented security flaws.

**Pre-built exploits included:**
- SQL Injection (login bypass)
- Reflected XSS (search)
- JWT Algorithm Confusion (auth bypass)
- IDOR (basket access)
- Path Traversal (file read)

## 📜 License

MIT
