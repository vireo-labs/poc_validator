# PoC Validator Backend

## Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
uvicorn main:app --reload
```

## Environment
Create `.env` with:
```
OPENROUTER_API_KEY=your_key_here
```
