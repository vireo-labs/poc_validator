# PoC Validator v0.1.1 - Architecture

> **Mission**: Validate security scanner alerts by proving exploitability, not just version matching.

---

## Current Implementation Status

| Component | Status | Details |
|-----------|--------|---------|
| 5-Agent Pipeline | ✅ Done | All agents working |
| LLM Exploit Generation | ✅ Done | Qwen 235B via OpenRouter |
| Langfuse Observability | ✅ Done | Full tracing |
| Skeptical LLM Judge | ✅ Done | Verifies evidence |
| Dependency Exploits | ✅ Done | 10+ npm packages |
| Snyk Parser | ✅ Done | JSON format |
| Multi-scanner | ❌ Pending | Only Snyk |
| Docker Sandbox | ❌ Pending | Using subprocess |
| REST API | ❌ Pending | CLI only |
| Frontend | ❌ Pending | Not connected |

---

## High-Level Flow

```mermaid
flowchart TB
    subgraph Inputs["INPUTS"]
        SNYK["Snyk JSON"]
        REPO["GitHub Repository"]
    end
    
    subgraph Stage1["Stage 1: Quick Triage (FREE)"]
        PARSE["Parse & Normalize"]
        FILTER["Filter Obvious FPs
        (test/, INFO, dead code)"]
        DEDUP["Deduplicate"]
        
        PARSE --> FILTER --> DEDUP
    end
    
    subgraph Stage2["Stage 2: Strategy Router"]
        ROUTE{"Vulnerability Type?"}
        
        ROUTE -->|"90%"| MINIMAL["MINIMAL
        10 seconds"]
        ROUTE -->|"10%"| FULL["FULL
        5 minutes"]
    end
    
    subgraph Stage3["Stage 3: 5-Agent Pipeline"]
        A1["1. Report Parser"]
        A2["2. Code Analyzer"]
        A3["3. PoC Discoverer"]
        A4["4. Sandbox Executor"]
        A5["5. LLM Judge (Skeptical)"]
        
        A1 --> A2 --> A3 --> A4 --> A5
    end
    
    subgraph Outputs["VERDICTS"]
        V1["EXPLOITABLE"]
        V2["FALSE_POSITIVE"]
        V3["NEEDS_REVIEW"]
    end

    Inputs --> Stage1
    Stage1 --> Stage2
    Stage2 --> Stage3
    Stage3 --> Outputs

    style MINIMAL fill:#22c55e,color:#fff
    style FULL fill:#f59e0b,color:#000
    style V1 fill:#ef4444,color:#fff
    style V2 fill:#22c55e,color:#fff
```

---

## 5-Agent Pipeline

### Agent 1: Report Parser
**File**: `agents/report_parser.py`

Parses scanner output into normalized format.
- Extracts: file, line, type, severity, package
- Uses LLM for complex parsing if needed

### Agent 2: Code Analyzer
**File**: `agents/code_analyzer.py`

Finds vulnerable code in repository.
- Clones repo (shallow)
- Pattern matching first, LLM fallback
- Returns vulnerable code context

### Agent 3: PoC Discoverer
**File**: `agents/poc_discoverer.py`

Generates exploit code.

```mermaid
flowchart LR
    INPUT["Vulnerability"] --> CHECK{"In Library?"}
    CHECK -->|"Dependency"| DEP["exploits/dependencies.py
    10+ npm packages"]
    CHECK -->|"HTTP"| HTTP["exploits/juice_shop.py
    SQLi, XSS, etc."]
    CHECK -->|"Not found"| LLM["Qwen 235B
    Generate exploit"]
    
    DEP & HTTP & LLM --> OUTPUT["Exploit Code"]
    
    style DEP fill:#22c55e,color:#fff
    style HTTP fill:#22c55e,color:#fff
    style LLM fill:#f59e0b,color:#000
```

**Exploit Libraries**:
| Library | Packages | Type |
|---------|----------|------|
| `dependencies.py` | vm2, lodash, jsonwebtoken, express-jwt, sanitize-html, moment, marsdb, braces, notevil, cookie | Node.js |
| `juice_shop.py` | SQLi, XSS, IDOR, Path Traversal, Auth Bypass | HTTP |

### Agent 4: Sandbox Executor
**File**: `agents/sandbox_executor.py`

Executes exploits in isolated environment.

| Language | Execution | Use Case |
|----------|-----------|----------|
| Python | subprocess | HTTP exploits |
| Node.js | subprocess in project dir | Dependency exploits |

### Agent 5: LLM Judge (Skeptical)
**File**: `agents/llm_judge.py`

**Key Feature**: Doesn't blindly trust "SUCCESS" claims.

```mermaid
flowchart TB
    INPUT["Exploit Output"] --> CHECK1{"FAILED: in output?"}
    CHECK1 -->|Yes| INVALID["FALSE_POSITIVE"]
    CHECK1 -->|No| CHECK2{"BLOCKED: in output?"}
    CHECK2 -->|Yes| INVALID
    CHECK2 -->|No| CHECK3{"VULNERABLE: in output?"}
    CHECK3 -->|Yes| VALID["EXPLOITABLE
    (Evidence verified)"]
    CHECK3 -->|No| LLM["LLM Skeptically Verifies
    (Qwen 235B)"]
    LLM --> VERDICT["Final Verdict"]
    
    style VALID fill:#ef4444,color:#fff
    style INVALID fill:#22c55e,color:#fff
```

---

## LLM Configuration

**Provider**: OpenRouter
**File**: `services/openrouter.py`

| Model | Use Case | Cost |
|-------|----------|------|
| `qwen/qwen3-235b-a22b-2507` | Exploit generation, Judgment | ~$0.02/call |

**Observability**: Langfuse
- All LLM calls traced
- Token usage tracked
- Metadata: package, severity, vuln_type

---

## Quick Triage

**File**: `services/pipeline.py` → `QuickTriage` class

```mermaid
flowchart TB
    START["New Alert"] --> Q1{"File in test/?"}
    Q1 -->|Yes| FP["FALSE_POSITIVE"]
    Q1 -->|No| Q2{"Severity = INFO?"}
    Q2 -->|Yes| FP
    Q2 -->|No| Q3{"Dead code marker?"}
    Q3 -->|Yes| FP
    Q3 -->|No| DEDUP["Deduplicate"]
    DEDUP --> VALIDATE["PROCEED"]
    
    style FP fill:#22c55e,color:#fff
    style VALIDATE fill:#f59e0b,color:#000
```

---

## File Structure

```
poc_validator/
├── backend/
│   ├── agents/
│   │   ├── report_parser.py      # Parse scanner output
│   │   ├── code_analyzer.py      # Find vulnerable code
│   │   ├── poc_discoverer.py     # Generate exploits
│   │   ├── sandbox_executor.py   # Run exploits
│   │   └── llm_judge.py          # Skeptical verification
│   │
│   ├── services/
│   │   ├── pipeline.py           # Main orchestrator
│   │   ├── openrouter.py         # LLM + Langfuse
│   │   ├── github_service.py     # Clone repos
│   │   └── parsers/
│   │       └── snyk_parser.py    # Snyk JSON parser
│   │
│   ├── exploits/
│   │   ├── dependencies.py       # NPM package exploits
│   │   └── juice_shop.py         # HTTP exploits
│   │
│   └── .env                      # API keys
│
├── scanner_data/
│   ├── real-snyk-juice-shop.json # Test data
│   └── juice-shop/               # Target project
│
└── docs/
    ├── ARCHITECTURE.md           # This file
    └── FLOWCHART.md              # Visual diagrams
```

---

## Environment Variables

```bash
# Required
OPENROUTER_API_KEY=sk-or-v1-xxx

# Optional - Langfuse
LANGFUSE_PUBLIC_KEY=pk-lf-xxx
LANGFUSE_SECRET_KEY=sk-lf-xxx
LANGFUSE_HOST=https://cloud.langfuse.com
```

---

## Running the Pipeline

```bash
cd backend
source venv/bin/activate

# Validate Snyk output
PYTHONPATH=. python services/pipeline.py \
  ../scanner_data/real-snyk-juice-shop.json \
  --project-path ../scanner_data/juice-shop
```

---

## Cost Model

| Scenario | Cost | Time |
|----------|------|------|
| Dependency exploit (cached) | Free | <1s |
| LLM-generated exploit | ~$0.02 | 5-15s |
| LLM judgment | ~$0.01 | 3-5s |
| **Per vulnerability** | ~$0.05 | 10-20s |

---

## Next Steps

| Priority | Task |
|----------|------|
| P1 | REST API (FastAPI) |
| P1 | Connect frontend |
| P2 | Docker deployment |
| P2 | Multi-scanner support |
| P3 | Jira/Slack integrations |
