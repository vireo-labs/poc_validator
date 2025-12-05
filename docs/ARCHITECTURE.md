# PoC Validator V2 - Production-Ready Architecture

> **Mission**: Validate 10,000 scanner alerts for ₹3,000 (not ₹100,000)

---

## Performance Targets

| Metric | V0 | MVP | Production |
|--------|-----|-----|------------|
| **Cost per validation** | ₹1-2 | ₹0.50 | ₹0.20 |
| **Time per validation** | 30s | 15s | 10s |
| **Throughput** | 100/hr | 1,000/hr | 10,000/hr |
| **Accuracy (F1)** | 80% | 90% | 95% |

---

## High-Level Flow (Updated)

```mermaid
flowchart TB
    subgraph Inputs["📥 INPUTS"]
        SCANNERS["Scanner Alerts
        (Snyk, Semgrep, etc.)"]
        REPO["Source Code Repo"]
    end
    
    subgraph Stage1["Stage 1: Quick Triage (FREE)"]
        PARSE["Parse & Normalize"]
        FILTER["Filter Obvious FPs
        (test/, dead code)"]
        PRIORITY["Priority Queue"]
        
        PARSE --> FILTER --> PRIORITY
    end
    
    subgraph Stage2["Stage 2: Validation Strategy"]
        ROUTE{"Route by
        Vulnerability Type"}
        
        ROUTE -->|"Library/Dependency
        90% of cases"| MINIMAL["⚡ MINIMAL REPRODUCTION
        10 seconds, ₹0.20"]
        
        ROUTE -->|"Complex Business Logic
        10% of cases"| FULL["🐳 FULL DEPLOYMENT
        5 minutes, ₹5.00"]
    end
    
    subgraph Stage3["Stage 3: Execution"]
        MINIMAL --> SANDBOX_MINI["Lightweight Container
        (Test Harness Only)"]
        FULL --> SANDBOX_FULL["Full Stack Container
        (App + DB + Services)"]
    end
    
    subgraph Stage4["Stage 4: LLM Judgment"]
        SANDBOX_MINI & SANDBOX_FULL --> JUDGE["Claude Haiku (90%)
        Claude Sonnet (10%)"]
        JUDGE --> VERDICT
    end
    
    subgraph Outputs["📊 VERDICTS"]
        VERDICT --> V1["🔴 EXPLOITABLE"]
        VERDICT --> V2["🟡 CONFIRMED"]
        VERDICT --> V3["🟢 FALSE POSITIVE"]
        VERDICT --> V4["⚪ NEEDS REVIEW"]
    end

    Inputs --> Stage1
    Stage1 --> Stage2
    Stage2 --> Stage3
    Stage3 --> Stage4

    style MINIMAL fill:#22c55e,color:#fff
    style FULL fill:#f59e0b,color:#000
    style V1 fill:#ef4444,color:#fff
    style V2 fill:#f59e0b,color:#fff
    style V3 fill:#22c55e,color:#fff
```

---

## Agent 4: Sandbox Executor (FIXED)

```mermaid
flowchart TB
    subgraph Input["� INPUT"]
        EXPLOIT["Exploit Code"]
        VULN_TYPE["Vulnerability Type"]
        CODE_CONTEXT["Vulnerable Code"]
    end

    subgraph Strategy["🎯 STRATEGY SELECTION"]
        DECIDE{"What type
        of vulnerability?"}
        
        DECIDE -->|"SQL Injection"| MINIMAL
        DECIDE -->|"XSS"| MINIMAL
        DECIDE -->|"Command Injection"| MINIMAL
        DECIDE -->|"Path Traversal"| MINIMAL
        DECIDE -->|"Dependency CVE"| MINIMAL
        DECIDE -->|"Deserialization"| MINIMAL
        
        DECIDE -->|"Auth Bypass"| CHECK_COMPLEX
        DECIDE -->|"Business Logic"| CHECK_COMPLEX
        DECIDE -->|"Race Condition"| FULL
        DECIDE -->|"Multi-step CSRF"| FULL
        
        CHECK_COMPLEX{"Can reproduce
        with mock?"}
        CHECK_COMPLEX -->|"Yes"| MINIMAL
        CHECK_COMPLEX -->|"No"| FULL
    end

    subgraph Minimal["⚡ MINIMAL REPRODUCTION (90%)"]
        M1["Generate Test Harness
        (Isolated function + input)"]
        M2["Spin up Alpine container
        (pre-warmed pool)"]
        M3["Run test
        (10 second timeout)"]
        M4["Capture output"]
        
        M1 --> M2 --> M3 --> M4
    end

    subgraph Full["🐳 FULL DEPLOYMENT (10%)"]
        F1["Pull app image
        (cached if possible)"]
        F2["Setup full stack
        (App + DB + Services)"]
        F3["Wait for health check"]
        F4["Run exploit
        (5 min timeout)"]
        F5["Capture all output"]
        
        F1 --> F2 --> F3 --> F4 --> F5
    end

    subgraph Output["📤 OUTPUT"]
        RESULT["Execution Result
        • stdout/stderr
        • exit code
        • network traffic
        • success indicators"]
    end

    Input --> DECIDE
    MINIMAL --> M1
    FULL --> F1
    M4 & F5 --> RESULT

    style MINIMAL fill:#22c55e,color:#fff
    style FULL fill:#f59e0b,color:#000
```

---

## Minimal Reproduction Examples

### Example 1: SQL Injection

```python
# INSTEAD OF: Deploy full app + database + run query

# MINIMAL REPRODUCTION:
def test_sqli_vulnerability():
    """Test if the vulnerable pattern is exploitable."""
    
    # 1. Extract the vulnerable code pattern
    vulnerable_code = """
    def get_user(user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return db.execute(query)
    """
    
    # 2. Create test harness with mock database
    harness = f"""
import sqlite3

# Mock the vulnerable function
{vulnerable_code}

# Test with malicious input
test_input = "1 OR 1=1"
try:
    result = get_user(test_input)
    if "SELECT" in str(result) or len(result) > 1:
        print("SUCCESS: SQL Injection confirmed")
        exit(0)
except Exception as e:
    if "syntax" not in str(e).lower():
        print("SUCCESS: Injection possible")
        exit(0)

print("FAILED: Input sanitized")
exit(1)
"""
    
    # 3. Run in 10 seconds
    return run_in_container(harness, timeout=10)
```

### Example 2: Command Injection

```python
# MINIMAL REPRODUCTION:
def test_cmdi_vulnerability():
    """Test command injection without full app."""
    
    harness = """
import subprocess

# Vulnerable pattern from code
def process_file(filename):
    cmd = f"cat {filename}"
    return subprocess.check_output(cmd, shell=True)

# Test with payload
try:
    result = process_file("; id")
    if "uid=" in result.decode():
        print("SUCCESS: Command injection confirmed")
        exit(0)
except:
    pass

print("FAILED: Input sanitized")
exit(1)
"""
    return run_in_container(harness, timeout=10)
```

### Example 3: Dependency CVE (log4j)

```python
# MINIMAL REPRODUCTION:
def test_log4j_vulnerability():
    """Test log4j without deploying full app."""
    
    harness = """
# Check if vulnerable log4j version exists
import subprocess
result = subprocess.run(
    ["grep", "-r", "log4j-core.*2\\.([0-9]|1[0-6])\\.", "pom.xml"],
    capture_output=True
)

if result.returncode == 0:
    print("SUCCESS: Vulnerable log4j version found")
    print(result.stdout.decode())
    exit(0)
else:
    print("FAILED: Safe log4j version")
    exit(1)
"""
    return run_in_container(harness, timeout=10)
```

---

## LLM Strategy (FIXED)

```mermaid
flowchart LR
    subgraph Input["Judgment Request"]
        REQ["Execution Results
        + Code Context"]
    end

    subgraph Router["🎯 LLM ROUTER"]
        DECIDE{"Complexity?"}
        
        DECIDE -->|"Clear success/fail
        (90% of cases)"| HAIKU["Claude Haiku
        ₹0.25/call
        Fast, cheap"]
        
        DECIDE -->|"Ambiguous result
        Edge case
        (10% of cases)"| SONNET["Claude Sonnet
        ₹2.50/call
        High accuracy"]
    end

    subgraph Cache["� CACHING"]
        CACHE{"Seen this
        pattern before?"}
        CACHE -->|"Yes"| CACHED["Return cached
        verdict (FREE)"]
        CACHE -->|"No"| DECIDE
    end

    subgraph Output["Verdict"]
        HAIKU & SONNET --> VERDICT["Final Verdict
        + Reasoning"]
    end

    REQ --> CACHE
    CACHED --> VERDICT

    style HAIKU fill:#22c55e,color:#fff
    style SONNET fill:#f59e0b,color:#000
    style CACHED fill:#3b82f6,color:#fff
```

---

## Quick Triage (SOFTENED)

```mermaid
flowchart TB
    START["New Alert"] --> Q1{"File in test/
    or spec/?"}
    
    Q1 -->|"Yes"| FP1["🟢 FALSE POSITIVE
    (Test file)"]
    Q1 -->|"No"| Q2{"Severity =
    INFO only?"}
    
    Q2 -->|"Yes"| FP2["� FALSE POSITIVE
    (Informational)"]
    Q2 -->|"No"| Q3{"Dead code
    (unreachable)?"}
    
    Q3 -->|"Yes"| FP3["🟢 FALSE POSITIVE
    (Dead code)"]
    Q3 -->|"No"| VALIDATE["⚡ PROCEED TO
    VALIDATION"]

    style FP1 fill:#22c55e,color:#fff
    style FP2 fill:#22c55e,color:#fff
    style FP3 fill:#22c55e,color:#fff
    style VALIDATE fill:#f59e0b,color:#000
```

**REMOVED from V0:**
- ❌ ORM assumption (ORMs have CVEs too)
- ❌ Framework assumption (frameworks have CVEs too)
- ❌ Dependency separation (they're easiest to validate!)

**Let data show us what's false positive, don't assume.**

---

## Cost Model (Per 10,000 Validations)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COST BREAKDOWN                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  STAGE 1: Quick Triage (FREE)                                       │
│  ├── Parse & normalize............ ₹0 × 10,000 = ₹0                │
│  ├── Filter obvious FPs........... ₹0                               │
│  └── Filtered out: ~3,000 alerts                                    │
│                                                                     │
│  STAGE 2-3: Validation (7,000 alerts proceed)                       │
│  ├── Minimal reproduction (90%)                                     │
│  │   └── 6,300 × ₹0.20 = ₹1,260                                    │
│  ├── Full deployment (10%)                                          │
│  │   └── 700 × ₹5.00 = ₹3,500                                      │
│  └── Subtotal: ₹4,760                                               │
│                                                                     │
│  STAGE 4: LLM Judgment (7,000 alerts)                               │
│  ├── Claude Haiku (90%)                                             │
│  │   └── 6,300 × ₹0.25 = ₹1,575                                    │
│  ├── Claude Sonnet (10%)                                            │
│  │   └── 700 × ₹2.50 = ₹1,750                                      │
│  └── Subtotal: ₹3,325                                               │
│                                                                     │
│  ══════════════════════════════════════════════════════════════     │
│  TOTAL: ₹8,085                                                      │
│                                                                     │
│  WITH OPTIMIZATIONS:                                                │
│  ├── LLM prompt caching (-40%).... -₹1,330                         │
│  ├── Pre-warmed containers (-20%). -₹952                           │
│  ├── PoC library hits (30%)....... -₹1,428                         │
│  └── OPTIMIZED TOTAL: ₹4,375                                       │
│                                                                     │
│  PRICING: ₹50,000/year → 91% GROSS MARGIN ✅                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cost Optimization Strategies

```mermaid
flowchart LR
    subgraph Infra["🏗️ INFRASTRUCTURE"]
        POOL["Pre-warmed
        Container Pool
        (10 ready containers)"]
        
        CACHE_IMG["Cached Docker
        Images
        (Popular apps)"]
    end

    subgraph LLM["🤖 LLM OPTIMIZATION"]
        PROMPT_CACHE["Prompt Caching
        (Same patterns)"]
        
        BATCH["Batch LLM Calls
        (10 at a time)"]
        
        HAIKU_FIRST["Haiku First
        Sonnet Fallback"]
    end

    subgraph Knowledge["📚 KNOWLEDGE BASE"]
        POC_LIB["PoC Library
        (1000+ tested exploits)"]
        
        FP_PATTERNS["False Positive
        Pattern Database"]
        
        CVE_MAP["CVE → Exploit
        Mapping"]
    end

    POOL --> |"Saves 5s"| FASTER["Faster Validation"]
    CACHE_IMG --> |"Saves 30s"| FASTER
    PROMPT_CACHE --> |"Saves 40%"| CHEAPER["Lower LLM Cost"]
    BATCH --> |"Saves 20%"| CHEAPER
    POC_LIB --> |"Skip LLM"| CHEAPER
    FP_PATTERNS --> |"Skip Validation"| CHEAPER
```

---

## Technology Stack (UPDATED)

| Component | Technology | Why |
|-----------|------------|-----|
| **Backend** | FastAPI (Python) | Async, fast, OpenAPI |
| **Frontend** | Next.js 14 | Modern React, SSR |
| **Database** | PostgreSQL | Reliable, JSON support |
| **Queue** | Redis + Celery | Batch job processing |
| **Sandbox** | Docker + Pool | Isolation, pre-warmed |
| **LLM** | **Anthropic Claude** | Consistent, prompt caching |
| **Cache** | Redis | LLM responses, PoCs |
| **Container Pool** | Custom Manager | Pre-warmed containers |

---

## Updated Agent Pipeline

```mermaid
flowchart TB
    subgraph A1["🔍 Agent 1: Parser"]
        A1_1["Parse Snyk/SARIF"]
        A1_2["Extract Claims"]
        A1_3["Normalize Format"]
    end

    subgraph A2["📂 Agent 2: Code Analyzer"]
        A2_1["Clone Repo (shallow)"]
        A2_2["Find Vulnerable Code"]
        A2_3["Extract Context"]
        A2_4["Classify Vuln Type"]
    end

    subgraph A3["⚡ Agent 3: Exploit Generator"]
        A3_1{"PoC Library
        has exploit?"}
        A3_1 -->|"Yes (30%)"| A3_2["Use Cached PoC
        (FREE)"]
        A3_1 -->|"No"| A3_3["Generate with
        Claude Haiku"]
    end

    subgraph A4["🐳 Agent 4: Sandbox Executor"]
        A4_1{"Minimal or
        Full Deploy?"}
        A4_1 -->|"Minimal (90%)"| A4_2["Test Harness
        10s, ₹0.20"]
        A4_1 -->|"Full (10%)"| A4_3["Full Stack
        5min, ₹5"]
    end

    subgraph A5["⚖️ Agent 5: LLM Judge"]
        A5_1{"Clear result?"}
        A5_1 -->|"Yes (90%)"| A5_2["Claude Haiku
        ₹0.25"]
        A5_1 -->|"No (10%)"| A5_3["Claude Sonnet
        ₹2.50"]
    end

    A1 --> A2 --> A3 --> A4 --> A5
    
    A5 --> VERDICT["Final Verdict"]

    style A3_2 fill:#22c55e,color:#fff
    style A4_2 fill:#22c55e,color:#fff
    style A5_2 fill:#22c55e,color:#fff
```

---

## File Structure (Updated)

```
poc_validator/
├── backend/
│   ├── agents/
│   │   ├── report_parser.py       # Parse scanner formats
│   │   ├── code_analyzer.py       # Analyze source code
│   │   ├── exploit_generator.py   # Generate/retrieve exploits
│   │   ├── sandbox_executor.py    # Run in sandbox (UPDATED)
│   │   └── llm_judge.py           # Judge with Claude (UPDATED)
│   │
│   ├── services/
│   │   ├── parsers/
│   │   │   ├── snyk_parser.py     # Snyk JSON
│   │   │   └── sarif_parser.py    # SARIF format
│   │   ├── anthropic_client.py    # Claude API (NEW)
│   │   ├── container_pool.py      # Pre-warmed containers (NEW)
│   │   ├── poc_library.py         # Cached exploits (NEW)
│   │   ├── quick_triage.py        # Fast filtering
│   │   └── github_service.py      # Clone repos
│   │
│   ├── exploits/
│   │   ├── sqli/                  # SQL injection PoCs
│   │   ├── xss/                   # XSS PoCs
│   │   ├── rce/                   # RCE PoCs
│   │   └── dependency/            # CVE-specific PoCs
│   │
│   └── main.py
│
├── frontend/
│   └── app/
│       ├── page.tsx               # Dashboard
│       ├── validate/page.tsx      # Upload & validate
│       └── results/page.tsx       # View results
│
└── docs/
    └── ARCHITECTURE.md            # This file
```

---

## Implementation Priority

| Priority | Task | Impact |
|----------|------|--------|
| **P0** | Minimal reproduction in Agent 4 | **25x cost reduction** |
| **P0** | Switch to Anthropic Claude | Consistent results |
| **P0** | Snyk/SARIF parsers | Real customer input |
| **P1** | Pre-warmed container pool | 5s faster per validation |
| **P1** | PoC library (top 100 CVEs) | 30% skip LLM generation |
| **P1** | LLM prompt caching | 40% LLM cost reduction |
| **P2** | Batch processing API | Handle 10K alerts |
| **P2** | Dashboard UI | Customer-facing |
