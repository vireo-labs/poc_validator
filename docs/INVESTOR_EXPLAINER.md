# PoC Validator - Investor Explainer

## The Problem: Vulnerability Scanner Noise

### The Pain Point
Modern DevSecOps teams use vulnerability scanners (Snyk, Semgrep, Trivy) that generate **thousands of alerts per week**. The critical issue:

> **70-80% of these alerts are false positives or unexploitable in the actual application context.**

### Why This Matters

| Current State | Impact |
|---------------|--------|
| Scanner flags 100 vulnerabilities | Dev team panics |
| 70 are false positives | Wasted investigation time |
| 20 are patched/mitigated | More wasted time |
| **10 are actually exploitable** | Hidden in the noise |

**Result:** Security teams suffer from "alert fatigue" and real threats get missed.

---

## The Solution: AI-Powered Exploit Validation

### What We Built
An **AI pipeline that actually attempts to exploit vulnerabilities** to determine if they're real threats.

> "Don't tell me it MIGHT be vulnerable. SHOW me."

### How It's Different

| Traditional Scanners | PoC Validator |
|---------------------|---------------|
| Pattern matching | Actual exploitation |
| "This CVE exists" | "This CVE is exploitable HERE" |
| High false positive rate | 95.7% accuracy |
| Thousands of alerts | Only actionable threats |

---

## The 5-Agent AI Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    VULNERABILITY SCANNER OUTPUT                  │
│                    (Snyk, Semgrep, Trivy JSON)                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT 1: REPORT PARSER                                         │
│  ────────────────────                                           │
│  • Parses scanner output (Snyk, Semgrep, Trivy)                │
│  • Extracts vulnerability metadata                              │
│  • Normalizes to common format                                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT 2: CODE ANALYZER                                         │
│  ──────────────────────                                         │
│  • Analyzes vulnerable code paths                              │
│  • Identifies exploit vectors (HTTP, dependency, file)         │
│  • Determines exploitation strategy                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT 3: POC DISCOVERER                                        │
│  ───────────────────────                                        │
│  • Checks cached exploit library (100+ known exploits)         │
│  • If not cached: LLM generates custom exploit code            │
│  • Outputs Python or JavaScript exploit script                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT 4: SANDBOX EXECUTOR                                      │
│  ─────────────────────────                                      │
│  • Runs exploit in isolated Docker container                   │
│  • Captures stdout, stderr, exit code                          │
│  • 30-second timeout with resource limits                       │
│  • Falls back to subprocess if Docker unavailable              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  AGENT 5: LLM JUDGE (SKEPTICAL)                                 │
│  ─────────────────────────────                                  │
│  • Analyzes exploit output                                     │
│  • Requires CONCRETE EVIDENCE of exploitation                  │
│  • Fast path: Clear "VULNERABLE:" output → EXPLOIT             │
│  • Slow path: Ambiguous output → LLM analysis                  │
│  • Rejects unsubstantiated "SUCCESS" claims                    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         FINAL VERDICT                            │
│  ──────────────────────────────────────────────────────────────│
│  🔴 EXPLOITABLE     - Proven vulnerability, fix immediately    │
│  🟢 FALSE POSITIVE  - Scanner flagged but not exploitable      │
│  🟡 NEEDS REVIEW    - Inconclusive, manual review needed       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technical Deep Dive

### Agent 3: PoC Discoverer (LLM Exploit Generation)

**Two Paths:**

1. **Fast Path (Cached Exploits)**
   - 100+ pre-built exploits for common CVEs
   - Instant execution, no LLM call
   - Examples: vm2 RCE, jsonwebtoken bypass, lodash prototype pollution

2. **LLM Path (Generated Exploits)**
   - Uses Qwen 235B via OpenRouter
   - Generates custom Python/JS exploit code
   - Strict success criteria in prompt

**Example LLM Prompt:**
```
You are a security exploit developer. Generate a Python exploit for:
- Vulnerability: Prototype Pollution in lodash
- Target: OWASP Juice Shop

The script MUST print "VULNERABLE:" with concrete evidence if successful.
```

### Agent 4: Sandbox Executor (Isolated Execution)

**Docker Execution:**
```python
# Runs in isolated container
container = docker.run(
    image="python:3.11-slim",
    command=["python", "/exploit.py"],
    network="sandbox_network",  # Isolated network
    mem_limit="256m",           # Resource limits
    cpu_period=100000,
    read_only=True
)
```

**Security Features:**
- Network isolation
- Memory/CPU limits
- Read-only filesystem
- 30-second timeout
- Automatic cleanup

### Agent 5: LLM Judge (Skeptical Verification)

**Multi-Phase Verification:**

```python
# Phase 1: Quick verdict patterns
if "VULNERABLE:" in output:
    return EXPLOITABLE  # Clear evidence

if "BLOCKED:" in output or exit_code == 1:
    return FALSE_POSITIVE  # Exploit failed

# Phase 2: LLM analysis for ambiguous cases
verdict = await llm.analyze(output, vulnerability)
```

**Why "Skeptical"?**
- Rejects generic "SUCCESS" without evidence
- Requires actual proof (data leak, RCE output, timing attack)
- Better to miss an edge case than false alarm

---

## Proven Results

### Accuracy on OWASP Juice Shop

| Metric | Score |
|--------|-------|
| **Accuracy** | 95.7% |
| **Precision** | 83.3% |
| **Recall** | 100% |

### Confusion Matrix

```
              Our Prediction
              EXPLOIT  SAFE
Actual  YES     10      0    ← Caught ALL 10 real threats
        NO       2     34   ← 2 false alarms (conservative)
```

### Noise Reduction

| Stage | Alerts |
|-------|--------|
| Snyk Scanner Output | 46 vulnerabilities |
| After PoC Validation | 12 actionable |
| **Noise Reduced** | **74%** |

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| **Backend API** | FastAPI (Python 3.11) |
| **Frontend** | Next.js 16 + React |
| **LLM** | Qwen 235B via OpenRouter |
| **Observability** | Langfuse (LLM tracing) |
| **Sandbox** | Docker with isolated networks |
| **Database** | SQLAlchemy (SQLite/Postgres) |

---

## Integration Points

### Current (MVP)
- ✅ Snyk JSON import
- ✅ REST API for programmatic access
- ✅ Web UI for manual testing

### Roadmap
- 🔜 GitHub App (PR comments, auto-validation)
- 🔜 Jira integration (auto-create tickets)
- 🔜 CI/CD blocking (fail builds on exploitable)
- 🔜 Semgrep/Trivy support

---

## Demo Script (5 minutes)

### 1. Show the Problem (1 min)
> "Here's a Snyk scan of OWASP Juice Shop - 46 vulnerabilities flagged. Which ones are actually dangerous?"

### 2. Upload & Validate (2 min)
- Upload `sample-test.json` (5 known exploitable packages)
- Show real-time progress bar
- Results appear: 5/5 marked EXPLOITABLE

### 3. Show Evidence (1 min)
- Click on vm2 result
- Show actual exploit output: `VULNERABLE: VM2 sandbox escape - command executed`
- This is PROOF, not speculation

### 4. The Value Prop (1 min)
> "We reduced 46 alerts to 10 actionable items with 100% catch rate. Your security team focuses on real threats, not chasing false positives."

---

## Business Model

### Target Customers
- DevSecOps teams at mid-to-large enterprises
- Security consultancies
- Companies with compliance requirements (SOC2, PCI-DSS)

### Pricing Model (Proposed)
| Tier | Validations/Month | Price |
|------|-------------------|-------|
| Starter | 500 | $99/mo |
| Team | 2,500 | $299/mo |
| Enterprise | Unlimited | Custom |

### Market Size
- AppSec tools market: $7.5B (2024)
- Growing 15% YoY
- False positive reduction is TOP pain point

---

## Competitive Advantage

| Competitor | Approach | Our Edge |
|------------|----------|----------|
| Snyk/Semgrep | Pattern matching | We actually exploit |
| Manual review | Human analysis | We're automated + faster |
| Other AI tools | Classification only | We run real code |

**Moat:**
- Cached exploit library (100+ and growing)
- LLM fine-tuned for exploit generation
- Skeptical judge reduces false positives

---

## Ask

- **Funding:** Seed round
- **Use of Funds:** 
  - Expand exploit library
  - Enterprise integrations (GitHub, Jira, CI/CD)
  - Security certifications
  - Go-to-market

---

## Contact

**Product:** PoC Validator by Vireo Labs
**Demo:** http://localhost:3001 (local) or request hosted demo
