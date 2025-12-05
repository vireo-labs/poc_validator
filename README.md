# PoC Validator

**Automated Security Vulnerability Validation**

PoC Validator automatically validates security scanner alerts by attempting to exploit vulnerabilities in a safe sandbox environment. It separates actually exploitable vulnerabilities from false positives.

## What It Does

1. **Parse** vulnerability reports from Snyk, Semgrep, and other scanners
2. **Analyze** code to verify the vulnerable code exists
3. **Generate** exploits dynamically using LLM or cached PoC library
4. **Execute** exploits in isolated sandboxes
5. **Judge** results to deliver a verdict

### Verdicts

- **EXPLOITABLE** - Proven exploitable with actual exploit execution
- **CONFIRMED** - Vulnerable version detected, needs code path verification
- **FALSE_POSITIVE** - Patched or not exploitable
- **NEEDS_REVIEW** - Inconclusive, requires manual review

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker
- OpenRouter API key (for LLM generation)

### Installation

```bash
# Clone the repository
git clone https://github.com/vireo-labs/poc_validator.git
cd poc_validator

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Usage

```bash
# Run Snyk scan on a target project
cd scanner_data
npx snyk test --json > snyk-output.json

# Run validation
cd ../backend
source venv/bin/activate
PYTHONPATH=. python services/integrated_validator.py <project_path> <snyk_output.json>
```

### Example Output

```
Validating 46 unique vulnerabilities (from 76 total)...
  [1/46] [EXPLOIT] vm2@3.9.17: Sandbox escape confirmed
  [2/46] [SAFE] lodash@4.17.21: Patched
  [3/46] [EXPLOIT] jsonwebtoken@0.4.0: None algorithm allowed
  ...

============================================================
VALIDATION COMPLETE
============================================================

Total Snyk alerts: 76
Unique validated: 46

By verdict:
  [EXPLOIT] EXPLOITABLE: 23
  [SAFE] FALSE_POSITIVE: 6
  [REVIEW] NEEDS_REVIEW: 17
```

## Architecture

### Validation Flow

```
Scanner Output (Snyk/Semgrep)
         |
         v
   Universal Parser
         |
         v
   Quick Triage (FREE)
   - Filter test files
   - Deduplicate
         |
         v
   Strategy Router
   - 90%: Minimal reproduction (fast, cheap)
   - 10%: Full deployment (slow, expensive)
         |
         v
   Exploit Generator
   - Check PoC Library (30% hit rate)
   - LLM generates custom exploit (70%)
         |
         v
   Sandbox Executor
   - Run exploit in project context
   - Capture output/proof
         |
         v
   Verdict Classification
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `snyk_parser.py` | Parse Snyk JSON output |
| `integrated_validator.py` | Main validation pipeline |
| `ExploitLibrary` | Cached exploits for known CVEs |
| LLM Generator | Dynamic exploit creation via OpenRouter |

## Exploit Library

Currently supports 7 packages with tested exploits:

| Package | Vulnerability Type |
|---------|-------------------|
| vm2 | RCE (sandbox escape) |
| lodash | Prototype pollution |
| jsonwebtoken | None algorithm attack |
| express-jwt | Auth bypass |
| sanitize-html | XSS bypass |
| moment | Path traversal |
| cookie | XSS |

For packages not in the library, the system uses LLM to generate custom exploit code.

## Project Structure

```
poc_validator/
├── backend/
│   ├── services/
│   │   ├── parsers/
│   │   │   └── snyk_parser.py      # Scanner output parser
│   │   ├── integrated_validator.py  # Main validation pipeline
│   │   └── openrouter.py           # LLM integration
│   ├── agents/                      # Agent implementations
│   └── exploits/                    # Exploit templates
├── scanner_data/                    # Scanner outputs and test repos
├── docs/
│   ├── ARCHITECTURE.md             # System design
│   └── FLOWCHART.md                # Mermaid diagrams
└── frontend/                        # Web UI (Next.js)
```

## API

### Validate Scanner Output

```python
from services.integrated_validator import IntegratedValidator

validator = IntegratedValidator("/path/to/project")
job = await validator.validate_batch("snyk-output.json")
summary = validator.get_summary(job)
```

## Cost Model

| Scenario | Cost | Time |
|----------|------|------|
| Cached exploit | Free | <1s |
| LLM-generated exploit | ~$0.01 | 5-10s |
| Full validation (per vuln) | ~$0.05 | 10s |

## License

Proprietary - Vireo Labs
