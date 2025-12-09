# PoC Validator v0.1.2

**Automated Security Vulnerability Validation with LLM-Powered Exploit Generation**

PoC Validator automatically validates security scanner alerts by attempting to exploit vulnerabilities in a safe environment. It separates actually exploitable vulnerabilities from false positives.

## What's New in v0.1.2

- **Larger LLM Model**: Now uses `qwen/qwen3-235b-a22b-2507` for better exploit generation
- **Skeptical LLM Judge**: Verifies exploit evidence, doesn't blindly trust SUCCESS claims
- **Langfuse Integration**: Full LLM observability and tracing
- **Improved Prompts**: Stricter success criteria to reduce false positives
- **5-Agent Architecture**: Proper pipeline using dedicated agents

## How It Works

```
Snyk/Semgrep Output
       ↓
┌──────────────────┐
│  Report Parser   │  Parse vulnerability data
└────────┬─────────┘
         ↓
┌──────────────────┐
│  Code Analyzer   │  Find vulnerable code in repo
└────────┬─────────┘
         ↓
┌──────────────────┐
│  PoC Discoverer  │  Get exploit (library or LLM)
└────────┬─────────┘
         ↓
┌──────────────────┐
│ Sandbox Executor │  Run exploit (Python/Node.js)
└────────┬─────────┘
         ↓
┌──────────────────┐
│    LLM Judge     │  Skeptically verify evidence
└────────┬─────────┘
         ↓
    VERDICT
```

### Verdicts

- **EXPLOITABLE** - Proven with actual exploit execution and evidence
- **FALSE_POSITIVE** - Patched, not exploitable, or insufficient evidence
- **NEEDS_REVIEW** - Inconclusive, requires manual review

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for dependency exploits)
- OpenRouter API key
- Langfuse account (optional, for observability)

### Installation

```bash
# Clone the repository
git clone https://github.com/vireo-labs/poc_validator.git
cd poc_validator
git checkout dynamic_v0.1.1

# Backend setup
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys:
#   OPENROUTER_API_KEY=sk-or-v1-xxx
#   LANGFUSE_PUBLIC_KEY=pk-lf-xxx (optional)
#   LANGFUSE_SECRET_KEY=sk-lf-xxx (optional)
#   LANGFUSE_HOST=https://cloud.langfuse.com
```

### Run Validation

```bash
cd backend
source venv/bin/activate

# Run with Snyk output
PYTHONPATH=. python services/pipeline.py <snyk_output.json> --project-path <path_to_project>

# Example with Juice Shop
PYTHONPATH=. python services/pipeline.py ../scanner_data/real-snyk-juice-shop.json --project-path ../scanner_data/juice-shop
```

### Example Output

```
Validating 46 unique vulnerabilities (from 76 total)...
  [1/46] [EXPLOIT] vm2: Dependency exploit confirmed vulnerability with evidence
  [2/46] [SAFE] lodash: Exploit explicitly reported failure
  [3/46] [EXPLOIT] jsonwebtoken: Dependency exploit confirmed vulnerability with evidence
  ...

============================================================
VALIDATION COMPLETE
============================================================

Total Snyk alerts: 76
Unique validated: 46

By verdict:
  [EXPLOIT] EXPLOITABLE: 22
  [SAFE] FALSE_POSITIVE: 24

=== EXPLOITABLE (22) ===
  [CRITICAL] vm2
       Remote Code Execution (RCE)
       Source: dependency_library
       Confidence: 95%
```

## Architecture

### 5-Agent Pipeline

| Agent | File | Purpose |
|-------|------|---------|
| Report Parser | `agents/report_parser.py` | Parse scanner output |
| Code Analyzer | `agents/code_analyzer.py` | Find vulnerable code |
| PoC Discoverer | `agents/poc_discoverer.py` | Generate exploits |
| Sandbox Executor | `agents/sandbox_executor.py` | Execute exploits |
| LLM Judge | `agents/llm_judge.py` | Verify and deliver verdict |

### Exploit Library

Supports 10+ packages with tested exploits:

| Package | Vulnerability Type |
|---------|-------------------|
| vm2 | RCE (sandbox escape) |
| lodash | Prototype pollution |
| jsonwebtoken | None algorithm attack |
| express-jwt | Auth bypass |
| sanitize-html | XSS bypass |
| moment | Path traversal |
| marsdb | Code injection |
| braces | ReDoS |

For packages not in the library, the system uses LLM (Qwen 235B) to generate exploit code.

## Project Structure

```
poc_validator/
├── backend/
│   ├── agents/                      # 5 validation agents
│   │   ├── report_parser.py
│   │   ├── code_analyzer.py
│   │   ├── poc_discoverer.py
│   │   ├── sandbox_executor.py
│   │   └── llm_judge.py
│   ├── services/
│   │   ├── pipeline.py              # Main orchestrator
│   │   ├── openrouter.py            # LLM with Langfuse
│   │   └── parsers/snyk_parser.py
│   └── exploits/
│       ├── juice_shop.py            # HTTP exploits
│       └── dependencies.py          # NPM package exploits
├── scanner_data/                    # Test data
└── docs/                            # Documentation
```

## Configuration

### Environment Variables

```bash
# Required
OPENROUTER_API_KEY=sk-or-v1-xxx

# Optional - Langfuse Observability
LANGFUSE_PUBLIC_KEY=pk-lf-xxx
LANGFUSE_SECRET_KEY=sk-lf-xxx
LANGFUSE_HOST=https://cloud.langfuse.com
```

### Model Selection

Default model: `qwen/qwen3-235b-a22b-2507`

To change, edit `backend/services/openrouter.py`:
```python
self.default_model = "your-preferred-model"
```

## Cost Model

| Scenario | Cost | Time |
|----------|------|------|
| Dependency exploit (cached) | Free | <1s |
| LLM-generated exploit | ~$0.02 | 5-15s |
| LLM verdict verification | ~$0.01 | 3-5s |
| Full validation (per vuln) | ~$0.05 | 10-20s |

## Langfuse Integration

All LLM calls are traced in Langfuse with:
- Model used
- Token usage
- Latency
- Metadata (package, severity, vuln_type)

View traces at: https://cloud.langfuse.com

## API Usage

```python
import asyncio
from services.pipeline import PipelineOrchestrator

async def validate():
    orchestrator = PipelineOrchestrator(
        project_path="./my-project"
    )
    summary = await orchestrator.validate_batch("snyk-output.json")
    print(summary)

asyncio.run(validate())
```

## License

Proprietary - Vireo Labs
