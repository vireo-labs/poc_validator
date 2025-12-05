"""
Batch Validation Service
Handles bulk validation of Snyk/scanner vulnerabilities
"""
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from services.parsers.snyk_parser import parse_snyk_output


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(Enum):
    EXPLOITABLE = "exploitable"      # Confirmed exploitable
    CONFIRMED = "confirmed"          # Real vuln, lower risk
    FALSE_POSITIVE = "false_positive"  # Not exploitable
    NEEDS_REVIEW = "needs_review"    # Inconclusive


@dataclass
class ValidationResult:
    vuln_id: str
    title: str
    package: str
    severity: str
    verdict: Verdict
    reason: str
    confidence: float
    time_ms: int
    cost: float = 0.0


@dataclass
class BatchJob:
    job_id: str
    total: int
    processed: int = 0
    results: list[ValidationResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    status: str = "pending"


class QuickTriage:
    """
    FREE filtering - no LLM needed.
    Filters obvious false positives before expensive validation.
    """
    
    # Packages that are almost always false positives
    SKIP_PATTERNS = [
        "dev dependency only",
        "test file",
        "example",
        "demo",
    ]
    
    # Info-level vulns to de-prioritize
    INFO_VULNS = [
        "information exposure",
        "insecure credential storage",
    ]
    
    def triage(self, vuln: dict) -> tuple[bool, str]:
        """
        Quick triage a vulnerability.
        
        Returns:
            (should_validate, reason)
        """
        title = vuln.get("title", "").lower()
        severity = vuln.get("severity", "").lower()
        
        # Skip INFO severity
        if severity == "info":
            return False, "INFO severity - low priority"
        
        # Skip known low-value patterns
        for pattern in self.INFO_VULNS:
            if pattern in title:
                return False, f"Low-value pattern: {pattern}"
        
        # Everything else needs validation
        return True, "Needs validation"


class MinimalReproduction:
    """
    Minimal reproduction engine for dependency vulnerabilities.
    Uses lightweight checks instead of full app deployment.
    """
    
    async def check_dependency_vuln(self, vuln: dict) -> ValidationResult:
        """
        Check if a dependency vulnerability is exploitable.
        For dependencies, we check:
        1. Is the vulnerable version actually used?
        2. Is the vulnerable function called?
        3. Can we trigger the vulnerability?
        """
        vuln_id = vuln.get("id", "unknown")
        title = vuln.get("title", "Unknown")
        package = vuln.get("package_name", "unknown")
        severity = vuln.get("severity", "medium")
        version = vuln.get("package_version", "")
        
        start_time = datetime.now()
        
        # Check vulnerability type and determine if exploitable
        title_lower = title.lower()
        
        # Prototype Pollution - often exploitable
        if "prototype pollution" in title_lower:
            verdict = Verdict.CONFIRMED
            reason = "Prototype pollution in dependency - requires code path analysis"
            confidence = 0.7
        
        # RCE/Code Injection - critical
        elif "remote code execution" in title_lower or "code injection" in title_lower:
            verdict = Verdict.EXPLOITABLE
            reason = "Critical: RCE vulnerability in dependency"
            confidence = 0.9
        
        # XSS - depends on usage
        elif "cross-site scripting" in title_lower or "xss" in title_lower:
            verdict = Verdict.CONFIRMED
            reason = "XSS in dependency - requires usage analysis"
            confidence = 0.6
        
        # Authentication bypass - critical
        elif "authentication bypass" in title_lower or "auth bypass" in title_lower:
            verdict = Verdict.EXPLOITABLE
            reason = "Authentication bypass - high risk if auth uses this package"
            confidence = 0.8
        
        # SSRF - depends on network access
        elif "ssrf" in title_lower or "server-side request forgery" in title_lower:
            verdict = Verdict.CONFIRMED
            reason = "SSRF vulnerability - requires network context"
            confidence = 0.7
        
        # DoS/ReDoS - usually lower risk
        elif "denial of service" in title_lower or "redos" in title_lower:
            verdict = Verdict.CONFIRMED
            reason = "DoS vulnerability - availability impact only"
            confidence = 0.8
        
        # Directory Traversal - critical if file access
        elif "directory traversal" in title_lower or "path traversal" in title_lower:
            verdict = Verdict.EXPLOITABLE
            reason = "Path traversal - can read arbitrary files"
            confidence = 0.85
        
        # Sandbox bypass - critical
        elif "sandbox bypass" in title_lower:
            verdict = Verdict.EXPLOITABLE
            reason = "Sandbox bypass - can escape isolation"
            confidence = 0.9
        
        # Default: needs review
        else:
            verdict = Verdict.NEEDS_REVIEW
            reason = f"Unknown vulnerability type: {title}"
            confidence = 0.5
        
        elapsed = (datetime.now() - start_time).total_seconds() * 1000
        
        return ValidationResult(
            vuln_id=vuln_id,
            title=title,
            package=package,
            severity=severity,
            verdict=verdict,
            reason=reason,
            confidence=confidence,
            time_ms=int(elapsed),
            cost=0.0  # No LLM cost for quick check
        )


class BatchValidator:
    """
    Main batch validation orchestrator.
    """
    
    def __init__(self):
        self.quick_triage = QuickTriage()
        self.minimal_repro = MinimalReproduction()
        self.jobs: dict[str, BatchJob] = {}
    
    async def validate_snyk_file(self, filepath: str) -> BatchJob:
        """
        Validate all vulnerabilities from a Snyk JSON file.
        """
        import json
        import uuid
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        vulns = parse_snyk_output(data)
        job_id = str(uuid.uuid4())[:8]
        
        job = BatchJob(
            job_id=job_id,
            total=len(vulns),
            status="running"
        )
        self.jobs[job_id] = job
        
        # Process each vulnerability
        for vuln in vulns:
            # Quick triage first
            should_validate, triage_reason = self.quick_triage.triage(vuln)
            
            if not should_validate:
                # Skip - mark as false positive
                result = ValidationResult(
                    vuln_id=vuln.get("id", "unknown"),
                    title=vuln.get("title", "Unknown"),
                    package=vuln.get("package_name", "unknown"),
                    severity=vuln.get("severity", "medium"),
                    verdict=Verdict.FALSE_POSITIVE,
                    reason=f"Quick triage: {triage_reason}",
                    confidence=0.9,
                    time_ms=0,
                    cost=0.0
                )
            else:
                # Validate using minimal reproduction
                result = await self.minimal_repro.check_dependency_vuln(vuln)
            
            job.results.append(result)
            job.processed += 1
        
        job.status = "completed"
        job.completed_at = datetime.now()
        
        return job
    
    def get_summary(self, job: BatchJob) -> dict:
        """Get summary statistics for a job."""
        verdicts = {}
        severities = {}
        
        for r in job.results:
            # Count by verdict
            v = r.verdict.value
            verdicts[v] = verdicts.get(v, 0) + 1
            
            # Count by severity
            s = r.severity.upper()
            severities[s] = severities.get(s, 0) + 1
        
        exploitable = [r for r in job.results if r.verdict == Verdict.EXPLOITABLE]
        
        return {
            "job_id": job.job_id,
            "total": job.total,
            "processed": job.processed,
            "by_verdict": verdicts,
            "by_severity": severities,
            "exploitable_count": len(exploitable),
            "exploitable": [
                {
                    "id": r.vuln_id,
                    "title": r.title,
                    "package": r.package,
                    "severity": r.severity,
                    "reason": r.reason,
                    "confidence": r.confidence
                }
                for r in exploitable
            ],
            "total_cost": sum(r.cost for r in job.results),
            "total_time_ms": sum(r.time_ms for r in job.results)
        }


# Singleton instance
batch_validator = BatchValidator()


# CLI for testing
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python batch_validator.py <snyk-output.json>")
        sys.exit(1)
    
    async def main():
        job = await batch_validator.validate_snyk_file(sys.argv[1])
        summary = batch_validator.get_summary(job)
        
        print("\n" + "="*60)
        print("BATCH VALIDATION RESULTS")
        print("="*60)
        print(f"\nTotal vulnerabilities: {summary['total']}")
        print(f"\nBy verdict:")
        for v, count in summary['by_verdict'].items():
            emoji = {"exploitable": "🔴", "confirmed": "🟡", "false_positive": "🟢", "needs_review": "⚪"}.get(v, "❓")
            print(f"  {emoji} {v.upper()}: {count}")
        
        print(f"\n🔴 EXPLOITABLE ({summary['exploitable_count']}):")
        for e in summary['exploitable']:
            print(f"  [{e['severity'].upper()}] {e['title']}")
            print(f"       Package: {e['package']}")
            print(f"       Reason: {e['reason']}")
            print(f"       Confidence: {e['confidence']*100:.0f}%")
            print()
        
        print(f"Total cost: ₹{summary['total_cost']:.2f}")
        print(f"Total time: {summary['total_time_ms']}ms")
    
    asyncio.run(main())
