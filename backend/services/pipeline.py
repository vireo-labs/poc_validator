"""
Validation Pipeline Orchestrator

This is the MAIN pipeline that orchestrates the 5 agents according to the architecture:
1. Report Parser - Parse scanner output
2. Code Analyzer - Find vulnerable code in repo
3. PoC Discoverer - Get exploit from library or generate via LLM
4. Sandbox Executor - Run exploit in isolated environment
5. LLM Judge - Analyze results and deliver verdict

Flow:
Scanner Input -> Quick Triage -> Strategy Router -> 5-Agent Pipeline -> Verdict
"""
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List

# Import the 5 agents
from agents.report_parser import report_parser
from agents.code_analyzer import code_analyzer
from agents.poc_discoverer import poc_discoverer
from agents.sandbox_executor import sandbox_executor
from agents.llm_judge import llm_judge

# Import parsers
from services.parsers.snyk_parser import parse_snyk_output


class Verdict(Enum):
    EXPLOITABLE = "exploitable"       # Proven with real exploit
    CONFIRMED = "confirmed"           # Vulnerable version, needs code path check
    FALSE_POSITIVE = "false_positive" # Patched or not exploitable
    NEEDS_REVIEW = "needs_review"     # Inconclusive


class ExecutionStrategy(Enum):
    MINIMAL = "minimal"       # 90% - Quick test, ~10 seconds
    FULL = "full"            # 10% - Full deployment, ~5 minutes
    

@dataclass
class ValidationResult:
    vuln_id: str
    title: str
    package: str
    severity: str
    verdict: Verdict
    confidence: float
    reason: str
    # Agent outputs
    parsed_data: dict = field(default_factory=dict)
    code_analysis: dict = field(default_factory=dict)
    exploit_info: dict = field(default_factory=dict)
    execution_result: dict = field(default_factory=dict)
    judgment: dict = field(default_factory=dict)
    # Metadata
    strategy: str = "minimal"
    time_ms: int = 0
    skipped: bool = False
    skip_reason: str = ""


class QuickTriage:
    """
    Stage 2: Quick Triage (FREE - No AI)
    Filters obvious false positives before expensive validation.
    """
    
    # Patterns to filter
    TEST_PATTERNS = ["/test/", "/tests/", "/__tests__/", "/spec/", "_test.", ".test.", "_spec."]
    DEAD_CODE_MARKERS = ["deprecated", "unused", "legacy", "old_"]
    
    def should_skip(self, vuln: dict) -> tuple[bool, str]:
        """
        Check if vulnerability should be skipped.
        Returns (should_skip, reason)
        """
        title = vuln.get("title", "").lower()
        file_path = vuln.get("affected_file", "").lower()
        severity = vuln.get("severity", "").upper()
        
        # Filter INFO severity
        if severity == "INFO":
            return True, "INFO severity - likely informational"
        
        # Filter test files
        for pattern in self.TEST_PATTERNS:
            if pattern in file_path:
                return True, f"Test file ({pattern})"
        
        # Filter dead code markers
        for marker in self.DEAD_CODE_MARKERS:
            if marker in file_path or marker in title:
                return True, f"Appears to be dead code ({marker})"
        
        return False, ""
    
    def deduplicate(self, vulns: list) -> list:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique = []
        for v in vulns:
            key = f"{v.get('package_name', '')}:{v.get('title', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique


class StrategyRouter:
    """
    Stage 3: Determine validation strategy.
    90% go to MINIMAL path (quick, cheap)
    10% go to FULL path (slow, expensive)
    """
    
    # Vulnerability types requiring full deployment
    FULL_DEPLOYMENT_TYPES = [
        "auth bypass", "authentication bypass", "authorization bypass",
        "business logic", "race condition", "session", "csrf",
        "privilege escalation", "access control"
    ]
    
    def determine_strategy(self, vuln: dict) -> ExecutionStrategy:
        """Determine whether to use minimal or full validation."""
        vuln_type = vuln.get("vulnerability_type", "").lower()
        title = vuln.get("title", "").lower()
        
        for pattern in self.FULL_DEPLOYMENT_TYPES:
            if pattern in vuln_type or pattern in title:
                return ExecutionStrategy.FULL
        
        return ExecutionStrategy.MINIMAL


class PipelineOrchestrator:
    """
    Main orchestrator that runs the 5-agent pipeline.
    """
    
    def __init__(self, repo_url: str = None, project_path: str = None):
        self.repo_url = repo_url
        self.project_path = Path(project_path).resolve() if project_path else None
        self.triage = QuickTriage()
        self.router = StrategyRouter()
    
    async def validate_single(self, vuln: dict) -> ValidationResult:
        """
        Run the 5-agent pipeline on a single vulnerability.
        """
        start = datetime.now()
        vuln_id = vuln.get("id", "unknown")
        title = vuln.get("title", "Unknown")
        package = vuln.get("package_name", "unknown")
        severity = vuln.get("severity", "medium").upper()
        
        # Quick triage
        should_skip, skip_reason = self.triage.should_skip(vuln)
        if should_skip:
            return ValidationResult(
                vuln_id=vuln_id,
                title=title,
                package=package,
                severity=severity,
                verdict=Verdict.FALSE_POSITIVE,
                confidence=0.9,
                reason=skip_reason,
                skipped=True,
                skip_reason=skip_reason,
                time_ms=int((datetime.now() - start).total_seconds() * 1000)
            )
        
        # Determine strategy
        strategy = self.router.determine_strategy(vuln)
        
        # ===== AGENT 1: Report Parser =====
        # For Snyk data, we already have parsed data, but we can enhance it
        parsed_data = {
            "title": title,
            "vulnerability_type": vuln.get("vulnerability_type", "Unknown"),
            "severity": severity,
            "affected_file": vuln.get("affected_file", ""),
            "description": vuln.get("description", ""),
            "package_name": package,
            "cve_id": vuln.get("cve_id", ""),
        }
        
        # ===== AGENT 2: Code Analyzer =====
        code_analysis = {}
        if self.repo_url:
            try:
                code_analysis = await code_analyzer.analyze(parsed_data, self.repo_url)
            except Exception as e:
                code_analysis = {"success": False, "error": str(e)}
        else:
            # If no repo URL, mark as needing analysis
            code_analysis = {
                "success": True,
                "data": {"vulnerable_code_exists": True},
                "classification": {"strategy": strategy.value}
            }
        
        # If code analysis says no vulnerable code exists, it's false positive
        if code_analysis.get("data", {}).get("vulnerable_code_exists") == False:
            return ValidationResult(
                vuln_id=vuln_id,
                title=title,
                package=package,
                severity=severity,
                verdict=Verdict.FALSE_POSITIVE,
                confidence=code_analysis.get("data", {}).get("confidence", 0.7),
                reason="Vulnerable code not found in repository",
                parsed_data=parsed_data,
                code_analysis=code_analysis,
                strategy=strategy.value,
                time_ms=int((datetime.now() - start).total_seconds() * 1000)
            )
        
        # ===== AGENT 3: PoC Discoverer =====
        exploit_info = await poc_discoverer.discover(parsed_data, code_analysis)
        
        if not exploit_info.get("success"):
            return ValidationResult(
                vuln_id=vuln_id,
                title=title,
                package=package,
                severity=severity,
                verdict=Verdict.NEEDS_REVIEW,
                confidence=0.4,
                reason=f"Failed to generate exploit: {exploit_info.get('error', 'Unknown')}",
                parsed_data=parsed_data,
                code_analysis=code_analysis,
                exploit_info=exploit_info,
                strategy=strategy.value,
                time_ms=int((datetime.now() - start).total_seconds() * 1000)
            )
        
        # ===== AGENT 4: Sandbox Executor =====
        exploit_code = exploit_info.get("exploit_code", "")
        exploit_name = exploit_info.get("exploit_name", f"Exploit for {title}")
        exploit_language = exploit_info.get("language", "python")
        
        # Pass project path for Node.js exploits that need node_modules
        project_path_str = str(self.project_path) if self.project_path else None
        
        execution_result = await sandbox_executor.execute(
            exploit_code=exploit_code,
            exploit_name=exploit_name,
            language=exploit_language,
            project_path=project_path_str
        )
        
        # ===== AGENT 5: LLM Judge =====
        judgment = await llm_judge.judge(parsed_data, code_analysis, execution_result)
        
        # Map LLM verdict to our Verdict enum
        llm_verdict = judgment.get("verdict", "NEEDS_REVIEW")
        if llm_verdict == "VALID":
            verdict = Verdict.EXPLOITABLE
        elif llm_verdict == "INVALID":
            verdict = Verdict.FALSE_POSITIVE
        else:
            verdict = Verdict.NEEDS_REVIEW
        
        return ValidationResult(
            vuln_id=vuln_id,
            title=title,
            package=package,
            severity=severity,
            verdict=verdict,
            confidence=judgment.get("confidence", 0.5),
            reason=judgment.get("reasoning", "See judgment details"),
            parsed_data=parsed_data,
            code_analysis=code_analysis,
            exploit_info=exploit_info,
            execution_result=execution_result,
            judgment=judgment,
            strategy=strategy.value,
            time_ms=int((datetime.now() - start).total_seconds() * 1000)
        )
    
    async def validate(self, snyk_data: dict) -> dict:
        """
        Validate all vulnerabilities from Snyk data dict.
        Use this for API uploads where data is already parsed.
        """
        vulns = parse_snyk_output(snyk_data)
        
        # Deduplicate
        unique_vulns = self.triage.deduplicate(vulns)
        
        print(f"Validating {len(unique_vulns)} unique vulnerabilities (from {len(vulns)} total)...")
        
        results = []
        for i, vuln in enumerate(unique_vulns, 1):
            result = await self.validate_single(vuln)
            results.append(result)
            
            # Progress
            status = {
                "exploitable": "[EXPLOIT]",
                "confirmed": "[CONFIRM]", 
                "false_positive": "[SAFE]",
                "needs_review": "[REVIEW]"
            }.get(result.verdict.value, "[?]")
            
            print(f"  [{i}/{len(unique_vulns)}] {status} {result.package}: {result.reason[:50]}")
        
        return self._build_summary(vulns, results)
    
    async def validate_batch(self, snyk_file: str) -> dict:
        """
        Validate all vulnerabilities from Snyk output.
        """
        # Load Snyk data
        with open(snyk_file, 'r') as f:
            data = json.load(f)
        
        vulns = parse_snyk_output(data)
        
        # Deduplicate
        unique_vulns = self.triage.deduplicate(vulns)
        
        print(f"Validating {len(unique_vulns)} unique vulnerabilities (from {len(vulns)} total)...")
        
        results = []
        for i, vuln in enumerate(unique_vulns, 1):
            result = await self.validate_single(vuln)
            results.append(result)
            
            # Progress
            status = {
                "exploitable": "[EXPLOIT]",
                "confirmed": "[CONFIRM]", 
                "false_positive": "[SAFE]",
                "needs_review": "[REVIEW]"
            }.get(result.verdict.value, "[?]")
            
            print(f"  [{i}/{len(unique_vulns)}] {status} {result.package}: {result.reason[:50]}")
        
        return self._build_summary(vulns, results)
    
    def _build_summary(self, all_vulns: list, results: list) -> dict:
        """Build summary of validation results."""
        by_verdict = {}
        for r in results:
            v = r.verdict.value
            by_verdict[v] = by_verdict.get(v, 0) + 1
        
        exploitable = [r for r in results if r.verdict == Verdict.EXPLOITABLE]
        
        return {
            "total_scanned": len(all_vulns),
            "unique_validated": len(results),
            "by_verdict": by_verdict,
            "exploitable_count": len(exploitable),
            "exploitable": [
                {
                    "package": r.package,
                    "title": r.title,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "reason": r.reason,
                    "strategy": r.strategy,
                    "exploit_source": r.exploit_info.get("source", "unknown"),
                }
                for r in exploitable
            ],
            "results": [
                {
                    "vuln_id": r.vuln_id,
                    "package": r.package,
                    "title": r.title,
                    "severity": r.severity,
                    "verdict": r.verdict.value,
                    "confidence": r.confidence,
                    "reason": r.reason,
                    "time_ms": r.time_ms,
                }
                for r in results
            ]
        }


# CLI
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pipeline.py <snyk_output.json> [--project-path <path>] [--repo-url <url>]")
        print("")
        print("Options:")
        print("  --project-path  Path to project with node_modules (for dependency exploits)")
        print("  --repo-url      GitHub repo URL (for code analysis)")
        sys.exit(1)
    
    snyk_file = sys.argv[1]
    repo_url = None
    project_path = None
    
    if "--repo-url" in sys.argv:
        idx = sys.argv.index("--repo-url")
        if idx + 1 < len(sys.argv):
            repo_url = sys.argv[idx + 1]
    
    if "--project-path" in sys.argv:
        idx = sys.argv.index("--project-path")
        if idx + 1 < len(sys.argv):
            project_path = sys.argv[idx + 1]
    
    async def main():
        orchestrator = PipelineOrchestrator(repo_url=repo_url, project_path=project_path)
        summary = await orchestrator.validate_batch(snyk_file)
        
        print("\n" + "="*60)
        print("VALIDATION COMPLETE")
        print("="*60)
        print(f"\nTotal Snyk alerts: {summary['total_scanned']}")
        print(f"Unique validated: {summary['unique_validated']}")
        print(f"\nBy verdict:")
        for v, count in summary['by_verdict'].items():
            status = {
                "exploitable": "[EXPLOIT]",
                "confirmed": "[CONFIRM]",
                "false_positive": "[SAFE]",
                "needs_review": "[REVIEW]"
            }.get(v, "[?]")
            print(f"  {status} {v.upper()}: {count}")
        
        print(f"\n=== EXPLOITABLE ({summary['exploitable_count']}) ===")
        for e in summary['exploitable']:
            print(f"  [{e['severity']}] {e['package']}")
            print(f"       {e['title']}")
            print(f"       Source: {e['exploit_source']}")
            print(f"       Confidence: {e['confidence']:.0%}")
            print()
        
        # Save results
        output_file = "validation-results.json"
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"[OK] Results saved to {output_file}")
    
    asyncio.run(main())
