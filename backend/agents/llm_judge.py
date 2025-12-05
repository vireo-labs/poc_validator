"""
Agent 5: LLM Judge
Interprets execution results and delivers final verdict.
"""
import json
from services.openrouter import openrouter


SYSTEM_PROMPT = """You are a security expert judging whether a vulnerability was successfully exploited.

Analyze the exploit execution results and return a JSON verdict:
{
    "verdict": "VALID" | "INVALID" | "NEEDS_REVIEW",
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of your verdict",
    "evidence": ["Key evidence point 1", "Key evidence point 2"],
    "recommendations": ["Recommendation 1", "Recommendation 2"]
}

Verdict criteria:
- VALID: Clear evidence of successful exploitation (e.g., unauthorized access, data exfiltration, code execution)
- INVALID: Exploit definitively failed, vulnerability not exploitable
- NEEDS_REVIEW: Inconclusive results, partial success, or requires human analysis

Only output valid JSON."""


class LLMJudgeAgent:
    """Interprets exploit results and delivers verdict."""
    
    async def judge(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """
        Judge whether the vulnerability was successfully exploited.
        
        Args:
            vuln_data: Original vulnerability data
            code_analysis: Code analysis results
            exploit_result: Sandbox execution results
            
        Returns:
            Verdict with reasoning
        """
        # Quick verdict for clear cases
        if exploit_result.get("exploit_succeeded"):
            return {
                "success": True,
                "verdict": "VALID",
                "confidence": 0.95,
                "reasoning": "Exploit executed successfully with clear success indicators",
                "evidence": [
                    f"Exit code: {exploit_result.get('exit_code')}",
                    "SUCCESS pattern found in output"
                ],
                "recommendations": [
                    "Prioritize patching this vulnerability",
                    "Review similar code patterns for same issue"
                ],
                "source": "quick_verdict"
            }
        
        if exploit_result.get("exit_code") != 0 and "FAILED" in exploit_result.get("stdout", ""):
            return {
                "success": True,
                "verdict": "INVALID",
                "confidence": 0.85,
                "reasoning": "Exploit failed with clear failure indicators",
                "evidence": [
                    f"Exit code: {exploit_result.get('exit_code')}",
                    "FAILED pattern found in output"
                ],
                "recommendations": [
                    "May be a false positive from scanner",
                    "Verify if patches have been applied"
                ],
                "source": "quick_verdict"
            }
        
        # Use LLM for nuanced judgment
        return await self._llm_judge(vuln_data, code_analysis, exploit_result)
    
    async def _llm_judge(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """Use LLM for complex verdict decisions."""
        user_content = f"""Judge this exploitation attempt:

## Vulnerability
Type: {vuln_data.get('vulnerability_type')}
Title: {vuln_data.get('title')}
Severity: {vuln_data.get('severity')}

## Code Analysis
File: {code_analysis.get('data', {}).get('file_path')}
Vulnerable: {code_analysis.get('data', {}).get('vulnerable_code_exists')}

## Execution Results
Exit Code: {exploit_result.get('exit_code')}
Duration: {exploit_result.get('duration_ms')}ms

### STDOUT:
{exploit_result.get('stdout', 'No output')[:2000]}

### STDERR:
{exploit_result.get('stderr', 'No errors')[:1000]}

Determine if this vulnerability was successfully exploited."""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.2
            )
            
            parsed = json.loads(response)
            parsed["success"] = True
            parsed["source"] = "llm_judgment"
            return parsed
            
        except json.JSONDecodeError:
            return {
                "success": True,
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.5,
                "reasoning": "Could not parse LLM judgment",
                "evidence": [],
                "recommendations": ["Manual review required"],
                "source": "fallback"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Singleton instance
llm_judge = LLMJudgeAgent()
