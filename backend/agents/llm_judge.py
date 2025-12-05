"""
Agent 5: LLM Judge
Interprets execution results and delivers final verdict.
Always verifies exploit output - never blindly trusts SUCCESS claims.
"""
import json
from services.openrouter import openrouter


SYSTEM_PROMPT = """You are a skeptical security expert judging whether a vulnerability was ACTUALLY exploited.

Your job is to VERIFY the exploit output - don't blindly trust "SUCCESS" claims.

Analyze the exploit execution results and return a JSON verdict:
{
    "verdict": "VALID" | "INVALID" | "NEEDS_REVIEW",
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of your verdict",
    "evidence": ["Key evidence point 1", "Key evidence point 2"],
    "recommendations": ["Recommendation 1", "Recommendation 2"]
}

STRICT Verdict criteria:
- VALID: You see CONCRETE EVIDENCE in the output:
  * Leaked data that shouldn't be accessible
  * Auth bypass with access to protected resources
  * RCE with command output
  * Response time > 5s for ReDoS
  * Reflected payload for XSS
  
- INVALID: The exploit clearly failed:
  * Quick responses for ReDoS (< 5s)
  * Payload was escaped/sanitized
  * Access denied / 401/403 responses
  * No evidence of impact

- NEEDS_REVIEW: Results are ambiguous

BE SKEPTICAL! If the exploit just says "SUCCESS" without showing actual evidence of exploitation, mark as INVALID or NEEDS_REVIEW.

Only output valid JSON."""


class LLMJudgeAgent:
    """Interprets exploit results and delivers verdict with skeptical verification."""
    
    async def judge(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """
        Judge whether the vulnerability was successfully exploited.
        Always verifies claims - never blindly trusts SUCCESS pattern.
        """
        stdout = exploit_result.get("stdout", "")
        stderr = exploit_result.get("stderr", "")
        exit_code = exploit_result.get("exit_code", 1)
        
        # Quick rejection for obvious failures
        if exit_code != 0 and "FAILED:" in stdout:
            return {
                "success": True,
                "verdict": "INVALID",
                "confidence": 0.90,
                "reasoning": "Exploit explicitly reported failure",
                "evidence": [
                    f"Exit code: {exit_code}",
                    "FAILED pattern in output"
                ],
                "recommendations": [
                    "Likely a false positive from scanner",
                    "Check if patches have been applied"
                ],
                "source": "quick_reject"
            }
        
        # For BLOCKED patterns (dependency exploits)
        if "BLOCKED:" in stdout or "BLOCKED:" in stderr:
            return {
                "success": True,
                "verdict": "INVALID",
                "confidence": 0.90,
                "reasoning": "Exploit was blocked - vulnerability patched or mitigated",
                "evidence": ["BLOCKED pattern in output"],
                "recommendations": ["Vulnerability appears to be patched"],
                "source": "quick_reject"
            }
        
        # For VULNERABLE patterns (dependency exploits) - these are reliable
        if "VULNERABLE:" in stdout:
            # Extract the evidence after VULNERABLE:
            evidence_line = [line for line in stdout.split('\n') if 'VULNERABLE:' in line]
            return {
                "success": True,
                "verdict": "VALID",
                "confidence": 0.95,
                "reasoning": "Dependency exploit confirmed vulnerability with evidence",
                "evidence": evidence_line[:2] if evidence_line else ["VULNERABLE pattern found"],
                "recommendations": [
                    "Update the vulnerable package immediately",
                    "Check for other usages of this package"
                ],
                "source": "dependency_exploit"
            }
        
        # For all other cases, use LLM to verify
        return await self._llm_verify(vuln_data, code_analysis, exploit_result)
    
    async def _llm_verify(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """Use LLM to skeptically verify exploit results."""
        stdout = exploit_result.get('stdout', 'No output')
        stderr = exploit_result.get('stderr', 'No errors')
        
        user_content = f"""Skeptically verify this exploitation attempt:

## Vulnerability
Type: {vuln_data.get('vulnerability_type')}
Title: {vuln_data.get('title')}
Package: {vuln_data.get('package_name')}
Severity: {vuln_data.get('severity')}

## Execution Results
Exit Code: {exploit_result.get('exit_code')}
Duration: {exploit_result.get('duration_ms')}ms

### STDOUT:
{stdout[:2000]}

### STDERR:
{stderr[:1000]}

IMPORTANT: Look for ACTUAL EVIDENCE of exploitation in the output.
- Just printing "SUCCESS" is NOT enough
- Need to see: leaked data, bypassed auth, slow response times, reflected payloads, etc.
- If no concrete evidence, mark as INVALID or NEEDS_REVIEW"""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.2,
                trace_name="llm_judge_verify",
                metadata={
                    "vuln_type": vuln_data.get('vulnerability_type'),
                    "package": vuln_data.get('package_name'),
                    "severity": vuln_data.get('severity'),
                    "exit_code": exploit_result.get('exit_code'),
                    "has_success": "SUCCESS" in stdout
                }
            )
            
            # Parse JSON response
            parsed = json.loads(response)
            parsed["success"] = True
            parsed["source"] = "llm_verified"
            return parsed
            
        except json.JSONDecodeError:
            # Try to extract JSON from response
            try:
                import re
                json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    parsed["success"] = True
                    parsed["source"] = "llm_verified_extracted"
                    return parsed
            except:
                pass
            
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
