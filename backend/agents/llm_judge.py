"""
Agent 5: LLM Judge
Interprets execution results and delivers final verdict.
HARDCORE SKEPTICAL - never blindly trusts claims, always verifies evidence.
"""
import json
import re
from services.openrouter import openrouter


SYSTEM_PROMPT = """You are an EXTREMELY SKEPTICAL security expert judging whether a vulnerability was ACTUALLY exploited.

Your default stance is: "This exploit probably didn't work. Prove me wrong."

## EVIDENCE REQUIREMENTS

For VALID verdict, you MUST see AT LEAST ONE of these CONCRETE EVIDENCE types:

1. **DATA LEAKAGE**: Actual sensitive data visible in output
   - Database records, passwords, tokens, PII
   - File contents that shouldn't be accessible
   
2. **AUTH BYPASS**: Clear proof of unauthorized access
   - Admin panel content, protected API responses
   - JWT tokens accepted without proper signature
   
3. **CODE EXECUTION**: Proof that arbitrary code ran
   - Output of injected commands (whoami, id, etc.)
   - File system changes, process execution
   - "SANDBOX_ESCAPED" or similar escape confirmation
   
4. **TIMING ATTACKS**: Measurable delay
   - ReDoS: Response time > 1000ms
   - Blind injection: Noticeable delay
   
5. **REFLECTED PAYLOADS**: Payload in response
   - XSS: Unescaped script tags in HTML
   - Injection: Query reflected in error

6. **VULNERABLE PACKAGE CONFIRMATION**:
   - Output explicitly states "VULNERABLE:" with evidence
   - Package version confirmed to be in vulnerable range

## RED FLAGS (Mark INVALID unless explained):

- Output just says "SUCCESS" with no details
- Python/Node errors or exceptions
- "Cannot read property" or similar runtime errors
- Connection refused, timeout without impact
- Exploit script crashed before completion
- Output says "test passed" without exploitation proof

## VERDICT CRITERIA:

VALID (0.8-1.0 confidence):
- Clear evidence from list above
- The evidence proves ACTUAL exploitation, not just attempt

INVALID (0.8-1.0 confidence):
- Exploit clearly failed
- BLOCKED/FAILED in output
- No evidence despite successful execution
- Patched version detected

NEEDS_REVIEW (0.5-0.7 confidence):
- Ambiguous output
- Partial evidence
- Edge cases

Return ONLY valid JSON:
{
    "verdict": "VALID" | "INVALID" | "NEEDS_REVIEW",
    "confidence": 0.0-1.0,
    "reasoning": "Explain what evidence you found or why it's missing",
    "evidence": ["Specific evidence from output"],
    "recommendations": ["Action items"]
}"""


class LLMJudgeAgent:
    """Interprets exploit results with HARDCORE SKEPTICISM."""
    
    # Patterns that PROVE exploitation
    VULNERABLE_PATTERNS = [
        r"VULNERABLE:",           # Our exploits use this
        r"SANDBOX_ESCAPED",       # vm2 sandbox bypass
        r"RCE possible",          # Remote code execution
        r"auth bypass",           # Authentication bypass
        r"leaked.*password",      # Data leakage
        r"leaked.*token",         # Token leakage
        r"admin.*access",         # Unauthorized access
    ]
    
    # Patterns that PROVE failure/blocking
    BLOCKED_PATTERNS = [
        r"BLOCKED:",              # Our exploits use this
        r"FAILED:",               # Explicit failure
        r"patched",               # Patched version
        r"sanitized",             # Input was sanitized
        r"Access denied",         # Access control worked
        r"401|403",               # Auth/authz blocked
    ]
    
    # Patterns that indicate BROKEN EXPLOIT (not target protection)
    BROKEN_EXPLOIT_PATTERNS = [
        r"Cannot read propert",   # JS property error
        r"undefined is not",      # JS undefined error
        r"TypeError:",            # Type errors
        r"ReferenceError:",       # Reference errors
        r"SyntaxError:",          # Syntax errors
        r"ModuleNotFoundError",   # Python import error
        r"ImportError",           # Python import error
        r"No such file",          # File not found
        r"ENOENT",                # Node file not found
        r"CONNECTION_REFUSED",    # Connection refused
    ]
    
    async def judge(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """
        Judge whether the vulnerability was successfully exploited.
        HARDCORE SKEPTICAL - default to INVALID unless proven otherwise.
        """
        stdout = exploit_result.get("stdout", "")
        stderr = exploit_result.get("stderr", "")
        exit_code = exploit_result.get("exit_code", 1)
        combined_output = f"{stdout}\n{stderr}"
        
        # ================================================================
        # PHASE 1: Quick Accept - Clear VULNERABLE evidence
        # ================================================================
        for pattern in self.VULNERABLE_PATTERNS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                evidence_lines = [line for line in stdout.split('\n') 
                                  if re.search(pattern, line, re.IGNORECASE)]
                return {
                    "success": True,
                    "verdict": "VALID",
                    "confidence": 0.95,
                    "reasoning": "Exploit confirmed vulnerability with concrete evidence",
                    "evidence": evidence_lines[:3] if evidence_lines else [f"Pattern matched: {pattern}"],
                    "recommendations": [
                        "Update the vulnerable package immediately",
                        "Check for other usages of this package"
                    ],
                    "source": "pattern_match_vulnerable"
                }
        
        # ================================================================
        # PHASE 2: Quick Reject - Clear BLOCKED/FAILED evidence  
        # ================================================================
        for pattern in self.BLOCKED_PATTERNS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                return {
                    "success": True,
                    "verdict": "INVALID",
                    "confidence": 0.90,
                    "reasoning": "Exploit was blocked - vulnerability patched or mitigated",
                    "evidence": [f"Pattern matched: {pattern}"],
                    "recommendations": ["Vulnerability appears to be patched"],
                    "source": "pattern_match_blocked"
                }
        
        # ================================================================
        # PHASE 3: Detect BROKEN EXPLOIT (our code is wrong, not target patched)
        # ================================================================
        for pattern in self.BROKEN_EXPLOIT_PATTERNS:
            if re.search(pattern, combined_output, re.IGNORECASE):
                # This is tricky - the exploit broke, but is target vulnerable?
                # Be conservative: mark as NEEDS_REVIEW since we can't tell
                return {
                    "success": True,
                    "verdict": "NEEDS_REVIEW",
                    "confidence": 0.60,
                    "reasoning": f"Exploit script encountered error: {pattern}. Cannot determine if target is vulnerable.",
                    "evidence": [
                        f"Error pattern: {pattern}",
                        "Exploit may be broken or target may be patched"
                    ],
                    "recommendations": [
                        "Review exploit code for errors",
                        "Manual testing recommended",
                        "Update exploit to handle this case"
                    ],
                    "source": "broken_exploit_detected"
                }
        
        # ================================================================
        # PHASE 4: Check for empty or suspicious output
        # ================================================================
        if not stdout.strip() and not stderr.strip():
            return {
                "success": True,
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.50,
                "reasoning": "No output from exploit - cannot determine result",
                "evidence": ["Empty stdout and stderr"],
                "recommendations": ["Manual review required"],
                "source": "empty_output"
            }
        
        # Only "SUCCESS" with no details = suspicious
        if re.search(r"^SUCCESS$", stdout.strip(), re.MULTILINE):
            if len(stdout) < 50:  # Very short output with just SUCCESS
                return {
                    "success": True,
                    "verdict": "NEEDS_REVIEW",
                    "confidence": 0.55,
                    "reasoning": "Output claims SUCCESS but provides no evidence",
                    "evidence": ["Generic SUCCESS without proof"],
                    "recommendations": ["Verify manually - success claim unsubstantiated"],
                    "source": "unsubstantiated_success"
                }
        
        # ================================================================
        # PHASE 5: Non-zero exit with errors = likely failure
        # ================================================================
        if exit_code != 0:
            return {
                "success": True,
                "verdict": "INVALID",
                "confidence": 0.85,
                "reasoning": f"Exploit exited with error code {exit_code}",
                "evidence": [
                    f"Exit code: {exit_code}",
                    stderr[:200] if stderr else "No stderr"
                ],
                "recommendations": ["Exploit failed to execute properly"],
                "source": "non_zero_exit"
            }
        
        # ================================================================
        # PHASE 6: Use LLM for ambiguous cases (SKEPTICALLY)
        # ================================================================
        return await self._llm_verify_skeptical(vuln_data, code_analysis, exploit_result)
    
    async def _llm_verify_skeptical(
        self,
        vuln_data: dict,
        code_analysis: dict,
        exploit_result: dict
    ) -> dict:
        """Use LLM with MAXIMUM SKEPTICISM to verify exploit results."""
        stdout = exploit_result.get('stdout', 'No output')
        stderr = exploit_result.get('stderr', 'No errors')
        
        user_content = f"""SKEPTICALLY analyze this exploitation attempt.

DEFAULT STANCE: This exploit probably FAILED. Prove me wrong with CONCRETE EVIDENCE.

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

## YOUR TASK:
1. Look for CONCRETE EVIDENCE of exploitation (leaked data, bypassed auth, RCE output, timing delays, reflected payloads)
2. If you see ONLY generic "success" messages without proof, mark INVALID
3. If output shows errors/exceptions, mark INVALID or NEEDS_REVIEW
4. Be PARANOID - assume the exploit failed unless you have proof

Return ONLY JSON with verdict, confidence, reasoning, evidence, recommendations."""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.1,  # Lower temp for more consistent skepticism
                trace_name="llm_judge_skeptical",
                metadata={
                    "vuln_type": vuln_data.get('vulnerability_type'),
                    "package": vuln_data.get('package_name'),
                    "severity": vuln_data.get('severity'),
                    "exit_code": exploit_result.get('exit_code'),
                    "output_length": len(stdout)
                }
            )
            
            # Parse JSON response
            parsed = self._parse_json_response(response)
            parsed["success"] = True
            parsed["source"] = "llm_skeptical_verified"
            return parsed
            
        except Exception as e:
            return {
                "success": True,
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.50,
                "reasoning": f"LLM verification failed: {str(e)}",
                "evidence": [],
                "recommendations": ["Manual review required"],
                "source": "llm_error_fallback"
            }
    
    def _parse_json_response(self, response: str) -> dict:
        """Robustly parse JSON from LLM response."""
        # Try direct parse
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON block
        try:
            # Look for JSON in code blocks
            json_match = re.search(r'```(?:json)?\s*(\{[^`]+\})\s*```', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
        except:
            pass
        
        # Try to find any JSON object
        try:
            json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        # Fallback
        return {
            "verdict": "NEEDS_REVIEW",
            "confidence": 0.50,
            "reasoning": "Could not parse LLM judgment",
            "evidence": [],
            "recommendations": ["Manual review required"]
        }


# Singleton instance
llm_judge = LLMJudgeAgent()
