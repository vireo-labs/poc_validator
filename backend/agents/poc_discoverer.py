"""
Agent 3: PoC Discoverer
Generates exploit code dynamically based on code analysis.
Uses tested exploits when available, falls back to LLM generation.
"""
import json
from typing import Optional
from services.openrouter import openrouter
from services.github_service import github_service
from exploits.juice_shop import get_exploit_for_vuln_type, EXPLOIT_MAP


SYSTEM_PROMPT = """You are a security exploit developer. Generate a Python exploit script for the given vulnerability.

The script MUST:
1. Use httpx for HTTP requests
2. TARGET_URL variable is pre-defined with the target URL
3. Print "SUCCESS:" followed by CONCRETE EVIDENCE if exploit works
4. Print "FAILED:" with reason if exploit fails
5. Include a main exploit() function that returns True/False
6. Exit with code 0 on success, 1 on failure

CRITICAL - Only return SUCCESS if you have ACTUAL EVIDENCE of exploitation:
- ReDoS: Response time > 5 seconds indicates vulnerability
- XSS: Payload reflected UNESCAPED in response body
- SQLi: Data returned that shouldn't be accessible, or error messages revealing DB
- Auth Bypass: Access to protected resource without valid credentials
- RCE: Command output visible in response
- SSRF: Internal resource accessed or response from internal service

DO NOT return SUCCESS just because:
- Server responded with 200/400/404
- Server didn't crash
- Request was accepted

Return ONLY the Python code, no markdown code blocks or explanations.

Example structure:
import httpx
import time

def exploit():
    start = time.time()
    target = TARGET_URL + "/endpoint"
    response = httpx.get(target)
    elapsed = time.time() - start
    
    # Check for ACTUAL evidence
    if elapsed > 5:  # ReDoS evidence
        print(f"SUCCESS: ReDoS confirmed - response took {elapsed:.2f}s")
        return True
    print(f"FAILED: Response was fast ({elapsed:.2f}s), not vulnerable")
    return False

if __name__ == "__main__":
    import sys
    sys.exit(0 if exploit() else 1)
"""


class PoCDiscovererAgent:
    """Generates exploit code using tested exploits or LLM generation."""
    
    async def discover(self, vuln_data: dict, code_analysis: dict) -> dict:
        """
        Generate exploit based on vulnerability type and code analysis.
        
        Priority:
        1. Dependency exploits (for npm package vulnerabilities)
        2. HTTP exploits (for runtime vulnerabilities like SQLi, XSS)
        3. LLM-generated exploit (fallback)
        
        Args:
            vuln_data: Parsed vulnerability data
            code_analysis: Code analysis results with actual code context
            
        Returns:
            Exploit code and metadata
        """
        vuln_type = vuln_data.get("vulnerability_type", "")
        title = vuln_data.get("title", "")
        package_name = vuln_data.get("package_name", "")
        
        # First: Check for dependency exploits (npm packages)
        if package_name:
            from exploits.dependencies import get_dependency_exploit
            dep_exploit = get_dependency_exploit(package_name)
            if dep_exploit:
                return {
                    "success": True,
                    "exploit_code": dep_exploit["code"],
                    "exploit_name": f"Dependency Exploit: {package_name}",
                    "source": "dependency_library",
                    "exploit_type": dep_exploit["type"],
                    "language": dep_exploit.get("language", "javascript"),
                    "confidence": 0.95,
                    "based_on_file": None
                }
        
        # Second: Check for HTTP exploits (runtime vulnerabilities)
        tested_exploit = get_exploit_for_vuln_type(vuln_type)
        
        if tested_exploit:
            exploit_name = f"HTTP Exploit: {title[:50]}" if title else f"HTTP {vuln_type} Exploit"
            return {
                "success": True,
                "exploit_code": tested_exploit,
                "exploit_name": exploit_name,
                "source": "http_exploit_library",
                "exploit_type": vuln_type,
                "language": "python",
                "confidence": 0.95,
                "based_on_file": code_analysis.get("data", {}).get("file_path")
            }
        
        # Third: Fall back to LLM-generated exploit
        analysis_data = code_analysis.get("data", {})
        
        # Get additional code context if we have repo path
        repo_path = code_analysis.get("repo_path")
        additional_context = ""
        
        if repo_path and analysis_data.get("file_path"):
            file_content = github_service.read_file(repo_path, analysis_data["file_path"])
            if file_content:
                additional_context = f"\n\nFull vulnerable file content:\n{file_content[:4000]}"
        
        # Generate exploit using LLM
        return await self._generate_exploit(vuln_data, analysis_data, additional_context)
    
    async def _generate_exploit(self, vuln_data: dict, analysis_data: dict, additional_context: str) -> dict:
        """Generate exploit using LLM based on actual code."""
        
        user_content = f"""Generate a Python exploit for this vulnerability:

## Vulnerability Details
Type: {vuln_data.get('vulnerability_type')}
Title: {vuln_data.get('title')}
Description: {vuln_data.get('description')}
Exploitation Steps: {vuln_data.get('exploitation_steps', [])}

## Vulnerable Code Analysis
File: {analysis_data.get('file_path', 'Unknown')}
Line: {analysis_data.get('vulnerable_line', 'Unknown')}
Pattern: {analysis_data.get('vulnerability_pattern', 'Unknown')}
Explanation: {analysis_data.get('explanation', '')}
{additional_context}

## Target Application
The target is OWASP Juice Shop running at TARGET_URL (typically http://juice-shop:3000 or http://localhost:3000).

Generate a complete, working Python exploit that:
1. Exploits this specific vulnerability
2. Provides clear SUCCESS/FAILED output
3. Uses httpx for HTTP requests
"""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.3,
                max_tokens=2500,
                trace_name="poc_discoverer",
                metadata={
                    "vuln_type": vuln_data.get('vulnerability_type'),
                    "package": vuln_data.get('package_name'),
                    "title": vuln_data.get('title', '')[:50]
                }
            )
            
            # Clean up response
            code = response.strip()
            
            # Remove markdown code blocks if present
            if code.startswith("```python"):
                code = code[9:]
            elif code.startswith("```"):
                code = code[3:]
            if code.endswith("```"):
                code = code[:-3]
            
            code = code.strip()
            
            # Validate it looks like Python code
            if not code or "def " not in code:
                return {
                    "success": False,
                    "error": "Generated code does not appear to be valid Python"
                }
            
            exploit_name = f"Dynamic {vuln_data.get('vulnerability_type', 'Unknown')} Exploit"
            if vuln_data.get('title'):
                exploit_name = f"Exploit: {vuln_data['title'][:50]}"
            
            return {
                "success": True,
                "exploit_code": code,
                "exploit_name": exploit_name,
                "source": "llm_generated",
                "confidence": 0.75,
                "based_on_file": analysis_data.get('file_path')
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Singleton instance
poc_discoverer = PoCDiscovererAgent()
