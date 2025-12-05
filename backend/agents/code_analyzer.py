"""
Agent 2: Code Analyzer (V2 - Universal)
Analyzes code in ANY GitHub repository to verify vulnerability exists.
Uses cost-effective pattern matching with LLM fallback.
"""
from typing import Optional
from services.github_service import github_service
from services.openrouter import openrouter
from services.vuln_classifier import vuln_classifier, ExecutionStrategy
from services.universal_verifier import universal_verifier


class CodeAnalyzerAgent:
    """
    Analyzes source code from any GitHub repository.
    
    V2 Features:
    - Universal repo support (not just Juice Shop)
    - Cost-effective pattern matching first
    - LLM only used when needed for complex analysis
    """
    
    async def analyze(self, vuln_data: dict, repo_url: str = None) -> dict:
        """
        Analyze code in repository to verify vulnerability.
        
        Args:
            vuln_data: Parsed vulnerability data
            repo_url: GitHub repository URL (required)
            
        Returns:
            Analysis results with verification status
        """
        if not repo_url:
            return {
                "success": False,
                "error": "Repository URL is required for code analysis"
            }
        
        # Classify vulnerability to determine strategy
        classification = vuln_classifier.classify(vuln_data)
        
        # Use universal verifier for pattern-based verification
        verification = await universal_verifier.verify(vuln_data, repo_url)
        
        # If pattern matching found strong evidence, we're done (no LLM needed)
        if verification.verified and verification.confidence >= 0.7:
            return self._build_result_from_verification(
                verification, classification, repo_url, use_llm=False
            )
        
        # For HTTP exploitable vulns, also prepare for exploitation
        if classification.strategy == ExecutionStrategy.HTTP_EXPLOIT and verification.verified:
            return self._build_result_from_verification(
                verification, classification, repo_url, use_llm=False
            )
        
        # For uncertain cases, use LLM for deeper analysis
        if not verification.verified or verification.confidence < 0.5:
            return await self._llm_deep_analysis(
                vuln_data, repo_url, verification, classification
            )
        
        # Return pattern-based result
        return self._build_result_from_verification(
            verification, classification, repo_url, use_llm=False
        )
    
    def _build_result_from_verification(self, verification, classification, 
                                          repo_url: str, use_llm: bool) -> dict:
        """Build analysis result from verification."""
        
        # Format matches for response
        matches_info = []
        for m in verification.matches[:5]:
            matches_info.append({
                "file": m.file_path,
                "line": m.line_number,
                "code": m.line_content,
                "pattern": m.pattern,
            })
        
        return {
            "success": True,
            "data": {
                "vulnerable_code_exists": verification.verified,
                "file_path": verification.file_analyzed,
                "vulnerable_line": verification.matches[0].line_number if verification.matches else None,
                "vulnerable_function": verification.matches[0].pattern if verification.matches else None,
                "vulnerability_pattern": ", ".join([m.pattern for m in verification.matches[:3]]),
                "confidence": verification.confidence,
                "explanation": verification.summary,
                "matches": matches_info,
            },
            "repo_path": github_service.clone_repo(repo_url).get("repo_path"),
            "classification": {
                "category": classification.category.value,
                "strategy": classification.strategy.value,
                "language": classification.language,
                "can_auto_exploit": verification.can_auto_exploit,
                "requires_manual_review": verification.requires_manual_review,
            },
            "cost": "low" if not use_llm else "medium",
        }
    
    async def _llm_deep_analysis(self, vuln_data: dict, repo_url: str,
                                   verification, classification) -> dict:
        """Use LLM for deeper analysis when pattern matching is uncertain."""
        
        # Clone repo and get relevant code context
        clone_result = github_service.clone_repo(repo_url)
        repo_path = clone_result.get("repo_path", "")
        affected_file = vuln_data.get("affected_file", "")
        
        code_context = ""
        if affected_file:
            content = github_service.read_file(repo_path, affected_file)
            if content:
                code_context = content[:3000]  # Limit to reduce tokens
        
        # Build prompt for LLM
        prompt = f"""Analyze this code for the reported vulnerability.

VULNERABILITY REPORT:
Type: {vuln_data.get('vulnerability_type')}
Description: {vuln_data.get('description')}
Affected File: {affected_file}

CODE CONTEXT:
```
{code_context}
```

PATTERN MATCHING RESULTS:
{verification.summary}
Found {len(verification.matches)} potential matches.

Analyze if this vulnerability EXISTS in the code. Respond in JSON:
{{
    "vulnerable": true/false,
    "confidence": 0.0-1.0,
    "explanation": "detailed explanation",
    "vulnerable_line": line number or null,
    "vulnerable_pattern": "the dangerous pattern found"
}}
"""
        
        try:
            response = await openrouter.analyze(
                system_prompt="You are a security code auditor. Analyze code for vulnerabilities. Be precise and accurate.",
                user_content=prompt,
                temperature=0.2,
                max_tokens=500,
            )
            
            # Parse LLM response
            import json
            # Try to extract JSON from response
            json_match = response
            if "```json" in response:
                json_match = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_match = response.split("```")[1].split("```")[0]
            
            analysis = json.loads(json_match.strip())
            
            return {
                "success": True,
                "data": {
                    "vulnerable_code_exists": analysis.get("vulnerable", False),
                    "file_path": affected_file,
                    "vulnerable_line": analysis.get("vulnerable_line"),
                    "vulnerable_function": analysis.get("vulnerable_pattern"),
                    "vulnerability_pattern": analysis.get("vulnerable_pattern"),
                    "confidence": analysis.get("confidence", 0.7),
                    "explanation": analysis.get("explanation"),
                },
                "repo_path": repo_path,
                "classification": {
                    "category": classification.category.value,
                    "strategy": classification.strategy.value,
                    "language": classification.language,
                    "can_auto_exploit": classification.strategy == ExecutionStrategy.HTTP_EXPLOIT,
                    "requires_manual_review": True,
                },
                "cost": "medium",
            }
            
        except Exception as e:
            # Fallback to pattern matching result
            return self._build_result_from_verification(
                verification, classification, repo_url, use_llm=True
            )


# Singleton instance
code_analyzer = CodeAnalyzerAgent()
