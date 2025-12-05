"""
Agent 2: Code Analyzer
Verifies that vulnerable code exists by analyzing the actual repository.
"""
import json
from typing import Optional
from services.openrouter import openrouter
from services.github_service import github_service


SYSTEM_PROMPT = """You are a security code analyst. Analyze the provided code to determine if it contains the described vulnerability.

Return a JSON object:
{
    "vulnerable_code_exists": true/false,
    "file_path": "path to vulnerable file",
    "vulnerable_line": line_number,
    "vulnerable_function": "function or method name",
    "vulnerability_pattern": "specific code pattern that makes it vulnerable",
    "confidence": 0.0-1.0,
    "explanation": "Detailed explanation of why this code is vulnerable and how it could be exploited"
}

Only output valid JSON."""


class CodeAnalyzerAgent:
    """Analyzes actual repository code to verify vulnerabilities."""
    
    def __init__(self):
        self.repo_path: Optional[str] = None
        self.repo_url: Optional[str] = None
    
    async def analyze(self, vuln_data: dict, repo_url: str = None) -> dict:
        """
        Verify vulnerable code exists by analyzing the actual repository.
        
        Args:
            vuln_data: Parsed vulnerability data from Report Parser
            repo_url: GitHub repository URL to analyze
            
        Returns:
            Analysis result with code location and confidence
        """
        # Use provided repo URL or default to Juice Shop
        repo_url = repo_url or "https://github.com/varun2117/juice-shop"
        
        # Clone/update the repository
        clone_result = github_service.clone_repo(repo_url)
        if not clone_result["success"]:
            return {
                "success": False,
                "error": f"Failed to clone repository: {clone_result.get('error')}"
            }
        
        self.repo_path = clone_result["repo_path"]
        self.repo_url = repo_url
        
        vuln_type = vuln_data.get("vulnerability_type", "")
        description = vuln_data.get("description", "")
        affected_file = vuln_data.get("affected_file", "")
        
        # Search for vulnerability patterns in code
        code_context = await self._find_vulnerable_code(vuln_type, description, affected_file)
        
        if not code_context:
            return {
                "success": True,
                "data": {
                    "vulnerable_code_exists": False,
                    "confidence": 0.3,
                    "explanation": "Could not find matching vulnerable code patterns in repository"
                },
                "source": "code_search"
            }
        
        # Use LLM to analyze the found code
        return await self._llm_analyze(vuln_data, code_context)
    
    async def _find_vulnerable_code(self, vuln_type: str, description: str, affected_file: str) -> Optional[str]:
        """Search repository for potentially vulnerable code."""
        
        # Define search terms based on vulnerability type
        search_terms = {
            "SQLi": ["query", "execute", "sequelize.query", "raw(", "sql"],
            "XSS": ["innerHTML", "document.write", "eval(", "v-html", "dangerouslySetInnerHTML"],
            "AuthBypass": ["jwt.verify", "authenticate", "login", "token", "session"],
            "IDOR": ["req.params.id", "findById", "req.query.id", "userId"],
            "PathTraversal": ["path.join", "readFile", "fs.read", "../", "path.resolve"],
            "RCE": ["exec(", "spawn(", "eval(", "child_process", "system("]
        }
        
        terms = search_terms.get(vuln_type, [])
        
        # Also extract keywords from description
        desc_words = description.lower().split()
        for word in ["login", "search", "user", "file", "upload", "token", "password", "query"]:
            if word in desc_words:
                terms.append(word)
        
        all_matches = []
        
        # If specific file is mentioned, prioritize it
        if affected_file:
            content = github_service.read_file(self.repo_path, affected_file)
            if content:
                all_matches.append({
                    "file": affected_file,
                    "content": content[:3000],
                    "source": "specified_file"
                })
        
        # Search for each term
        for term in terms[:5]:  # Limit searches
            matches = github_service.search_code(self.repo_path, term)
            for match in matches[:3]:  # Top 3 matches per term
                context = github_service.get_file_context(
                    self.repo_path, 
                    match["file"], 
                    match["line"],
                    context=15
                )
                if context:
                    all_matches.append({
                        "file": match["file"],
                        "line": match["line"],
                        "match": match["content"],
                        "context": context
                    })
        
        if not all_matches:
            return None
        
        # Format matches for LLM analysis
        formatted = f"Repository: {self.repo_url}\n\n"
        for i, match in enumerate(all_matches[:5], 1):
            formatted += f"=== Match {i}: {match.get('file', 'Unknown')} ===\n"
            if "content" in match:
                formatted += f"{match['content'][:2000]}\n\n"
            elif "context" in match:
                formatted += f"Line {match.get('line', '?')}: {match.get('match', '')}\n"
                formatted += f"Context:\n{match['context']}\n\n"
        
        return formatted
    
    async def _llm_analyze(self, vuln_data: dict, code_context: str) -> dict:
        """Use LLM to analyze code and confirm vulnerability."""
        
        user_content = f"""Analyze if this code contains the described vulnerability:

## Vulnerability Details
Type: {vuln_data.get('vulnerability_type')}
Title: {vuln_data.get('title')}
Description: {vuln_data.get('description')}
CWE: {vuln_data.get('cwe_id', 'Unknown')}

## Code Found in Repository
{code_context}

Determine if this code is vulnerable and explain why."""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.2
            )
            
            # Parse JSON response
            parsed = json.loads(response)
            return {
                "success": True,
                "data": parsed,
                "source": "llm_analysis",
                "repo_url": self.repo_url,
                "repo_path": self.repo_path
            }
            
        except json.JSONDecodeError:
            # Try to extract useful info even if not valid JSON
            return {
                "success": True,
                "data": {
                    "vulnerable_code_exists": True,
                    "confidence": 0.6,
                    "explanation": response[:500] if response else "Analysis completed"
                },
                "source": "llm_analysis_fallback"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Singleton instance
code_analyzer = CodeAnalyzerAgent()
