"""
Agent 1: Report Parser
Extracts structured vulnerability data from security scanner reports.
"""
import json
from typing import Optional
from services.openrouter import openrouter


SYSTEM_PROMPT = """You are a security report parser. Extract vulnerability information from the provided security scanner report.

Return a JSON object with the following structure:
{
    "title": "Brief vulnerability title",
    "vulnerability_type": "One of: SQLi, XSS, RCE, SSRF, AuthBypass, IDOR, PathTraversal, XXE, Other",
    "severity": "One of: CRITICAL, HIGH, MEDIUM, LOW",
    "affected_file": "File path if mentioned",
    "affected_line": line_number or null,
    "affected_endpoint": "API endpoint or URL path if mentioned",
    "description": "Detailed description of the vulnerability",
    "cwe_id": "CWE identifier if mentioned (e.g., CWE-89)",
    "exploitation_steps": ["Step 1", "Step 2", ...],
    "confidence": 0.0-1.0
}

Only output valid JSON, no other text."""


class ReportParserAgent:
    """Parses security scanner reports into structured vulnerability data."""
    
    async def parse(self, report_content: str, source: Optional[str] = None) -> dict:
        """
        Parse a vulnerability report into structured data.
        
        Args:
            report_content: Raw report content (PDF text, JSON, etc.)
            source: Scanner name (Snyk, Semgrep, etc.)
            
        Returns:
            Structured vulnerability data dict
        """
        user_content = f"""Parse this security vulnerability report:

Source Scanner: {source or 'Unknown'}

Report Content:
{report_content}"""

        try:
            response = await openrouter.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_content=user_content,
                temperature=0.1  # Low temp for consistent parsing
            )
            
            # Parse JSON response
            parsed = json.loads(response)
            parsed["raw_report"] = report_content
            parsed["source"] = source
            return {
                "success": True,
                "data": parsed
            }
            
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Failed to parse LLM response as JSON: {e}",
                "raw_response": response
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Singleton instance
report_parser = ReportParserAgent()
