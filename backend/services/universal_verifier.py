"""
Universal Code Verifier
Verifies vulnerability patterns exist in ANY repository's source code.
Cost-effective - uses pattern matching first, LLM only when needed.
"""
import re
from typing import Optional
from dataclasses import dataclass
from services.github_service import github_service
from services.vuln_classifier import vuln_classifier, VulnClassification, ExecutionStrategy


@dataclass
class PatternMatch:
    """A matched dangerous pattern in code."""
    file_path: str
    line_number: int
    line_content: str
    pattern: str
    context_before: list[str]
    context_after: list[str]


@dataclass
class VerificationResult:
    """Result of code verification."""
    verified: bool
    confidence: float
    strategy_used: str
    matches: list[PatternMatch]
    file_analyzed: Optional[str]
    summary: str
    requires_manual_review: bool
    can_auto_exploit: bool


class UniversalCodeVerifier:
    """
    Verifies vulnerabilities across ANY repository.
    
    Strategy:
    1. Clone the target repo
    2. Classify the vulnerability type
    3. Use appropriate verification method:
       - Pattern matching for memory corruption
       - LLM analysis for complex logic
       - Static analysis for config issues
    """
    
    async def verify(self, vuln_data: dict, repo_url: str) -> VerificationResult:
        """
        Verify a vulnerability exists in the given repository.
        
        Args:
            vuln_data: Parsed vulnerability data
            repo_url: GitHub repository URL
            
        Returns:
            VerificationResult with matches and confidence
        """
        # Step 1: Classify vulnerability
        classification = vuln_classifier.classify(vuln_data)
        
        # Step 2: Clone repository
        try:
            clone_result = github_service.clone_repo(repo_url)
            if not clone_result.get("success"):
                raise Exception(clone_result.get("error", "Unknown error"))
            repo_path = clone_result["repo_path"]
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=0.0,
                strategy_used="clone_failed",
                matches=[],
                file_analyzed=None,
                summary=f"Failed to clone repository: {e}",
                requires_manual_review=True,
                can_auto_exploit=False,
            )
        
        # Step 3: Choose verification strategy
        if classification.strategy == ExecutionStrategy.CODE_PATTERN_ONLY:
            return await self._verify_by_pattern(vuln_data, repo_path, classification)
        elif classification.strategy == ExecutionStrategy.HTTP_EXPLOIT:
            return await self._verify_for_http_exploit(vuln_data, repo_path, classification)
        elif classification.strategy == ExecutionStrategy.STATIC_ANALYSIS:
            return await self._verify_static(vuln_data, repo_path, classification)
        else:
            return await self._verify_manual(vuln_data, repo_path, classification)
    
    async def _verify_by_pattern(self, vuln_data: dict, repo_path: str, 
                                  classification: VulnClassification) -> VerificationResult:
        """
        Verify by searching for dangerous code patterns.
        Used for memory corruption, command injection, etc.
        """
        affected_file = vuln_data.get("affected_file", "")
        description = vuln_data.get("description", "")
        
        matches = []
        
        # Get dangerous patterns for this language
        if classification.language:
            patterns = vuln_classifier.get_dangerous_patterns(classification.language)
        else:
            # Try all patterns if language unknown
            patterns = []
            for lang_patterns in vuln_classifier.get_dangerous_patterns("c"):
                patterns.extend(lang_patterns if isinstance(lang_patterns, list) else [lang_patterns])
        
        # Extract specific patterns from the description
        description_patterns = self._extract_patterns_from_description(description)
        patterns.extend(description_patterns)
        
        # Search in the specific affected file first
        if affected_file:
            file_matches = self._search_file_for_patterns(
                repo_path, affected_file, patterns
            )
            matches.extend(file_matches)
        
        # If no specific file or no matches, search relevant files
        if not matches:
            extensions = self._get_extensions_for_language(classification.language)
            for ext in extensions:
                files = github_service.find_files(repo_path, f"*{ext}")
                for f in files[:20]:  # Limit to avoid too much scanning
                    file_matches = self._search_file_for_patterns(
                        repo_path, f, patterns[:5]  # Top 5 patterns
                    )
                    matches.extend(file_matches)
                    if len(matches) >= 5:
                        break
        
        # Build result
        verified = len(matches) > 0
        confidence = min(0.95, 0.5 + (len(matches) * 0.1))
        
        if verified:
            summary = f"Found {len(matches)} dangerous pattern(s) matching vulnerability description"
        else:
            summary = "No matching dangerous patterns found in source code"
        
        return VerificationResult(
            verified=verified,
            confidence=confidence if verified else 0.2,
            strategy_used="pattern_matching",
            matches=matches,
            file_analyzed=affected_file or "multiple files",
            summary=summary,
            requires_manual_review=not verified,
            can_auto_exploit=False,  # Pattern-only vulns need manual exploitation
        )
    
    async def _verify_for_http_exploit(self, vuln_data: dict, repo_path: str,
                                        classification: VulnClassification) -> VerificationResult:
        """
        Verify web vulnerabilities that can be exploited via HTTP.
        Searches for vulnerable code patterns and marks as exploitable.
        """
        affected_file = vuln_data.get("affected_file", "")
        vuln_type = vuln_data.get("vulnerability_type", "").lower()
        
        # Define patterns for common web vulns
        web_patterns = {
            "sqli": ["query", "execute", "raw", "sql", "cursor", "db."],
            "xss": ["innerHTML", "dangerouslySetInnerHTML", "document.write", "eval"],
            "ssrf": ["fetch", "request", "axios", "http.get", "urllib"],
            "path traversal": ["path.join", "readFile", "open(", "file_get_contents"],
            "command injection": ["exec", "system", "popen", "shell", "spawn"],
        }
        
        patterns = []
        for key, pats in web_patterns.items():
            if key in vuln_type:
                patterns.extend(pats)
        
        if not patterns:
            patterns = ["req.body", "req.params", "req.query", "request."]
        
        matches = []
        if affected_file:
            matches = self._search_file_for_patterns(repo_path, affected_file, patterns)
        
        verified = len(matches) > 0
        
        return VerificationResult(
            verified=verified,
            confidence=0.85 if verified else 0.3,
            strategy_used="web_pattern_analysis",
            matches=matches,
            file_analyzed=affected_file,
            summary=f"Web vulnerability {'confirmed' if verified else 'patterns not found'} - can attempt HTTP exploitation",
            requires_manual_review=False,
            can_auto_exploit=verified,  # Web vulns can be auto-exploited
        )
    
    async def _verify_static(self, vuln_data: dict, repo_path: str,
                              classification: VulnClassification) -> VerificationResult:
        """Verify using static analysis patterns."""
        # For config/crypto issues, search for known bad patterns
        patterns = [
            "password", "secret", "api_key", "private_key",
            "md5", "sha1", "DES", "insecure",
        ]
        
        matches = []
        for ext in [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"]:
            files = github_service.find_files(repo_path, f"*{ext}")
            for f in files[:10]:
                file_matches = self._search_file_for_patterns(repo_path, f, patterns)
                matches.extend(file_matches)
        
        return VerificationResult(
            verified=len(matches) > 0,
            confidence=0.6 if matches else 0.2,
            strategy_used="static_analysis",
            matches=matches[:10],
            file_analyzed="multiple files",
            summary=f"Static analysis found {len(matches)} potential issues",
            requires_manual_review=True,
            can_auto_exploit=False,
        )
    
    async def _verify_manual(self, vuln_data: dict, repo_path: str,
                              classification: VulnClassification) -> VerificationResult:
        """Fallback for vulns that need manual review."""
        return VerificationResult(
            verified=False,
            confidence=0.1,
            strategy_used="manual_required",
            matches=[],
            file_analyzed=vuln_data.get("affected_file"),
            summary="This vulnerability type requires manual verification",
            requires_manual_review=True,
            can_auto_exploit=False,
        )
    
    def _search_file_for_patterns(self, repo_path: str, file_path: str, 
                                   patterns: list[str]) -> list[PatternMatch]:
        """Search a file for dangerous patterns."""
        matches = []
        
        content = github_service.read_file(repo_path, file_path)
        if not content:
            return matches
        
        lines = content.split("\n")
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if pattern.lower() in line.lower():
                    match = PatternMatch(
                        file_path=file_path,
                        line_number=i + 1,
                        line_content=line.strip(),
                        pattern=pattern,
                        context_before=lines[max(0, i-2):i],
                        context_after=lines[i+1:min(len(lines), i+3)],
                    )
                    matches.append(match)
        
        return matches
    
    def _extract_patterns_from_description(self, description: str) -> list[str]:
        """Extract function/variable names from vulnerability description."""
        patterns = []
        
        # Look for function-like patterns: word followed by (
        func_pattern = re.findall(r'\b(\w+)\s*\(', description)
        patterns.extend(func_pattern)
        
        # Look for common dangerous function mentions
        dangerous_funcs = [
            "strcpy", "strcat", "sprintf", "gets", "scanf",
            "eval", "exec", "system", "popen",
            "query", "execute", "raw",
        ]
        for func in dangerous_funcs:
            if func in description.lower():
                patterns.append(func)
        
        return list(set(patterns))[:10]  # Limit to 10 patterns
    
    def _get_extensions_for_language(self, language: Optional[str]) -> list[str]:
        """Get file extensions for a language."""
        lang_exts = {
            "c": [".c", ".h"],
            "cpp": [".cpp", ".cc", ".hpp", ".h"],
            "python": [".py"],
            "javascript": [".js", ".mjs"],
            "typescript": [".ts", ".tsx"],
            "java": [".java"],
            "go": [".go"],
            "rust": [".rs"],
            "php": [".php"],
        }
        return lang_exts.get(language, [".c", ".py", ".js", ".ts", ".java"])


# Singleton
universal_verifier = UniversalCodeVerifier()
