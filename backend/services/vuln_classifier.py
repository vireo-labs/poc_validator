"""
Vulnerability Classifier
Classifies vulnerabilities into categories to determine verification strategy.
Cost-effective approach - no LLM needed for classification.
"""
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class VulnCategory(Enum):
    """High-level vulnerability categories."""
    WEB_APP = "web_app"           # HTTP-based, can be exploited via requests
    MEMORY_CORRUPTION = "memory"   # Buffer overflows, use-after-free, etc.
    LOGIC_FLAW = "logic"          # Business logic, auth bypass, etc.
    INJECTION = "injection"        # SQL, Command, LDAP, etc. (could be web or CLI)
    CRYPTO = "crypto"             # Weak crypto, key exposure, etc.
    CONFIG = "config"             # Misconfigurations
    UNKNOWN = "unknown"


class ExecutionStrategy(Enum):
    """How to verify/exploit this vulnerability."""
    HTTP_EXPLOIT = "http_exploit"        # Run HTTP-based exploit against target
    CODE_PATTERN_ONLY = "code_pattern"   # Just verify code pattern exists
    COMPILE_AND_RUN = "compile_run"      # Need to compile target + run exploit
    MANUAL_REVIEW = "manual_review"      # Human verification required
    STATIC_ANALYSIS = "static_analysis"  # Use static analysis tools


@dataclass
class VulnClassification:
    """Classification result for a vulnerability."""
    category: VulnCategory
    strategy: ExecutionStrategy
    language: Optional[str]
    requires_target: bool
    can_auto_verify: bool
    confidence: float
    reason: str


# Vulnerability type to category mappings
VULN_TYPE_MAPPINGS = {
    # Web Application Vulnerabilities
    "sqli": (VulnCategory.INJECTION, ExecutionStrategy.HTTP_EXPLOIT),
    "sql injection": (VulnCategory.INJECTION, ExecutionStrategy.HTTP_EXPLOIT),
    "xss": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "cross-site scripting": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "csrf": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "ssrf": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "idor": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "broken access control": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "path traversal": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "lfi": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "rfi": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "xxe": (VulnCategory.INJECTION, ExecutionStrategy.HTTP_EXPLOIT),
    "ssti": (VulnCategory.INJECTION, ExecutionStrategy.HTTP_EXPLOIT),
    "deserialization": (VulnCategory.WEB_APP, ExecutionStrategy.HTTP_EXPLOIT),
    "auth bypass": (VulnCategory.LOGIC_FLAW, ExecutionStrategy.HTTP_EXPLOIT),
    "authentication bypass": (VulnCategory.LOGIC_FLAW, ExecutionStrategy.HTTP_EXPLOIT),
    
    # Memory Corruption Vulnerabilities
    "buffer overflow": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "stack overflow": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "heap overflow": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "use after free": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "uaf": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "double free": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "integer overflow": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "format string": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "memory corruption": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "out of bounds": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "oob read": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "oob write": (VulnCategory.MEMORY_CORRUPTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    
    # Command/Code Injection
    "command injection": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "os command injection": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "code injection": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "rce": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "remote code execution": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    "ldap injection": (VulnCategory.INJECTION, ExecutionStrategy.CODE_PATTERN_ONLY),
    
    # Crypto Issues
    "weak encryption": (VulnCategory.CRYPTO, ExecutionStrategy.STATIC_ANALYSIS),
    "hardcoded secrets": (VulnCategory.CRYPTO, ExecutionStrategy.CODE_PATTERN_ONLY),
    "insecure random": (VulnCategory.CRYPTO, ExecutionStrategy.CODE_PATTERN_ONLY),
    
    # Configuration
    "misconfiguration": (VulnCategory.CONFIG, ExecutionStrategy.STATIC_ANALYSIS),
    "exposed secrets": (VulnCategory.CONFIG, ExecutionStrategy.CODE_PATTERN_ONLY),
}

# Language detection from file extensions
LANG_EXTENSIONS = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
}

# Dangerous functions by language (for pattern detection)
DANGEROUS_PATTERNS = {
    "c": [
        "strcpy", "strcat", "sprintf", "gets", "scanf",
        "memcpy", "memmove", "strncpy",  # can be unsafe
        "system", "popen", "exec",
    ],
    "cpp": [
        "strcpy", "strcat", "sprintf", "gets",
        "system", "popen", "exec",
    ],
    "python": [
        "eval", "exec", "os.system", "subprocess.call",
        "pickle.loads", "__import__", "compile",
    ],
    "javascript": [
        "eval", "Function", "setTimeout", "setInterval",
        "exec", "child_process", "dangerouslySetInnerHTML",
    ],
    "php": [
        "eval", "exec", "system", "shell_exec", "passthru",
        "include", "require", "file_get_contents",
    ],
    "java": [
        "Runtime.exec", "ProcessBuilder", "readObject",
        "XMLDecoder", "ScriptEngine.eval",
    ],
}


class VulnClassifier:
    """Classifies vulnerabilities to determine verification strategy."""
    
    def classify(self, vuln_data: dict) -> VulnClassification:
        """
        Classify a vulnerability based on its type and description.
        
        Args:
            vuln_data: Parsed vulnerability data
            
        Returns:
            VulnClassification with category, strategy, etc.
        """
        vuln_type = vuln_data.get("vulnerability_type", "").lower()
        description = vuln_data.get("description", "").lower()
        affected_file = vuln_data.get("affected_file", "")
        
        # Detect language from file extension
        language = None
        for ext, lang in LANG_EXTENSIONS.items():
            if affected_file.endswith(ext):
                language = lang
                break
        
        # Try to match vulnerability type
        category = VulnCategory.UNKNOWN
        strategy = ExecutionStrategy.MANUAL_REVIEW
        
        for pattern, (cat, strat) in VULN_TYPE_MAPPINGS.items():
            if pattern in vuln_type or pattern in description:
                category = cat
                strategy = strat
                break
        
        # Determine if we need a running target
        requires_target = strategy == ExecutionStrategy.HTTP_EXPLOIT
        
        # Can we auto-verify?
        can_auto_verify = strategy in [
            ExecutionStrategy.HTTP_EXPLOIT,
            ExecutionStrategy.CODE_PATTERN_ONLY,
            ExecutionStrategy.STATIC_ANALYSIS,
        ]
        
        # Build confidence based on how specific the match was
        confidence = 0.9 if category != VulnCategory.UNKNOWN else 0.3
        
        reason = self._build_reason(category, strategy, language)
        
        return VulnClassification(
            category=category,
            strategy=strategy,
            language=language,
            requires_target=requires_target,
            can_auto_verify=can_auto_verify,
            confidence=confidence,
            reason=reason,
        )
    
    def _build_reason(self, category: VulnCategory, strategy: ExecutionStrategy, 
                      language: Optional[str]) -> str:
        """Build human-readable reason for classification."""
        reasons = {
            ExecutionStrategy.HTTP_EXPLOIT: 
                "Web vulnerability - can verify via HTTP requests against running target",
            ExecutionStrategy.CODE_PATTERN_ONLY:
                "Code analysis vulnerability - verify pattern exists in source code",
            ExecutionStrategy.COMPILE_AND_RUN:
                "Requires compilation and execution to verify",
            ExecutionStrategy.STATIC_ANALYSIS:
                "Can be detected via static analysis tools",
            ExecutionStrategy.MANUAL_REVIEW:
                "Requires manual human review for verification",
        }
        
        lang_note = f" (Language: {language})" if language else ""
        return reasons.get(strategy, "Unknown strategy") + lang_note
    
    def get_dangerous_patterns(self, language: str) -> list[str]:
        """Get list of dangerous patterns for a language."""
        return DANGEROUS_PATTERNS.get(language, [])


# Singleton
vuln_classifier = VulnClassifier()
