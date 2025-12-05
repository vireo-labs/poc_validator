"""
Snyk Parser - Parse Snyk JSON output
"""
import json
from typing import Optional


def parse_snyk_output(json_data: dict) -> list[dict]:
    """
    Parse Snyk JSON output into normalized vulnerability format.
    
    Args:
        json_data: Raw Snyk JSON output
        
    Returns:
        List of normalized vulnerability dicts
    """
    vulnerabilities = []
    
    for vuln in json_data.get("vulnerabilities", []):
        normalized = {
            "source": "snyk",
            "id": vuln.get("id", ""),
            "title": vuln.get("title", ""),
            "description": vuln.get("description", ""),
            "severity": vuln.get("severity", "medium").upper(),
            "cvss_score": vuln.get("cvssScore", 0),
            "vulnerability_type": _classify_vuln_type(vuln.get("title", "")),
            "package_name": vuln.get("packageName", ""),
            "package_version": vuln.get("version", ""),
            "affected_file": vuln.get("filePath", ""),
            "upgrade_path": vuln.get("upgradePath", []),
            "is_upgradable": vuln.get("isUpgradable", False),
            "cwe": _extract_cwe(vuln),
            "references": _extract_references(vuln),
        }
        vulnerabilities.append(normalized)
    
    return vulnerabilities


def _classify_vuln_type(title: str) -> str:
    """Classify vulnerability type from title."""
    title_lower = title.lower()
    
    if "sql injection" in title_lower:
        return "SQLi"
    elif "cross-site scripting" in title_lower or "xss" in title_lower:
        return "XSS"
    elif "prototype pollution" in title_lower:
        return "Prototype Pollution"
    elif "authentication bypass" in title_lower:
        return "Auth Bypass"
    elif "command injection" in title_lower:
        return "Command Injection"
    elif "path traversal" in title_lower:
        return "Path Traversal"
    elif "deserialization" in title_lower:
        return "Deserialization"
    elif "information exposure" in title_lower:
        return "Information Disclosure"
    elif "denial of service" in title_lower:
        return "DoS"
    else:
        return "Other"


def _extract_cwe(vuln: dict) -> Optional[str]:
    """Extract CWE from vulnerability data."""
    # Snyk often includes CWE in identifiers
    identifiers = vuln.get("identifiers", {})
    cwes = identifiers.get("CWE", [])
    return cwes[0] if cwes else None


def _extract_references(vuln: dict) -> list[str]:
    """Extract references/links from vulnerability data."""
    refs = []
    if vuln.get("id"):
        refs.append(f"https://snyk.io/vuln/{vuln['id']}")
    return refs


def parse_snyk_file(filepath: str) -> list[dict]:
    """
    Parse Snyk JSON file.
    
    Args:
        filepath: Path to Snyk JSON output file
        
    Returns:
        List of normalized vulnerability dicts
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    return parse_snyk_output(data)


# Quick test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        vulns = parse_snyk_file(sys.argv[1])
        print(f"Found {len(vulns)} vulnerabilities:")
        for v in vulns:
            print(f"  [{v['severity']}] {v['title']} ({v['vulnerability_type']})")
    else:
        print("Usage: python snyk_parser.py <snyk-output.json>")
