"""
GitHub Service
Clones and analyzes repositories for vulnerability verification.
"""
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional


class GitHubService:
    """Service for cloning and reading GitHub repositories."""
    
    REPOS_DIR = Path("/tmp/poc_validator_repos")
    
    def __init__(self):
        self.REPOS_DIR.mkdir(parents=True, exist_ok=True)
    
    def clone_repo(self, repo_url: str, force_refresh: bool = False) -> dict:
        """
        Clone a GitHub repository.
        
        Args:
            repo_url: GitHub repo URL (e.g., https://github.com/owner/repo)
            force_refresh: If True, delete existing clone and re-clone
            
        Returns:
            Dict with repo_path and status
        """
        # Extract repo name from URL
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        repo_path = self.REPOS_DIR / repo_name
        
        if repo_path.exists():
            if force_refresh:
                shutil.rmtree(repo_path)
            else:
                # Pull latest changes
                try:
                    subprocess.run(
                        ["git", "pull"],
                        cwd=repo_path,
                        capture_output=True,
                        timeout=60
                    )
                    return {
                        "success": True,
                        "repo_path": str(repo_path),
                        "status": "updated"
                    }
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Failed to update repo: {e}"
                    }
        
        # Clone the repository
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr
                }
            
            return {
                "success": True,
                "repo_path": str(repo_path),
                "status": "cloned"
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Clone operation timed out"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def read_file(self, repo_path: str, file_path: str) -> Optional[str]:
        """Read a file from the cloned repository."""
        full_path = Path(repo_path) / file_path
        try:
            if full_path.exists() and full_path.is_file():
                return full_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            pass
        return None
    
    def find_files(self, repo_path: str, pattern: str = "*.ts") -> list[str]:
        """Find files matching a pattern in the repository."""
        repo = Path(repo_path)
        return [str(f.relative_to(repo)) for f in repo.rglob(pattern)]
    
    def search_code(self, repo_path: str, search_term: str, extensions: list[str] = None) -> list[dict]:
        """
        Search for a term in repository code.
        
        Args:
            repo_path: Path to cloned repository
            search_term: Term to search for
            extensions: File extensions to search (e.g., ['.ts', '.js'])
            
        Returns:
            List of matches with file, line number, and content
        """
        extensions = extensions or ['.ts', '.js', '.py', '.java']
        matches = []
        repo = Path(repo_path)
        
        for ext in extensions:
            for file_path in repo.rglob(f"*{ext}"):
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    lines = content.split('\n')
                    
                    for i, line in enumerate(lines, 1):
                        if search_term.lower() in line.lower():
                            matches.append({
                                "file": str(file_path.relative_to(repo)),
                                "line": i,
                                "content": line.strip()[:200]
                            })
                except Exception:
                    continue
        
        return matches[:50]  # Limit results
    
    def get_file_context(self, repo_path: str, file_path: str, line: int, context: int = 10) -> str:
        """Get code context around a specific line."""
        content = self.read_file(repo_path, file_path)
        if not content:
            return ""
        
        lines = content.split('\n')
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        
        context_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            context_lines.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(context_lines)


# Singleton instance
github_service = GitHubService()
