"""
Agent 4: Sandbox Executor
Runs exploits in isolated Docker containers or local subprocess.
Supports both Python (HTTP exploits) and Node.js (dependency exploits).
"""
import asyncio
import subprocess
import tempfile
import time
import os
from pathlib import Path
from typing import Optional


class SandboxExecutorAgent:
    """Executes exploits in isolated Docker sandbox or local subprocess."""
    
    # Default Juice Shop URL when running locally
    LOCAL_JUICE_SHOP_URL = "http://localhost:3000"
    
    # Path to project with node_modules (for dependency exploits)
    project_path: Optional[Path] = None
    
    def set_project_path(self, path: str):
        """Set the project path for dependency exploits."""
        self.project_path = Path(path).resolve()
    
    async def execute(
        self, 
        exploit_code: str, 
        exploit_name: str,
        language: str = "python",
        project_path: str = None
    ) -> dict:
        """
        Execute exploit against target.
        
        Args:
            exploit_code: Exploit script (Python or JavaScript)
            exploit_name: Name of the exploit
            language: "python" or "javascript"
            project_path: Path to project with node_modules (for JS exploits)
            
        Returns:
            Execution results with stdout, stderr, exit code
        """
        if project_path:
            self.project_path = Path(project_path).resolve()
        
        if language == "javascript":
            return await self._execute_nodejs(exploit_code, exploit_name)
        else:
            return await self._execute_python(exploit_code, exploit_name)
    
    async def _execute_python(self, exploit_code: str, exploit_name: str) -> dict:
        """Execute Python exploit using subprocess."""
        start_time = time.time()
        
        try:
            # Create temp file with exploit code
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False
            ) as f:
                # Prepend TARGET_URL to the exploit code
                full_code = f'TARGET_URL = "{self.LOCAL_JUICE_SHOP_URL}"\n\n{exploit_code}'
                f.write(full_code)
                exploit_path = f.name
            
            # Run the exploit
            process = await asyncio.create_subprocess_exec(
                'python3', exploit_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                process.kill()
                return {
                    "success": False,
                    "exploit_name": exploit_name,
                    "target_url": self.LOCAL_JUICE_SHOP_URL,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "Execution timed out after 30 seconds",
                    "duration_ms": 30000,
                    "exploit_succeeded": False,
                    "execution_mode": "python_subprocess"
                }
            
            # Clean up temp file
            Path(exploit_path).unlink(missing_ok=True)
            
            duration_ms = int((time.time() - start_time) * 1000)
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            return {
                "success": True,
                "exploit_name": exploit_name,
                "target_url": self.LOCAL_JUICE_SHOP_URL,
                "exit_code": process.returncode,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "duration_ms": duration_ms,
                "exploit_succeeded": process.returncode == 0 and "SUCCESS:" in stdout_str,
                "execution_mode": "python_subprocess"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "exploit_name": exploit_name,
                "execution_mode": "python_subprocess"
            }
    
    async def _execute_nodejs(self, exploit_code: str, exploit_name: str) -> dict:
        """Execute Node.js exploit in project context."""
        start_time = time.time()
        
        # Determine execution directory
        if self.project_path and (self.project_path / "node_modules").exists():
            exec_dir = self.project_path
        else:
            # Fallback: try to find a project with node_modules
            exec_dir = Path.cwd()
        
        try:
            # Write exploit to project directory so it can find node_modules
            exploit_file = exec_dir / f"_exploit_test_{int(time.time())}.js"
            exploit_file.write_text(exploit_code)
            
            try:
                # Run the exploit
                process = await asyncio.create_subprocess_exec(
                    'node', str(exploit_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(exec_dir)
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=30.0
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    return {
                        "success": False,
                        "exploit_name": exploit_name,
                        "exit_code": -1,
                        "stdout": "",
                        "stderr": "Execution timed out after 30 seconds",
                        "duration_ms": 30000,
                        "exploit_succeeded": False,
                        "execution_mode": "nodejs_subprocess"
                    }
                
                duration_ms = int((time.time() - start_time) * 1000)
                stdout_str = stdout.decode('utf-8', errors='replace')
                stderr_str = stderr.decode('utf-8', errors='replace')
                
                # Check for vulnerability indicators
                is_vulnerable = "VULNERABLE" in stdout_str or "VULNERABLE" in stderr_str
                
                return {
                    "success": True,
                    "exploit_name": exploit_name,
                    "project_path": str(exec_dir),
                    "exit_code": process.returncode,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "duration_ms": duration_ms,
                    "exploit_succeeded": is_vulnerable,
                    "execution_mode": "nodejs_subprocess"
                }
                
            finally:
                # Clean up exploit file
                if exploit_file.exists():
                    exploit_file.unlink()
                    
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "exploit_name": exploit_name,
                "execution_mode": "nodejs_subprocess"
            }
    
    async def _check_docker(self) -> bool:
        """Check if Docker daemon is available and running."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    async def _execute_docker(self, exploit_code: str, exploit_name: str) -> dict:
        """Execute exploit in Docker sandbox."""
        try:
            from services.docker_sandbox import sandbox
            
            # Ensure Juice Shop is running
            target = await sandbox.start_juice_shop()
            target_url = target["internal_url"]
            
            # Run exploit in sandbox
            result = await sandbox.run_exploit(
                exploit_code=exploit_code,
                target_url=target_url,
                timeout=30
            )
            
            return {
                "success": True,
                "exploit_name": exploit_name,
                "target_url": target_url,
                "exit_code": result["exit_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "duration_ms": result["duration_ms"],
                "exploit_succeeded": result["success"] and "SUCCESS:" in result["stdout"],
                "execution_mode": "docker"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "exploit_name": exploit_name,
                "execution_mode": "docker"
            }


# Singleton instance
sandbox_executor = SandboxExecutorAgent()
