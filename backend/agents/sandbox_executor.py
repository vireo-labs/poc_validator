"""
Agent 4: Sandbox Executor
Runs exploits in isolated Docker containers against Juice Shop.
Falls back to subprocess execution when Docker is unavailable.
"""
import asyncio
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


class SandboxExecutorAgent:
    """Executes exploits in isolated Docker sandbox or local subprocess."""
    
    # Default Juice Shop URL when running locally
    LOCAL_JUICE_SHOP_URL = "http://localhost:3000"
    
    async def execute(self, exploit_code: str, exploit_name: str) -> dict:
        """
        Execute exploit against Juice Shop.
        
        Uses Docker sandbox if available, otherwise falls back to subprocess.
        
        Args:
            exploit_code: Python exploit script
            exploit_name: Name of the exploit
            
        Returns:
            Execution results with stdout, stderr, exit code
        """
        # Always try subprocess first for now (Docker SDK has socket issues on Mac)
        # Docker sandbox can be enabled once the socket issue is resolved
        return await self._execute_subprocess(exploit_code, exploit_name)
    
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
    
    async def _execute_subprocess(self, exploit_code: str, exploit_name: str) -> dict:
        """Execute exploit using subprocess (fallback when Docker unavailable)."""
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
                    "execution_mode": "subprocess"
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
                "execution_mode": "subprocess"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "exploit_name": exploit_name,
                "execution_mode": "subprocess"
            }
    
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
