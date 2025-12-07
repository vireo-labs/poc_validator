"""
Docker Sandbox Service
Manages isolated containers for running exploits safely.
Supports both Python and Node.js exploits.
"""
import docker
import asyncio
from typing import Optional
import time
import os


class DockerSandboxService:
    """Service for running exploits in isolated Docker containers."""
    
    JUICE_SHOP_IMAGE = "bkimminich/juice-shop"
    PYTHON_IMAGE = "python:3.11-slim"
    NODE_IMAGE = "node:18-alpine"
    SANDBOX_NETWORK = "poc_validator_sandbox"
    
    def __init__(self):
        self._client = None
        self._docker_available = None
    
    def is_available(self) -> bool:
        """Check if Docker is available."""
        if self._docker_available is None:
            try:
                client = docker.from_env()
                client.ping()
                self._docker_available = True
            except Exception:
                self._docker_available = False
        return self._docker_available
    
    @property
    def client(self):
        """Lazy initialization of Docker client."""
        if self._client is None:
            try:
                self._client = docker.from_env()
                self._ensure_network()
            except docker.errors.DockerException as e:
                raise RuntimeError(f"Docker not available: {e}")
        return self._client
    
    def _ensure_network(self):
        """Create isolated network if it doesn't exist."""
        try:
            self.client.networks.get(self.SANDBOX_NETWORK)
        except docker.errors.NotFound:
            self.client.networks.create(
                self.SANDBOX_NETWORK,
                driver="bridge",
                internal=False  # Allow network for HTTP requests
            )
    
    async def start_juice_shop(self) -> dict:
        """
        Start Juice Shop container for testing.
        
        Returns:
            Dict with container_id and internal_url
        """
        # Check if already running
        containers = self.client.containers.list(
            filters={"ancestor": self.JUICE_SHOP_IMAGE}
        )
        if containers:
            container = containers[0]
            return {
                "container_id": container.id,
                "internal_url": "http://juice-shop:3000",
                "external_url": "http://localhost:3000",
                "status": "already_running"
            }
        
        # Start new container
        container = self.client.containers.run(
            self.JUICE_SHOP_IMAGE,
            name="juice-shop-target",
            ports={"3000/tcp": 3000},
            network=self.SANDBOX_NETWORK,
            detach=True,
            remove=True
        )
        
        # Wait for startup
        await asyncio.sleep(5)
        
        return {
            "container_id": container.id,
            "internal_url": "http://juice-shop:3000",
            "external_url": "http://localhost:3000",
            "status": "started"
        }
    
    async def run_python_exploit(
        self,
        exploit_code: str,
        target_url: str = "http://localhost:3000",
        timeout: int = 30
    ) -> dict:
        """
        Run Python exploit in isolated container.
        
        Args:
            exploit_code: Python exploit script to execute
            target_url: URL of target application
            timeout: Maximum execution time in seconds
            
        Returns:
            Dict with exit_code, stdout, stderr, duration_ms
        """
        start_time = time.time()
        
        # Create exploit runner script
        runner_script = f'''
import sys
TARGET_URL = "{target_url}"

{exploit_code}
'''
        
        try:
            # Install httpx in container and run exploit
            container = self.client.containers.run(
                self.PYTHON_IMAGE,
                command=["sh", "-c", f"pip install httpx -q && python -c '{runner_script.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"],
                network="host",  # Use host network to access localhost:3000
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,
                detach=True,
                remove=False
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result["StatusCode"]
            except Exception:
                container.kill()
                exit_code = -1
            
            stdout = container.logs(stdout=True, stderr=False).decode()
            stderr = container.logs(stdout=False, stderr=True).decode()
            
            container.remove(force=True)
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Check for success indicators
            exploit_succeeded = exit_code == 0 and ("SUCCESS:" in stdout or "VULNERABLE:" in stdout)
            
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "exploit_succeeded": exploit_succeeded,
                "execution_mode": "docker_python"
            }
            
        except docker.errors.DockerException as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
                "exploit_succeeded": False,
                "execution_mode": "docker_python"
            }
    
    async def run_nodejs_exploit(
        self,
        exploit_code: str,
        project_path: str = None,
        timeout: int = 30
    ) -> dict:
        """
        Run Node.js exploit in isolated container.
        
        Args:
            exploit_code: JavaScript exploit script
            project_path: Path to project with node_modules to mount
            timeout: Maximum execution time in seconds
            
        Returns:
            Dict with exit_code, stdout, stderr, duration_ms
        """
        start_time = time.time()
        
        volumes = {}
        working_dir = "/app"
        
        # Mount project directory if provided (for access to node_modules)
        if project_path and os.path.exists(project_path):
            volumes[os.path.abspath(project_path)] = {"bind": "/app", "mode": "ro"}
        
        try:
            # Write exploit code as inline script
            container = self.client.containers.run(
                self.NODE_IMAGE,
                command=["sh", "-c", f"node -e '{exploit_code.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}'"],
                volumes=volumes,
                working_dir=working_dir,
                network="host",
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,
                detach=True,
                remove=False
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result["StatusCode"]
            except Exception:
                container.kill()
                exit_code = -1
            
            stdout = container.logs(stdout=True, stderr=False).decode()
            stderr = container.logs(stdout=False, stderr=True).decode()
            
            container.remove(force=True)
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Check for vulnerability indicators
            exploit_succeeded = "VULNERABLE:" in stdout or "VULNERABLE:" in stderr
            
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "exploit_succeeded": exploit_succeeded,
                "execution_mode": "docker_nodejs"
            }
            
        except docker.errors.DockerException as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
                "exploit_succeeded": False,
                "execution_mode": "docker_nodejs"
            }
    
    def stop_juice_shop(self):
        """Stop and remove Juice Shop container."""
        try:
            container = self.client.containers.get("juice-shop-target")
            container.stop()
            container.remove()
        except docker.errors.NotFound:
            pass
    
    def cleanup(self):
        """Clean up all sandbox resources."""
        self.stop_juice_shop()
        try:
            network = self.client.networks.get(self.SANDBOX_NETWORK)
            network.remove()
        except docker.errors.NotFound:
            pass


# Singleton instance
sandbox = DockerSandboxService()
