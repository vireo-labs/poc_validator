"""
Docker Sandbox Service
Manages isolated containers for running exploits safely.
"""
import docker
import asyncio
from typing import Optional
import time


class DockerSandboxService:
    """Service for running exploits in isolated Docker containers."""
    
    JUICE_SHOP_IMAGE = "bkimminich/juice-shop"
    SANDBOX_NETWORK = "poc_validator_sandbox"
    
    def __init__(self):
        self._client = None
        
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
                internal=True  # No external internet access
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
    
    async def run_exploit(
        self,
        exploit_code: str,
        target_url: str = "http://juice-shop:3000",
        timeout: int = 30
    ) -> dict:
        """
        Run exploit code in isolated Python container.
        
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
sys.path.insert(0, '/exploit')

TARGET_URL = "{target_url}"

{exploit_code}
'''
        
        try:
            container = self.client.containers.run(
                "python:3.11-slim",
                command=["python", "-c", runner_script],
                network=self.SANDBOX_NETWORK,
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU
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
            
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": duration_ms,
                "success": exit_code == 0
            }
            
        except docker.errors.DockerException as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": int((time.time() - start_time) * 1000),
                "success": False
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
