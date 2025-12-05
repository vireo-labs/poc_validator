"""
OpenRouter API Service
Provides LLM access through OpenRouter for multiple model options.
"""
import os
import httpx
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class OpenRouterService:
    """Service for making LLM calls through OpenRouter API."""
    
    BASE_URL = "https://openrouter.ai/api/v1"
    
    def __init__(self):
        self._api_key = None
        self.default_model = "qwen/qwen3-coder-30b-a3b-instruct"  # User-specified model
    
    @property
    def api_key(self):
        """Load API key fresh each time to catch .env updates."""
        load_dotenv(override=True)
        return os.getenv("OPENROUTER_API_KEY", "")
        
    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> dict:
        """
        Send a chat completion request to OpenRouter.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model identifier (e.g., 'anthropic/claude-3-haiku')
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
            
        Returns:
            Response dict with 'content' and 'model' keys
        """
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set in environment")
            
        model = model or self.default_model
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:3000",
                    "X-Title": "PoC Validator"
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=60.0
            )
            response.raise_for_status()
            data = response.json()
            
            return {
                "content": data["choices"][0]["message"]["content"],
                "model": data.get("model", model),
                "usage": data.get("usage", {})
            }
    
    async def analyze(self, system_prompt: str, user_content: str, **kwargs) -> str:
        """
        Convenience method for single-turn analysis.
        
        Args:
            system_prompt: System instructions
            user_content: User message content
            **kwargs: Additional args passed to chat()
            
        Returns:
            Assistant response content as string
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]
        result = await self.chat(messages, **kwargs)
        return result["content"]


# Singleton instance
openrouter = OpenRouterService()
