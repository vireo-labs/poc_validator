"""
OpenRouter API Service with Langfuse Observability
Provides LLM access through OpenRouter with full tracing.
"""
import os
from typing import Optional
from dotenv import load_dotenv
from openai import OpenAI
from langfuse import Langfuse

load_dotenv()


class OpenRouterService:
    """Service for making LLM calls through OpenRouter API with Langfuse tracing."""
    
    BASE_URL = "https://openrouter.ai/api/v1"
    
    def __init__(self):
        self.default_model = "qwen/qwen3-235b-a22b-2507"  # Larger model for better exploit generation
        self._client = None
        self._langfuse = None
        self._init_langfuse()
    
    def _init_langfuse(self):
        """Initialize Langfuse client."""
        load_dotenv(override=True)
        public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
        
        if public_key and secret_key:
            self._langfuse = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                host=host
            )
            print(f"[Langfuse] Initialized - Host: {host}")
        else:
            print("[Langfuse] Warning: Keys not found, tracing disabled")
    
    @property
    def api_key(self):
        """Load API key fresh each time to catch .env updates."""
        load_dotenv(override=True)
        return os.getenv("OPENROUTER_API_KEY", "")
    
    @property
    def client(self):
        """Get OpenAI client configured for OpenRouter."""
        if self._client is None:
            self._client = OpenAI(
                base_url=self.BASE_URL,
                api_key=self.api_key,
                default_headers={
                    "HTTP-Referer": "http://localhost:3000",
                    "X-Title": "PoC Validator"
                }
            )
        return self._client
    
    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
        trace_name: str = None,
        metadata: dict = None
    ) -> dict:
        """
        Send a chat completion request to OpenRouter with Langfuse tracing.
        """
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set in environment")
            
        model = model or self.default_model
        
        # Create generation in Langfuse
        generation = None
        if self._langfuse:
            generation = self._langfuse.start_generation(
                name=trace_name or "openrouter_chat",
                model=model,
                input=messages,
                metadata={
                    **(metadata or {}),
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
            )
        
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            content = response.choices[0].message.content
            usage_details = {}
            if response.usage:
                usage_details = {
                    "input": response.usage.prompt_tokens,
                    "output": response.usage.completion_tokens,
                    "total": response.usage.total_tokens
                }
            
            # Update generation with output, then end
            if generation:
                generation.update(
                    output=content,
                    usage_details=usage_details
                )
                generation.end()
            
            return {
                "content": content,
                "model": response.model or model,
                "usage": usage_details
            }
            
        except Exception as e:
            # Log error
            if generation:
                generation.update(
                    level="ERROR",
                    status_message=str(e)
                )
                generation.end()
            raise
    
    async def analyze(
        self, 
        system_prompt: str, 
        user_content: str, 
        trace_name: str = None,
        metadata: dict = None,
        **kwargs
    ) -> str:
        """
        Convenience method for single-turn analysis with tracing.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]
        result = await self.chat(
            messages, 
            trace_name=trace_name,
            metadata=metadata,
            **kwargs
        )
        return result["content"]
    
    def flush(self):
        """Flush Langfuse events - call this to ensure traces are sent."""
        if self._langfuse:
            self._langfuse.flush()
            print("[Langfuse] Flushed traces")


# Singleton instance
openrouter = OpenRouterService()
