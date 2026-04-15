#!/usr/bin/env python3
"""
LLM API Module

Simple interface for calling LLM APIs with connection pooling and reuse.
All prompts and user inputs are passed by the caller, not embedded in this module.

Usage:
    from utils.llm_api import LLMAPI

    api = LLMAPI()
    result = api.call(system_prompt="You are...", user_prompt="Analyze...")
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

try:
    from openai import OpenAI
    import httpx
except ImportError:
    raise ImportError("openai and httpx are required. Install with: pip install openai httpx")


class LLMAPI:
    """
    LLM API interface for OpenAI-compatible APIs with connection pooling.

    Features:
    - Connection pooling and reuse
    - Configurable pool size and timeouts
    - Automatic connection cleanup

    All prompts and inputs are provided by the caller.
    """

    def __init__(self, env_path: str = None,
                 max_connections: int = 50,
                 max_keepalive_connections: int = 20,
                 connection_timeout: float = 10.0,
                 read_timeout: float = 30.0):
        """
        Initialize LLM API client with connection pooling.

        Args:
            env_path: Path to .env file containing API credentials
            max_connections: Maximum number of connections in the pool
            max_keepalive_connections: Maximum number of idle connections to keep alive
            connection_timeout: Timeout for establishing a connection (seconds)
            read_timeout: Timeout for reading a response (seconds)
        """
        if env_path is None:
            env_path = Path(__file__).parent.parent / ".env"
        load_dotenv(env_path)

        self.api_key = os.getenv("OPENAI_API_KEY")
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in .env file")

        # Create httpx client with connection pooling
        # Limits: http://limits/python-sdk/latest/limits/
        self.http_client = httpx.Client(
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive_connections,
                keepalive_expiry=5.0,  # Keep idle connections alive for 5 seconds
            ),
            timeout=httpx.Timeout(
                connect=connection_timeout,
                read=read_timeout,
                write=5.0,
                pool=connection_timeout,
            ),
        )

        # Create OpenAI client with custom httpx client
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            http_client=self.http_client
        )

        self.total_calls = 0
        self.successful_calls = 0

        # Token statistics
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def call(self, system_prompt: str, user_prompt: str,
             temperature: float = 0.1, json_mode: bool = True,
             model_override: str = None) -> Dict[str, Any]:
        """
        Call LLM API with provided prompts.

        Args:
            system_prompt: System prompt defining the task
            user_prompt: User prompt containing the input data
            temperature: Sampling temperature (lower = more deterministic)
            json_mode: Whether to use JSON response format
            model_override: Override the default model name

        Returns:
            Parsed JSON response dict with keys:
            - content: str (raw response if json_mode=False)
            - parsed: dict (parsed JSON if json_mode=True)
            - error: str (error message if call failed)
            - success: bool
            - input_tokens: int (number of input tokens used)
            - output_tokens: int (number of output tokens used)
        """
        self.total_calls += 1

        if not system_prompt or not user_prompt:
            return {
                'success': False,
                'error': 'Empty prompt provided',
                'content': None,
                'parsed': None,
                'input_tokens': 0,
                'output_tokens': 0
            }

        try:
            messages = [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ]

            # Use model_override if provided, otherwise use default model
            model_to_use = model_override if model_override else self.model

            kwargs = {
                'model': model_to_use,
                'messages': messages,
                'temperature': temperature
            }

            if json_mode:
                kwargs['response_format'] = {"type": "json_object"}

            # Use the pooled client
            response = self.client.chat.completions.create(**kwargs)

            raw_content = response.choices[0].message.content
            self.successful_calls += 1

            # Extract token usage
            input_tokens = 0
            output_tokens = 0
            if hasattr(response, 'usage') and response.usage:
                input_tokens = response.usage.prompt_tokens or 0
                output_tokens = response.usage.completion_tokens or 0
                self.total_input_tokens += input_tokens
                self.total_output_tokens += output_tokens

            result = {
                'success': True,
                'content': raw_content,
                'parsed': None,
                'error': None,
                'input_tokens': input_tokens,
                'output_tokens': output_tokens
            }

            if json_mode and raw_content:
                try:
                    result['parsed'] = json.loads(raw_content)
                except json.JSONDecodeError:
                    # Try to extract JSON from markdown code blocks
                    import re
                    json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw_content, re.DOTALL)
                    if json_match:
                        try:
                            result['parsed'] = json.loads(json_match.group(1).strip())
                        except json.JSONDecodeError:
                            result['error'] = 'Failed to parse JSON response'
                            result['success'] = False
                    else:
                        result['error'] = 'Failed to parse JSON response'
                        result['success'] = False

            return result

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'content': None,
                'parsed': None,
                'input_tokens': 0,
                'output_tokens': 0
            }

    def close(self):
        """
        Close the HTTP client and release all connections.

        Should be called when done using the API to properly cleanup resources.
        """
        if self.http_client:
            self.http_client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures connections are closed."""
        self.close()

    def get_stats(self) -> Dict[str, int]:
        """
        Get API call statistics.

        Returns:
            Dict with total_calls, successful_calls, and token usage
        """
        return {
            'total_calls': self.total_calls,
            'successful_calls': self.successful_calls,
            'total_input_tokens': self.total_input_tokens,
            'total_output_tokens': self.total_output_tokens
        }

    def get_token_stats(self) -> Dict[str, int]:
        """
        Get token usage statistics.

        Returns:
            Dict with input_tokens and output_tokens
        """
        return {
            'input_tokens': self.total_input_tokens,
            'output_tokens': self.total_output_tokens
        }

    def reset_token_stats(self):
        """Reset token statistics counters."""
        self.total_input_tokens = 0
        self.total_output_tokens = 0


# Convenience function for quick API call
def call_llm(system_prompt: str, user_prompt: str,
             env_path: str = None, temperature: float = 0.1,
             json_mode: bool = True) -> Dict[str, Any]:
    """
    Quick LLM API call function (creates new client each time).

    For better performance, create an LLMAPI instance and reuse it.

    Args:
        system_prompt: System prompt defining the task
        user_prompt: User prompt containing the input data
        env_path: Path to .env file
        temperature: Sampling temperature
        json_mode: Whether to use JSON response format

    Returns:
        API response dict
    """
    with LLMAPI(env_path) as api:
        return api.call(system_prompt, user_prompt, temperature, json_mode)
