"""Model API adapters for different LLM providers."""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class ModelProviderType(str, Enum):
    """Supported model provider types."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    VLLM = "vllm"
    OLLAMA = "ollama"
    LOCAL = "local"
    MOCK = "mock"


class ModelError(Exception):
    """Base model error."""
    pass


class ModelTimeoutError(ModelError):
    """Model request timed out."""
    pass


class ModelRateLimitError(ModelError):
    """Rate limit exceeded."""
    pass


class ModelAuthError(ModelError):
    """Authentication error."""
    pass


class ModelProviderError(ModelError):
    """Provider-specific error."""
    pass


class ModelSafetyError(ModelError):
    """Content safety violation."""
    pass


@dataclass(frozen=True)
class ModelConfig:
    """Configuration for model provider."""
    model_name: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    organization: Optional[str] = None
    timeout_seconds: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop_sequences: List[str] = field(default_factory=list)
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Message:
    """Chat message."""
    role: str  # system, user, assistant, tool
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


@dataclass(frozen=True)
class ToolCall:
    """Tool call from model."""
    id: str
    type: str  # function
    function: Dict[str, Any]  # name, arguments


@dataclass(frozen=True)
class ModelResponse:
    """Model response."""
    content: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: Optional[str] = None
    usage: Optional[Dict[str, int]] = None
    model: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class StreamingChunk:
    """Streaming response chunk."""
    content: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: Optional[str] = None
    is_final: bool = False


@dataclass(frozen=True)
class ToolCall:
    """Tool call from model."""
    id: str
    type: str  # function
    function: Dict[str, Any]  # name, arguments


@dataclass(frozen=True)
class StreamingChunk:
    """Streaming response chunk."""
    content: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: Optional[str] = None
    is_final: bool = False


@dataclass(frozen=True)
class ToolCall:
    """Tool call from model."""
    id: str
    type: str  # function
    function: Dict[str, Any]  # name, arguments


@dataclass(frozen=True)
class StreamingChunk:
    """Streaming response chunk."""
    content: Optional[str] = None
    tool_calls: Optional[List[ToolCall]] = None
    finish_reason: Optional[str] = None
    is_final: bool = False


class ModelAdapter(ABC):
    """Abstract base class for model providers."""

    @property
    @abstractmethod
    def provider_type(self) -> ModelProviderType:
        """Return the provider type."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available."""
        ...

    @abstractmethod
    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        """Complete a chat conversation."""
        ...

    @abstractmethod
    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        """Stream a chat completion."""
        ...

    @abstractmethod
    async def count_tokens(self, messages: List[Message]) -> int:
        """Count tokens in messages."""
        ...

    @abstractmethod
    def validate_config(self, config: ModelConfig) -> bool:
        """Validate configuration."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Close connections."""
        ...


class OpenAIAdapter:
    """OpenAI API adapter."""

    provider_type = ModelProviderType.OPENAI

    def __init__(self, config: ModelConfig):
        if not OPENAI_AVAILABLE:
            raise ModelError("openai package not installed. Install with: pip install openai")

        self.config = config
        self._client = openai.AsyncOpenAI(
            api_key=config.api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=config.base_url,
            organization=config.organization,
            timeout=config.timeout_seconds,
            max_retries=config.max_retries,
        )

    def is_available(self) -> bool:
        return OPENAI_AVAILABLE and bool(self.config.api_key or os.environ.get("OPENAI_API_KEY"))

    def validate_config(self, config: ModelConfig) -> bool:
        return bool(config.api_key or os.environ.get("OPENAI_API_KEY"))

    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        cfg = config or self.config
        openai_messages = self._convert_messages(messages)
        openai_tools = self._convert_tools(tools) if tools else None

        try:
            response = await self._client.chat.completions.create(
                model=cfg.model_name,
                messages=openai_messages,
                tools=openai_tools,
                temperature=cfg.temperature,
                top_p=cfg.top_p,
                max_tokens=cfg.max_tokens,
                frequency_penalty=cfg.frequency_penalty,
                presence_penalty=cfg.presence_penalty,
                stop=cfg.stop_sequences or None,
                **cfg.extra_params,
            )

            choice = response.choices[0]
            tool_calls = None
            if choice.message.tool_calls:
                tool_calls = [
                    ToolCall(
                        id=tc.id,
                        type=tc.type,
                        function={
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    )
                    for tc in choice.message.tool_calls
                ]

            return ModelResponse(
                content=choice.message.content,
                tool_calls=tool_calls,
                finish_reason=choice.finish_reason,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                } if response.usage else None,
                model=response.model,
                raw_response=response.model_dump(),
            )

        except openai.RateLimitError as e:
            raise ModelRateLimitError(str(e))
        except openai.AuthenticationError as e:
            raise ModelAuthError(str(e))
        except openai.APITimeoutError as e:
            raise ModelTimeoutError(str(e))
        except openai.APIError as e:
            raise ModelProviderError(str(e))

    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        cfg = config or self.config
        openai_messages = self._convert_messages(messages)
        openai_tools = self._convert_tools(tools) if tools else None

        try:
            stream = await self._client.chat.completions.create(
                model=cfg.model_name,
                messages=openai_messages,
                tools=openai_tools,
                temperature=cfg.temperature,
                top_p=cfg.top_p,
                max_tokens=cfg.max_tokens,
                frequency_penalty=cfg.frequency_penalty,
                presence_penalty=cfg.presence_penalty,
                stop=cfg.stop_sequences or None,
                stream=True,
                **cfg.extra_params,
            )

            async for chunk in stream:
                if not chunk.choices:
                    continue

                choice = chunk.choices[0]
                delta = choice.delta

                tool_calls = None
                if delta.tool_calls:
                    tool_calls = [
                        ToolCall(
                            id=tc.id or str(uuid.uuid4()),
                            type=tc.type,
                            function={
                                "name": tc.function.name if tc.function else "",
                                "arguments": tc.function.arguments if tc.function else "",
                            },
                        )
                        for tc in delta.tool_calls
                    ]

                yield StreamingChunk(
                    content=delta.content,
                    tool_calls=tool_calls,
                    finish_reason=choice.finish_reason,
                    is_final=choice.finish_reason is not None,
                )

        except openai.RateLimitError as e:
            raise ModelRateLimitError(str(e))
        except openai.AuthenticationError as e:
            raise ModelAuthError(str(e))
        except openai.APITimeoutError as e:
            raise ModelTimeoutError(str(e))
        except openai.APIError as e:
            raise ModelProviderError(str(e))

    async def count_tokens(self, messages: List[Message]) -> int:
        """Estimate token count (rough approximation)."""
        text = " ".join(m.content for m in messages if m.content)
        return len(text) // 4  # Rough approximation

    async def close(self) -> None:
        await self._client.close()

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        """Convert internal messages to OpenAI format."""
        result = []
        for msg in messages:
            msg_dict = {
                "role": msg.role,
                "content": msg.content,
            }
            if msg.name:
                msg_dict["name"] = msg.name
            if msg.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": tc.function,
                    }
                    for tc in msg.tool_calls
                ]
            if msg.tool_call_id:
                msg_dict["tool_call_id"] = msg.tool_call_id
            result.append(msg_dict)
        return result

    def _convert_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert internal tools to OpenAI format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {}),
                },
            }
            for t in tools
        ]


class AnthropicAdapter:
    """Anthropic Claude API adapter."""

    provider_type = ModelProviderType.ANTHROPIC

    def __init__(self, config: ModelConfig):
        if not ANTHROPIC_AVAILABLE:
            raise ModelError("anthropic package not installed. Install with: pip install anthropic")

        self.config = config
        self._client = anthropic.AsyncAnthropic(
            api_key=config.api_key or os.environ.get("ANTHROPIC_API_KEY"),
            base_url=config.base_url,
            timeout=config.timeout_seconds,
            max_retries=config.max_retries,
        )

    def is_available(self) -> bool:
        return ANTHROPIC_AVAILABLE and bool(self.config.api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def validate_config(self, config: ModelConfig) -> bool:
        return bool(config.api_key or os.environ.get("ANTHROPIC_API_KEY"))

    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        cfg = config or self.config
        anthropic_messages = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools) if tools else None

        try:
            response = await self._client.messages.create(
                model=cfg.model_name,
                messages=anthropic_messages,
                tools=anthropic_tools,
                max_tokens=cfg.max_tokens or 4096,
                temperature=cfg.temperature,
                top_p=cfg.top_p,
                stop_sequences=cfg.stop_sequences or None,
                **cfg.extra_params,
            )

            tool_calls = None
            content_parts = []
            for block in response.content:
                if block.type == "text":
                    content_parts.append(block.text)
                elif block.type == "tool_use":
                    if not tool_calls:
                        tool_calls = []
                    tool_calls.append(ToolCall(
                        id=block.id,
                        type="function",
                        function={
                            "name": block.name,
                            "arguments": json.dumps(block.input),
                        },
                    ))

            return ModelResponse(
                content="".join(content_parts) if content_parts else None,
                tool_calls=tool_calls,
                finish_reason=response.stop_reason,
                usage={
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                },
                model=response.model,
            )

        except anthropic.RateLimitError as e:
            raise ModelRateLimitError(str(e))
        except anthropic.AuthenticationError as e:
            raise ModelAuthError(str(e))
        except anthropic.APITimeoutError as e:
            raise ModelTimeoutError(str(e))
        except anthropic.APIError as e:
            raise ModelProviderError(str(e))

    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        cfg = config or self.config
        anthropic_messages = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools) if tools else None

        try:
            stream = await self._client.messages.stream(
                model=cfg.model_name,
                messages=anthropic_messages,
                tools=anthropic_tools,
                max_tokens=cfg.max_tokens or 4096,
                temperature=cfg.temperature,
                top_p=cfg.top_p,
                stop_sequences=cfg.stop_sequences or None,
                **cfg.extra_params,
            )

            async for event in stream:
                if event.type == "content_block_delta":
                    if event.delta.type == "text_delta":
                        yield StreamingChunk(
                            content=event.delta.text,
                            is_final=False,
                        )
                elif event.type == "message_delta":
                    if event.delta.stop_reason:
                        yield StreamingChunk(
                            content=None,
                            finish_reason=event.delta.stop_reason,
                            is_final=True,
                        )

        except anthropic.RateLimitError as e:
            raise ModelRateLimitError(str(e))
        except anthropic.AuthenticationError as e:
            raise ModelAuthError(str(e))
        except anthropic.APITimeoutError as e:
            raise ModelTimeoutError(str(e))
        except anthropic.APIError as e:
            raise ModelProviderError(str(e))

    async def count_tokens(self, messages: List[Message]) -> int:
        """Count tokens using Anthropic's tokenizer."""
        try:
            text = " ".join(m.content for m in messages if m.content)
            response = await self._client.messages.count_tokens(
                model=self.config.model_name,
                messages=self._convert_messages(messages),
            )
            return response.input_tokens
        except Exception:
            text = " ".join(m.content for m in messages if m.content)
            return len(text) // 4

    async def close(self) -> None:
        await self._client.close()

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        """Convert to Anthropic format."""
        result = []
        for msg in messages:
            if msg.role == "system":
                continue  # System handled separately in Anthropic
            result.append({
                "role": "user" if msg.role == "user" else "assistant",
                "content": msg.content,
            })
        return result

    def _convert_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {}),
            }
            for t in tools
        ]


class VLLMAdapter:
    """Local vLLM server adapter (OpenAI-compatible API)."""

    provider_type = ModelProviderType.VLLM

    def __init__(self, config: ModelConfig):
        if not HTTPX_AVAILABLE:
            raise ModelError("httpx package not installed. Install with: pip install httpx")

        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.base_url or "http://localhost:8000/v1",
            timeout=config.timeout_seconds,
        )

    def is_available(self) -> bool:
        return HTTPX_AVAILABLE

    def validate_config(self, config: ModelConfig) -> bool:
        return bool(config.base_url)

    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        cfg = config or self.config
        openai_messages = self._convert_messages(messages)
        openai_tools = self._convert_tools(tools) if tools else None

        payload = {
            "model": cfg.model_name,
            "messages": openai_messages,
            "temperature": cfg.temperature,
            "top_p": cfg.top_p,
            "max_tokens": cfg.max_tokens,
            "frequency_penalty": cfg.frequency_penalty,
            "presence_penalty": cfg.presence_penalty,
            "stop": cfg.stop_sequences or None,
            "stream": False,
        }
        if openai_tools:
            payload["tools"] = openai_tools

        try:
            response = await self._client.post(
                "/chat/completions",
                json=payload,
                timeout=cfg.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            choice = data["choices"][0]
            tool_calls = None
            if choice["message"].get("tool_calls"):
                tool_calls = [
                    ToolCall(
                        id=tc["id"],
                        type=tc["type"],
                        function=tc["function"],
                    )
                    for tc in choice["message"]["tool_calls"]
                ]

            return ModelResponse(
                content=choice["message"].get("content"),
                tool_calls=tool_calls,
                finish_reason=choice.get("finish_reason"),
                usage=data.get("usage"),
                model=data.get("model"),
                raw_response=data,
            )

        except httpx.TimeoutException as e:
            raise ModelTimeoutError(str(e))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise ModelRateLimitError(str(e))
            elif e.response.status_code == 401:
                raise ModelAuthError(str(e))
            raise ModelProviderError(str(e))
        except Exception as e:
            raise ModelProviderError(str(e))

    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        cfg = config or self.config
        openai_messages = self._convert_messages(messages)
        openai_tools = self._convert_tools(tools) if tools else None

        payload = {
            "model": cfg.model_name,
            "messages": openai_messages,
            "temperature": cfg.temperature,
            "top_p": cfg.top_p,
            "max_tokens": cfg.max_tokens,
            "frequency_penalty": cfg.frequency_penalty,
            "presence_penalty": cfg.presence_penalty,
            "stop": cfg.stop_sequences or None,
            "stream": True,
        }
        if tools:
            payload["tools"] = self._convert_tools(tools)

        try:
            async with self._client.stream(
                "POST",
                "/chat/completions",
                json=payload,
                timeout=cfg.timeout_seconds,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data)
                            if chunk["choices"]:
                                choice = chunk["choices"][0]
                                delta = choice["delta"]
                                tool_calls = None
                                if delta.get("tool_calls"):
                                    tool_calls = [
                                        ToolCall(
                                            id=tc["id"],
                                            type=tc["type"],
                                            function=tc["function"],
                                        )
                                        for tc in delta["tool_calls"]
                                    ]
                                yield StreamingChunk(
                                    content=delta.get("content"),
                                    tool_calls=tool_calls,
                                    finish_reason=choice.get("finish_reason"),
                                    is_final=choice.get("finish_reason") is not None,
                                )
                        except json.JSONDecodeError:
                            continue

        except httpx.TimeoutException as e:
            raise ModelTimeoutError(str(e))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise ModelRateLimitError(str(e))
            elif e.response.status_code == 401:
                raise ModelAuthError(str(e))
            raise ModelProviderError(str(e))
        except Exception as e:
            raise ModelProviderError(str(e))

    async def count_tokens(self, messages: List[Message]) -> int:
        text = " ".join(m.content for m in messages if m.content)
        return len(text) // 4

    async def close(self) -> None:
        await self._client.aclose()

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        result = []
        for msg in messages:
            msg_dict = {"role": msg.role, "content": msg.content}
            if msg.name:
                msg_dict["name"] = msg.name
            if msg.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": tc.type,
                        "function": tc.function,
                    }
                    for tc in msg.tool_calls
                ]
            if msg.tool_call_id:
                msg_dict["tool_call_id"] = msg.tool_call_id
            result.append(msg_dict)
        return result

    def _convert_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {}),
                },
            }
            for t in tools
        ]


class OllamaAdapter:
    """Ollama local model adapter."""

    provider_type = ModelProviderType.OLLAMA

    def __init__(self, config: ModelConfig):
        if not HTTPX_AVAILABLE:
            raise ModelError("httpx package not installed. Install with: pip install httpx")

        self.config = config
        self._client = httpx.AsyncClient(
            base_url=config.base_url or "http://localhost:11434",
            timeout=config.timeout_seconds,
        )

    def is_available(self) -> bool:
        return HTTPX_AVAILABLE

    def validate_config(self, config: ModelConfig) -> bool:
        return bool(config.base_url)

    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        cfg = config or self.config

        payload = {
            "model": cfg.model_name,
            "messages": self._convert_messages(messages),
            "stream": False,
            "options": {
                "temperature": cfg.temperature,
                "top_p": cfg.top_p,
                "num_predict": cfg.max_tokens,
                "stop": cfg.stop_sequences,
            },
        }

        try:
            response = await self._client.post(
                "/api/chat",
                json=payload,
                timeout=cfg.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            return ModelResponse(
                content=data.get("message", {}).get("content"),
                finish_reason=data.get("done_reason"),
                model=data.get("model"),
                raw_response=data,
            )

        except httpx.TimeoutException as e:
            raise ModelTimeoutError(str(e))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise ModelRateLimitError(str(e))
            raise ModelProviderError(str(e))
        except Exception as e:
            raise ModelProviderError(str(e))

    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        cfg = config or self.config

        payload = {
            "model": cfg.model_name,
            "messages": self._convert_messages(messages),
            "stream": True,
            "options": {
                "temperature": cfg.temperature,
                "top_p": cfg.top_p,
                "num_predict": cfg.max_tokens,
                "stop": cfg.stop_sequences,
            },
        }

        try:
            async with self._client.stream(
                "POST",
                "/api/chat",
                json=payload,
                timeout=cfg.timeout_seconds,
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    if data.get("message", {}).get("content"):
                        yield StreamingChunk(
                            content=data["message"]["content"],
                            is_final=data.get("done", False),
                        )
                    if data.get("done"):
                        break

        except httpx.TimeoutException as e:
            raise ModelTimeoutError(str(e))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise ModelRateLimitError(str(e))
            raise ModelProviderError(str(e))
        except Exception as e:
            raise ModelProviderError(str(e))

    async def count_tokens(self, messages: List[Message]) -> int:
        text = " ".join(m.content for m in messages if m.content)
        return len(text) // 4

    async def close(self) -> None:
        await self._client.aclose()

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, Any]]:
        return [
            {"role": m.role, "content": m.content}
            for m in messages
        ]


class MockAdapter:
    """Mock adapter for testing."""

    provider_type = ModelProviderType.MOCK

    def __init__(self, config: ModelConfig):
        self.config = config
        self.responses: List[ModelResponse] = []
        self.stream_responses: List[List[StreamingChunk]] = []

    def is_available(self) -> bool:
        return True

    def validate_config(self, config: ModelConfig) -> bool:
        return True

    def set_responses(self, responses: List[ModelResponse]) -> None:
        self.responses = responses

    def set_stream_responses(self, responses: List[List[StreamingChunk]]) -> None:
        self.stream_responses = responses

    async def complete(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        if self.responses:
            return self.responses.pop(0)
        return ModelResponse(
            content="Mock response",
            finish_reason="stop",
            model="mock",
        )

    async def stream(
        self,
        messages: List[Message],
        config: Optional[ModelConfig] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AsyncIterator[StreamingChunk]:
        if self.stream_responses:
            chunks = self.stream_responses.pop(0)
            for chunk in chunks:
                yield chunk
        else:
            yield StreamingChunk(content="Mock ", is_final=False)
            await asyncio.sleep(0.01)
            yield StreamingChunk(content="response", is_final=True)

    async def count_tokens(self, messages: List[Message]) -> int:
        return sum(len(m.content) for m in messages if m.content) // 4

    async def close(self) -> None:
        pass


def create_model_adapter(
    provider: ModelProviderType,
    config: ModelConfig,
) -> ModelAdapter:
    """Factory function to create model adapter."""
    if provider == ModelProviderType.OPENAI:
        return OpenAIAdapter(config)
    elif provider == ModelProviderType.ANTHROPIC:
        return AnthropicAdapter(config)
    elif provider == ModelProviderType.VLLM:
        return VLLMAdapter(config)
    elif provider == ModelProviderType.OLLAMA:
        return OllamaAdapter(config)
    elif provider == ModelProviderType.MOCK:
        return MockAdapter(config)
    else:
        raise ValueError(f"Unknown provider: {provider}")