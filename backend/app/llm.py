"""Client for the local llama.cpp server (OpenAI-compatible + native endpoints).

- Token counting uses the model's own tokenizer (/tokenize) on the exact chat-templated
  prompt (/apply-template), so the 2,048 budget is measured, not guessed.
- Replies are grammar-constrained by a JSON schema; thinking mode is disabled.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from .config import settings


class LLMError(Exception):
    """Base error; `retryable` tells the worker whether trying again can help."""

    def __init__(self, msg: str, retryable: bool = True, context_overflow: bool = False):
        super().__init__(msg)
        self.retryable = retryable
        self.context_overflow = context_overflow


@dataclass
class ChatResult:
    content: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int
    finish_reason: str | None


class LLMClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.llm_url).rstrip("/")
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=httpx.Timeout(30.0))
        self._cache: dict[str, int] = {}

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> bool:
        try:
            r = await self._client.get("/health", timeout=5)
            return r.status_code == 200 and r.json().get("status") == "ok"
        except (httpx.HTTPError, ValueError):
            return False

    async def wait_ready(self, max_wait_s: float = 300) -> None:
        deadline = time.monotonic() + max_wait_s
        delay = 1.0
        while time.monotonic() < deadline:
            if await self.health():
                return
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 10)
        raise LLMError("Local model server is not ready", retryable=True)

    async def props(self) -> dict:
        try:
            r = await self._client.get("/props", timeout=5)
            return r.json()
        except (httpx.HTTPError, ValueError):
            return {}

    async def count_tokens(self, text: str) -> int:
        if text in self._cache:
            return self._cache[text]
        try:
            r = await self._client.post("/tokenize", json={"content": text}, timeout=30)
            r.raise_for_status()
            n = len(r.json()["tokens"])
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise LLMError(f"tokenize failed: {exc}") from exc
        if len(self._cache) < 50_000 and len(text) < 4000:
            self._cache[text] = n
        return n

    async def count_chat(self, messages: list[dict]) -> int:
        """Exact prompt size: render the chat template, then tokenize it."""
        try:
            r = await self._client.post(
                "/apply-template",
                json={"messages": messages, "chat_template_kwargs": {"enable_thinking": False}},
                timeout=30,
            )
            r.raise_for_status()
            prompt = r.json()["prompt"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise LLMError(f"apply-template failed: {exc}") from exc
        return await self.count_tokens(prompt)

    async def chat(self, messages: list[dict], schema: dict, max_tokens: int,
                   timeout_s: float | None = None, temperature: float = 0.0) -> ChatResult:
        body = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
            "cache_prompt": True,
            "response_format": {"type": "json_schema", "json_schema": {"name": "result", "schema": schema}},
            "chat_template_kwargs": {"enable_thinking": False},
        }
        t0 = time.monotonic()
        try:
            r = await self._client.post("/v1/chat/completions", json=body,
                                        timeout=timeout_s or settings.call_timeout_s)
        except httpx.TimeoutException as exc:
            raise LLMError(f"model call timed out after {timeout_s or settings.call_timeout_s}s") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"model server unreachable: {exc}") from exc
        if r.status_code >= 400:
            text = r.text[:300]
            overflow = "context" in text.lower() and ("exceed" in text.lower() or "too long" in text.lower())
            raise LLMError(f"model server HTTP {r.status_code}: {text}",
                           retryable=r.status_code >= 500 or r.status_code == 429, context_overflow=overflow)
        try:
            data = r.json()
            choice = data["choices"][0]
            usage = data.get("usage", {})
        except (ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"malformed server response: {exc}") from exc
        return ChatResult(
            content=choice.get("message", {}).get("content") or "",
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            latency_ms=int((time.monotonic() - t0) * 1000),
            finish_reason=choice.get("finish_reason"),
        )
