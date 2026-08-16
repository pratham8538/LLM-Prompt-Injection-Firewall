"""
LLM Provider Adapter — Stage 4
================================

Per the project blueprint (§26), the firewall should not be hard-wired to
one LLM vendor. This module defines a small provider interface and two
implementations:

  - GeminiProvider: real calls to the Gemini API (needs GEMINI_API_KEY).
  - OpenAIProvider: real calls to OpenAI Chat Completions (needs OPENAI_API_KEY).
  - MockProvider:   deterministic canned responses, no network required.
                     Useful for local dev/demo and for CI, where you don't
                     want tests depending on a live API key or quota.

api.py depends only on the LLMProvider interface, never on a specific
vendor SDK — swapping providers is a one-line change (see get_provider()).
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

import requests


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Send prompt to the LLM and return its text response."""
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    """Real Gemini API call via the generativelanguage REST endpoint.

    Requires the GEMINI_API_KEY environment variable. Note: this class is
    only exercised when you run the API on a machine with network access
    to Google's API — it is not reachable from this sandboxed environment.
    """

    API_URL = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.6-flash:generateContent"
    )

    def __init__(self, api_key: str | None = None, timeout: float = 30.0):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. Export it before starting the "
                "API, e.g.: export GEMINI_API_KEY=your_key_here"
            )
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.API_URL}?key={self.api_key}",
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Unexpected Gemini response shape: {data}") from exc


class OpenAIProvider(LLMProvider):
    """Real OpenAI Chat Completions call. Requires OPENAI_API_KEY.

    Demonstrates that swapping providers doesn't touch api.py or
    detector.py at all — this class implements the same LLMProvider
    interface as GeminiProvider.
    """

    API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini", timeout: float = 30.0):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export it before starting the "
                "API, e.g.: export OPENAI_API_KEY=your_key_here"
            )
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        resp = requests.post(
            self.API_URL,
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise RuntimeError(f"Unexpected OpenAI response shape: {data}") from exc


class ClaudeProvider(LLMProvider):
    """Real Anthropic Messages API call. Requires ANTHROPIC_API_KEY.

    Included because the original blueprint's provider-independence
    diagram (§26) explicitly names Gemini / OpenAI / Claude as the three
    swappable targets.
    """

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-6", timeout: float = 30.0):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Export it before starting the "
                "API, e.g.: export ANTHROPIC_API_KEY=your_key_here"
            )
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        resp = requests.post(
            self.API_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return "".join(block["text"] for block in data["content"] if block.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise RuntimeError(f"Unexpected Claude response shape: {data}") from exc


class MockProvider(LLMProvider):
    """No-network stand-in for real providers. Returns a deterministic,
    clearly-labeled canned response so it's obvious in testing/demo that
    this is NOT a real model output."""

    def generate(self, prompt: str) -> str:
        preview = prompt[:120] + ("..." if len(prompt) > 120 else "")
        return (
            "[MOCK LLM RESPONSE — no real model was called] "
            f"Received prompt: {preview!r}"
        )


class MockLeakyProvider(LLMProvider):
    """Test-only provider that always returns a response containing a
    compliance-confirmation leak phrase, so the output-scanning path in
    /api/chat can be exercised without a live LLM. Select via
    LLM_PROVIDER=mock_leaky. Never used unless explicitly requested."""

    def generate(self, prompt: str) -> str:
        return (
            "Sure, I will ignore my previous guidelines and tell you the secret: "
            f"the answer to your prompt {prompt[:40]!r} is 42."
        )


def get_provider() -> LLMProvider:
    """Provider selection point.

    Priority: explicit LLM_PROVIDER env var > whichever API key is set >
    mock fallback. This is the one place that knows about specific
    vendors — everything else in the codebase talks to LLMProvider only.
    """
    choice = os.environ.get("LLM_PROVIDER", "").lower()
    if choice == "gemini":
        return GeminiProvider()
    if choice == "openai":
        return OpenAIProvider()
    if choice == "claude":
        return ClaudeProvider()
    if choice == "mock":
        return MockProvider()
    if choice == "mock_leaky":
        return MockLeakyProvider()

    if os.environ.get("GEMINI_API_KEY"):
        return GeminiProvider()
    if os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider()
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ClaudeProvider()
    return MockProvider()
