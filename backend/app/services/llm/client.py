"""
LLM provider abstraction — Phase 7B.

Defines a provider interface and registers concrete implementations.
The scanner and API never import a vendor SDK directly — they always go
through get_llm_provider() so swapping providers requires zero scanner changes.

SECURITY NOTES:
  - API keys are NEVER logged, printed, or returned to callers.
  - Providers receive pre-redacted context — see redaction.py.
  - This module never executes repository code or shell commands.
  - Malformed responses raise LLMProviderError, not raw vendor exceptions.

AVAILABILITY:
  - If LLM_ENABLED=false (default), get_llm_provider() raises LLMUnavailableError.
  - If a required setting is missing, get_llm_provider() raises LLMUnavailableError.
  - Callers must handle LLMUnavailableError gracefully — it is NOT a fatal error.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from urllib.error import URLError

from app.services.llm.schemas import LLMAnalysisResult

logger = logging.getLogger(__name__)


# ── Custom exception hierarchy ─────────────────────────────────────────────


class LLMError(Exception):
    """Base class for all LLM-related errors."""

    pass


class LLMUnavailableError(LLMError):
    """
    LLM is not available (disabled, misconfigured, missing API key, etc.).

    This is a CONTROLLED state, not a bug. Callers should return a
    LLMUnavailableResult rather than propagating this exception to the user.
    """

    pass


class LLMTimeoutError(LLMError):
    """Provider request timed out."""

    pass


class LLMRateLimitError(LLMError):
    """Provider rate limit was exceeded."""

    pass


class LLMProviderError(LLMError):
    """Unrecoverable provider error (bad request, auth failure, malformed response, etc.)."""

    pass


# ── Provider interface ─────────────────────────────────────────────────────


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.

    Implementations must:
      1. Never log the API key.
      2. Never return raw chain-of-thought / hidden reasoning.
      3. Return a parsed LLMAnalysisResult on success.
      4. Raise LLMTimeoutError, LLMRateLimitError, or LLMProviderError on failure.
      5. Never raise unhandled vendor SDK exceptions to callers.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short identifier, e.g. 'openai', 'anthropic', 'mock'."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The specific model string, e.g. 'gpt-4o-mini'."""

    @abstractmethod
    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 30,
    ) -> LLMAnalysisResult:
        """
        Call the provider with the system prompt and user message.

        Args:
            system_prompt: The fixed security analysis system instruction.
            user_message:  The redacted finding context.
            timeout:       Request timeout in seconds.

        Returns:
            Validated LLMAnalysisResult.

        Raises:
            LLMTimeoutError:    Request timed out.
            LLMRateLimitError:  Provider rate limit exceeded.
            LLMProviderError:   Any other provider failure.
        """


# ── OpenAI provider ────────────────────────────────────────────────────────


class OpenAIProvider(LLMProvider):
    """
    OpenAI Chat Completions provider.

    Uses only the standard library (urllib) so no extra dependency is
    required. This keeps the implementation Python 3.9 compatible without
    requiring the openai SDK.

    SECURITY: The API key is read from settings and NEVER logged or returned.
    """

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise LLMUnavailableError("OpenAI API key is empty.")
        # Store key without logging it
        self._api_key = api_key
        self._model = model

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 30,
    ) -> LLMAnalysisResult:
        """Call OpenAI Chat Completions API."""
        import urllib.request

        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": 1024,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=data,
            headers={
                # API key never logged — only passed in header
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            import socket

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except socket.timeout:
            raise LLMTimeoutError(f"OpenAI request timed out after {timeout}s")
        except URLError as exc:
            reason = str(exc.reason) if hasattr(exc, "reason") else str(exc)
            # Check for 429 in the error response
            if "429" in reason:
                raise LLMRateLimitError("OpenAI rate limit exceeded")
            raise LLMProviderError(f"OpenAI request failed: {reason}")
        except Exception as exc:
            raise LLMProviderError(f"Unexpected OpenAI error: {type(exc).__name__}")

        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> LLMAnalysisResult:
        """Parse and validate the OpenAI JSON response."""
        try:
            outer = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMProviderError(f"OpenAI response is not valid JSON: {exc}")

        # Check for API-level errors (auth, quota, etc.)
        if "error" in outer:
            err_msg = outer["error"].get("message", "Unknown OpenAI error")
            code = outer["error"].get("code", "")
            if code == "rate_limit_exceeded":
                raise LLMRateLimitError(f"OpenAI rate limit: {err_msg}")
            raise LLMProviderError(f"OpenAI API error: {err_msg}")

        try:
            content = outer["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMProviderError(f"Unexpected OpenAI response structure: {exc}")

        try:
            result_dict = json.loads(content)
        except json.JSONDecodeError as exc:
            raise LLMProviderError(f"OpenAI content is not valid JSON: {exc}")

        try:
            return LLMAnalysisResult(
                **result_dict,
                provider=self.provider_name,
                model=self.model_name,
            )
        except Exception as exc:
            raise LLMProviderError(f"LLM response failed schema validation: {exc}")


# ── Anthropic provider ─────────────────────────────────────────────────────


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude Messages API provider.

    Uses only standard library (urllib). Python 3.9 compatible.
    SECURITY: API key is never logged or returned.
    """

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise LLMUnavailableError("Anthropic API key is empty.")
        self._api_key = api_key
        self._model = model

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._model

    def analyze(
        self,
        system_prompt: str,
        user_message: str,
        timeout: int = 30,
    ) -> LLMAnalysisResult:
        """Call Anthropic Messages API."""
        import urllib.request

        payload: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": 1024,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message},
            ],
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "x-api-key": self._api_key,  # Never logged
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            import socket

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except socket.timeout:
            raise LLMTimeoutError(f"Anthropic request timed out after {timeout}s")
        except URLError as exc:
            reason = str(exc.reason) if hasattr(exc, "reason") else str(exc)
            if "429" in reason or "rate_limit" in reason.lower():
                raise LLMRateLimitError("Anthropic rate limit exceeded")
            raise LLMProviderError(f"Anthropic request failed: {reason}")
        except Exception as exc:
            raise LLMProviderError(f"Unexpected Anthropic error: {type(exc).__name__}")

        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> LLMAnalysisResult:
        """Parse and validate the Anthropic Messages response."""
        try:
            outer = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMProviderError(f"Anthropic response is not valid JSON: {exc}")

        if "error" in outer:
            err_msg = outer["error"].get("message", "Unknown Anthropic error")
            err_type = outer["error"].get("type", "")
            if err_type == "rate_limit_error":
                raise LLMRateLimitError(f"Anthropic rate limit: {err_msg}")
            raise LLMProviderError(f"Anthropic API error: {err_msg}")

        try:
            content = outer["content"][0]["text"]
        except (KeyError, IndexError) as exc:
            raise LLMProviderError(f"Unexpected Anthropic response structure: {exc}")

        # Anthropic may wrap JSON in markdown code blocks
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            # Remove first and last fencing lines
            content = "\n".join(lines[1:-1]) if len(lines) > 2 else content

        try:
            result_dict = json.loads(content)
        except json.JSONDecodeError as exc:
            raise LLMProviderError(f"Anthropic content is not valid JSON: {exc}")

        try:
            return LLMAnalysisResult(
                **result_dict,
                provider=self.provider_name,
                model=self.model_name,
            )
        except Exception as exc:
            raise LLMProviderError(f"LLM response failed schema validation: {exc}")


# ── Provider factory ───────────────────────────────────────────────────────


def get_llm_provider() -> LLMProvider:
    """
    Return an initialised LLM provider based on current settings.

    Raises LLMUnavailableError if:
      - LLM_ENABLED is false (the default safe state)
      - LLM_PROVIDER is empty or unsupported
      - LLM_API_KEY is missing
      - LLM_MODEL is missing

    SECURITY: This function never logs the API key.
    """
    from app.database import settings  # late import to avoid circular dependency

    if not settings.LLM_ENABLED:
        raise LLMUnavailableError("LLM is disabled (LLM_ENABLED=false).")

    provider_name = (settings.LLM_PROVIDER or "").strip().lower()
    api_key = (settings.LLM_API_KEY or "").strip()
    model = (settings.LLM_MODEL or "").strip()

    if not provider_name:
        raise LLMUnavailableError("LLM_PROVIDER is not set.")
    if not api_key:
        raise LLMUnavailableError("LLM_API_KEY is not set.")
    if not model:
        raise LLMUnavailableError("LLM_MODEL is not set.")

    if provider_name == "openai":
        return OpenAIProvider(api_key=api_key, model=model)
    if provider_name == "anthropic":
        return AnthropicProvider(api_key=api_key, model=model)

    raise LLMUnavailableError(
        f"Unsupported LLM provider: '{provider_name}'. "
        "Supported: openai, anthropic."
    )
