"""
LLM service package — Phase 7B.

Provides LLM-assisted finding intelligence with:
  - Provider abstraction (no vendor lock-in)
  - Secret / sensitive data redaction before any external call
  - Prompt injection defenses
  - Deterministic request hashing for deduplication
  - Fully optional — disabled, unavailable, or misconfigured providers
    never cause the deterministic scanner to fail
"""

from app.services.llm.schemas import (
    LLMVerdict,
    LLMAnalysisResult,
    LLMUnavailableResult,
)
from app.services.llm.client import (
    LLMProvider,
    get_llm_provider,
    LLMUnavailableError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMProviderError,
)
from app.services.llm.analyzer import LLMAnalyzer

__all__ = [
    "LLMVerdict",
    "LLMAnalysisResult",
    "LLMUnavailableResult",
    "LLMProvider",
    "get_llm_provider",
    "LLMUnavailableError",
    "LLMTimeoutError",
    "LLMRateLimitError",
    "LLMProviderError",
    "LLMAnalyzer",
]
