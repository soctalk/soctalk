"""LLM provider factory.

SocTalk supports either:
- Anthropic (via langchain-anthropic)
- OpenAI-compatible (via langchain-openai)

The provider selection is mutually exclusive and configured via environment.
See `soctalk.config.LLMConfig`.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from soctalk.config import LLMConfig


class LLMProviderError(ValueError):
    """Raised when the configured LLM provider is invalid or incomplete."""


class SchemaValidationError(ValueError):
    """The model's response failed structured-output schema validation
    after the retry budget was exhausted."""


def classify_llm_error(e: BaseException) -> str:
    """Bucket an LLM-provider exception into a stable category string.

    Categories the worker actually branches on:
      * ``insufficient_credit`` — provider billing / quota lack
      * ``rate_limited``        — provider 429 / TPM RPM exceeded
      * ``provider_error``      — other 4xx/5xx from the provider
      * ``timeout``             — local/transport timeout
      * ``schema_validation``   — structured output failed validation
      * ``unknown``             — fallback

    The category goes to logs + state["verdict_error"] /
    state["supervisor_error"]; the raw error string is intentionally
    kept out of any user-facing field.
    """
    if isinstance(e, SchemaValidationError):
        return "schema_validation"
    msg = str(e).lower()
    status = getattr(e, "status_code", None) or getattr(
        getattr(e, "response", None), "status_code", None
    )
    if "credit balance" in msg or "insufficient_quota" in msg or "billing" in msg:
        return "insufficient_credit"
    if status == 429 or "rate limit" in msg or "tokens per minute" in msg:
        return "rate_limited"
    if status and 400 <= int(status) < 600:
        return "provider_error"
    if "timeout" in msg or "timed out" in msg:
        return "timeout"
    return "unknown"


async def ainvoke_structured(
    llm: BaseChatModel,
    schema: type,
    messages: list[Any],
    *,
    on_response: Any = None,
) -> Any:
    """Invoke ``llm`` with schema-enforced output and one validation retry.

    Uses ``with_structured_output(include_raw=True)`` so the raw AIMessage
    (with ``usage_metadata``) survives for budget tracking — ``on_response``
    is called with each raw message. On a validation failure the error is
    fed back to the model once (self-correction); a second failure raises
    :class:`SchemaValidationError`, which ``classify_llm_error`` maps to
    ``schema_validation`` so the run fails loudly instead of a fabricated
    default steering triage.

    Provider errors (rate limit, timeout, 5xx) raise as usual — retry for
    those lives in the SDK layer configured by ``create_chat_model``.
    """
    from langchain_core.messages import HumanMessage

    structured = llm.with_structured_output(schema, include_raw=True)

    result = await structured.ainvoke(messages)
    raw = result.get("raw")
    if raw is not None and on_response is not None:
        on_response(raw)
    if result.get("parsed") is not None:
        return result["parsed"]

    parsing_error = result.get("parsing_error")
    retry_messages = list(messages)
    if raw is not None:
        retry_messages.append(raw)
    retry_messages.append(
        HumanMessage(
            content=(
                f"Your previous response failed validation against the "
                f"{getattr(schema, '__name__', 'output')} schema: {parsing_error}. "
                "Respond again, following the schema exactly."
            )
        )
    )
    result = await structured.ainvoke(retry_messages)
    raw = result.get("raw")
    if raw is not None and on_response is not None:
        on_response(raw)
    if result.get("parsed") is not None:
        return result["parsed"]

    raise SchemaValidationError(str(result.get("parsing_error")))


def create_chat_model(
    llm_config: LLMConfig,
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    **kwargs: Any,
) -> BaseChatModel:
    """Create a chat model for the configured provider.

    Args:
        llm_config: LLM configuration.
        model: Model name (provider-specific).
        temperature: Sampling temperature.
        max_tokens: Maximum tokens to generate.
        kwargs: Provider-specific keyword args (reserved for future use).

    Returns:
        A LangChain chat model instance.
    """
    if llm_config.anthropic_api_key and llm_config.openai_api_key:
        raise LLMProviderError(
            "Both ANTHROPIC_API_KEY and OPENAI_API_KEY are set. Choose exactly one LLM provider."
        )

    if llm_config.provider == "anthropic":
        if not llm_config.anthropic_api_key:
            raise LLMProviderError("ANTHROPIC_API_KEY is required when SOCTALK_LLM_PROVIDER=anthropic")

        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as e:
            raise LLMProviderError(
                "Anthropic provider selected but `langchain-anthropic` is not installed."
            ) from e

        anthropic_kwargs: dict[str, Any] = {
            "model": model,
            "api_key": llm_config.anthropic_api_key,
            "temperature": temperature,
            "max_tokens": max_tokens,
            # Bounded transport behavior: the SDK default timeout is 600s
            # and it already retries 408/429/5xx with backoff — we bound
            # the timeout and keep retries at the SDK layer (single layer,
            # no app-side retry wrapping).
            "timeout": llm_config.timeout_seconds,
            "max_retries": llm_config.max_retries,
            **kwargs,
        }
        if llm_config.anthropic_base_url:
            anthropic_kwargs["base_url"] = llm_config.anthropic_base_url

        try:
            return ChatAnthropic(**anthropic_kwargs)
        except TypeError:
            if llm_config.anthropic_base_url and not os.getenv("ANTHROPIC_BASE_URL"):
                os.environ["ANTHROPIC_BASE_URL"] = llm_config.anthropic_base_url
            return ChatAnthropic(
                model=model,
                api_key=llm_config.anthropic_api_key,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )

    if llm_config.provider == "openai":
        if not llm_config.openai_api_key:
            raise LLMProviderError("OPENAI_API_KEY is required when SOCTALK_LLM_PROVIDER=openai")

        # Prefer environment-driven configuration for OpenAI-compatible providers.
        # `langchain-openai`/`openai` pick up OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_ORGANIZATION.
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as e:
            raise LLMProviderError(
                "OpenAI provider selected but `langchain-openai` is not installed."
            ) from e

        openai_kwargs: dict[str, Any] = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": llm_config.timeout_seconds,
            "max_retries": llm_config.max_retries,
            **kwargs,
        }

        if llm_config.openai_base_url:
            openai_kwargs["base_url"] = llm_config.openai_base_url
        if llm_config.openai_organization:
            openai_kwargs["organization"] = llm_config.openai_organization

        try:
            return ChatOpenAI(**openai_kwargs)
        except TypeError:
            if llm_config.openai_base_url and not os.getenv("OPENAI_BASE_URL"):
                os.environ["OPENAI_BASE_URL"] = llm_config.openai_base_url
            if llm_config.openai_organization and not os.getenv("OPENAI_ORGANIZATION"):
                os.environ["OPENAI_ORGANIZATION"] = llm_config.openai_organization
            return ChatOpenAI(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )

    raise LLMProviderError(
        f"Unsupported LLM provider: {llm_config.provider!r}. Expected 'anthropic' or 'openai'."
    )
