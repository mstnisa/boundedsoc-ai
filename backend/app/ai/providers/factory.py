from app.ai.providers.base import LLMProvider
from app.ai.providers.mock_provider import MockLLMProvider
from app.core.config import get_settings


def get_provider() -> LLMProvider:
    settings = get_settings()

    if settings.llm_provider == "openai" and settings.openai_api_key:
        from app.ai.providers.live_providers import OpenAIProvider

        return OpenAIProvider(api_key=settings.openai_api_key, model=settings.llm_model)

    if settings.llm_provider == "anthropic" and settings.anthropic_api_key:
        from app.ai.providers.live_providers import AnthropicProvider

        return AnthropicProvider(api_key=settings.anthropic_api_key, model=settings.llm_model)

    # Default / fallback: always safe to run, no key required.
    return MockLLMProvider()
