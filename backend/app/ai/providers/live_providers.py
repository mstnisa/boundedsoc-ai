"""
Optional real-provider adapters, only ever instantiated by get_provider()
when LLM_PROVIDER != "mock" and the matching key is present in .env. Kept
thin: schema validation and evidence enforcement happen in app.ai.graph
regardless of provider, so swapping providers never changes the safety
guarantees.
"""
from app.ai.providers.base import LLMProvider, LLMResponse


class OpenAIProvider(LLMProvider):
    provider_name = "openai"

    def __init__(self, api_key: str, model: str):
        self.model_name = model
        self._api_key = api_key

    def complete(self, *, system_prompt: str, user_prompt: str, prompt_template_version: str) -> LLMResponse:
        from openai import OpenAI  # imported lazily so it's not a hard dependency in mock mode

        client = OpenAI(api_key=self._api_key)
        resp = client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            response_format={"type": "json_object"},
        )
        return LLMResponse(
            text=resp.choices[0].message.content or "{}",
            provider=self.provider_name,
            model=self.model_name,
            prompt_template_version=prompt_template_version,
        )


class AnthropicProvider(LLMProvider):
    provider_name = "anthropic"

    def __init__(self, api_key: str, model: str):
        self.model_name = model
        self._api_key = api_key

    def complete(self, *, system_prompt: str, user_prompt: str, prompt_template_version: str) -> LLMResponse:
        import anthropic  # imported lazily so it's not a hard dependency in mock mode

        client = anthropic.Anthropic(api_key=self._api_key)
        resp = client.messages.create(
            model=self.model_name,
            max_tokens=2000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in resp.content if hasattr(block, "text"))
        return LLMResponse(
            text=text,
            provider=self.provider_name,
            model=self.model_name,
            prompt_template_version=prompt_template_version,
        )
