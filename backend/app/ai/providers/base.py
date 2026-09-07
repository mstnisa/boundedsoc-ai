"""Provider-agnostic LLM interface. Every provider returns a raw string;
callers (app.ai.graph) are responsible for schema-validating the output
against a Pydantic model and treating parse failures as "no claim", never
as a reason to invent one.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    prompt_template_version: str


class LLMProvider(ABC):
    provider_name: str
    model_name: str

    @abstractmethod
    def complete(self, *, system_prompt: str, user_prompt: str, prompt_template_version: str) -> LLMResponse:
        ...
