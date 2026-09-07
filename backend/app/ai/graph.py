"""
LangGraph orchestration for the three bounded AI tasks (severity, MITRE
mapping, report drafting). Each is its own small, explicit graph rather than
one large agent loop — per the AI design rules, the LLM is only ever used
for bounded tasks with structured, schema-validated output, never given
free rein or tool access of its own.

Graph shape (identical for all three tasks):
    build_prompt -> call_llm -> parse_and_validate -> END

parse_and_validate never raises on bad model output: a JSON/schema failure
produces an empty result with an error note, which the caller logs to the
audit trail instead of retrying blindly or fabricating a fallback claim.
"""

import json
from typing import Any, Callable, TypedDict

from langgraph.graph import END, StateGraph
from pydantic import BaseModel, ValidationError

from app.ai.providers.base import LLMProvider


class TaskState(TypedDict, total=False):
    system_prompt: str
    user_prompt: str
    prompt_template_version: str
    raw_response: str
    provider: str
    model: str
    parsed: dict[str, Any] | None
    errors: list[str]


def _make_call_llm_node(provider: LLMProvider) -> Callable[[TaskState], TaskState]:
    def call_llm(state: TaskState) -> TaskState:
        response = provider.complete(
            system_prompt=state["system_prompt"],
            user_prompt=state["user_prompt"],
            prompt_template_version=state["prompt_template_version"],
        )
        return {
            **state,
            "raw_response": response.text,
            "provider": response.provider,
            "model": response.model,
        }

    return call_llm


def _make_parse_node(schema: type[BaseModel] | None) -> Callable[[TaskState], TaskState]:
    def parse_and_validate(state: TaskState) -> TaskState:
        errors = list(state.get("errors", []))
        parsed: dict[str, Any] | None = None
        try:
            raw = json.loads(state["raw_response"])
            if schema is not None:
                schema.model_validate(raw)  # raises if shape is wrong
            parsed = raw
        except (json.JSONDecodeError, ValidationError) as exc:
            errors.append(f"schema_validation_failed: {exc}")
        return {**state, "parsed": parsed, "errors": errors}

    return parse_and_validate


def build_bounded_graph(provider: LLMProvider, schema: type[BaseModel] | None = None):
    graph = StateGraph(TaskState)
    graph.add_node("call_llm", _make_call_llm_node(provider))
    graph.add_node("parse_and_validate", _make_parse_node(schema))
    graph.set_entry_point("call_llm")
    graph.add_edge("call_llm", "parse_and_validate")
    graph.add_edge("parse_and_validate", END)
    return graph.compile()


def run_bounded_task(
    provider: LLMProvider,
    *,
    system_prompt: str,
    user_prompt: str,
    prompt_template_version: str,
    schema: type[BaseModel] | None = None,
) -> TaskState:
    app_graph = build_bounded_graph(provider, schema=schema)
    initial: TaskState = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "prompt_template_version": prompt_template_version,
        "errors": [],
    }
    return app_graph.invoke(initial)
