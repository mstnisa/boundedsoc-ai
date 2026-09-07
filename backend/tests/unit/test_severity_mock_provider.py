"""Unit tests for the deterministic mock LLM provider's heuristics, in
isolation from the DB/graph layer."""

import json

from app.ai.providers.mock_provider import MockLLMProvider


def test_severity_high_when_malicious_present():
    provider = MockLLMProvider()
    resp = provider.complete(
        system_prompt="TASK: severity",
        user_prompt="evidence_id=enrichment:1 :: verdict=malicious confidence=0.9",
        prompt_template_version="v1",
    )
    parsed = json.loads(resp.text)
    assert parsed["severity"] == "high"
    assert parsed["evidence_refs"] == ["enrichment:1"]


def test_severity_low_when_no_signal():
    provider = MockLLMProvider()
    resp = provider.complete(
        system_prompt="TASK: severity",
        user_prompt="evidence_id=event:1 :: benign host activity",
        prompt_template_version="v1",
    )
    parsed = json.loads(resp.text)
    assert parsed["severity"] == "low"


def test_mitre_matches_powershell_keywords():
    provider = MockLLMProvider()
    resp = provider.complete(
        system_prompt="TASK: mitre",
        user_prompt="evidence_id=event:1 :: powershell -enc invoke-expression downloadstring",
        prompt_template_version="v1",
    )
    parsed = json.loads(resp.text)
    technique_ids = [s["technique_id"] for s in parsed["suggestions"]]
    assert "T1059.001" in technique_ids


def test_mitre_no_suggestions_when_no_keywords_match():
    provider = MockLLMProvider()
    resp = provider.complete(
        system_prompt="TASK: mitre",
        user_prompt="evidence_id=event:1 :: nothing suspicious here at all",
        prompt_template_version="v1",
    )
    parsed = json.loads(resp.text)
    assert parsed["suggestions"] == []
