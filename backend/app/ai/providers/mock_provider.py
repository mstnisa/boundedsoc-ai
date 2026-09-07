"""
Deterministic, offline mock LLM. This is the default provider
(LLM_PROVIDER=mock) so the whole system — including the AI reasoning layer —
runs with zero API keys and zero network calls, and produces reproducible
output for tests and the benchmark.

It is NOT a language model: it applies transparent, keyword/rule-based
heuristics against the (already-sanitized) incident data it is given, and
returns JSON shaped exactly like a real provider's structured-output
response would be. This keeps app.ai.graph's parsing/validation/evidence
logic identical whether the real backing model is mocked or live.
"""
import json
import re

from app.ai.providers.base import LLMProvider, LLMResponse

_MITRE_KEYWORDS = {
    "T1059.001": ["powershell", "-enc", "encodedcommand", "invoke-expression", "iex"],
    "T1027": ["base64", "obfuscat", "-enc"],
    "T1105": ["downloadstring", "certutil", "bitsadmin", "invoke-webrequest"],
    "T1110": ["failed logon", "failed login", "4625", "brute"],
    "T1078": ["successful logon", "4624", "valid account"],
    "T1003.001": ["lsass", "mimikatz", "procdump"],
}

_MITRE_NAMES = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1027": "Obfuscated Files or Information",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
}


class MockLLMProvider(LLMProvider):
    provider_name = "mock"
    model_name = "mock-soc-analyst-v1"

    def complete(self, *, system_prompt: str, user_prompt: str, prompt_template_version: str) -> LLMResponse:
        task = "unknown"
        m = re.search(r"TASK:\s*(\w+)", system_prompt)
        if m:
            task = m.group(1)

        if task == "severity":
            text = self._severity(user_prompt)
        elif task == "mitre":
            text = self._mitre(user_prompt)
        elif task == "report":
            text = self._report(user_prompt)
        else:
            text = json.dumps({"error": "unknown task"})

        return LLMResponse(
            text=text,
            provider=self.provider_name,
            model=self.model_name,
            prompt_template_version=prompt_template_version,
        )

    # -- task heuristics -----------------------------------------------
    def _severity(self, user_prompt: str) -> str:
        lowered = user_prompt.lower()
        malicious_hits = lowered.count("malicious")
        suspicious_hits = lowered.count("suspicious")
        high_rule_level = bool(re.search(r"rule_level[\"':\s]+(1[2-9]|[2-9]\d)", lowered))

        evidence_refs = re.findall(r"evidence_id=(\S+)", user_prompt)

        if malicious_hits >= 1 or high_rule_level:
            severity, conf = "high", 0.78
        elif suspicious_hits >= 2:
            severity, conf = "medium", 0.62
        elif suspicious_hits >= 1:
            severity, conf = "low", 0.55
        else:
            severity, conf = "low", 0.4

        rationale = (
            f"Derived from {malicious_hits} malicious-verdict enrichment result(s), "
            f"{suspicious_hits} suspicious-verdict result(s), and rule severity signals "
            f"present in the correlated events for this incident."
        )
        return json.dumps(
            {
                "severity": severity,
                "confidence": conf,
                "rationale": rationale,
                "evidence_refs": evidence_refs[:10] or ["no_evidence_refs_supplied"],
            }
        )

    def _mitre(self, user_prompt: str) -> str:
        lowered = user_prompt.lower()
        evidence_refs = re.findall(r"evidence_id=(\S+)", user_prompt)
        suggestions = []
        for tech_id, keywords in _MITRE_KEYWORDS.items():
            hits = [kw for kw in keywords if kw in lowered]
            if hits:
                confidence = min(0.5 + 0.12 * len(hits), 0.95)
                suggestions.append(
                    {
                        "technique_id": tech_id,
                        "technique_name": _MITRE_NAMES[tech_id],
                        "rationale": (
                            f"Matched keyword indicator(s) {hits} in the correlated event/enrichment data "
                            f"for this incident, consistent with {_MITRE_NAMES[tech_id]}."
                        ),
                        "confidence": round(confidence, 2),
                        "evidence_refs": evidence_refs[:5] or ["no_evidence_refs_supplied"],
                    }
                )
        return json.dumps({"suggestions": suggestions})

    def _report(self, user_prompt: str) -> str:
        evidence_refs = re.findall(r"evidence_id=(\S+)", user_prompt)
        return json.dumps(
            {
                "executive_summary": (
                    "AI-drafted summary based on correlated alerts, extracted IOCs, enrichment "
                    "verdicts, and MITRE ATT&CK technique suggestions for this incident. This is a "
                    "first draft only and requires analyst review before any action is taken."
                ),
                "severity_assessment": (
                    "See the incident's AI-suggested severity and its rationale/evidence; an analyst "
                    "must confirm or override this before it is treated as final."
                ),
                "sections": [
                    {
                        "heading": "Indicators of Compromise",
                        "body": "Extracted IOCs and their enrichment verdicts are listed in the incident's IOC table below, each with provider, verdict, confidence, and fetch timestamp.",
                        "evidence_refs": evidence_refs[:10] or ["no_evidence_refs_supplied"],
                    },
                    {
                        "heading": "MITRE ATT&CK Mapping",
                        "body": "See the MITRE suggestions attached to this incident, each with rationale and evidence references, pending analyst approval.",
                        "evidence_refs": evidence_refs[:10] or ["no_evidence_refs_supplied"],
                    },
                    {
                        "heading": "Recommended Next Steps (for analyst judgment, not automated action)",
                        "body": "Review the timeline and enrichment evidence, confirm or correct the suggested severity and MITRE techniques, and decide on response actions per your organization's playbook. This system does not take response actions automatically.",
                        "evidence_refs": [],
                    },
                ],
            }
        )
