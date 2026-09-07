"""
Deterministic mock of a VirusTotal-style lookup. Deterministic (hash-seeded)
so the same IOC always yields the same verdict across runs — useful for
reproducible tests and the benchmark in Phase H. No network calls, no key
required.
"""
import hashlib

from app.adapters.base import EnrichmentOutcome, ThreatIntelAdapter
from app.models.ioc import IOCType

_KNOWN_MALICIOUS_HINTS = ("evil", "malware", "c2", "phish", "badguy", "trojan")


class MockVirusTotalAdapter(ThreatIntelAdapter):
    name = "mock_virustotal"
    supported_types = {IOCType.ip, IOCType.domain, IOCType.url, IOCType.hash_md5, IOCType.hash_sha1, IOCType.hash_sha256}

    def lookup(self, ioc_type: IOCType, value: str) -> EnrichmentOutcome:
        digest = hashlib.sha256(f"{ioc_type.value}:{value}".encode()).hexdigest()
        score = int(digest[:4], 16) % 100  # deterministic pseudo-"engines flagged" score

        lowered = value.lower()
        forced_malicious = any(hint in lowered for hint in _KNOWN_MALICIOUS_HINTS)

        if forced_malicious or score >= 80:
            verdict, confidence = "malicious", 0.75 + (score % 20) / 100
        elif score >= 55:
            verdict, confidence = "suspicious", 0.5 + (score % 25) / 100
        else:
            verdict, confidence = "benign", 0.6 + (score % 30) / 100

        return EnrichmentOutcome(
            provider=self.name,
            verdict=verdict,
            confidence=round(min(confidence, 0.99), 2),
            evidence={
                "simulated_engines_flagged": score % 70,
                "simulated_engines_total": 70,
                "lookup_value": value,
                "lookup_type": ioc_type.value,
                "note": "MOCKED response — deterministic hash-seeded, not a real VirusTotal call.",
            },
            is_mocked=True,
        )
