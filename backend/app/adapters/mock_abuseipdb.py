"""Deterministic mock of an AbuseIPDB-style IP reputation lookup."""

import hashlib

from app.adapters.base import EnrichmentOutcome, ThreatIntelAdapter
from app.models.ioc import IOCType


class MockAbuseIPDBAdapter(ThreatIntelAdapter):
    name = "mock_abuseipdb"
    supported_types = {IOCType.ip}

    def lookup(self, ioc_type: IOCType, value: str) -> EnrichmentOutcome:
        digest = hashlib.sha256(f"abuseipdb:{value}".encode()).hexdigest()
        abuse_score = int(digest[:4], 16) % 101  # 0-100, mirrors AbuseIPDB's confidence score

        if abuse_score >= 75:
            verdict, confidence = "malicious", 0.7 + abuse_score / 500
        elif abuse_score >= 30:
            verdict, confidence = "suspicious", 0.5 + abuse_score / 400
        else:
            verdict, confidence = "benign", 0.65

        return EnrichmentOutcome(
            provider=self.name,
            verdict=verdict,
            confidence=round(min(confidence, 0.99), 2),
            evidence={
                "simulated_abuse_confidence_score": abuse_score,
                "simulated_total_reports": abuse_score // 5,
                "lookup_value": value,
                "note": "MOCKED response — deterministic hash-seeded, not a real AbuseIPDB call.",
            },
            is_mocked=True,
        )
