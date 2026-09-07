"""
Skeleton for a real (non-mocked) provider call, gated entirely behind
TI_USE_LIVE_PROVIDERS=true and a present API key. Not wired to any route by
default — see app.services.enrichment.get_adapters(). Included so the
adapter-pattern promise ("real-provider toggle via config") is a real,
inspectable code path rather than a stub comment, without ever making a
network call unless the operator explicitly opts in and supplies their own
key in .env.
"""

import httpx

from app.adapters.base import EnrichmentOutcome, ThreatIntelAdapter
from app.models.ioc import IOCType


class LiveVirusTotalAdapter(ThreatIntelAdapter):
    name = "virustotal"
    supported_types = {IOCType.ip, IOCType.domain, IOCType.hash_md5, IOCType.hash_sha1, IOCType.hash_sha256}

    def __init__(self, api_key: str):
        self._api_key = api_key

    def lookup(self, ioc_type: IOCType, value: str) -> EnrichmentOutcome:
        endpoint_map = {
            IOCType.ip: f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
            IOCType.domain: f"https://www.virustotal.com/api/v3/domains/{value}",
        }
        url = endpoint_map.get(ioc_type, f"https://www.virustotal.com/api/v3/files/{value}")

        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers={"x-apikey": self._api_key})
            resp.raise_for_status()
            payload = resp.json()

        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1

        if malicious / total > 0.15:
            verdict, confidence = "malicious", min(0.6 + malicious / total, 0.99)
        elif malicious > 0:
            verdict, confidence = "suspicious", 0.5
        else:
            verdict, confidence = "benign", 0.6

        return EnrichmentOutcome(
            provider=self.name,
            verdict=verdict,
            confidence=round(confidence, 2),
            evidence={"last_analysis_stats": stats, "vt_link": url},
            is_mocked=False,
        )
