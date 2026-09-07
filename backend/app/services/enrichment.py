"""
Enrichment orchestration: picks adapters for an IOC type, applies a simple
in-process TTL cache and a token-bucket rate limiter (per-process; a Redis
backend can replace this without changing the interface), and always stores
provider/verdict/confidence/evidence/fetched_at for provenance.
"""
import time
from collections import defaultdict, deque

from sqlalchemy.orm import Session

from app.adapters.base import ThreatIntelAdapter
from app.adapters.mock_abuseipdb import MockAbuseIPDBAdapter
from app.adapters.mock_virustotal import MockVirusTotalAdapter
from app.core.config import get_settings
from app.models.enrichment_result import EnrichmentResult
from app.models.ioc import IOC

settings = get_settings()

_cache: dict[tuple[str, str, str], tuple[float, object]] = {}
_rate_buckets: dict[str, deque] = defaultdict(deque)


def get_adapters() -> list[ThreatIntelAdapter]:
    adapters: list[ThreatIntelAdapter] = [MockVirusTotalAdapter(), MockAbuseIPDBAdapter()]

    if settings.ti_use_live_providers and settings.virustotal_api_key:
        from app.adapters.live_http_adapter import LiveVirusTotalAdapter

        adapters.append(LiveVirusTotalAdapter(api_key=settings.virustotal_api_key))

    return adapters


def _rate_limited(provider: str) -> bool:
    bucket = _rate_buckets[provider]
    now = time.monotonic()
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= settings.ti_rate_limit_per_minute:
        return True
    bucket.append(now)
    return False


def enrich_ioc(db: Session, ioc: IOC) -> list[EnrichmentResult]:
    results: list[EnrichmentResult] = []

    for adapter in get_adapters():
        if ioc.type not in adapter.supported_types:
            continue

        cache_key = (adapter.name, ioc.type.value, ioc.value)
        cached = _cache.get(cache_key)
        if cached and time.monotonic() - cached[0] < settings.ti_cache_ttl_seconds:
            outcome = cached[1]
        else:
            if _rate_limited(adapter.name):
                continue
            outcome = adapter.lookup(ioc.type, ioc.value)
            _cache[cache_key] = (time.monotonic(), outcome)

        result = EnrichmentResult(
            ioc_id=ioc.id,
            provider=outcome.provider,
            verdict=outcome.verdict,
            confidence=outcome.confidence,
            evidence=outcome.evidence,
            is_mocked=outcome.is_mocked,
        )
        db.add(result)
        results.append(result)

    db.flush()
    return results
