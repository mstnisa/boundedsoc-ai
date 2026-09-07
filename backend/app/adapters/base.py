"""Adapter pattern for threat-intelligence providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.models.ioc import IOCType


@dataclass
class EnrichmentOutcome:
    provider: str
    verdict: str  # malicious | suspicious | benign | unknown
    confidence: float
    evidence: dict[str, Any]
    is_mocked: bool


class ThreatIntelAdapter(ABC):
    name: str
    supported_types: set[IOCType]

    @abstractmethod
    def lookup(self, ioc_type: IOCType, value: str) -> EnrichmentOutcome: ...
