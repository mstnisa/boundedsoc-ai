"""
Lightweight ML prefilter (Module: ML Prefilter). A small RandomForestClassifier
scores each newly-ingested incident as "routine" or "needs_review" *before*
the expensive AI reasoning layer runs, so LLM calls can be skipped/deferred
for alerts that look like the same noisy patterns seen many times before.

Honesty, matching the mock-LLM-provider pattern already used elsewhere in
this repo: the model is trained on a small bundled SYNTHETIC dataset
(data/ml/triage_training_examples.json), not live customer traffic — stated
here, in the README, and in docs/business-value.md. A "routine" label never
removes or hides an incident: it's just deprioritized in the queue, and an
analyst can always request full AI analysis manually regardless of the label.
"""

import json
from functools import lru_cache
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.services import audit

MODEL_VERSION = "rf-v1-synthetic"
TRAINING_DATA_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "ml" / "triage_training_examples.json"
)

FEATURE_ORDER = [
    "alert_count",
    "distinct_hosts",
    "max_rule_level",
    "has_bruteforce_kw",
    "has_powershell_kw",
    "has_c2_kw",
]

_BRUTEFORCE_KW = ("failed logon", "failed login", "authentication failure", "multiple failed")
_POWERSHELL_KW = ("powershell", "-enc", "encodedcommand", "downloadstring", "invoke-expression")
_C2_KW = ("c2", "beacon", "malicious", "callback")


@lru_cache(maxsize=1)
def _get_model() -> RandomForestClassifier:
    payload = json.loads(TRAINING_DATA_PATH.read_text())
    X = [ex["features"] for ex in payload["examples"]]
    y = [ex["label"] for ex in payload["examples"]]
    clf = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
    clf.fit(X, y)
    return clf


def extract_features(incident: Incident) -> list[float]:
    alerts = incident.alerts
    events = incident.events
    hosts = {getattr(e, "source_host", None) for e in events if getattr(e, "source_host", None)}
    max_level = 0
    text_blob = []
    for a in alerts:
        raw = a.raw_payload or {}
        rule = raw.get("rule", {}) if isinstance(raw, dict) else {}
        try:
            max_level = max(max_level, int(rule.get("level", 0)))
        except (TypeError, ValueError):
            pass
        text_blob.append(json.dumps(raw).lower())
    blob = " ".join(text_blob)

    return [
        float(len(alerts)),
        float(len(hosts) or 1),
        float(max_level),
        1.0 if any(kw in blob for kw in _BRUTEFORCE_KW) else 0.0,
        1.0 if any(kw in blob for kw in _POWERSHELL_KW) else 0.0,
        1.0 if any(kw in blob for kw in _C2_KW) else 0.0,
    ]


def classify_incident(db: Session, incident: Incident, actor: str = "system") -> Incident:
    features = extract_features(incident)
    model = _get_model()
    label = model.predict([features])[0]
    proba = model.predict_proba([features])[0]
    confidence = float(max(proba))

    incident.ml_triage_label = label
    incident.ml_confidence = confidence
    incident.ml_model_version = MODEL_VERSION
    db.add(incident)

    audit.record(
        db,
        actor=f"ml:{MODEL_VERSION}",
        action="incident.ml_triage",
        target=f"incident:{incident.id}",
        reason=(
            f"Classified as '{label}' (confidence {confidence:.2f}) by the synthetic-trained ML "
            "prefilter — this only deprioritizes queue ordering, it never hides or drops the incident."
        ),
        details={"features": dict(zip(FEATURE_ORDER, features)), "model_version": MODEL_VERSION},
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return incident
