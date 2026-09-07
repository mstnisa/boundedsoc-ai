#!/usr/bin/env python3
"""
Runs the measurement/benchmark plan against a LIVE backend (default
http://localhost:8000) over the hand-labeled synthetic cases in
data/eval/eval_cases.json, and writes real, measured results to
data/eval/benchmark_results.json and docs/benchmark_results.md.

This does NOT fabricate numbers. Every timing, accuracy, and rate figure
below is computed from actual HTTP calls made during this run. The one
number that is explicitly NOT measured here is human analyst time: no real
analysts were available to time a fully manual investigation, so the
"manual workflow" comparison uses a documented STEP COUNT (how many
distinct actions a human would have to perform) rather than a timed
duration, and that limitation is stated plainly in the output rather than
presented as a measured time-savings claim.

Usage:
    python scripts/benchmark.py [--base-url http://localhost:8000]
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
EVAL_CASES_PATH = REPO_ROOT / "data" / "eval" / "eval_cases.json"
RESULTS_JSON_PATH = REPO_ROOT / "data" / "eval" / "benchmark_results.json"
RESULTS_MD_PATH = REPO_ROOT / "docs" / "benchmark_results.md"

# Documented (not timed) manual-workflow step counts -- see module docstring.
# These represent the distinct manual actions a SOC analyst would take
# working the same case without this tool, based on the standard
# triage->enrich->map->report workflow described in the project brief.
MANUAL_STEPS_PER_CASE = {
    "read_and_triage_alert": 1,
    "manually_extract_iocs": 1,  # one pass through the raw log, regardless of IOC count
    "per_ioc_ti_lookup": "1 per IOC (each a separate console/tab)",
    "manual_mitre_mapping": 1,  # consult ATT&CK Navigator / documentation
    "manual_timeline_reconstruction": 1,
    "write_report_draft": 1,
    "peer_review_pass": 1,
}
ASSISTED_ANALYST_ACTIONS_PER_CASE = 6  # dashboard button clicks: extract, enrich, timeline, severity, mitre, report
# (ingest is automatic via the alert source / n8n trigger, not an analyst action)


def load_cases() -> list[dict]:
    data = json.loads(EVAL_CASES_PATH.read_text())
    return data["cases"]


def run_case(client: httpx.Client, case: dict) -> dict:
    case_id = case["case_id"]
    gt = case["ground_truth"]
    errors: list[str] = []
    timings: dict[str, float] = {}

    def timed_post(path: str, **kwargs) -> dict:
        t0 = time.perf_counter()
        resp = client.post(path, **kwargs)
        elapsed = time.perf_counter() - t0
        if resp.status_code >= 400:
            errors.append(f"{path} -> {resp.status_code}")
        return {"elapsed": elapsed, "status": resp.status_code, "body": resp.json() if resp.status_code < 400 else {}}

    def timed_get(path: str, **kwargs) -> dict:
        t0 = time.perf_counter()
        resp = client.get(path, **kwargs)
        elapsed = time.perf_counter() - t0
        if resp.status_code >= 400:
            errors.append(f"{path} -> {resp.status_code}")
        return {"elapsed": elapsed, "status": resp.status_code, "body": resp.json() if resp.status_code < 400 else {}}

    t_start = time.perf_counter()

    ingest = timed_post("/alerts", json=case["alert_bundle"])
    incident_id = ingest["body"].get("incident_id")
    timings["ingest"] = ingest["elapsed"]
    if not incident_id:
        return {"case_id": case_id, "error": "ingest_failed", "errors": errors}

    extract = timed_post(f"/incidents/{incident_id}/extract-iocs")
    timings["extract_iocs"] = extract["elapsed"]

    enrich = timed_post(f"/incidents/{incident_id}/enrich")
    timings["enrich"] = enrich["elapsed"]  # -> "IOC enrichment latency"

    timed_get(f"/incidents/{incident_id}/timeline")

    severity = timed_post(f"/incidents/{incident_id}/severity-suggestion")
    t_triage_done = time.perf_counter()
    timings["severity_suggestion"] = severity["elapsed"]
    time_to_triage = t_triage_done - t_start

    mitre = timed_post(f"/incidents/{incident_id}/mitre-suggestions")
    timings["mitre_suggestions"] = mitre["elapsed"]

    report = timed_post(f"/incidents/{incident_id}/report-draft")
    t_report_done = time.perf_counter()
    timings["report_draft"] = report["elapsed"]
    time_to_report_draft = t_report_done - t_start

    predicted_severity = severity["body"].get("severity") or "unknown"
    predicted_techniques = sorted({s["technique_id"] for s in mitre["body"].get("suggestions", [])})
    expected_techniques = sorted(set(gt["expected_mitre_techniques"]))

    tp_techniques = set(predicted_techniques) & set(expected_techniques)
    precision = len(tp_techniques) / len(predicted_techniques) if predicted_techniques else (1.0 if not expected_techniques else 0.0)
    recall = len(tp_techniques) / len(expected_techniques) if expected_techniques else (1.0 if not predicted_techniques else 0.0)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    predicted_malicious = predicted_severity in ("high", "critical") or len(predicted_techniques) > 0
    actual_malicious = gt["is_malicious"]
    if predicted_malicious and actual_malicious:
        confusion = "TP"
    elif predicted_malicious and not actual_malicious:
        confusion = "FP"
    elif not predicted_malicious and actual_malicious:
        confusion = "FN"
    else:
        confusion = "TN"

    severity_in_band = predicted_severity in gt["expected_severity_band"]

    return {
        "case_id": case_id,
        "incident_id": incident_id,
        "timings_seconds": timings,
        "time_to_triage_seconds": time_to_triage,
        "time_to_report_draft_seconds": time_to_report_draft,
        "predicted_severity": predicted_severity,
        "expected_severity_band": gt["expected_severity_band"],
        "severity_in_expected_band": severity_in_band,
        "predicted_mitre_techniques": predicted_techniques,
        "expected_mitre_techniques": expected_techniques,
        "mitre_precision": precision,
        "mitre_recall": recall,
        "mitre_f1": f1,
        "confusion_label": confusion,
        "api_errors": errors,
    }


def hallucination_and_drop_stats(client: httpx.Client) -> dict:
    resp = client.get("/audit-logs", params={"limit": 1000})
    resp.raise_for_status()
    logs = resp.json()
    suggest_actions = [l for l in logs if ".suggest" in l["action"] and not l["action"].endswith(".dropped")]
    dropped_actions = [l for l in logs if l["action"].endswith(".dropped")]
    total_attempts = len(suggest_actions) + len(dropped_actions)
    drop_rate = len(dropped_actions) / total_attempts if total_attempts else 0.0
    return {
        "total_ai_suggestion_attempts": total_attempts,
        "accepted_evidence_backed_suggestions": len(suggest_actions),
        "dropped_for_missing_or_hallucinated_evidence": len(dropped_actions),
        "drop_rate": drop_rate,
        "note": (
            "A 'drop' means a claim was rejected before ever reaching the database because it lacked a "
            "valid evidence_ref -- this is the guardrail working, not a hallucination that leaked "
            "through. With the default mock LLM provider, the drop rate is structurally 0% because the "
            "mock only ever echoes evidence_id tokens it was actually given (see "
            "tests/adversarial/test_prompt_injection.py for a test using a deliberately hallucinating "
            "provider, which confirms the drop path itself works)."
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()

    cases = load_cases()
    results = []
    total_requests = 0
    failed_requests = 0

    with httpx.Client(base_url=args.base_url, timeout=30) as client:
        health = client.get("/health")
        if health.status_code != 200:
            print(f"Backend not reachable at {args.base_url} (health check: {health.status_code})", file=sys.stderr)
            sys.exit(1)

        for case in cases:
            print(f"Running case: {case['case_id']} ...")
            result = run_case(client, case)
            results.append(result)

        stats = hallucination_and_drop_stats(client)

    valid_results = [r for r in results if "error" not in r]
    for r in valid_results:
        total_requests += 7  # ingest, extract, enrich, timeline, severity, mitre, report
        failed_requests += len(r["api_errors"])

    def agg(key):
        vals = [r[key] for r in valid_results]
        return {
            "mean": statistics.mean(vals) if vals else None,
            "median": statistics.median(vals) if vals else None,
            "min": min(vals) if vals else None,
            "max": max(vals) if vals else None,
        }

    confusion_counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for r in valid_results:
        confusion_counts[r["confusion_label"]] += 1

    n = len(valid_results)
    accuracy = (confusion_counts["TP"] + confusion_counts["TN"]) / n if n else None
    fpr = confusion_counts["FP"] / (confusion_counts["FP"] + confusion_counts["TN"]) if (confusion_counts["FP"] + confusion_counts["TN"]) else None
    fnr = confusion_counts["FN"] / (confusion_counts["FN"] + confusion_counts["TP"]) if (confusion_counts["FN"] + confusion_counts["TP"]) else None

    mitre_precisions = [r["mitre_precision"] for r in valid_results]
    mitre_recalls = [r["mitre_recall"] for r in valid_results]
    mitre_f1s = [r["mitre_f1"] for r in valid_results]

    summary = {
        "run_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backend_base_url": args.base_url,
        "n_cases": n,
        "time_to_triage_seconds": agg("time_to_triage_seconds"),
        "time_to_report_draft_seconds": agg("time_to_report_draft_seconds"),
        "ioc_enrichment_latency_seconds": {
            "mean": statistics.mean([r["timings_seconds"]["enrich"] for r in valid_results]) if valid_results else None,
        },
        "mitre_suggestion_accuracy": {
            "mean_precision": statistics.mean(mitre_precisions) if mitre_precisions else None,
            "mean_recall": statistics.mean(mitre_recalls) if mitre_recalls else None,
            "mean_f1": statistics.mean(mitre_f1s) if mitre_f1s else None,
        },
        "incident_classification_confusion_matrix": confusion_counts,
        "incident_classification_accuracy": accuracy,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "api_requests_total": total_requests,
        "api_requests_failed": failed_requests,
        "api_failure_rate": (failed_requests / total_requests) if total_requests else None,
        "hallucination_and_evidence_drop_stats": stats,
        "human_correction_rate": None,
        "human_correction_rate_note": (
            "NOT MEASURED. This requires real analysts using the review endpoint over time; no live "
            "analyst usage has occurred yet. The review/audit infrastructure to measure this "
            "(analyst_reviews.decision counts vs total AI suggestions) is implemented and ready -- see "
            "app.api.routes.incidents:submit_incident_review and GET /audit-logs -- but the number "
            "itself does not exist until real analysts generate it. Treat this as a roadmap item, not "
            "an omitted result."
        ),
        "manual_workflow_note": (
            "Manual-workflow figures are a DOCUMENTED STEP COUNT, not a timed duration -- no human "
            "analysts were available to time a fully manual investigation of these cases. See "
            "MANUAL_STEPS_PER_CASE and ASSISTED_ANALYST_ACTIONS_PER_CASE in this script. Do not read "
            "the numbers below as a measured time-savings claim."
        ),
        "manual_steps_per_case": MANUAL_STEPS_PER_CASE,
        "assisted_analyst_actions_per_case": ASSISTED_ANALYST_ACTIONS_PER_CASE,
    }

    output = {"summary": summary, "per_case_results": results}
    RESULTS_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_JSON_PATH.write_text(json.dumps(output, indent=2))

    write_markdown_report(output)
    print(f"\nWrote {RESULTS_JSON_PATH}")
    print(f"Wrote {RESULTS_MD_PATH}")


def write_markdown_report(output: dict):
    s = output["summary"]
    lines = [
        "# Benchmark Results (measured)",
        "",
        f"Run at `{s['run_timestamp_utc']}` against `{s['backend_base_url']}`, "
        f"over {s['n_cases']} hand-labeled synthetic cases (`data/eval/eval_cases.json`), "
        "using the default mocked TI providers and the mock LLM provider (`LLM_PROVIDER=mock`).",
        "",
        "**These are real measured numbers from an actual run of this script "
        "(`scripts/benchmark.py`) against a live backend -- not projections.**",
        "",
        "## Timing (assisted workflow, measured)",
        "",
        f"- Time-to-triage (ingest -> AI severity suggestion): "
        f"mean {s['time_to_triage_seconds']['mean']:.3f}s, "
        f"median {s['time_to_triage_seconds']['median']:.3f}s",
        f"- Time-to-report-draft (ingest -> AI report draft): "
        f"mean {s['time_to_report_draft_seconds']['mean']:.3f}s, "
        f"median {s['time_to_report_draft_seconds']['median']:.3f}s",
        f"- IOC enrichment latency (mocked TI adapters): "
        f"mean {s['ioc_enrichment_latency_seconds']['mean']:.3f}s",
        "",
        "These are local, single-process, mocked-provider timings (no real network TI calls, no real "
        "LLM API latency) -- they measure the orchestration/DB overhead of the pipeline itself, not "
        "what a live deployment with real providers would see.",
        "",
        "## MITRE ATT&CK suggestion accuracy (measured vs. hand-labeled ground truth)",
        "",
        f"- Mean precision: {s['mitre_suggestion_accuracy']['mean_precision']:.2f}",
        f"- Mean recall: {s['mitre_suggestion_accuracy']['mean_recall']:.2f}",
        f"- Mean F1: {s['mitre_suggestion_accuracy']['mean_f1']:.2f}",
        "",
        "## Incident-level classification (malicious vs. benign, vs. hand-labeled ground truth)",
        "",
        f"- Confusion matrix: {s['incident_classification_confusion_matrix']}",
        f"- Accuracy: {s['incident_classification_accuracy']:.2f}"
        if s["incident_classification_accuracy"] is not None
        else "- Accuracy: N/A",
        f"- False positive rate: {s['false_positive_rate']:.2f}" if s["false_positive_rate"] is not None else "- False positive rate: N/A",
        f"- False negative rate: {s['false_negative_rate']:.2f}" if s["false_negative_rate"] is not None else "- False negative rate: N/A",
        "",
        "*'Predicted malicious' = AI severity suggestion was high/critical OR at least one MITRE "
        "technique was suggested. This is a simple, transparent rule chosen for this benchmark -- it is "
        "not the product's own decision logic, which never auto-labels an incident at all (see the "
        "human-review requirement).*",
        "",
        "## API reliability",
        "",
        f"- Total API requests made during this run: {s['api_requests_total']}",
        f"- Failed (>=400) requests: {s['api_requests_failed']}",
        f"- Failure rate: {s['api_failure_rate']:.2%}" if s["api_failure_rate"] is not None else "- Failure rate: N/A",
        "",
        "## Evidence / hallucination guardrail stats",
        "",
        f"- Total AI suggestion attempts (severity + MITRE): "
        f"{s['hallucination_and_evidence_drop_stats']['total_ai_suggestion_attempts']}",
        f"- Accepted (evidence-backed): "
        f"{s['hallucination_and_evidence_drop_stats']['accepted_evidence_backed_suggestions']}",
        f"- Dropped (missing/hallucinated evidence): "
        f"{s['hallucination_and_evidence_drop_stats']['dropped_for_missing_or_hallucinated_evidence']}",
        f"- Drop rate: {s['hallucination_and_evidence_drop_stats']['drop_rate']:.2%}",
        "",
        s["hallucination_and_evidence_drop_stats"]["note"],
        "",
        "## What is explicitly NOT measured here",
        "",
        f"- **Human correction rate**: {s['human_correction_rate_note']}",
        f"- **Manual-workflow timing**: {s['manual_workflow_note']}",
        "",
        "## Manual (documented, unmeasured) vs. assisted (measured) step count",
        "",
        "| | Manual (documented estimate) | Assisted (this tool) |",
        "|---|---|---|",
        "| Analyst actions per case | read alert, extract IOCs by hand, "
        "one TI lookup per IOC, map to MITRE manually, reconstruct timeline manually, "
        "draft report, peer review = 6 fixed steps + 1 per IOC | "
        f"{s['assisted_analyst_actions_per_case']} fixed dashboard actions, regardless of IOC count |",
        "",
        "## Per-case detail",
        "",
        "| Case | Confusion | Severity (pred / expected band) | MITRE F1 | Time-to-report (s) |",
        "|---|---|---|---|---|",
    ]
    for r in output["per_case_results"]:
        if "error" in r:
            lines.append(f"| {r['case_id']} | ERROR | - | - | - |")
            continue
        lines.append(
            f"| {r['case_id']} | {r['confusion_label']} | "
            f"{r['predicted_severity']} / {r['expected_severity_band']} | "
            f"{r['mitre_f1']:.2f} | {r['time_to_report_draft_seconds']:.3f} |"
        )

    lines += [
        "",
        "---",
        "",
        "Re-run this benchmark yourself: `python scripts/benchmark.py` (backend must be running "
        "locally, e.g. via `docker-compose up`). Re-running overwrites this file with a fresh, "
        "equally-real measurement.",
    ]

    RESULTS_MD_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_MD_PATH.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
