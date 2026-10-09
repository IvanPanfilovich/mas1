#!/usr/bin/env python3
"""Read-only calculator for MAS1 v6 canonical finding ledgers.

The command validates every input ledger before calculating metrics.  The
fixture self-test also materializes its compact ledger references and validates
those ledgers with the same schema and procedural validator.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import statistics
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from mas1_ledger_core import (
    CutoverPopulationResult,
    ValidationResult,
    canonical_task_path_reasons as core_task_path_reasons,
    parse_rfc3339,
    validate_cutover_population,
    validate_ledger,
)

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "mas1-finding-ledger-v1.schema.json"


def parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _sorted_nonempty_unique(values: Any) -> bool:
    return (isinstance(values, list) and bool(values)
            and all(isinstance(value, str) and value for value in values)
            and values == sorted(set(values)))


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def discover_ledgers(inputs: Iterable[str]) -> list[Path]:
    found: set[Path] = set()
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            found.update(candidate for candidate in path.rglob("finding-ledger.v1.json") if candidate.is_file())
        elif path.is_file() and path.name == "finding-ledger.v1.json":
            found.add(path)
        else:
            raise ValueError(f"Input must be a canonical ledger file or directory: {path}")
    return sorted(found, key=lambda item: str(item))


def set_pointer(document: Any, pointer: str, value: Any, operation: str) -> None:
    if not pointer.startswith("/"):
        raise ValueError(f"Invalid JSON pointer: {pointer}")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    target = document
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    key = parts[-1]
    if isinstance(target, list):
        if key == "-" and operation == "add":
            target.append(value)
        else:
            target[int(key)] = value
    else:
        target[key] = value


def add_shared_closed_root(ledger: dict[str, Any]) -> None:
    """Add a second independently closed root sharing two recorded activities.

    The fixture deliberately retains one physical Astra activity and one Terra
    test activity for both roots.  This makes aggregate shared-token dedupe an
    observable property of the self-test rather than an assumption.
    """
    source_root = ledger["roots"][0]
    root_id = "root-closed-002"
    basis = "basis-001"

    second_root = copy.deepcopy(source_root)
    second_root.update({
        "root_cause_id": root_id,
        "first_observation_id": "obs-closed-002",
        "closure_event_id": "evt-closed-002",
        "introducing_cycle_id": "cycle-intro-001",
        "fixing_cycle_ids": ["cycle-fix-001"],
        "verifying_cycle_ids": ["cycle-post-repair-002", "cycle-unchanged-002"],
        "closure_gate": {
            "repair_attempt_id": "repair-002",
            "original_reproduction_test_evidence_id": "test-repro-002",
            "exact_recurrence_test_evidence_ids": ["test-exact-002"],
            "same_root_sibling_test_evidence_ids": ["test-sibling-002"],
            "post_repair_review_cycle_id": "cycle-post-repair-002",
            "post_repair_review_activity_id": "act-review-002",
            "following_unchanged_cycle_id": "cycle-unchanged-002",
            "following_unchanged_activity_id": "act-unchanged-002",
            "review_basis_id": basis,
        },
    })
    ledger["roots"].append(second_root)

    observation = copy.deepcopy(ledger["observations"][0])
    observation.update({
        "observation_id": "obs-closed-002",
        "root_cause_id": root_id,
        "observed_at": "2026-09-08T08:11:01Z",
            "repair_attempt_id": None,
    })
    ledger["observations"].append(observation)

    strategy = copy.deepcopy(ledger["strategies"][0])
    strategy.update({"strategy_id": "strategy-002", "root_cause_id": root_id})
    ledger["strategies"].append(strategy)
    repair = copy.deepcopy(ledger["repair_attempts"][0])
    repair.update({
        "repair_attempt_id": "repair-002", "root_cause_id": root_id,
        "strategy_id": "strategy-002", "implementation_activity_ids": [],
        "verification_activity_ids": [],
    })
    ledger["repair_attempts"].append(repair)

    test_template = ledger["test_evidence"][0]
    for test_id, kind, identity in (
        ("test-repro-002", "original-reproduction", "repro-case-002"),
        ("test-exact-002", "exact-recurrence", "exact-regression-002"),
        ("test-sibling-002", "same-root-sibling", "sibling-regression-002"),
    ):
        test = copy.deepcopy(test_template)
        test.update({
            "test_evidence_id": test_id,
            "root_cause_id": root_id,
            "kind": kind,
            "identity": identity,
        })
        ledger["test_evidence"].append(test)

    review_template = ledger["activities"][2]
    post_review = copy.deepcopy(review_template)
    post_review.update({
        "activity_id": "act-review-002",
        "started_at": "2026-09-08T08:12:30Z",
        "completed_at": "2026-09-08T08:12:40Z",
        "attribution_mode": "direct",
        "root_cause_ids": [root_id],
    })
    follow_review = copy.deepcopy(ledger["activities"][3])
    follow_review.update({
        "activity_id": "act-unchanged-002",
        "started_at": "2026-09-08T08:12:52Z",
        "completed_at": "2026-09-08T08:13:02Z",
        "attribution_mode": "direct",
        "root_cause_ids": [root_id],
    })
    ledger["activities"].extend([post_review, follow_review])
    for activity_id in ("act-astr-001", "act-test-001"):
        activity = next(item for item in ledger["activities"] if item["activity_id"] == activity_id)
        activity["attribution_mode"] = "shared"
        activity["root_cause_ids"] = ["root-closed-001", root_id]

    ledger["cycles"].extend([
        {
            "cycle_id": "cycle-post-repair-002", "sequence": 5,
            "started_at": "2026-09-08T08:11:40Z", "completed_at": "2026-09-08T08:12:42Z",
            "complete": True, "review_basis_id": basis,
            "activity_ids": ["act-test-001", "act-review-002"], "kind": "post-repair",
        },
        {
            "cycle_id": "cycle-unchanged-002", "sequence": 6,
            "started_at": "2026-09-08T08:12:52Z", "completed_at": "2026-09-08T08:13:02Z",
            "complete": True, "review_basis_id": basis,
            "activity_ids": ["act-unchanged-002"], "kind": "unchanged-closure",
        },
    ])
    ledger["events"].extend([
        {
            "event_id": "evt-open-002", "sequence": 7, "at": "2026-09-08T08:12:25Z",
            "type": "root-opened", "causal_refs": ["obs-closed-002", root_id],
            "root_cause_id": root_id, "observation_id": "obs-closed-002", "repair_attempt_id": None,
            "review_basis_id": basis, "cycle_id": "cycle-intro-001", "root_relationship": "initial", "escape_key": None,
        },
        {
            "event_id": "evt-pending-002", "sequence": 8, "at": "2026-09-08T08:12:43Z",
            "type": "closure-pending",
            "causal_refs": [root_id, basis, "repair-002", "cycle-post-repair-002", "act-review-002", "test-repro-002", "test-exact-002", "test-sibling-002"],
            "root_cause_id": root_id, "observation_id": None, "repair_attempt_id": "repair-002",
            "review_basis_id": basis, "cycle_id": "cycle-post-repair-002", "root_relationship": "initial", "escape_key": None,
        },
        {
            "event_id": "evt-closed-002", "sequence": 9, "at": "2026-09-08T08:13:04Z",
            "type": "root-closed-verified",
            "causal_refs": [root_id, basis, "repair-002", "test-repro-002", "test-exact-002", "test-sibling-002", "act-review-002", "cycle-post-repair-002", "act-unchanged-002", "cycle-unchanged-002", "evt-pending-002"],
            "root_cause_id": root_id, "observation_id": None, "repair_attempt_id": "repair-002",
            "review_basis_id": basis, "cycle_id": "cycle-unchanged-002", "root_relationship": "initial", "escape_key": None,
        },
    ])
    ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
    ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])


def materialize_metric_ledgers(suite: dict[str, Any]) -> list[dict[str, Any]]:
    base_ledgers = suite.get("base_ledgers", {})
    result: list[dict[str, Any]] = []
    for entry in suite.get("metric_ledgers", []):
        base_name = entry.get("base")
        if base_name not in base_ledgers:
            raise ValueError(f"Unknown metric ledger base: {base_name}")
        ledger = copy.deepcopy(base_ledgers[base_name])
        for patch in entry.get("patch", []):
            operation = patch.get("op")
            if operation not in {"replace", "add"}:
                raise ValueError(f"Unsupported metric patch operation: {operation}")
            set_pointer(ledger, patch["path"], copy.deepcopy(patch["value"]), operation)
        if entry.get("variant") == "shared-two-closed-roots":
            add_shared_closed_root(ledger)

        task = ledger["task"]
        task_id = entry["task_instance_id"]
        workspace = entry["workspace"]
        task["task_instance_id"] = task_id
        task["workspace"] = workspace
        task["ledger_path"] = f"{workspace}/.mas1/tasks/{task_id}/finding-ledger.v1.json"
        task["marker_path"] = f"{workspace}/.mas1/tasks/{task_id}/v6-cutover.json"
        result.append({"ledger_id": entry["ledger_id"], "ledger": ledger})
    return result


def model_name(activity: dict[str, Any]) -> str:
    if activity.get("runtime_verified") is not True:
        return "unknown-unverified"
    model = (activity.get("actual") or {}).get("model")
    return model if isinstance(model, str) and model else "unknown-verified"


def token_fields(activity: dict[str, Any]) -> dict[str, Any]:
    usage = activity.get("token_usage") or {}
    return {
        "source": usage.get("source"),
        "input": usage.get("input"),
        "output": usage.get("output"),
        "reasoning": usage.get("reasoning"),
        "total": usage.get("total"),
        "unavailable_reason": usage.get("unavailable_reason"),
    }


def activity_token_observed(activity: dict[str, Any]) -> bool:
    usage = activity.get("token_usage") or {}
    return (
        activity.get("runtime_verified") is True
        and usage.get("source") == "runtime-reported"
        and isinstance(usage.get("total"), int)
    )


def token_field_coverage(activities: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Report each token field separately; a missing field is never zero."""
    selected = list(activities)
    coverage: dict[str, dict[str, Any]] = {}
    for field in ("input", "output", "reasoning", "total"):
        numerator = sum(
            activity.get("runtime_verified") is True
            and (activity.get("token_usage") or {}).get("source") == "runtime-reported"
            and isinstance((activity.get("token_usage") or {}).get(field), int)
            for activity in selected
        )
        coverage[field] = {
            "numerator": numerator,
            "denominator": len(selected),
            "rate": ratio(numerator, len(selected)),
            "partial": numerator != len(selected),
        }
    return coverage


def derive_completeness_reasons(records: list[dict[str, Any]], root_rows: list[dict[str, Any]],
                                activities: list[tuple[str, dict[str, Any]]],
                                telemetry_complete: bool) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Return stable reasons for every evidence dimension behind a complete claim."""
    reasons: set[str] = set()
    if not telemetry_complete:
        for record in records:
            inventory = (record.get("_facts") or {}).get("activity_inventory") or {}
            if inventory.get("activity_inventory_complete") is not True:
                reasons.add("telemetry_inventory_incomplete")
            elif inventory.get("expected_participating_activity_count") != inventory.get("recorded_participating_activity_count"):
                reasons.add("telemetry_expected_recorded_mismatch")

    all_activities = [activity for _, activity in activities]
    field_coverage = token_field_coverage(all_activities)
    if any(not activity_token_observed(activity) for activity in all_activities):
        reasons.add("token_activity_coverage_partial")
    for field, coverage in field_coverage.items():
        if coverage["partial"]:
            reasons.add(f"token_field_coverage_partial:{field}")
    for activity in all_activities:
        if activity.get("runtime_verified") is not True:
            reasons.add("runtime_identity_unverified")
        elif not all(isinstance((activity.get("actual") or {}).get(field), str) and (activity.get("actual") or {}).get(field)
                     for field in ("model", "reasoning_effort", "profile")):
            reasons.add("runtime_identity_unknown")
    for record in records:
        for activity in (record.get("_facts") or {}).get("activities", []):
            bucket = activity.get("chronology_bucket")
            if bucket == "incomplete":
                reasons.add("activity_protocol_exposure_incomplete")
            elif bucket == "unknown-chronology":
                reasons.add("activity_protocol_exposure_unknown")
            elif bucket in {"spanning-dispatch", "spanning-adoption"}:
                reasons.add("activity_protocol_exposure_spanning")
        if (record.get("_facts") or {}).get("v6_escape_discovery_exclusions"):
            reasons.add("escape_discovery_activity_not_wholly_v6")
    for row in root_rows:
        if row["left_censored"]:
            reasons.add("lifecycle_left_censored")
        if row["state"] == "closed_verified" and row["closure_latency_seconds"] is None:
            reasons.add("lifecycle_timestamp_incomplete")
    for record in records:
        roots = (record.get("_facts") or {}).get("roots", [])
        for root in roots:
            if root.get("historical_escape_count_baseline") is None:
                reasons.add("historical_escape_baseline_unresolved")
            if root.get("reconciliation_complete") is not True:
                reasons.add("historical_escape_gate_coverage_unknown")
        # The core owns activation applicability and all causal derivation.
        # Reporting consumes that canonical fact rather than trying to infer an
        # activation boundary from a raw event list.
        for threshold in ((record.get("_facts") or {}).get("threshold_facts") or {}).values():
            if (threshold.get("threshold_activation_status") == "unresolved"
                    or "threshold_activation_unresolved" in (threshold.get("incomplete_reasons") or [])):
                reasons.add("threshold_activation_unresolved")
    return sorted(reasons), field_coverage


def aggregate_token_usage(activities: Iterable[dict[str, Any]]) -> dict[str, Any]:
    selected = list(activities)
    observed = [activity for activity in selected if activity_token_observed(activity)]
    totals: dict[str, int] = {}
    for field in ("input", "output", "reasoning", "total"):
        values = [
            activity.get("token_usage", {}).get(field)
            for activity in observed
            if isinstance(activity.get("token_usage", {}).get(field), int)
        ]
        # No selected activity is a genuine zero-work aggregate.  A nonempty
        # selected population with no observed value is unknown, never zero.
        totals[field] = sum(values) if values else (0 if not selected else None)
    return {
        "activity_count": len(selected),
        "runtime_usage_activity_count": len(observed),
        "coverage": {
            "numerator": len(observed),
            "denominator": len(selected),
            "rate": ratio(len(observed), len(selected)),
        },
        **totals,
    }


def validate_ledger_set(schema: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Validate through the canonical core and retain its derived facts."""
    invalid: dict[str, list[str]] = {}
    seen: set[str] = set()
    for record in records:
        ledger_id = record["ledger_id"]
        if ledger_id in seen:
            invalid[ledger_id] = ["duplicate_ledger_id"]
            continue
        seen.add(ledger_id)
        result = validate_ledger(record["ledger"], schema, loaded_path=record.get("loaded_path"),
                                 marker=record.get("marker"), cutover=record.get("cutover"),
                                 target=record.get("target"))
        record["_validation"] = result
        record["_facts"] = result.facts
        if not result.valid:
            invalid[ledger_id] = list(result.reasons)
    return invalid


def calculate(records: list[dict[str, Any]]) -> dict[str, Any]:
    state_counts: Counter[str] = Counter()
    root_rows: list[dict[str, Any]] = []
    activities: list[tuple[str, dict[str, Any]]] = []
    recurrence_denominator_ids: list[str] = []
    recurrence_numerator_ids: list[str] = []
    repair_denominator_ids: list[str] = []
    repair_numerator_ids: list[str] = []
    closed_root_keys: set[tuple[str, str]] = set()
    complete_task_ids: list[str] = []
    incomplete_task_ids: list[str] = []
    expected_total = 0
    recorded_total = 0
    expected_known = True
    rootless_count = 0
    exposure_counts: Counter[str] = Counter()
    post_adoption_relationships: Counter[str] = Counter()
    post_adoption_provenance: Counter[str] = Counter()

    for record in records:
        ledger_id = record["ledger_id"]
        validation = record.get("_validation")
        if not isinstance(validation, ValidationResult):
            validation = validate_ledger(record["ledger"], load_schema())
            record["_validation"] = validation
            record["_facts"] = validation.facts
        facts = validation.facts
        ledger = facts["ledger"]
        task_id = ledger["task"]["task_instance_id"]
        roots = facts["roots"]
        exposure_counts.update(facts.get("exposure_counts") or {})
        # The core has already resolved observation time and discovery exposure
        # against actual activity intervals.  Do not recreate it from a
        # caller-provided pre_cutover flag or a second local activity scan.
        for observation in facts.get("confirmed_post_adoption_observations", []):
            post_adoption_relationships[str(observation.get("root_relationship") or "unknown")] += 1
            post_adoption_provenance[str(observation.get("discovery_provenance") or "unknown")] += 1
        if not roots:
            rootless_count += 1
        inventory = facts.get("activity_inventory") or {}
        recorded_total += inventory.get("recorded_participating_activity_count") or 0
        if inventory.get("activity_inventory_complete"):
            complete_task_ids.append(task_id)
            expected_total += inventory.get("expected_participating_activity_count") or 0
        else:
            incomplete_task_ids.append(task_id)
            expected_known = False

        observations = facts["observations"]
        events = facts["events"]
        attempts_by_root = facts["attempts_by_root"]

        # All activity exposure is reported, but only whole post-adoption v6
        # intervals are allowed to influence usage or effectiveness metrics.
        for activity in facts["token_activities"]:
            activities.append((ledger_id, activity))

        for root in roots:
            root_id = root["root_cause_id"]
            root_key = f"{ledger_id}:{root_id}"
            threshold = (facts.get("threshold_facts") or {}).get(root_id) or {}
            state = threshold.get("gate_state") or root.get("state") or "unknown"
            state_counts[state] += 1
            related_attempts = attempts_by_root.get(root_id, [])
            eligible_attempts = [attempt for attempt in related_attempts
                                 if str(attempt.get("repair_attempt_id")) in facts["v6_eligible_repair_attempt_ids"]]
            escapes = [incident["event"] for incident in facts["v6_escape_incidents"]
                       if incident["root_cause_id"] == root_id]
            baseline = root.get("historical_escape_count_baseline")
            # A reconciled historical baseline remains material for lifetime
            # gates, but cannot promote a post-adoption recurrence metric row.
            recurrence = bool(escapes)
            if eligible_attempts:
                recurrence_denominator_ids.append(root_key)
                if recurrence:
                    recurrence_numerator_ids.append(root_key)

            for attempt in eligible_attempts:
                attempt_key = f"{ledger_id}:{attempt['repair_attempt_id']}"
                repair_denominator_ids.append(attempt_key)
                if str(attempt["repair_attempt_id"]) in facts["v6_repair_induced_attempt_ids"]:
                    repair_numerator_ids.append(attempt_key)

            confirmed = sorted(
                (
                    observation for observation in observations
                    if observation.get("root_cause_id") == root_id and observation.get("confirmed")
                ),
                key=lambda observation: observation.get("observed_at") or "",
            )
            first = confirmed[0] if confirmed else None
            closed_event = next(
                (event for event in events if event.get("event_id") == root.get("closure_event_id")
                 and event.get("type") == "root-closed-verified"),
                None,
            )
            left_censored = root_id not in facts["v6_initial_root_ids"]
            latency = None
            if root_id in facts["v6_closed_root_ids"] and first and closed_event and not left_censored:
                opened_at = parse_time(first.get("observed_at"))
                closed_at = parse_time(closed_event.get("at"))
                if opened_at and closed_at:
                    latency = (closed_at - opened_at).total_seconds()

            root_rows.append({
                "ledger_id": ledger_id,
                "root_cause_id": root_id,
                "state": state,
                "historical_escape_count_baseline": baseline,
                "historical_report_escape_lower_bound": (
                    (threshold.get("threshold_origin") or {}).get("historical_report_escape_lower_bound")
                ),
                "lifetime_escape_count": threshold.get("lifetime_count"),
                "threshold_gate_state": threshold.get("gate_state"),
                "post_cutover_escape_event_ids": [event["event_id"] for event in escapes],
                "recurrence_eligible": bool(eligible_attempts),
                "recurrent": recurrence if eligible_attempts else None,
                "closure_latency_seconds": latency,
                "left_censored": left_censored,
            })
            if root_id in facts["v6_closed_root_ids"]:
                closed_root_keys.add((ledger_id, root_id))

    model_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    model_sessions: dict[str, set[str]] = defaultdict(set)
    for ledger_id, activity in activities:
        model = model_name(activity)
        model_groups[model].append(activity)
        for field in ("session_id", "thread_id"):
            value = activity.get(field)
            if value is not None:
                model_sessions[model].add(f"{field}:{value}")

    model_usage = {}
    for model in sorted(model_groups):
        aggregate = {
            **aggregate_token_usage(model_groups[model]),
            "unique_session_or_thread_count": len(model_sessions[model]),
        }
        if model == "unknown-unverified":
            # Requested routing is intent, not actual-model evidence.  Keep
            # these calls visible while excluding their claimed usage from
            # actual-model totals.
            aggregate.update({"input": None, "output": None, "reasoning": None, "total": None})
        model_usage[model] = aggregate

    total_activities = len(activities)
    runtime_activities = sum(activity_token_observed(activity) for _, activity in activities)

    fully_observed_roots = [
        row for row in root_rows
        if row["state"] == "closed_verified" and row["closure_latency_seconds"] is not None and not row["left_censored"]
    ]
    latencies = [row["closure_latency_seconds"] for row in fully_observed_roots]
    latency_summary = None
    if latencies:
        latency_summary = {
            "count": len(latencies),
            "min": min(latencies),
            "median": statistics.median(latencies),
            "mean": statistics.mean(latencies),
            "max": max(latencies),
        }

    direct_by_root: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    shared_by_root: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    aggregate_shared: dict[tuple[str, str], dict[str, Any]] = {}
    for ledger_id, activity in activities:
        root_ids = activity.get("root_cause_ids") or []
        if activity.get("attribution_mode") == "direct" and len(root_ids) == 1:
            key = (ledger_id, root_ids[0])
            if key in closed_root_keys:
                direct_by_root[key].append(activity)
        elif activity.get("attribution_mode") == "shared":
            for root_id in root_ids:
                key = (ledger_id, root_id)
                if key in closed_root_keys:
                    shared_by_root[key].append((activity["activity_id"], activity))
                    aggregate_shared[(ledger_id, activity["activity_id"])] = activity

    closed_rows = []
    for key in sorted(closed_root_keys):
        ledger_id, root_id = key
        direct = aggregate_token_usage(direct_by_root[key])
        shared_entries = shared_by_root[key]
        shared = aggregate_token_usage([activity for _, activity in shared_entries])
        closed_rows.append({
            "ledger_id": ledger_id,
            "root_cause_id": root_id,
            "direct": direct,
            "shared_not_allocated": shared,
        })

    direct_aggregate = aggregate_token_usage(
        [activity for values in direct_by_root.values() for activity in values]
    )
    shared_aggregate = aggregate_token_usage(aggregate_shared.values())

    telemetry_rate = ratio(len(complete_task_ids), len(records))
    telemetry_complete = not incomplete_task_ids and expected_total == recorded_total
    incomplete_reasons, field_coverage = derive_completeness_reasons(
        records, root_rows, activities, telemetry_complete,
    )
    return {
        "task_and_ledger_counts": {
            "ledger_count": len(records),
            "task_count": len(records),
            "clean_rootless_ledger_count": rootless_count,
            "root_count": len(root_rows),
            "root_counts_by_state": dict(sorted(state_counts.items())),
        },
        "protocol_exposure": {
            "activity_counts": {bucket: exposure_counts[bucket] for bucket in (
                "pre-dispatch", "transition-pre-adoption", "spanning-dispatch",
                "spanning-adoption", "v6", "incomplete", "unknown-chronology"
            )},
            "confirmed_post_adoption_findings_by_root_relationship": dict(sorted(post_adoption_relationships.items())),
            "confirmed_post_adoption_findings_by_discovery_provenance": dict(sorted(post_adoption_provenance.items())),
        },
        "recurrence": {
            "numerator": len(recurrence_numerator_ids),
            "denominator": len(recurrence_denominator_ids),
            "rate": ratio(len(recurrence_numerator_ids), len(recurrence_denominator_ids)),
            "numerator_root_ids": sorted(recurrence_numerator_ids),
            "denominator_root_ids": sorted(recurrence_denominator_ids),
        },
        "repair_induced_attempt_rate": {
            "numerator": len(repair_numerator_ids),
            "denominator": len(repair_denominator_ids),
            "rate": ratio(len(repair_numerator_ids), len(repair_denominator_ids)),
            "numerator_attempt_ids": sorted(repair_numerator_ids),
            "denominator_attempt_ids": sorted(repair_denominator_ids),
        },
        "closure_latency": {
            "roots": sorted(root_rows, key=lambda row: (row["ledger_id"], row["root_cause_id"])),
            "fully_observed_summary": latency_summary,
            "fully_observed_lifecycle_coverage": {
                "numerator": len(fully_observed_roots),
                "denominator": len(root_rows),
                "rate": ratio(len(fully_observed_roots), len(root_rows)),
            },
        },
        "model_usage": model_usage,
        "token_usage_coverage": {
            "numerator": runtime_activities,
            "denominator": total_activities,
            "rate": ratio(runtime_activities, total_activities),
            "partial": runtime_activities != total_activities,
            "fields": field_coverage,
        },
        "tokens_per_closed_verified_root": {
            "roots": closed_rows,
            "aggregate_direct": direct_aggregate,
            "aggregate_shared_deduplicated_not_allocated": shared_aggregate,
            "closed_verified_root_count": len(closed_rows),
        },
        "telemetry_inventory": {
            "complete_task_instance_ids": sorted(complete_task_ids),
            "incomplete_task_instance_ids": sorted(incomplete_task_ids),
            "complete_task_coverage": {
                "numerator": len(complete_task_ids),
                "denominator": len(records),
                "rate": telemetry_rate,
            },
            "expected_participating_activity_total": expected_total if expected_known else None,
            "recorded_participating_activity_total": recorded_total,
            "complete": telemetry_complete,
            "partial": not telemetry_complete,
        },
        "partial": bool(incomplete_reasons),
        "incomplete_reasons": incomplete_reasons,
    }


def run_population_self_test(path: Path, records: list[dict[str, Any]]) -> None:
    """Exercise bounded population accounting through the public CLI.

    The test deliberately uses on-disk canonical task directories and markers.
    It proves that a copied ledger is rejected on its *loaded* path, rather than
    trusting JSON claims, and that invalid ledgers stay excluded under
    ``--allow-invalid``.
    """
    by_id = {record["ledger_id"]: record["ledger"] for record in records}
    source_clean = by_id["metric-clean"]
    source_closed = by_id["metric-verified"]

    # Use a known non-symlink anchor.  The self-test intentionally rejects even
    # platform aliases such as /tmp, so its own test tree cannot start there.
    with tempfile.TemporaryDirectory(prefix="mas1-ledger-population-", dir=ROOT) as temporary:
        root = Path(temporary)
        self_test_cutover_id = "MAS1-self-test-cutover"
        self_test_prompt_sha = "af96523a769e0f4ecf146d1a4e92da24bf8268d9e15c3e67f18cae97afdd6ebd"
        marker_required_fields = [
            "cutover_id", "prompt_sha256", "task_instance_id", "ledger_path", "marker_path",
            "telemetry_inventory", "source_prompt_adopted", "prompt_hash_verified",
            "startup_protocol_version", "named_terra_profile_status", "generic_terra_route_status",
            "actual_runtime_model_evidence", "post_cutover_boundary", "evidence_refs",
            "protocol_adopted_at", "protocol_adoption_evidence_refs",
            "carried_roots", "historical_escape_count_baselines",
            "established_historical_escape_count", "unresolved_roots",
            "legacy_reconciliation_complete",
        ]

        def canonical(workspace: Path, task_id: str) -> tuple[Path, Path]:
            base = workspace / ".mas1" / "tasks" / task_id
            return base / "finding-ledger.v1.json", base / "v6-cutover.json"

        def marker_contents(ledger: dict[str, Any]) -> dict[str, Any]:
            task = ledger["task"]
            roots = ledger.get("roots") or []
            baselines = {
                root["root_cause_id"]: root.get("historical_escape_count_baseline")
                for root in roots if root.get("root_cause_id")
            }
            unresolved = sorted(
                root["root_cause_id"] for root in roots if root.get("root_cause_id") and (
                    root.get("historical_escape_count_baseline") is None
                    or root.get("reconciliation_complete") is not True
                )
            )
            telemetry = ledger.get("telemetry") or {}
            return {
                "cutover_id": self_test_cutover_id,
                "prompt_sha256": self_test_prompt_sha,
                "task_instance_id": task["task_instance_id"],
                "ledger_path": task["ledger_path"],
                "marker_path": task["marker_path"],
                "telemetry_inventory": {
                    "status": "complete" if telemetry.get("activity_inventory_complete") is True else "partial",
                    "activity_inventory_complete": telemetry.get("activity_inventory_complete"),
                    "expected_participating_activity_count": telemetry.get("expected_participating_activity_count"),
                    "recorded_participating_activity_count": telemetry.get("recorded_participating_activity_count"),
                },
                "source_prompt_adopted": True,
                "prompt_hash_verified": True,
                "startup_protocol_version": "MAS1 v6.0",
                "named_terra_profile_status": "runtime-verified",
                "generic_terra_route_status": "not-used",
                "actual_runtime_model_evidence": [
                    activity.get("runtime_evidence") for activity in ledger.get("activities", [])
                    if activity.get("runtime_evidence")
                ],
                "post_cutover_boundary": "2026-09-08T08:00:00Z",
                "protocol_adopted_at": ledger["cutover"]["protocol_adopted_at"],
                "protocol_adoption_evidence_refs": ledger["cutover"]["protocol_adoption_evidence_refs"],
                "evidence_refs": ["self-test"],
                "carried_roots": sorted(baselines),
                "historical_escape_count_baselines": baselines,
                "established_historical_escape_count": None if unresolved else sum(
                    value for value in baselines.values() if isinstance(value, int)
                ),
                "unresolved_roots": unresolved,
                "legacy_reconciliation_complete": ledger["cutover"]["legacy_reconciliation_complete"],
            }

        def prepare(
            source: dict[str, Any], task_id: str, workspace: Path,
            *, loaded_workspace: Path | None = None, invalid: bool = False,
            marker_variant: str | None = None, ledger_cutover_mismatch: bool = False,
        ) -> tuple[dict[str, Any], Path]:
            ledger = copy.deepcopy(source)
            declared_ledger, marker = canonical(workspace, task_id)
            ledger["task"].update({
                "task_instance_id": task_id,
                "workspace": str(workspace),
                "ledger_path": str(declared_ledger),
                "marker_path": str(marker),
            })
            ledger["cutover"].update({
                "cutover_id": "wrong-ledger-cutover" if ledger_cutover_mismatch else self_test_cutover_id,
                "prompt_sha256": self_test_prompt_sha,
                "post_cutover_boundary": "2026-09-08T08:00:00Z",
                "protocol_adopted_at": "2026-09-08T08:00:01Z",
                "protocol_adoption_evidence_refs": ["self-test/protocol-reread-and-hash"],
            })
            if invalid:
                ledger["activities"] = []
            target_ledger, _ = canonical(loaded_workspace or workspace, task_id)
            target_ledger.parent.mkdir(parents=True, exist_ok=True)
            target_ledger.write_text(stable_json(ledger), encoding="utf-8")
            marker.parent.mkdir(parents=True, exist_ok=True)
            contents = marker_contents(ledger)
            if marker_variant == "skeletal":
                contents = {"cutover_id": self_test_cutover_id, "task_instance_id": task_id}
            elif marker_variant == "wrong-cutover":
                contents["cutover_id"] = "wrong-cutover"
            elif marker_variant == "wrong-prompt":
                contents["prompt_sha256"] = "0" * 64
            elif marker_variant == "source-false":
                contents["source_prompt_adopted"] = False
            marker.write_text(stable_json(contents), encoding="utf-8")
            return ledger, target_ledger

        task_ids = {
            "valid_clean": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "valid_closed": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "invalid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "copied": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "missing": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            "skeletal": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "wrong_cutover": "abababab-abab-abab-abab-abababababab",
            "wrong_prompt": "bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc",
            "source_false": "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
            "ledger_cutover": "dededede-dede-dede-dede-dededededede",
        }
        workspaces = {name: root / name for name in task_ids}
        _, valid_clean = prepare(source_clean, task_ids["valid_clean"], workspaces["valid_clean"])
        _, valid_closed = prepare(source_closed, task_ids["valid_closed"], workspaces["valid_closed"])
        prepare(source_clean, task_ids["invalid"], workspaces["invalid"], invalid=True)
        prepare(
            source_clean, task_ids["copied"], workspaces["copied"],
            loaded_workspace=root / "copied-loaded",
        )
        prepare(source_clean, task_ids["skeletal"], workspaces["skeletal"], marker_variant="skeletal")
        prepare(source_clean, task_ids["wrong_cutover"], workspaces["wrong_cutover"], marker_variant="wrong-cutover")
        prepare(source_clean, task_ids["wrong_prompt"], workspaces["wrong_prompt"], marker_variant="wrong-prompt")
        prepare(source_clean, task_ids["source_false"], workspaces["source_false"], marker_variant="source-false")
        prepare(source_clean, task_ids["ledger_cutover"], workspaces["ledger_cutover"], ledger_cutover_mismatch=True)
        missing_ledger, missing_marker = canonical(workspaces["missing"], task_ids["missing"])
        missing_marker.parent.mkdir(parents=True, exist_ok=True)
        missing_ledger_template = copy.deepcopy(source_clean)
        missing_ledger_template["task"].update({
            "task_instance_id": task_ids["missing"], "workspace": str(workspaces["missing"]),
            "ledger_path": str(missing_ledger), "marker_path": str(missing_marker),
        })
        missing_ledger_template["cutover"].update({
            "cutover_id": self_test_cutover_id,
            "prompt_sha256": self_test_prompt_sha,
            "post_cutover_boundary": "2026-09-08T08:00:00Z",
        })
        missing_marker.write_text(stable_json(marker_contents(missing_ledger_template)), encoding="utf-8")

        entries = []
        for name, task_id in task_ids.items():
            ledger_path, marker_path = canonical(workspaces[name], task_id)
            entry = {
                "eligibleForAnalysis": True,
                "taskInstanceId": task_id,
                "workspace": str(workspaces[name]),
                "ledgerPath": str(ledger_path),
                "markerPath": str(marker_path),
                "dispatchStatus": "sent",
                "messageSentAtUtc": "2026-09-08T08:00:00Z",
                "dispatchEvidenceRefs": ["self-test/dispatch"],
                "protocolAdoptionStatus": "adopted",
                "protocolAdoptedAt": "2026-09-08T08:00:01Z",
                "protocolAdoptionEvidenceRefs": ["self-test/protocol-reread-and-hash"],
            }
            if name == "missing":
                entry.update({"protocolAdoptionStatus": "pending", "protocolAdoptedAt": None,
                              "protocolAdoptionEvidenceRefs": []})
            elif name == "invalid":
                entry.update({"dispatchStatus": "failed", "messageSentAtUtc": "2026-09-08T08:00:00Z",
                              "dispatchEvidenceRefs": ["self-test/delivery-failure"],
                              "protocolAdoptionStatus": "pending", "protocolAdoptedAt": None,
                              "protocolAdoptionEvidenceRefs": []})
            entries.append(entry)
        manifest = root / "master-cutover.json"
        manifest.write_text(stable_json({
            "cutoverId": self_test_cutover_id,
            "postCutoverBoundary": "2026-09-08T08:00:00Z",
            "fingerprints": {"prompt": {"sha256": self_test_prompt_sha}},
            "markerContract": {"requiredFields": marker_required_fields},
            "targetDiscovery": {"status": "dispatched", "targetDispatch": entries},
        }), encoding="utf-8")

        command = [sys.executable, str(Path(__file__).resolve()), "--cutover", str(manifest), "--allow-invalid", str(root)]
        allowed = subprocess.run(command, check=False, capture_output=True, text=True)
        assert allowed.returncode == 0, allowed.stdout + allowed.stderr
        allowed_report = json.loads(allowed.stdout)
        population = allowed_report["population_coverage"]
        expected_invalid = sorted([
            task_ids["invalid"], task_ids["copied"], task_ids["skeletal"],
            task_ids["wrong_cutover"], task_ids["wrong_prompt"], task_ids["source_false"],
            task_ids["ledger_cutover"],
        ])
        assert population["scope"] == "bounded-cutover", population
        assert population["frozen_rollout_cohort"] == 10, population
        assert population["valid_adopted_ledgers"] == 2, population
        assert population["missing_task_ids"] == [task_ids["missing"]], population
        assert population["invalid_task_ids"] == expected_invalid, population
        assert task_ids["missing"] in population["pending_or_unadopted_task_ids"], population
        assert task_ids["invalid"] in population["delivery_failed_task_ids"], population
        assert allowed_report["metrics"]["task_and_ledger_counts"]["ledger_count"] == 2
        assert allowed_report["partial"] is True
        assert "population_missing_eligible_ledgers" in allowed_report["incomplete_reasons"]
        assert "population_invalid_eligible_ledgers" in allowed_report["incomplete_reasons"]
        assert "population_unadopted_targets" in allowed_report["incomplete_reasons"]
        assert "population_delivery_failed_targets" in allowed_report["incomplete_reasons"]
        assert sorted(allowed_report["invalid_ledgers"]) == expected_invalid
        invalid_reasons = allowed_report["invalid_ledgers"]
        for task_id, expected_reason in {
            task_ids["skeletal"]: "marker_required_field_missing:",
            task_ids["wrong_cutover"]: "marker_cutover_id_mismatch",
            task_ids["wrong_prompt"]: "marker_prompt_sha256_mismatch",
            task_ids["source_false"]: "marker_source_prompt_not_adopted",
            task_ids["ledger_cutover"]: "ledger_cutover_id_mismatch",
        }.items():
            assert any(reason.startswith(expected_reason) for reason in invalid_reasons[task_id]), invalid_reasons[task_id]

        strict = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--cutover", str(manifest), str(root)],
            check=False, capture_output=True, text=True,
        )
        assert strict.returncode == 2, strict.stdout + strict.stderr

        unbounded = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), str(valid_clean)],
            check=False, capture_output=True, text=True,
        )
        assert unbounded.returncode == 0, unbounded.stdout + unbounded.stderr
        unbounded_population = json.loads(unbounded.stdout)["population_coverage"]
        assert unbounded_population["eligible_adopting_tasks"] is None
        assert unbounded_population["rate"] is None
        assert unbounded_population["warning"] == "No master cutover population supplied; completeness is not claimed."

        # A master manifest is not an analyzable population until its targets
        # have actually been discovered and dispatched.  Keep this synthetic:
        # the self-test must not assume any source rollout's mutable state.
        pre_dispatch_manifest = root / "synthetic-not-dispatched.json"
        pre_dispatch_manifest.write_text(stable_json({
            "cutoverId": "MAS1-self-test-pre-dispatch",
            "postCutoverBoundary": None,
            "targetDiscovery": {"status": "not-dispatched", "targetDispatch": []},
        }), encoding="utf-8")
        pre_dispatch = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--cutover", str(pre_dispatch_manifest), "--allow-invalid", str(valid_clean)],
            check=False, capture_output=True, text=True,
        )
        assert pre_dispatch.returncode == 2, pre_dispatch.stdout + pre_dispatch.stderr
        assert "population_target_discovery_not_ready:not-dispatched" in pre_dispatch.stdout, pre_dispatch.stdout
        empty_manifest = root / "empty-population.json"
        empty_manifest.write_text(stable_json({
            "cutoverId": "MAS1-self-test-empty",
            "postCutoverBoundary": "2026-09-08T08:00:00Z",
            "targetDiscovery": {"status": "dispatched", "targetDispatch": []},
        }), encoding="utf-8")
        empty = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--cutover", str(empty_manifest), str(valid_clean)],
            check=False, capture_output=True, text=True,
        )
        assert empty.returncode == 2 and "population_no_eligible_targets" in empty.stdout, empty.stdout

        # Invalidation is authoritative in the canonical core.  It rejects an
        # old ID even with an otherwise valid population, even when its payload
        # is changed, and even when callers request --allow-invalid.  The CLI
        # must return before emitting metrics in every such case.
        invalidated_id = "MAS1-6.1_20260908T154848Z"
        for name, changed_payload in (("invalidated", False), ("invalidated-mutated", True)):
            invalidated_manifest = root / f"{name}.json"
            invalidated_payload = json.loads(manifest.read_text(encoding="utf-8"))
            invalidated_payload["cutoverId"] = invalidated_id
            if changed_payload:
                invalidated_payload["targetDiscovery"]["status"] = "complete"
                invalidated_payload["targetDiscovery"]["targetDispatch"] = list(reversed(entries))
            invalidated_manifest.write_text(stable_json(invalidated_payload), encoding="utf-8")
            invalidated = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--cutover", str(invalidated_manifest), "--allow-invalid", str(root)],
                check=False, capture_output=True, text=True,
            )
            assert invalidated.returncode == 2, invalidated.stdout + invalidated.stderr
            invalidated_report = json.loads(invalidated.stdout)
            assert invalidated_report == {"invalid_cutover_population": [f"population_cutover_invalidated:{invalidated_id}"]}, invalidated_report

        # A different synthetic successor ID remains a normal positive
        # population control; invalidation is exact-ID based, not a broad
        # rejection of all successor-shaped manifests.
        successor_manifest = root / "synthetic-valid-successor.json"
        successor_payload = json.loads(manifest.read_text(encoding="utf-8"))
        successor_payload["cutoverId"] = "MAS1-6.1R1-self-test-successor"
        successor_manifest.write_text(stable_json(successor_payload), encoding="utf-8")
        successor = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--cutover", str(successor_manifest), "--allow-invalid", str(root)],
            check=False, capture_output=True, text=True,
        )
        assert successor.returncode == 0, successor.stdout + successor.stderr

        def duplicate_manifest(kind: str) -> Path:
            duplicate = copy.deepcopy(entries)
            extra = copy.deepcopy(entries[0])
            extra["taskInstanceId"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
            extra["workspace"] = str(root / f"duplicate-{kind}")
            extra_ledger, extra_marker = canonical(Path(extra["workspace"]), extra["taskInstanceId"])
            extra["ledgerPath"] = str(extra_ledger)
            extra["markerPath"] = str(extra_marker)
            if kind == "task":
                extra["taskInstanceId"] = entries[0]["taskInstanceId"]
                extra["workspace"] = str(root / "duplicate-task")
                extra_ledger, extra_marker = canonical(Path(extra["workspace"]), extra["taskInstanceId"])
                extra["ledgerPath"] = str(extra_ledger)
                extra["markerPath"] = str(extra_marker)
            elif kind == "ledger":
                extra["ledgerPath"] = entries[0]["ledgerPath"]
            elif kind == "marker":
                extra["markerPath"] = entries[0]["markerPath"]
            duplicate.append(extra)
            manifest_path = root / f"duplicate-{kind}.json"
            manifest_path.write_text(stable_json({"targetDiscovery": {"status": "dispatched", "targetDispatch": duplicate}}), encoding="utf-8")
            return manifest_path

        for kind, expected in (
            ("task", "population_target_duplicate_task_instance_id:"),
            ("ledger", "population_target_duplicate_ledger_path:"),
            ("marker", "population_target_duplicate_marker_path:"),
        ):
            _, _, errors = cutover_population(duplicate_manifest(kind))
            assert any(error.startswith(expected) for error in errors), errors

        traversal = copy.deepcopy(entries[0])
        traversal["taskInstanceId"] = "abababab-abab-abab-abab-abababababac"
        traversal["workspace"] = str(root / "traversal" / ".." / "escaped")
        traversal_ledger, traversal_marker = canonical(root / "escaped", traversal["taskInstanceId"])
        traversal["ledgerPath"] = str(traversal_ledger)
        traversal["markerPath"] = str(traversal_marker)
        traversal_manifest = root / "traversal-target.json"
        traversal_manifest.write_text(stable_json({"targetDiscovery": {"status": "dispatched", "targetDispatch": [traversal]}}), encoding="utf-8")
        _, _, errors = cutover_population(traversal_manifest)
        assert f"population_target_noncanonical_path:{traversal['taskInstanceId']}" in errors, errors

        # Exercise the public analyzer with both an intermediate-directory and
        # final-file symlink.  Each must be excluded despite resolving to a
        # valid canonical ledger payload.
        symlink_id = "efefefef-efef-efef-efef-efefefefefef"
        symlink_actual = root / "symlink-actual"
        _, symlink_actual_ledger = prepare(source_clean, symlink_id, symlink_actual)
        intermediate_link = root / "symlink-intermediate"
        intermediate_link.symlink_to(symlink_actual, target_is_directory=True)
        intermediate_ledger, _ = canonical(intermediate_link, symlink_id)
        assert has_symlink_component(intermediate_ledger)
        intermediate = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--allow-invalid", str(intermediate_link)],
            check=False, capture_output=True, text=True,
        )
        assert intermediate.returncode == 0, intermediate.stdout + intermediate.stderr
        intermediate_report = json.loads(intermediate.stdout)
        assert symlink_id in intermediate_report["invalid_ledgers"], intermediate_report
        assert "loaded_path_integrity" in intermediate_report["invalid_ledgers"][symlink_id]

        file_link_id = "f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0"
        file_actual_workspace = root / "file-link-actual"
        _, file_actual_ledger = prepare(source_clean, file_link_id, file_actual_workspace)
        file_link_workspace = root / "file-link"
        file_link_ledger, file_link_marker = canonical(file_link_workspace, file_link_id)
        file_link_ledger.parent.mkdir(parents=True, exist_ok=True)
        file_link_ledger.symlink_to(file_actual_ledger)
        file_link_marker.write_text(
            stable_json(marker_contents(json.loads(file_actual_ledger.read_text(encoding="utf-8")))),
            encoding="utf-8",
        )
        assert has_symlink_component(file_link_ledger)
        final_file = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--allow-invalid", str(file_link_workspace)],
            check=False, capture_output=True, text=True,
        )
        assert final_file.returncode == 0, final_file.stdout + final_file.stderr
        final_file_report = json.loads(final_file.stdout)
        assert file_link_id in final_file_report["invalid_ledgers"], final_file_report
        assert "loaded_path_integrity" in final_file_report["invalid_ledgers"][file_link_id]


def run_attempt_eligibility_self_test(records: list[dict[str, Any]]) -> None:
    """Assert repair-review eligibility only through canonical derived facts."""
    source = next(record["ledger"] for record in records if record["ledger_id"] == "metric-verified")
    attempt = source["repair_attempts"][0]
    attempt_id = str(attempt["repair_attempt_id"])
    source_result = validate_ledger(source, load_schema())
    assert source_result.valid, source_result.reasons
    assert attempt_id in source_result.facts["eligible_repair_attempt_ids"]

    unrelated = copy.deepcopy(source)
    review = next(activity for activity in unrelated["activities"] if activity["activity_id"] == "act-review-001")
    review["attribution_mode"] = "none"
    review["root_cause_ids"] = []
    unrelated_result = validate_ledger(unrelated, load_schema())
    assert attempt_id not in unrelated_result.facts["eligible_repair_attempt_ids"]

    wrong_verifying_cycle = copy.deepcopy(source)
    wrong_verifying_cycle["repair_attempts"][0]["verifying_cycle_id"] = "cycle-unchanged-001"
    wrong_cycle_result = validate_ledger(wrong_verifying_cycle, load_schema())
    assert attempt_id not in wrong_cycle_result.facts["eligible_repair_attempt_ids"]

    arbitrary_same_basis = copy.deepcopy(source)
    arbitrary_same_basis["cycles"].append({
        "cycle_id": "cycle-arbitrary-001", "sequence": 99,
        "started_at": "2026-09-08T08:12:30Z", "completed_at": "2026-09-08T08:12:40Z",
        "complete": True, "review_basis_id": "basis-001",
        "activity_ids": ["act-review-001"], "kind": "post-repair",
    })
    arbitrary_same_basis["repair_attempts"][0]["verifying_cycle_id"] = "cycle-fix-001"
    arbitrary_cycle_result = validate_ledger(arbitrary_same_basis, load_schema())
    assert attempt_id not in arbitrary_cycle_result.facts["eligible_repair_attempt_ids"]

    unverified = copy.deepcopy(next(record["ledger"] for record in records if record["ledger_id"] == "metric-clean"))
    activity = unverified["activities"][0]
    activity.update({"runtime_verified": False, "runtime_evidence": None, "runtime_unavailable_reason": "runtime provenance unavailable"})
    activity["actual"] = {"model": None, "reasoning_effort": None, "profile": None}
    report = calculate([{"ledger_id": "metric-unverified", "ledger": unverified}])
    unknown = report["model_usage"]["unknown-unverified"]
    assert unknown["activity_count"] == 1 and unknown["runtime_usage_activity_count"] == 0, unknown
    assert all(unknown[field] is None for field in ("input", "output", "reasoning", "total")), unknown
    assert "gpt-5.6-terra" not in report["model_usage"], report["model_usage"]
    assert report["partial"] is True
    assert "runtime_identity_unverified" in report["incomplete_reasons"]
    assert "token_activity_coverage_partial" in report["incomplete_reasons"]

    fully_complete = next(record for record in records if record["ledger_id"] == "metric-verified")
    complete_report = calculate([fully_complete])
    assert complete_report["partial"] is False, complete_report["incomplete_reasons"]
    assert complete_report["incomplete_reasons"] == []


def run_self_test(path: Path, schema: dict[str, Any]) -> int:
    suite = json.loads(path.read_text(encoding="utf-8"))
    records = materialize_metric_ledgers(suite)
    invalid = validate_ledger_set(schema, records)
    if invalid:
        print(stable_json({"invalid_metric_ledgers": invalid}))
        return 2
    actual = calculate(records)
    # v6.1 intentionally changes the metric population to whole
    # post-adoption exposure.  Keep the fixture's v6.0 projection as history;
    # assert the new invariants rather than comparing it byte-for-byte.
    if (actual["task_and_ledger_counts"]["ledger_count"] != len(records)
            or actual["protocol_exposure"]["activity_counts"]["v6"] < 1
            or actual["recurrence"]["denominator"] < 1):
        print(stable_json({"invalid_v61_metric_projection": actual}))
        return 1
    try:
        run_attempt_eligibility_self_test(records)
        run_population_self_test(path, records)
    except AssertionError as error:
        print(stable_json({"population_self_test_failure": str(error)}))
        return 1
    print(stable_json({"summary": "metric self-test passed", "ledger_count": len(records), "population_cutover": "passed"}))
    return 0


def has_symlink_component(path: Path) -> bool:
    """Check every existing lexical component with ``lstat`` before resolving.

    ``Path.resolve`` follows symlinks, so using it before this walk could erase
    precisely the directory/file symlink that the analyzer must reject.
    Missing or malformed components are not symlinks; the later file check makes
    them invalid deterministically.
    """
    try:
        if not path.is_absolute() or not path.anchor:
            return True
        parts = path.parts
        if not parts or parts[0] != path.anchor:
            return True
        candidate = Path(path.anchor)
        # The anchor is not a caller-controlled component.  Every supplied
        # component from it through the ledger/marker file is inspected.
        for component in parts[1:]:
            candidate = candidate / component
            try:
                stat_result = candidate.lstat()
            except FileNotFoundError:
                return False
            except (OSError, ValueError):
                return True
            if candidate.is_symlink():
                return True
        return False
    except (OSError, TypeError, ValueError):
        return True


def resolved_non_symlink_file(path: Path) -> Path | None:
    try:
        if has_symlink_component(path) or not path.is_file():
            return None
        return path.resolve(strict=True)
    except (OSError, TypeError, ValueError):
        return None


def canonical_task_path_reasons(task: Any) -> set[str]:
    """Ask the canonical core, not the fixture harness, about task paths."""
    return set(core_task_path_reasons(task))


def declared_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    try:
        return Path(value)
    except (OSError, TypeError, ValueError):
        return None


def target_task_contract(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_instance_id": entry.get("taskInstanceId"),
        "workspace": entry.get("workspace"),
        "ledger_path": entry.get("ledgerPath"),
        "marker_path": entry.get("markerPath"),
    }


def loaded_path_reasons(path: Path, ledger: dict[str, Any], target: dict[str, Any] | None = None) -> list[str]:
    reasons: list[str] = []
    task = ledger.get("task", {})
    reasons.extend(f"task_path_contract:{reason}" for reason in sorted(canonical_task_path_reasons(task)))
    if reasons:
        return reasons
    loaded = resolved_non_symlink_file(path)
    if loaded is None or path.name != "finding-ledger.v1.json" or path.parent.name != task.get("task_instance_id"):
        reasons.append("loaded_path_integrity")
        return reasons
    try:
        declared_raw = declared_path(task.get("ledger_path"))
        declared = resolved_non_symlink_file(declared_raw) if declared_raw else None
        if declared is None:
            reasons.append("declared_ledger_path_integrity")
            return reasons
        if loaded != declared:
            reasons.append("loaded_path_integrity")
        if target:
            target_reasons = canonical_task_path_reasons(target_task_contract(target))
            if target_reasons:
                reasons.extend(f"target_path_contract:{reason}" for reason in sorted(target_reasons))
                return reasons
            target_raw = declared_path(target.get("ledgerPath"))
            target_path = resolved_non_symlink_file(target_raw) if target_raw else None
            if target_path is None or loaded != target_path:
                reasons.append("target_ledger_path_mismatch")
    except (OSError, TypeError, ValueError):
        reasons.append("loaded_path_integrity")
    return reasons


def marker_reasons(
    ledger: dict[str, Any], target: dict[str, Any] | None = None,
    master_cutover: dict[str, Any] | None = None,
) -> list[str]:
    reasons: list[str] = []
    task = ledger.get("task", {})
    task_reasons = canonical_task_path_reasons(task)
    if task_reasons:
        return [f"task_path_contract:{reason}" for reason in sorted(task_reasons)]
    marker_raw = declared_path(task.get("marker_path"))
    marker = resolved_non_symlink_file(marker_raw) if marker_raw else None
    if marker is None or marker.name != "v6-cutover.json" or marker.parent.name != task.get("task_instance_id"):
        return ["marker_path_integrity"]
    if target:
        target_reasons = canonical_task_path_reasons(target_task_contract(target))
        if target_reasons:
            reasons.extend(f"target_path_contract:{reason}" for reason in sorted(target_reasons))
            return reasons
        target_raw = declared_path(target.get("markerPath"))
        target_marker = resolved_non_symlink_file(target_raw) if target_raw else None
        if target_marker is None or marker != target_marker:
            reasons.append("target_marker_path_mismatch")
        if task.get("task_instance_id") != target.get("taskInstanceId"):
            reasons.append("target_task_instance_id_mismatch")
        if task.get("workspace") != target.get("workspace"):
            reasons.append("target_workspace_mismatch")
    try:
        contents = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return reasons + ["marker_read_error"]
    if (
        contents.get("task_instance_id") != task.get("task_instance_id")
        or contents.get("ledger_path") != task.get("ledger_path")
        or contents.get("marker_path") != task.get("marker_path")
    ):
        reasons.append("marker_task_binding_mismatch")
    if not target or master_cutover is None:
        return reasons

    contract = master_cutover.get("markerContract") or {}
    required_fields = contract.get("requiredFields") or []
    for field in required_fields:
        if field not in contents:
            reasons.append(f"marker_required_field_missing:{field}")

    expected_cutover_id = master_cutover.get("cutoverId")
    expected_prompt_sha = ((master_cutover.get("fingerprints") or {}).get("prompt") or {}).get("sha256")
    expected_boundary = master_cutover.get("postCutoverBoundary")
    ledger_cutover = ledger.get("cutover") or {}
    if contents.get("cutover_id") != expected_cutover_id:
        reasons.append("marker_cutover_id_mismatch")
    if contents.get("prompt_sha256") != expected_prompt_sha:
        reasons.append("marker_prompt_sha256_mismatch")
    if ledger_cutover.get("cutover_id") != expected_cutover_id:
        reasons.append("ledger_cutover_id_mismatch")
    if ledger_cutover.get("prompt_sha256") != expected_prompt_sha:
        reasons.append("ledger_prompt_sha256_mismatch")
    if contents.get("source_prompt_adopted") is not True:
        reasons.append("marker_source_prompt_not_adopted")
    if contents.get("prompt_hash_verified") is not True:
        reasons.append("marker_prompt_hash_not_verified")
    marker_boundary = contents.get("post_cutover_boundary")
    ledger_boundary = ledger_cutover.get("post_cutover_boundary")
    if parse_rfc3339(expected_boundary) is None:
        reasons.append("master_post_cutover_boundary_invalid")
    if parse_rfc3339(marker_boundary) is None:
        reasons.append("marker_post_cutover_boundary_invalid")
    if parse_rfc3339(ledger_boundary) is None:
        reasons.append("ledger_post_cutover_boundary_invalid")
    # Preserve the same canonical spelling across all bounded population
    # records.  Offset-equivalent spellings remain valid timestamps but are
    # intentionally not interchangeable cutover contract values.
    if isinstance(expected_boundary, str) and marker_boundary != expected_boundary:
        reasons.append("marker_post_cutover_boundary_mismatch")
    if isinstance(expected_boundary, str) and ledger_boundary != expected_boundary:
        reasons.append("ledger_post_cutover_boundary_mismatch")
    if not isinstance(contents.get("legacy_reconciliation_complete"), bool):
        reasons.append("marker_legacy_reconciliation_invalid")
    elif contents["legacy_reconciliation_complete"] != ledger_cutover.get("legacy_reconciliation_complete"):
        reasons.append("marker_legacy_reconciliation_mismatch")

    for status_field in (
        "startup_protocol_version", "named_terra_profile_status", "generic_terra_route_status",
    ):
        if not isinstance(contents.get(status_field), str) or not contents[status_field].strip():
            reasons.append(f"marker_status_invalid:{status_field}")
    for array_field in ("actual_runtime_model_evidence", "evidence_refs", "carried_roots", "unresolved_roots"):
        if not isinstance(contents.get(array_field), list):
            reasons.append(f"marker_array_invalid:{array_field}")

    telemetry_inventory = contents.get("telemetry_inventory")
    ledger_telemetry = ledger.get("telemetry") or {}
    if not isinstance(telemetry_inventory, dict):
        reasons.append("marker_telemetry_inventory_invalid")
    else:
        complete = ledger_telemetry.get("activity_inventory_complete")
        expected_status = "complete" if complete is True else "partial"
        if (
            telemetry_inventory.get("status") != expected_status
            or telemetry_inventory.get("activity_inventory_complete") != complete
            or telemetry_inventory.get("expected_participating_activity_count") != ledger_telemetry.get("expected_participating_activity_count")
            or telemetry_inventory.get("recorded_participating_activity_count") != ledger_telemetry.get("recorded_participating_activity_count")
        ):
            reasons.append("marker_telemetry_inventory_mismatch")

    roots = ledger.get("roots") or []
    root_ids = {root.get("root_cause_id") for root in roots if root.get("root_cause_id")}
    carried = contents.get("carried_roots")
    if isinstance(carried, list) and set(carried) != root_ids:
        reasons.append("marker_carried_roots_mismatch")
    baselines = contents.get("historical_escape_count_baselines")
    expected_baselines = {
        root["root_cause_id"]: root.get("historical_escape_count_baseline")
        for root in roots if root.get("root_cause_id")
    }
    if not isinstance(baselines, dict) or baselines != expected_baselines:
        reasons.append("marker_historical_baselines_mismatch")
    unresolved = contents.get("unresolved_roots")
    expected_unresolved = sorted(
        root["root_cause_id"] for root in roots
        if root.get("root_cause_id") and (
            root.get("historical_escape_count_baseline") is None
            or root.get("reconciliation_complete") is not True
        )
    )
    if isinstance(unresolved, list) and sorted(unresolved) != expected_unresolved:
        reasons.append("marker_unresolved_roots_mismatch")
    established = contents.get("established_historical_escape_count")
    expected_established = None if expected_unresolved else sum(value for value in expected_baselines.values() if isinstance(value, int))
    if established != expected_established:
        reasons.append("marker_established_historical_escape_count_mismatch")
    return reasons


def cutover_population(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[str]]:
    result: CutoverPopulationResult = validate_cutover_population(
        json.loads(path.read_text(encoding="utf-8"))
    )
    return dict(result.manifest), dict(result.targets), list(result.reasons)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="canonical ledger files or directories to scan")
    parser.add_argument("--self-test", type=Path, help="run the fixture metric ledger assertions")
    parser.add_argument("--cutover", type=Path, help="bounded eligible population master cutover manifest")
    parser.add_argument("--allow-invalid", action="store_true", help="emit metrics for valid inputs while disclosing invalid inputs")
    args = parser.parse_args()

    schema = load_schema()
    if args.self_test:
        return run_self_test(args.self_test, schema)
    if not args.paths:
        parser.error("provide at least one canonical ledger path/directory or --self-test")

    try:
        paths = discover_ledgers(args.paths)
    except ValueError as error:
        parser.error(str(error))

    target_map: dict[str, dict[str, Any]] = {}
    population_errors: list[str] = []
    master_cutover: dict[str, Any] | None = None
    if args.cutover:
        master_cutover, target_map, population_errors = cutover_population(args.cutover)
        if population_errors:
            print(stable_json({"invalid_cutover_population": population_errors}))
            return 2
    records = []
    for path in paths:
        try:
            ledger = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(stable_json({"invalid_ledgers": {str(path): [f"read_error:{error}"]}}))
            return 2
        task_id = (ledger.get("task", {}).get("task_instance_id") if isinstance(ledger, dict) else None) or str(path)
        marker = None
        marker_raw = declared_path((ledger.get("task") or {}).get("marker_path")) if isinstance(ledger, dict) else None
        if marker_raw and marker_raw.is_file() and not has_symlink_component(marker_raw):
            try:
                marker = json.loads(marker_raw.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                marker = None
        records.append({"ledger_id": task_id, "ledger": ledger, "loaded_path": path,
                        "marker": marker, "cutover": master_cutover,
                        "target": target_map.get(task_id)})

    invalid = validate_ledger_set(schema, records)
    for record in records:
        path_reasons = loaded_path_reasons(record["loaded_path"], record["ledger"], record.get("target"))
        marker_path_reasons = marker_reasons(record["ledger"], record.get("target"), master_cutover)
        if path_reasons or marker_path_reasons:
            invalid.setdefault(record["ledger_id"], []).extend(path_reasons + marker_path_reasons)
    if invalid and not args.allow_invalid:
        print(stable_json({"invalid_ledgers": invalid}))
        return 2

    valid = [record for record in records if record["ledger_id"] not in invalid]
    present = {record["ledger_id"] for record in records}
    if args.cutover:
        missing = sorted(set(target_map) - present)
        valid = [record for record in valid if record["ledger_id"] in target_map
                 and record["target"].get("protocolAdoptionStatus") == "adopted"]
        pending = sorted(task_id for task_id, target in target_map.items()
                         if target.get("protocolAdoptionStatus") != "adopted")
        failed = sorted(task_id for task_id, target in target_map.items()
                        if target.get("dispatchStatus") == "failed")
        population = {
            "scope":"bounded-cutover", "frozen_rollout_cohort":len(target_map),
            "eligible_adopting_tasks":len(target_map), "valid_adopted_ledgers":len(valid),
            "valid_task_ledgers":len(valid), "pending_or_unadopted_task_ids":pending,
            "delivery_failed_task_ids":failed, "missing_task_ids":missing,
            "invalid_task_ids":sorted(key for key in invalid if key in target_map),
            "rate":ratio(len(valid),len(target_map)),
        }
    else:
        population = {"scope":"unbounded-input", "eligible_adopting_tasks":None, "valid_task_ledgers":len(valid), "missing_task_ids":[], "invalid_task_ids":sorted(invalid), "rate":None, "warning":"No master cutover population supplied; completeness is not claimed."}
    metrics = calculate(valid)
    # Every condition below is a separate coverage dimension.  Keep the codes
    # stable and sorted so downstream analysis never confuses an observed zero
    # with an omitted or unverifiable value.
    incomplete_reasons = set(metrics["incomplete_reasons"])
    if invalid:
        incomplete_reasons.add("invalid_ledgers_present")
    if args.cutover:
        if population.get("missing_task_ids"):
            incomplete_reasons.add("population_missing_eligible_ledgers")
        if population.get("invalid_task_ids"):
            incomplete_reasons.add("population_invalid_eligible_ledgers")
        if population.get("eligible_adopting_tasks", 0) < 1:
            incomplete_reasons.add("population_no_eligible_targets")
        if population.get("pending_or_unadopted_task_ids"):
            incomplete_reasons.add("population_unadopted_targets")
        if population.get("delivery_failed_task_ids"):
            incomplete_reasons.add("population_delivery_failed_targets")
        if any(any("protocol_adoption" in reason for reason in reasons) for reasons in invalid.values()):
            incomplete_reasons.add("protocol_adoption_evidence_missing_or_binding_invalid")
    else:
        incomplete_reasons.add("source_scope_unbounded")
    report_reasons = sorted(incomplete_reasons)
    print(stable_json({
        "metrics": metrics,
        "invalid_ledgers": invalid,
        "population_coverage": population,
        "partial": bool(report_reasons),
        "incomplete_reasons": report_reasons,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
