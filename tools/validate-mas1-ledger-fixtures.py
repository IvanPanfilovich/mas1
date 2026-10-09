#!/usr/bin/env python3
"""MAS1 v6 ledger fixture validator for schema and procedural checks."""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from jsonschema import Draft202012Validator
from mas1_ledger_core import validate_ledger


Case = Dict[str, Any]


def manifest_reasons(suite: Any) -> list[str]:
    """Check that every original V003 obligation is still executable.

    This is fixture-suite metadata validation only; semantic verdicts continue
    to come exclusively from ``validate_ledger`` below.
    """
    if not isinstance(suite, dict):
        return ["manifest_suite_not_object"]
    manifest = suite.get("legacy_requirement_manifest")
    cases = suite.get("cases")
    if not isinstance(manifest, dict) or not isinstance(cases, list):
        return ["manifest_missing"]
    entries = manifest.get("entries")
    if manifest.get("pinned_fixture_sha256") != "734c136be247ce67f9f30c81aecf287fc84ee18272c3594ea0636c651c3f9367":
        return ["manifest_pinned_hash"]
    if manifest.get("count") != 134 or not isinstance(entries, list) or len(entries) != 134 or len(cases) != 134:
        return ["manifest_count"]
    reasons: list[str] = []
    seen: set[str] = set()
    required = {"stable_id", "original_name", "original_base", "original_variant_if_present", "original_expected_valid",
                "original_expected_errors", "original_patch", "migrated_case_id", "representation_changes", "error_prefix_mapping"}
    for index, (entry, case) in enumerate(zip(entries, cases), start=1):
        stable_id = f"V003-{index:03d}"
        if not isinstance(entry, dict) or not required.issubset(entry):
            reasons.append(f"manifest_fields:{stable_id}"); continue
        if entry.get("stable_id") != stable_id or stable_id in seen:
            reasons.append(f"manifest_id:{stable_id}")
        seen.add(stable_id)
        if (entry.get("original_name"), entry.get("original_base"), entry.get("original_expected_valid"),
                entry.get("original_expected_errors"), entry.get("original_patch")) != (
                    case.get("name"), case.get("base"), case.get("expected_valid"), case.get("expected_errors"), case.get("patch")):
            reasons.append(f"manifest_case_mismatch:{stable_id}")
        if not isinstance(entry.get("error_prefix_mapping"), dict):
            reasons.append(f"manifest_error_mapping:{stable_id}")
        elif not case.get("expected_valid") and any(error not in entry["error_prefix_mapping"] for error in case.get("expected_errors", [])):
            reasons.append(f"manifest_error_mapping:{stable_id}")
    return sorted(set(reasons))


def _lexically_absolute_without_traversal(value: Any) -> bool:
    """Accept only a nonempty absolute path without a literal ``..`` part.

    This deliberately runs before normalization.  Normalizing first would turn
    a supplied traversal such as ``/workspace/../other`` into a harmless-looking
    path and make the ledger's path claim non-auditable.
    """
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return False
    try:
        path = Path(value)
    except (OSError, TypeError, ValueError):
        return False
    return path.is_absolute() and ".." not in path.parts


def canonical_task_path_reasons(task: Any) -> Set[str]:
    """Validate the lexical canonical paths shared by fixtures and analysis.

    The paths are checked lexically rather than through ``resolve`` so a
    traversal component or symlink cannot be hidden by normalization.  Filesystem
    identity and no-symlink checks are a separate production-analyzer concern.
    """
    reasons: Set[str] = set()
    if not isinstance(task, dict):
        return {"task_invalid"}
    task_id = task.get("task_instance_id")
    try:
        if not isinstance(task_id, str) or str(uuid.UUID(task_id)) != task_id:
            reasons.add("task_instance_uuid")
    except (AttributeError, ValueError, TypeError):
        reasons.add("task_instance_uuid")

    workspace = task.get("workspace")
    if not _lexically_absolute_without_traversal(workspace):
        reasons.add("task_workspace_path_invalid")
        if isinstance(workspace, str) and ".." in Path(workspace).parts:
            reasons.add("path_traversal")
        return reasons

    normalized_workspace = os.path.normpath(workspace)
    expected = {
        "ledger_path": os.path.join(
            normalized_workspace, ".mas1", "tasks", str(task_id), "finding-ledger.v1.json"
        ),
        "marker_path": os.path.join(
            normalized_workspace, ".mas1", "tasks", str(task_id), "v6-cutover.json"
        ),
    }
    for field, expected_path in expected.items():
        value = task.get(field)
        if not _lexically_absolute_without_traversal(value):
            reasons.add("task_path_absolute")
            if isinstance(value, str):
                try:
                    if ".." in Path(value).parts:
                        reasons.add("path_traversal")
                except (OSError, TypeError, ValueError):
                    pass
            reasons.add("task_path_template")
            continue
        normalized_value = os.path.normpath(value)
        if normalized_value != expected_path:
            reasons.add("task_path_template")
            try:
                if Path(normalized_value).parent.name != str(task_id):
                    reasons.add("task_path_parent_mismatch")
            except (OSError, TypeError, ValueError):
                reasons.add("task_path_parent_mismatch")
    return reasons


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "fixtures",
        nargs="?",
        default=str(
            Path(__file__).resolve().with_name("mas1-ledger-fixtures.json")
        ),
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_pointer(target: Any, pointer: str) -> List[Any]:
    if not pointer:
        return [target]
    if not pointer.startswith("/"):
        raise ValueError(f"JSON pointer must start with '/': {pointer}")
    if pointer == "/":
        return [target]
    parts = pointer.lstrip("/").split("/")
    out = target
    for part in parts:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(out, list):
            index = int(part)
            out = out[index]
        else:
            out = out[part]
    return out


def set_pointer(target: Any, pointer: str, value: Any) -> None:
    if pointer == "/":
        raise ValueError("cannot replace whole document via pointer")
    parts = pointer.lstrip("/").split("/")
    out = target
    for idx, raw_part in enumerate(parts):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if idx == len(parts) - 1:
            if isinstance(out, list):
                out[int(part)] = value
            else:
                out[part] = value
            return
        if isinstance(out, list):
            out = out[int(part)]
        else:
            out = out[part]


def apply_patch(document: Any, ops: Iterable[Dict[str, Any]]) -> Any:
    patched = copy.deepcopy(document)
    for op in ops:
        operation = op.get("op")
        if operation not in {"replace", "add", "remove"}:
            raise ValueError(f"Unsupported patch op '{operation}'. Only replace, add, and remove are supported.")
        path = op.get("path")
        if not isinstance(path, str):
            raise ValueError("Patch op.path must be a string")
        if operation == "remove":
            if path == "/":
                raise ValueError("cannot remove whole document via pointer")
            parent_path, _, raw_part = path.rpartition("/")
            parent = resolve_pointer(patched, parent_path)
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if isinstance(parent, list):
                del parent[int(part)]
            else:
                del parent[part]
            continue
        if operation == "add" and path.endswith("/-"):
            parent = resolve_pointer(patched, path[:-2])
            if not isinstance(parent, list):
                raise ValueError("add /- requires an array parent")
            parent.append(op["value"])
        else:
            set_pointer(patched, path, op["value"])
    return patched


def replace_ids(value: Any, mapping: Dict[str, str]) -> Any:
    """Copy a fixture entity while changing only its stable identifiers."""
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [replace_ids(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: replace_ids(item, mapping) for key, item in value.items()}
    return value


def add_second_thresholded_root(ledger: Dict[str, Any]) -> Dict[str, Any]:
    """Create a second fully independent post-threshold causal family.

    The base fixture contains one historical escape plus one post-cutover escape.
    Duplicating every causal entity (rather than merely another root row) proves
    that the Astra successor gate is evaluated per root, not globally.
    """
    mapping = {
        "root-closed-001": "root-threshold-002",
        "obs-closed-001": "obs-threshold-002",
        "obs-escape-001": "obs-escape-002",
        "basis-001": "basis-002",
        "cycle-intro-001": "cycle-intro-002",
        "cycle-fix-001": "cycle-fix-002",
        "cycle-post-repair-001": "cycle-post-repair-002",
        "cycle-unchanged-001": "cycle-unchanged-002",
        "test-repro-001": "test-repro-002",
        "test-exact-001": "test-exact-002",
        "test-sibling-001": "test-sibling-002",
        "evt-baseline-001": "evt-baseline-002",
        "repair-001": "repair-002",
        "repair-old": "repair-old-002",
        "strategy-001": "strategy-002",
        "strategy-old": "strategy-old-002",
        "act-intro-001": "act-intro-002",
        "act-fix-001": "act-fix-002",
        "act-review-001": "act-review-002",
        "act-unchanged-001": "act-unchanged-002",
        "act-astr-001": "act-astr-002",
        "act-test-001": "act-test-002",
        "act-fix-successor": "act-fix-successor-002",
        "evt-open-001": "evt-open-002",
        "evt-confirm-001": "evt-confirm-002",
        "evt-fix-001": "evt-fix-002",
        "evt-pending-001": "evt-pending-002",
        "evt-closed-001": "evt-closed-002",
        "evt-escape-001": "evt-escape-002",
        "evt-astra-001": "evt-astra-002",
        "evt-reopen-001": "evt-reopen-002",
    }
    second = copy.deepcopy(ledger)
    for collection in (
        "roots", "observations", "review_bases", "cycles", "test_evidence",
        "repair_attempts", "strategies", "activities", "events",
    ):
        copies = replace_ids(second[collection], mapping)
        if collection == "cycles":
            for entry in copies:
                entry["sequence"] += len(ledger[collection])
        elif collection == "events":
            for entry in copies:
                entry["sequence"] += len(ledger[collection])
        ledger[collection].extend(copies)
    ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
    ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])
    return ledger



# Semantic validation is intentionally core-owned.  This harness only builds
# fixture inputs, invokes validate_ledger, and reports expected outcomes.

def evaluate_fixture_case(
    case: Case,
    base_ledgers: Dict[str, Any],
    schema_validator: Draft202012Validator,
    suite_dir: Path,
) -> tuple[bool, List[str]]:
    name = case.get("name", "unnamed case")
    base_id = case.get("base")
    if base_id not in base_ledgers:
        return False, [f"missing_base:{base_id}"]

    patched_ledger = copy.deepcopy(base_ledgers[base_id])
    if case.get("variant") == "two-thresholded-roots":
        patched_ledger = add_second_thresholded_root(patched_ledger)
    patched_ledger = apply_patch(patched_ledger, case.get("patch", []))
    ledger = patched_ledger

    expected_valid = bool(case.get("expected_valid", False))
    expected_errors = set(case.get("expected_errors", []))
    ledger_path = case.get("ledger_path")

    # The fixture command deliberately has no semantic checker list.  Production
    # validation (schema first, then ordered causal rules) lives in the core.
    result = validate_ledger(ledger, schema_validator.schema)
    reasons = set(result.reasons)

    if not expected_valid and case.get("expect_schema_validation", True) is False:
        # Explicit bypass for a procedural-only fixture; none used in this suite.
        pass

    actual_ok = len(reasons) == 0
    if expected_valid:
        if not actual_ok:
            return False, sorted(reasons)
        return True, []

    if actual_ok:
        return False, ["unexpectedly_valid"]
    if expected_errors:
        missing = []
        for expected in expected_errors:
            matched = False
            for reason in reasons:
                if reason == expected or reason.startswith(f"{expected}:"):
                    matched = True
                    break
            if not matched:
                missing.append(expected)
        if missing:
            missing = sorted(missing)
            return False, [f"missing_expected_reason:{','.join(missing)}"] + sorted(reasons)
    return True, []


def main() -> int:
    args = parse_args()
    fixtures_path = Path(args.fixtures)
    suite = load_json(fixtures_path)
    manifest_errors = manifest_reasons(suite)
    if manifest_errors:
        print("Fixture manifest invalid:")
        for reason in manifest_errors:
            print(f"  - {reason}")
        return 1
    base_ledgers = suite["base_ledgers"]
    schema_path = Path(__file__).resolve().with_name("mas1-finding-ledger-v1.schema.json")
    schema = load_json(schema_path)

    print(f"Validating schema: {schema_path}")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    passed = 0
    failed = 0
    case_count = len(suite.get("cases", []))

    for idx, case in enumerate(suite.get("cases", []), start=1):
        ok, issues = evaluate_fixture_case(case, base_ledgers, validator, fixtures_path.parent)
        name = case.get("name", f"case-{idx:02d}")
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
            print(f"[{status}] {idx:02d}/{case_count}: {name}")
            continue
        failed += 1
        print(f"[{status}] {idx:02d}/{case_count}: {name}")
        for issue in issues[:6]:
            print(f"  - {issue}")
        if len(issues) > 6:
            print(f"  - ... {len(issues) - 6} more reasons")

    print(f"\nSummary: passed={passed} failed={failed} total={case_count}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
