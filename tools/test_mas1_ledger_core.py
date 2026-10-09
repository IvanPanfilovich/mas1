"""Regression tests for the single MAS1 v6 production validator."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta
from pathlib import Path

import mas1_ledger_core as ledger_core
from mas1_ledger_core import (
    INVALIDATED_CUTOVER_CATALOGUE,
    INVALIDATED_CUTOVER_CATALOGUE_VERSION,
    LEGACY_V6_0_AUDIT_AUTHORIZATION_SHA256,
    LEGACY_V6_0_AUDIT_CATALOGUE,
    LEGACY_V6_0_AUDIT_CATALOGUE_SHA256,
    LEGACY_V6_0_AUDIT_DECISION_SHA256,
    LEGACY_V6_0_AUDIT_DESCRIPTOR,
    LEGACY_V6_0_AUDIT_DESCRIPTOR_SHA256,
    LEGACY_V6_0_AUDIT_JUDGE_RESULT_SHA256,
    LEGACY_V6_0_AUDIT_MIGRATION_ID,
    HISTORICAL_REPORT_IMPORT_CATALOGUE,
    HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256,
    HISTORICAL_REPORT_IMPORT_ENTRY_ID,
    HISTORICAL_REPORT_IMPORT_EVENT_ID,
    HISTORICAL_REPORT_IMPORT_PAYLOADS,
    HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256,
    HISTORICAL_REPORT_ROOT_ID,
    HISTORICAL_REPORT_ROOT_OPENED_EVENT_ID,
    HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
    LegacyMigrationError,
    RULE_REGISTRY,
    ValidationResult,
    apply_legacy_v6_0_audit_migration,
    validate_cutover_population,
    validate_ledger,
    _lower_bound_binding_snapshot_ok,
    _modern_escape_incidents,
    _validation_context,
)

ROOT = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("mas1_ledger_analyzer", ROOT / "analyze-mas1-ledgers.py")
assert _SPEC is not None and _SPEC.loader is not None
analyzer = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(analyzer)
_RUNNER_SPEC = importlib.util.spec_from_file_location("mas1_fixture_runner", ROOT / "validate-mas1-ledger-fixtures.py")
assert _RUNNER_SPEC is not None and _RUNNER_SPEC.loader is not None
fixture_runner = importlib.util.module_from_spec(_RUNNER_SPEC)
_RUNNER_SPEC.loader.exec_module(fixture_runner)


class LedgerCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((ROOT / "mas1-finding-ledger-v1.schema.json").read_text())
        cls.suite = json.loads((ROOT / "mas1-ledger-fixtures.json").read_text())

    def base(self, name: str = "closed_root") -> dict:
        return copy.deepcopy(self.suite["base_ledgers"][name])

    def r004_control(self, name: str = "S") -> dict:
        """Pure data controls for Repair 004; no validator behavior lives here."""
        ledger = self.base("baseline2_astra")
        root = ledger["roots"][0]
        root.update({
            "state": "awaiting_post_repair_review", "previous_state": "repairing", "blocked_reason": None,
            "closure_event_id": None,
            "first_threshold_activation_event_id": "evt-activation-001",
        })
        # Preserve the original initial observation/escape lineage, but remove
        # synthetic closure/start history from the modern control.
        keep = {"evt-baseline-001", "evt-open-001", "evt-confirm-001", "evt-escape-001", "evt-reopen-001"}
        ledger["events"] = [item for item in ledger["events"] if item["event_id"] in keep]
        reservation = next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == "repair-001")
        reservation.update({
            "record_kind": "reservation", "created_at": "2026-09-08T08:13:39Z", "status": "planned",
            "started_at": None, "completed_at": None, "review_basis_id": "basis-001",
            "authorization_basis_id": "basis-001", "authorization_epoch_event_id": "evt-activation-001",
            "authorization_event_id": None, "expected_authorization_event_id": "evt-astra-001",
            "reservation_event_id": "evt-reservation-001",
            "implementation_activity_ids": ["act-fix-successor"], "verification_activity_ids": [],
        })
        strategy = next(item for item in ledger["strategies"] if item["strategy_id"] == "strategy-001")
        strategy.update({"created_at": "2026-09-08T08:13:38Z", "threshold_event_id": "evt-escape-001"})
        astr = next(item for item in ledger["activities"] if item["activity_id"] == "act-astr-001")
        astr["actual"].update({"model": "gpt-6-astra", "reasoning_effort": "xhigh"})
        implementation = next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor")
        implementation.update({
            "status": "completed", "started_at": "2026-09-08T08:13:52Z", "completed_at": "2026-09-08T08:13:58Z",
            "repair_attempt_id": "repair-001",
            "repair_attempt_bindings": [{"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-001"}],
        })
        def event(event_id: str, sequence: int, at: str, kind: str, **fields: object) -> dict:
            row = {"event_id": event_id, "sequence": sequence, "at": at, "type": kind,
                   "causal_refs": [], "root_cause_id": "root-closed-001", "observation_id": None,
                   "repair_attempt_id": None, "review_basis_id": None, "cycle_id": None,
                   "root_relationship": None, "escape_key": None}
            row.update(fields)
            return row
        ledger["events"].extend([
            event("evt-activation-001", 9, "2026-09-08T08:13:37Z", "threshold-activated",
                  causal_refs=["root-closed-001", "evt-escape-001"], activation_anchor_event_id="evt-escape-001",
                  first_threshold_known_at="2026-09-08T08:13:35Z", original_protocol_adopted_at="2026-09-08T07:59:00Z",
                  effective_at="2026-09-08T08:13:35Z", historical_baseline_reconciliation_event_id=None,
                  evidence_refs=["evt-escape-001"]),
            event("evt-reservation-001", 10, "2026-09-08T08:13:39Z", "repair-reserved",
                  causal_refs=["root-closed-001", "repair-001", "strategy-001", "basis-001"],
                  repair_attempt_id="repair-001", review_basis_id="basis-001", strategy_id="strategy-001",
                  reservation_event_id="evt-reservation-001", expected_authorization_event_id="evt-astra-001"),
            event("evt-astra-begin-001", 11, "2026-09-08T08:13:40Z", "astra-adjudication-started",
                  causal_refs=["root-closed-001", "repair-001", "strategy-001", "basis-001", "evt-activation-001", "act-astr-001"],
                  repair_attempt_id="repair-001", review_basis_id="basis-001", strategy_id="strategy-001",
                  adjudication_activity_id="act-astr-001"),
            event("evt-astra-001", 12, "2026-09-08T08:13:51Z", "astra-adjudicated",
                  causal_refs=["root-closed-001", "repair-001", "strategy-001", "basis-001", "evt-escape-001", "evt-activation-001", "act-astr-001", "evt-astra-begin-001"],
                  repair_attempt_id="repair-001", review_basis_id="basis-001", cycle_id="cycle-fix-001",
                  threshold_event_id="evt-escape-001", activation_anchor_event_id="evt-escape-001",
                  first_threshold_activation_event_id="evt-activation-001", decision_trigger_event_id="evt-escape-001",
                  authorization_epoch_event_id="evt-activation-001", authorization_basis_id="basis-001",
                  strategy_id="strategy-001", successor_strategy_id="strategy-001", adjudication_activity_id="act-astr-001",
                  adjudication_start_event_id="evt-astra-begin-001",
                  implementation_activity_ids=["act-fix-successor"], disposition="approved",
                  decision_evidence_refs=["evt-escape-001"]),
            event("evt-start-001", 13, "2026-09-08T08:13:52Z", "repair-attempted",
                  causal_refs=["root-closed-001", "repair-001", "strategy-001", "basis-001", "evt-astra-001", "act-fix-successor"],
                  repair_attempt_id="repair-001", review_basis_id="basis-001", cycle_id="cycle-fix-001",
                  strategy_id="strategy-001", authorization_basis_id="basis-001",
                  implementation_activity_ids=["act-fix-successor"],
                  started_at="2026-09-08T08:13:52Z", authorization_event_id="evt-astra-001"),
            event("evt-settlement-001", 14, "2026-09-08T08:14:00Z", "repair-threshold-settled",
                  causal_refs=["root-closed-001", "repair-001", "evt-start-001", "act-fix-successor", "basis-001"],
                  repair_attempt_id="repair-001", review_basis_id="basis-001", cycle_id="cycle-fix-001",
                  start_event_id="evt-start-001", terminal_outcome="succeeded", settled_at="2026-09-08T08:14:00Z",
                  mutation_finished_at="2026-09-08T08:13:58Z", decision_trigger_event_id="evt-escape-001",
                  authorization_epoch_event_id="evt-activation-001"),
        ])
        if name == "P":
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] not in {"evt-start-001", "evt-settlement-001"}]
            ledger["activities"] = [item for item in ledger["activities"] if item["activity_id"] != "act-fix-successor"]
            root.update({"state": "open", "previous_state": "blocked"})
        elif name == "A":
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] != "evt-settlement-001"]
            implementation.update({"status": "running", "completed_at": None})
            root.update({"state": "repairing", "previous_state": "open"})
        elif name == "W":
            ledger = self.r004_control("P")
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] not in {"evt-astra-001", "evt-astra-begin-001"}]
            ledger["activities"] = [item for item in ledger["activities"] if item["activity_id"] != "act-astr-001"]
            ledger["roots"][0].update({"state": "blocked", "previous_state": "open", "blocked_reason": "awaiting Astra", "block_code": "second-escape-astra-required"})
        elif name == "U":
            ledger = self.r004_control("W")
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] != "evt-activation-001"]
            ledger["roots"][0]["first_threshold_activation_event_id"] = None
        elif name == "B0":
            ledger = self.r004_control("W")
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] != "evt-activation-001"]
            ledger["roots"][0].update({
                "first_threshold_activation_event_id": None, "threshold_anchor": None,
                "historical_escape_count_baseline": None, "escape_count_lifetime": None,
                "reconciliation_complete": False, "block_code": "historical-baseline-unresolved",
                "blocked_reason": "historical baseline unresolved",
            })
        elif name in {"H0", "HS"}:
            ledger = self.r004_historical_control(executed=name == "HS")
        elif name == "T2":
            ledger = self.r004_two_root_control()
        ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
        ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])
        return ledger

    def r004_historical_control(self, *, executed: bool = False) -> dict:
        """H0/HS: canonical historical anchor, never prose-derived authority."""
        ledger = self.r004_control("W")
        root = ledger["roots"][0]
        ledger["events"] = [item for item in ledger["events"]
                            if item["event_id"] not in {"evt-escape-001", "evt-reopen-001", "evt-activation-001"}]
        ledger["observations"] = [item for item in ledger["observations"] if item["observation_id"] != "obs-escape-001"]
        root.update({
            "historical_escape_count_baseline": 2, "escape_count_lifetime": 2,
            "threshold_anchor": {"kind": "historical-baseline", "historical_threshold_reconciled_event_id": "evt-historical-001", "reconciled_baseline": 2},
            "historical_baseline_reconciliation_event_id": "evt-historical-001",
            "first_threshold_activation_event_id": "evt-activation-001", "state": "blocked",
            "previous_state": "open", "blocked_reason": "awaiting Astra", "block_code": "second-escape-astra-required",
        })
        ledger["cutover"]["protocol_adopted_at"] = "2026-09-08T08:13:35Z"
        historical = {
            "event_id": "evt-historical-001", "sequence": 7, "at": "2026-09-08T08:13:00Z",
            "type": "historical-threshold-reconciled", "causal_refs": ["root-closed-001"],
            "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None,
            "review_basis_id": None, "cycle_id": None, "root_relationship": None, "escape_key": None,
            "reconciled_baseline": 2, "evidence_refs": ["evt-baseline-001"],
        }
        activation = {
            "event_id": "evt-activation-001", "sequence": 8, "at": "2026-09-08T08:13:37Z",
            "type": "threshold-activated", "causal_refs": ["root-closed-001", "evt-historical-001"],
            "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None,
            "review_basis_id": None, "cycle_id": None, "root_relationship": None, "escape_key": None,
            "activation_anchor_event_id": "evt-historical-001", "first_threshold_known_at": "2026-09-08T08:13:00Z",
            "original_protocol_adopted_at": "2026-09-08T08:13:35Z", "effective_at": "2026-09-08T08:13:35Z",
            "historical_baseline_reconciliation_event_id": "evt-historical-001", "evidence_refs": ["evt-baseline-001"],
        }
        ledger["events"].extend([historical, activation])
        reservation = next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == "repair-001")
        reservation["authorization_epoch_event_id"] = "evt-activation-001"
        strategy = next(item for item in ledger["strategies"] if item["strategy_id"] == "strategy-001")
        strategy.update({"threshold_event_id": "evt-historical-001", "threshold_escape_event_id": None})
        if executed:
            source = self.r004_control("S")
            additions = [copy.deepcopy(item) for item in source["events"] if item["event_id"] in {"evt-astra-begin-001", "evt-astra-001", "evt-start-001", "evt-settlement-001"}]
            for event in additions:
                for key, value in list(event.items()):
                    if value == "evt-escape-001":
                        event[key] = "evt-historical-001"
                    elif isinstance(value, list):
                        event[key] = ["evt-historical-001" if item == "evt-escape-001" else item for item in value]
            ledger["events"].extend(additions)
            for activity_id in ("act-astr-001", "act-fix-successor"):
                ledger["activities"].append(copy.deepcopy(next(item for item in source["activities"] if item["activity_id"] == activity_id)))
            root.update({"state": "awaiting_post_repair_review", "previous_state": "repairing", "blocked_reason": None, "block_code": None})
        ledger["events"].sort(key=lambda item: item["sequence"])
        ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
        ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])
        return ledger

    def r004_two_root_control(self) -> dict:
        """T2 uses a fully disjoint shifted copy; only task/cutover are shared."""
        ledger = self.r004_control("S")
        collections = {
            "roots": "root_cause_id", "observations": "observation_id", "review_bases": "review_basis_id",
            "cycles": "cycle_id", "test_evidence": "test_evidence_id", "repair_attempts": "repair_attempt_id",
            "strategies": "strategy_id", "activities": "activity_id", "events": "event_id",
        }
        ids = {row[field] for collection, field in collections.items() for row in ledger[collection] if isinstance(row.get(field), str)}
        ids.add("repair-old")
        mapping = {value: (f"{value}-r2" if value == "repair-old" else value[:-3] + "002")
                   for value in ids if value.endswith("-001") or value == "repair-old"}
        mapping["act-fix-successor"] = "act-fix-successor-002"
        mapping["strategy-old"] = "strategy-old-002"

        def clone(value: object, key: str | None = None) -> object:
            if isinstance(value, dict):
                return {item_key: clone(item_value, item_key) for item_key, item_value in value.items()}
            if isinstance(value, list):
                return [clone(item, key) for item in value]
            if isinstance(value, str):
                if value in mapping:
                    return mapping[value]
                if key == "original_protocol_adopted_at":
                    return value
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is not None:
                        return (parsed + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
                except ValueError:
                    pass
            if key == "sequence" and isinstance(value, int):
                return value + 20
            return value

        for collection in collections:
            ledger[collection].extend(clone(row) for row in copy.deepcopy(ledger[collection]))
        ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
        ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])
        return ledger

    def r004_add_later_escape(self, ledger: dict, *, at: str = "2026-09-08T08:14:10Z") -> None:
        """Append a real same-root escape/reopen tuple after S succeeds."""
        root = ledger["roots"][0]
        observation = copy.deepcopy(next(item for item in ledger["observations"] if item["observation_id"] == "obs-escape-001"))
        observation.update({"observation_id": "obs-escape-002", "repair_attempt_id": "repair-001", "observed_at": at,
                            "detected_cycle_id": "cycle-fix-001", "fixing_cycle_id": "cycle-fix-001", "verifying_cycle_id": "cycle-post-repair-001"})
        ledger["observations"].append(observation)
        event = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-escape-001"))
        next_sequence = max(item["sequence"] for item in ledger["events"]) + 1
        event.update({"event_id": "evt-escape-002", "sequence": next_sequence, "at": at, "observation_id": "obs-escape-002",
                      "repair_attempt_id": "repair-001", "causal_refs": ["obs-escape-002", "repair-001", "cycle-fix-001", "basis-001", "root-closed-001"],
                      "escape_key": {"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-001", "review_basis_id": "basis-001", "cycle_id": "cycle-fix-001"}})
        reopen = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-reopen-001"))
        reopen.update({"event_id": "evt-reopen-002", "sequence": next_sequence + 1, "at": "2026-09-08T08:14:11Z", "observation_id": "obs-escape-002",
                       "repair_attempt_id": "repair-001",
                       "causal_refs": ["obs-escape-002", "evt-escape-002", "root-closed-001", "repair-001", "basis-001", "cycle-fix-001"]})
        ledger["events"].extend([event, reopen])
        root.update({"escape_count_lifetime": 3, "state": "blocked", "previous_state": "awaiting_post_repair_review",
                     "blocked_reason": "new escape requires Astra", "block_code": "second-escape-astra-required"})

    def r004_add_fresh_attempt(self, ledger: dict, *, suffix: str = "002", start: str = "2026-09-08T08:14:30Z", outcome: str | None = "succeeded") -> None:
        """Append a distinct, exact modern reservation/grant/start lifecycle."""
        root = ledger["roots"][0]
        activation_id = root["first_threshold_activation_event_id"]
        anchor_id = root["threshold_anchor"]["threshold_escape_event_id"]
        trigger = max((item for item in ledger["events"] if item["type"] == "escape-confirmed"), key=lambda item: item["sequence"])["event_id"]
        epoch = max((item for item in ledger["events"] if item["type"] in {"threshold-activated", "escape-confirmed", "basis-invalidated"}), key=lambda item: item["sequence"])["event_id"]
        repair, strategy, grant_id, astr_id, implementation_id = (f"repair-{suffix}", f"strategy-{suffix}", f"evt-astra-{suffix}", f"act-astr-{suffix}", f"act-fix-{suffix}")
        reservation = copy.deepcopy(next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == "repair-001"))
        reservation.update({"repair_attempt_id": repair, "strategy_id": strategy, "created_at": "2026-09-08T08:14:17Z",
                            "authorization_epoch_event_id": epoch, "expected_authorization_event_id": grant_id,
                            "reservation_event_id": f"evt-reservation-{suffix}",
                            "implementation_activity_ids": [implementation_id]})
        strategy_row = copy.deepcopy(next(item for item in ledger["strategies"] if item["strategy_id"] == "strategy-001"))
        strategy_row.update({"strategy_id": strategy, "created_at": "2026-09-08T08:14:18Z", "astra_adjudication_activity_id": astr_id,
                             "threshold_event_id": anchor_id, "threshold_escape_event_id": anchor_id,
                             "failed_predecessor_strategy_ids": ["strategy-001"]})
        astr = copy.deepcopy(next(item for item in ledger["activities"] if item["activity_id"] == "act-astr-001"))
        astr.update({"activity_id": astr_id, "started_at": "2026-09-08T08:14:20Z", "completed_at": "2026-09-08T08:14:25Z",
                     "causal_refs": [anchor_id, trigger, root["root_cause_id"]]})
        event_sequence = max(item["sequence"] for item in ledger["events"])
        reservation_event = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-reservation-001"))
        reservation_event.update({"event_id": f"evt-reservation-{suffix}", "sequence": event_sequence + 1, "at": "2026-09-08T08:14:17Z",
                                  "repair_attempt_id": repair, "strategy_id": strategy, "reservation_event_id": f"evt-reservation-{suffix}",
                                  "expected_authorization_event_id": grant_id,
                                  "causal_refs": [root["root_cause_id"], repair, strategy, "basis-001"]})
        begin = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-astra-begin-001"))
        begin.update({"event_id": f"evt-astra-begin-{suffix}", "sequence": event_sequence + 2, "at": "2026-09-08T08:14:20Z",
                      "repair_attempt_id": repair, "strategy_id": strategy, "adjudication_activity_id": astr_id,
                      "causal_refs": [root["root_cause_id"], repair, strategy, "basis-001", activation_id, astr_id]})
        grant = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-astra-001"))
        grant.update({"event_id": grant_id, "sequence": event_sequence + 3, "at": "2026-09-08T08:14:26Z", "repair_attempt_id": repair,
                      "strategy_id": strategy, "successor_strategy_id": strategy, "adjudication_activity_id": astr_id,
                      "implementation_activity_ids": [implementation_id], "threshold_event_id": anchor_id,
                      "activation_anchor_event_id": anchor_id, "first_threshold_activation_event_id": activation_id,
                      "decision_trigger_event_id": trigger, "authorization_epoch_event_id": epoch,
                      "adjudication_start_event_id": f"evt-astra-begin-{suffix}",
                      "causal_refs": list(dict.fromkeys([root["root_cause_id"], repair, strategy, "basis-001", anchor_id, activation_id, trigger, epoch, astr_id, f"evt-astra-begin-{suffix}"]))})
        start_event = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-start-001"))
        start_event.update({"event_id": f"evt-start-{suffix}", "sequence": event_sequence + 4, "at": start,
                            "repair_attempt_id": repair, "strategy_id": strategy, "authorization_basis_id": "basis-001",
                            "authorization_event_id": grant_id, "implementation_activity_ids": [implementation_id],
                            "started_at": start,
                            "causal_refs": [root["root_cause_id"], repair, strategy, "basis-001", grant_id, implementation_id]})
        implementation = copy.deepcopy(next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor"))
        implementation.update({"activity_id": implementation_id, "started_at": start, "completed_at": "2026-09-08T08:14:36Z",
                               "status": "completed", "repair_attempt_id": repair,
                               "repair_attempt_bindings": [{"root_cause_id": root["root_cause_id"], "repair_attempt_id": repair}]})
        ledger["repair_attempts"].append(reservation); ledger["strategies"].append(strategy_row)
        ledger["activities"].extend([astr, implementation]); ledger["events"].extend([reservation_event, begin, grant, start_event])
        if outcome is not None:
            settlement = copy.deepcopy(next(item for item in ledger["events"] if item["event_id"] == "evt-settlement-001"))
            settlement.update({"event_id": f"evt-settlement-{suffix}", "sequence": event_sequence + 5, "at": "2026-09-08T08:14:40Z",
                               "repair_attempt_id": repair, "start_event_id": f"evt-start-{suffix}", "terminal_outcome": outcome,
                               "settled_at": "2026-09-08T08:14:40Z", "mutation_finished_at": "2026-09-08T08:14:36Z",
                               "decision_trigger_event_id": trigger, "authorization_epoch_event_id": epoch,
                               "causal_refs": [root["root_cause_id"], repair, f"evt-start-{suffix}", implementation_id, "basis-001"]})
            ledger["events"].append(settlement)
            root.update({"state": "awaiting_post_repair_review" if outcome == "succeeded" else "blocked", "previous_state": "repairing",
                         "blocked_reason": None if outcome == "succeeded" else "terminal repair"})
        else:
            implementation.update({"status": "running", "completed_at": None})
            root.update({"state": "repairing", "previous_state": "open", "blocked_reason": None})
        ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
        ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])

    def r004_close_current_epoch(self, ledger: dict, *, suffix: str = "001", first_probe_time: str = "2026-09-08T08:14:02Z") -> None:
        """Append the complete, data-only modern closure epoch for the frontier."""
        root = ledger["roots"][0]
        repair = [item for item in ledger["repair_attempts"] if item.get("record_kind") == "reservation"][-1]
        repair_id = repair["repair_attempt_id"]
        basis = repair["review_basis_id"]
        def clone_activity(source_id: str, activity_id: str, kind: str, start: str, end: str) -> dict:
            row = copy.deepcopy(next(item for item in ledger["activities"] if item["activity_id"] == source_id))
            row.update({"activity_id": activity_id, "type": kind, "status": "completed", "started_at": start,
                        "completed_at": end, "repair_attempt_id": None, "repair_attempt_bindings": []})
            return row
        late = repair_id != "repair-001"
        starts = (["2026-09-08T08:14:42Z", "2026-09-08T08:14:44Z", "2026-09-08T08:14:46Z"] if late
                  else ["2026-09-08T08:14:02Z", "2026-09-08T08:14:04Z", "2026-09-08T08:14:06Z"])
        ends = (["2026-09-08T08:14:43Z", "2026-09-08T08:14:45Z", "2026-09-08T08:14:47Z"] if late
                else ["2026-09-08T08:14:03Z", "2026-09-08T08:14:05Z", "2026-09-08T08:14:07Z"])
        probe_activities = [clone_activity("act-test-001", f"act-probe-{kind}-{suffix}", "test", start, end)
                            for kind, start, end in zip(("original", "exact", "sibling"), starts, ends)]
        review = clone_activity("act-review-001", f"act-post-review-{suffix}", "post-repair-review", "2026-09-08T08:14:08Z", "2026-09-08T08:14:10Z")
        review.update({"review_route": "named-terra-first-pass", "fallback_reason": None})
        unchanged = clone_activity("act-unchanged-001", f"act-unchanged-review-{suffix}", "unchanged-followup-review", "2026-09-08T08:14:13Z", "2026-09-08T08:14:15Z")
        ledger["activities"].extend(probe_activities + [review, unchanged])
        test_ids = [f"test-modern-{kind}-{suffix}" for kind in ("original", "exact", "sibling")]
        ledger["test_evidence"].extend([
            {"test_evidence_id": test_id, "root_cause_id": root["root_cause_id"], "kind": kind,
             "identity": f"{kind}-modern-probe-{suffix}", "execution_activity_id": activity["activity_id"],
             "result": "pass", "executed_at": end, "review_basis_id": basis}
            for test_id, kind, activity, end in zip(test_ids, ("original-reproduction", "exact-recurrence", "same-root-sibling"), probe_activities, ends)
        ])
        post_start, post_end = ("2026-09-08T08:14:41Z", "2026-09-08T08:14:51Z") if late else ("2026-09-08T08:14:01Z", "2026-09-08T08:14:11Z")
        review["started_at"], review["completed_at"] = (("2026-09-08T08:14:48Z", "2026-09-08T08:14:50Z") if late else ("2026-09-08T08:14:08Z", "2026-09-08T08:14:10Z"))
        unchanged["started_at"], unchanged["completed_at"] = (("2026-09-08T08:14:53Z", "2026-09-08T08:14:55Z") if late else ("2026-09-08T08:14:13Z", "2026-09-08T08:14:15Z"))
        post_cycle = {"cycle_id": f"cycle-post-modern-{suffix}", "sequence": max(item["sequence"] for item in ledger["cycles"]) + 1, "started_at": post_start,
                      "completed_at": post_end, "complete": True, "review_basis_id": basis,
                      "activity_ids": [item["activity_id"] for item in probe_activities] + [review["activity_id"]], "kind": "post-repair"}
        following_cycle = {"cycle_id": f"cycle-unchanged-modern-{suffix}", "sequence": post_cycle["sequence"] + 1, "started_at": "2026-09-08T08:14:52Z" if late else "2026-09-08T08:14:12Z",
                           "completed_at": "2026-09-08T08:14:56Z" if late else "2026-09-08T08:14:16Z", "complete": True, "review_basis_id": basis,
                           "activity_ids": [unchanged["activity_id"]], "kind": "unchanged-closure"}
        ledger["cycles"].extend([post_cycle, following_cycle])
        gate = {"repair_attempt_id": repair_id, "original_reproduction_test_evidence_id": test_ids[0],
                "exact_recurrence_test_evidence_ids": [test_ids[1]], "same_root_sibling_test_evidence_ids": [test_ids[2]],
                "post_repair_review_cycle_id": post_cycle["cycle_id"], "post_repair_review_activity_id": review["activity_id"],
                "following_unchanged_cycle_id": following_cycle["cycle_id"], "following_unchanged_activity_id": unchanged["activity_id"],
                "review_basis_id": basis}
        def event(event_id: str, sequence: int, at: str, kind: str, **fields: object) -> dict:
            row = {"event_id": event_id, "sequence": sequence, "at": at, "type": kind, "causal_refs": [],
                   "root_cause_id": root["root_cause_id"], "observation_id": None, "repair_attempt_id": repair_id,
                   "review_basis_id": basis, "cycle_id": None, "root_relationship": None, "escape_key": None}
            row.update(fields); return row
        pending_id, closed_id = f"evt-pending-modern-{suffix}", f"evt-closed-modern-{suffix}"
        sequence = max(item["sequence"] for item in ledger["events"])
        pending_at, closed_at = (("2026-09-08T08:14:51Z", "2026-09-08T08:14:56Z") if late else ("2026-09-08T08:14:11Z", "2026-09-08T08:14:16Z"))
        ledger["events"].extend([
            event(pending_id, sequence + 1, pending_at, "closure-pending", cycle_id=post_cycle["cycle_id"],
                  causal_refs=[root["root_cause_id"], repair_id, basis, post_cycle["cycle_id"], review["activity_id"], *test_ids]),
            event(closed_id, sequence + 2, closed_at, "root-closed-verified", cycle_id=following_cycle["cycle_id"],
                  causal_refs=[root["root_cause_id"], repair_id, basis, following_cycle["cycle_id"], unchanged["activity_id"], pending_id, *test_ids]),
        ])
        root.update({"state": "closed_verified", "previous_state": "closure_pending", "closure_event_id": closed_id,
                     "closure_gate": gate, "verifying_cycle_ids": [post_cycle["cycle_id"], following_cycle["cycle_id"]]})
        ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
        ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])

    def test_fixture_base_uses_production_entry_point(self) -> None:
        result = validate_ledger(self.base(), self.schema)
        self.assertIsInstance(result, ValidationResult)
        self.assertTrue(result.valid, result.reasons)
        self.assertIn("escape_incidents", result.facts)
        self.assertIn("lifecycle_epochs", result.facts)

    def test_invalid_json_shaped_data_never_raises(self) -> None:
        for malformed in (None, [], "not-json", {"task": []}, {"activities": "bad"}):
            result = validate_ledger(malformed, self.schema)
            self.assertFalse(result.valid)
            self.assertTrue(result.reasons)

    def test_barrier2_diagnostics_are_guarded_and_nonauthoritative_on_failure(self) -> None:
        valid = validate_ledger(self.base("baseline2_astra"), self.schema)
        self.assertTrue(valid.facts["validation_context"]["authoritative"])
        self.assertIn("mutation_activity_ids", valid.facts["validation_context"])
        invalid = self.base("baseline2_astra")
        invalid["events"] = ["malformed"]
        result = validate_ledger(invalid, self.schema)
        self.assertFalse(result.valid)
        self.assertFalse(result.facts.get("validation_context", {}).get("authoritative", False))

    def test_ordered_registry_is_nonempty_and_stable(self) -> None:
        names = [rule.__name__ for rule in RULE_REGISTRY]
        self.assertEqual(names, sorted(names, key=names.index))
        self.assertIn("check_escape_binding_threshold", names)
        self.assertIn("check_basis_invalidation", names)
        self.assertNotIn("check_astra_adjudication_event_gate", names)

    def test_duplicate_escape_is_rejected_once_by_core(self) -> None:
        ledger = self.base("baseline2_duplicate")
        result = validate_ledger(ledger, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any("escape" in reason for reason in result.reasons), result.reasons)
        self.assertEqual(result.facts["lifetime_escape_counts"]["root-closed-001"], 2)

    def test_analyzer_validates_with_core_before_metrics(self) -> None:
        ledger = self.base("no_roots")
        record = {"ledger_id": "core-test", "ledger": ledger}
        invalid = analyzer.validate_ledger_set(self.schema, [record])
        self.assertEqual(invalid, {})
        self.assertIn("_facts", record)
        self.assertIsInstance(record["_validation"], ValidationResult)

    def test_timezone_equivalence_is_normalized_in_facts(self) -> None:
        ledger = self.base("no_roots")
        activity = ledger["activities"][0]
        activity["started_at"] = "2026-09-08T01:00:00-07:00"
        activity["completed_at"] = "2026-09-08T01:00:01-07:00"
        result = validate_ledger(ledger, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertEqual(result.facts["activities"][0]["chronology_bucket"], "v6")

    def test_cutover_boundary_is_required_and_offset_aware(self) -> None:
        missing = self.base("no_roots")
        missing["cutover"].pop("post_cutover_boundary")
        self.assertFalse(validate_ledger(missing, self.schema).valid)

        malformed = self.base("no_roots")
        malformed["cutover"]["post_cutover_boundary"] = "2026-09-08 08:00:00"
        malformed_result = validate_ledger(malformed, self.schema)
        self.assertFalse(malformed_result.valid)
        self.assertIn("cutover_boundary_invalid", malformed_result.reasons)

    def test_boundary_marker_and_master_require_exact_contract_string(self) -> None:
        ledger = self.base("no_roots")
        boundary = ledger["cutover"]["post_cutover_boundary"]
        marker = {**ledger["task"], "post_cutover_boundary": boundary,
                  "protocol_adopted_at": ledger["cutover"]["protocol_adopted_at"],
                  "protocol_adoption_evidence_refs": ledger["cutover"]["protocol_adoption_evidence_refs"]}
        master = {
            "cutoverId": ledger["cutover"]["cutover_id"],
            "postCutoverBoundary": boundary,
            "fingerprints": {"prompt": {"sha256": ledger["cutover"]["prompt_sha256"]}},
        }
        self.assertTrue(validate_ledger(ledger, self.schema, marker=marker, cutover=master).valid)

        timezone_equivalent_marker = {**marker, "post_cutover_boundary": "2026-09-08T07:53:44+00:00"}
        mismatch = validate_ledger(ledger, self.schema, marker=timezone_equivalent_marker, cutover=master)
        self.assertFalse(mismatch.valid)
        self.assertIn("marker_boundary_mismatch", mismatch.reasons)

        wrong_master = {**master, "postCutoverBoundary": "2026-09-08T07:53:45Z"}
        master_mismatch = validate_ledger(ledger, self.schema, marker=marker, cutover=wrong_master)
        self.assertFalse(master_mismatch.valid)
        self.assertIn("cutover_boundary_mismatch", master_mismatch.reasons)

    def test_consumer_bypass_guard(self) -> None:
        runner = (ROOT / "validate-mas1-ledger-fixtures.py").read_text()
        analyzer_source = (ROOT / "analyze-mas1-ledgers.py").read_text()
        self.assertIn("validate_ledger(ledger, schema_validator.schema)", runner)
        self.assertIn("validate_ledger(record[\"ledger\"], schema", analyzer_source)
        self.assertNotIn("module.check_", analyzer_source)

    def test_barrier1_registry_is_native_and_runner_is_reporting_only(self) -> None:
        core_source = (ROOT / "mas1_ledger_core.py").read_text()
        runner_source = (ROOT / "validate-mas1-ledger-fixtures.py").read_text()
        self.assertNotIn("importlib", core_source)
        self.assertNotIn("_legacy_rules", core_source)
        self.assertNotIn("validate-mas1-ledger-fixtures.py", core_source)
        self.assertNotRegex(runner_source, r"(?m)^def check_")
        for rule in RULE_REGISTRY:
            self.assertEqual(rule.__module__, "mas1_ledger_core")

    def test_unrelated_root_does_not_change_existing_escape_incident(self) -> None:
        original = validate_ledger(self.base(), self.schema)
        expanded = self.base()
        # An independently well-formed new root is not silently inferred from
        # an existing escape family; duplicate root IDs remain fail-closed.
        expanded["roots"].append(copy.deepcopy(expanded["roots"][0]))
        changed = validate_ledger(expanded, self.schema)
        self.assertTrue(original.valid)
        self.assertFalse(changed.valid)
        self.assertTrue(any("root_duplicate_id" in item for item in changed.reasons))

    def _case_ledger(self, name: str) -> dict:
        case = next(item for item in self.suite["cases"] if item["name"] == name)
        ledger = copy.deepcopy(self.suite["base_ledgers"][case["base"]])
        if case.get("variant") == "two-thresholded-roots":
            ledger = fixture_runner.add_second_thresholded_root(ledger)
        return fixture_runner.apply_patch(ledger, case.get("patch", []))

    # UC-001: complete-history closure epoch / changed basis successor strategy.
    def test_uc001_basis_invalidation_and_reclosure_matrix(self) -> None:
        invalid = validate_ledger(self._case_ledger("invalid closed root continues on a changed review basis"), self.schema)
        self.assertFalse(invalid.valid)
        self.assertTrue(any("basis_change_requires_reset" in item for item in invalid.reasons))
        reset = validate_ledger(self._case_ledger("valid changed basis invalidation resets closure"), self.schema)
        self.assertTrue(reset.valid, reset.reasons)
        self.assertIn("basis-invalidated", [event["type"] for event in reset.facts["events"]])
        missing_basis = self.base("closed_root")
        missing_basis["repair_attempts"][0]["review_basis_id"] = None
        result = validate_ledger(missing_basis, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any("closure_gate_repair_anchor" in item or "repair_attempt" in item for item in result.reasons))

    # UC-002: baseline permutations and historical threshold anchors never crash.
    def test_uc002_historical_threshold_matrix(self) -> None:
        blocked = validate_ledger(self.base("baseline2_blocked"), self.schema)
        approved = validate_ledger(self.base("baseline2_astra"), self.schema)
        self.assertTrue(blocked.valid, blocked.reasons)
        self.assertTrue(approved.valid, approved.reasons)
        for baseline in (None, 0, 1, 2, 3):
            for root_name in ("closed_root", "baseline2_blocked"):
                ledger = self.base(root_name)
                ledger["roots"][0]["historical_escape_count_baseline"] = baseline
                result = validate_ledger(ledger, self.schema)
                self.assertIsInstance(result, ValidationResult)
        anchored = self.base("baseline2_blocked")
        root = anchored["roots"][0]
        root["historical_escape_count_baseline"] = 2
        root["escape_count_lifetime"] = 3
        root["threshold_anchor"] = {"kind": "historical-baseline", "historical_threshold_reconciled_event_id": "nope", "reconciled_baseline": 2}
        rejected = validate_ledger(anchored, self.schema)
        self.assertFalse(rejected.valid)
        self.assertTrue(any("threshold_anchor_historical_invalid" in reason for reason in rejected.reasons))

    def test_threshold_anchor_and_block_code_are_exact_for_lifetime_gate(self) -> None:
        """P1: neither prose nor an arbitrary same-root escape can open the gate."""
        def assert_reason(ledger: dict, reason: str) -> None:
            result = validate_ledger(ledger, self.schema)
            self.assertFalse(result.valid)
            self.assertIn(f"{reason}:root-closed-001", result.reasons)

        # Baseline one plus its first unique post-cutover escape crosses the
        # threshold. Missing/null anchor and every missing/null/wrong code fail.
        for anchor in ("missing", None):
            ledger = self.base("baseline2_blocked")
            if anchor == "missing":
                ledger["roots"][0].pop("threshold_anchor")
            else:
                ledger["roots"][0]["threshold_anchor"] = anchor
            assert_reason(ledger, "threshold_anchor_required")
        for code in ("missing", None, "historical-baseline-unresolved"):
            ledger = self.base("baseline2_blocked")
            if code == "missing":
                ledger["roots"][0].pop("block_code")
            else:
                ledger["roots"][0]["block_code"] = code
            assert_reason(ledger, "threshold_block_code")

        # Baseline zero needs the second unique event, so an earlier or later
        # same-root escape cannot be substituted as the threshold anchor.
        def baseline_zero_with_escapes(count: int) -> dict:
            ledger = self.base("baseline2_blocked")
            root = ledger["roots"][0]
            root["historical_escape_count_baseline"] = 0
            root["escape_count_lifetime"] = count
            for number in range(2, count + 1):
                ledger["events"].append({
                    "event_id": f"evt-escape-{number:03d}", "sequence": 7 + number,
                    "at": f"2026-09-08T08:14:{number:02d}Z", "type": "escape-confirmed",
                    "causal_refs": ["obs-escape-001", f"repair-{number:03d}", "cycle-fix-001", "basis-001", "root-closed-001"],
                    "root_cause_id": "root-closed-001", "observation_id": "obs-escape-001",
                    "repair_attempt_id": f"repair-{number:03d}", "review_basis_id": "basis-001",
                    "cycle_id": "cycle-fix-001", "root_relationship": "exact-recurrence",
                    "escape_key": {"root_cause_id": "root-closed-001", "repair_attempt_id": f"repair-{number:03d}", "review_basis_id": "basis-001", "cycle_id": "cycle-fix-001"},
                })
            return ledger

        for anchor in ("missing", None):
            ledger = baseline_zero_with_escapes(2)
            if anchor == "missing":
                ledger["roots"][0].pop("threshold_anchor")
            else:
                ledger["roots"][0]["threshold_anchor"] = anchor
            assert_reason(ledger, "threshold_anchor_required")
        for code in ("missing", None, "historical-baseline-unresolved"):
            ledger = baseline_zero_with_escapes(2)
            ledger["roots"][0]["threshold_anchor"] = {"kind": "post-cutover-escape", "threshold_escape_event_id": "evt-escape-002"}
            if code == "missing":
                ledger["roots"][0].pop("block_code")
            else:
                ledger["roots"][0]["block_code"] = code
            assert_reason(ledger, "threshold_block_code")
        earlier = baseline_zero_with_escapes(2)
        self.assertEqual(earlier["roots"][0]["threshold_anchor"]["threshold_escape_event_id"], "evt-escape-001")
        assert_reason(earlier, "threshold_anchor_not_threshold")
        later = baseline_zero_with_escapes(3)
        later["roots"][0]["threshold_anchor"] = {"kind": "post-cutover-escape", "threshold_escape_event_id": "evt-escape-003"}
        assert_reason(later, "threshold_anchor_not_threshold")

        # A reconciled baseline already at the threshold uses the typed
        # historical anchor; a post-cutover anchor remains valid for the
        # blocked baseline-one state above, and the Astra successor control is
        # independently valid.
        historical = self.base("baseline2_blocked")
        root = historical["roots"][0]
        root["historical_escape_count_baseline"] = 2
        root["escape_count_lifetime"] = 3
        root["threshold_anchor"] = {
            "kind": "historical-baseline",
            "historical_threshold_reconciled_event_id": "evt-historical-threshold-001",
            "reconciled_baseline": 2,
        }
        historical["events"].append({
            "event_id": "evt-historical-threshold-001", "sequence": 9,
            "at": "2026-09-08T08:14:00Z", "type": "historical-threshold-reconciled",
            "causal_refs": ["root-closed-001"], "root_cause_id": "root-closed-001",
            "observation_id": None, "repair_attempt_id": None, "review_basis_id": None,
            "cycle_id": None, "root_relationship": None, "escape_key": None,
            "reconciled_baseline": 2, "evidence_refs": ["evt-baseline-001"],
        })
        self.assertTrue(validate_ledger(historical, self.schema).valid)
        self.assertTrue(validate_ledger(self.base("baseline2_astra"), self.schema).valid)

    def test_canonical_threshold_facts_are_safe_and_authoritative(self) -> None:
        approved = validate_ledger(self.base("baseline2_astra"), self.schema)
        fact = approved.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["threshold_kind"], "post-cutover-escape")
        self.assertEqual(fact["threshold_event_id"], "evt-escape-001")
        self.assertEqual(fact["lifetime_count"], 2)
        self.assertFalse(fact["awaiting_astra"])
        self.assertEqual(fact["authorization"]["strategy_id"], "strategy-001")
        malformed = self.base("baseline2_blocked")
        malformed["events"][6]["sequence"] = "7"
        malformed["events"][6]["escape_key"]["cycle_id"] = ["unhashable"]
        result = validate_ledger(malformed, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("threshold_sequence_invalid:evt-escape-001", result.reasons)
        self.assertIn("threshold_escape_key_invalid:evt-escape-001", result.reasons)
        self.assertFalse(any(reason.startswith("internal:") for reason in result.reasons), result.reasons)

    def test_per_attempt_astra_authorization_is_universal_and_planned_safe(self) -> None:
        """A valid sibling grant cannot authorize another affected attempt."""
        valid = validate_ledger(self.base("baseline2_astra"), self.schema)
        fact = valid.facts["threshold_facts"]["root-closed-001"]
        self.assertTrue(valid.valid, valid.reasons)
        self.assertEqual(fact["authorized_attempt_ids"], ["repair-001"])
        self.assertEqual(fact["current_authorization_epoch_event_id"], "evt-escape-001")

        for suffix, started in (("before", "2026-09-08T08:13:51Z"), ("after", "2026-09-08T08:14:05Z")):
            ledger = self.base("baseline2_astra")
            rogue = copy.deepcopy(ledger["repair_attempts"][0])
            rogue.update({"repair_attempt_id": f"repair-{suffix}", "started_at": started,
                          "completed_at": "2026-09-08T08:14:06Z", "implementation_activity_ids": [],
                          "authorization_event_id": None, "authorization_basis_id": None,
                          "authorization_epoch_event_id": None})
            ledger["repair_attempts"].append(rogue)
            result = validate_ledger(ledger, self.schema)
            self.assertFalse(result.valid)
            self.assertIn(f"astra_attempt_authorization_required:root-closed-001:repair-{suffix}", result.reasons)
            self.assertIn(f"repair-{suffix}", result.facts["threshold_facts"]["root-closed-001"]["unauthorized_attempt_ids"])

        for field, value in (("repair_attempt_id", "repair-wrong"),
                             ("authorization_basis_id", "basis-wrong"),
                             ("authorization_epoch_event_id", "evt-fix-001"),
                             ("adjudication_activity_id", "act-fix-successor")):
            ledger = self.base("baseline2_astra")
            ledger["events"][-1][field] = value
            result = validate_ledger(ledger, self.schema)
            self.assertFalse(result.valid, field)
            self.assertIn("astra_attempt_authorization_required:root-closed-001:repair-001", result.reasons)

        unlinked = self.base("baseline2_astra")
        rogue_activity = copy.deepcopy(unlinked["activities"][-1])
        rogue_activity.update({"activity_id": "act-unlinked", "started_at": "2026-09-08T08:14:01Z",
                               "completed_at": "2026-09-08T08:14:02Z", "repair_attempt_id": None})
        unlinked["activities"].append(rogue_activity)
        unlinked["telemetry"]["recorded_participating_activity_count"] += 1
        unlinked["telemetry"]["expected_participating_activity_count"] += 1
        result = validate_ledger(unlinked, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("threshold_implementation_uncovered:root-closed-001:act-unlinked", result.reasons)

        planned = self.base("baseline2_astra")
        attempt = planned["repair_attempts"][0]
        attempt.update({"started_at": None, "completed_at": None, "status": "planned", "implementation_activity_ids": []})
        planned["events"][-1]["implementation_activity_ids"] = []
        planned["events"][-1]["causal_refs"].remove("act-fix-successor")
        planned["activities"] = [activity for activity in planned["activities"] if activity["activity_id"] != "act-fix-successor"]
        planned["telemetry"]["recorded_participating_activity_count"] -= 1
        planned["telemetry"]["expected_participating_activity_count"] -= 1
        planned["roots"][0].update({"state": "blocked", "previous_state": "repairing", "blocked_reason": "implementation remains planned"})
        result = validate_ledger(planned, self.schema)
        self.assertTrue(result.valid, result.reasons)
        planned_fact = result.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(planned_fact["planned_attempt_ids"], ["repair-001"])
        self.assertTrue(planned_fact["attempt_results"]["repair-001"]["authorized"])

    def test_r7_terminal_implementation_and_planned_state_are_not_forged(self) -> None:
        """Actual role/state, rather than a reserved ID, controls execution."""
        review = self.base("baseline2_astra")
        activity = next(item for item in review["activities"] if item["activity_id"] == "act-fix-successor")
        activity["type"] = "review"
        result = validate_ledger(review, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("lc:activity_role:root-closed-001:repair-001", result.reasons)

        running = self.base("baseline2_astra")
        activity = next(item for item in running["activities"] if item["activity_id"] == "act-fix-successor")
        activity.update({"status": "running", "completed_at": None})
        result = validate_ledger(running, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("lc:activity_role:root-closed-001:repair-001", result.reasons)

        falsely_planned = self.base("baseline2_astra")
        falsely_planned["repair_attempts"][0]["status"] = "planned"
        result = validate_ledger(falsely_planned, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("lc:attempt_record:root-closed-001:repair-001", result.reasons)

    def test_r004_named_modern_controls_expose_exact_facts(self) -> None:
        expected = {
            "S": ("awaiting_post_repair_review", False, ["repair-001"], [], "succeeded", True, True, True, True),
            "P": ("open", False, [], [], "planned", False, True, False, True),
            "A": ("repairing", False, ["repair-001"], [], "active", False, True, True, True),
            "W": ("blocked", True, [], [], "planned", False, False, False, True),
        }
        for name, (state, awaiting, authorized, unauthorized, lifecycle, complete, grant, started, execution) in expected.items():
            with self.subTest(name=name):
                result = validate_ledger(self.r004_control(name), self.schema)
                self.assertTrue(result.valid, result.reasons)
                fact = result.facts["threshold_facts"]["root-closed-001"]
                attempt = fact["attempt_facts"]["repair-001"]
                self.assertEqual(fact["gate_state"], state)
                self.assertEqual(fact["awaiting_astra"], awaiting)
                self.assertEqual(fact["authorized_attempt_ids"], authorized)
                self.assertEqual(fact["unauthorized_attempt_ids"], unauthorized)
                self.assertEqual(fact["threshold_relevant_attempt_ids"], ["repair-001"])
                self.assertEqual(fact["frontier_attempt_id"], "repair-001")
                self.assertEqual(attempt["lifecycle_state"], lifecycle)
                self.assertEqual(attempt["completion_eligible"], complete)
                self.assertEqual(attempt["grant_valid"], grant)
                self.assertEqual(attempt["start_authorized"], started)
                self.assertEqual(attempt["execution_valid"], execution)
                self.assertEqual(attempt["record_kind"], "reservation")
                self.assertEqual(attempt["threshold_affected"], True)
                self.assertEqual(attempt["historical_nonauthorizing"], False)
        self.assertEqual(validate_ledger(self.r004_control("S"), self.schema).facts["threshold_facts"]["root-closed-001"]["closure_epoch_id"],
                         "epoch:root-closed-001:evt-activation-001:repair-001:evt-settlement-001")

    def test_r005_causal_order_frontier_bindings(self) -> None:
        """005 binds reservations and grants to a sequence-only causal prefix."""
        valid = self.r004_control("S")
        self.assertTrue(validate_ledger(valid, self.schema).valid)
        old_modern = copy.deepcopy(valid)
        next(item for item in old_modern["repair_attempts"] if item["repair_attempt_id"] == "repair-001").pop("reservation_event_id")
        result = validate_ledger(old_modern, self.schema)
        self.assertFalse(result.valid)
        self.assertIn(f"compat:unsupported-modern-reservation-version:{old_modern['task']['task_instance_id']}", result.reasons)
        equal_grant_start = copy.deepcopy(valid)
        next(item for item in equal_grant_start["events"] if item["event_id"] == "evt-start-001")["started_at"] = "2026-09-08T08:13:51Z"
        result = validate_ledger(equal_grant_start, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any(reason.startswith("auth:chronology:root-closed-001:repair-001") for reason in result.reasons))
        during_adjudication = copy.deepcopy(valid)
        for event in during_adjudication["events"]:
            if event["sequence"] >= 12:
                event["sequence"] += 1
        invalidator = {"event_id": "evt-basis-during-005", "sequence": 12, "at": "2026-09-08T08:13:45Z", "type": "basis-invalidated", "causal_refs": ["root-closed-001"], "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None, "review_basis_id": "basis-001", "cycle_id": None, "root_relationship": None, "escape_key": None}
        grant_index = next(index for index, event in enumerate(during_adjudication["events"]) if event["event_id"] == "evt-astra-001")
        during_adjudication["events"].insert(grant_index, invalidator)
        during_adjudication["roots"][0].update({"state": "blocked", "blocked_reason": "basis changed during adjudication"})
        result = validate_ledger(during_adjudication, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any(reason.startswith("auth:grant_binding:root-closed-001:repair-001") for reason in result.reasons))
        id_independent = self.r004_control("S")
        self.r004_add_fresh_attempt(id_independent, suffix="inverse")
        result = validate_ledger(id_independent, self.schema)
        self.assertTrue(result.valid, result.reasons)
        fact = result.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["frontier_attempt_id"], "repair-inverse")
        self.assertEqual(fact["closure_epoch_id"].split(":")[3], "repair-inverse")

    def test_r005_invalidator_position_matrix(self) -> None:
        """005-INV: each causal position retains its own authority boundary."""
        root_id = "root-closed-001"
        attempt_id = "repair-001"
        positions = (
            ("before_adjudication", "2026-09-08T08:13:39Z", "evt-astra-begin-001", True,
             False, False, True, None, "auth:grant_binding"),
            ("during_adjudication", "2026-09-08T08:13:45Z", "evt-astra-001", True,
             False, False, True, None, "auth:grant_binding"),
            ("after_adjudication_before_grant", "2026-09-08T08:13:50.500000Z", "evt-astra-001", True,
             False, False, True, None, "auth:grant_binding"),
            ("after_grant_before_start", "2026-09-08T08:13:51.500000Z", "evt-start-001", True,
             True, False, True, None, "auth:chronology"),
            ("at_start_invalidator_before_start", "2026-09-08T08:13:52Z", "evt-start-001", True,
             True, False, True, None, "auth:chronology"),
            ("at_start_invalidator_after_start", "2026-09-08T08:13:52Z", "evt-settlement-001", False,
             True, True, False, "auth:crossing", "auth:crossing"),
            ("during_mutation", "2026-09-08T08:13:55Z", "evt-settlement-001", True,
             True, True, False, "auth:crossing", "auth:crossing"),
            ("after_settlement", "2026-09-08T08:14:01Z", None, True,
             True, True, True, "after_settlement", ""),
        )

        def insert_at(ledger: dict, target_event_id: str | None, before_target: bool, count: int) -> int:
            if target_event_id is None:
                index = len(ledger["events"])
            elif before_target:
                index = next(index for index, event in enumerate(ledger["events"])
                             if event["event_id"] == target_event_id)
            else:
                index = next(index for index, event in enumerate(ledger["events"])
                             if event["event_id"] == target_event_id) + 1
            for event in ledger["events"][index:]:
                event["sequence"] += count
            return index

        def basis_invalidator(case_id: str, position: str, at: str, target: str | None, before_target: bool) -> tuple[dict, str]:
            ledger = self.r004_control("S")
            index = insert_at(ledger, target, before_target, 1)
            sequence = ledger["events"][index]["sequence"] - 1 if index < len(ledger["events"]) else max(
                event["sequence"] for event in ledger["events"]
            ) + 1
            event_id = f"evt-basis-{case_id.lower()}"
            ledger["events"].insert(index, {
                "event_id": event_id, "sequence": sequence, "at": at, "type": "basis-invalidated",
                "causal_refs": [root_id], "root_cause_id": root_id, "observation_id": None,
                "repair_attempt_id": None, "review_basis_id": "basis-001", "cycle_id": None,
                "root_relationship": None, "escape_key": None,
            })
            ledger["roots"][0].update({"state": "blocked", "previous_state": "repairing",
                                         "blocked_reason": f"{position} basis invalidation"})
            return ledger, event_id

        def escape_invalidator(case_id: str, position: str, at: str, target: str | None, before_target: bool) -> tuple[dict, str]:
            ledger = self.r004_control("S")
            index = insert_at(ledger, target, before_target, 2)
            sequence = ledger["events"][index]["sequence"] - 2 if index < len(ledger["events"]) else max(
                event["sequence"] for event in ledger["events"]
            ) + 1
            suffix = case_id.lower()
            cycle_id = f"cycle-inv-{suffix}"
            activity_id = f"act-inv-{suffix}"
            observation_id = f"obs-inv-{suffix}"
            event_id = f"evt-escape-{suffix}"
            instant = datetime.fromisoformat(at.replace("Z", "+00:00"))
            began_at = (instant - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            activity = copy.deepcopy(next(item for item in ledger["activities"] if item["activity_id"] == "act-review-001"))
            activity.update({"activity_id": activity_id, "type": "discovery", "started_at": began_at, "completed_at": at})
            ledger["activities"].append(activity)
            ledger["cycles"].append({"cycle_id": cycle_id, "sequence": 5, "started_at": began_at,
                                      "completed_at": at, "complete": True, "review_basis_id": "basis-001",
                                      "activity_ids": [activity_id], "kind": "other"})
            observation = copy.deepcopy(next(item for item in ledger["observations"] if item["observation_id"] == "obs-escape-001"))
            observation.update({"observation_id": observation_id, "observed_at": at, "repair_attempt_id": "repair-old",
                                "cycle_id": cycle_id, "detected_cycle_id": cycle_id,
                                "discovering_activity_ids": [activity_id], "activity_ids": [activity_id]})
            ledger["observations"].append(observation)
            escape = {
                "event_id": event_id, "sequence": sequence, "at": at, "type": "escape-confirmed",
                "causal_refs": [observation_id, "repair-old", cycle_id, "basis-001", root_id],
                "root_cause_id": root_id, "observation_id": observation_id, "repair_attempt_id": "repair-old",
                "review_basis_id": "basis-001", "cycle_id": cycle_id, "root_relationship": "exact-recurrence",
                "escape_key": {"root_cause_id": root_id, "repair_attempt_id": "repair-old",
                               "review_basis_id": "basis-001", "cycle_id": cycle_id},
            }
            reopen = {
                "event_id": f"evt-reopen-{suffix}", "sequence": sequence + 1, "at": at, "type": "root-reopened",
                "causal_refs": [observation_id, event_id, root_id], "root_cause_id": root_id,
                "observation_id": observation_id, "repair_attempt_id": "repair-old", "review_basis_id": "basis-001",
                "cycle_id": cycle_id, "root_relationship": "exact-recurrence", "escape_key": None,
            }
            ledger["events"][index:index] = [escape, reopen]
            ledger["roots"][0].update({"escape_count_lifetime": 3, "state": "blocked", "previous_state": "repairing",
                                         "blocked_reason": f"{position} escape invalidation"})
            ledger["telemetry"]["recorded_participating_activity_count"] = len(ledger["activities"])
            ledger["telemetry"]["expected_participating_activity_count"] = len(ledger["activities"])
            return ledger, event_id

        for family, builder, prefix in (
            ("ESC", escape_invalidator, "escape-confirmed"),
            ("BASIS", basis_invalidator, "basis-invalidated"),
        ):
            for number, (position, at, target, before_target, grant_valid, start_authorized, execution_valid,
                         crossing, reason_prefix) in enumerate(positions, start=1):
                case_id = f"005-INV-{family}-{number:02d}"
                ledger, invalidator_id = builder(case_id, position, at, target, before_target)
                invalidator = next(event for event in ledger["events"] if event["event_id"] == invalidator_id)
                start = next(event for event in ledger["events"] if event["event_id"] == "evt-start-001")
                grant = next(event for event in ledger["events"] if event["event_id"] == "evt-astra-001")
                settlement = next(event for event in ledger["events"] if event["event_id"] == "evt-settlement-001")
                mutation = next(activity for activity in ledger["activities"] if activity["activity_id"] == "act-fix-successor")
                with self.subTest(case_id=case_id):
                    # Construction proof: no case is a renamed shared ledger.
                    self.assertEqual(invalidator["type"], prefix)
                    self.assertEqual(invalidator["at"], at)
                    self.assertEqual(invalidator["root_cause_id"], root_id)
                    self.assertLess(grant["sequence"], start["sequence"])
                    self.assertLess(grant["at"], start["started_at"])
                    self.assertLessEqual(start["started_at"], mutation["started_at"])
                    self.assertLessEqual(mutation["completed_at"], settlement["settled_at"])
                    if target is not None:
                        target_event = next(event for event in ledger["events"] if event["event_id"] == target)
                        if before_target:
                            self.assertLess(invalidator["sequence"], target_event["sequence"])
                        else:
                            self.assertGreater(invalidator["sequence"], target_event["sequence"])
                    else:
                        self.assertGreater(invalidator["sequence"], settlement["sequence"])
                    if position == "at_start_invalidator_before_start":
                        self.assertEqual(invalidator["at"], start["at"])
                        self.assertLess(invalidator["sequence"], start["sequence"])
                    if position == "at_start_invalidator_after_start":
                        self.assertEqual(invalidator["at"], start["at"])
                        self.assertGreater(invalidator["sequence"], start["sequence"])

                    result = validate_ledger(ledger, self.schema)
                    self.assertEqual(result.valid, position == "after_settlement", result.reasons)
                    if reason_prefix:
                        self.assertTrue(any(reason.startswith(reason_prefix) for reason in result.reasons), result.reasons)
                    facts = result.facts["threshold_facts"][root_id]
                    attempt = facts["attempt_facts"][attempt_id]
                    self.assertEqual(attempt["grant_valid"], grant_valid)
                    self.assertEqual(attempt["start_authorized"], start_authorized)
                    self.assertEqual(attempt["execution_valid"], execution_valid)
                    self.assertEqual(attempt["crossing_invalidator_event_id"],
                                     invalidator_id if crossing in {"auth:crossing", "after_settlement"} else None)
                    self.assertEqual(facts["authorization_epoch_event_id"], invalidator_id)
                    self.assertEqual(facts["decision_trigger_event_id"],
                                     invalidator_id if family == "ESC" else "evt-escape-001")
                    self.assertEqual(facts["closure_eligible"], False)

    def test_r005_chronology_and_permitted_equalities_matrix(self) -> None:
        """005-CHRON: each asserted ordering has a material input witness."""
        def event(ledger: dict, event_id: str) -> dict:
            return next(row for row in ledger["events"] if row["event_id"] == event_id)
        def activity(ledger: dict, activity_id: str) -> dict:
            return next(row for row in ledger["activities"] if row["activity_id"] == activity_id)
        def strategy(ledger: dict) -> dict:
            return next(row for row in ledger["strategies"] if row["strategy_id"] == "strategy-001")
        invalid: list[tuple[str, dict, bool]] = []
        original = self.r004_control("S")
        # The original strict trigger witness is 08:13:34Z: moving the
        # triggering escape to Astra start removes the required predecessor.
        event(original, "evt-escape-001")["at"] = "2026-09-08T08:13:34Z"
        self.assertEqual(event(original, "evt-escape-001")["at"], "2026-09-08T08:13:34Z")
        invalid.append(("005-CHRON-001-original-081334", original, True))
        trigger_equal = self.r004_control("S")
        activity(trigger_equal, "act-astr-001")["started_at"] = "2026-09-08T08:13:35Z"
        event(trigger_equal, "evt-astra-begin-001")["at"] = "2026-09-08T08:13:35Z"
        self.assertEqual(event(trigger_equal, "evt-escape-001")["at"], activity(trigger_equal, "act-astr-001")["started_at"])
        invalid.append(("005-CHRON-002-trigger-equals-astra", trigger_equal, False))
        strategy_after = self.r004_control("S")
        strategy(strategy_after)["created_at"] = "2026-09-08T08:13:41Z"
        self.assertGreater(strategy(strategy_after)["created_at"], activity(strategy_after, "act-astr-001")["started_at"])
        invalid.append(("005-CHRON-003-strategy-after-astra", strategy_after, False))
        activation_after = self.r004_control("S")
        activity(activation_after, "act-astr-001")["started_at"] = "2026-09-08T08:13:36Z"
        event(activation_after, "evt-astra-begin-001")["at"] = "2026-09-08T08:13:36Z"
        self.assertGreater(event(activation_after, "evt-activation-001")["at"], activity(activation_after, "act-astr-001")["started_at"])
        invalid.append(("005-CHRON-004-activation-after-astra", activation_after, False))
        invalidation_equal = self.r004_control("S")
        for row in invalidation_equal["events"]:
            if row["sequence"] >= 11:
                row["sequence"] += 1
        begin_index = next(index for index, row in enumerate(invalidation_equal["events"]) if row["event_id"] == "evt-astra-begin-001")
        invalidation_equal["events"].insert(begin_index, {"event_id": "evt-basis-at-astra", "sequence": 11, "at": "2026-09-08T08:13:40Z", "type": "basis-invalidated", "causal_refs": ["root-closed-001"], "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None, "review_basis_id": "basis-001", "cycle_id": None, "root_relationship": None, "escape_key": None})
        invalidation_equal["roots"][0].update({"state": "blocked", "blocked_reason": "basis invalidated at Astra start"})
        self.assertEqual(invalidation_equal["events"][begin_index]["at"], activity(invalidation_equal, "act-astr-001")["started_at"])
        invalid.append(("005-CHRON-005-basis-at-astra", invalidation_equal, False))
        completion_after = self.r004_control("S")
        activity(completion_after, "act-astr-001")["completed_at"] = "2026-09-08T08:13:52Z"
        self.assertGreater(activity(completion_after, "act-astr-001")["completed_at"], event(completion_after, "evt-astra-001")["at"])
        invalid.append(("005-CHRON-006-completion-after-grant", completion_after, False))
        grant_equal_start = self.r004_control("S")
        event(grant_equal_start, "evt-start-001")["started_at"] = event(grant_equal_start, "evt-astra-001")["at"]
        self.assertEqual(event(grant_equal_start, "evt-start-001")["started_at"], event(grant_equal_start, "evt-astra-001")["at"])
        invalid.append(("005-CHRON-007-grant-equals-start", grant_equal_start, True))
        for case_id, ledger, expected_grant in invalid:
            with self.subTest(case_id=case_id):
                result = validate_ledger(ledger, self.schema)
                self.assertFalse(result.valid, result.reasons)
                self.assertEqual(result.facts["threshold_facts"]["root-closed-001"]["attempt_facts"]["repair-001"]["grant_valid"], expected_grant)
        allowed: list[tuple[str, dict]] = []
        strategy_equal = self.r004_control("S")
        strategy(strategy_equal)["created_at"] = activity(strategy_equal, "act-astr-001")["started_at"]
        self.assertEqual(strategy(strategy_equal)["created_at"], activity(strategy_equal, "act-astr-001")["started_at"])
        allowed.append(("005-EQ-001-strategy-equals-astra", strategy_equal))
        activation_equal = self.r004_control("S")
        for row in (event(activation_equal, "evt-activation-001"), event(activation_equal, "evt-reservation-001"), event(activation_equal, "evt-astra-begin-001")):
            row["at"] = "2026-09-08T08:13:40Z"
        next(row for row in activation_equal["repair_attempts"] if row["repair_attempt_id"] == "repair-001")["created_at"] = "2026-09-08T08:13:40Z"
        self.assertEqual(event(activation_equal, "evt-activation-001")["at"], activity(activation_equal, "act-astr-001")["started_at"])
        allowed.append(("005-EQ-002-activation-record-equals-astra", activation_equal))
        complete_equal_grant = self.r004_control("S")
        activity(complete_equal_grant, "act-astr-001")["completed_at"] = event(complete_equal_grant, "evt-astra-001")["at"]
        self.assertEqual(activity(complete_equal_grant, "act-astr-001")["completed_at"], event(complete_equal_grant, "evt-astra-001")["at"])
        allowed.append(("005-EQ-003-complete-equals-grant", complete_equal_grant))
        zero_duration = self.r004_control("S")
        activity(zero_duration, "act-astr-001")["completed_at"] = activity(zero_duration, "act-astr-001")["started_at"]
        self.assertLess(event(zero_duration, "evt-activation-001")["sequence"], event(zero_duration, "evt-astra-begin-001")["sequence"])
        self.assertLess(event(zero_duration, "evt-astra-begin-001")["sequence"], event(zero_duration, "evt-astra-001")["sequence"])
        allowed.append(("005-EQ-004-zero-duration-astra", zero_duration))
        for case_id, ledger in allowed:
            with self.subTest(case_id=case_id):
                result = validate_ledger(ledger, self.schema)
                self.assertTrue(result.valid, result.reasons)
                self.assertTrue(result.facts["threshold_facts"]["root-closed-001"]["attempt_facts"]["repair-001"]["grant_valid"])

    def test_r005_frontier_delayed_settlement_and_ownership_matrix(self) -> None:
        """005-FRONT/OWN: delayed records never outrank reservation order."""
        delayed = self.r004_control("S")
        p1_activity = next(row for row in delayed["activities"] if row["activity_id"] == "act-fix-successor")
        self.r004_add_fresh_attempt(delayed, suffix="p2delayed")
        delayed["events"] = [row for row in delayed["events"] if row["event_id"] != "evt-settlement-001"]
        p1_activity.update({"status": "completed", "completed_at": "2026-09-08T08:14:16Z"})
        template = next(row for row in self.r004_control("S")["events"] if row["event_id"] == "evt-settlement-001")
        late = copy.deepcopy(template)
        late.update({"event_id": "evt-settlement-p1-delayed", "sequence": max(row["sequence"] for row in delayed["events"]) + 1,
                     "at": "2026-09-08T08:14:50Z", "settled_at": "2026-09-08T08:14:16Z", "mutation_finished_at": "2026-09-08T08:14:16Z"})
        delayed["events"].append(late)
        delayed["roots"][0].update({"state": "awaiting_post_repair_review", "previous_state": "repairing"})
        self.assertEqual(delayed["events"][-1]["event_id"], "evt-settlement-p1-delayed")
        self.assertLess(p1_activity["completed_at"], next(row for row in delayed["events"] if row["event_id"] == "evt-reservation-p2delayed")["at"])
        result = validate_ledger(delayed, self.schema)
        self.assertTrue(result.valid, result.reasons)
        facts = result.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(facts["frontier_attempt_id"], "repair-p2delayed")
        self.assertEqual(facts["attempt_facts"]["repair-001"]["settlement_event_id"], "evt-settlement-p1-delayed")

        running_predecessor = self.r004_control("S")
        self.r004_add_fresh_attempt(running_predecessor, suffix="p2running")
        running_predecessor["events"] = [row for row in running_predecessor["events"] if row["event_id"] != "evt-settlement-001"]
        next(row for row in running_predecessor["activities"] if row["activity_id"] == "act-fix-successor").update({"status": "running", "completed_at": None})
        self.assertEqual(next(row for row in running_predecessor["activities"] if row["activity_id"] == "act-fix-successor")["status"], "running")
        result = validate_ledger(running_predecessor, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any(reason.startswith("auth:ownership_barrier") for reason in result.reasons), result.reasons)

        terminal_after = self.r004_control("S")
        self.r004_add_fresh_attempt(terminal_after, suffix="p2late")
        old = next(row for row in terminal_after["activities"] if row["activity_id"] == "act-fix-successor")
        old["completed_at"] = "2026-09-08T08:14:18Z"
        old_settlement = next(row for row in terminal_after["events"] if row["event_id"] == "evt-settlement-001")
        old_settlement.update({"at": "2026-09-08T08:14:18Z", "settled_at": "2026-09-08T08:14:18Z", "mutation_finished_at": "2026-09-08T08:14:18Z"})
        p2_reservation = next(row for row in terminal_after["events"] if row["event_id"] == "evt-reservation-p2late")
        self.assertGreater(old["completed_at"], p2_reservation["at"])
        result = validate_ledger(terminal_after, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any(reason.startswith("auth:ownership_barrier") for reason in result.reasons), result.reasons)

        exact_boundary = self.r004_control("S")
        old = next(row for row in exact_boundary["activities"] if row["activity_id"] == "act-fix-successor")
        old_settlement = next(row for row in exact_boundary["events"] if row["event_id"] == "evt-settlement-001")
        old.update({"completed_at": "2026-09-08T08:14:17Z"})
        old_settlement.update({"at": "2026-09-08T08:14:17Z", "settled_at": "2026-09-08T08:14:17Z", "mutation_finished_at": "2026-09-08T08:14:17Z"})
        self.r004_add_fresh_attempt(exact_boundary, suffix="p2edge")
        self.assertEqual(old["completed_at"], next(row for row in exact_boundary["events"] if row["event_id"] == "evt-reservation-p2edge")["at"])
        self.assertTrue(validate_ledger(exact_boundary, self.schema).valid)

        for outcome in ("failed", "superseded", "cancelled"):
            with self.subTest(case_id=f"005-HIST-{outcome}"):
                ledger = self.r004_control("S")
                self.r004_add_fresh_attempt(ledger, suffix=f"p2{outcome}")
                next(row for row in ledger["events"] if row["event_id"] == f"evt-settlement-p2{outcome}")["terminal_outcome"] = outcome
                ledger["roots"][0].update({"state": "blocked", "blocked_reason": f"P2 {outcome}"})
                result = validate_ledger(ledger, self.schema)
                self.assertTrue(result.valid, result.reasons)
                facts = result.facts["threshold_facts"]["root-closed-001"]
                self.assertEqual(facts["frontier_attempt_id"], f"repair-p2{outcome}")
                self.assertEqual(facts["gate_state"], "blocked")
                self.assertTrue(facts["awaiting_astra"])

    def test_r005_event_binding_and_snapshot_matrix(self) -> None:
        """005-BIND: malformed causal ordinals and retrofits fail closed."""
        valid = self.r004_control("S")
        cases: list[tuple[str, dict, str]] = []
        duplicate = copy.deepcopy(valid); next(row for row in duplicate["events"] if row["event_id"] == "evt-astra-001")["sequence"] = 11
        self.assertEqual(next(row for row in duplicate["events"] if row["event_id"] == "evt-astra-001")["sequence"], 11)
        cases.append(("005-BIND-001-duplicate-sequence", duplicate, "event_sequence_duplicate"))
        boolean = copy.deepcopy(valid); next(row for row in boolean["events"] if row["event_id"] == "evt-astra-001")["sequence"] = True
        self.assertIs(next(row for row in boolean["events"] if row["event_id"] == "evt-astra-001")["sequence"], True)
        cases.append(("005-BIND-002-boolean-sequence", boolean, "schema:type"))
        missing = copy.deepcopy(valid); next(row for row in missing["events"] if row["event_id"] == "evt-astra-001").pop("sequence")
        self.assertNotIn("sequence", next(row for row in missing["events"] if row["event_id"] == "evt-astra-001"))
        cases.append(("005-BIND-003-missing-sequence", missing, "schema:required"))
        wrong_reservation = copy.deepcopy(valid); next(row for row in wrong_reservation["events"] if row["event_id"] == "evt-reservation-001")["root_cause_id"] = "wrong-root"
        self.assertEqual(next(row for row in wrong_reservation["events"] if row["event_id"] == "evt-reservation-001")["root_cause_id"], "wrong-root")
        cases.append(("005-BIND-004-wrong-root-reservation", wrong_reservation, "lc:attempt_record"))
        dangling_begin = copy.deepcopy(valid); next(row for row in dangling_begin["events"] if row["event_id"] == "evt-astra-001")["adjudication_start_event_id"] = "missing-begin"
        self.assertEqual(next(row for row in dangling_begin["events"] if row["event_id"] == "evt-astra-001")["adjudication_start_event_id"], "missing-begin")
        cases.append(("005-BIND-005-dangling-begin", dangling_begin, "auth:grant_binding"))
        for case_id, ledger, reason in cases:
            with self.subTest(case_id=case_id):
                result = validate_ledger(ledger, self.schema)
                self.assertFalse(result.valid, result.reasons)
                self.assertTrue(any(item.startswith(reason) for item in result.reasons), result.reasons)
        previous = self.r004_control("S")
        rewritten = copy.deepcopy(previous)
        next(row for row in rewritten["events"] if row["event_id"] == "evt-reservation-001")["at"] = "2026-09-08T08:13:38Z"
        self.assertNotEqual(next(row for row in rewritten["events"] if row["event_id"] == "evt-reservation-001")["at"], next(row for row in previous["events"] if row["event_id"] == "evt-reservation-001")["at"])
        result = validate_ledger(rewritten, self.schema, previous)
        self.assertFalse(result.valid); self.assertIn("event:immutable:evt-reservation-001", result.reasons)
        old_snapshot = copy.deepcopy(previous)
        next(row for row in old_snapshot["repair_attempts"] if row["repair_attempt_id"] == "repair-001").pop("reservation_event_id")
        result = validate_ledger(previous, self.schema, old_snapshot)
        self.assertFalse(result.valid)
        self.assertIn(f"compat:unsupported-modern-reservation-version:{previous['task']['task_instance_id']}", result.reasons)

    def test_r005_prestart_cancellation_and_old_plan_barrier(self) -> None:
        """005-CANCEL: an unstarted reservation has one explicit terminal path."""
        ledger = self.r004_control("S")
        self.r004_add_fresh_attempt(ledger, suffix="cancelp2")
        # P1 is a separate older planned reservation: no start or mutation.
        p1 = copy.deepcopy(next(row for row in ledger["repair_attempts"] if row["repair_attempt_id"] == "repair-001"))
        p1.update({"repair_attempt_id": "repair-old-plan", "strategy_id": "strategy-old", "created_at": "2026-09-08T08:13:38Z", "reservation_event_id": "evt-reservation-old-plan", "expected_authorization_event_id": "evt-astra-old-plan", "implementation_activity_ids": [], "verification_activity_ids": []})
        old_strategy = copy.deepcopy(next(row for row in ledger["strategies"] if row["strategy_id"] == "strategy-001")); old_strategy.update({"strategy_id": "strategy-old", "created_at": "2026-09-08T08:13:37Z", "failed_predecessor_strategy_ids": []})
        old_reservation = copy.deepcopy(next(row for row in ledger["events"] if row["event_id"] == "evt-reservation-001")); old_reservation.update({"event_id": "evt-reservation-old-plan", "sequence": 10, "at": "2026-09-08T08:13:38Z", "repair_attempt_id": "repair-old-plan", "strategy_id": "strategy-old", "reservation_event_id": "evt-reservation-old-plan", "causal_refs": ["root-closed-001", "repair-old-plan", "strategy-old", "basis-001"]})
        # Shift every current event to preserve stored sequence ordering, then
        # insert the actual older reservation before the P2 reservation.
        for row in ledger["events"]: row["sequence"] += 1
        ledger["events"].insert(next(i for i,row in enumerate(ledger["events"]) if row["event_id"] == "evt-reservation-001"), old_reservation)
        for number, row in enumerate(ledger["events"], start=1): row["sequence"] = number
        ledger["repair_attempts"].append(p1); ledger["strategies"].append(old_strategy)
        ledger["roots"][0].update({"state": "blocked", "blocked_reason": "older plan unresolved"})
        self.assertEqual(old_reservation["type"], "repair-reserved")
        self.assertLess(old_reservation["sequence"], next(row for row in ledger["events"] if row["event_id"] == "evt-reservation-cancelp2")["sequence"])
        blocked = validate_ledger(ledger, self.schema)
        self.assertFalse(blocked.valid)
        self.assertTrue(any(reason.startswith("auth:ownership_barrier") for reason in blocked.reasons), blocked.reasons)
        # The exact terminal pre-start cancellation has no start ID, no
        # mutation, and is appended after all successor facts are recorded.
        cancel = copy.deepcopy(next(row for row in self.r004_control("S")["events"] if row["event_id"] == "evt-settlement-001"))
        cancel.update({"event_id": "evt-cancel-old-plan", "sequence": max(row["sequence"] for row in ledger["events"]) + 1, "at": "2026-09-08T08:14:50Z", "repair_attempt_id": "repair-old-plan", "start_event_id": None, "terminal_outcome": "cancelled", "settled_at": "2026-09-08T08:13:38Z", "mutation_finished_at": None, "causal_refs": ["root-closed-001", "repair-old-plan", "basis-001"]})
        ledger["events"].append(cancel)
        ledger["roots"][0].update({"state": "awaiting_post_repair_review", "blocked_reason": None})
        self.assertIsNone(cancel["start_event_id"]); self.assertIsNone(cancel["mutation_finished_at"])
        settled = validate_ledger(ledger, self.schema)
        self.assertTrue(settled.valid, settled.reasons)
        fact = settled.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["attempt_facts"]["repair-old-plan"]["lifecycle_state"], "cancelled")
        self.assertEqual(fact["frontier_attempt_id"], "repair-cancelp2")
        old_start = copy.deepcopy(ledger)
        start = copy.deepcopy(next(row for row in old_start["events"] if row["event_id"] == "evt-start-001"))
        start.update({"event_id": "evt-start-old-plan", "sequence": max(row["sequence"] for row in old_start["events"]) + 1, "repair_attempt_id": "repair-old-plan", "authorization_event_id": "evt-astra-old-plan", "started_at": "2026-09-08T08:15:00Z"})
        old_start["events"].append(start)
        result = validate_ledger(old_start, self.schema)
        self.assertFalse(result.valid)
        self.assertTrue(any(reason.startswith("auth:ownership_barrier") or reason.startswith("lc:terminal") for reason in result.reasons), result.reasons)

    def test_r005_analyzer_rejects_invalid_causal_members_before_metrics(self) -> None:
        """005-ANALYZER: metrics never receive malformed authorization facts."""
        invalid_escape = self.r004_control("A")
        self.r004_add_later_escape(invalid_escape, at="2026-09-08T08:13:57Z")
        self.assertEqual(next(event for event in invalid_escape["events"] if event["event_id"] == "evt-escape-002")["type"],
                         "escape-confirmed")
        self.assertEqual(next(activity for activity in invalid_escape["activities"] if activity["activity_id"] == "act-fix-successor")["completed_at"],
                         None)
        invalid_invalidator = self.r004_control("S")
        for row in invalid_invalidator["events"]:
            if row["sequence"] >= 12: row["sequence"] += 1
        index = next(i for i,row in enumerate(invalid_invalidator["events"]) if row["event_id"] == "evt-astra-001")
        invalid_invalidator["events"].insert(index, {"event_id": "evt-basis-analyzer-invalid", "sequence": 12, "at": "2026-09-08T08:13:45Z", "type": "basis-invalidated", "causal_refs": ["root-closed-001"], "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None, "review_basis_id": "basis-001", "cycle_id": None, "root_relationship": None, "escape_key": None})
        invalid_invalidator["roots"][0].update({"state": "blocked", "blocked_reason": "invalid adjudication epoch"})
        old_modern = self.r004_control("S")
        next(row for row in old_modern["repair_attempts"] if row["repair_attempt_id"] == "repair-001").pop("reservation_event_id")
        records = [
            {"ledger_id": "invalid-escape-crossing", "ledger": invalid_escape},
            {"ledger_id": "invalid-invalidator", "ledger": invalid_invalidator},
            {"ledger_id": "unsupported-old-modern", "ledger": old_modern},
        ]
        rejected = analyzer.validate_ledger_set(self.schema, records)
        self.assertIn("invalid-escape-crossing", rejected)
        self.assertTrue(any(reason.startswith("auth:crossing") for reason in rejected["invalid-escape-crossing"]), rejected)
        self.assertIn("invalid-invalidator", rejected)
        self.assertTrue(any(reason.startswith("auth:grant_binding") for reason in rejected["invalid-invalidator"]), rejected)
        self.assertIn("unsupported-old-modern", rejected)
        self.assertIn(f"compat:unsupported-modern-reservation-version:{old_modern['task']['task_instance_id']}", rejected["unsupported-old-modern"])

    def test_r004_reservation_execution_and_terminal_negatives(self) -> None:
        reserved = self.r004_control("P")
        # A reservation is not execution: adding the actual implementation
        # without an append-only start/settlement is rejected.
        source = self.r004_control("S")
        reserved["activities"].append(next(item for item in source["activities"] if item["activity_id"] == "act-fix-successor"))
        reserved["telemetry"]["recorded_participating_activity_count"] += 1
        reserved["telemetry"]["expected_participating_activity_count"] += 1
        result = validate_ledger(reserved, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("auth:chronology:root-closed-001:repair-001", result.reasons)

        invalid_grant = self.r004_control("S")
        next(item for item in invalid_grant["events"] if item["event_id"] == "evt-astra-001")["disposition"] = "rejected"
        result = validate_ledger(invalid_grant, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("auth:grant_binding:root-closed-001:repair-001", result.reasons)

        active_without_completion = self.r004_control("A")
        active_without_completion["events"].append({
            **next(item for item in self.r004_control("S")["events"] if item["event_id"] == "evt-settlement-001"),
            "terminal_outcome": "succeeded",
        })
        result = validate_ledger(active_without_completion, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("lc:terminal:root-closed-001:repair-001", result.reasons)

    def test_r004_unresolved_and_historical_named_controls(self) -> None:
        unresolved = validate_ledger(self.r004_control("U"), self.schema)
        self.assertTrue(unresolved.valid, unresolved.reasons)
        fact = unresolved.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["threshold_activation_status"], "unresolved")
        self.assertEqual(fact["gate_state"], "blocked")
        self.assertTrue(fact["awaiting_astra"])
        self.assertIn("threshold_activation_unresolved", fact["incomplete_reasons"])

        baseline_unknown = validate_ledger(self.r004_control("B0"), self.schema)
        self.assertTrue(baseline_unknown.valid, baseline_unknown.reasons)
        fact = baseline_unknown.facts["threshold_facts"]["root-closed-001"]
        self.assertIsNone(fact["threshold_applicable"])
        self.assertFalse(fact["baseline_resolved"])
        self.assertEqual(fact["gate_state"], "blocked")
        self.assertFalse(fact["closure_eligible"])
        self.assertIn("historical_baseline_unresolved", fact["incomplete_reasons"])

        historical = validate_ledger(self.r004_control("H0"), self.schema)
        self.assertTrue(historical.valid, historical.reasons)
        fact = historical.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["threshold_anchor_event_id"], "evt-historical-001")
        self.assertEqual(fact["decision_trigger_event_id"], "evt-historical-001")
        self.assertEqual(fact["threshold_activation_status"], "active")
        self.assertEqual(fact["gate_state"], "blocked")

        historical_success = validate_ledger(self.r004_control("HS"), self.schema)
        self.assertTrue(historical_success.valid, historical_success.reasons)
        fact = historical_success.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(fact["authorized_attempt_ids"], ["repair-001"])
        self.assertEqual(fact["attempt_facts"]["repair-001"]["grant_valid"], True)
        self.assertEqual(fact["gate_state"], "awaiting_post_repair_review")

    def test_r004_two_root_isolation_and_named_negatives(self) -> None:
        isolated = validate_ledger(self.r004_control("T2"), self.schema)
        self.assertTrue(isolated.valid, isolated.reasons)
        facts = isolated.facts["threshold_facts"]
        self.assertEqual(facts["root-closed-001"]["authorized_attempt_ids"], ["repair-001"])
        self.assertEqual(facts["root-closed-002"]["authorized_attempt_ids"], ["repair-002"])
        self.assertEqual(facts["root-closed-002"]["attempt_facts"]["repair-002"]["grant_event_id"], "evt-astra-002")

        execution_without_activation = self.r004_control("U")
        source = self.r004_control("S")
        execution_without_activation["events"].append(copy.deepcopy(next(item for item in source["events"] if item["event_id"] == "evt-start-001")))
        execution_without_activation["activities"].append(copy.deepcopy(next(item for item in source["activities"] if item["activity_id"] == "act-fix-successor")))
        execution_without_activation["telemetry"]["recorded_participating_activity_count"] += 1
        execution_without_activation["telemetry"]["expected_participating_activity_count"] += 1
        result = validate_ledger(execution_without_activation, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("auth:chronology:root-closed-001:repair-001", result.reasons)

        bad_anchor = self.r004_control("H0")
        bad_anchor["roots"][0]["threshold_anchor"]["historical_threshold_reconciled_event_id"] = "evt-baseline-001"
        result = validate_ledger(bad_anchor, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("auth:anchor:root-closed-001", result.reasons)

        prose = self.r004_control("B0")
        prose["roots"][0]["blocked_reason"] = "reports say at least two historic escapes"
        result = validate_ledger(prose, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertIsNone(result.facts["threshold_facts"]["root-closed-001"]["threshold_applicable"])

        cross_grant = self.r004_control("T2")
        attempt = next(item for item in cross_grant["repair_attempts"] if item["repair_attempt_id"] == "repair-002")
        attempt["expected_authorization_event_id"] = "evt-astra-001"
        result = validate_ledger(cross_grant, self.schema)
        self.assertFalse(result.valid)
        self.assertIn("auth:grant_binding:root-closed-002:repair-002", result.reasons)

    def test_r004_analyzer_uses_canonical_activation_partialness(self) -> None:
        for name in ("U", "B0"):
            record = {"ledger_id": f"r004-{name}", "ledger": self.r004_control(name)}
            self.assertEqual(analyzer.validate_ledger_set(self.schema, [record]), {})
            report = analyzer.calculate([record])
            self.assertTrue(report["partial"])
            self.assertIn("threshold_activation_unresolved", report["incomplete_reasons"])
        active = {"ledger_id": "r004-HS", "ledger": self.r004_control("HS")}
        self.assertEqual(analyzer.validate_ledger_set(self.schema, [active]), {})
        self.assertNotIn("threshold_activation_unresolved", analyzer.calculate([active])["incomplete_reasons"])

    def test_r004_generated_activity_state_times(self) -> None:
        """004-LCA: stable Cartesian controls; builders only mutate data."""
        starts = {"valid": "2026-09-08T08:13:52Z", "null": None}
        for status in ("running", "completed", "failed", "cancelled", "planned", "unknown"):
            for start_name, started_at in starts.items():
                for end_name in ("null", "before", "equal", "after"):
                    case_id = f"004-LCA-{status}-{start_name}-{end_name}"
                    ledger = self.r004_control("A")
                    activity = next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor")
                    activity["status"] = status
                    activity["started_at"] = started_at
                    if end_name == "null":
                        activity["completed_at"] = None
                    elif started_at is None:
                        activity["completed_at"] = "2026-09-08T08:13:53Z"
                    elif end_name == "before":
                        activity["completed_at"] = "2026-09-08T08:13:51Z"
                    elif end_name == "equal":
                        activity["completed_at"] = started_at
                    else:
                        activity["completed_at"] = "2026-09-08T08:13:53Z"
                    valid = (status == "running" and start_name == "valid" and end_name == "null") or (
                        status in {"completed", "failed", "cancelled"} and start_name == "valid" and end_name in {"equal", "after"}
                    )
                    result = validate_ledger(ledger, self.schema)
                    with self.subTest(case_id=case_id):
                        self.assertEqual(result.valid, valid, result.reasons)
                        if valid:
                            fact = result.facts["threshold_facts"]["root-closed-001"]
                            self.assertEqual(fact["attempt_facts"]["repair-001"]["lifecycle_state"], "active")
                            self.assertFalse(fact["attempt_facts"]["repair-001"]["completion_eligible"])
                        else:
                            self.assertTrue(any(reason.startswith(("lc:activity_state", "lc:activity_role", "activity_temporal", "schema:")) for reason in result.reasons), result.reasons)

    def test_r004_generated_reservation_state_times(self) -> None:
        """004-LCR: reservations are immutable planned records."""
        for status in ("planned", "running", "active", "closed", "succeeded", "failed", "unknown"):
            for started in (None, "2026-09-08T08:13:52Z"):
                for completed in (None, "2026-09-08T08:13:53Z"):
                    case_id = f"004-LCR-{status}-{'null' if started is None else 'valid'}-{'null' if completed is None else 'valid'}"
                    ledger = self.r004_control("P")
                    reservation = next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == "repair-001")
                    reservation.update({"status": status, "started_at": started, "completed_at": completed})
                    valid = status == "planned" and started is None and completed is None
                    result = validate_ledger(ledger, self.schema)
                    with self.subTest(case_id=case_id):
                        self.assertEqual(result.valid, valid, result.reasons)
                        if valid:
                            self.assertEqual(result.facts["threshold_facts"]["root-closed-001"]["attempt_facts"]["repair-001"]["lifecycle_state"], "planned")
                        else:
                            self.assertTrue(any(reason.startswith(("lc:attempt_record", "schema:")) for reason in result.reasons), result.reasons)

    def test_r004_generated_settlement_activity_states(self) -> None:
        """004-LCT: only succeeded/completed earns completion credit."""
        for outcome in ("succeeded", "failed", "superseded", "cancelled"):
            for status in ("running", "completed", "failed", "cancelled"):
                case_id = f"004-LCT-{outcome}-{status}"
                ledger = self.r004_control("S")
                activity = next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor")
                activity["status"] = status
                activity["completed_at"] = None if status == "running" else "2026-09-08T08:13:58Z"
                settlement = next(item for item in ledger["events"] if item["event_id"] == "evt-settlement-001")
                settlement["terminal_outcome"] = outcome
                valid = (outcome == "succeeded" and status == "completed") or (outcome != "succeeded" and status in {"completed", "failed", "cancelled"})
                if outcome != "succeeded":
                    ledger["roots"][0].update({"state": "blocked", "previous_state": "repairing", "blocked_reason": "terminal repair did not succeed"})
                result = validate_ledger(ledger, self.schema)
                with self.subTest(case_id=case_id):
                    self.assertEqual(result.valid, valid, result.reasons)
                    if valid:
                        attempt = result.facts["threshold_facts"]["root-closed-001"]["attempt_facts"]["repair-001"]
                        self.assertEqual(attempt["lifecycle_state"], outcome)
                        self.assertEqual(attempt["completion_eligible"], outcome == "succeeded")
                    else:
                        self.assertTrue(any(reason.startswith(("lc:terminal", "lc:activity_state", "schema:")) for reason in result.reasons), result.reasons)

    def test_r004_lifecycle_cases_001_through_016(self) -> None:
        cases: list[tuple[str, dict, bool, str]] = []
        cases.append(("004-LC-001", self.r004_control("A"), True, ""))
        review = self.r004_control("S"); next(item for item in review["activities"] if item["activity_id"] == "act-fix-successor")["type"] = "review"
        cases.append(("004-LC-002", review, False, "lc:activity_role"))
        running = self.r004_control("S"); next(item for item in running["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "running", "completed_at": None})
        cases.append(("004-LC-003", running, False, "lc:terminal"))
        running_end = self.r004_control("S"); next(item for item in running_end["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "running", "completed_at": "2026-09-08T08:13:58Z"})
        cases.append(("004-LC-004", running_end, False, "lc:activity_state"))
        no_start = self.r004_control("S"); no_start["events"] = [event for event in no_start["events"] if event["event_id"] != "evt-start-001"]
        cases.append(("004-LC-005", no_start, False, "lc:terminal"))
        two_start = self.r004_control("S"); duplicate = copy.deepcopy(next(event for event in two_start["events"] if event["event_id"] == "evt-start-001")); duplicate.update({"event_id": "evt-start-002", "sequence": 13, "at": "2026-09-08T08:14:01Z"}); two_start["events"].append(duplicate)
        cases.append(("004-LC-006", two_start, False, "lc:terminal"))
        two_settlement = self.r004_control("S"); duplicate = copy.deepcopy(next(event for event in two_settlement["events"] if event["event_id"] == "evt-settlement-001")); duplicate.update({"event_id": "evt-settlement-002", "sequence": 13, "at": "2026-09-08T08:14:01Z"}); two_settlement["events"].append(duplicate)
        cases.append(("004-LC-007", two_settlement, False, "lc:terminal"))
        after_settlement = self.r004_control("S"); attempt = next(item for item in after_settlement["repair_attempts"] if item["repair_attempt_id"] == "repair-001"); grant = next(event for event in after_settlement["events"] if event["event_id"] == "evt-astra-001"); attempt["implementation_activity_ids"].append("act-fix-late"); grant["implementation_activity_ids"].append("act-fix-late"); late = copy.deepcopy(next(item for item in after_settlement["activities"] if item["activity_id"] == "act-fix-successor")); late.update({"activity_id": "act-fix-late", "started_at": "2026-09-08T08:14:01Z", "completed_at": "2026-09-08T08:14:02Z"}); after_settlement["activities"].append(late); after_settlement["telemetry"]["recorded_participating_activity_count"] += 1; after_settlement["telemetry"]["expected_participating_activity_count"] += 1
        cases.append(("004-LC-008", after_settlement, False, "lc:terminal"))
        pre_cancel = self.r004_control("P"); template = next(event for event in self.r004_control("S")["events"] if event["event_id"] == "evt-settlement-001"); template.update({"start_event_id": None, "terminal_outcome": "cancelled", "mutation_finished_at": None, "causal_refs": ["root-closed-001", "repair-001", "basis-001"]}); pre_cancel["events"].append(template)
        cases.append(("004-LC-009", pre_cancel, True, ""))
        pre_success = self.r004_control("P"); template = next(event for event in self.r004_control("S")["events"] if event["event_id"] == "evt-settlement-001"); template.update({"start_event_id": None, "terminal_outcome": "succeeded", "mutation_finished_at": None, "causal_refs": ["root-closed-001", "repair-001", "basis-001"]}); pre_success["events"].append(template)
        cases.append(("004-LC-010", pre_success, False, "lc:terminal"))
        no_impl = self.r004_control("S"); no_impl["activities"] = [item for item in no_impl["activities"] if item["activity_id"] != "act-fix-successor"]
        cases.append(("004-LC-011", no_impl, False, "lc:terminal"))
        before_start = self.r004_control("S"); next(item for item in before_start["activities"] if item["activity_id"] == "act-fix-successor")["started_at"] = "2026-09-08T08:13:51Z"
        cases.append(("004-LC-012", before_start, False, "lc:window"))
        after_end = self.r004_control("S"); next(item for item in after_end["activities"] if item["activity_id"] == "act-fix-successor")["completed_at"] = "2026-09-08T08:14:01Z"
        cases.append(("004-LC-013", after_end, False, "lc:window"))
        wrong_max = self.r004_control("S"); next(event for event in wrong_max["events"] if event["event_id"] == "evt-settlement-001")["mutation_finished_at"] = "2026-09-08T08:13:57Z"
        cases.append(("004-LC-014", wrong_max, False, "lc:terminal"))
        candidate = self.r004_control("A"); next(item for item in candidate["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "completed", "completed_at": "2026-09-08T08:13:58Z"}); candidate["events"].append(copy.deepcopy(next(event for event in self.r004_control("S")["events"] if event["event_id"] == "evt-settlement-001"))); candidate["roots"][0].update({"state": "awaiting_post_repair_review", "previous_state": "repairing"})
        cases.append(("004-LC-015", candidate, True, ""))
        resumed = self.r004_control("S"); next(item for item in resumed["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "running", "completed_at": None})
        cases.append(("004-LC-016", resumed, False, "lc:terminal"))

        for case_id, ledger, valid, prefix in cases:
            previous = self.r004_control("A") if case_id == "004-LC-015" else (self.r004_control("S") if case_id == "004-LC-016" else None)
            result = validate_ledger(ledger, self.schema, previous)
            with self.subTest(case_id=case_id):
                self.assertEqual(result.valid, valid, result.reasons)
                if prefix:
                    self.assertTrue(any(reason.startswith(prefix) for reason in result.reasons), result.reasons)

    def test_r004_previous_snapshot_append_only_controls(self) -> None:
        previous = self.r004_control("S")
        self.assertTrue(validate_ledger(copy.deepcopy(previous), self.schema, previous).valid)

        changed_event = copy.deepcopy(previous)
        next(event for event in changed_event["events"] if event["event_id"] == "evt-astra-001")["at"] = "2026-09-08T08:13:52Z"
        result = validate_ledger(changed_event, self.schema, previous)
        self.assertFalse(result.valid)
        self.assertIn("event:immutable:evt-astra-001", result.reasons)

        changed_reservation = copy.deepcopy(previous)
        next(item for item in changed_reservation["repair_attempts"] if item["repair_attempt_id"] == "repair-001")["created_at"] = "2026-09-08T08:13:40Z"
        result = validate_ledger(changed_reservation, self.schema, previous)
        self.assertFalse(result.valid)
        self.assertIn("lc:terminal:root-closed-001:repair-001", result.reasons)

        changed_anchor = copy.deepcopy(previous)
        changed_anchor["roots"][0]["first_threshold_activation_event_id"] = None
        result = validate_ledger(changed_anchor, self.schema, previous)
        self.assertFalse(result.valid)
        self.assertIn("auth:activation_immutable:root-closed-001", result.reasons)

        changed_adoption = copy.deepcopy(previous)
        changed_adoption["cutover"]["protocol_adopted_at"] = "2026-09-08T08:13:36Z"
        result = validate_ledger(changed_adoption, self.schema, previous)
        self.assertFalse(result.valid)
        self.assertIn("auth:activation_immutable:cutover:protocol_adopted_at", result.reasons)

        active = self.r004_control("A")
        settled = copy.deepcopy(active)
        next(item for item in settled["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "completed", "completed_at": "2026-09-08T08:13:58Z"})
        settled["events"].append(copy.deepcopy(next(event for event in self.r004_control("S")["events"] if event["event_id"] == "evt-settlement-001")))
        settled["roots"][0].update({"state": "awaiting_post_repair_review", "previous_state": "repairing"})
        self.assertTrue(validate_ledger(settled, self.schema, active).valid)

        resumed = copy.deepcopy(previous)
        next(item for item in resumed["activities"] if item["activity_id"] == "act-fix-successor").update({"status": "running", "completed_at": None})
        result = validate_ledger(resumed, self.schema, previous)
        self.assertFalse(result.valid)
        self.assertIn("lc:terminal:root-closed-001:repair-001:act-fix-successor", result.reasons)

    def test_r004_ownership_table_001_through_013(self) -> None:
        """004-OWN controls keep every affected attempt visible to facts."""
        cases: list[tuple[str, dict, bool, str]] = []
        for case_id in ("004-OWN-001", "004-OWN-002", "004-OWN-003"):
            ledger = self.r004_control("S"); self.r004_add_fresh_attempt(ledger, suffix=case_id[-3:])
            grant_id = f"evt-astra-{case_id[-3:]}"
            ledger["events"] = [item for item in ledger["events"] if item["event_id"] != grant_id]
            ledger["roots"][0].update({"state": "blocked", "previous_state": "repairing", "blocked_reason": "unapproved attempt"})
            cases.append((case_id, ledger, False, "auth:chronology"))
        unowned = self.r004_control("S"); activity = copy.deepcopy(next(item for item in unowned["activities"] if item["activity_id"] == "act-fix-successor")); activity.update({"activity_id": "act-unowned", "repair_attempt_id": None, "repair_attempt_bindings": [], "started_at": "2026-09-08T08:14:01Z", "completed_at": "2026-09-08T08:14:02Z"}); unowned["activities"].append(activity); unowned["telemetry"]["recorded_participating_activity_count"] += 1; unowned["telemetry"]["expected_participating_activity_count"] += 1; unowned["roots"][0].update({"state": "blocked", "blocked_reason": "unowned mutation"})
        cases.append(("004-OWN-004", unowned, False, "auth:ownership"))
        relabel = self.r004_control("S"); attempt = next(item for item in relabel["repair_attempts"] if item["repair_attempt_id"] == "repair-001"); grant = next(item for item in relabel["events"] if item["event_id"] == "evt-astra-001"); attempt.update({"implementation_activity_ids": [], "verification_activity_ids": ["act-fix-successor"]}); grant["implementation_activity_ids"] = []
        cases.append(("004-OWN-005", relabel, False, "lc:link"))
        dual = self.r004_control("S"); next(item for item in dual["repair_attempts"] if item["repair_attempt_id"] == "repair-001")["verification_activity_ids"] = ["act-fix-successor"]
        cases.append(("004-OWN-006", dual, False, "lc:attempt_record"))
        absent = self.r004_control("S"); next(item for item in absent["repair_attempts"] if item["repair_attempt_id"] == "repair-001")["implementation_activity_ids"] = []
        cases.append(("004-OWN-007", absent, False, "lc:link"))
        wrong_attempt = self.r004_control("S"); next(item for item in wrong_attempt["activities"] if item["activity_id"] == "act-fix-successor")["repair_attempt_bindings"] = [{"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-wrong"}]
        cases.append(("004-OWN-008", wrong_attempt, False, "lc:activity_role"))

        shared = self.r004_control("T2")
        second = next(item for item in shared["repair_attempts"] if item["repair_attempt_id"] == "repair-002")
        second["implementation_activity_ids"] = ["act-fix-successor"]
        second_grant = next(item for item in shared["events"] if item["event_id"] == "evt-astra-002"); second_grant["implementation_activity_ids"] = ["act-fix-successor"]
        shared["activities"] = [item for item in shared["activities"] if item["activity_id"] != "act-fix-successor-002"]
        shared_activity = next(item for item in shared["activities"] if item["activity_id"] == "act-fix-successor")
        shared_activity.update({"attribution_mode": "shared", "root_cause_ids": ["root-closed-001", "root-closed-002"], "repair_attempt_id": None,
                                "repair_attempt_bindings": [{"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-001"}, {"root_cause_id": "root-closed-002", "repair_attempt_id": "repair-002"}]})
        # Interleave the two actual starts/settlements so the one shared
        # activity has a truthful interval for both roots.
        shared_activity.update({"started_at": "2026-09-08T08:24:00Z", "completed_at": "2026-09-08T08:24:06Z"})
        for root_suffix in ("001", "002"):
            start_event = next(item for item in shared["events"] if item["event_id"] == f"evt-start-{root_suffix}")
            start_event.update({"at": "2026-09-08T08:24:00Z", "started_at": "2026-09-08T08:24:00Z"})
            if root_suffix == "002":
                start_event["implementation_activity_ids"] = ["act-fix-successor"]
                start_event["causal_refs"] = [
                    "act-fix-successor" if item == "act-fix-successor-002" else item
                    for item in start_event["causal_refs"]
                ]
            settlement = next(item for item in shared["events"] if item["event_id"] == f"evt-settlement-{root_suffix}")
            settlement.update({"at": "2026-09-08T08:24:10Z", "settled_at": "2026-09-08T08:24:10Z", "mutation_finished_at": "2026-09-08T08:24:06Z"})
        next(item for item in shared["events"] if item["event_id"] == "evt-settlement-002")["causal_refs"] = ["root-closed-002", "repair-002", "evt-start-002", "act-fix-successor", "basis-002"]
        shared["events"].sort(key=lambda item: (item["at"], item["event_id"]))
        for number, event in enumerate(shared["events"], 1): event["sequence"] = number
        shared["telemetry"]["recorded_participating_activity_count"] = len(shared["activities"]); shared["telemetry"]["expected_participating_activity_count"] = len(shared["activities"])
        cases.append(("004-OWN-009", shared, True, ""))
        missing_shared = copy.deepcopy(shared); next(item for item in missing_shared["activities"] if item["activity_id"] == "act-fix-successor")["repair_attempt_bindings"] = [{"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-001"}]
        cases.append(("004-OWN-010", missing_shared, False, "auth:ownership"))
        unapproved_shared = copy.deepcopy(shared); next(item for item in unapproved_shared["repair_attempts"] if item["repair_attempt_id"] == "repair-002")["expected_authorization_event_id"] = "evt-astra-001"
        cases.append(("004-OWN-011", unapproved_shared, False, "auth:grant_binding"))
        same_root = self.r004_control("S"); self.r004_add_fresh_attempt(same_root, suffix="same"); next(item for item in same_root["repair_attempts"] if item["repair_attempt_id"] == "repair-same")["implementation_activity_ids"] = ["act-fix-successor"]; next(item for item in same_root["events"] if item["event_id"] == "evt-astra-same")["implementation_activity_ids"] = ["act-fix-successor"]
        cases.append(("004-OWN-012", same_root, False, "lc:activity_role"))
        cross = self.r004_control("A"); self.r004_add_later_escape(cross, at="2026-09-08T08:13:57Z"); next(item for item in cross["activities"] if item["activity_id"] == "act-fix-successor")["completed_at"] = "2026-09-08T08:13:58Z"
        cases.append(("004-OWN-013", cross, False, "auth:crossing"))

        for case_id, ledger, valid, prefix in cases:
            result = validate_ledger(ledger, self.schema)
            with self.subTest(case_id=case_id):
                self.assertEqual(result.valid, valid, result.reasons)
                if prefix:
                    self.assertTrue(any(reason.startswith(prefix) for reason in result.reasons), result.reasons)

    def test_r004_activation_boundary_generator(self) -> None:
        """004-BOUNDARY: whole-before is historical; equality is not a grant."""
        intervals = {
            "before": ("2026-09-08T08:13:32Z", "2026-09-08T08:13:34Z", True, ""),
            "ends_exactly": ("2026-09-08T08:13:32Z", "2026-09-08T08:13:35Z", True, ""),
            "starts_exactly": ("2026-09-08T08:13:35Z", "2026-09-08T08:13:36Z", False, "auth:chronology"),
            "spanning": ("2026-09-08T08:13:34Z", "2026-09-08T08:13:36Z", False, "auth:crossing"),
            "after": ("2026-09-08T08:13:36Z", "2026-09-08T08:13:37Z", False, "auth:chronology"),
        }
        for relation, (started, completed, valid, prefix) in intervals.items():
            ledger = self.r004_control("S")
            activity = copy.deepcopy(next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor"))
            activity.update({"activity_id": f"act-boundary-{relation}", "repair_attempt_id": None, "repair_attempt_bindings": [],
                             "started_at": started, "completed_at": completed})
            ledger["activities"].append(activity); ledger["telemetry"]["recorded_participating_activity_count"] += 1; ledger["telemetry"]["expected_participating_activity_count"] += 1
            if not valid:
                ledger["roots"][0].update({"state": "blocked", "blocked_reason": "boundary mutation lacks permission"})
            result = validate_ledger(ledger, self.schema)
            with self.subTest(case_id=f"004-BOUNDARY-{relation}"):
                self.assertEqual(result.valid, valid, result.reasons)
                if prefix:
                    fact = result.facts["threshold_facts"]["root-closed-001"]
                    self.assertIn(f"act-boundary-{relation}", fact["mutation_activity_ids"])
                    self.assertIn(f"act-boundary-{relation}", fact["uncovered_mutation_activity_ids"])
                    self.assertTrue(any(reason.startswith(prefix) for reason in result.reasons), result.reasons)

    def test_r004_invalidation_table_001_through_013(self) -> None:
        """004-INV: a later boundary revokes future mutation, never history."""
        cases: list[tuple[str, dict, bool, str]] = []
        stale = self.r004_control("S"); self.r004_add_later_escape(stale); self.r004_add_fresh_attempt(stale, suffix="stale")
        next(item for item in stale["repair_attempts"] if item["repair_attempt_id"] == "repair-stale")["expected_authorization_event_id"] = "evt-astra-001"
        next(item for item in stale["events"] if item["event_id"] == "evt-start-stale")["authorization_event_id"] = "evt-astra-001"
        stale["roots"][0].update({"state": "blocked", "blocked_reason": "stale grant"})
        cases.append(("004-INV-001", stale, False, "auth:grant_binding"))
        later_escape = self.r004_control("S"); self.r004_add_later_escape(later_escape)
        cases.append(("004-INV-002", later_escape, True, ""))
        crossing = self.r004_control("A"); self.r004_add_later_escape(crossing, at="2026-09-08T08:13:57Z"); next(item for item in crossing["activities"] if item["activity_id"] == "act-fix-successor")["completed_at"] = "2026-09-08T08:13:58Z"
        cases.append(("004-INV-003", crossing, False, "auth:crossing"))
        running_cross = self.r004_control("A"); self.r004_add_later_escape(running_cross, at="2026-09-08T08:13:57Z")
        cases.append(("004-INV-004", running_cross, False, "auth:crossing"))
        verify_only = self.r004_control("S"); self.r004_add_later_escape(verify_only)
        cases.append(("004-INV-005", verify_only, True, ""))
        hidden = self.r004_control("A"); self.r004_add_later_escape(hidden, at="2026-09-08T08:13:57Z"); activity = next(item for item in hidden["activities"] if item["activity_id"] == "act-fix-successor"); activity.update({"type": "review", "completed_at": "2026-09-08T08:13:58Z"})
        cases.append(("004-INV-006", hidden, False, "auth:crossing"))
        crossed_success = self.r004_control("A"); self.r004_add_later_escape(crossed_success, at="2026-09-08T08:13:57Z"); activity = next(item for item in crossed_success["activities"] if item["activity_id"] == "act-fix-successor"); activity.update({"status": "completed", "completed_at": "2026-09-08T08:13:58Z"}); crossed_success["events"].append(copy.deepcopy(next(item for item in self.r004_control("S")["events"] if item["event_id"] == "evt-settlement-001")))
        cases.append(("004-INV-007", crossed_success, False, "auth:crossing"))
        cases.append(("004-INV-008", self.r004_control("S"), True, ""))
        basis_stale = self.r004_control("S"); basis_stale["events"].append({"event_id": "evt-basis-002", "sequence": max(item["sequence"] for item in basis_stale["events"]) + 1, "at": "2026-09-08T08:14:10Z", "type": "basis-invalidated", "causal_refs": ["root-closed-001"], "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None, "review_basis_id": "basis-001", "cycle_id": None, "root_relationship": None, "escape_key": None}); basis_stale["roots"][0].update({"state": "blocked", "blocked_reason": "basis invalidated"})
        cases.append(("004-INV-009", basis_stale, True, ""))
        cases.append(("004-INV-010", running_cross, False, "auth:crossing"))
        cases.append(("004-INV-011", later_escape, True, ""))
        cases.append(("004-INV-012", basis_stale, True, ""))
        cases.append(("004-INV-013", self.r004_control("P"), True, ""))
        for case_id, ledger, valid, prefix in cases:
            result = validate_ledger(ledger, self.schema)
            with self.subTest(case_id=case_id):
                self.assertEqual(result.valid, valid, result.reasons)
                fact = result.facts["threshold_facts"]["root-closed-001"]
                self.assertEqual(fact["gate_state"], ledger["roots"][0]["state"])
                if prefix:
                    self.assertTrue(any(reason.startswith(prefix) for reason in result.reasons), result.reasons)

    def test_r004_frontier_table_001_through_010(self) -> None:
        """004-FRONT: facts choose the current authorization frontier."""
        failed = self.r004_control("S"); next(item for item in failed["events"] if item["event_id"] == "evt-settlement-001")["terminal_outcome"] = "failed"; failed["roots"][0].update({"state": "blocked", "blocked_reason": "failed repair"})
        fresh_unused = copy.deepcopy(failed); self.r004_add_fresh_attempt(fresh_unused, suffix="front006")
        fresh_unused["events"] = [item for item in fresh_unused["events"] if item["event_id"] not in {"evt-start-front006", "evt-settlement-front006"}]
        fresh_unused["activities"] = [item for item in fresh_unused["activities"] if item["activity_id"] != "act-fix-front006"]
        fresh_unused["roots"][0].update({"state": "open", "previous_state": "blocked", "blocked_reason": None})
        fresh_unused["telemetry"]["recorded_participating_activity_count"] = len(fresh_unused["activities"]); fresh_unused["telemetry"]["expected_participating_activity_count"] = len(fresh_unused["activities"])
        self.assertEqual(next(item for item in fresh_unused["events"] if item["event_id"] == "evt-astra-front006")["repair_attempt_id"], "repair-front006")
        missing_fresh_grant = copy.deepcopy(fresh_unused); missing_fresh_grant["events"] = [item for item in missing_fresh_grant["events"] if item["event_id"] != "evt-astra-front006"]
        missing_fresh_grant["roots"][0].update({"state": "blocked", "blocked_reason": "P2 grant removed"})
        p2_success = copy.deepcopy(failed); self.r004_add_fresh_attempt(p2_success, suffix="front008")
        self.assertEqual(next(item for item in p2_success["events"] if item["event_id"] == "evt-settlement-front008")["terminal_outcome"], "succeeded")
        controls = {
            "004-FRONT-001": (self.r004_control("W"), "blocked", True, True),
            "004-FRONT-002": (self.r004_control("P"), "open", False, True),
            "004-FRONT-003": (self.r004_control("A"), "repairing", False, True),
            "004-FRONT-004": (self.r004_control("S"), "awaiting_post_repair_review", False, True),
            "004-FRONT-005": (failed, "blocked", True, True),
            "004-FRONT-006": (fresh_unused, "open", False, True),
            "004-FRONT-007": (missing_fresh_grant, "blocked", True, False),
            "004-FRONT-008": (p2_success, "awaiting_post_repair_review", False, True),
            "004-FRONT-009": (self.r004_control("S"), "awaiting_post_repair_review", False, True),
            "004-FRONT-010": (self.r004_control("T2"), "awaiting_post_repair_review", False, True),
        }
        for case_id, (ledger, state, awaiting, valid) in controls.items():
            result = validate_ledger(ledger, self.schema)
            with self.subTest(case_id=case_id):
                self.assertEqual(result.valid, valid, result.reasons)
                fact = result.facts["threshold_facts"]["root-closed-001"]
                self.assertEqual(fact["gate_state"], state)
                self.assertEqual(fact["awaiting_astra"], awaiting)

    def test_r004_closure_table_001_through_014(self) -> None:
        """004-CLOSE: modern closure evidence is scoped to the live frontier epoch."""
        valid = self.r004_control("S"); self.r004_close_current_epoch(valid)
        result = validate_ledger(valid, self.schema)
        self.assertTrue(result.valid, result.reasons)
        facts = result.facts["threshold_facts"]["root-closed-001"]
        self.assertEqual(facts["gate_state"], "closed_verified")
        self.assertTrue(facts["closure_eligible"])
        self.assertEqual(facts["frontier_attempt_id"], "repair-001")

        before = copy.deepcopy(valid)
        next(item for item in before["test_evidence"] if item["test_evidence_id"] == "test-modern-original-001")["executed_at"] = "2026-09-08T08:13:57Z"
        overlap = copy.deepcopy(valid)
        next(item for item in overlap["test_evidence"] if item["test_evidence_id"] == "test-modern-sibling-001")["identity"] = next(item for item in overlap["test_evidence"] if item["test_evidence_id"] == "test-modern-exact-001")["identity"]
        absent = copy.deepcopy(valid)
        next(item for item in absent["cycles"] if item["cycle_id"] == "cycle-post-modern-001")["activity_ids"].remove("act-probe-exact-001")
        wrong_terra = copy.deepcopy(valid)
        next(item for item in wrong_terra["activities"] if item["activity_id"] == "act-post-review-001")["actual"]["model"] = "gpt-5.6-sol"
        skipped = copy.deepcopy(valid)
        earlier_activity = copy.deepcopy(next(item for item in skipped["activities"] if item["activity_id"] == "act-unchanged-review-001"))
        earlier_activity.update({"activity_id": "act-unchanged-earlier", "started_at": "2026-09-08T08:14:12Z", "completed_at": "2026-09-08T08:14:12Z"})
        skipped["activities"].append(earlier_activity)
        following = next(item for item in skipped["cycles"] if item["cycle_id"] == "cycle-unchanged-modern-001"); following["sequence"] = 7
        skipped["cycles"].insert(-1, {"cycle_id": "cycle-unchanged-earlier", "sequence": 6, "started_at": "2026-09-08T08:14:11Z", "completed_at": "2026-09-08T08:14:12Z", "complete": True, "review_basis_id": "basis-001", "activity_ids": ["act-unchanged-earlier"], "kind": "unchanged-closure"})
        stale_repair = copy.deepcopy(valid); self.r004_add_fresh_attempt(stale_repair, suffix="002")
        stale_repair["roots"][0].update({"state": "closed_verified", "previous_state": "closure_pending"})
        stale_escape = copy.deepcopy(valid); self.r004_add_later_escape(stale_escape); stale_escape["roots"][0]["state"] = "closed_verified"
        old_probe = copy.deepcopy(valid); self.r004_add_later_escape(old_probe); self.r004_add_fresh_attempt(old_probe, suffix="002")
        old_probe["roots"][0].update({"state": "closed_verified", "previous_state": "closure_pending", "blocked_reason": None})
        unsettled = copy.deepcopy(valid); self.r004_add_fresh_attempt(unsettled, suffix="002", outcome=None); unsettled["roots"][0]["state"] = "closed_verified"
        cases = {
            "004-CLOSE-002": (before, "closure:epoch"), "004-CLOSE-003": (overlap, "closure_probe_identity_overlap"),
            "004-CLOSE-004": (absent, "closure:epoch"), "004-CLOSE-005": (wrong_terra, "closure_post_repair_terra_route"),
            "004-CLOSE-006": (skipped, "closure_first_subsequent_skipped"), "004-CLOSE-007": (stale_repair, "closure:epoch"),
            "004-CLOSE-008": (stale_escape, "closure:epoch"), "004-CLOSE-009": (stale_escape, "closure:epoch"),
            "004-CLOSE-012": (old_probe, "closure:epoch"), "004-CLOSE-013": (unsettled, "closure:epoch"),
        }
        for case_id, (ledger, reason) in cases.items():
            with self.subTest(case_id=case_id):
                outcome = validate_ledger(ledger, self.schema)
                self.assertFalse(outcome.valid, outcome.reasons)
                self.assertTrue(any(item.startswith(reason) for item in outcome.reasons), outcome.reasons)
        # 010: a real escape opens a new epoch; P2 has fresh grant, probes,
        # Terra review, and unchanged review.  It is not a relabelled P1.
        close010 = self.r004_control("S"); self.r004_add_later_escape(close010); self.r004_add_fresh_attempt(close010, suffix="close010")
        self.r004_close_current_epoch(close010, suffix="close010")
        self.assertEqual(next(row for row in close010["events"] if row["event_id"] == "evt-escape-002")["type"], "escape-confirmed")
        self.assertEqual(close010["roots"][0]["closure_gate"]["repair_attempt_id"], "repair-close010")
        outcome = validate_ledger(close010, self.schema)
        self.assertTrue(outcome.valid, outcome.reasons)
        self.assertEqual(outcome.facts["threshold_facts"]["root-closed-001"]["frontier_attempt_id"], "repair-close010")
        # 011: a basis invalidation creates a newer authorization epoch, then
        # a fresh P2 supplies the only closure-eligible implementation.
        close011 = self.r004_control("S")
        new_basis = copy.deepcopy(next(row for row in close011["review_bases"] if row["review_basis_id"] == "basis-001")); new_basis["review_basis_id"] = "basis-close011"; close011["review_bases"].append(new_basis)
        changed_activity = copy.deepcopy(next(row for row in close011["activities"] if row["activity_id"] == "act-review-001")); changed_activity.update({"activity_id": "act-basis-close011", "review_basis_id": "basis-close011", "started_at": "2026-09-08T08:14:08Z", "completed_at": "2026-09-08T08:14:09Z"}); close011["activities"].append(changed_activity)
        close011["cycles"].append({"cycle_id": "cycle-basis-close011", "sequence": max(row["sequence"] for row in close011["cycles"]) + 1, "started_at": "2026-09-08T08:14:08Z", "completed_at": "2026-09-08T08:14:09Z", "complete": True, "review_basis_id": "basis-close011", "activity_ids": ["act-basis-close011"], "kind": "post-repair"})
        close011["events"].append({"event_id": "evt-basis-close011", "sequence": max(row["sequence"] for row in close011["events"]) + 1, "at": "2026-09-08T08:14:10Z", "type": "basis-invalidated", "causal_refs": ["root-closed-001", "cycle-basis-close011"], "root_cause_id": "root-closed-001", "observation_id": None, "repair_attempt_id": None, "review_basis_id": "basis-close011", "cycle_id": None, "root_relationship": None, "escape_key": None})
        close011["roots"][0].update({"state": "blocked", "blocked_reason": "basis invalidated"})
        self.r004_add_fresh_attempt(close011, suffix="close011")
        for row in close011["repair_attempts"]:
            if row["repair_attempt_id"] == "repair-close011": row.update({"review_basis_id": "basis-close011", "authorization_basis_id": "basis-close011"})
        for row in close011["events"]:
            if row.get("repair_attempt_id") == "repair-close011":
                if row.get("review_basis_id") == "basis-001": row["review_basis_id"] = "basis-close011"
                row["causal_refs"] = ["basis-close011" if item == "basis-001" else item for item in row.get("causal_refs", [])]
                if row["type"] == "astra-adjudicated": row["authorization_basis_id"] = "basis-close011"
        self.r004_close_current_epoch(close011, suffix="close011")
        self.assertEqual(next(row for row in close011["events"] if row["event_id"] == "evt-basis-close011")["type"], "basis-invalidated")
        self.assertEqual(next(row for row in close011["repair_attempts"] if row["repair_attempt_id"] == "repair-close011")["authorization_epoch_event_id"], "evt-basis-close011")
        outcome = validate_ledger(close011, self.schema)
        self.assertTrue(outcome.valid, outcome.reasons)
        self.assertEqual(outcome.facts["threshold_facts"]["root-closed-001"]["frontier_attempt_id"], "repair-close011")
        # 014: P1 stops before P2 reservation but its terminal settlement is
        # appended last.  Its delayed append must not replace P2's closure.
        close014 = self.r004_control("S")
        self.r004_add_later_escape(close014); self.r004_add_fresh_attempt(close014, suffix="close014")
        p1_settlement = next(row for row in close014["events"] if row["event_id"] == "evt-settlement-001")
        close014["events"].remove(p1_settlement)
        p1_settlement.update({"sequence": max(row["sequence"] for row in close014["events"]) + 20, "at": "2026-09-08T08:15:30Z"})
        close014["events"].append(p1_settlement)
        self.assertEqual(close014["events"][-1]["event_id"], "evt-settlement-001")
        self.r004_close_current_epoch(close014, suffix="close014")
        self.assertEqual(close014["roots"][0]["closure_gate"]["repair_attempt_id"], "repair-close014")
        outcome = validate_ledger(close014, self.schema)
        self.assertTrue(outcome.valid, outcome.reasons)
        self.assertEqual(outcome.facts["threshold_facts"]["root-closed-001"]["frontier_attempt_id"], "repair-close014")

    def test_r004_compatibility_table_001_through_013_and_dom_golden(self) -> None:
        """004-COMPAT: the exact DOM history remains finite and nonauthorizing."""
        dom_path = Path("/Users/ivanf/Desktop/domido-4/domido-web-app-DOMIDO-535/.mas1/tasks/01a05948-96a2-7313-9b38-5478600abe0b/finding-ledger.v1.json")
        raw = dom_path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "dd35785c3dc95636e16e65845612590c413620153401f4e62bb18b2d598d73fa")
        dom = json.loads(raw)
        canonical = json.dumps(dom, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), "a5043c22520d864c406b970f51ea5f738c144566d8b08fe98292e367ef45c37c")
        outcome = validate_ledger(dom, self.schema)
        self.assertTrue(outcome.valid, outcome.reasons)
        self.assertIsNone(outcome.facts["threshold_facts"]["SEC14-LIFETIME-OWNERSHIP"]["lifetime_count"])
        # 002/003 retain the event/cycle representation verbatim; 005 accepts
        # equal canonical and legacy evidence while 006 rejects contradiction.
        reconciliation = next(item for item in dom["events"] if item.get("type") == "historical-threshold-reconciled")
        equal = copy.deepcopy(dom); equal_event = next(item for item in equal["events"] if item.get("event_id") == reconciliation["event_id"])
        equal_event["evidence_refs"] = list(equal_event["historical_evidence_refs"])
        self.assertTrue(validate_ledger(equal, self.schema).valid)
        conflict = copy.deepcopy(equal); next(item for item in conflict["events"] if item.get("event_id") == reconciliation["event_id"])["evidence_refs"] = ["conflict-evidence"]
        bad = validate_ledger(conflict, self.schema)
        self.assertFalse(bad.valid); self.assertTrue(any(item.startswith("compat:conflict") for item in bad.reasons), bad.reasons)
        unknown_status = copy.deepcopy(dom); unknown_status["repair_attempts"][0]["status"] = "completed-but-not-a-status"
        self.assertFalse(validate_ledger(unknown_status, self.schema).valid)
        inherited = copy.deepcopy(dom)
        inherited["repair_attempts"][0].update({"started_at": "2026-09-08T13:30:00Z", "completed_at": "2026-09-08T13:30:01Z"})
        # 004-COMPAT-004: a historical Astra record cannot become a
        # post-adoption authorization merely by moving its legacy attempt.
        self.assertFalse(validate_ledger(inherited, self.schema).valid)
        moved_mutation = copy.deepcopy(dom)
        old_mutation = next(item for item in moved_mutation["activities"] if item.get("type") == "implementation")
        old_mutation.update({"started_at": "2026-09-08T13:30:00Z", "completed_at": "2026-09-08T13:30:01Z"})
        # 004-COMPAT-008: historical eligibility is bounded by the original
        # adoption boundary, not a user-controlled legacy label.
        self.assertFalse(validate_ledger(moved_mutation, self.schema).valid)
        canonical_activation = copy.deepcopy(dom)
        canonical_root = next(item for item in canonical_activation["roots"] if item["root_cause_id"] == "SEC14-REDACTION-BOUNDARY")
        canonical_root["first_threshold_activation_event_id"] = "EVT-SEC14-REDACTION-ACTIVATED-CANONICAL"
        canonical_root["historical_baseline_reconciliation_event_id"] = reconciliation["event_id"]
        canonical_activation["events"].append({
            "event_id": "EVT-SEC14-REDACTION-ACTIVATED-CANONICAL", "sequence": max(item["sequence"] for item in dom["events"]) + 1,
            "at": "2026-09-08T13:30:00Z", "type": "threshold-activated", "root_cause_id": canonical_root["root_cause_id"],
            "activation_anchor_event_id": reconciliation["event_id"], "first_threshold_known_at": reconciliation["at"],
            "original_protocol_adopted_at": dom["cutover"]["protocol_adopted_at"], "effective_at": dom["cutover"]["protocol_adopted_at"],
            "historical_baseline_reconciliation_event_id": reconciliation["event_id"], "evidence_refs": list(reconciliation["historical_evidence_refs"]),
            "causal_refs": [canonical_root["root_cause_id"], reconciliation["event_id"]], "observation_id": None,
            "repair_attempt_id": None, "review_basis_id": None, "cycle_id": None, "root_relationship": None, "escape_key": None,
        })
        self.assertTrue(validate_ledger(canonical_activation, self.schema).valid)
        # B0 remains unknown until a typed reconciliation/activation exists;
        # prose cannot manufacture the count or anchor.
        b0 = self.r004_control("B0"); b0["roots"][0]["blocked_reason"] = "at least two historical escapes (prose only)"
        b0_outcome = validate_ledger(b0, self.schema)
        self.assertTrue(b0_outcome.valid, b0_outcome.reasons)
        self.assertIsNone(b0_outcome.facts["threshold_facts"]["root-closed-001"]["lifetime_count"])
        reconciled = self.r004_historical_control(executed=False)
        self.assertTrue(validate_ledger(reconciled, self.schema).valid)
        backdated = copy.deepcopy(reconciled)
        next(item for item in backdated["events"] if item["event_id"] == "evt-activation-001")["first_threshold_known_at"] = "2020-01-01T00:00:00Z"
        outcome = validate_ledger(backdated, self.schema)
        self.assertFalse(outcome.valid); self.assertTrue(any(item.startswith("auth:activation") for item in outcome.reasons), outcome.reasons)

    def test_r004_malformed_generator_and_cli_boundary(self) -> None:
        """004-MAL: every modern record category fails closed under bad shape."""
        source = self.r004_control("S")
        records = {
            "reservation": ("repair_attempts", lambda row: row.get("record_kind") == "reservation",
                            ["record_kind", "repair_attempt_id", "root_cause_id", "strategy_id", "created_at", "status", "review_basis_id", "authorization_basis_id", "authorization_epoch_event_id", "expected_authorization_event_id", "implementation_activity_ids"]),
            "activation": ("events", lambda row: row.get("type") == "threshold-activated",
                           ["event_id", "sequence", "at", "root_cause_id", "activation_anchor_event_id", "first_threshold_known_at", "original_protocol_adopted_at", "effective_at", "evidence_refs", "causal_refs"]),
            "grant": ("events", lambda row: row.get("type") == "astra-adjudicated",
                      ["event_id", "sequence", "at", "root_cause_id", "repair_attempt_id", "strategy_id", "adjudication_activity_id", "first_threshold_activation_event_id", "authorization_epoch_event_id", "implementation_activity_ids", "decision_evidence_refs", "causal_refs"]),
            "start": ("events", lambda row: row.get("type") == "repair-attempted",
                      ["event_id", "sequence", "at", "root_cause_id", "repair_attempt_id", "started_at", "authorization_event_id", "causal_refs"]),
            "settlement": ("events", lambda row: row.get("type") == "repair-threshold-settled",
                           ["event_id", "sequence", "at", "root_cause_id", "repair_attempt_id", "start_event_id", "terminal_outcome", "settled_at", "mutation_finished_at", "causal_refs"]),
            "mutation_activity": ("activities", lambda row: row.get("activity_id") == "act-fix-successor",
                                  ["activity_id", "type", "status", "started_at", "completed_at", "root_cause_ids", "repair_attempt_bindings"]),
        }
        for record_name, (collection, predicate, fields) in records.items():
            for field in fields:
                value = next(item for item in source[collection] if predicate(item))[field]
                # Every required field has a removal control.  Each record
                # also supplies the remaining mutation categories below,
                # keeping the finite generator fast enough for routine runs.
                mutations: list[tuple[str, object]] = [("remove", None)]
                if field == fields[0]:
                    mutations.extend([("null", None), ("wrong-type", {"wrong": True}), ("blank", "   ")])
                    if field != "event_id":
                        mutations.append(("dangling-or-wrong-reference", "missing-reference"))
                if (field.endswith("_at") or field == "at") and field == next(name for name in fields if name.endswith("_at") or name == "at"):
                    mutations.extend([("invalid-timestamp", "not-a-timestamp"), ("naive-timestamp", "2026-09-08T08:00:00")])
                if isinstance(value, list) and value and field == next(name for name in fields if isinstance(next(item for item in source[collection] if predicate(item))[name], list)):
                    mutations.append(("duplicate-member", [value[0], value[0]]))
                for mutation, replacement in mutations:
                    malformed = copy.deepcopy(source)
                    row = next(item for item in malformed[collection] if predicate(item))
                    if mutation == "remove":
                        row.pop(field, None)
                    else:
                        row[field] = replacement
                    with self.subTest(case_id=f"004-MAL-{record_name}-{field}-{mutation}"):
                        result = validate_ledger(malformed, self.schema)
                        self.assertFalse(result.valid, result.reasons)
                        self.assertFalse(any(reason.startswith("internal:") for reason in result.reasons), result.reasons)
        top_level = [None, [], "ledger", 1, True, {"roots": "wrong"}, {"roots": ["non-object"]}]
        for value in top_level:
            with self.subTest(case_id=f"004-MAL-top-{type(value).__name__}"):
                result = validate_ledger(value, self.schema)
                self.assertFalse(result.valid, result.reasons)
        duplicate = copy.deepcopy(source); duplicate["events"].append(copy.deepcopy(duplicate["events"][0]))
        boolean_sequence = copy.deepcopy(source); next(item for item in boolean_sequence["events"] if item["event_id"] == "evt-astra-001")["sequence"] = True
        for case_id, malformed in (("004-MAL-duplicate-id", duplicate), ("004-MAL-boolean-sequence", boolean_sequence)):
            result = validate_ledger(malformed, self.schema)
            with self.subTest(case_id=case_id):
                self.assertFalse(result.valid, result.reasons)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "finding-ledger.v1.json"; path.write_bytes(b"\xff\xfe")
            command = [sys.executable, str(ROOT / "analyze-mas1-ledgers.py"), str(path)]
            completed = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            self.assertIn("invalid_ledgers", completed.stdout)

    def test_r004_fixture_manifest_and_architecture_acceptance(self) -> None:
        """Barrier 5 retains V003 obligations without another semantic engine."""
        manifest = self.suite["legacy_requirement_manifest"]
        self.assertEqual((manifest["count"], len(manifest["entries"])), (134, 134))
        self.assertEqual({entry["stable_id"] for entry in manifest["entries"]}, {f"V003-{index:03d}" for index in range(1, 135)})
        for stable_id in ("V003-020", "V003-093", "V003-096", "V003-124", "V003-130", "V003-133", "V003-134"):
            self.assertNotEqual(next(entry for entry in manifest["entries"] if entry["stable_id"] == stable_id)["representation_changes"], "unchanged legacy fixture representation")
        self.assertEqual(len(RULE_REGISTRY), 15)
        self.assertEqual(sum(getattr(rule, "__name__", "") == "rule_threshold_lifecycle" for rule in RULE_REGISTRY), 1)
        runner_source = (ROOT / "validate-mas1-ledger-fixtures.py").read_text()
        self.assertIn("result = validate_ledger", runner_source)
        self.assertNotIn("mas1_ledger_core import *", runner_source)

    def test_r004_analyzer_table_001_through_012_and_facts_snapshot(self) -> None:
        """004-AN: analysis gates on core facts and invalidity, never raw repair reconstruction."""
        clean = self.r004_control("P")
        unresolved = self.r004_control("U")
        active = self.r004_control("A")
        records = [
            {"ledger_id": "an-clean", "ledger": clean}, {"ledger_id": "an-unresolved", "ledger": unresolved},
            {"ledger_id": "an-active", "ledger": active},
        ]
        self.assertEqual(analyzer.validate_ledger_set(self.schema, records), {})
        report = analyzer.calculate(records)
        self.assertTrue(report["partial"])
        self.assertIn("threshold_activation_unresolved", report["incomplete_reasons"])
        self.assertEqual(report["incomplete_reasons"], sorted(set(report["incomplete_reasons"])))
        # A post-validation raw mutation cannot alter a report generated from
        # the canonical snapshot held in the ValidationResult facts graph.
        snapshot_record = [{"ledger_id": "an-snapshot", "ledger": self.r004_control("S")}]
        self.assertEqual(analyzer.validate_ledger_set(self.schema, snapshot_record), {})
        before = analyzer.stable_json(analyzer.calculate(snapshot_record))
        snapshot_record[0]["ledger"]["repair_attempts"][0]["status"] = "untrusted-raw-mutation"
        self.assertEqual(analyzer.stable_json(analyzer.calculate(snapshot_record)), before)
        invalid = [{"ledger_id": "an-invalid", "ledger": self.r004_control("S")}]
        next(item for item in invalid[0]["ledger"]["events"] if item["event_id"] == "evt-astra-001")["disposition"] = "rejected"
        self.assertTrue(analyzer.validate_ledger_set(self.schema, invalid))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); ledger_path = root / "finding-ledger.v1.json"
            ledger_path.write_text(json.dumps(invalid[0]["ledger"]), encoding="utf-8")
            predecessor = subprocess.run([sys.executable, str(ROOT / "analyze-mas1-ledgers.py"), str(ledger_path)], text=True, capture_output=True, check=False)
            self.assertEqual(predecessor.returncode, 2, predecessor.stdout + predecessor.stderr)
            self.assertIn("auth:grant_binding:root-closed-001:repair-001", predecessor.stdout)
            # Public portability: synthetic cutovers exercise the same rejection
            # gates without importing private source-machine rollout masters.
            synthetic_corrective = root / "synthetic-not-dispatched.json"
            synthetic_corrective.write_text(json.dumps({
                "cutoverId": "SYNTHETIC-PUBLIC-NOT-DISPATCHED",
                "postCutoverBoundary": None,
                "targetDiscovery": {"status": "not-dispatched", "targetDispatch": []},
            }), encoding="utf-8")
            synthetic_invalidated = root / "synthetic-invalidated.json"
            synthetic_invalidated.write_text(json.dumps({
                "cutoverId": "MAS1-6.1_20260908T154848Z",
            }), encoding="utf-8")
            corrective = subprocess.run([sys.executable, str(ROOT / "analyze-mas1-ledgers.py"), "--cutover", str(synthetic_corrective), str(ledger_path)], text=True, capture_output=True, check=False)
            self.assertEqual(corrective.returncode, 2, corrective.stdout + corrective.stderr)
            self.assertIn("population_target_discovery_not_ready:not-dispatched", corrective.stdout)
            # A catalogue invalidation is a release-control decision, so it
            # wins before even an independently malformed old-modern input.
            old_modern = copy.deepcopy(invalid[0]["ledger"])
            next(row for row in old_modern["repair_attempts"] if row["repair_attempt_id"] == "repair-001").pop("reservation_event_id")
            old_modern_dir = root / "old-modern"
            old_modern_dir.mkdir()
            old_modern_path = old_modern_dir / "finding-ledger.v1.json"
            old_modern_path.write_text(json.dumps(old_modern), encoding="utf-8")
            predecessor = subprocess.run([
                sys.executable, str(ROOT / "analyze-mas1-ledgers.py"), "--cutover",
                str(synthetic_invalidated), "--allow-invalid",
                str(old_modern_path),
            ], text=True, capture_output=True, check=False)
            self.assertEqual(predecessor.returncode, 2, predecessor.stdout + predecessor.stderr)
            self.assertEqual(predecessor.stdout, '{"invalid_cutover_population":["population_cutover_invalidated:MAS1-6.1_20260908T154848Z"]}\n',
                             predecessor.stdout + predecessor.stderr)

    # UC-003: repair-induced numerator is an incident, not a loose observation.
    def test_uc003_repair_induced_incident_scope(self) -> None:
        records = analyzer.materialize_metric_ledgers(self.suite)
        self.assertEqual(analyzer.validate_ledger_set(self.schema, records), {})
        report = analyzer.calculate(records)
        rate = report["repair_induced_attempt_rate"]
        self.assertEqual((rate["numerator"], rate["denominator"]), (1, 4))
        invalid = validate_ledger(self._case_ledger("invalid cross root predecessor"), self.schema)
        self.assertFalse(invalid.valid)

    # UC-004: zero, all-missing, mixed, reasoning-null, and unverified telemetry.
    def test_uc004_token_coverage_matrix(self) -> None:
        def activity(total, reasoning=0, verified=True):
            return {"runtime_verified": verified, "token_usage": {
                "source": "runtime-reported" if verified else "unavailable",
                "input": total, "output": total, "reasoning": reasoning, "total": total,
            }}
        zero = analyzer.aggregate_token_usage([activity(0)])
        self.assertEqual(zero["total"], 0)
        missing = analyzer.aggregate_token_usage([activity(None, None, False)])
        self.assertIsNone(missing["total"])
        mixed = analyzer.aggregate_token_usage([activity(7), activity(None, None, False)])
        self.assertEqual(mixed["total"], 7)
        self.assertEqual(mixed["coverage"]["numerator"], 1)

    # UC-005: offset-aware boundary buckets include exact, spanning, and unknown.
    def test_uc005_rfc3339_boundary_matrix(self) -> None:
        ledger = self.base("no_roots")
        ledger["cutover"]["post_cutover_boundary"] = "2026-09-08T08:00:00Z"
        ledger["cutover"]["protocol_adopted_at"] = "2026-09-08T08:00:02Z"
        template = ledger["activities"][0]
        ledger["activities"] = []
        for number, start, end in (
            (1, "2026-09-08T07:59:59Z", "2026-09-08T08:00:00Z"),
            (2, "2026-09-08T08:00:00-00:00", "2026-09-08T08:00:01Z"),
            (3, "2026-09-08T07:59:59Z", "2026-09-08T08:00:01Z"),
        ):
            row = copy.deepcopy(template); row["activity_id"] = f"boundary-{number}"; row["started_at"] = start; row["completed_at"] = end
            ledger["activities"].append(row)
        ledger["telemetry"]["recorded_participating_activity_count"] = 3
        ledger["telemetry"]["expected_participating_activity_count"] = 3
        marker = {**ledger["task"], "post_cutover_boundary": "2026-09-08T08:00:00Z",
                  "protocol_adopted_at": "2026-09-08T08:00:02Z",
                  "protocol_adoption_evidence_refs": ledger["cutover"]["protocol_adoption_evidence_refs"]}
        result = validate_ledger(ledger, self.schema, marker=marker)
        self.assertTrue(result.valid, result.reasons)
        self.assertEqual([item["chronology_bucket"] for item in result.facts["activities"]], ["pre-dispatch", "transition-pre-adoption", "spanning-dispatch"])
        unknown = copy.deepcopy(ledger)
        unknown["activities"][0]["started_at"] = None
        self.assertFalse(validate_ledger(unknown, self.schema).valid)

    def test_p2_missing_eligible_population_is_partial(self) -> None:
        # The CLI carries this condition in population_coverage and now treats
        # it as top-level partial even when the supplied ledger itself is clean.
        source = (ROOT / "analyze-mas1-ledgers.py").read_text()
        self.assertIn("population_missing_eligible_ledgers", source)
        self.assertIn("source_scope_unbounded", source)

    def test_unverified_runtime_makes_top_level_metrics_partial(self) -> None:
        ledger = self.base("no_roots")
        activity = ledger["activities"][0]
        activity.update({
            "runtime_verified": False,
            "runtime_evidence": None,
            "runtime_unavailable_reason": "runtime evidence unavailable",
            "actual": {"model": None, "reasoning_effort": None, "profile": None},
        })
        activity["token_usage"].update({
            "input": None, "output": None, "reasoning": None, "total": None,
            "source": "unavailable", "unavailable_reason": "usage unavailable",
            "reasoning_unavailable_reason": "usage unavailable",
        })
        self.assertTrue(validate_ledger(ledger, self.schema).valid)
        report = analyzer.calculate([{"ledger_id": "unverified", "ledger": ledger}])
        self.assertTrue(report["partial"])
        self.assertIn("runtime_identity_unverified", report["incomplete_reasons"])

    def test_metamorphic_matrix(self) -> None:
        base = self.base()
        self.assertTrue(validate_ledger(base, self.schema).valid)
        evidence = copy.deepcopy(base); evidence["observations"][0]["evidence_refs"].append("additional-proof")
        facts = validate_ledger(evidence, self.schema).facts
        self.assertEqual(len(facts["escape_incidents"]), 0)
        duplicate = copy.deepcopy(base); duplicate["events"].append(copy.deepcopy(duplicate["events"][0]))
        self.assertFalse(validate_ledger(duplicate, self.schema).valid)

    def test_protocol_adoption_target_marker_and_master_bind_exactly(self) -> None:
        ledger = self.base("no_roots")
        cutover = ledger["cutover"]
        marker = {**ledger["task"], "post_cutover_boundary": cutover["post_cutover_boundary"],
                  "protocol_adopted_at": cutover["protocol_adopted_at"],
                  "protocol_adoption_evidence_refs": cutover["protocol_adoption_evidence_refs"]}
        master = {"cutoverId": cutover["cutover_id"], "postCutoverBoundary": cutover["post_cutover_boundary"],
                  "fingerprints": {"prompt": {"sha256": cutover["prompt_sha256"]}}}
        target = {"dispatchStatus": "sent", "messageSentAtUtc": "2026-09-08T07:58:00Z",
                  "dispatchEvidenceRefs": ["dispatch/proof"],
                  "protocolAdoptionStatus": "adopted", "protocolAdoptedAt": cutover["protocol_adopted_at"],
                  "protocolAdoptionEvidenceRefs": cutover["protocol_adoption_evidence_refs"]}
        self.assertTrue(validate_ledger(ledger, self.schema, marker=marker, cutover=master, target=target).valid)
        early = copy.deepcopy(target); early["protocolAdoptedAt"] = "2026-09-08T07:57:59Z"
        self.assertIn("target_protocol_adoption_mismatch", validate_ledger(ledger, self.schema, marker=marker, cutover=master, target=early).reasons)
        missing = copy.deepcopy(ledger); missing["cutover"]["protocol_adoption_evidence_refs"] = []
        self.assertFalse(validate_ledger(missing, self.schema).valid)
        mismatch_marker = {**marker, "protocol_adoption_evidence_refs": ["wrong"]}
        self.assertIn("marker_protocol_adoption_evidence_mismatch", validate_ledger(ledger, self.schema, marker=mismatch_marker).reasons)

    def test_cutover_target_dispatch_adoption_state_machine(self) -> None:
        task_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        workspace = "/tmp/mas1-target-state"
        entry = {
            "eligibleForAnalysis": True,
            "taskInstanceId": task_id,
            "workspace": workspace,
            "ledgerPath": f"{workspace}/.mas1/tasks/{task_id}/finding-ledger.v1.json",
            "markerPath": f"{workspace}/.mas1/tasks/{task_id}/v6-cutover.json",
            "dispatchStatus": "sent",
            "messageSentAtUtc": "2026-09-08T08:00:00Z",
            "dispatchEvidenceRefs": ["dispatch/message-accepted"],
            "protocolAdoptionStatus": "adopted",
            "protocolAdoptedAt": "2026-09-08T08:00:01Z",
            "protocolAdoptionEvidenceRefs": ["adoption/reread-and-hash"],
        }
        def population(target: dict) -> dict:
            return {
                "cutoverId": "MAS1-test",
                "postCutoverBoundary": "2026-09-08T08:00:00Z",
                "targetDiscovery": {"status": "dispatched", "targetDispatch": [target]},
            }

        self.assertTrue(validate_cutover_population(population(entry)).valid)
        pending_adopted = copy.deepcopy(entry)
        pending_adopted.update({"dispatchStatus": "pending", "messageSentAtUtc": None,
                                "dispatchEvidenceRefs": [], "protocolAdoptionStatus": "adopted"})
        self.assertFalse(validate_cutover_population(population(pending_adopted)).valid)
        failed_adopted = copy.deepcopy(entry)
        failed_adopted["dispatchStatus"] = "failed"
        self.assertFalse(validate_cutover_population(population(failed_adopted)).valid)
        missing_evidence = copy.deepcopy(entry)
        missing_evidence["dispatchEvidenceRefs"] = []
        self.assertFalse(validate_cutover_population(population(missing_evidence)).valid)
        pre_boundary = copy.deepcopy(entry)
        pre_boundary["messageSentAtUtc"] = "2026-09-08T07:59:59Z"
        self.assertFalse(validate_cutover_population(population(pre_boundary)).valid)

    def test_invalidated_cutover_id_is_rejected_before_payload_validation(self) -> None:
        invalidated_id = "MAS1-6.1_20260908T154848Z"
        self.assertIn(invalidated_id, INVALIDATED_CUTOVER_CATALOGUE)
        self.assertTrue(INVALIDATED_CUTOVER_CATALOGUE_VERSION.startswith("MAS1-v6.1-"))
        for payload in (
            {"cutoverId": invalidated_id},
            {
                "cutoverId": invalidated_id,
                "postCutoverBoundary": "2026-09-08T08:00:00Z",
                "targetDiscovery": {"status": "complete", "targetDispatch": []},
            },
        ):
            result = validate_cutover_population(payload)
            self.assertFalse(result.valid)
            self.assertEqual(result.reasons, (f"population_cutover_invalidated:{invalidated_id}",))
            self.assertEqual(dict(result.targets), {})

    def test_protocol_exposure_buckets_and_running_work(self) -> None:
        ledger = self.base("no_roots")
        ledger["cutover"].update({"post_cutover_boundary": "2026-09-08T08:00:00Z", "protocol_adopted_at": "2026-09-08T08:00:10Z"})
        template = ledger["activities"][0]
        ledger["activities"] = []
        intervals = [
            ("pre", "completed", "2026-09-08T07:59:59Z", "2026-09-08T08:00:00Z", "pre-dispatch"),
            ("transition", "completed", "2026-09-08T08:00:00Z", "2026-09-08T08:00:10Z", "transition-pre-adoption"),
            ("dispatch-span", "completed", "2026-09-08T07:59:59Z", "2026-09-08T08:00:10Z", "spanning-dispatch"),
            ("adoption-span", "completed", "2026-09-08T08:00:09Z", "2026-09-08T08:00:11Z", "spanning-adoption"),
            ("v6", "completed", "2026-09-08T08:00:10Z", "2026-09-08T08:00:11Z", "v6"),
            ("running", "running", "2026-09-08T08:00:11Z", None, "incomplete"),
        ]
        for activity_id, status, started, completed, _ in intervals:
            row = copy.deepcopy(template); row.update({"activity_id": activity_id, "status": status, "started_at": started, "completed_at": completed})
            ledger["activities"].append(row)
        ledger["telemetry"].update({"recorded_participating_activity_count": 6, "expected_participating_activity_count": 6})
        result = validate_ledger(ledger, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertEqual([row["chronology_bucket"] for row in result.facts["activities"]], [item[-1] for item in intervals])
        report = analyzer.calculate([{"ledger_id": "exposure", "ledger": ledger}])
        self.assertEqual(report["token_usage_coverage"]["denominator"], 1)
        self.assertIn("activity_protocol_exposure_spanning", report["incomplete_reasons"])
        self.assertIn("activity_protocol_exposure_incomplete", report["incomplete_reasons"])

    def test_transition_escape_lifetime_not_v6_recurrence_and_spanning_closure_excludes_tokens(self) -> None:
        transition = self.base("open_reopened")
        transition["cutover"]["protocol_adopted_at"] = "2026-09-08T08:12:30Z"
        result = validate_ledger(transition, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertTrue(result.facts["escape_incidents"], "lifetime escape remains present")
        self.assertEqual(result.facts["v6_escape_incidents"], [])
        report = analyzer.calculate([{"ledger_id": "transition", "ledger": transition}])
        self.assertEqual(report["recurrence"]["numerator"], 0)

        closure = self.base("closed_root")
        clean = validate_ledger(closure, self.schema)
        self.assertIn("root-closed-001", clean.facts["v6_closed_root_ids"])
        spanning = copy.deepcopy(closure)
        fix = next(activity for activity in spanning["activities"] if activity["activity_id"] == "act-fix-001")
        fix["started_at"] = "2026-09-08T07:58:59Z"
        rejected = validate_ledger(spanning, self.schema)
        self.assertNotIn("root-closed-001", rejected.facts["v6_closed_root_ids"])
        report = analyzer.calculate([{"ledger_id": "spanning", "ledger": spanning}])
        self.assertEqual(report["tokens_per_closed_verified_root"]["closed_verified_root_count"], 0)
        self.assertIn("activity_protocol_exposure_spanning", report["incomplete_reasons"])

    def test_spanning_discovery_excludes_v6_escape_but_not_lifetime_gate(self) -> None:
        ledger = self.base("open_reopened")
        discovering = next(activity for activity in ledger["activities"] if activity["activity_id"] == "act-review-001")
        discovering["started_at"] = "2026-09-08T07:58:59Z"
        result = validate_ledger(ledger, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertEqual(len(result.facts["escape_incidents"]), 1)
        self.assertEqual(result.facts["v6_escape_incidents"], [])
        self.assertEqual(len(result.facts["v6_escape_discovery_exclusions"]), 1)
        report = analyzer.calculate([{"ledger_id": "spanning-discovery", "ledger": ledger}])
        self.assertEqual(report["recurrence"]["numerator"], 0)
        self.assertIn("escape_discovery_activity_not_wholly_v6", report["incomplete_reasons"])

    def test_clean_rootless_v6_adopter_is_counted_and_initial_is_new(self) -> None:
        ledger = self.base("no_roots")
        report = analyzer.calculate([{"ledger_id": "clean", "ledger": ledger}])
        self.assertEqual(report["task_and_ledger_counts"]["clean_rootless_ledger_count"], 1)
        self.assertEqual(report["protocol_exposure"]["confirmed_post_adoption_findings_by_root_relationship"], {})
        initial = self.base("closed_root")
        initial_report = analyzer.calculate([{"ledger_id": "initial", "ledger": initial}])
        self.assertEqual(initial_report["protocol_exposure"]["confirmed_post_adoption_findings_by_root_relationship"]["initial"], 1)
        self.assertNotIn("repair-induced", initial_report["protocol_exposure"]["confirmed_post_adoption_findings_by_root_relationship"])
        # A claimed pre-cutover flag never changes whole-interval exposure.
        activity = ledger["activities"][0]; activity["pre_cutover"] = True
        self.assertEqual(validate_ledger(ledger, self.schema).facts["activities"][0]["chronology_bucket"], "v6")

    def test_unconfirmed_known_open_observation_is_not_confirmed_post_adoption(self) -> None:
        ledger = self.base("open_reopened")
        known_open = copy.deepcopy(ledger["observations"][1])
        known_open.update({
            "observation_id": "obs-known-open-001", "root_relationship": "same-root-sibling",
            "status": "known-still-open", "confirmed": False,
            "observed_at": "2026-09-08T08:13:31Z", "repair_attempt_id": None,
            "review_basis_id": None, "cycle_id": None, "detected_cycle_id": "cycle-fix-001",
        })
        ledger["observations"].append(known_open)
        result = validate_ledger(ledger, self.schema)
        self.assertTrue(result.valid, result.reasons)
        report = analyzer.calculate([{"ledger_id": "known-open", "ledger": ledger}])
        relationships = report["protocol_exposure"]["confirmed_post_adoption_findings_by_root_relationship"]
        self.assertEqual(relationships, {"exact-recurrence": 1, "initial": 1})

    def test_lower_bound_incident_and_first_binding_are_hermetic_and_append_only(self) -> None:
        """Two reservation-linked escapes bind only the generic second event."""
        ledger = self.r004_control("S")
        root = ledger["roots"][0]
        root.update({
            "historical_escape_count_baseline": None, "escape_count_lifetime": None,
            "reconciliation_complete": False, "threshold_anchor": None,
            "first_threshold_activation_event_id": None, "historical_baseline_reconciliation_event_id": None,
            "state": "blocked", "block_code": "second-escape-astra-required",
        })
        # The ordinary initial escape deliberately remains legacy.  The two
        # later reservation-linked observations are the only lower-bound input.
        self.r004_add_later_escape(ledger, at="2026-09-08T08:14:10Z")
        root["escape_count_lifetime"] = None
        start = next(row for row in ledger["events"] if row["event_id"] == "evt-start-001")
        start.update({"implementation_activity_ids": ["act-fix-successor"], "strategy_id": "strategy-001"})
        start["causal_refs"] = list(dict.fromkeys([*start["causal_refs"], "act-fix-successor"]))
        next(row for row in ledger["repair_attempts"] if row["repair_attempt_id"] == "repair-001")["implementation_activity_ids"] = []
        next(row for row in ledger["events"] if row["event_id"] == "evt-astra-001")["implementation_activity_ids"] = []
        # Ordinary history is sequence-ordered: grant, reservation, then start.
        next(row for row in ledger["events"] if row["event_id"] == "evt-astra-001")["sequence"] = 9
        first_reopen = next(row for row in ledger["events"] if row["event_id"] == "evt-reopen-002")
        first_reopen["causal_refs"].extend(["repair-001", "basis-001", "cycle-fix-001"])
        source_observation = next(row for row in ledger["observations"] if row["observation_id"] == "obs-escape-002")
        source_escape = next(row for row in ledger["events"] if row["event_id"] == "evt-escape-002")
        source_reopen = next(row for row in ledger["events"] if row["event_id"] == "evt-reopen-002")
        observation = copy.deepcopy(source_observation)
        observation.update({"observation_id": "obs-escape-003", "observed_at": "2026-09-08T08:14:12Z",
                            "detected_cycle_id": "cycle-escape-003", "cycle_id": "cycle-escape-003"})
        escape = copy.deepcopy(source_escape)
        escape.update({"event_id": "evt-escape-003", "sequence": 19, "at": "2026-09-08T08:14:12Z",
                       "observation_id": "obs-escape-003", "cycle_id": "cycle-escape-003",
                       "escape_key": {"root_cause_id": "root-closed-001", "repair_attempt_id": "repair-001",
                                      "review_basis_id": "basis-001", "cycle_id": "cycle-escape-003"},
                       "causal_refs": ["obs-escape-003", "repair-001", "cycle-escape-003", "basis-001", "root-closed-001"]})
        reopen = copy.deepcopy(source_reopen)
        reopen.update({"event_id": "evt-reopen-003", "sequence": 20, "at": "2026-09-08T08:14:13Z",
                       "observation_id": "obs-escape-003", "cycle_id": "cycle-escape-003",
                       "causal_refs": ["obs-escape-003", "evt-escape-003", "root-closed-001", "repair-001", "basis-001", "cycle-escape-003"]})
        ledger["observations"].append(observation); ledger["events"].extend([escape, reopen])
        activation = next(row for row in ledger["events"] if row["event_id"] == "evt-activation-001")
        activation.update({"activation_anchor_event_id": "evt-escape-003", "first_threshold_known_at": "2026-09-08T08:14:12Z",
                           "effective_at": "2026-09-08T08:14:12Z"})
        previous = copy.deepcopy(ledger)
        context = _validation_context(previous)
        assert context is not None
        incidents, reasons = _modern_escape_incidents(context, "root-closed-001")
        self.assertEqual(reasons, set())
        self.assertEqual([row["event_id"] for row in incidents], ["evt-escape-002", "evt-escape-003"])

        # The second incident is selected generically; a first or third ID is
        # never accepted as a bindable anchor.
        root["threshold_anchor"] = {"kind": "post-cutover-escape", "threshold_escape_event_id": "evt-escape-003"}
        root["first_threshold_activation_event_id"] = "evt-activation-001"
        self.assertTrue(_lower_bound_binding_snapshot_ok(previous, ledger, "root-closed-001"))

        rewritten = copy.deepcopy(ledger)
        next(row for row in rewritten["events"] if row["event_id"] == "evt-escape-002")["at"] = "2026-09-08T08:14:11Z"
        self.assertFalse(_lower_bound_binding_snapshot_ok(previous, rewritten, "root-closed-001"))
        rebound = copy.deepcopy(ledger)
        rebound["roots"][0]["threshold_anchor"]["threshold_escape_event_id"] = "evt-escape-002"
        self.assertFalse(_lower_bound_binding_snapshot_ok(previous, rebound, "root-closed-001"))
        duplicate = copy.deepcopy(previous)
        next(row for row in duplicate["events"] if row["event_id"] == "evt-escape-003")["escape_key"] = copy.deepcopy(source_escape["escape_key"])
        duplicate_context = _validation_context(duplicate)
        assert duplicate_context is not None
        _, duplicate_reasons = _modern_escape_incidents(duplicate_context, "root-closed-001")
        self.assertTrue(any(reason.startswith("incident:duplicate_key") for reason in duplicate_reasons))

    def test_modern_failed_incident_dispatch_is_independent_of_known_baseline(self) -> None:
        """A reservation-linked failed attempt never falls back to legacy causality."""
        ledger = self.r004_control("S")
        start = next(item for item in ledger["events"] if item["event_id"] == "evt-start-001")
        start.update({
            "strategy_id": "strategy-001",
            "implementation_activity_ids": ["act-fix-successor"],
        })
        start["causal_refs"] = list(dict.fromkeys([*start["causal_refs"], "act-fix-successor"]))
        next(item for item in ledger["activities"] if item["activity_id"] == "act-fix-successor")["status"] = "failed"
        next(item for item in ledger["events"] if item["event_id"] == "evt-settlement-001")["terminal_outcome"] = "failed"
        ledger["roots"][0].update({
            "state": "blocked", "previous_state": "repairing",
            "blocked_reason": "failed attempt", "block_code": "second-escape-astra-required",
        })
        self.r004_add_later_escape(ledger)
        reopen = next(item for item in ledger["events"] if item["event_id"] == "evt-reopen-002")
        reopen["causal_refs"] = [
            "root-closed-001", "evt-escape-002", "obs-escape-002",
            "repair-001", "basis-001", "cycle-fix-001",
        ]
        outcome = validate_ledger(ledger, self.schema)
        self.assertTrue(outcome.valid, outcome.reasons)
        context = _validation_context(ledger)
        assert context is not None
        incidents, reasons = _modern_escape_incidents(context, "root-closed-001")
        self.assertEqual(reasons, set())
        self.assertEqual([item["event_id"] for item in incidents], ["evt-escape-002"])

    def test_lower_bound_phase5q_production_entry_rejects_complete_evidence_tampering(self) -> None:
        """Read-only current-machine integration for the approved VREC cases."""
        ledger_path = Path("/Users/ivanf/Desktop/domido-2/domido-web-app/.mas1/tasks/01a089b1-99d7-7fd1-8615-b8e8aacdf844/finding-ledger.v1.json")
        self.assertTrue(ledger_path.is_file(), "Phase5Q integration evidence is required on this machine")
        phase5q = json.loads(ledger_path.read_text())
        self.assertTrue(validate_ledger(phase5q, self.schema).valid)
        root = lambda ledger: next(item for item in ledger["roots"] if item["root_cause_id"] == "RC-14")
        def assert_rejected(ledger: dict) -> None:
            outcome = validate_ledger(ledger, self.schema)
            self.assertFalse(outcome.valid, outcome.reasons)
            self.assertTrue(any(reason.startswith(("incident:ordinary:RC-14", "incident:lineage:RC-14", "escape_causality:RC-14"))
                                for reason in outcome.reasons), outcome.reasons)

        wrong_finish = copy.deepcopy(phase5q)
        next(event for event in wrong_finish["events"] if event["event_id"] == "EVT-PHASE5P-0106")["mutation_finished_at"] = "2026-09-10T20:16:08.000Z"
        assert_rejected(wrong_finish)
        duplicate_ids = copy.deepcopy(phase5q)
        start = next(event for event in duplicate_ids["events"] if event["event_id"] == "EVT-PHASE5P-0103")
        start["implementation_activity_ids"].append(start["implementation_activity_ids"][0])
        assert_rejected(duplicate_ids)
        wrong_strategy = copy.deepcopy(phase5q)
        next(event for event in wrong_strategy["events"] if event["event_id"] == "EVT-PHASE5O-0100")["strategy_id"] = "foreign-strategy"
        assert_rejected(wrong_strategy)
        grant_after_start = copy.deepcopy(phase5q)
        next(event for event in grant_after_start["events"] if event["event_id"] == "EVT-PHASE5O-0100")["sequence"] = 104
        assert_rejected(grant_after_start)
        hidden_activity = copy.deepcopy(phase5q)
        source = next(item for item in hidden_activity["activities"] if item["activity_id"] == "ACT-V6-TERRA-RC14-V2-ROUTE-CONTINUITY-IMPLEMENTATION")
        extra = copy.deepcopy(source)
        extra["activity_id"] = "ACT-V6-TERRA-RC14-V2-HIDDEN-EXTRA"
        hidden_activity["activities"].append(extra)
        hidden_activity["telemetry"]["recorded_participating_activity_count"] = len(hidden_activity["activities"])
        hidden_activity["telemetry"]["expected_participating_activity_count"] = len(hidden_activity["activities"])
        assert_rejected(hidden_activity)

        attempt_id = "REPAIR-RC14-GALLERY-BUSY-FOCUS-PRESERVATION-V2-RESERVED-20260910"
        source_attempt = next(item for item in phase5q["repair_attempts"] if item["repair_attempt_id"] == attempt_id)
        source_strategy = next(item for item in phase5q["strategies"] if item["strategy_id"] == source_attempt["strategy_id"])
        adjudication_id = source_strategy["astra_adjudication_activity_id"]
        for label, mutate in (
            ("runtime-verified-without-identity", lambda ledger: next(
                item for item in ledger["activities"] if item["activity_id"] == adjudication_id
            ).__setitem__("runtime_verified", True)),
            ("runtime-injected-while-unverified", lambda ledger: next(
                item for item in ledger["activities"] if item["activity_id"] == adjudication_id
            ).update({
                "actual": {"model": "forged", "reasoning_effort": "xhigh", "profile": "forged"},
                "runtime_evidence": "forged-runtime",
            })),
            ("wrong-expected-authorization", lambda ledger: next(
                item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == attempt_id
            ).__setitem__("expected_authorization_event_id", "EVT-RC14-WRONG-GRANT")),
            ("reservation-time-mismatch", lambda ledger: next(
                item for item in ledger["events"] if item["event_id"] == "EVT-PHASE5O-0101"
            ).__setitem__("at", "2026-09-10T19:51:49.645Z")),
            ("verification-injection", lambda ledger: next(
                item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == attempt_id
            ).__setitem__("verification_activity_ids", ["ACT-V6-RC11-RC13-RC14-V2-TARGETED-16"])),
            ("duplicate-root-attempt-binding", lambda ledger: next(
                item for item in ledger["activities"]
                if item["activity_id"] == "ACT-V6-TERRA-RC14-V2-ROUTE-CONTINUITY-IMPLEMENTATION"
            )["repair_attempt_bindings"].append({"root_cause_id": "RC-14", "repair_attempt_id": attempt_id})),
        ):
            with self.subTest(admission_tamper=label):
                candidate = copy.deepcopy(phase5q)
                mutate(candidate)
                assert_rejected(candidate)

        # Exact VREC reproduction: a third reservation cannot smuggle a
        # completed, bound mutation through binding-pending without its grant
        # and terminal settlement.
        incomplete = copy.deepcopy(phase5q)
        third_attempt_id = "REPAIR-RC14-V3-INCOMPLETE"
        third_reservation_id = "EVT-RC14-V3-INCOMPLETE-RESERVATION"
        third_grant_id = "EVT-RC14-V3-INCOMPLETE-GRANT"
        third_impl_id = "ACT-RC14-V3-INCOMPLETE-IMPLEMENTATION"
        third = copy.deepcopy(source_attempt)
        third.update({
            "repair_attempt_id": third_attempt_id,
            "created_at": "2026-09-10T20:30:00Z",
            "expected_authorization_event_id": third_grant_id,
            "reservation_event_id": third_reservation_id,
            "implementation_activity_ids": [], "verification_activity_ids": [],
        })
        reservation = copy.deepcopy(next(
            item for item in incomplete["events"] if item["event_id"] == "EVT-PHASE5O-0101"
        ))
        reservation.update({
            "event_id": third_reservation_id,
            "sequence": max(item["sequence"] for item in incomplete["events"]) + 1,
            "at": third["created_at"], "repair_attempt_id": third_attempt_id,
            "reservation_event_id": third_reservation_id,
            "expected_authorization_event_id": third_grant_id,
            "causal_refs": ["RC-14", third_attempt_id, third["strategy_id"], third["authorization_basis_id"]],
        })
        start = copy.deepcopy(next(
            item for item in incomplete["events"] if item["event_id"] == "EVT-PHASE5P-0103"
        ))
        start.update({
            "event_id": "EVT-RC14-V3-INCOMPLETE-START",
            "sequence": reservation["sequence"] + 1,
            "at": "2026-09-10T20:31:00Z", "started_at": "2026-09-10T20:31:00Z",
            "repair_attempt_id": third_attempt_id,
            "authorization_event_id": third_grant_id,
            "implementation_activity_ids": [third_impl_id],
            "causal_refs": [
                "RC-14", third_attempt_id, third["strategy_id"], third["review_basis_id"],
                third_grant_id, third_impl_id,
            ],
        })
        implementation = copy.deepcopy(next(
            item for item in incomplete["activities"]
            if item["activity_id"] == "ACT-V6-TERRA-RC14-V2-ROUTE-CONTINUITY-IMPLEMENTATION"
        ))
        implementation.update({
            "activity_id": third_impl_id,
            "started_at": "2026-09-10T20:31:00Z", "completed_at": "2026-09-10T20:32:00Z",
            "repair_attempt_id": third_attempt_id,
            "repair_attempt_bindings": [{"root_cause_id": "RC-14", "repair_attempt_id": third_attempt_id}],
        })
        incomplete["repair_attempts"].append(third)
        incomplete["events"].extend([reservation, start])
        incomplete["activities"].append(implementation)
        incomplete["telemetry"]["recorded_participating_activity_count"] = len(incomplete["activities"])
        incomplete["telemetry"]["expected_participating_activity_count"] = len(incomplete["activities"])
        incomplete_outcome = validate_ledger(incomplete, self.schema)
        self.assertFalse(incomplete_outcome.valid, incomplete_outcome.reasons)
        self.assertIn(f"auth:unbound_attempt_incomplete:RC-14:{third_attempt_id}", incomplete_outcome.reasons)

        def append_future_plan(ledger: dict, *, expected_grant_id: str) -> None:
            future_attempt_id = "REPAIR-RC14-FUTURE-PLAN"
            future_strategy_id = "gallery-busy-focus-preservation/future-plan"
            future_reservation_id = "EVT-RC14-FUTURE-RESERVATION"
            future = copy.deepcopy(source_attempt)
            future.update({
                "repair_attempt_id": future_attempt_id, "strategy_id": future_strategy_id,
                "created_at": "2026-09-10T20:30:00Z",
                "authorization_epoch_event_id": "EVT-PHASE5Q-0120",
                "expected_authorization_event_id": expected_grant_id,
                "reservation_event_id": future_reservation_id,
                "implementation_activity_ids": [], "verification_activity_ids": [],
            })
            strategy = copy.deepcopy(source_strategy)
            strategy.update({
                "strategy_id": future_strategy_id, "created_at": "2026-09-10T20:29:59Z",
                "astra_adjudication_activity_id": None,
                "failed_predecessor_strategy_ids": [source_strategy["strategy_id"]],
                "disposition": "proposed", "decision_evidence_refs": ["future-plan"],
            })
            event = copy.deepcopy(next(
                item for item in ledger["events"] if item["event_id"] == "EVT-PHASE5O-0101"
            ))
            event.update({
                "event_id": future_reservation_id,
                "sequence": max(item["sequence"] for item in ledger["events"]) + 1,
                "at": future["created_at"], "repair_attempt_id": future_attempt_id,
                "strategy_id": future_strategy_id, "reservation_event_id": future_reservation_id,
                "expected_authorization_event_id": expected_grant_id,
                "causal_refs": ["RC-14", future_attempt_id, future_strategy_id, future["authorization_basis_id"]],
            })
            ledger["repair_attempts"].append(future)
            ledger["strategies"].append(strategy)
            ledger["events"].append(event)

        harmless_future = copy.deepcopy(phase5q)
        append_future_plan(harmless_future, expected_grant_id="EVT-RC14-FUTURE-GRANT")
        self.assertTrue(validate_ledger(harmless_future, self.schema).valid)
        existing_grant = copy.deepcopy(phase5q)
        append_future_plan(existing_grant, expected_grant_id="EVT-PHASE5O-0100")
        existing_outcome = validate_ledger(existing_grant, self.schema)
        self.assertFalse(existing_outcome.valid, existing_outcome.reasons)
        self.assertTrue(any(reason.startswith("auth:unbound_plan_not_empty:RC-14") for reason in existing_outcome.reasons))

        bound = copy.deepcopy(phase5q)
        root(bound)["threshold_anchor"] = {"kind": "post-cutover-escape", "threshold_escape_event_id": "EVT-PHASE5Q-0113"}
        root(bound)["first_threshold_activation_event_id"] = "EVT-PHASE5Q-0115"
        binding = validate_ledger(bound, self.schema, phase5q)
        self.assertTrue(binding.valid, binding.reasons)
        self.assertEqual(binding.facts["threshold_facts"]["RC-14"]["lifetime_count"], None)
        # A post-bound V3 reservation has a real Astra runtime record but no
        # start/mutation.  It is an open, fresh-unused authorization.
        fresh = copy.deepcopy(bound)
        v3_attempt = "REPAIR-RC14-V3-FRESH"; v3_strategy = "gallery-busy-focus-preservation/v3"; v3_basis = "BASIS-RC14-V3"
        v3_reservation = "EVT-RC14-V3-RESERVATION"; v3_begin = "EVT-RC14-V3-BEGIN"; v3_grant = "EVT-RC14-V3-GRANT"; v3_activity = "ACT-RC14-V3-ASTRA"; v3_impl = "ACT-RC14-V3-IMPLEMENTATION"
        attempt = copy.deepcopy(next(item for item in fresh["repair_attempts"] if item["repair_attempt_id"] == "REPAIR-RC14-GALLERY-BUSY-FOCUS-PRESERVATION-V2-RESERVED-20260910"))
        attempt.update({"repair_attempt_id": v3_attempt, "strategy_id": v3_strategy, "created_at": "2026-09-10T21:00:00Z",
                        "review_basis_id": v3_basis, "authorization_basis_id": v3_basis, "authorization_epoch_event_id": "EVT-PHASE5Q-0120",
                        "expected_authorization_event_id": v3_grant, "reservation_event_id": v3_reservation,
                        "implementation_activity_ids": [v3_impl], "verification_activity_ids": []})
        strategy = copy.deepcopy(next(item for item in fresh["strategies"] if item["strategy_id"] == "gallery-busy-focus-preservation/v2-route-continuity"))
        strategy.update({"strategy_id": v3_strategy, "created_at": "2026-09-10T21:00:30Z", "astra_adjudication_activity_id": v3_activity,
                         "failed_predecessor_strategy_ids": ["gallery-busy-focus-preservation/v2-route-continuity"], "authorization_basis_id": v3_basis,
                         "threshold_event_id": "EVT-PHASE5Q-0113", "threshold_escape_event_id": "EVT-PHASE5Q-0113",
                         "decision_evidence_refs": ["hermetic-v3-decision"]})
        basis = copy.deepcopy(next(item for item in fresh["review_bases"] if item["review_basis_id"] == "BASIS-RC14-V2-ROUTE-CONTINUITY-AUTH-20260910"))
        basis["review_basis_id"] = v3_basis
        activity = copy.deepcopy(next(item for item in fresh["activities"] if item["activity_id"] == "ACT-V6-ASTRA-RC14-V2-AUTHORIZATION"))
        activity.update({"activity_id": v3_activity, "type": "astra-adjudication", "started_at": "2026-09-10T21:01:00Z", "completed_at": "2026-09-10T21:02:00Z",
                         "actual": {"model": "gpt-6-astra", "reasoning_effort": "xhigh", "profile": "mas1_judge_astra"},
                         "runtime_verified": True, "runtime_evidence": "hermetic-v3-runtime", "runtime_unavailable_reason": None,
                         "root_cause_ids": ["RC-14"], "attribution_mode": "direct", "repair_attempt_bindings": []})
        def event(source_id: str, event_id: str, sequence: int, at: str, kind: str, **fields: object) -> dict:
            row = copy.deepcopy(next(item for item in fresh["events"] if item["event_id"] == source_id))
            row.update({"event_id": event_id, "sequence": sequence, "at": at, "type": kind, "root_cause_id": "RC-14",
                        "observation_id": None, "repair_attempt_id": v3_attempt, "review_basis_id": v3_basis,
                        "cycle_id": None, "root_relationship": None, "escape_key": None})
            row.update(fields); return row
        reservation_event = event("EVT-PHASE5O-0101", v3_reservation, 121, "2026-09-10T21:00:00Z", "repair-reserved",
                                  strategy_id=v3_strategy, reservation_event_id=v3_reservation,
                                  expected_authorization_event_id=v3_grant,
                                  causal_refs=["RC-14", v3_attempt, v3_strategy, v3_basis])
        begin = event("EVT-PHASE5Q-0115", v3_begin, 122, "2026-09-10T21:01:00Z", "astra-adjudication-started",
                      strategy_id=v3_strategy, adjudication_activity_id=v3_activity,
                      causal_refs=["RC-14", v3_attempt, v3_strategy, v3_basis, "EVT-PHASE5Q-0115", v3_activity])
        grant = event("EVT-PHASE5O-0100", v3_grant, 123, "2026-09-10T21:02:01Z", "astra-adjudicated",
                      strategy_id=v3_strategy, successor_strategy_id=v3_strategy, adjudication_activity_id=v3_activity,
                      adjudication_start_event_id=v3_begin, threshold_event_id="EVT-PHASE5Q-0113",
                      activation_anchor_event_id="EVT-PHASE5Q-0113", first_threshold_activation_event_id="EVT-PHASE5Q-0115",
                      decision_trigger_event_id="EVT-PHASE5Q-0118", authorization_epoch_event_id="EVT-PHASE5Q-0120",
                      authorization_basis_id=v3_basis, implementation_activity_ids=[v3_impl], disposition="approved", decision_evidence_refs=["hermetic-v3-decision"],
                      causal_refs=["RC-14", v3_attempt, v3_strategy, v3_basis, "EVT-PHASE5Q-0113", "EVT-PHASE5Q-0115", "EVT-PHASE5Q-0118", "EVT-PHASE5Q-0120", v3_activity, v3_begin])
        fresh["repair_attempts"].append(attempt); fresh["strategies"].append(strategy); fresh["review_bases"].append(basis); fresh["activities"].append(activity); fresh["events"].extend([reservation_event, begin, grant])
        root(fresh).update({"state": "open", "previous_state": "blocked", "blocked_reason": None, "block_code": None})
        fresh["telemetry"]["recorded_participating_activity_count"] = len(fresh["activities"]); fresh["telemetry"]["expected_participating_activity_count"] = len(fresh["activities"])
        v3_result = validate_ledger(fresh, self.schema, bound)
        self.assertTrue(v3_result.valid, v3_result.reasons)
        self.assertEqual(v3_result.facts["threshold_facts"]["RC-14"]["gate_state"], "open")
        self.assertEqual(v3_result.facts["threshold_facts"]["RC-14"]["fresh_unused_authorization_event_ids"], [v3_grant])
        # Finalize V3, record one complete linked incident, then use that
        # finalized predecessor in a V4 fresh authorization.
        finalized = copy.deepcopy(fresh)
        implementation = copy.deepcopy(next(item for item in finalized["activities"] if item["activity_id"] == "ACT-V6-TERRA-RC14-V2-ROUTE-CONTINUITY-IMPLEMENTATION"))
        implementation.update({"activity_id": v3_impl, "started_at": "2026-09-10T21:03:00Z", "completed_at": "2026-09-10T21:04:00Z",
                               "status": "failed", "repair_attempt_bindings": [{"root_cause_id": "RC-14", "repair_attempt_id": v3_attempt}], "root_cause_ids": ["RC-14"], "attribution_mode": "direct"})
        start_v3 = event("EVT-PHASE5P-0103", "EVT-RC14-V3-START", 124, "2026-09-10T21:03:00Z", "repair-attempted",
                         strategy_id=v3_strategy, authorization_event_id=v3_grant, authorization_basis_id=v3_basis, started_at="2026-09-10T21:03:00Z",
                         implementation_activity_ids=[v3_impl], causal_refs=["RC-14", v3_attempt, v3_strategy, v3_basis, v3_grant, v3_impl])
        settle_v3 = event("EVT-PHASE5P-0106", "EVT-RC14-V3-SETTLE", 125, "2026-09-10T21:04:01Z", "repair-threshold-settled",
                          start_event_id="EVT-RC14-V3-START", terminal_outcome="failed", settled_at="2026-09-10T21:04:01Z",
                          mutation_finished_at="2026-09-10T21:04:00Z", causal_refs=["RC-14", v3_attempt, "EVT-RC14-V3-START", v3_impl])
        cycle = copy.deepcopy(next(item for item in finalized["cycles"] if item["cycle_id"] == "CYCLE-RC14-V2-EXACT-RECURRENCE-ESCAPE-20260910"))
        cycle.update({"cycle_id": "CYCLE-RC14-V3-ESCAPE", "sequence": max(item["sequence"] for item in finalized["cycles"]) + 1})
        observation = copy.deepcopy(next(item for item in finalized["observations"] if item["observation_id"] == "OBS-PHASE5Q-RC14-V2-EXACT-RECURRENCE-MANUAL"))
        observation.update({"observation_id": "OBS-RC14-V3-ESCAPE", "observed_at": "2026-09-10T21:05:00Z", "repair_attempt_id": v3_attempt,
                            "review_basis_id": v3_basis, "cycle_id": cycle["cycle_id"], "detected_cycle_id": cycle["cycle_id"]})
        escape_v3 = event("EVT-PHASE5Q-0113", "EVT-RC14-V3-ESCAPE", 126, "2026-09-10T21:05:00Z", "escape-confirmed",
                          observation_id=observation["observation_id"], cycle_id=cycle["cycle_id"], root_relationship="exact-recurrence",
                          escape_key={"root_cause_id": "RC-14", "repair_attempt_id": v3_attempt, "review_basis_id": v3_basis, "cycle_id": cycle["cycle_id"]},
                          causal_refs=["RC-14", v3_attempt, v3_basis, cycle["cycle_id"], observation["observation_id"]])
        reopen_v3 = event("EVT-PHASE5Q-0114", "EVT-RC14-V3-REOPEN", 127, "2026-09-10T21:05:01Z", "root-reopened",
                          observation_id=observation["observation_id"], cycle_id=cycle["cycle_id"], root_relationship="exact-recurrence",
                          causal_refs=["RC-14", v3_attempt, v3_basis, cycle["cycle_id"], observation["observation_id"], escape_v3["event_id"]])
        finalized["activities"].append(implementation); finalized["cycles"].append(cycle); finalized["observations"].append(observation); finalized["events"].extend([start_v3, settle_v3, escape_v3, reopen_v3])
        root(finalized).update({"state": "blocked", "previous_state": "open", "blocked_reason": "V3 escape", "block_code": "second-escape-astra-required"})
        finalized["telemetry"]["recorded_participating_activity_count"] = len(finalized["activities"]); finalized["telemetry"]["expected_participating_activity_count"] = len(finalized["activities"])
        v3_final = validate_ledger(finalized, self.schema, fresh)
        self.assertTrue(v3_final.valid, v3_final.reasons)
        for outcome, activity_status in (("succeeded", "completed"), ("cancelled", "cancelled"), ("superseded", "cancelled")):
            terminal_case = copy.deepcopy(finalized)
            next(item for item in terminal_case["activities"] if item["activity_id"] == v3_impl)["status"] = activity_status
            next(item for item in terminal_case["events"] if item["event_id"] == "EVT-RC14-V3-SETTLE")["terminal_outcome"] = outcome
            terminal_result = validate_ledger(terminal_case, self.schema, fresh)
            self.assertTrue(terminal_result.valid, (outcome, terminal_result.reasons))
        mismatched_terminal = copy.deepcopy(finalized)
        next(item for item in mismatched_terminal["activities"] if item["activity_id"] == v3_impl)["status"] = "completed"
        self.assertFalse(validate_ledger(mismatched_terminal, self.schema, fresh).valid)
        v4 = copy.deepcopy(finalized)
        v4_attempt = "REPAIR-RC14-V4-FRESH"; v4_strategy = "gallery-busy-focus-preservation/v4"; v4_basis = "BASIS-RC14-V4"; v4_reservation = "EVT-RC14-V4-RESERVATION"; v4_begin = "EVT-RC14-V4-BEGIN"; v4_grant = "EVT-RC14-V4-GRANT"; v4_activity = "ACT-RC14-V4-ASTRA"
        v4_row = copy.deepcopy(attempt); v4_row.update({"repair_attempt_id": v4_attempt, "strategy_id": v4_strategy, "created_at": "2026-09-10T21:06:00Z", "review_basis_id": v4_basis, "authorization_basis_id": v4_basis, "authorization_epoch_event_id": escape_v3["event_id"], "expected_authorization_event_id": v4_grant, "reservation_event_id": v4_reservation, "implementation_activity_ids": [], "verification_activity_ids": []})
        v4_strategy_row = copy.deepcopy(strategy); v4_strategy_row.update({"strategy_id": v4_strategy, "created_at": "2026-09-10T21:06:30Z", "astra_adjudication_activity_id": v4_activity, "failed_predecessor_strategy_ids": [v3_strategy], "authorization_basis_id": v4_basis, "decision_evidence_refs": ["hermetic-v4-decision"]})
        v4_basis_row = copy.deepcopy(basis); v4_basis_row["review_basis_id"] = v4_basis
        v4_activity_row = copy.deepcopy(activity); v4_activity_row.update({"activity_id": v4_activity, "started_at": "2026-09-10T21:07:00Z", "completed_at": "2026-09-10T21:08:00Z", "runtime_evidence": "hermetic-v4-runtime"})
        def v4event(source: dict, event_id: str, sequence: int, at: str, kind: str, **fields: object) -> dict:
            row = copy.deepcopy(source); row.update({"event_id": event_id, "sequence": sequence, "at": at, "type": kind, "repair_attempt_id": v4_attempt, "review_basis_id": v4_basis, "strategy_id": v4_strategy, "observation_id": None, "cycle_id": None, "root_relationship": None, "escape_key": None}); row.update(fields); return row
        v4_reserve_event = v4event(reservation_event, v4_reservation, 128, "2026-09-10T21:06:00Z", "repair-reserved", reservation_event_id=v4_reservation, expected_authorization_event_id=v4_grant, causal_refs=["RC-14", v4_attempt, v4_strategy, v4_basis])
        v4_begin_event = v4event(begin, v4_begin, 129, "2026-09-10T21:07:00Z", "astra-adjudication-started", adjudication_activity_id=v4_activity, causal_refs=["RC-14", v4_attempt, v4_strategy, v4_basis, "EVT-PHASE5Q-0115", v4_activity])
        v4_grant_event = v4event(grant, v4_grant, 130, "2026-09-10T21:08:01Z", "astra-adjudicated", successor_strategy_id=v4_strategy, adjudication_activity_id=v4_activity, adjudication_start_event_id=v4_begin, threshold_event_id="EVT-PHASE5Q-0113", activation_anchor_event_id="EVT-PHASE5Q-0113", first_threshold_activation_event_id="EVT-PHASE5Q-0115", decision_trigger_event_id=escape_v3["event_id"], authorization_epoch_event_id=escape_v3["event_id"], authorization_basis_id=v4_basis, implementation_activity_ids=[], disposition="approved", decision_evidence_refs=["hermetic-v4-decision"], causal_refs=["RC-14", v4_attempt, v4_strategy, v4_basis, "EVT-PHASE5Q-0113", "EVT-PHASE5Q-0115", escape_v3["event_id"], v4_activity, v4_begin])
        v4["repair_attempts"].append(v4_row); v4["strategies"].append(v4_strategy_row); v4["review_bases"].append(v4_basis_row); v4["activities"].append(v4_activity_row); v4["events"].extend([v4_reserve_event, v4_begin_event, v4_grant_event])
        root(v4).update({"state": "open", "previous_state": "blocked", "blocked_reason": None, "block_code": None}); v4["telemetry"]["recorded_participating_activity_count"] = len(v4["activities"]); v4["telemetry"]["expected_participating_activity_count"] = len(v4["activities"])
        v4_result = validate_ledger(v4, self.schema, finalized)
        self.assertTrue(v4_result.valid, v4_result.reasons)
        invalid_predecessor = copy.deepcopy(v4)
        next(item for item in invalid_predecessor["strategies"] if item["strategy_id"] == v4_strategy)["failed_predecessor_strategy_ids"] = [v4_strategy]
        bad_v4 = validate_ledger(invalid_predecessor, self.schema, finalized)
        self.assertFalse(bad_v4.valid, bad_v4.reasons)
        self.assertTrue(any(reason.startswith(("auth:grant_binding:RC-14", "auth:predecessor:RC-14", "auth:frontier:RC-14")) for reason in bad_v4.reasons), bad_v4.reasons)
        invalid_v3_predecessor = copy.deepcopy(v4)
        next(item for item in invalid_v3_predecessor["strategies"] if item["strategy_id"] == v3_strategy)["failed_predecessor_strategy_ids"] = [v3_strategy]
        invalid_v3_result = validate_ledger(invalid_v3_predecessor, self.schema, finalized)
        self.assertFalse(invalid_v3_result.valid, invalid_v3_result.reasons)
        self.assertNotIn(v4_attempt, invalid_v3_result.facts["threshold_facts"]["RC-14"]["authorized_attempt_ids"])
        predecessor_cycle = copy.deepcopy(v4)
        next(item for item in predecessor_cycle["strategies"] if item["strategy_id"] == v3_strategy)["failed_predecessor_strategy_ids"] = [v4_strategy]
        cycle_result = validate_ledger(predecessor_cycle, self.schema, finalized)
        self.assertFalse(cycle_result.valid, cycle_result.reasons)
        self.assertTrue(any(reason.startswith("auth:predecessor_cycle:RC-14") for reason in cycle_result.reasons), cycle_result.reasons)
        frozen_basis = copy.deepcopy(bound)
        next(item for item in frozen_basis["review_bases"]
             if item["review_basis_id"] == "BASIS-RC11-RC13-RC14-V33-PROPOSAL-20260910")["artifact_fingerprint"] = "tampered"
        frozen = validate_ledger(frozen_basis, self.schema, phase5q)
        self.assertFalse(frozen.valid, frozen.reasons)
        self.assertIn("auth:activation_binding:RC-14", frozen.reasons)
        frozen_cycle = copy.deepcopy(bound)
        next(item for item in frozen_cycle["cycles"]
             if item["cycle_id"] == "CYCLE-RC14-V2-EXACT-RECURRENCE-ESCAPE-20260910")["kind"] = "tampered"
        self.assertIn("auth:activation_binding:RC-14", validate_ledger(frozen_cycle, self.schema, phase5q).reasons)
        neutral_cycle_membership = copy.deepcopy(bound)
        neutral_cycle = next(item for item in neutral_cycle_membership["cycles"]
                             if item["cycle_id"] == "CYCLE-RC14-V2-REPAIR-INDUCED-AUTO-ESCAPE-20260910")
        neutral_cycle["activity_ids"] = list(reversed(neutral_cycle["activity_ids"]))
        neutral_cycle_result = validate_ledger(neutral_cycle_membership, self.schema, phase5q)
        self.assertFalse(neutral_cycle_result.valid, neutral_cycle_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", neutral_cycle_result.reasons)
        nested_escape_map = copy.deepcopy(bound)
        next(item for item in nested_escape_map["events"]
             if item["event_id"] == "EVT-PHASE5Q-0113")["escape_key"]["review_basis_id"] = "BASIS-RC14-NESTED-TAMPER"
        nested_map_result = validate_ledger(nested_escape_map, self.schema, phase5q)
        self.assertFalse(nested_map_result.valid, nested_map_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", nested_map_result.reasons)
        namespace_collision = copy.deepcopy(bound)
        collision_row = copy.deepcopy(namespace_collision["test_evidence"][0])
        collision_row["test_evidence_id"] = "BASIS-RC14-V2-ROUTE-CONTINUITY-AUTH-20260910"
        namespace_collision["test_evidence"].append(collision_row)
        collision_result = validate_ledger(namespace_collision, self.schema, phase5q)
        self.assertFalse(collision_result.valid, collision_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", collision_result.reasons)
        unrelated_append = copy.deepcopy(bound)
        unrelated_basis = copy.deepcopy(unrelated_append["review_bases"][0])
        unrelated_basis["review_basis_id"] = "BASIS-UNRELATED-APPEND-CONTROL"
        unrelated_append["review_bases"].append(unrelated_basis)
        unrelated_result = validate_ledger(unrelated_append, self.schema, phase5q)
        self.assertTrue(unrelated_result.valid, unrelated_result.reasons)
        for label, mutate in (
            ("missing", lambda row: row.pop("threshold_anchor")),
            ("partial", lambda row: row.__setitem__("threshold_anchor", {"kind": "post-cutover-escape", "threshold_escape_event_id": "EVT-PHASE5Q-0113"})),
            ("wrong", lambda row: row.__setitem__("threshold_anchor", {"kind": "post-cutover-escape", "threshold_escape_event_id": "EVT-PHASE5Q-0118"})),
        ):
            candidate = copy.deepcopy(phase5q)
            mutate(root(candidate))
            if label == "partial":
                # Anchor-only is intentionally not an activation binding.
                pass
            rejected = validate_ledger(candidate, self.schema, phase5q)
            self.assertFalse(rejected.valid, (label, rejected.reasons))
            self.assertIn("auth:activation_binding:RC-14", rejected.reasons)
        rebound = copy.deepcopy(bound)
        root(rebound)["threshold_anchor"]["threshold_escape_event_id"] = "EVT-PHASE5Q-0118"
        rebound_result = validate_ledger(rebound, self.schema, bound)
        self.assertFalse(rebound_result.valid, rebound_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", rebound_result.reasons)
        missing_previous_binding_key = copy.deepcopy(phase5q)
        root(missing_previous_binding_key).pop("threshold_anchor")
        missing_previous_result = validate_ledger(bound, self.schema, missing_previous_binding_key)
        self.assertFalse(missing_previous_result.valid, missing_previous_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", missing_previous_result.reasons)
        for collection, identity, source_id, appended_id in (
            ("repair_attempts", "repair_attempt_id", "REPAIR-RC14-GALLERY-BUSY-FOCUS-PRESERVATION-V2-RESERVED-20260910", "REPAIR-RC14-TARGET-APPEND"),
            ("activities", "activity_id", "ACT-V6-TERRA-RC14-V2-ROUTE-CONTINUITY-IMPLEMENTATION", "ACT-V6-RC14-TARGET-APPEND"),
            ("test_evidence", "test_evidence_id", "TEST-RC14-V2-EXACT-RECURRENCE-MANUAL-SHOW-MORE-20260910", "TEST-RC14-TARGET-APPEND"),
        ):
            appended = copy.deepcopy(bound)
            row = copy.deepcopy(next(item for item in appended[collection] if item[identity] == source_id))
            row[identity] = appended_id
            appended[collection].append(row)
            appended["telemetry"]["recorded_participating_activity_count"] = len(appended["activities"])
            appended["telemetry"]["expected_participating_activity_count"] = len(appended["activities"])
            result = validate_ledger(appended, self.schema, phase5q)
            self.assertFalse(result.valid, (collection, result.reasons))
            self.assertIn("auth:activation_binding:RC-14", result.reasons)
        target_event = copy.deepcopy(bound)
        event = copy.deepcopy(next(item for item in target_event["events"] if item["event_id"] == "EVT-PHASE5Q-0119"))
        event.update({"event_id": "EVT-PHASE5Q-TARGET-APPEND", "sequence": max(item["sequence"] for item in target_event["events"]) + 1})
        target_event["events"].append(event)
        event_result = validate_ledger(target_event, self.schema, phase5q)
        self.assertFalse(event_result.valid, event_result.reasons)
        self.assertIn("auth:activation_binding:RC-14", event_result.reasons)
        closing = copy.deepcopy(bound)
        root(closing)["state"] = "closure_pending"
        outcome = validate_ledger(closing, self.schema)
        self.assertIn("closure:lower_bound:RC-14", outcome.reasons)

    def test_lower_bound_second_disjoint_root_and_snapshot_boundary(self) -> None:
        """The lower-bound path is root-generic and preserves the append boundary."""
        ledger = self.r004_two_root_control()
        self.assertTrue(validate_ledger(ledger, self.schema).valid)
        root_id, repair_id, strategy_id, basis_id = (
            "root-closed-002", "repair-002", "strategy-002", "basis-002",
        )
        root = next(item for item in ledger["roots"] if item["root_cause_id"] == root_id)
        root.update({
            "historical_escape_count_baseline": None, "escape_count_lifetime": None,
            "reconciliation_complete": False, "threshold_anchor": None,
            "first_threshold_activation_event_id": None,
            "historical_baseline_reconciliation_event_id": None,
            "state": "blocked", "block_code": "second-escape-astra-required",
            "blocked_reason": "historical baseline unresolved",
        })
        start = next(item for item in ledger["events"] if item["event_id"] == "evt-start-002")
        start.update({"implementation_activity_ids": ["act-fix-successor-002"], "strategy_id": strategy_id})
        start["causal_refs"] = list(dict.fromkeys([*start["causal_refs"], "act-fix-successor-002"]))
        # The completed historical mutation is represented only by the start
        # and activity binding, never by a future reservation payload.
        next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == repair_id)["implementation_activity_ids"] = []
        ordinary_grant = next(item for item in ledger["events"] if item["event_id"] == "evt-astra-002")
        ordinary_grant["implementation_activity_ids"] = []
        ordinary_grant["sequence"] = 30
        next(item for item in ledger["events"] if item["event_id"] == "evt-reservation-002")["sequence"] = 32
        ledger["events"].sort(key=lambda item: item["sequence"])

        source_observation = next(item for item in ledger["observations"] if item["observation_id"] == "obs-escape-002")
        source_escape = next(item for item in ledger["events"] if item["event_id"] == "evt-escape-002")
        source_reopen = next(item for item in ledger["events"] if item["event_id"] == "evt-reopen-002")
        maximum = max(item["sequence"] for item in ledger["events"])
        incident_ids: list[str] = []
        for number, cycle_id, at in (
            (1, "cycle-fix-002", "2026-09-08T08:24:10Z"),
            (2, "cycle-post-repair-002", "2026-09-08T08:24:12Z"),
        ):
            observation_id = f"obs-lower-bound-002-{number}"
            escape_id = f"evt-lower-bound-002-{number}"
            reopen_id = f"evt-lower-bound-reopen-002-{number}"
            observation = copy.deepcopy(source_observation)
            observation.update({
                "observation_id": observation_id, "repair_attempt_id": repair_id,
                "review_basis_id": basis_id, "cycle_id": cycle_id,
                "detected_cycle_id": cycle_id, "observed_at": at,
            })
            escape = copy.deepcopy(source_escape)
            escape.update({
                "event_id": escape_id, "sequence": maximum + number * 2 - 1,
                "at": at, "observation_id": observation_id,
                "repair_attempt_id": repair_id, "review_basis_id": basis_id,
                "cycle_id": cycle_id, "root_cause_id": root_id,
                "escape_key": {
                    "root_cause_id": root_id, "repair_attempt_id": repair_id,
                    "review_basis_id": basis_id, "cycle_id": cycle_id,
                },
                "causal_refs": [root_id, observation_id, repair_id, basis_id, cycle_id],
            })
            reopen = copy.deepcopy(source_reopen)
            reopen.update({
                "event_id": reopen_id, "sequence": maximum + number * 2,
                "at": "2026-09-08T08:24:13Z", "observation_id": observation_id,
                "repair_attempt_id": repair_id, "review_basis_id": basis_id,
                "cycle_id": cycle_id, "root_cause_id": root_id,
                "causal_refs": [root_id, observation_id, escape_id, repair_id, basis_id, cycle_id],
            })
            ledger["observations"].append(observation)
            ledger["events"].extend([escape, reopen])
            incident_ids.append(escape_id)

        # The retained ordinary escape is still valid causal history, but is
        # deliberately excluded from the modern lower-bound denominator.
        legacy_escape_id = "evt-escape-002"
        context = _validation_context(ledger)
        assert context is not None
        incidents, reasons = _modern_escape_incidents(context, root_id)
        self.assertEqual(reasons, set())
        self.assertEqual([item["event_id"] for item in incidents], incident_ids)
        self.assertNotIn(legacy_escape_id, [item["event_id"] for item in incidents])

        activation = next(item for item in ledger["events"] if item["event_id"] == "evt-activation-002")
        activation.update({
            "activation_anchor_event_id": incident_ids[1],
            "first_threshold_known_at": "2026-09-08T08:24:12Z",
            "effective_at": "2026-09-08T08:24:12Z",
            "at": "2026-09-08T08:24:13Z",
            "causal_refs": [root_id, incident_ids[1]],
            "evidence_refs": [incident_ids[1]],
        })
        previous = copy.deepcopy(ledger)
        pending = validate_ledger(previous, self.schema)
        self.assertTrue(pending.valid, pending.reasons)
        pending_fact = pending.facts["threshold_facts"][root_id]
        self.assertEqual(pending_fact["lower_bound_incident_count"], 2)
        self.assertEqual(pending_fact["threshold_activation_status"], "binding-pending")

        bound = copy.deepcopy(previous)
        bound_root = next(item for item in bound["roots"] if item["root_cause_id"] == root_id)
        bound_root["threshold_anchor"] = {"kind": "post-cutover-escape", "threshold_escape_event_id": incident_ids[1]}
        bound_root["first_threshold_activation_event_id"] = "evt-activation-002"
        self.assertTrue(_lower_bound_binding_snapshot_ok(previous, bound, root_id))
        result = validate_ledger(bound, self.schema)
        self.assertTrue(result.valid, result.reasons)
        self.assertEqual(result.facts["threshold_facts"][root_id]["gate_state"], "blocked")

        # An explicitly disjoint root may append a new row that happens to
        # point at target-root support; that is not a target-history rewrite.
        unrelated = copy.deepcopy(bound)
        unrelated_event = copy.deepcopy(source_reopen)
        unrelated_event.update({
            "event_id": "evt-other-root-adjacent-append", "sequence": maximum + 5,
            "at": "2026-09-08T08:24:20Z", "root_cause_id": "root-closed-001",
            "observation_id": None, "repair_attempt_id": None, "review_basis_id": None,
            "cycle_id": None, "causal_refs": ["root-closed-001", basis_id],
        })
        unrelated["events"].append(unrelated_event)
        self.assertTrue(_lower_bound_binding_snapshot_ok(previous, unrelated, root_id))

        relabeled_shared = copy.deepcopy(bound)
        next(item for item in relabeled_shared["review_bases"] if item["review_basis_id"] == basis_id)["review_basis_id"] = "basis-002-relabelled"
        self.assertFalse(_lower_bound_binding_snapshot_ok(previous, relabeled_shared, root_id))
        relabeled_target = copy.deepcopy(bound)
        next(item for item in relabeled_target["events"] if item["event_id"] == incident_ids[0])["root_cause_id"] = "root-closed-001"
        self.assertFalse(_lower_bound_binding_snapshot_ok(previous, relabeled_target, root_id))

        # A missing or malformed linked attempt must not fall back to the
        # retained ordinary branch merely because this root contains legacy rows.
        missing_attempt = copy.deepcopy(previous)
        missing_escape = next(item for item in missing_attempt["events"] if item["event_id"] == incident_ids[0])
        missing_escape["repair_attempt_id"] = "repair-missing"
        missing_escape["escape_key"]["repair_attempt_id"] = "repair-missing"
        missing_context = _validation_context(missing_attempt)
        assert missing_context is not None
        missing_incidents, missing_reasons = _modern_escape_incidents(missing_context, root_id)
        self.assertEqual(missing_reasons, set())
        self.assertNotIn(incident_ids[0], [item["event_id"] for item in missing_incidents])
        missing_result = validate_ledger(missing_attempt, self.schema)
        self.assertFalse(missing_result.valid, missing_result.reasons)
        self.assertIn(f"escape_causality:{root_id}", missing_result.reasons)

        malformed_attempt = copy.deepcopy(previous)
        next(item for item in malformed_attempt["repair_attempts"] if item["repair_attempt_id"] == repair_id)["reservation_event_id"] = "evt-reservation-missing"
        malformed_context = _validation_context(malformed_attempt)
        assert malformed_context is not None
        malformed_incidents, malformed_reasons = _modern_escape_incidents(malformed_context, root_id)
        self.assertTrue(any(reason.startswith(f"incident:ordinary:{root_id}:{repair_id}") for reason in malformed_reasons), malformed_reasons)
        self.assertEqual(malformed_incidents, [])
        malformed_result = validate_ledger(malformed_attempt, self.schema)
        self.assertFalse(malformed_result.valid, malformed_result.reasons)
        self.assertIn(f"escape_causality:{root_id}", malformed_result.reasons)


class LegacyV60AuditMigrationTests(unittest.TestCase):
    """Finite compatibility admission, migration, recovery, and replay."""

    TASK_ID = "01a07819-9ad8-7851-bc8f-513aa93f4dcb"
    LIVE_TASK = Path("/Users/ivanf/Documents/ChatGPT/Instructons/.mas1/tasks") / TASK_ID

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads((ROOT / "mas1-finding-ledger-v1.schema.json").read_text(encoding="utf-8"))
        evidence = cls.LIVE_TASK / "migrations" / LEGACY_V6_0_AUDIT_MIGRATION_ID
        ledger_bytes = (evidence / "before-ledger.json").read_bytes()
        marker_bytes = (evidence / "before-marker.json").read_bytes()
        if hashlib.sha256(ledger_bytes).hexdigest() != "ef0aef213647b5f7bf3eb29258c6d5f43ad3044ce2cc4f6e02aec9019082e992":
            raise RuntimeError("immutable before-ledger snapshot mismatch")
        if hashlib.sha256(marker_bytes).hexdigest() != "d7dd7438868fb019661c267a41245a622fa6a247a1a8a9fd39b64cb26dddba49":
            raise RuntimeError("immutable before-marker snapshot mismatch")
        cls.original_ledger = json.loads(ledger_bytes)
        cls.original_marker = json.loads(marker_bytes)

    @staticmethod
    def _pretty(value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

    @staticmethod
    def _sha(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def _prepare(self, root: Path) -> dict[str, object]:
        root = root.resolve()
        workspace = root / "workspace"
        task_dir = workspace / ".mas1" / "tasks" / self.TASK_ID
        migration_dir = task_dir / "migrations" / LEGACY_V6_0_AUDIT_MIGRATION_ID
        migration_dir.mkdir(parents=True, mode=0o700)
        migration_dir.chmod(0o700)
        ledger_path, marker_path = task_dir / "finding-ledger.v1.json", task_dir / "v6-cutover.json"

        before_ledger = copy.deepcopy(self.original_ledger)
        before_marker = copy.deepcopy(self.original_marker)
        before_ledger["task"].update({
            "workspace": str(workspace), "ledger_path": str(ledger_path), "marker_path": str(marker_path),
        })
        before_marker.update({"ledger_path": str(ledger_path), "marker_path": str(marker_path)})
        ledger_bytes, marker_bytes = self._pretty(before_ledger), self._pretty(before_marker)
        ledger_path.write_bytes(ledger_bytes); ledger_path.chmod(0o644)
        marker_path.write_bytes(marker_bytes); marker_path.chmod(0o644)

        descriptor = copy.deepcopy(LEGACY_V6_0_AUDIT_DESCRIPTOR)
        descriptor.update({
            "workspace": str(workspace), "ledger_path": str(ledger_path), "marker_path": str(marker_path),
            "migration_dir": str(migration_dir),
        })
        descriptor["authorization"]["path"] = str(migration_dir / "authorization.json")
        descriptor["decision"]["path"] = str(migration_dir / "decision.json")
        descriptor["original_representation"].update({
            "ledger_snapshot_path": str(migration_dir / "before-ledger.json"),
            "ledger_sha256": self._sha(ledger_bytes),
            "marker_snapshot_path": str(migration_dir / "before-marker.json"),
            "marker_sha256": self._sha(marker_bytes),
        })
        descriptor["journal"]["path"] = str(migration_dir / "migration.journal.json")
        descriptor["receipt"]["path"] = str(migration_dir / "migration.receipt.json")

        authorization = {
            "schema_version": "mas1-legacy-v6.0-migration-authorization.v1",
            "authorization_id": descriptor["authorization"]["authorization_id"],
            "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID,
        }
        authorization_bytes = self._pretty(authorization)
        descriptor["authorization"]["sha256"] = self._sha(authorization_bytes)
        decision = {
            "schema_version": "mas1-legacy-v6.0-migration-decision.v1",
            "decision_id": descriptor["decision"]["decision_id"],
            "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID,
            "disposition": "approved",
            "judge_result": {"result_sha256": LEGACY_V6_0_AUDIT_JUDGE_RESULT_SHA256},
        }
        decision_bytes = self._pretty(decision)
        descriptor["decision"]["sha256"] = self._sha(decision_bytes)
        descriptor_sha = self._sha(self._pretty(descriptor))
        ledger_candidate = ledger_core._legacy_candidate_bytes(ledger_bytes, descriptor)
        marker_candidate = ledger_core._legacy_candidate_bytes(marker_bytes, descriptor)

        entry = copy.deepcopy(LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID])
        entry.update({
            "workspace": str(workspace), "ledger_path": str(ledger_path), "marker_path": str(marker_path),
            "migration_dir": str(migration_dir),
        })
        entry["original"].update({"ledger_sha256": self._sha(ledger_bytes), "marker_sha256": self._sha(marker_bytes)})
        entry["authorization"].update({
            "path": str(migration_dir / "authorization.json"), "sha256": self._sha(authorization_bytes),
        })
        entry["decision"].update({
            "path": str(migration_dir / "decision.json"), "sha256": self._sha(decision_bytes),
        })
        entry["descriptor"]["sha256"] = descriptor_sha
        entry["transformation"].update({
            "after_ledger_sha256": self._sha(ledger_candidate),
            "after_marker_sha256": self._sha(marker_candidate),
        })
        fixed = entry["artifacts"]["fixed"]
        fixed.update({
            "authorization": str(migration_dir / "authorization.json"),
            "decision": str(migration_dir / "decision.json"),
            "before_ledger": str(migration_dir / "before-ledger.json"),
            "before_marker": str(migration_dir / "before-marker.json"),
            "journal": str(migration_dir / "migration.journal.json"),
            "receipt": str(migration_dir / "migration.receipt.json"),
            "lock": str(migration_dir / "migration.lock"),
        })
        temp = entry["artifacts"]["temporaries"]
        temp.update({
            "before_ledger": str(migration_dir / f".before-ledger.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
            "before_marker": str(migration_dir / f".before-marker.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
            "journal": str(migration_dir / f".migration.journal.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
            "receipt": str(migration_dir / f".migration.receipt.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
            "ledger_publication": str(task_dir / f".finding-ledger.v1.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
            "marker_publication": str(task_dir / f".v6-cutover.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp"),
        })
        entry["identity_requirements"]["uid"] = os.getuid()
        entry["journal"]["path"] = fixed["journal"]
        entry["receipt"]["path"] = fixed["receipt"]
        (migration_dir / "authorization.json").write_bytes(authorization_bytes)
        (migration_dir / "authorization.json").chmod(0o400)
        (migration_dir / "decision.json").write_bytes(decision_bytes)
        (migration_dir / "decision.json").chmod(0o400)
        schema = copy.deepcopy(self.schema)
        schema["$defs"]["legacyV60Audit"]["const"] = copy.deepcopy(descriptor)
        catalogue_sha = self._sha(json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode())
        return {
            "entry": entry, "descriptor": descriptor, "schema": schema, "catalogue_sha": catalogue_sha,
            "ledger_path": ledger_path, "marker_path": marker_path, "migration_dir": migration_dir,
            "ledger_bytes": ledger_bytes, "marker_bytes": marker_bytes,
        }

    def _patch(self, case: dict[str, object]):
        return mock.patch.multiple(
            ledger_core,
            LEGACY_V6_0_AUDIT_CATALOGUE={LEGACY_V6_0_AUDIT_MIGRATION_ID: case["entry"]},
            LEGACY_V6_0_AUDIT_CATALOGUE_SHA256=case["catalogue_sha"],
            LEGACY_V6_0_AUDIT_DESCRIPTOR=case["descriptor"],
        )

    def _crash_at(self, case: dict[str, object], label: str) -> None:
        def crash(point: str) -> None:
            if point == label:
                os._exit(91)
        with self._patch(case):
            process = multiprocessing.get_context("fork").Process(
                target=apply_legacy_v6_0_audit_migration, kwargs={"crash_hook": crash})
            process.start(); process.join(10)
        self.assertEqual(process.exitcode, 91, label)

    def test_legacy_catalogue_and_schema_literal_are_exact(self) -> None:
        descriptor_bytes = self._pretty(LEGACY_V6_0_AUDIT_DESCRIPTOR)
        catalogue_bytes = json.dumps(
            LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID],
            ensure_ascii=False, separators=(",", ":"), sort_keys=False,
        ).encode()
        self.assertEqual((len(descriptor_bytes), self._sha(descriptor_bytes)),
                         (5818, LEGACY_V6_0_AUDIT_DESCRIPTOR_SHA256))
        self.assertEqual((len(catalogue_bytes), self._sha(catalogue_bytes)),
                         (8798, LEGACY_V6_0_AUDIT_CATALOGUE_SHA256))
        evidence = self.LIVE_TASK / "migrations" / LEGACY_V6_0_AUDIT_MIGRATION_ID
        live_ledger = (evidence / "before-ledger.json").read_bytes()
        live_marker = (evidence / "before-marker.json").read_bytes()
        ledger_candidate = ledger_core._legacy_candidate_bytes(live_ledger, LEGACY_V6_0_AUDIT_DESCRIPTOR)
        marker_candidate = ledger_core._legacy_candidate_bytes(live_marker, LEGACY_V6_0_AUDIT_DESCRIPTOR)
        self.assertEqual((len(ledger_candidate), self._sha(ledger_candidate)),
                         (78650, "c69ccf5bb03a25faec07f402c560f6faf37f386b6e9b82fc3596e72903903aed"))
        self.assertEqual((len(marker_candidate), self._sha(marker_candidate)),
                         (12038, "ca5d518280d88ca52841d777acd53ea38bf82abd2b6e3e3a8452c2cc0d6fc937"))
        self.assertEqual(self.schema["$defs"]["legacyV60Audit"]["const"], LEGACY_V6_0_AUDIT_DESCRIPTOR)
        self.assertEqual(LEGACY_V6_0_AUDIT_AUTHORIZATION_SHA256,
                         "bc46358783920eef8a159a052aec4c034fe2763b29e5ceb58f15a4343ef6d546")
        self.assertEqual(LEGACY_V6_0_AUDIT_DECISION_SHA256,
                         "623900dddb37aff988f00d53a0a519f6d6f33749a6947757b0e76ce2cdd7ca5e")
        self.assertEqual(LEGACY_V6_0_AUDIT_DESCRIPTOR["threshold_evidence"]["evidence_refs"][0],
                         "agent-result:/root/response_contract_repair_review_astra")
        self.assertIn(".migration.journal.json.MIG-LEGACY-V6-0-AUDIT-01A07819-V1.tmp",
                      LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]
                      ["artifacts"]["temporaries"]["journal"])

    def test_schema_branches_are_mutually_exclusive_and_compatibility_closed(self) -> None:
        modern = copy.deepcopy(json.loads((ROOT / "mas1-ledger-fixtures.json").read_text())["base_ledgers"]["no_roots"])
        self.assertTrue(validate_ledger(modern, self.schema).valid)
        modern["legacy_v6_0_audit"] = copy.deepcopy(LEGACY_V6_0_AUDIT_DESCRIPTOR)
        self.assertFalse(validate_ledger(modern, self.schema).valid)
        modern.pop("legacy_v6_0_audit")
        modern["rogue_top_level"] = True
        self.assertTrue(validate_ledger(modern, self.schema).valid)

    def test_apply_accepts_exact_inputs_validates_and_replays_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            with self._patch(case):
                outcome = apply_legacy_v6_0_audit_migration()
                self.assertEqual(outcome, {"status": "complete", "replay": False,
                                           "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID})
                ledger = json.loads(case["ledger_path"].read_text())
                marker = json.loads(case["marker_path"].read_text())
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertTrue(result.valid, result.reasons)
                self.assertTrue(result.facts["legacy_v6_0_audit"]["active"])
                self.assertTrue(all(item["chronology_bucket"] == "unknown-chronology"
                                    for item in result.facts["activities"]))
                journal = json.loads((case["migration_dir"] / "migration.journal.json").read_text())
                receipt = json.loads((case["migration_dir"] / "migration.receipt.json").read_text())
                identities = journal["selected_identities"]
                self.assertEqual(tuple(identities), (
                    "ledger", "marker", "authorization", "decision", "ledger_candidate",
                    "marker_candidate", "published_ledger", "published_marker",
                ))
                self.assertEqual(identities["ledger_candidate"], identities["published_ledger"])
                self.assertEqual(identities["marker_candidate"], identities["published_marker"])
                self.assertEqual(receipt["published_ledger_identity"], identities["published_ledger"])
                self.assertEqual(receipt["published_marker_identity"], identities["published_marker"])
                records = [{"ledger_id": ledger["ledger_id"], "ledger": ledger,
                            "loaded_path": case["ledger_path"], "marker": marker}]
                self.assertEqual(analyzer.validate_ledger_set(case["schema"], records), {})
                report = analyzer.calculate(records)
                exposure = report["protocol_exposure"]["activity_counts"]
                self.assertEqual(exposure["v6"], 0)
                self.assertGreater(exposure["unknown-chronology"], 0)
                self.assertTrue(report["partial"])
                before = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns, self._sha(path.read_bytes()))
                          for path in case["migration_dir"].iterdir()}
                self.assertTrue(apply_legacy_v6_0_audit_migration()["replay"])
                after = {path.name: (path.stat().st_ino, path.stat().st_mtime_ns, self._sha(path.read_bytes()))
                         for path in case["migration_dir"].iterdir()}
                self.assertEqual(after, before)

    def test_zero_effect_authorization_layout_and_collision_rejections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary)); original = case["ledger_path"].read_bytes()
            with self._patch(case):
                with self.assertRaisesRegex(LegacyMigrationError, "catalogue_admission"):
                    apply_legacy_v6_0_audit_migration("outside-catalogue")
                case["migration_dir"].joinpath("authorization.json").chmod(0o600)
                with self.assertRaisesRegex(LegacyMigrationError, "authority_integrity"):
                    apply_legacy_v6_0_audit_migration()
                self.assertEqual(case["ledger_path"].read_bytes(), original)
                self.assertFalse(case["migration_dir"].joinpath("migration.journal.json").exists())

        for variant in ("collision", "journal-temp", "symlink"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                if variant == "collision":
                    case["migration_dir"].joinpath("before-ledger.json").write_text("foreign")
                elif variant == "journal-temp":
                    Path(case["entry"]["artifacts"]["temporaries"]["journal"]).write_text("foreign")
                else:
                    target = Path(temporary) / "foreign"; target.write_text("foreign")
                    case["migration_dir"].joinpath("before-ledger.json").symlink_to(target)
                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration()

    def test_standalone_snapshot_receipt_descriptor_and_type_tampering_fail(self) -> None:
        mutations = ("snapshot", "receipt", "descriptor", "marker", "boolean-number", "extra")
        for variant in mutations:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                with self._patch(case):
                    apply_legacy_v6_0_audit_migration()
                    ledger = json.loads(case["ledger_path"].read_text())
                    marker = json.loads(case["marker_path"].read_text())
                    if variant == "snapshot":
                        path = case["migration_dir"] / "before-ledger.json"; path.chmod(0o600)
                    elif variant == "receipt":
                        path = case["migration_dir"] / "migration.receipt.json"; path.chmod(0o600)
                    elif variant == "descriptor":
                        ledger["legacy_v6_0_audit"]["mode"] = "transplanted"
                    elif variant == "marker":
                        marker["post_cutover_boundary"] = "2026-09-08T11:00:10Z"
                    elif variant == "boolean-number":
                        ledger["roots"][0]["historical_escape_count_baseline"] = True
                    else:
                        ledger["legacy_v6_0_audit"]["private"] = "forbidden"
                    result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                    self.assertFalse(result.valid, (variant, result.reasons))

    def test_frozen_telemetry_is_recursively_exact_without_previous_ledger(self) -> None:
        variants = ("key-order", "scalar", "bool-number", "list-order", "container-type")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                with self._patch(case):
                    apply_legacy_v6_0_audit_migration()
                    ledger = json.loads(case["ledger_path"].read_text())
                    marker = json.loads(case["marker_path"].read_text())
                    telemetry = ledger["telemetry"]
                    if variant == "key-order":
                        ledger["telemetry"] = {key: telemetry[key] for key in reversed(tuple(telemetry))}
                    elif variant == "scalar":
                        telemetry["unavailable_reason"] += " altered"
                    elif variant == "bool-number":
                        telemetry["activity_inventory_complete"] = 0
                    elif variant == "list-order":
                        telemetry["inventory_evidence_refs"] = list(reversed(telemetry["inventory_evidence_refs"]))
                    else:
                        telemetry["inventory_evidence_refs"][0] = {
                            "value": telemetry["inventory_evidence_refs"][0]
                        }
                    case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                    result = validate_ledger(
                        ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                    self.assertFalse(result.valid)
                    self.assertIn("compat:frozen_telemetry", result.reasons)

    def test_mixed_layout_without_authenticated_journal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            ledger_after = ledger_core._legacy_candidate_bytes(case["ledger_bytes"], case["descriptor"])
            case["ledger_path"].write_bytes(ledger_after); case["ledger_path"].chmod(0o644)
            with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "unauthenticated_mixed_state"):
                apply_legacy_v6_0_audit_migration()
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            marker_after = ledger_core._legacy_candidate_bytes(case["marker_bytes"], case["descriptor"])
            case["marker_path"].write_bytes(marker_after); case["marker_path"].chmod(0o644)
            with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "layout_contradiction"):
                apply_legacy_v6_0_audit_migration()

    def test_lock_exclusion_and_identity_anomalies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary)); lock = case["migration_dir"] / "migration.lock"
            lock.write_bytes(b""); lock.chmod(0o600)
            fd = os.open(lock, os.O_RDWR)
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "lock_busy"):
                    apply_legacy_v6_0_audit_migration()
            finally:
                os.close(fd)
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary)); hard = Path(temporary) / "hard"
            os.link(case["ledger_path"], hard)
            with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "canonical_identity"):
                apply_legacy_v6_0_audit_migration()

    def test_recovery_rejects_selected_replacement_and_candidate_drift_before_publish(self) -> None:
        variants = ("ledger-replaced", "authorization-replaced", "ledger-drift",
                    "marker-symlink", "marker-hardlink")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                self._crash_at(case, "after_publication_intent_journal")
                entry = case["entry"]
                ledger_path, marker_path = case["ledger_path"], case["marker_path"]
                if variant == "ledger-replaced":
                    replacement = ledger_path.with_name("same-byte-ledger-replacement")
                    replacement.write_bytes(ledger_path.read_bytes()); replacement.chmod(0o644)
                    os.replace(replacement, ledger_path)
                elif variant == "authorization-replaced":
                    authorization = Path(entry["artifacts"]["fixed"]["authorization"])
                    replacement = authorization.with_name("same-byte-authorization-replacement")
                    replacement.write_bytes(authorization.read_bytes()); replacement.chmod(0o400)
                    os.replace(replacement, authorization)
                elif variant == "ledger-drift":
                    candidate = Path(entry["artifacts"]["temporaries"]["ledger_publication"])
                    candidate.write_bytes(b"{}\n"); candidate.chmod(0o644)
                elif variant == "marker-symlink":
                    candidate = Path(entry["artifacts"]["temporaries"]["marker_publication"])
                    foreign = Path(temporary) / "foreign-marker"
                    foreign.write_bytes(candidate.read_bytes()); foreign.chmod(0o644)
                    candidate.unlink(); candidate.symlink_to(foreign)
                else:
                    candidate = Path(entry["artifacts"]["temporaries"]["marker_publication"])
                    os.link(candidate, Path(temporary) / "unrelated-marker-hardlink")
                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration()
                self.assertEqual(self._sha(ledger_path.read_bytes()), entry["original"]["ledger_sha256"])
                self.assertEqual(self._sha(marker_path.read_bytes()), entry["original"]["marker_sha256"])

        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            self._crash_at(case, "after_ledger_published_journal")
            entry = case["entry"]
            marker_path = case["marker_path"]
            replacement = marker_path.with_name("same-byte-marker-replacement")
            replacement.write_bytes(marker_path.read_bytes()); replacement.chmod(0o644)
            os.replace(replacement, marker_path)
            with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "selected_identity:marker"):
                apply_legacy_v6_0_audit_migration()
            self.assertEqual(self._sha(marker_path.read_bytes()), entry["original"]["marker_sha256"])

    def test_lock_path_swap_is_rejected_after_open_and_before_canonical_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary)); entry = case["entry"]
            lock = Path(entry["artifacts"]["fixed"]["lock"])
            swapped = False

            def swap(point: str) -> None:
                nonlocal swapped
                if point == "before_ledger_publish_rename" and not swapped:
                    swapped = True
                    os.replace(lock, lock.with_name("displaced-lock"))
                    lock.write_bytes(b""); lock.chmod(0o600)

            with self._patch(case), self.assertRaisesRegex(LegacyMigrationError, "lock_integrity"):
                apply_legacy_v6_0_audit_migration(crash_hook=swap)
            self.assertTrue(swapped)
            self.assertEqual(self._sha(case["ledger_path"].read_bytes()), entry["original"]["ledger_sha256"])
            self.assertEqual(self._sha(case["marker_path"].read_bytes()), entry["original"]["marker_sha256"])

    def test_post_checkpoint_path_swaps_cannot_reach_marker_or_receipt(self) -> None:
        variants = ("candidate", "authority", "lock", "published-ledger")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                swapped = False

                def replace_same_bytes(path: Path, mode: int, suffix: str) -> None:
                    replacement = path.with_name(f"same-byte-{suffix}")
                    replacement.write_bytes(path.read_bytes()); replacement.chmod(mode)
                    os.replace(replacement, path)

                def swap(point: str) -> None:
                    nonlocal swapped
                    trigger = ("after_ledger_publish_rename" if variant == "published-ledger"
                               else "after_ledger_publish_checkpoint")
                    if point != trigger or swapped:
                        return
                    swapped = True
                    if variant == "candidate":
                        replace_same_bytes(
                            Path(entry["artifacts"]["temporaries"]["ledger_publication"]),
                            0o644, "candidate")
                    elif variant == "authority":
                        replace_same_bytes(
                            Path(entry["artifacts"]["fixed"]["authorization"]),
                            0o400, "authorization")
                    elif variant == "lock":
                        lock = Path(entry["artifacts"]["fixed"]["lock"])
                        os.replace(lock, lock.with_name("post-checkpoint-displaced-lock"))
                        lock.write_bytes(b""); lock.chmod(0o600)
                    else:
                        replace_same_bytes(case["ledger_path"], 0o644, "published-ledger")

                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration(crash_hook=swap)
                self.assertTrue(swapped)
                self.assertEqual(self._sha(case["marker_path"].read_bytes()), entry["original"]["marker_sha256"])
                self.assertFalse(Path(entry["artifacts"]["fixed"]["receipt"]).exists())
                journal = json.loads(Path(entry["artifacts"]["fixed"]["journal"]).read_text())
                self.assertEqual(journal["events"][-1]["phase"], "publication_intent")

    def test_recovery_rejects_same_byte_published_ledger_replacement(self) -> None:
        for crash_point in ("after_ledger_publish_rename", "after_ledger_published_journal"):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                self._crash_at(case, crash_point)
                ledger_path = case["ledger_path"]
                replacement = ledger_path.with_name("same-byte-recovered-ledger")
                replacement.write_bytes(ledger_path.read_bytes()); replacement.chmod(0o644)
                os.replace(replacement, ledger_path)
                with self._patch(case), self.assertRaisesRegex(
                        LegacyMigrationError, "ledger_published_identity"):
                    apply_legacy_v6_0_audit_migration()
                self.assertEqual(self._sha(case["marker_path"].read_bytes()), entry["original"]["marker_sha256"])
                self.assertFalse(Path(entry["artifacts"]["fixed"]["receipt"]).exists())

    def test_terminal_replay_rebinds_published_and_selected_identities(self) -> None:
        variants = ("ledger-replaced", "authorization-replaced", "marker-hardlink", "lock-swap")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                with self._patch(case):
                    apply_legacy_v6_0_audit_migration()
                    hook = None
                    if variant == "ledger-replaced":
                        path = case["ledger_path"]; replacement = path.with_name("same-byte-terminal-ledger")
                        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644)
                        os.replace(replacement, path)
                    elif variant == "authorization-replaced":
                        path = Path(entry["artifacts"]["fixed"]["authorization"])
                        replacement = path.with_name("same-byte-terminal-authorization")
                        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o400)
                        os.replace(replacement, path)
                    elif variant == "marker-hardlink":
                        os.link(case["marker_path"], Path(temporary) / "terminal-marker-hardlink")
                    else:
                        lock = Path(entry["artifacts"]["fixed"]["lock"])
                        def hook(point: str) -> None:
                            if point == "after_lock_open":
                                os.replace(lock, lock.with_name("terminal-displaced-lock"))
                                lock.write_bytes(b""); lock.chmod(0o600)
                    if variant != "lock-swap":
                        ledger = json.loads(case["ledger_path"].read_text())
                        marker = json.loads(case["marker_path"].read_text())
                        validation = validate_ledger(
                            ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                        self.assertFalse(validation.valid, (variant, validation.reasons))
                    with self.assertRaises(LegacyMigrationError):
                        apply_legacy_v6_0_audit_migration(crash_hook=hook)

    def test_terminal_replay_rejects_receipt_and_journal_inode_swaps_after_rebind(self) -> None:
        for linked_pair in (False, True):
            for artifact in ("receipt", "journal"):
                with self.subTest(linked_pair=linked_pair, artifact=artifact), \
                        tempfile.TemporaryDirectory() as temporary:
                    case = self._prepare(Path(temporary)); entry = case["entry"]
                    receipt = Path(entry["artifacts"]["fixed"]["receipt"])
                    receipt_temp = Path(entry["artifacts"]["temporaries"]["receipt"])
                    with self._patch(case):
                        apply_legacy_v6_0_audit_migration()
                        if linked_pair:
                            os.link(receipt, receipt_temp)
                        swapped = False

                        def swap(point: str) -> None:
                            nonlocal swapped
                            if point != "after_receipt_replay_rebind" or swapped:
                                return
                            swapped = True
                            if linked_pair:
                                self.assertFalse(receipt_temp.exists())
                            path = receipt if artifact == "receipt" else Path(
                                entry["artifacts"]["fixed"]["journal"])
                            replacement = path.with_name(f"same-byte-replay-{artifact}")
                            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o400)
                            os.replace(replacement, path)

                        with self.assertRaises(LegacyMigrationError):
                            apply_legacy_v6_0_audit_migration(crash_hook=swap)
                        self.assertTrue(swapped)

    def test_recovered_receipt_pair_rejects_swaps_around_unlink(self) -> None:
        for boundary in ("before_receipt_temp_unlink", "after_receipt_temp_unlink"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                receipt = Path(entry["artifacts"]["fixed"]["receipt"])
                receipt_temp = Path(entry["artifacts"]["temporaries"]["receipt"])
                with self._patch(case):
                    apply_legacy_v6_0_audit_migration()
                    os.link(receipt, receipt_temp)
                    swapped = False

                    def swap(point: str) -> None:
                        nonlocal swapped
                        if point != boundary or swapped:
                            return
                        swapped = True
                        self.assertEqual(receipt_temp.exists(), boundary.startswith("before_"))
                        replacement = receipt.with_name(f"same-byte-{boundary}-receipt")
                        replacement.write_bytes(receipt.read_bytes()); replacement.chmod(0o400)
                        os.replace(replacement, receipt)

                    with self.assertRaisesRegex(LegacyMigrationError, "receipt_integrity"):
                        apply_legacy_v6_0_audit_migration(crash_hook=swap)
                    self.assertTrue(swapped)

    def test_receipt_admission_rebinds_all_dependencies_and_staged_identity(self) -> None:
        variants = (
            "ledger", "marker", "authorization", "decision", "journal", "lock",
            "receipt-temp-replaced", "receipt-temp-mode", "receipt-temp-hardlink",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                swapped = False

                def replace_same_bytes(path: Path, mode: int, suffix: str) -> None:
                    replacement = path.with_name(f"same-byte-{suffix}")
                    replacement.write_bytes(path.read_bytes()); replacement.chmod(mode)
                    os.replace(replacement, path)

                def swap(point: str) -> None:
                    nonlocal swapped
                    if point != "after_receipt_temp_dir_fsync" or swapped:
                        return
                    swapped = True
                    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
                    if variant == "ledger":
                        replace_same_bytes(case["ledger_path"], 0o644, "receipt-ledger")
                    elif variant == "marker":
                        replace_same_bytes(case["marker_path"], 0o644, "receipt-marker")
                    elif variant in {"authorization", "decision", "journal"}:
                        replace_same_bytes(Path(fixed[variant]), 0o400, f"receipt-{variant}")
                    elif variant == "lock":
                        lock = Path(fixed["lock"])
                        os.replace(lock, lock.with_name("receipt-displaced-lock"))
                        lock.write_bytes(b""); lock.chmod(0o600)
                    elif variant == "receipt-temp-replaced":
                        replace_same_bytes(Path(temps["receipt"]), 0o400, "receipt-temp")
                    elif variant == "receipt-temp-mode":
                        Path(temps["receipt"]).chmod(0o600)
                    else:
                        os.link(Path(temps["receipt"]), Path(temporary) / "receipt-temp-hardlink")

                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration(crash_hook=swap)
                self.assertTrue(swapped)
                self.assertFalse(Path(entry["artifacts"]["fixed"]["receipt"]).exists())

    def test_terminal_success_return_rechecks_named_objects_after_receipt_publish(self) -> None:
        variants = ("ledger", "marker", "authorization", "decision", "journal", "lock", "receipt")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                swapped = False

                def replace_same_bytes(path: Path, mode: int, suffix: str) -> None:
                    replacement = path.with_name(f"same-byte-final-{suffix}")
                    replacement.write_bytes(path.read_bytes()); replacement.chmod(mode)
                    os.replace(replacement, path)

                def swap(point: str) -> None:
                    nonlocal swapped
                    if point != "after_receipt_dir_fsync" or swapped:
                        return
                    swapped = True
                    fixed = entry["artifacts"]["fixed"]
                    if variant == "ledger":
                        replace_same_bytes(case["ledger_path"], 0o644, "ledger")
                    elif variant == "marker":
                        replace_same_bytes(case["marker_path"], 0o644, "marker")
                    elif variant in {"authorization", "decision", "journal", "receipt"}:
                        replace_same_bytes(Path(fixed[variant]), 0o400, variant)
                    else:
                        lock = Path(fixed["lock"])
                        os.replace(lock, lock.with_name("final-displaced-lock"))
                        lock.write_bytes(b""); lock.chmod(0o600)

                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration(crash_hook=swap)
                self.assertTrue(swapped)

    def test_exclusive_link_interval_recovers_only_owned_pair(self) -> None:
        cases = (
            ("before_ledger", "after_before_ledger_link"),
            ("before_marker", "after_before_marker_link"),
            ("receipt", "after_receipt_link"),
        )
        for artifact, crash_point in cases:
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                self._crash_at(case, crash_point)
                target = Path(entry["artifacts"]["fixed"][artifact])
                temp = Path(entry["artifacts"]["temporaries"][artifact])
                self.assertEqual((target.stat().st_dev, target.stat().st_ino, target.stat().st_nlink),
                                 (temp.stat().st_dev, temp.stat().st_ino, 2))
                with self._patch(case):
                    self.assertEqual(apply_legacy_v6_0_audit_migration()["status"], "complete")
                self.assertFalse(temp.exists())
                self.assertEqual(target.stat().st_nlink, 1)

        for artifact, crash_point in (("before_ledger", "after_before_ledger_rename"),
                                      ("receipt", None)):
            with self.subTest(unrelated_hardlink=artifact), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary)); entry = case["entry"]
                if crash_point is None:
                    with self._patch(case):
                        apply_legacy_v6_0_audit_migration()
                else:
                    self._crash_at(case, crash_point)
                target = Path(entry["artifacts"]["fixed"][artifact])
                os.link(target, Path(temporary) / f"unrelated-{artifact}")
                with self._patch(case), self.assertRaises(LegacyMigrationError):
                    apply_legacy_v6_0_audit_migration()

    def test_crash_matrix_recovers_only_authenticated_progress(self) -> None:
        phases = LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]["journal"]["phases"]
        labels = [item for phase in phases for item in (f"before_{phase}_journal", f"after_{phase}_journal")]
        labels += ["before_lock_open", "after_lock_open", "before_lock_create_dir_fsync", "after_lock_create_dir_fsync"]
        for artifact in ("journal", "before_ledger", "before_marker", "ledger_candidate", "marker_candidate", "receipt"):
            labels.extend(
                f"{side}_{artifact}_{boundary}"
                for boundary in ("temp_create", "write", "file_fsync", "temp_dir_fsync")
                for side in ("before", "after")
            )
        for artifact in ("journal", "before_ledger", "before_marker", "receipt"):
            labels.extend(
                f"{side}_{artifact}_{boundary}"
                for boundary in ("rename", "dir_fsync")
                for side in ("before", "after")
            )
        for artifact in ("before_ledger", "before_marker", "receipt"):
            labels.append(f"after_{artifact}_link")
            labels.extend(f"{side}_{artifact}_temp_unlink" for side in ("before", "after"))
        for artifact in ("ledger_publish", "marker_publish"):
            labels.extend(
                f"{side}_{artifact}_{boundary}"
                for boundary in ("rename", "dir_fsync")
                for side in ("before", "after")
            )
        labels.extend(("after_ledger_publish_checkpoint", "after_marker_publish_checkpoint"))
        labels = list(dict.fromkeys(labels))
        unauthenticated_temp = {
            "after_journal_temp_create", "before_journal_write", "after_journal_write",
            "before_journal_file_fsync", "after_journal_file_fsync",
            "before_journal_temp_dir_fsync", "after_journal_temp_dir_fsync", "before_journal_rename",
        }
        for label in labels:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                def crash(point: str) -> None:
                    if point == label:
                        os._exit(91)
                with self._patch(case):
                    process = multiprocessing.get_context("fork").Process(
                        target=apply_legacy_v6_0_audit_migration, kwargs={"crash_hook": crash})
                    process.start(); process.join(10)
                    self.assertEqual(process.exitcode, 91, label)
                    # A crash before the selected journal becomes durable has
                    # no authenticated ownership and must stop on its temp.
                    if label in unauthenticated_temp:
                        with self.assertRaises(LegacyMigrationError):
                            apply_legacy_v6_0_audit_migration()
                    else:
                        self.assertEqual(apply_legacy_v6_0_audit_migration()["status"], "complete")

        for label in ("after_before_ledger_write", "after_ledger_candidate_file_fsync",
                      "after_ledger_publish_rename", "after_receipt_write"):
            with self.subTest(ordinary_exception=label), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                def ordinary(point: str) -> None:
                    if point == label:
                        raise RuntimeError("synthetic")
                with self._patch(case):
                    with self.assertRaises(RuntimeError):
                        apply_legacy_v6_0_audit_migration(crash_hook=ordinary)
                    self.assertEqual(apply_legacy_v6_0_audit_migration()["status"], "complete")

    def test_recovered_publications_fsync_directory_before_journal_advance(self) -> None:
        cases = (
            ("ledger", "after_ledger_publish_rename", "ledger_publish", "ledger_published"),
            ("marker", "after_marker_publish_rename", "marker_publish", "marker_published"),
        )
        for artifact, crash_point, publish_label, phase in cases:
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))

                def crash(point: str) -> None:
                    if point == crash_point:
                        os._exit(91)

                with self._patch(case):
                    process = multiprocessing.get_context("fork").Process(
                        target=apply_legacy_v6_0_audit_migration, kwargs={"crash_hook": crash})
                    process.start(); process.join(10)
                    self.assertEqual(process.exitcode, 91)

                    observed: list[str] = []
                    durable = False

                    def power_loss_model(point: str) -> None:
                        nonlocal durable
                        observed.append(point)
                        if point == f"after_{publish_label}_dir_fsync":
                            durable = True
                        if point == f"before_{phase}_journal":
                            # Model the crash-consistency requirement: journal
                            # publication must not begin while the recovered
                            # canonical rename is still only volatile state.
                            if not durable:
                                raise AssertionError(f"{artifact} phase advanced before directory fsync")
                            raise RuntimeError("synthetic power loss after durability barrier")

                    with self.assertRaisesRegex(RuntimeError, "synthetic power loss"):
                        apply_legacy_v6_0_audit_migration(crash_hook=power_loss_model)
                    fsync_done = observed.index(f"after_{publish_label}_dir_fsync")
                    journal_started = observed.index(f"before_{phase}_journal")
                    self.assertLess(fsync_done, journal_started)
                    self.assertEqual(apply_legacy_v6_0_audit_migration()["status"], "complete")

    def test_current_backdated_attempt_and_frozen_authority_are_nonauthorizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            with self._patch(case):
                apply_legacy_v6_0_audit_migration()
                ledger = json.loads(case["ledger_path"].read_text()); marker = json.loads(case["marker_path"].read_text())
                root_id = ledger["roots"][0]["root_cause_id"]
                attempt = copy.deepcopy(ledger["repair_attempts"][0])
                attempt.update({
                    "repair_attempt_id": "compat-backdated", "root_cause_id": root_id,
                    "record_kind": "reservation", "started_at": "2026-09-10T00:00:00Z",
                    "authorization_event_id": ledger["events"][0]["event_id"],
                })
                ledger["repair_attempts"].append(attempt)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                self.assertIn("compat:frozen_root_touch:repair_attempts:compat-backdated", result.reasons)

    def test_appended_legacy_shape_is_current_by_exact_snapshot_membership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            with self._patch(case):
                apply_legacy_v6_0_audit_migration()
                ledger = json.loads(case["ledger_path"].read_text()); marker = json.loads(case["marker_path"].read_text())
                baseline = validate_ledger(
                    ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertTrue(baseline.valid, baseline.reasons)
                copied = copy.deepcopy(ledger["repair_attempts"][0])
                copied["repair_attempt_id"] = "legacy-shaped-new-id"
                copied["started_at"] = "2020-01-01T00:00:00Z"
                copied["completed_at"] = "2020-01-01T00:00:01Z"
                self.assertNotIn("record_kind", copied)
                ledger["repair_attempts"].append(copied)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                result = validate_ledger(
                    ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                root_id = copied["root_cause_id"]
                self.assertFalse(result.valid)
                self.assertIn(
                    "compat:frozen_root_touch:repair_attempts:legacy-shaped-new-id", result.reasons)
                other_root = next(item["root_cause_id"] for item in ledger["roots"]
                                  if item["root_cause_id"] != root_id)
                self.assertEqual(result.facts["threshold_facts"][other_root],
                                 baseline.facts["threshold_facts"][other_root])

        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            with self._patch(case):
                apply_legacy_v6_0_audit_migration()
                ledger = json.loads(case["ledger_path"].read_text()); marker = json.loads(case["marker_path"].read_text())
                activity = copy.deepcopy(ledger["activities"][0])
                activity.update({
                    "activity_id": "legacy-shaped-current-implementation",
                    "type": "implementation",
                    "started_at": "2020-01-01T00:00:00Z",
                    "completed_at": "2020-01-01T00:00:01Z",
                })
                ledger["activities"].append(activity)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                result = validate_ledger(
                    ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                for root_id in activity["root_cause_ids"]:
                    self.assertEqual(
                        result.facts["threshold_facts"][root_id],
                        baseline.facts["threshold_facts"][root_id],
                    )
                self.assertTrue(any(reason.startswith("compat:frozen_root_touch:activities:")
                                    for reason in result.reasons), result.reasons)

    def test_neutral_root_ownership_reaches_fixed_point_independent_of_traversal_order(self) -> None:
        observations: list[tuple[set[str], set[str], set[str]]] = []
        for head_first in (True, False):
            with self.subTest(head_first=head_first), tempfile.TemporaryDirectory() as temporary:
                case = self._prepare(Path(temporary))
                with self._patch(case):
                    apply_legacy_v6_0_audit_migration()
                    ledger = json.loads(case["ledger_path"].read_text())
                    marker = json.loads(case["marker_path"].read_text())
                    baseline = validate_ledger(
                        ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                    self.assertTrue(baseline.valid, baseline.reasons)
                    worker_root = "RC-HARVEST-WORKER-DEADLINE-CLEANUP"
                    atomicity_root = "RC-HARVEST-PREPARE-PAIR-ATOMICITY"
                    template = copy.deepcopy(ledger["events"][0])
                    sequence = max(event["sequence"] for event in ledger["events"]) + 1

                    def event(event_id: str, offset: int, references: list[str],
                              root_id: str | None = None) -> dict:
                        item = copy.deepcopy(template)
                        item.update({
                            "event_id": event_id, "sequence": sequence + offset,
                            "at": f"2026-09-11T13:{30 + offset:02d}:00Z",
                            "causal_refs": references, "root_cause_id": root_id,
                        })
                        return item

                    explicit = event(
                        "EVT-CURRENT-EXPLICIT-ROOT", 0, ["ACT-V6-CUTOVER-001"], worker_root)
                    head = event(
                        "EVT-CURRENT-NEUTRAL-HEAD", 1,
                        ["ACT-V6-ASTRA-JUDGMENT-001", "EVT-CURRENT-NEUTRAL-TAIL"])
                    tail = event(
                        "EVT-CURRENT-NEUTRAL-TAIL", 2, ["ACT-V6-SOL-REVIEW-001"])
                    if head_first:
                        ledger["events"].extend((explicit, head, tail))
                    else:
                        tail["sequence"], head["sequence"] = sequence + 1, sequence + 2
                        tail["at"], head["at"] = "2026-09-11T13:31:00Z", "2026-09-11T13:32:00Z"
                        ledger["events"].extend((explicit, tail, head))
                    case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                    result = validate_ledger(
                        ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                    self.assertFalse(result.valid)
                    context = _validation_context(ledger)
                    self.assertIsNotNone(context)
                    assert context is not None
                    ownership = ledger_core._legacy_row_root_ownership(context)
                    event_indexes = {
                        item["event_id"]: index for index, item in enumerate(context.rows["events"])
                    }
                    explicit_roots = ownership[("events", event_indexes[explicit["event_id"]])]
                    head_roots = ownership[("events", event_indexes[head["event_id"]])]
                    tail_roots = ownership[("events", event_indexes[tail["event_id"]])]
                    self.assertEqual(explicit_roots, {worker_root})
                    self.assertEqual(head_roots, {worker_root, atomicity_root})
                    self.assertEqual(tail_roots, {worker_root, atomicity_root})
                    modern_roots: set[str] = set()
                    self.assertTrue(any(reason.startswith("compat:frozen_root_touch:events:")
                                        for reason in result.reasons), result.reasons)
                    for root_id in set(result.facts["threshold_facts"]):
                        self.assertEqual(
                            result.facts["threshold_facts"][root_id],
                            baseline.facts["threshold_facts"][root_id])
                    observations.append((explicit_roots, head_roots, modern_roots))
        self.assertEqual(observations[0], observations[1])

    def test_analyzer_and_immutable_dependency_integration(self) -> None:
        expected = {
            "validate-mas1-ledger-fixtures.py": "61627e49ba9512c874f17da79b78bf35b82119310ac034cc7cb3727895265d1f",
            "mas1-ledger-fixtures.json": "9f2fe85fa5649fd1f150bf1a11003bc4016d6a75b00dae9487b181be79b14f7e",
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        self.assertIn("MAS1-6.1_20260908T154848Z", INVALIDATED_CUTOVER_CATALOGUE)


class PostMigrationRepresentabilityTests(unittest.TestCase):
    """Release-catalogued historical reports remain evidence, never authority."""

    TASK_ID = LegacyV60AuditMigrationTests.TASK_ID
    LIVE_TASK = LegacyV60AuditMigrationTests.LIVE_TASK

    @classmethod
    def setUpClass(cls) -> None:
        LegacyV60AuditMigrationTests.setUpClass()
        cls.schema = LegacyV60AuditMigrationTests.schema
        cls.original_ledger = LegacyV60AuditMigrationTests.original_ledger
        cls.original_marker = LegacyV60AuditMigrationTests.original_marker

    _pretty = staticmethod(LegacyV60AuditMigrationTests._pretty)
    _sha = staticmethod(LegacyV60AuditMigrationTests._sha)
    _prepare = LegacyV60AuditMigrationTests._prepare

    def _report_catalogue(self, case: dict[str, object]) -> tuple[dict, str]:
        catalogue = copy.deepcopy(HISTORICAL_REPORT_IMPORT_CATALOGUE)
        entry = catalogue["entries"][0]
        entry.update({
            "workspace": case["entry"]["workspace"],
            "ledger_path": case["entry"]["ledger_path"],
            "required_descriptor_sha256": case["entry"]["descriptor"]["sha256"],
        })
        digest = self._sha(ledger_core._canonical_json_ascii(catalogue))
        return catalogue, digest

    def _patch(self, case: dict[str, object]):
        catalogue, digest = self._report_catalogue(case)
        return mock.patch.multiple(
            ledger_core,
            LEGACY_V6_0_AUDIT_CATALOGUE={LEGACY_V6_0_AUDIT_MIGRATION_ID: case["entry"]},
            LEGACY_V6_0_AUDIT_CATALOGUE_SHA256=case["catalogue_sha"],
            LEGACY_V6_0_AUDIT_DESCRIPTOR=case["descriptor"],
            HISTORICAL_REPORT_IMPORT_CATALOGUE=catalogue,
            HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256=digest,
        )

    def _registered(self, temporary: str) -> tuple[dict[str, object], dict, dict]:
        case = self._prepare(Path(temporary))
        with self._patch(case):
            apply_legacy_v6_0_audit_migration()
        ledger = json.loads(case["ledger_path"].read_text())
        marker = json.loads(case["marker_path"].read_text())
        sequence = max(event["sequence"] for event in ledger["events"])
        import_activity_id = "ACT-RETRY-V2-PERSISTENCE-REPORT-IMPORT-001"
        p0, p1, p2 = copy.deepcopy(HISTORICAL_REPORT_IMPORT_PAYLOADS)
        ledger["observations"].extend((p0, p1, p2))
        ledger["roots"].append({
            "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
            "state": "blocked", "previous_state": "open",
            "blocked_reason": "A second retained repair escape requires a current Astra-authorized successor.",
            "block_code": "second-escape-astra-required",
            "invariant": HISTORICAL_REPORT_IMPORT_CATALOGUE["entries"][0]["origin_invariant"],
            "causal_explanation": HISTORICAL_REPORT_IMPORT_CATALOGUE["entries"][0]["origin_causal_explanation"],
            "created_at": "2026-09-11T13:12:00Z", "creation_time_basis": "ledger-registration",
            "reconciliation_complete": False,
            "first_observation_id": p0["observation_id"], "escape_count_lifetime": None,
            "introducing_cycle_id": None, "fixing_cycle_ids": [], "verifying_cycle_ids": [],
            "closure_event_id": None,
            "closure_gate": {
                "original_reproduction_test_evidence_id": None,
                "exact_recurrence_test_evidence_ids": [], "same_root_sibling_test_evidence_ids": [],
                "repair_attempt_id": None, "post_repair_review_cycle_id": None,
                "post_repair_review_activity_id": None, "following_unchanged_cycle_id": None,
                "following_unchanged_activity_id": None, "review_basis_id": None,
            },
            "historical_escape_count_baseline": None, "historical_escape_evidence_refs": [],
            "threshold_anchor": {"kind": "historical-report-lower-bound", "report_import_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID},
            "first_threshold_activation_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            "historical_baseline_reconciliation_event_id": None,
        })
        ledger["activities"].append({
            "activity_id": import_activity_id, "type": "ledger-administration", "status": "completed",
            "started_at": "2026-09-11T13:11:00Z", "completed_at": "2026-09-11T13:11:30Z",
            "requested": {"model": None, "reasoning_effort": None, "profile": None},
            "actual": {"model": None, "reasoning_effort": None, "profile": None},
            "runtime_verified": False, "runtime_evidence": None,
            "runtime_unavailable_reason": "Historical importer runtime telemetry is unavailable.",
            "session_id": None, "session_id_unavailable_reason": "Unavailable.",
            "thread_id": None, "thread_id_unavailable_reason": "Unavailable.",
            "token_usage": {"input": None, "output": None, "reasoning": None, "total": None,
                            "source": "unavailable", "unavailable_reason": "Unavailable.",
                            "reasoning_unavailable_reason": "Unavailable."},
            "attribution_mode": "direct", "root_cause_ids": [HISTORICAL_REPORT_ROOT_ID],
            "repair_attempt_id": None, "repair_attempt_bindings": [],
        })
        bindings = [
            {"observation_id": payload["observation_id"], "payload_sha256": digest}
            for payload, digest in zip(HISTORICAL_REPORT_IMPORT_PAYLOADS, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256)
        ]
        _, report_catalogue_sha = self._report_catalogue(case)
        ledger["events"].extend((
            {
                "record_kind": "historical-report-import-event-v1",
                "schema_version": "mas1-historical-report-import-event.v1",
                "type": "historical-report-imported", "event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
                "sequence": sequence + 1, "at": "2026-09-11T13:11:45Z",
                "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
                "causal_refs": [import_activity_id, p0["observation_id"], p1["observation_id"], p2["observation_id"], HISTORICAL_REPORT_ROOT_ID],
                "evidence_refs": ["catalogue:" + HISTORICAL_REPORT_IMPORT_ENTRY_ID],
                "at_semantics": "administrative-import-time",
                "catalogue_entry_id": HISTORICAL_REPORT_IMPORT_ENTRY_ID,
                "catalogue_sha256": report_catalogue_sha,
                "import_activity_id": import_activity_id, "observation_bindings": bindings,
                "observation_id": None, "repair_attempt_id": None, "review_basis_id": None,
                "cycle_id": None, "root_relationship": None, "escape_key": None,
            },
            {
                "event_id": HISTORICAL_REPORT_ROOT_OPENED_EVENT_ID, "sequence": sequence + 2,
                "at": "2026-09-11T13:12:00Z", "type": "root-opened",
                "causal_refs": [HISTORICAL_REPORT_IMPORT_EVENT_ID, HISTORICAL_REPORT_ROOT_ID, p0["observation_id"]],
                "root_cause_id": HISTORICAL_REPORT_ROOT_ID, "observation_id": p0["observation_id"],
                "repair_attempt_id": None, "review_basis_id": None, "cycle_id": None,
                "root_relationship": "initial", "escape_key": None,
            },
            {
                "event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID, "sequence": sequence + 3,
                "at": "2026-09-11T13:12:01Z", "type": "threshold-activated",
                "causal_refs": [HISTORICAL_REPORT_IMPORT_EVENT_ID, HISTORICAL_REPORT_ROOT_ID],
                "root_cause_id": HISTORICAL_REPORT_ROOT_ID, "observation_id": None,
                "repair_attempt_id": None, "review_basis_id": None, "cycle_id": None,
                "root_relationship": None, "escape_key": None,
                "activation_anchor_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
                "first_threshold_known_at": None, "original_protocol_adopted_at": None,
                "effective_at": "2026-09-11T13:10:56Z",
                "evidence_refs": ["migration-receipt:MIG-LEGACY-V6-0-AUDIT-01A07819-V1"],
            },
        ))
        case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
        return case, ledger, marker

    def _append_successor(self, ledger: dict, *, suffix: str = "001", predecessor_ids: list[str] | None = None,
                          outcome: str = "succeeded") -> dict[str, str]:
        root = next(item for item in ledger["roots"] if item["root_cause_id"] == HISTORICAL_REPORT_ROOT_ID)
        sequence = max(item["sequence"] for item in ledger["events"])
        attempt_id, strategy_id = f"retry-current-{suffix}", f"strategy-current-{suffix}"
        reservation_id, begin_id = f"evt-retry-reserved-{suffix}", f"evt-retry-astra-begin-{suffix}"
        grant_id, start_id, settlement_id = (
            f"evt-retry-astra-grant-{suffix}", f"evt-retry-start-{suffix}", f"evt-retry-settlement-{suffix}"
        )
        astr_id, implementation_id, basis_id = (
            f"act-retry-astra-{suffix}", f"act-retry-implementation-{suffix}", f"basis-retry-{suffix}"
        )
        start_minute = 20 + int(suffix[-1]) * 2
        times = {
            "reserve": f"2026-09-11T13:{start_minute:02d}:00Z",
            "begin": f"2026-09-11T13:{start_minute:02d}:01Z",
            "judge_end": f"2026-09-11T13:{start_minute:02d}:05Z",
            "grant": f"2026-09-11T13:{start_minute:02d}:06Z",
            "start": f"2026-09-11T13:{start_minute:02d}:07Z",
            "impl_end": f"2026-09-11T13:{start_minute:02d}:12Z",
            "settle": f"2026-09-11T13:{start_minute:02d}:13Z",
        }
        current_artifacts = [
            {"artifact": "scripts/retry_locked_runtime_v2.py", "sha256": "1" * 64},
            {"artifact": "tests/test_runtime_resource_retry_v2.py", "sha256": "2" * 64},
        ]
        digest = self._sha(ledger_core._canonical_json_ascii(current_artifacts))
        basis = {
            "review_basis_id": basis_id, "artifact_fingerprint": digest,
            "closure_boundary_fingerprint": "b" * 64,
            "requirements_authority_fingerprint": "c" * 64,
            "toolchain_dependency_fingerprint": "d" * 64,
            "mandatory_check_set_fingerprint": "e" * 64,
        }
        ledger["review_bases"].append(copy.deepcopy(basis))
        attempt = {
            "record_kind": "reservation", "repair_attempt_id": attempt_id,
            "root_cause_id": HISTORICAL_REPORT_ROOT_ID, "strategy_id": strategy_id,
            "created_at": times["reserve"], "status": "planned", "started_at": None,
            "completed_at": None, "review_basis_id": basis_id, "authorization_basis_id": basis_id,
            "authorization_epoch_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            "authorization_event_id": None, "expected_authorization_event_id": grant_id,
            "reservation_event_id": reservation_id, "implementation_activity_ids": [implementation_id],
            "verification_activity_ids": [], "introducing_cycle_id": None,
            "fixing_cycle_id": None, "verifying_cycle_id": None,
        }
        explanation = "Closed declarative schemas and killed-process disk-boundary tests replace incremental conditionals and mocked persistence seams."
        strategy = {
            "strategy_id": strategy_id, "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
            "description": explanation, "created_at": times["reserve"],
            "failed_predecessor_strategy_ids": list(predecessor_ids or []),
            "failed_predecessor_report_observation_ids": sorted([
                "OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002",
                "OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001",
            ]),
            "materially_different_from_predecessors": True,
            "material_difference_explanation": explanation,
            "disposition": "approved", "decision_evidence_refs": ["current-astra-result"],
            "astra_adjudication_activity_id": astr_id,
            "threshold_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
            "authorization_basis_id": basis_id,
            "authorization_epoch_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            "implementation_activity_ids": [implementation_id],
        }
        binding = {
            "schema_version": "mas1-import-origin-decision-binding.v1",
            "task_instance_id": ledger["task"]["task_instance_id"],
            "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
            "catalogue_entry_id": HISTORICAL_REPORT_IMPORT_ENTRY_ID,
            "catalogue_sha256": next(
                item["catalogue_sha256"] for item in ledger["events"]
                if item.get("event_id") == HISTORICAL_REPORT_IMPORT_EVENT_ID
            ),
            "report_import_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
            "activation_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            "decision_trigger_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
            "authorization_epoch_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            "repair_attempt_id": attempt_id, "strategy_id": strategy_id,
            "authorization_basis_id": basis_id, "implementation_activity_ids": [implementation_id],
            "imported_predecessor_payloads": sorted([
                {"observation_id": payload["observation_id"], "payload_sha256": payload_sha}
                for payload, payload_sha in zip(HISTORICAL_REPORT_IMPORT_PAYLOADS[1:], HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256[1:])
            ], key=lambda item: item["observation_id"]),
            "failed_predecessor_strategy_ids": list(predecessor_ids or []),
            "material_difference_explanation": explanation,
            "review_basis": copy.deepcopy(basis),
            "current_artifacts": copy.deepcopy(current_artifacts),
        }
        binding_sha = self._sha(ledger_core._canonical_json_ascii(binding))
        strategy.update({"import_origin_decision_binding": binding,
                         "import_origin_decision_binding_sha256": binding_sha})
        attempt["import_origin_decision_binding_sha256"] = binding_sha
        ledger["repair_attempts"].append(attempt); ledger["strategies"].append(strategy)

        def activity(activity_id: str, kind: str, started: str, completed: str, runtime: bool) -> dict:
            return {
                "activity_id": activity_id, "type": kind, "status": "completed",
                "started_at": started, "completed_at": completed,
                "requested": {"model": "gpt-6-astra" if runtime else "gpt-5.6-sol", "reasoning_effort": "xhigh", "profile": "fixed"},
                "actual": {"model": "gpt-6-astra" if runtime else "gpt-5.6-sol", "reasoning_effort": "xhigh", "profile": "fixed"},
                "runtime_verified": True, "runtime_evidence": "provider-enforced-route", "runtime_unavailable_reason": None,
                "session_id": None, "session_id_unavailable_reason": "Unavailable.",
                "thread_id": None, "thread_id_unavailable_reason": "Unavailable.",
                "token_usage": {"input": 1, "output": 1, "reasoning": 0, "total": 2,
                                "source": "runtime-reported", "unavailable_reason": None,
                                "reasoning_unavailable_reason": None},
                "attribution_mode": "direct", "root_cause_ids": [HISTORICAL_REPORT_ROOT_ID],
                "repair_attempt_id": attempt_id,
                "repair_attempt_bindings": [{"root_cause_id": HISTORICAL_REPORT_ROOT_ID, "repair_attempt_id": attempt_id}],
                "review_basis_id": basis_id,
                "import_origin_decision_binding_sha256": binding_sha,
            }
        astr = activity(astr_id, "astra-adjudication", times["begin"], times["judge_end"], True)
        astr.update({"repair_attempt_id": None, "repair_attempt_bindings": []})
        implementation = activity(implementation_id, "implementation", times["start"], times["impl_end"], False)
        if outcome != "succeeded":
            implementation["status"] = "failed"
        ledger["activities"].extend((astr, implementation))

        def event(event_id: str, offset: int, at: str, kind: str, **fields: object) -> dict:
            row = {
                "event_id": event_id, "sequence": sequence + offset, "at": at, "type": kind,
                "causal_refs": [], "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
                "observation_id": None, "repair_attempt_id": attempt_id,
                "review_basis_id": basis_id, "cycle_id": None,
                "root_relationship": None, "escape_key": None,
                "import_origin_decision_binding_sha256": binding_sha,
            }
            row.update(fields); return row
        reservation = event(
            reservation_id, 1, times["reserve"], "repair-reserved",
            causal_refs=[HISTORICAL_REPORT_ROOT_ID, attempt_id, strategy_id, basis_id],
            strategy_id=strategy_id, reservation_event_id=reservation_id,
            expected_authorization_event_id=grant_id,
        )
        begin = event(
            begin_id, 2, times["begin"], "astra-adjudication-started",
            causal_refs=[HISTORICAL_REPORT_ROOT_ID, attempt_id, strategy_id, basis_id,
                         HISTORICAL_REPORT_ACTIVATION_EVENT_ID, astr_id],
            strategy_id=strategy_id, adjudication_activity_id=astr_id,
        )
        grant = event(
            grant_id, 3, times["grant"], "astra-adjudicated",
            causal_refs=[HISTORICAL_REPORT_ROOT_ID, attempt_id, strategy_id, basis_id,
                         HISTORICAL_REPORT_IMPORT_EVENT_ID, HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
                         astr_id, begin_id],
            strategy_id=strategy_id, successor_strategy_id=strategy_id,
            threshold_event_id=HISTORICAL_REPORT_IMPORT_EVENT_ID,
            activation_anchor_event_id=HISTORICAL_REPORT_IMPORT_EVENT_ID,
            first_threshold_activation_event_id=HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            decision_trigger_event_id=HISTORICAL_REPORT_IMPORT_EVENT_ID,
            authorization_epoch_event_id=HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
            authorization_basis_id=basis_id, adjudication_activity_id=astr_id,
            adjudication_start_event_id=begin_id, implementation_activity_ids=[implementation_id],
            disposition="approved", decision_evidence_refs=["current-astra-result"],
            import_origin_decision_binding=copy.deepcopy(binding),
        )
        start = event(
            start_id, 4, times["start"], "repair-attempted",
            causal_refs=[HISTORICAL_REPORT_ROOT_ID, attempt_id, strategy_id, basis_id, grant_id, implementation_id],
            strategy_id=strategy_id, authorization_basis_id=basis_id,
            implementation_activity_ids=[implementation_id], started_at=times["start"],
            authorization_event_id=grant_id,
        )
        settlement = event(
            settlement_id, 5, times["settle"], "repair-threshold-settled",
            causal_refs=[HISTORICAL_REPORT_ROOT_ID, attempt_id, start_id, implementation_id, basis_id],
            start_event_id=start_id, terminal_outcome=outcome, settled_at=times["settle"],
            mutation_finished_at=times["impl_end"],
            decision_trigger_event_id=HISTORICAL_REPORT_IMPORT_EVENT_ID,
            authorization_epoch_event_id=HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
        )
        ledger["events"].extend((reservation, begin, grant, start, settlement))
        root.update({
            "state": "awaiting_post_repair_review" if outcome == "succeeded" else "blocked",
            "previous_state": "repairing",
            "blocked_reason": None if outcome == "succeeded" else "Current repair failed.",
            "block_code": None if outcome == "succeeded" else "second-escape-astra-required",
        })
        return {"attempt": attempt_id, "strategy": strategy_id, "binding_sha": binding_sha,
                "grant": grant_id, "implementation": implementation_id}

    def test_exact_catalogue_payload_digests_and_summaries(self) -> None:
        payloads = HISTORICAL_REPORT_IMPORT_PAYLOADS
        self.assertEqual(
            [(len(ledger_core._canonical_json_ascii(payload)), self._sha(ledger_core._canonical_json_ascii(payload))) for payload in payloads],
            [(2125, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256[0]),
             (2317, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256[1]),
             (2837, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256[2])],
        )
        encoded = ledger_core._canonical_json_ascii(HISTORICAL_REPORT_IMPORT_CATALOGUE)
        self.assertEqual((len(encoded), self._sha(encoded)), (9325, HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256))
        self.assertEqual([p["historical_report"]["reported_episode"] for p in payloads], [0, 1, 2])

    def test_full_import_authenticates_with_null_history_and_zero_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)
            fact = result.facts["threshold_facts"][HISTORICAL_REPORT_ROOT_ID]
            self.assertEqual(fact["lower_bound_incident_count"], 2)
            self.assertIsNone(fact["lifetime_count"])
            self.assertFalse(fact["baseline_resolved"])
            self.assertEqual(fact["gate_state"], "blocked")
            self.assertTrue(fact["awaiting_astra"])
            self.assertEqual(fact["authorized_attempt_ids"], [])
            self.assertEqual(fact["decision_trigger_event_id"], HISTORICAL_REPORT_IMPORT_EVENT_ID)
            self.assertEqual(fact["authorization_epoch_event_id"], HISTORICAL_REPORT_ACTIVATION_EVENT_ID)
            inventory = result.facts["activity_inventory"]
            self.assertEqual(inventory["frozen_recorded_activity_count"], 5)
            self.assertEqual(inventory["post_snapshot_recorded_activity_count"], 1)
            self.assertEqual(inventory["recorded_participating_activity_count"], 6)
            self.assertFalse(inventory["activity_inventory_complete"])

    def test_full_current_successor_requires_every_structured_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            ids = self._append_successor(ledger)
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)
            fact = result.facts["threshold_facts"][HISTORICAL_REPORT_ROOT_ID]
            self.assertEqual(fact["authorized_attempt_ids"], [ids["attempt"]])
            self.assertTrue(fact["attempt_facts"][ids["attempt"]]["completion_eligible"])
            self.assertEqual(fact["gate_state"], "awaiting_post_repair_review")

        for target in ("strategy", "attempt", "reservation", "begin", "adjudication", "grant", "start", "implementation", "settlement"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                case, ledger, marker = self._registered(temporary)
                ids = self._append_successor(ledger)
                if target == "strategy":
                    row = next(item for item in ledger["strategies"] if item["strategy_id"] == ids["strategy"])
                elif target == "attempt":
                    row = next(item for item in ledger["repair_attempts"] if item["repair_attempt_id"] == ids["attempt"])
                elif target == "adjudication":
                    row = next(item for item in ledger["activities"] if item["activity_id"].startswith("act-retry-astra"))
                elif target == "implementation":
                    row = next(item for item in ledger["activities"] if item["activity_id"] == ids["implementation"])
                else:
                    kind = {"reservation": "repair-reserved", "begin": "astra-adjudication-started",
                            "grant": "astra-adjudicated", "start": "repair-attempted",
                            "settlement": "repair-threshold-settled"}[target]
                    row = next(item for item in ledger["events"] if item["type"] == kind and item.get("repair_attempt_id") == ids["attempt"])
                row.pop("import_origin_decision_binding_sha256", None)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                with self._patch(case):
                    result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid, target)
                self.assertIn(f"auth:grant_binding:{HISTORICAL_REPORT_ROOT_ID}:{ids['attempt']}", result.reasons)

    def test_first_successor_exception_and_later_real_predecessor_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            first = self._append_successor(ledger, suffix="001", outcome="failed")
            second = self._append_successor(
                ledger, suffix="002", predecessor_ids=[first["strategy"]], outcome="succeeded")
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                valid = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(valid.valid, valid.reasons)
            fact = valid.facts["threshold_facts"][HISTORICAL_REPORT_ROOT_ID]
            self.assertEqual(fact["frontier_attempt_id"], second["attempt"])
            self.assertEqual(fact["authorized_attempt_ids"], [first["attempt"], second["attempt"]])

            strategy = next(item for item in ledger["strategies"] if item["strategy_id"] == second["strategy"])
            strategy["failed_predecessor_strategy_ids"] = []
            strategy["import_origin_decision_binding"]["failed_predecessor_strategy_ids"] = []
            strategy["import_origin_decision_binding_sha256"] = self._sha(
                ledger_core._canonical_json_ascii(strategy["import_origin_decision_binding"])
            )
            replacement = strategy["import_origin_decision_binding_sha256"]
            for collection in (ledger["repair_attempts"], ledger["activities"], ledger["events"]):
                for row in collection:
                    if row.get("repair_attempt_id") == second["attempt"] or row.get("activity_id") in {
                        "act-retry-astra-002", second["implementation"]
                    }:
                        row["import_origin_decision_binding_sha256"] = replacement
                        if row.get("event_id") == second["grant"]:
                            row["import_origin_decision_binding"] = copy.deepcopy(strategy["import_origin_decision_binding"])
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                invalid = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(invalid.valid)
            self.assertIn(f"auth:grant_binding:{HISTORICAL_REPORT_ROOT_ID}:{second['attempt']}", invalid.reasons)

    def test_ordinary_report_import_rows_remain_ordinary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = self._prepare(Path(temporary))
            with self._patch(case):
                apply_legacy_v6_0_audit_migration()
                ledger = json.loads(case["ledger_path"].read_text()); marker = json.loads(case["marker_path"].read_text())
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            ordinary = [row for row in ledger["observations"] if row.get("discovery_provenance") == "report-import"]
            self.assertEqual(len(ordinary), 9)
            self.assertTrue(all("record_kind" not in row for row in ordinary))
            self.assertTrue(result.valid, result.reasons)
            ordinary[0]["observed_at"] = None
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                invalid = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(invalid.valid)

    def test_imported_origin_is_immutable_across_previous_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, previous, marker = self._registered(temporary)
            current = copy.deepcopy(previous)
            root = next(item for item in current["roots"] if item["root_cause_id"] == HISTORICAL_REPORT_ROOT_ID)
            root["invariant"] += " rewritten"
            case["ledger_path"].write_bytes(self._pretty(current)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(current, case["schema"], previous_ledger=previous,
                                         loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(result.valid)
            self.assertIn(f"report_import:origin_immutable:{HISTORICAL_REPORT_ROOT_ID}", result.reasons)

    def test_current_rows_remain_unknown_chronology_and_have_no_v6_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            self._append_successor(ledger)
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)
            current = [row for row in result.facts["activities"] if row["activity_id"].startswith("act-retry-")]
            self.assertTrue(current)
            self.assertTrue(all(row["chronology_bucket"] == "unknown-chronology" for row in current))
            self.assertEqual(result.facts["token_activities"], [])
            fact = result.facts["threshold_facts"][HISTORICAL_REPORT_ROOT_ID]
            self.assertEqual(fact["lower_bound_incident_count"], 2)
            self.assertIsNone(fact["lifetime_count"])

            record = {"ledger_id": ledger["ledger_id"], "ledger": ledger, "_validation": result, "_facts": result.facts}
            report = analyzer.calculate([record])
            row = next(item for item in report["closure_latency"]["roots"] if item["root_cause_id"] == HISTORICAL_REPORT_ROOT_ID)
            self.assertEqual(row["historical_report_escape_lower_bound"], 2)
            self.assertIsNone(row["lifetime_escape_count"])
            self.assertEqual(row["threshold_gate_state"], "awaiting_post_repair_review")
            self.assertEqual(report["model_usage"], {})

    def test_catalogue_rejects_rewriting_discriminators_and_digest_arms(self) -> None:
        mutations = (
            lambda ledger: ledger["observations"][len(self.original_ledger["observations"])]["historical_report"].__setitem__("reported_episode", True),
            lambda ledger: ledger["observations"][len(self.original_ledger["observations"])]["historical_report"]["reviewed_artifacts"][0].__setitem__("value", "a" * 64),
            lambda ledger: ledger["observations"][len(self.original_ledger["observations"])].__setitem__("private", "secret"),
            lambda ledger: ledger["events"][-3].__setitem__("catalogue_sha256", "0" * 64),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                case, ledger, marker = self._registered(temporary)
                mutate(ledger)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                with self._patch(case):
                    result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                self.assertTrue(any("report_import:" in reason or reason.startswith("schema:") for reason in result.reasons), result.reasons)

    def test_frozen_root_direct_and_transitive_touches_reject_without_fact_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            with self._patch(case):
                baseline = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(baseline.valid, baseline.reasons)
            frozen = "RC-HARVEST-WORKER-DEADLINE-CLEANUP"
            template = copy.deepcopy(ledger["events"][0])
            template.update({
                "event_id": "EVT-FROZEN-TRANSITIVE-TOUCH", "sequence": max(e["sequence"] for e in ledger["events"]) + 1,
                "at": "2026-09-11T13:15:00Z", "root_cause_id": None,
                "causal_refs": [frozen],
            })
            ledger["events"].append(template)
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(result.valid)
            self.assertIn("compat:frozen_root_touch:events:EVT-FROZEN-TRANSITIVE-TOUCH", result.reasons)
            self.assertEqual(result.facts["threshold_facts"][frozen], baseline.facts["threshold_facts"][frozen])

    def test_each_frozen_root_rejects_explicit_shared_neutral_nested_transitive_and_collision_touches(self) -> None:
        frozen_roots = list(
            LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]["frozen_root_ids"])
        self.assertEqual(len(frozen_roots), 10)
        for ordinal, frozen_root in enumerate(frozen_roots):
            with self.subTest(frozen_root=frozen_root), tempfile.TemporaryDirectory() as temporary:
                case, ledger, marker = self._registered(temporary)
                with self._patch(case):
                    baseline = validate_ledger(
                        ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertTrue(baseline.valid, baseline.reasons)
                sequence = max(event["sequence"] for event in ledger["events"])
                prefix = f"EVT-FROZEN-TOUCH-{ordinal:02d}"

                def event(event_id: str, offset: int, *, root_id: str | None,
                          causal_refs: list[str], **extra: object) -> dict:
                    row = {
                        "event_id": event_id, "sequence": sequence + offset,
                        "at": f"2026-09-11T14:00:{offset:02d}Z", "type": "activity-recorded",
                        "causal_refs": causal_refs, "root_cause_id": root_id,
                        "observation_id": None, "repair_attempt_id": None,
                        "review_basis_id": None, "cycle_id": None,
                        "root_relationship": None, "escape_key": None,
                    }
                    row.update(extra)
                    return row

                direct = event(
                    prefix + "-EXPLICIT-CURRENT", 1,
                    root_id=HISTORICAL_REPORT_ROOT_ID, causal_refs=[frozen_root])
                shared = event(
                    prefix + "-SHARED", 2,
                    root_id=HISTORICAL_REPORT_ROOT_ID, causal_refs=[],
                    root_cause_ids=[HISTORICAL_REPORT_ROOT_ID, frozen_root])
                neutral = event(
                    prefix + "-NEUTRAL", 3, root_id=None, causal_refs=[frozen_root])
                nested_tail = event(
                    prefix + "-NESTED-TAIL", 4, root_id=None, causal_refs=[],
                    touch_context={"nested": [{"frozen_root_ref": frozen_root}]})
                transitive_head = event(
                    prefix + "-TRANSITIVE-EXPLICIT-CURRENT", 5,
                    root_id=HISTORICAL_REPORT_ROOT_ID,
                    causal_refs=[nested_tail["event_id"]])
                collision = event(
                    frozen_root, 6, root_id=HISTORICAL_REPORT_ROOT_ID, causal_refs=[])
                appended = (direct, shared, neutral, nested_tail, transitive_head, collision)
                ledger["events"].extend(appended)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                with self._patch(case):
                    result = validate_ledger(
                        ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                for row in appended:
                    self.assertIn(
                        f"compat:frozen_root_touch:events:{row['event_id']}", result.reasons)
                self.assertEqual(
                    result.facts["threshold_facts"][frozen_root],
                    baseline.facts["threshold_facts"][frozen_root])

                context = _validation_context(ledger)
                self.assertIsNotNone(context)
                assert context is not None
                indexes = {row["event_id"]: index for index, row in enumerate(context.rows["events"])}
                ownership = ledger_core._legacy_row_root_ownership(context)
                self.assertEqual(
                    ownership[("events", indexes[direct["event_id"]])],
                    {HISTORICAL_REPORT_ROOT_ID})
                touches = ledger_core._legacy_frozen_touch_rows(
                    context, self.original_ledger, set(frozen_roots))
                self.assertIn(("events", indexes[direct["event_id"]]), touches)
                self.assertIn(("events", indexes[transitive_head["event_id"]]), touches)

    def test_coordinated_payload_and_commitment_rewrite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            index = len(self.original_ledger["observations"])
            ledger["observations"][index]["historical_report"]["reported_finding"] = "Coordinated rewrite."
            replacement = self._sha(ledger_core._canonical_json_ascii(ledger["observations"][index]))
            ledger["events"][-3]["observation_bindings"][0]["payload_sha256"] = replacement
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(result.valid)
            self.assertIn("report_import:observation_order_or_payload", result.reasons)

    def test_schema_union_arms_are_closed_exclusive_and_type_strict(self) -> None:
        mutations = (
            lambda ledger: ledger["observations"][0].__setitem__("record_kind", "historical-report-import-v1"),
            lambda ledger: ledger["observations"][-1]["historical_report"].__setitem__("reported_episode", 2.0),
            lambda ledger: ledger["observations"][-1]["historical_report"]["reviewed_artifacts"][0].__setitem__("digest_kind", "sha256-prefix"),
            lambda ledger: ledger["observations"][-1]["historical_report"]["reviewed_artifacts"][0].__setitem__("unknown", True),
            lambda ledger: ledger["events"][-3].__setitem__("unknown", True),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                case, ledger, marker = self._registered(temporary)
                mutate(ledger)
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                with self._patch(case):
                    result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                self.assertTrue(any(reason.startswith("schema:") for reason in result.reasons), result.reasons)

    def test_transplant_and_cross_namespace_collision_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            ledger["observations"][-1]["root_cause_id"] = ledger["roots"][0]["root_cause_id"]
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                transplanted = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(transplanted.valid)
            self.assertIn("report_import:observation_order_or_payload", transplanted.reasons)

        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            collision = copy.deepcopy(ledger["events"][0])
            collision.update({
                "event_id": ledger["activities"][0]["activity_id"],
                "sequence": max(event["sequence"] for event in ledger["events"]) + 1,
                "at": "2026-09-11T13:19:00Z", "causal_refs": [], "root_cause_id": None,
                "import_origin_decision_binding_sha256": "0" * 64,
            })
            ledger["events"].append(collision)
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertFalse(result.valid)
            self.assertTrue(any(reason.startswith("compat:frozen_root_touch:events:") for reason in result.reasons), result.reasons)
            self.assertIn(
                f"report_import:field_scope:events:{collision['event_id']}", result.reasons)

        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, _ = self._registered(temporary)
            ids = self._append_successor(ledger)
            # The same root-specific records cannot be transplanted into an
            # unauthenticated call site merely because all embedded IDs match.
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"])
            self.assertFalse(result.valid)
            self.assertIn(
                f"report_import:field_scope:strategies:{ids['strategy']}", result.reasons)

    def test_canonical_inventory_grows_without_rewriting_raw_telemetry_or_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            frozen_telemetry = copy.deepcopy(ledger["telemetry"])
            frozen_marker = copy.deepcopy(marker)
            self._append_successor(ledger)
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)
            self.assertEqual(ledger["telemetry"], frozen_telemetry)
            self.assertEqual(marker, frozen_marker)
            inventory = result.facts["activity_inventory"]
            self.assertEqual((inventory["frozen_recorded_activity_count"],
                              inventory["post_snapshot_recorded_activity_count"],
                              inventory["recorded_participating_activity_count"]), (5, 3, 8))
            self.assertIsNone(inventory["expected_participating_activity_count"])

    def test_binding_rejects_artifact_basis_and_astra_gate_mismatch(self) -> None:
        for mutation in ("artifact", "basis", "astra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                case, ledger, marker = self._registered(temporary)
                ids = self._append_successor(ledger)
                strategy = next(item for item in ledger["strategies"] if item["strategy_id"] == ids["strategy"])
                if mutation == "artifact":
                    strategy["import_origin_decision_binding"]["current_artifacts"][0]["sha256"] = "f" * 64
                elif mutation == "basis":
                    basis = next(item for item in ledger["review_bases"] if item["review_basis_id"].startswith("basis-retry"))
                    basis["mandatory_check_set_fingerprint"] = "f" * 64
                else:
                    activity = next(item for item in ledger["activities"] if item["activity_id"].startswith("act-retry-astra"))
                    activity["actual"]["model"] = "gpt-5.6-sol"
                case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
                with self._patch(case):
                    result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
                self.assertFalse(result.valid)
                self.assertIn(f"auth:grant_binding:{HISTORICAL_REPORT_ROOT_ID}:{ids['attempt']}", result.reasons)

    def test_allowed_state_transition_preserves_import_origin_with_previous_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, previous, marker = self._registered(temporary)
            current = copy.deepcopy(previous)
            self._append_successor(current)
            case["ledger_path"].write_bytes(self._pretty(current)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(current, case["schema"], previous_ledger=previous,
                                         loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)

    def test_fake_raw_lower_bound_field_has_no_canonical_or_analyzer_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case, ledger, marker = self._registered(temporary)
            ids = self._append_successor(ledger)
            strategy = next(item for item in ledger["strategies"] if item["strategy_id"] == ids["strategy"])
            strategy["historical_report_escape_lower_bound"] = 999
            case["ledger_path"].write_bytes(self._pretty(ledger)); case["ledger_path"].chmod(0o644)
            with self._patch(case):
                result = validate_ledger(ledger, case["schema"], loaded_path=case["ledger_path"], marker=marker)
            self.assertTrue(result.valid, result.reasons)
            fact = result.facts["threshold_facts"][HISTORICAL_REPORT_ROOT_ID]
            self.assertEqual(fact["threshold_origin"]["historical_report_escape_lower_bound"], 2)
            record = {"ledger_id": ledger["ledger_id"], "ledger": ledger, "_validation": result, "_facts": result.facts}
            report = analyzer.calculate([record])
            row = next(item for item in report["closure_latency"]["roots"] if item["root_cause_id"] == HISTORICAL_REPORT_ROOT_ID)
            self.assertEqual(row["historical_report_escape_lower_bound"], 2)




if __name__ == "__main__":
    unittest.main()
