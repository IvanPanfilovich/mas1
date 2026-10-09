"""Canonical, fail-closed MAS1 v6 ledger validation and derived facts.

This is deliberately the only production validation entry point.  The fixture
runner is a small harness and the reporting command consumes the facts returned
here; neither is allowed to silently reimplement causal reconstruction.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Dict, Iterable, List, Optional, Set

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent

# This catalogue is release-controlled source, rather than a directory scan or
# a mutable manifest field.  Its hashes bind the recorded evidence; they do
# not authenticate a changed manifest.  Adding an entry is a reviewed source
# change because it changes which populations may be analyzed.
INVALIDATED_CUTOVER_CATALOGUE_VERSION = "MAS1-v6.1-invalidation-catalogue-1"
INVALIDATED_CUTOVER_CATALOGUE: Mapping[str, Mapping[str, str]] = {
    "MAS1-6.1_20260908T154848Z": {
        "predecessor_sha256": "28239d3d80ffd96c444a9ce1d40b525e9dd732f801daada8b3823210e40b1dcc",
        "original_disposition_id": "MAS1-6.1_20260908T154848Z-unauthorized-self-registration",
        "original_disposition_path": "/Users/ivanf/Desktop/Saved Prompts/cutover-incidents/MAS1-6.1_20260908T154848Z-unauthorized-self-registration/incident-disposition.json",
        "original_disposition_sha256": "38baaa08f5339bcc2b65e027ef9fa6d87575f5922f584ec347ebf12643ecf436",
        "corrected_disposition_id": "MAS1-6.1_20260908T154848Z-unauthorized-self-registration-correction-20260908T164500Z",
        "corrected_disposition_path": "/Users/ivanf/Desktop/Saved Prompts/cutover-incidents/MAS1-6.1_20260908T154848Z-unauthorized-self-registration/corrected-incident-disposition-20260908T164500Z.json",
        "corrected_disposition_sha256": "3cb5ea70b5ff5fbbb1d932ae7cd64a039edd3adce9672e5f87541763cdf58be6",
    },
}

# One release-controlled, descriptor-only compatibility migration.  This is
# deliberately separate from INVALIDATED_CUTOVER_CATALOGUE: the latter rejects
# a rollout identifier, while this entry admits one exact historical task and
# one exact, independently authorized transformation.
LEGACY_V6_0_AUDIT_MIGRATION_ID = "MIG-LEGACY-V6-0-AUDIT-01A07819-V1"
LEGACY_V6_0_AUDIT_CATALOGUE_ENTRY_ID = "CATALOGUE-LEGACY-V6-0-AUDIT-01A07819-V1"
LEGACY_V6_0_AUDIT_AUTHORIZATION_SHA256 = "bc46358783920eef8a159a052aec4c034fe2763b29e5ceb58f15a4343ef6d546"
LEGACY_V6_0_AUDIT_JUDGE_RESULT_SHA256 = "fd7e3ffd5f10ba846b718568f27563488e986b62a008c1579417e3bff44a722d"
LEGACY_V6_0_AUDIT_DECISION_SHA256 = "623900dddb37aff988f00d53a0a519f6d6f33749a6947757b0e76ce2cdd7ca5e"
LEGACY_V6_0_AUDIT_DESCRIPTOR_SHA256 = "232de48c0361068b557a2addd2087adf9a2028f34cf5c3150fa82ed429d7fbc7"
LEGACY_V6_0_AUDIT_CATALOGUE_SHA256 = "f49b89e2990da898f6e30c23a9cbde991959ff4b4d087e46ee06fdc8c63204eb"


def _legacy_threshold_evidence() -> dict[str, Any]:
    return {
        "record_type": "threshold-evidence",
        "observation_id": "OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002",
        "root_cause_id": "RC-RUNTIME-RETRY-PERSISTENT-CONTRACT",
        "root_relationship": "repair-induced",
        "reviewed_script_sha256": "2dd557a581097a78210183e31497e236c0f84558bef53ddb283769eb3ed50252",
        "reviewed_tests_sha256": "d5183170d4d56d5ba257fd3eeb867016028390da20673877df347e51d12dd740",
        "original_provider_timestamp": None,
        "original_provider_timestamp_unavailable_reason":
            "The completed Astra finding arrived without a provider timestamp in the available task evidence.",
        "original_discovery_at": None,
        "original_discovery_at_unavailable_reason":
            "The original second-escape discovery time is unavailable in the task evidence.",
        "first_threshold_known_at": None,
        "first_threshold_known_at_unavailable_reason":
            "The first moment the second-escape threshold became known is unavailable and is not inferred from administrative or migration timestamps.",
        "threshold_evidence_received_at": "2026-09-11T13:10:56Z",
        "threshold_time_basis": "auditable_receipt_upper_bound",
        "threshold_evidence_received_at_semantics":
            "Local receipt of the already-completed second-escape finding before compatibility implementation; a conservative auditable upper bound, not the unavailable original discovery, provider, authorization, decision-recording, migration-selection, or apply time.",
        "evidence_refs": [
            "agent-result:/root/response_contract_repair_review_astra",
            "observation:OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002",
            "script-sha256:2dd557a581097a78210183e31497e236c0f84558bef53ddb283769eb3ed50252",
            "tests-sha256:d5183170d4d56d5ba257fd3eeb867016028390da20673877df347e51d12dd740",
        ],
    }


def _legacy_descriptor() -> dict[str, Any]:
    task = "01a07819-9ad8-7851-bc8f-513aa93f4dcb"
    workspace = "/Users/ivanf/Documents/ChatGPT/Instructons"
    task_dir = f"{workspace}/.mas1/tasks/{task}"
    migration_dir = f"{task_dir}/migrations/{LEGACY_V6_0_AUDIT_MIGRATION_ID}"
    return {
        "schema_version": "mas1-legacy-v6.0-audit-descriptor.v1",
        "record_type": "legacy-v6.0-audit",
        "mode": "legacy-v6.0-audit-v1",
        "catalogue_entry_id": LEGACY_V6_0_AUDIT_CATALOGUE_ENTRY_ID,
        "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID,
        "task_instance_id": task,
        "workspace": workspace,
        "ledger_path": f"{task_dir}/finding-ledger.v1.json",
        "marker_path": f"{task_dir}/v6-cutover.json",
        "migration_dir": migration_dir,
        "authorization": {
            "authorization_id": "AUTH-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-authorization.v1",
            "path": f"{migration_dir}/authorization.json",
            "sha256": LEGACY_V6_0_AUDIT_AUTHORIZATION_SHA256,
        },
        "decision": {
            "decision_id": "DEC-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-decision.v1",
            "path": f"{migration_dir}/decision.json",
            "sha256": LEGACY_V6_0_AUDIT_DECISION_SHA256,
        },
        "original_representation": {
            "ledger_schema_version": "mas1-finding-ledger.v1",
            "cutover_id": "MAS1-6.0_20260908T075344Z",
            "ledger_snapshot_path": f"{migration_dir}/before-ledger.json",
            "ledger_sha256": "ef0aef213647b5f7bf3eb29258c6d5f43ad3044ce2cc4f6e02aec9019082e992",
            "marker_snapshot_path": f"{migration_dir}/before-marker.json",
            "marker_sha256": "d7dd7438868fb019661c267a41245a622fa6a247a1a8a9fd39b64cb26dddba49",
            "ledger_absent_modern_fields": [
                "post_cutover_boundary", "protocol_adopted_at", "protocol_adoption_evidence_refs",
            ],
            "marker_post_cutover_boundary": "2026-09-08T11:00:09Z",
            "marker_absent_modern_fields": ["protocol_adopted_at", "protocol_adoption_evidence_refs"],
        },
        "transformation": {
            "version": "legacy-v6.0-audit-descriptor-only.v1",
            "operation": "append-one-identical-legacy_v6_0_audit-member-to-ledger-and-marker",
            "candidate_serialization": (
                "Preserve every original byte before the final `}\n`; append `,\n  \"legacy_v6_0_audit\": ` "
                "plus the descriptor rendered by json.dumps(ensure_ascii=False, indent=2) with every continuation "
                "line shifted two spaces, then `\n}\n`."
            ),
            "original_content_preservation":
                "All original members, collection rows, array order, object key presence, scalar types, and marker fields remain byte-for-byte in the preserved prefix.",
        },
        "journal": {
            "journal_id": "JOURNAL-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-journal.v1",
            "path": f"{migration_dir}/migration.journal.json",
            "terminal_phase": "receipt_intent",
        },
        "receipt": {
            "receipt_id": "RECEIPT-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-receipt.v1",
            "path": f"{migration_dir}/migration.receipt.json",
            "binding": "identity-and-path-only; target payloads do not contain a receipt digest",
        },
        "original_protocol_adopted_at": None,
        "threshold_evidence": _legacy_threshold_evidence(),
    }


LEGACY_V6_0_AUDIT_DESCRIPTOR: Mapping[str, Any] = _legacy_descriptor()


def _legacy_catalogue_entry() -> dict[str, Any]:
    descriptor = LEGACY_V6_0_AUDIT_DESCRIPTOR
    task = descriptor["task_instance_id"]
    workspace = descriptor["workspace"]
    task_dir = f"{workspace}/.mas1/tasks/{task}"
    migration_dir = descriptor["migration_dir"]
    journal_path = descriptor["journal"]["path"]
    receipt_path = descriptor["receipt"]["path"]
    phases = [
        "selected", "before_ledger_snapshot_intent", "before_ledger_snapshotted",
        "before_marker_snapshot_intent", "before_marker_snapshotted", "ledger_candidate_intent",
        "ledger_candidate_fsynced", "marker_candidate_intent", "marker_candidate_fsynced",
        "publication_intent", "ledger_published", "marker_published", "pair_verified", "receipt_intent",
    ]
    return {
        "schema_version": "mas1-legacy-v6.0-migration-catalogue-entry.v1",
        "catalogue_entry_id": LEGACY_V6_0_AUDIT_CATALOGUE_ENTRY_ID,
        "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID,
        "mode": "legacy-v6.0-audit-v1",
        "task_instance_id": task,
        "workspace": workspace,
        "ledger_path": descriptor["ledger_path"],
        "marker_path": descriptor["marker_path"],
        "migration_dir": migration_dir,
        "original": {
            "cutover_id": "MAS1-6.0_20260908T075344Z",
            "ledger_schema_version": "mas1-finding-ledger.v1",
            "ledger_sha256": "ef0aef213647b5f7bf3eb29258c6d5f43ad3044ce2cc4f6e02aec9019082e992",
            "marker_sha256": "d7dd7438868fb019661c267a41245a622fa6a247a1a8a9fd39b64cb26dddba49",
            "ledger_absent_modern_fields": [
                "post_cutover_boundary", "protocol_adopted_at", "protocol_adoption_evidence_refs",
            ],
            "marker_post_cutover_boundary": "2026-09-08T11:00:09Z",
            "marker_absent_modern_fields": ["protocol_adopted_at", "protocol_adoption_evidence_refs"],
        },
        "authorization": {
            "authorization_id": "AUTH-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-authorization.v1",
            "path": f"{migration_dir}/authorization.json",
            "sha256": LEGACY_V6_0_AUDIT_AUTHORIZATION_SHA256,
        },
        "decision": {
            "decision_id": "DEC-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-decision.v1",
            "path": f"{migration_dir}/decision.json",
            "sha256": LEGACY_V6_0_AUDIT_DECISION_SHA256,
            "judge_result_sha256": LEGACY_V6_0_AUDIT_JUDGE_RESULT_SHA256,
        },
        "descriptor": {
            "schema_version": "mas1-legacy-v6.0-audit-descriptor.v1",
            "member_name": "legacy_v6_0_audit",
            "sha256": LEGACY_V6_0_AUDIT_DESCRIPTOR_SHA256,
        },
        "transformation": {
            "version": "legacy-v6.0-audit-descriptor-only.v1",
            "candidate_serialization": "preserved-prefix-plus-indented-descriptor-v1",
            "after_ledger_sha256": "c69ccf5bb03a25faec07f402c560f6faf37f386b6e9b82fc3596e72903903aed",
            "after_marker_sha256": "ca5d518280d88ca52841d777acd53ea38bf82abd2b6e3e3a8452c2cc0d6fc937",
        },
        "artifacts": {
            "fixed": {
                "authorization": f"{migration_dir}/authorization.json",
                "decision": f"{migration_dir}/decision.json",
                "before_ledger": f"{migration_dir}/before-ledger.json",
                "before_marker": f"{migration_dir}/before-marker.json",
                "journal": journal_path,
                "receipt": receipt_path,
                "lock": f"{migration_dir}/migration.lock",
            },
            "temporaries": {
                "before_ledger": f"{migration_dir}/.before-ledger.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
                "before_marker": f"{migration_dir}/.before-marker.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
                "journal": f"{migration_dir}/.migration.journal.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
                "receipt": f"{migration_dir}/.migration.receipt.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
                "ledger_publication": f"{task_dir}/.finding-ledger.v1.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
                "marker_publication": f"{task_dir}/.v6-cutover.json.{LEGACY_V6_0_AUDIT_MIGRATION_ID}.tmp",
            },
        },
        "identity_requirements": {
            "uid": 501, "nlink": 1, "canonical_file_mode": 420,
            "evidence_directory_mode": 448, "evidence_file_mode": 256,
            "lock_file_mode": 384, "temporary_file_mode": 384,
            "no_symlinks": True, "same_filesystem_candidates": True,
        },
        "journal": {
            "journal_id": "JOURNAL-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-journal.v1",
            "path": journal_path,
            "phases": phases,
            "terminal_phase": "receipt_intent",
            "event_schema": {"required_keys": ["sequence", "phase", "at"], "additional_properties": False},
        },
        "receipt": {
            "receipt_id": "RECEIPT-LEGACY-V6-0-AUDIT-01A07819-V1",
            "schema_version": "mas1-legacy-v6.0-migration-receipt.v1",
            "path": receipt_path,
            "target_binding": "identity-and-path-only-no-receipt-digest",
            "journal_binding": "final-journal-bytes-sha256-at-receipt_intent",
        },
        "threshold_evidence": _legacy_threshold_evidence(),
        "frozen_root_ids": [
            "RC-TRANSCRIPT-SOURCE-PROVENANCE", "RC-V1-REPRESENTATION-ADMISSION",
            "RC-SOURCE-COVERAGE-AUTHORITY", "RC-PARTIAL-HARVEST-PROMOTION",
            "RC-LOCAL-MLX-COMPATIBILITY", "RC-HARVEST-CURSOR-FAIRNESS",
            "RC-HARVEST-WORKER-DEADLINE-CLEANUP", "RC-HARVEST-CAPACITY-RESERVE",
            "RC-HARVEST-PATH-ALIASING", "RC-HARVEST-PREPARE-PAIR-ATOMICITY",
        ],
        "compatibility_semantics": {
            "original_protocol_adopted_at": None,
            "threshold_enforcement_time_source": "threshold_evidence.threshold_evidence_received_at",
            "timestamp_grandfathering": False,
            "frozen_rows": "snapshot-membership-and-exact-content",
            "frozen_roots": "nonauthorizing",
            "new_rows": "root-local-modern-controls-even-if-backdated",
            "predecessor_imports": "nonauthorizing",
            "analyzer_semantics": "unchanged",
        },
    }


LEGACY_V6_0_AUDIT_CATALOGUE: Mapping[str, Mapping[str, Any]] = {
    LEGACY_V6_0_AUDIT_MIGRATION_ID: _legacy_catalogue_entry(),
}


# Release-controlled retained-report catalogue.  These payloads describe only
# what the task retained from the three completed reviews.  In particular they
# carry no execution authority and do not reconstruct unavailable timestamps,
# backend identity, token usage, or original report bytes.
HISTORICAL_REPORT_IMPORT_CATALOGUE_VERSION = "mas1-historical-report-import-catalogue.v1"
HISTORICAL_REPORT_IMPORT_ENTRY_ID = "REPORT-IMPORT-01A07819-PERSISTENT-CONTRACT-V1"
HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256 = "beb20faf159863c6301f6810e4b9d59bf3f18267e929fe4ac9bdfb0dd3be06a8"
HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256 = (
    "e1f56b3fabec4fc7e6422ca31a9e4da210e530ee894ca576b4bffcf190f24f3a",
    "5f546d17cfb87d2cff0209448bc55a332c4666241ccd41be071e87ddda6a2f83",
    "c7b1fbd9bd3ffb59b54f15c084c09dd93a88d9f86aeab52e0d3d0e85b0acc2fc",
)
HISTORICAL_REPORT_IMPORT_EVENT_ID = "EVT-RETRY-V2-PERSISTENCE-REPORT-IMPORT-001"
HISTORICAL_REPORT_ROOT_OPENED_EVENT_ID = "EVT-RETRY-V2-PERSISTENCE-ROOT-OPENED-001"
HISTORICAL_REPORT_ACTIVATION_EVENT_ID = "EVT-RETRY-V2-PERSISTENCE-THRESHOLD-ACTIVATED-001"
HISTORICAL_REPORT_ROOT_ID = "RC-RUNTIME-RETRY-PERSISTENT-CONTRACT"


def _canonical_json_ascii(value: Any) -> bytes:
    """Canonical bytes for release-controlled report and decision bindings."""
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")


def _historical_report_payloads() -> tuple[dict[str, Any], ...]:
    # JSON literals keep the independently adjudicated Annex A transcription
    # reviewable and prevent a builder from silently filling unavailable facts.
    return tuple(json.loads(value) for value in (
        r'''{"record_kind":"historical-report-import-v1","observation_id":"OBS-RETRY-V2-TERRA-PERSISTENCE-001","root_cause_id":"RC-RUNTIME-RETRY-PERSISTENT-CONTRACT","root_relationship":"initial","discovery_provenance":"report-import","severity":"P1","status":"confirmed-from-report","confirmed":true,"observed_at":null,"pre_cutover":null,"discovering_activity_ids":[],"activity_ids":[],"repair_attempt_id":null,"review_basis_id":null,"cycle_id":null,"introducing_cycle_id":null,"fixing_cycle_id":null,"verifying_cycle_id":null,"detected_cycle_id":null,"import_event_id":"EVT-RETRY-V2-PERSISTENCE-REPORT-IMPORT-001","evidence_refs":["agent-result:/root/response_contract_repair_review_terra","retained-task-report:OBS-RETRY-V2-TERRA-PERSISTENCE-001:script-prefix:eb156a:tests-prefix:c23143"],"historical_report":{"reported_episode":0,"predecessor_observation_id":null,"source_report_refs":["agent-result:/root/response_contract_repair_review_terra","retained-task-report:OBS-RETRY-V2-TERRA-PERSISTENCE-001:script-prefix:eb156a:tests-prefix:c23143"],"historical_chronology":"unknown","chronology_unavailable_reason":"Original discovery, repair and reviewer-provider timestamps are unavailable; reported episode order is not a timestamp.","execution_lineage":"incomplete","execution_lineage_unavailable_reason":"Original repair, basis and cycle identities and reservation, grant, start and settlement records are unavailable.","report_bytes_sha256":null,"report_bytes_unavailable_reason":"Original reviewer-result bytes are unavailable; this is a release-reviewed transcription of retained task evidence, not an original report digest.","reviewed_artifacts":[{"artifact":"scripts/retry_locked_runtime_v2.py","digest_kind":"sha256-prefix","value":"eb156a"},{"artifact":"tests/test_runtime_resource_retry_v2.py","digest_kind":"sha256-prefix","value":"c23143"}],"reported_finding":"The retained initial Terra review reported acceptance of arbitrary persisted trace data, the accepted lifecycle label as a failure diagnostic code, and Boolean counters.","failed_approach_summary":null,"actual_runtime_identity":null,"actual_token_usage":null}}''',
        r'''{"record_kind":"historical-report-import-v1","observation_id":"OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001","root_cause_id":"RC-RUNTIME-RETRY-PERSISTENT-CONTRACT","root_relationship":"repair-induced","discovery_provenance":"report-import","severity":"P1","status":"confirmed-from-report","confirmed":true,"observed_at":null,"pre_cutover":null,"discovering_activity_ids":[],"activity_ids":[],"repair_attempt_id":null,"review_basis_id":null,"cycle_id":null,"introducing_cycle_id":null,"fixing_cycle_id":null,"verifying_cycle_id":null,"detected_cycle_id":null,"import_event_id":"EVT-RETRY-V2-PERSISTENCE-REPORT-IMPORT-001","evidence_refs":["agent-result:/root/response_contract_repair_review_terra","retained-task-report:OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001:script-prefix:04e129:tests-prefix:cb37b2"],"historical_report":{"reported_episode":1,"predecessor_observation_id":"OBS-RETRY-V2-TERRA-PERSISTENCE-001","source_report_refs":["agent-result:/root/response_contract_repair_review_terra","retained-task-report:OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001:script-prefix:04e129:tests-prefix:cb37b2"],"historical_chronology":"unknown","chronology_unavailable_reason":"Original discovery, repair and reviewer-provider timestamps are unavailable; reported episode order is not a timestamp.","execution_lineage":"incomplete","execution_lineage_unavailable_reason":"Original repair, basis and cycle identities and reservation, grant, start and settlement records are unavailable.","report_bytes_sha256":null,"report_bytes_unavailable_reason":"Original reviewer-result bytes are unavailable; this is a release-reviewed transcription of retained task evidence, not an original report digest.","reviewed_artifacts":[{"artifact":"scripts/retry_locked_runtime_v2.py","digest_kind":"sha256-prefix","value":"04e129"},{"artifact":"tests/test_runtime_resource_retry_v2.py","digest_kind":"sha256-prefix","value":"cb37b2"}],"reported_finding":"The retained first post-repair Terra review reported acceptance of a request_delegate failure with all delegate counters zero, demonstrating incomplete stage/counter causality.","failed_approach_summary":"The first repair added targeted persisted-trace, failure-code and integer-counter checks to the existing conditional validator.","actual_runtime_identity":null,"actual_token_usage":null}}''',
        r'''{"record_kind":"historical-report-import-v1","observation_id":"OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002","root_cause_id":"RC-RUNTIME-RETRY-PERSISTENT-CONTRACT","root_relationship":"repair-induced","discovery_provenance":"report-import","severity":"P1","status":"confirmed-from-report","confirmed":true,"observed_at":null,"pre_cutover":null,"discovering_activity_ids":[],"activity_ids":[],"repair_attempt_id":null,"review_basis_id":null,"cycle_id":null,"introducing_cycle_id":null,"fixing_cycle_id":null,"verifying_cycle_id":null,"detected_cycle_id":null,"import_event_id":"EVT-RETRY-V2-PERSISTENCE-REPORT-IMPORT-001","evidence_refs":["agent-result:/root/response_contract_repair_review_astra","retained-task-report:OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002:script-sha256:2dd557a581097a78210183e31497e236c0f84558bef53ddb283769eb3ed50252:tests-sha256:d5183170d4d56d5ba257fd3eeb867016028390da20673877df347e51d12dd740"],"historical_report":{"reported_episode":2,"predecessor_observation_id":"OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001","source_report_refs":["agent-result:/root/response_contract_repair_review_astra","retained-task-report:OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002:script-sha256:2dd557a581097a78210183e31497e236c0f84558bef53ddb283769eb3ed50252:tests-sha256:d5183170d4d56d5ba257fd3eeb867016028390da20673877df347e51d12dd740"],"historical_chronology":"unknown","chronology_unavailable_reason":"Original discovery, repair and reviewer-provider timestamps are unavailable; reported episode order is not a timestamp.","execution_lineage":"incomplete","execution_lineage_unavailable_reason":"Original repair, basis and cycle identities and reservation, grant, start and settlement records are unavailable.","report_bytes_sha256":null,"report_bytes_unavailable_reason":"Original reviewer-result bytes are unavailable; this is a release-reviewed transcription of retained task evidence, not an original report digest.","reviewed_artifacts":[{"artifact":"scripts/retry_locked_runtime_v2.py","digest_kind":"sha256","value":"2dd557a581097a78210183e31497e236c0f84558bef53ddb283769eb3ed50252"},{"artifact":"tests/test_runtime_resource_retry_v2.py","digest_kind":"sha256","value":"d5183170d4d56d5ba257fd3eeb867016028390da20673877df347e51d12dd740"}],"reported_finding":"The retained second post-repair Astra review reported acceptance of impossible factory and post_benchmark_check histories and a private extra benchmark field. These same-basis symptoms form one escape; missing crash/integration evidence is an additional acceptance gap, not another escape.","failed_approach_summary":"The second repair added stage/counter causal conditions while retaining incremental reachability checks, permissive nested benchmark data and insufficient production-boundary integration tests.","actual_runtime_identity":null,"actual_token_usage":null}}''',
    ))


HISTORICAL_REPORT_IMPORT_PAYLOADS: tuple[Mapping[str, Any], ...] = _historical_report_payloads()


def _historical_report_import_catalogue() -> dict[str, Any]:
    entry = {
        "catalogue_entry_id": HISTORICAL_REPORT_IMPORT_ENTRY_ID,
        "schema_version": "mas1-historical-report-import-catalogue-entry.v1",
        "canonicalization_version": "mas1-canonical-json-ascii.v1",
        "task_instance_id": "01a07819-9ad8-7851-bc8f-513aa93f4dcb",
        "workspace": "/Users/ivanf/Documents/ChatGPT/Instructons",
        "ledger_path": "/Users/ivanf/Documents/ChatGPT/Instructons/.mas1/tasks/01a07819-9ad8-7851-bc8f-513aa93f4dcb/finding-ledger.v1.json",
        "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
        "required_migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID,
        "required_descriptor_sha256": LEGACY_V6_0_AUDIT_DESCRIPTOR_SHA256,
        "import_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
        "root_opened_event_id": HISTORICAL_REPORT_ROOT_OPENED_EVENT_ID,
        "activation_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
        "import_event_schema_version": "mas1-historical-report-import-event.v1",
        "threshold_origin_version": "historical-report-lower-bound.v1",
        "origin_invariant": "Persisted retry outcomes must be closed, privacy-safe aggregates representing reachable execution histories, with the same contract enforced before writing and during replay.",
        "origin_causal_explanation": "Incremental conditionals left writer/replay schema and reachability gaps; tests replaced production seams instead of proving persistence and crash recovery.",
        "threshold_receipt_binding": {
            "observation_id": "OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002",
            "evidence_received_at": "2026-09-11T13:10:56Z",
            "time_basis": "auditable_receipt_upper_bound",
            "first_threshold_known_at": None,
            "original_protocol_adopted_at": None,
        },
        "historical_report_escape_lower_bound": 2,
    }
    entry["observations"] = [
        {"payload": deepcopy(payload), "payload_sha256": digest}
        for payload, digest in zip(HISTORICAL_REPORT_IMPORT_PAYLOADS, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256)
    ]
    return {"schema_version": HISTORICAL_REPORT_IMPORT_CATALOGUE_VERSION, "entries": [entry]}


HISTORICAL_REPORT_IMPORT_CATALOGUE: Mapping[str, Any] = _historical_report_import_catalogue()


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    reasons: tuple[str, ...]
    facts: Mapping[str, Any]


@dataclass(frozen=True)
class ValidationContext:
    """Safely indexed ledger rows for the eventual native rule registry.

    This deliberately carries no authorization verdict.  Until the R7 cutover
    atomically replaces the legacy threshold path, it is structural evidence
    only and therefore cannot become a second threshold authority.
    """
    ledger: Mapping[str, Any]
    rows: Mapping[str, tuple[Mapping[str, Any], ...]]
    indexes: Mapping[str, Mapping[str, Mapping[str, Any]]]
    event_positions: Mapping[str, int]
    normalized: Mapping[str, Any]


def _validation_context(ledger: Any) -> ValidationContext | None:
    if not isinstance(ledger, dict):
        return None
    collections = {
        "roots": "root_cause_id", "observations": "observation_id", "activities": "activity_id",
        "events": "event_id", "repair_attempts": "repair_attempt_id", "strategies": "strategy_id",
        "cycles": "cycle_id", "review_bases": "review_basis_id", "test_evidence": "test_evidence_id",
    }
    rows: dict[str, tuple[Mapping[str, Any], ...]] = {}
    indexes: dict[str, dict[str, Mapping[str, Any]]] = {}
    for collection, identity in collections.items():
        value = ledger.get(collection)
        safe_rows = tuple(item for item in value if isinstance(item, Mapping)) if isinstance(value, list) else ()
        rows[collection] = safe_rows
        indexes[collection] = {item[identity]: item for item in safe_rows if isinstance(item.get(identity), str)}
    event_positions = {event_id: index for index, item in enumerate(rows["events"])
                       if isinstance((event_id := item.get("event_id")), str)}
    events = indexes["events"]
    attempts = indexes["repair_attempts"]
    activations = tuple(item for item in rows["events"] if item.get("type") == "threshold-activated")
    settlements = tuple(item for item in rows["events"] if item.get("type") == "repair-threshold-settled")
    starts = tuple(item for item in rows["events"] if item.get("type") == "repair-attempted")
    mutations = tuple(item for item in rows["activities"] if item.get("type") == "implementation")
    normalized = {
        "authoritative": False,
        "attempts_by_id": attempts,
        "starts_by_attempt": {item.get("repair_attempt_id"): item for item in starts if isinstance(item.get("repair_attempt_id"), str)},
        "settlements_by_attempt": {item.get("repair_attempt_id"): item for item in settlements if isinstance(item.get("repair_attempt_id"), str)},
        "activation_events_by_root": {item.get("root_cause_id"): item for item in activations if isinstance(item.get("root_cause_id"), str)},
        "mutation_activity_ids": tuple(sorted(item["activity_id"] for item in mutations if isinstance(item.get("activity_id"), str))),
        "event_ids": tuple(sorted(events)),
    }
    return ValidationContext(ledger=ledger, rows=rows, indexes=indexes, event_positions=event_positions, normalized=normalized)


@dataclass(frozen=True)
class CutoverPopulationResult:
    """Canonical validation result for a frozen rollout population.

    Population state is part of the MAS1 causal contract.  Keeping it beside
    ledger validation prevents the analyzer (or another consumer) from
    accepting a contradictory dispatch/adoption story before it sees a ledger.
    """
    valid: bool
    reasons: tuple[str, ...]
    manifest: Mapping[str, Any]
    targets: Mapping[str, Mapping[str, Any]]


def parse_rfc3339(value: Any) -> datetime | None:
    """Parse an offset-aware RFC3339 timestamp, returning UTC or ``None``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _schema_reasons(ledger: Any, schema: Any) -> set[str]:
    reasons: set[str] = set()
    if not isinstance(schema, dict):
        return {"internal:schema_not_object"}
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        def add_error(error: Any) -> None:
            # Exclusive discriminated unions report a oneOf umbrella.  Retain
            # the pre-existing ordinary leaf reasons as well so adding the
            # historical branch cannot change established diagnostics.
            if error.validator == "oneOf" and error.context:
                for child in error.context:
                    add_error(child)
            else:
                reasons.add(classify_schema_error(error))
        for error in validator.iter_errors(ledger):
            add_error(error)
        # JSON Schema deliberately treats mathematically integral JSON numbers
        # such as ``2.0`` as integers.  Historical report episodes are an exact
        # release-controlled discriminator, so their decoded representation is
        # narrower: a native integer (and never a Boolean) is required before
        # catalogue hashing or semantic authentication.
        if isinstance(ledger, dict):
            for index, observation in enumerate(ledger.get("observations", [])):
                if not isinstance(observation, dict) or observation.get("record_kind") != "historical-report-import-v1":
                    continue
                report = observation.get("historical_report")
                episode = report.get("reported_episode") if isinstance(report, dict) else None
                if type(episode) is not int:
                    reasons.add(f"schema:type:observations/{index}/historical_report/reported_episode")
    except Exception as exc:  # never turn malformed input into a reporting crash
        reasons.add(f"internal:schema_validation:{type(exc).__name__}")
    return reasons


def _sorted_unique_nonempty(values: Any) -> bool:
    return (isinstance(values, list) and bool(values)
            and all(isinstance(value, str) and value for value in values)
            and values == sorted(set(values)))


def _target_task_contract(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "task_instance_id": entry.get("taskInstanceId"),
        "workspace": entry.get("workspace"),
        "ledger_path": entry.get("ledgerPath"),
        "marker_path": entry.get("markerPath"),
    }


def _target_dispatch_reasons(entry: Any, boundary: Any, *, require_identity: bool = False) -> set[str]:
    """Fail closed on the one permitted target dispatch/adoption state machine."""
    reasons: set[str] = set()
    if not isinstance(entry, Mapping):
        return {"target_not_object"}
    dispatch = entry.get("dispatchStatus")
    adoption = entry.get("protocolAdoptionStatus")
    sent_at = entry.get("messageSentAtUtc")
    dispatch_refs = entry.get("dispatchEvidenceRefs")
    adopted_at = entry.get("protocolAdoptedAt")
    adoption_refs = entry.get("protocolAdoptionEvidenceRefs")
    boundary_at = parse_rfc3339(boundary)
    if dispatch not in {"pending", "sent", "failed"}:
        reasons.add("target_dispatch_status_invalid")
    if adoption not in {"pending", "adopted"}:
        reasons.add("target_adoption_status_invalid")

    if dispatch == "pending":
        if sent_at is not None or dispatch_refs != []:
            reasons.add("target_pending_dispatch_contradiction")
        if adoption != "pending" or adopted_at is not None or adoption_refs != []:
            reasons.add("target_pending_adoption_contradiction")
    elif dispatch in {"sent", "failed"}:
        parsed_sent = parse_rfc3339(sent_at)
        if parsed_sent is None or boundary_at is None or parsed_sent < boundary_at:
            reasons.add("target_dispatch_timestamp_invalid_or_pre_boundary")
        if not _sorted_unique_nonempty(dispatch_refs):
            reasons.add("target_dispatch_evidence_invalid")
        if dispatch == "failed" and (adoption != "pending" or adopted_at is not None or adoption_refs != []):
            reasons.add("target_failed_adoption_contradiction")
        if dispatch == "sent" and adoption == "pending" and (adopted_at is not None or adoption_refs != []):
            reasons.add("target_sent_pending_adoption_contradiction")
        if dispatch == "sent" and adoption == "adopted":
            parsed_adopted = parse_rfc3339(adopted_at)
            if (parsed_adopted is None or parsed_sent is None or boundary_at is None
                    or parsed_adopted < parsed_sent or parsed_adopted < boundary_at):
                reasons.add("target_adoption_timestamp_invalid_or_pre_dispatch")
            if not _sorted_unique_nonempty(adoption_refs):
                reasons.add("target_adoption_evidence_invalid")
    elif adoption == "adopted":
        # Keep the invalid-status branch fail-closed even if its fields happen
        # to resemble a valid sent/adopted transition.
        reasons.add("target_adopted_without_sent_dispatch")

    if require_identity:
        identity_reasons = _native_canonical_task_path_reasons(_target_task_contract(entry))
        if identity_reasons:
            # Keep one stable, consumer-friendly umbrella code alongside
            # the exact lexical reason needed for diagnostics.
            reasons.add("target_noncanonical_path")
            reasons.update(identity_reasons)
    return reasons


_LEGACY_COLLECTIONS: Mapping[str, str] = {
    "roots": "root_cause_id", "observations": "observation_id", "review_bases": "review_basis_id",
    "cycles": "cycle_id", "test_evidence": "test_evidence_id", "repair_attempts": "repair_attempt_id",
    "strategies": "strategy_id", "activities": "activity_id", "events": "event_id",
}
_LEGACY_IDENTITY_KEYS = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "sha256")
_LEGACY_JOURNAL_KEYS = (
    "schema_version", "record_type", "journal_id", "migration_id", "mode", "catalogue_entry_id",
    "task_instance_id", "workspace", "ledger_path", "marker_path", "migration_dir",
    "authorization_id", "authorization_path", "authorization_sha256", "decision_id", "decision_path",
    "decision_sha256", "descriptor_sha256", "before_ledger_path", "before_ledger_sha256",
    "before_marker_path", "before_marker_sha256", "after_ledger_sha256", "after_marker_sha256",
    "lock_path", "journal_path", "journal_temp_path", "receipt_path", "receipt_temp_path",
    "ledger_candidate_path", "marker_candidate_path", "threshold_evidence", "selected_identities", "events",
)
_LEGACY_RECEIPT_KEYS = (
    "schema_version", "record_type", "receipt_id", "migration_id", "mode", "catalogue_entry_id",
    "task_instance_id", "workspace", "ledger_path", "marker_path", "migration_dir", "authorization_id",
    "authorization_sha256", "decision_id", "decision_sha256", "descriptor_sha256",
    "before_ledger_sha256", "before_marker_sha256", "after_ledger_sha256", "after_marker_sha256",
    "journal_id", "journal_path", "journal_sha256", "journal_terminal_phase", "threshold_evidence",
    "published_ledger_identity", "published_marker_identity", "recorded_at", "recorded_at_semantics",
    "status", "evidence_refs",
)
_LEGACY_SELECTED_IDENTITY_KEYS = (
    "ledger", "marker", "authorization", "decision",
    "ledger_candidate", "marker_candidate", "published_ledger", "published_marker",
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _json_exact(left: Any, right: Any) -> bool:
    """JSON equality with key-order and bool-vs-number distinctions."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (tuple(left) == tuple(right)
                and all(_json_exact(left[key], right[key]) for key in left))
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_exact(a, b) for a, b in zip(left, right))
    return left == right


def _legacy_descriptor_bytes(descriptor: Mapping[str, Any]) -> bytes:
    return (json.dumps(descriptor, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _legacy_candidate_bytes(original: bytes, descriptor: Mapping[str, Any]) -> bytes:
    if not original.endswith(b"}\n"):
        raise ValueError("legacy_source_suffix")
    rendered = json.dumps(descriptor, ensure_ascii=False, indent=2).replace("\n", "\n  ").encode("utf-8")
    return original[:-2] + b',\n  "legacy_v6_0_audit": ' + rendered + b"\n}\n"


def _identity_from_stat(info: os.stat_result, data: bytes) -> dict[str, Any]:
    return {
        "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid, "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink, "size": len(data), "sha256": _sha256(data),
    }


def _identity_shape(value: Any) -> bool:
    return (isinstance(value, dict) and tuple(value) == _LEGACY_IDENTITY_KEYS
            and all(_strict_int(value[key]) for key in _LEGACY_IDENTITY_KEYS[:-1])
            and isinstance(value["sha256"], str) and len(value["sha256"]) == 64
            and value["nlink"] == 1 and value["size"] >= 0)


def _path_has_symlink(path: Path) -> bool:
    try:
        current = path
        while True:
            if current.is_symlink():
                return True
            if current.parent == current:
                return False
            current = current.parent
    except OSError:
        return True


def _read_regular_bound(path: Path, *, uid: int, mode: int, expected_sha256: str | None = None,
                        expected_nlink: int = 1) -> tuple[bytes, dict[str, Any]]:
    if _path_has_symlink(path):
        raise ValueError("symlink")
    named_before = os.lstat(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if ((named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(named_before.st_mode) or not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid or before.st_nlink != expected_nlink
                or stat.S_IMODE(before.st_mode) != mode):
            raise ValueError("identity")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("identity_changed")
        named_after = os.lstat(path)
        if ((named_after.st_dev, named_after.st_ino, named_after.st_size, named_after.st_mtime_ns,
             named_after.st_uid, named_after.st_gid, stat.S_IMODE(named_after.st_mode), named_after.st_nlink) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode), after.st_nlink)):
            raise ValueError("named_identity_changed")
        identity = _identity_from_stat(after, data)
        if expected_sha256 is not None and identity["sha256"] != expected_sha256:
            raise ValueError("hash")
        return data, identity
    finally:
        os.close(fd)


def _open_directory_bound(path: Path, *, uid: int) -> int:
    if _path_has_symlink(path):
        raise ValueError("symlink")
    named = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        valid = (
            (named.st_dev, named.st_ino, named.st_uid, named.st_gid,
             stat.S_IMODE(named.st_mode), named.st_nlink)
            == (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                stat.S_IMODE(opened.st_mode), opened.st_nlink)
            and stat.S_ISDIR(named.st_mode) and opened.st_uid == uid
        )
    except OSError:
        os.close(fd)
        raise
    if not valid:
        os.close(fd)
        raise ValueError("directory_identity")
    return fd


def _read_regular_at(directory_fd: int, name: str, *, uid: int, mode: int,
                     expected_sha256: str | None = None) -> tuple[bytes, dict[str, Any]]:
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError("name")
    named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if ((named_before.st_dev, named_before.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(named_before.st_mode) or not stat.S_ISREG(before.st_mode)
                or before.st_uid != uid or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode):
            raise ValueError("identity")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (named_after.st_dev, named_after.st_ino, named_after.st_size, named_after.st_mtime_ns,
                    named_after.st_uid, named_after.st_gid, stat.S_IMODE(named_after.st_mode), named_after.st_nlink)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                    after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode), after.st_nlink)):
            raise ValueError("identity_changed")
        identity = _identity_from_stat(after, data)
        if expected_sha256 is not None and identity["sha256"] != expected_sha256:
            raise ValueError("hash")
        return data, identity
    finally:
        os.close(fd)


def _legacy_journal_reasons(journal: Any, entry: Mapping[str, Any]) -> set[str]:
    reasons: set[str] = set()
    if not isinstance(journal, dict) or set(journal) != set(_LEGACY_JOURNAL_KEYS):
        return {"compat:journal_schema"}
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    expected = {
        "schema_version": "mas1-legacy-v6.0-migration-journal.v1", "record_type": "migration-journal",
        "journal_id": entry["journal"]["journal_id"], "migration_id": entry["migration_id"],
        "mode": entry["mode"], "catalogue_entry_id": entry["catalogue_entry_id"],
        "task_instance_id": entry["task_instance_id"], "workspace": entry["workspace"],
        "ledger_path": entry["ledger_path"], "marker_path": entry["marker_path"],
        "migration_dir": entry["migration_dir"], "authorization_id": entry["authorization"]["authorization_id"],
        "authorization_path": entry["authorization"]["path"], "authorization_sha256": entry["authorization"]["sha256"],
        "decision_id": entry["decision"]["decision_id"], "decision_path": entry["decision"]["path"],
        "decision_sha256": entry["decision"]["sha256"], "descriptor_sha256": entry["descriptor"]["sha256"],
        "before_ledger_path": fixed["before_ledger"], "before_ledger_sha256": entry["original"]["ledger_sha256"],
        "before_marker_path": fixed["before_marker"], "before_marker_sha256": entry["original"]["marker_sha256"],
        "after_ledger_sha256": entry["transformation"]["after_ledger_sha256"],
        "after_marker_sha256": entry["transformation"]["after_marker_sha256"], "lock_path": fixed["lock"],
        "journal_path": fixed["journal"], "journal_temp_path": temps["journal"], "receipt_path": fixed["receipt"],
        "receipt_temp_path": temps["receipt"], "ledger_candidate_path": temps["ledger_publication"],
        "marker_candidate_path": temps["marker_publication"], "threshold_evidence": entry["threshold_evidence"],
    }
    for key, value in expected.items():
        if not _json_exact(journal.get(key), value):
            reasons.add(f"compat:journal_binding:{key}")
    identities = journal.get("selected_identities")
    if (not isinstance(identities, dict) or tuple(identities) != _LEGACY_SELECTED_IDENTITY_KEYS
            or any(not _identity_shape(identities.get(key))
                   for key in ("ledger", "marker", "authorization", "decision"))):
        reasons.add("compat:journal_identities")
    events = journal.get("events")
    phases = entry["journal"]["phases"]
    phase_index: int | None = None
    if not isinstance(events, list) or not events or len(events) > len(phases):
        reasons.add("compat:journal_events")
    else:
        last: datetime | None = None
        for index, event in enumerate(events):
            if (not isinstance(event, dict) or set(event) != {"sequence", "phase", "at"}
                    or event.get("sequence") != index + 1 or event.get("phase") != phases[index]):
                reasons.add("compat:journal_events")
                break
            instant = parse_rfc3339(event.get("at"))
            if instant is None or (last is not None and instant < last):
                reasons.add("compat:journal_events")
                break
            last = instant
        else:
            phase_index = len(events) - 1
    if isinstance(identities, dict) and phase_index is not None:
        phase_requirements = (
            ("ledger_candidate", "ledger_candidate_fsynced"),
            ("marker_candidate", "marker_candidate_fsynced"),
            ("published_ledger", "ledger_published"),
            ("published_marker", "marker_published"),
        )
        for key, phase_name in phase_requirements:
            required = phase_index >= phases.index(phase_name)
            if required != _identity_shape(identities.get(key)):
                reasons.add(f"compat:journal_identity_phase:{key}")
        for candidate, published in (("ledger_candidate", "published_ledger"),
                                     ("marker_candidate", "published_marker")):
            if identities.get(published) is not None \
                    and not _json_exact(identities.get(candidate), identities.get(published)):
                reasons.add(f"compat:journal_identity_binding:{published}")
    return reasons


def _legacy_receipt_reasons(receipt: Any, journal_data: bytes, journal: Any,
                            entry: Mapping[str, Any]) -> set[str]:
    if not isinstance(receipt, dict) or set(receipt) != set(_LEGACY_RECEIPT_KEYS):
        return {"compat:receipt_schema"}
    expected = {
        "schema_version": "mas1-legacy-v6.0-migration-receipt.v1", "record_type": "migration-receipt",
        "receipt_id": entry["receipt"]["receipt_id"], "migration_id": entry["migration_id"],
        "mode": entry["mode"], "catalogue_entry_id": entry["catalogue_entry_id"],
        "task_instance_id": entry["task_instance_id"], "workspace": entry["workspace"],
        "ledger_path": entry["ledger_path"], "marker_path": entry["marker_path"],
        "migration_dir": entry["migration_dir"], "authorization_id": entry["authorization"]["authorization_id"],
        "authorization_sha256": entry["authorization"]["sha256"], "decision_id": entry["decision"]["decision_id"],
        "decision_sha256": entry["decision"]["sha256"], "descriptor_sha256": entry["descriptor"]["sha256"],
        "before_ledger_sha256": entry["original"]["ledger_sha256"],
        "before_marker_sha256": entry["original"]["marker_sha256"],
        "after_ledger_sha256": entry["transformation"]["after_ledger_sha256"],
        "after_marker_sha256": entry["transformation"]["after_marker_sha256"],
        "journal_id": entry["journal"]["journal_id"], "journal_path": entry["journal"]["path"],
        "journal_sha256": _sha256(journal_data), "journal_terminal_phase": entry["journal"]["terminal_phase"],
        "threshold_evidence": entry["threshold_evidence"], "status": "complete",
    }
    reasons: set[str] = set()
    for key, value in expected.items():
        if not _json_exact(receipt.get(key), value):
            reasons.add(f"compat:receipt_binding:{key}")
    if not isinstance(journal, dict) or not journal.get("events") \
            or journal["events"][-1].get("phase") != entry["journal"]["terminal_phase"]:
        reasons.add("compat:receipt_journal_terminal")
    for key in ("published_ledger_identity", "published_marker_identity"):
        published = receipt.get(key)
        expected_sha = entry["transformation"][
            "after_ledger_sha256" if key == "published_ledger_identity" else "after_marker_sha256"
        ]
        if (not _identity_shape(published) or published.get("uid") != entry["identity_requirements"]["uid"]
                or published.get("mode") != entry["identity_requirements"]["canonical_file_mode"]
                or published.get("sha256") != expected_sha):
            reasons.add(f"compat:receipt_binding:{key}")
    if parse_rfc3339(receipt.get("recorded_at")) is None:
        reasons.add("compat:receipt_recorded_at")
    if receipt.get("recorded_at_semantics") != (
            "Administrative terminal receipt time only; not protocol adoption, threshold discovery, authorization, or adjudication time."):
        reasons.add("compat:receipt_recorded_at_semantics")
    refs = receipt.get("evidence_refs")
    if not _sorted_unique_nonempty(refs):
        reasons.add("compat:receipt_evidence_refs")
    return reasons


def _legacy_snapshot_reasons(before: Any, current: Any, marker_before: Any, marker_current: Any,
                             descriptor: Mapping[str, Any]) -> set[str]:
    reasons: set[str] = set()
    if not all(isinstance(value, dict) for value in (before, current, marker_before, marker_current)):
        return {"compat:snapshot_json"}
    expected_top = list(before) + ["legacy_v6_0_audit"]
    if list(current) != expected_top or not _json_exact(current.get("legacy_v6_0_audit"), descriptor):
        reasons.add("compat:ledger_descriptor_or_order")
    for key in before:
        if key in _LEGACY_COLLECTIONS:
            old, new = before.get(key), current.get(key)
            if (not isinstance(old, list) or not isinstance(new, list) or len(new) < len(old)
                    or any(not _json_exact(left, right) for left, right in zip(old, new))):
                reasons.add(f"compat:frozen_collection:{key}")
        elif key == "telemetry":
            if not _json_exact(before.get(key), current.get(key)):
                reasons.add("compat:frozen_telemetry")
        elif not _json_exact(before.get(key), current.get(key)):
            reasons.add(f"compat:frozen_member:{key}")
    if list(marker_current) != list(marker_before) + ["legacy_v6_0_audit"]:
        reasons.add("compat:marker_descriptor_or_order")
    for key in marker_before:
        if not _json_exact(marker_before.get(key), marker_current.get(key)):
            reasons.add(f"compat:frozen_marker:{key}")
    if not _json_exact(marker_current.get("legacy_v6_0_audit"), descriptor):
        reasons.add("compat:marker_descriptor_or_order")
    return reasons


def _legacy_compatibility_reasons(ledger: Any, loaded_path: Any, marker: Any) -> tuple[bool, set[str], Mapping[str, Any] | None]:
    """Authenticate one terminal compatibility migration from a single snapshot."""
    if not isinstance(ledger, dict) or "legacy_v6_0_audit" not in ledger:
        return False, set(), None
    reasons: set[str] = set()
    descriptor = ledger.get("legacy_v6_0_audit")
    expected_descriptor = LEGACY_V6_0_AUDIT_DESCRIPTOR
    entry = LEGACY_V6_0_AUDIT_CATALOGUE.get(LEGACY_V6_0_AUDIT_MIGRATION_ID)
    if not isinstance(entry, Mapping):
        return False, {"compat:catalogue_missing"}, None
    catalogue_bytes = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")
    if _sha256(catalogue_bytes) != LEGACY_V6_0_AUDIT_CATALOGUE_SHA256:
        reasons.add("compat:catalogue_digest")
    if not isinstance(descriptor, dict) or not _json_exact(descriptor, expected_descriptor):
        reasons.add("compat:descriptor")
    elif _sha256(_legacy_descriptor_bytes(descriptor)) != entry["descriptor"]["sha256"]:
        reasons.add("compat:descriptor_digest")
    if str(loaded_path) != entry["ledger_path"]:
        reasons.add("compat:loaded_path")
    if not isinstance(marker, dict):
        reasons.add("compat:marker_required")
    if reasons:
        return False, reasons, None
    identity = entry["identity_requirements"]
    migration_dir = Path(entry["migration_dir"])
    try:
        info = os.lstat(migration_dir)
        if (_path_has_symlink(migration_dir) or not stat.S_ISDIR(info.st_mode) or info.st_uid != identity["uid"]
                or stat.S_IMODE(info.st_mode) != identity["evidence_directory_mode"]):
            raise ValueError("migration_dir")
        fixed = entry["artifacts"]["fixed"]
        current_ledger_data, current_ledger_identity = _read_regular_bound(
            Path(entry["ledger_path"]), uid=identity["uid"], mode=identity["canonical_file_mode"])
        current_marker_data, current_marker_identity = _read_regular_bound(
            Path(entry["marker_path"]), uid=identity["uid"], mode=identity["canonical_file_mode"])
        auth_data, auth_identity = _read_regular_bound(Path(fixed["authorization"]), uid=identity["uid"],
                                                        mode=identity["evidence_file_mode"],
                                                        expected_sha256=entry["authorization"]["sha256"])
        decision_data, decision_identity = _read_regular_bound(Path(fixed["decision"]), uid=identity["uid"],
                                                                mode=identity["evidence_file_mode"],
                                                                expected_sha256=entry["decision"]["sha256"])
        before_ledger_data, before_ledger_identity = _read_regular_bound(
            Path(fixed["before_ledger"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=entry["original"]["ledger_sha256"])
        before_marker_data, before_marker_identity = _read_regular_bound(
            Path(fixed["before_marker"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=entry["original"]["marker_sha256"])
        journal_data, journal_identity = _read_regular_bound(Path(fixed["journal"]), uid=identity["uid"],
                                                              mode=identity["evidence_file_mode"])
        receipt_data, _ = _read_regular_bound(Path(fixed["receipt"]), uid=identity["uid"],
                                               mode=identity["evidence_file_mode"])
        _read_regular_bound(Path(fixed["lock"]), uid=identity["uid"], mode=identity["lock_file_mode"])
        parsed_current = json.loads(current_ledger_data)
        parsed_marker = json.loads(current_marker_data)
        before_ledger = json.loads(before_ledger_data)
        before_marker = json.loads(before_marker_data)
        auth = json.loads(auth_data); decision = json.loads(decision_data)
        journal = json.loads(journal_data); receipt = json.loads(receipt_data)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False, {"compat:evidence_integrity"}, None
    if not _json_exact(parsed_current, ledger):
        reasons.add("compat:loaded_payload")
    if not _json_exact(parsed_marker, marker):
        reasons.add("compat:marker_payload")
    reasons.update(_legacy_snapshot_reasons(before_ledger, ledger, before_marker, marker, descriptor))
    if _sha256(_legacy_candidate_bytes(before_ledger_data, descriptor)) != entry["transformation"]["after_ledger_sha256"]:
        reasons.add("compat:ledger_candidate_digest")
    if _sha256(_legacy_candidate_bytes(before_marker_data, descriptor)) != entry["transformation"]["after_marker_sha256"]:
        reasons.add("compat:marker_candidate_digest")
    if _sha256(current_marker_data) != entry["transformation"]["after_marker_sha256"]:
        reasons.add("compat:marker_current_digest")
    if not isinstance(auth, dict) or auth.get("schema_version") != entry["authorization"]["schema_version"] \
            or auth.get("authorization_id") != entry["authorization"]["authorization_id"] \
            or auth.get("migration_id") != entry["migration_id"]:
        reasons.add("compat:authorization_payload")
    if (not isinstance(decision, dict) or decision.get("schema_version") != entry["decision"]["schema_version"]
            or decision.get("decision_id") != entry["decision"]["decision_id"]
            or decision.get("migration_id") != entry["migration_id"] or decision.get("disposition") != "approved"
            or (decision.get("judge_result") or {}).get("result_sha256") != entry["decision"]["judge_result_sha256"]):
        reasons.add("compat:decision_payload")
    reasons.update(_legacy_journal_reasons(journal, entry))
    reasons.update(_legacy_receipt_reasons(receipt, journal_data, journal, entry))
    selected = journal.get("selected_identities") if isinstance(journal, dict) else {}
    for receipt_key, journal_key in (("published_ledger_identity", "published_ledger"),
                                     ("published_marker_identity", "published_marker")):
        if not _json_exact(receipt.get(receipt_key), (selected or {}).get(journal_key)):
            reasons.add(f"compat:receipt_binding:{receipt_key}")
    if (_sha256(current_ledger_data) == entry["transformation"]["after_ledger_sha256"]
            and not _json_exact(receipt.get("published_ledger_identity"), current_ledger_identity)):
        reasons.add("compat:receipt_binding:published_ledger_identity")
    if not _json_exact(receipt.get("published_marker_identity"), current_marker_identity):
        reasons.add("compat:receipt_binding:published_marker_identity")
    for key, actual in (("ledger", before_ledger_identity), ("marker", before_marker_identity),
                        ("authorization", auth_identity), ("decision", decision_identity)):
        recorded = (selected or {}).get(key)
        if key in {"authorization", "decision"}:
            matches = _json_exact(recorded, actual)
        else:
            # Snapshot publication necessarily gives the copy a new inode and
            # restrictive mode.  The selected source identity remains durable
            # historical evidence; all attributes that a copy can preserve are
            # independently rederived from the frozen snapshot.
            matches = _legacy_selected_copy_matches(recorded, actual, identity)
        if not matches:
            reasons.add(f"compat:selected_identity:{key}")
    if not _json_exact(entry["threshold_evidence"], descriptor.get("threshold_evidence")):
        reasons.add("compat:threshold_binding")
    return not reasons, reasons, before_ledger if not reasons else None


def _historical_report_import_state(
    context: ValidationContext, snapshot: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], set[str], Mapping[str, Any] | None]:
    """Authenticate the one release-catalogued retained-report registration.

    Presence is selected only by the closed discriminators.  Once any member
    appears the complete catalogue-bound registration is required; a mutable
    commitment inside the ledger can never authenticate altered report data.
    """
    reasons: set[str] = set()
    try:
        catalogue_bytes = _canonical_json_ascii(HISTORICAL_REPORT_IMPORT_CATALOGUE)
    except (TypeError, ValueError, UnicodeError):
        return {}, {"report_import:catalogue_encoding"}, None
    if _sha256(catalogue_bytes) != HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256:
        return {}, {"report_import:catalogue_digest"}, None
    entries = HISTORICAL_REPORT_IMPORT_CATALOGUE.get("entries")
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
        return {}, {"report_import:catalogue_shape"}, None
    entry = entries[0]
    expected_observations = [binding["payload"] for binding in entry["observations"]]
    historical = [
        row for row in context.rows["observations"]
        if row.get("record_kind") == "historical-report-import-v1"
    ]
    import_events = [
        row for row in context.rows["events"]
        if row.get("record_kind") == "historical-report-import-event-v1"
        or row.get("type") == "historical-report-imported"
    ]
    root = context.indexes["roots"].get(HISTORICAL_REPORT_ROOT_ID)
    present = bool(historical or import_events or isinstance(root, Mapping))
    if not present:
        return {}, reasons, None
    task = context.ledger.get("task") or {}
    descriptor = context.ledger.get("legacy_v6_0_audit") or {}
    if (
        task.get("task_instance_id") != entry["task_instance_id"]
        or task.get("workspace") != entry["workspace"]
        or task.get("ledger_path") != entry["ledger_path"]
        or descriptor.get("migration_id") != entry["required_migration_id"]
        or _sha256(_legacy_descriptor_bytes(descriptor)) != entry["required_descriptor_sha256"]
    ):
        reasons.add("report_import:catalogue_scope")

    snapshot_count = len(snapshot.get("observations", [])) if isinstance(snapshot.get("observations"), list) else 0
    suffix = list(context.rows["observations"][snapshot_count:])
    if len(suffix) < 3 or any(not _json_exact(suffix[index], expected_observations[index]) for index in range(3)):
        reasons.add("report_import:observation_order_or_payload")
    if not all(any(_json_exact(row, expected) for row in historical) for expected in expected_observations) \
            or len(historical) != 3:
        reasons.add("report_import:observation_set")
    for expected, digest in zip(expected_observations, HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256):
        if _sha256(_canonical_json_ascii(expected)) != digest:
            reasons.add("report_import:payload_digest")

    if len(import_events) != 1:
        reasons.add("report_import:event_count")
        import_event: Mapping[str, Any] = {}
    else:
        import_event = import_events[0]
    expected_event_keys = {
        "record_kind", "schema_version", "type", "event_id", "sequence", "at", "root_cause_id",
        "causal_refs", "evidence_refs", "at_semantics", "catalogue_entry_id", "catalogue_sha256",
        "import_activity_id", "observation_bindings", "observation_id", "repair_attempt_id",
        "review_basis_id", "cycle_id", "root_relationship", "escape_key",
    }
    expected_bindings = [
        {"observation_id": item["payload"]["observation_id"], "payload_sha256": item["payload_sha256"]}
        for item in entry["observations"]
    ]
    nullable = ("observation_id", "repair_attempt_id", "review_basis_id", "cycle_id", "root_relationship", "escape_key")
    event_ok = bool(
        set(import_event) == expected_event_keys
        and import_event.get("record_kind") == "historical-report-import-event-v1"
        and import_event.get("schema_version") == entry["import_event_schema_version"]
        and import_event.get("type") == "historical-report-imported"
        and import_event.get("event_id") == entry["import_event_id"]
        and import_event.get("root_cause_id") == entry["root_cause_id"]
        and import_event.get("at_semantics") == "administrative-import-time"
        and import_event.get("catalogue_entry_id") == entry["catalogue_entry_id"]
        and import_event.get("catalogue_sha256") == HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256
        and import_event.get("observation_bindings") == expected_bindings
        and all(import_event.get(key) is None for key in nullable)
        and _nonblank_sorted_unique(import_event.get("evidence_refs"))
        and isinstance(import_event.get("sequence"), int)
        and not isinstance(import_event.get("sequence"), bool)
        and parse_rfc3339(import_event.get("at")) is not None
    )
    if not event_ok:
        reasons.add("report_import:event_binding")

    activity = context.indexes["activities"].get(import_event.get("import_activity_id"))
    activity_ok = bool(
        isinstance(activity, Mapping)
        and activity.get("type") in {"ledger-administration", "administration", "implementation"}
        and activity.get("status") == "completed"
        and _direct_root_attribution(activity, HISTORICAL_REPORT_ROOT_ID)
        and parse_rfc3339(activity.get("started_at")) is not None
        and parse_rfc3339(activity.get("completed_at")) is not None
        and parse_rfc3339(activity.get("started_at")) <= parse_rfc3339(activity.get("completed_at"))
        and parse_rfc3339(activity.get("completed_at")) <= parse_rfc3339(import_event.get("at"))
    )
    if not activity_ok:
        reasons.add("report_import:activity")

    opened = context.indexes["events"].get(entry["root_opened_event_id"])
    activation = context.indexes["events"].get(entry["activation_event_id"])
    root_ok = bool(
        isinstance(root, Mapping)
        and root.get("first_observation_id") == expected_observations[0]["observation_id"]
        and root.get("invariant") == entry["origin_invariant"]
        and root.get("causal_explanation") == entry["origin_causal_explanation"]
        and root.get("creation_time_basis") == "ledger-registration"
        and root.get("reconciliation_complete") is False
        and root.get("historical_escape_count_baseline") is None
        and root.get("escape_count_lifetime") is None
        and root.get("historical_escape_evidence_refs") == []
        and root.get("historical_baseline_reconciliation_event_id") is None
        and root.get("threshold_anchor") == {
            "kind": "historical-report-lower-bound", "report_import_event_id": entry["import_event_id"],
        }
        and root.get("first_threshold_activation_event_id") == entry["activation_event_id"]
        and isinstance(opened, Mapping)
        and opened.get("type") == "root-opened"
        and opened.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        and opened.get("observation_id") == expected_observations[0]["observation_id"]
        and root.get("created_at") == opened.get("at")
    )
    if not root_ok:
        reasons.add("report_import:root_origin")
    boundary = entry["threshold_receipt_binding"]["evidence_received_at"]
    activation_ok = bool(
        isinstance(activation, Mapping)
        and activation.get("type") == "threshold-activated"
        and activation.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        and activation.get("activation_anchor_event_id") == entry["import_event_id"]
        and activation.get("first_threshold_known_at") is None
        and activation.get("original_protocol_adopted_at") is None
        and activation.get("effective_at") == boundary
        and _nonblank_sorted_unique(activation.get("evidence_refs"))
        and {HISTORICAL_REPORT_ROOT_ID, entry["import_event_id"]}.issubset(
            set(activation.get("causal_refs") or [])
        )
    )
    if not activation_ok:
        reasons.add("report_import:activation")
    import_at = parse_rfc3339(import_event.get("at"))
    opened_at = parse_rfc3339(opened.get("at")) if isinstance(opened, Mapping) else None
    activation_at = parse_rfc3339(activation.get("at")) if isinstance(activation, Mapping) else None
    effective_at = parse_rfc3339(activation.get("effective_at")) if isinstance(activation, Mapping) else None
    if not (
        isinstance(opened, Mapping) and isinstance(activation, Mapping)
        and isinstance(import_event.get("sequence"), int) and not isinstance(import_event.get("sequence"), bool)
        and isinstance(opened.get("sequence"), int) and not isinstance(opened.get("sequence"), bool)
        and isinstance(activation.get("sequence"), int) and not isinstance(activation.get("sequence"), bool)
        and import_event.get("sequence") < opened.get("sequence") < activation.get("sequence")
        and import_at is not None and opened_at is not None and import_at <= opened_at
        and activation_at is not None and effective_at is not None and activation_at >= effective_at
    ):
        reasons.add("report_import:event_order")

    origin = {
        "version": "historical-report-lower-bound.v1",
        "root_cause_id": HISTORICAL_REPORT_ROOT_ID,
        "report_import_event_id": entry["import_event_id"],
        "activation_event_id": entry["activation_event_id"],
        "historical_report_escape_lower_bound": 2,
        "lifetime_count": None,
        "baseline_resolved": False,
        "first_threshold_known_at": None,
        "original_protocol_adopted_at": None,
        "enforcement_boundary": boundary,
        "enforcement_boundary_basis": entry["threshold_receipt_binding"]["time_basis"],
        "authorization": "none",
    }
    return {HISTORICAL_REPORT_ROOT_ID: origin}, reasons, entry


def _historical_report_field_scope_reasons(
    context: ValidationContext, *, compatibility_active: bool,
) -> set[str]:
    """Reject import-only authority fields outside the authenticated root.

    Ordinary record schemas intentionally remain extensible.  That must not
    allow a foreign task or disjoint root to borrow the report-import anchor or
    its content-addressed decision vocabulary.
    """
    reasons: set[str] = set()
    scoped = compatibility_active
    strategy_fields = {
        "failed_predecessor_report_observation_ids", "material_difference_explanation",
        "import_origin_decision_binding", "import_origin_decision_binding_sha256",
    }
    binding_fields = {"import_origin_decision_binding", "import_origin_decision_binding_sha256"}

    def reject(collection: str, identity: Any) -> None:
        reasons.add(f"report_import:field_scope:{collection}:{identity if isinstance(identity, str) else 'unknown'}")

    for row in context.rows["roots"]:
        anchor = row.get("threshold_anchor")
        if isinstance(anchor, Mapping) and anchor.get("kind") == "historical-report-lower-bound" \
                and not (scoped and row.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID):
            reject("roots", row.get("root_cause_id"))
    for row in context.rows["strategies"]:
        if strategy_fields.intersection(row) and not (
            scoped and row.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        ):
            reject("strategies", row.get("strategy_id"))
    for row in context.rows["repair_attempts"]:
        if binding_fields.intersection(row) and not (
            scoped and row.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        ):
            reject("repair_attempts", row.get("repair_attempt_id"))
    for row in context.rows["activities"]:
        if binding_fields.intersection(row) and not (
            scoped and _direct_root_attribution(row, HISTORICAL_REPORT_ROOT_ID)
        ):
            reject("activities", row.get("activity_id"))
    for row in context.rows["events"]:
        historical_event = row.get("record_kind") == "historical-report-import-event-v1"
        if (historical_event or binding_fields.intersection(row)) and not (
            scoped and row.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        ):
            reject("events", row.get("event_id"))
    for row in context.rows["observations"]:
        if row.get("record_kind") == "historical-report-import-v1" and not (
            scoped and row.get("root_cause_id") == HISTORICAL_REPORT_ROOT_ID
        ):
            reject("observations", row.get("observation_id"))
    return reasons


class LegacyMigrationError(RuntimeError):
    """Enumerated, non-sensitive migration failure."""


def _migration_fail(code: str) -> None:
    raise LegacyMigrationError(code)


def _migration_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _migration_hit(hook: Callable[[str], None] | None, label: str) -> None:
    if hook is not None:
        hook(label)


def _migration_fsync_dir(path: Path, hook: Callable[[str], None] | None, label: str) -> None:
    _migration_hit(hook, f"before_{label}_dir_fsync")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    _migration_hit(hook, f"after_{label}_dir_fsync")


def _migration_owned_temp(path: Path, entry: Mapping[str, Any]) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    identity = entry["identity_requirements"]
    return (stat.S_ISREG(info.st_mode) and info.st_uid == identity["uid"] and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in {identity["temporary_file_mode"],
                                              identity["evidence_file_mode"],
                                              identity["canonical_file_mode"]})


def _migration_temp_bytes(path: Path, data: bytes, final_mode: int, entry: Mapping[str, Any],
                          hook: Callable[[str], None] | None, label: str) -> dict[str, Any]:
    if path.exists() or path.is_symlink():
        if not _migration_owned_temp(path, entry):
            _migration_fail(f"collision:{label}")
        try:
            existing, existing_identity = _read_regular_bound(
                path, uid=entry["identity_requirements"]["uid"], mode=stat.S_IMODE(os.lstat(path).st_mode))
        except (OSError, ValueError):
            _migration_fail(f"collision:{label}")
        if existing == data and stat.S_IMODE(os.lstat(path).st_mode) == final_mode:
            return existing_identity
        _migration_hit(hook, f"before_{label}_stale_temp_unlink")
        os.unlink(path)
        _migration_fsync_dir(path.parent, hook, f"{label}_stale_temp_unlink")
        _migration_hit(hook, f"after_{label}_stale_temp_unlink")
    _migration_hit(hook, f"before_{label}_temp_create")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, entry["identity_requirements"]["temporary_file_mode"])
    _migration_hit(hook, f"after_{label}_temp_create")
    staged_identity: dict[str, Any] | None = None
    try:
        _migration_hit(hook, f"before_{label}_write")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _migration_fail(f"write:{label}")
            view = view[written:]
        _migration_hit(hook, f"after_{label}_write")
        _migration_hit(hook, f"before_{label}_file_fsync")
        os.fsync(fd)
        _migration_hit(hook, f"after_{label}_file_fsync")
        os.fchmod(fd, final_mode)
        os.fsync(fd)
        staged_identity = _identity_from_stat(os.fstat(fd), data)
    finally:
        os.close(fd)
    _migration_fsync_dir(path.parent, hook, f"{label}_temp")
    if not _identity_shape(staged_identity):
        _migration_fail(f"temp_identity:{label}")
    return staged_identity


def _migration_publish_new(temp: Path, target: Path, entry: Mapping[str, Any],
                           hook: Callable[[str], None] | None, label: str,
                           expected_data: bytes, expected_mode: int,
                           pre_publish: Callable[[], None] | None = None) -> None:
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            _migration_fail(f"collision:{label}")
        temp_exists = temp.exists() or temp.is_symlink()
        try:
            target_stat = os.lstat(target)
            temp_stat = os.lstat(temp) if temp_exists else None
            linked_pair = bool(
                temp_stat is not None and not stat.S_ISLNK(temp_stat.st_mode)
                and (target_stat.st_dev, target_stat.st_ino) == (temp_stat.st_dev, temp_stat.st_ino)
            )
            target_data, target_identity = _read_regular_bound(
                target, uid=entry["identity_requirements"]["uid"], mode=expected_mode,
                expected_nlink=2 if linked_pair else 1)
        except (OSError, ValueError):
            _migration_fail(f"collision:{label}")
        if target_data != expected_data:
            _migration_fail(f"collision:{label}")
        if temp_exists:
            if temp.is_symlink():
                _migration_fail(f"collision:{label}")
            try:
                temp_data, temp_identity = _read_regular_bound(
                    temp, uid=entry["identity_requirements"]["uid"], mode=expected_mode,
                    expected_nlink=2 if linked_pair else 1)
            except (OSError, ValueError):
                _migration_fail(f"collision:{label}")
            if (temp_data != expected_data or linked_pair != (
                    (target_identity["device"], target_identity["inode"])
                    == (temp_identity["device"], temp_identity["inode"]))):
                _migration_fail(f"collision:{label}")
            _migration_hit(hook, f"before_{label}_temp_unlink")
            os.unlink(temp)
            _migration_hit(hook, f"after_{label}_temp_unlink")
            _migration_fsync_dir(temp.parent, hook, f"{label}_recovered")
            try:
                recovered, _ = _read_regular_bound(
                    target, uid=entry["identity_requirements"]["uid"], mode=expected_mode,
                    expected_sha256=_sha256(expected_data))
            except (OSError, ValueError):
                _migration_fail(f"collision:{label}")
            if recovered != expected_data:
                _migration_fail(f"collision:{label}")
        return
    _migration_hit(hook, f"before_{label}_rename")
    if pre_publish is not None:
        pre_publish()
    try:
        os.link(temp, target, follow_symlinks=False)
    except FileExistsError:
        _migration_fail(f"collision:{label}")
    _migration_hit(hook, f"after_{label}_link")
    _migration_hit(hook, f"before_{label}_temp_unlink")
    os.unlink(temp)
    _migration_hit(hook, f"after_{label}_temp_unlink")
    _migration_hit(hook, f"after_{label}_rename")
    _migration_fsync_dir(target.parent, hook, label)


def _migration_publish_bytes(temp: Path, target: Path, entry: Mapping[str, Any],
                             hook: Callable[[str], None] | None, label: str,
                             expected_data: bytes, expected_mode: int,
                             pre_publish: Callable[[], None] | None = None) -> None:
    # If the exclusive link already exists, inspect/reconcile it before temp
    # construction.  This is the only authenticated recovery for a crash in
    # the link+unlink interval, and requires the two catalogue-owned names to
    # be the sole links to the exact expected inode.
    if not (target.exists() or target.is_symlink()):
        _migration_temp_bytes(temp, expected_data, expected_mode, entry, hook, label)
    _migration_publish_new(
        temp, target, entry, hook, label, expected_data, expected_mode, pre_publish)


def _migration_read_exclusive_target(temp: Path, target: Path, entry: Mapping[str, Any],
                                     expected_mode: int) -> tuple[bytes, dict[str, Any], bool]:
    """Read a published target, admitting only its exact interrupted link pair."""
    temp_exists = temp.exists() or temp.is_symlink()
    try:
        target_stat = os.lstat(target)
        temp_stat = os.lstat(temp) if temp_exists else None
        linked_pair = bool(
            temp_stat is not None and not stat.S_ISLNK(temp_stat.st_mode)
            and (target_stat.st_dev, target_stat.st_ino) == (temp_stat.st_dev, temp_stat.st_ino)
        )
        target_data, target_identity = _read_regular_bound(
            target, uid=entry["identity_requirements"]["uid"], mode=expected_mode,
            expected_nlink=2 if linked_pair else 1)
        if temp_exists:
            temp_data, temp_identity = _read_regular_bound(
                temp, uid=entry["identity_requirements"]["uid"], mode=expected_mode,
                expected_nlink=2 if linked_pair else 1)
            if (not linked_pair or temp_data != target_data
                    or (temp_identity["device"], temp_identity["inode"])
                    != (target_identity["device"], target_identity["inode"])):
                raise ValueError("exclusive_pair")
        return target_data, target_identity, linked_pair
    except (OSError, ValueError):
        _migration_fail("receipt_integrity")


def _migration_journal_bytes(journal: Mapping[str, Any]) -> bytes:
    return (json.dumps(journal, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _migration_store_journal(journal: Mapping[str, Any], entry: Mapping[str, Any],
                             hook: Callable[[str], None] | None) -> None:
    path = Path(entry["artifacts"]["fixed"]["journal"])
    temp = Path(entry["artifacts"]["temporaries"]["journal"])
    _migration_temp_bytes(temp, _migration_journal_bytes(journal),
                          entry["identity_requirements"]["evidence_file_mode"], entry, hook, "journal")
    _migration_hit(hook, "before_journal_rename")
    os.replace(temp, path)
    _migration_hit(hook, "after_journal_rename")
    _migration_fsync_dir(path.parent, hook, "journal")


def _migration_advance(journal: dict[str, Any], phase: str, entry: Mapping[str, Any],
                       hook: Callable[[str], None] | None) -> None:
    phases = entry["journal"]["phases"]
    events = journal["events"]
    expected = phases[len(events)] if len(events) < len(phases) else None
    if phase != expected:
        _migration_fail("journal_transition")
    event = {"sequence": len(events) + 1, "phase": phase, "at": _migration_now()}
    if events and parse_rfc3339(event["at"]) < parse_rfc3339(events[-1]["at"]):
        event["at"] = events[-1]["at"]
    events.append(event)
    _migration_hit(hook, f"before_{phase}_journal")
    _migration_store_journal(journal, entry, hook)
    _migration_hit(hook, f"after_{phase}_journal")


def _migration_initial_journal(entry: Mapping[str, Any], selected: Mapping[str, Any]) -> dict[str, Any]:
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    return {
        "schema_version": "mas1-legacy-v6.0-migration-journal.v1", "record_type": "migration-journal",
        "journal_id": entry["journal"]["journal_id"], "migration_id": entry["migration_id"],
        "mode": entry["mode"], "catalogue_entry_id": entry["catalogue_entry_id"],
        "task_instance_id": entry["task_instance_id"], "workspace": entry["workspace"],
        "ledger_path": entry["ledger_path"], "marker_path": entry["marker_path"],
        "migration_dir": entry["migration_dir"], "authorization_id": entry["authorization"]["authorization_id"],
        "authorization_path": entry["authorization"]["path"], "authorization_sha256": entry["authorization"]["sha256"],
        "decision_id": entry["decision"]["decision_id"], "decision_path": entry["decision"]["path"],
        "decision_sha256": entry["decision"]["sha256"], "descriptor_sha256": entry["descriptor"]["sha256"],
        "before_ledger_path": fixed["before_ledger"], "before_ledger_sha256": entry["original"]["ledger_sha256"],
        "before_marker_path": fixed["before_marker"], "before_marker_sha256": entry["original"]["marker_sha256"],
        "after_ledger_sha256": entry["transformation"]["after_ledger_sha256"],
        "after_marker_sha256": entry["transformation"]["after_marker_sha256"], "lock_path": fixed["lock"],
        "journal_path": fixed["journal"], "journal_temp_path": temps["journal"], "receipt_path": fixed["receipt"],
        "receipt_temp_path": temps["receipt"], "ledger_candidate_path": temps["ledger_publication"],
        "marker_candidate_path": temps["marker_publication"], "threshold_evidence": deepcopy(entry["threshold_evidence"]),
        "selected_identities": {
            "ledger": deepcopy(selected["ledger"]), "marker": deepcopy(selected["marker"]),
            "authorization": deepcopy(selected["authorization"]),
            "decision": deepcopy(selected["decision"]),
            "ledger_candidate": None, "marker_candidate": None,
            "published_ledger": None, "published_marker": None,
        },
        "events": [],
    }


def _migration_load_journal(entry: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    try:
        data, _ = _read_regular_bound(
            Path(entry["journal"]["path"]), uid=entry["identity_requirements"]["uid"],
            mode=entry["identity_requirements"]["evidence_file_mode"])
        journal = json.loads(data)
    except (OSError, ValueError, json.JSONDecodeError):
        _migration_fail("journal_integrity")
    if _legacy_journal_reasons(journal, entry):
        _migration_fail("journal_integrity")
    return journal, data


def _migration_layout(entry: Mapping[str, Any]) -> tuple[str, bytes, bytes, dict[str, Any], dict[str, Any]]:
    identity = entry["identity_requirements"]
    try:
        ledger, ledger_identity = _read_regular_bound(
            Path(entry["ledger_path"]), uid=identity["uid"], mode=identity["canonical_file_mode"])
        marker, marker_identity = _read_regular_bound(
            Path(entry["marker_path"]), uid=identity["uid"], mode=identity["canonical_file_mode"])
    except (OSError, ValueError):
        _migration_fail("canonical_identity")
    left = "before" if _sha256(ledger) == entry["original"]["ledger_sha256"] else (
        "after" if _sha256(ledger) == entry["transformation"]["after_ledger_sha256"] else "other")
    right = "before" if _sha256(marker) == entry["original"]["marker_sha256"] else (
        "after" if _sha256(marker) == entry["transformation"]["after_marker_sha256"] else "other")
    layout = f"{left}/{right}"
    if layout not in {"before/before", "after/before", "after/after"}:
        _migration_fail("layout_contradiction" if layout == "before/after" else "layout_invalid")
    return layout, ledger, marker, ledger_identity, marker_identity


def _migration_assert_lock_path(lock_fd: int, entry: Mapping[str, Any]) -> None:
    path = Path(entry["artifacts"]["fixed"]["lock"])
    identity = entry["identity_requirements"]
    try:
        if _path_has_symlink(path):
            raise ValueError("symlink")
        named = os.lstat(path)
        opened = os.fstat(lock_fd)
        if ((named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(named.st_mode) or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != identity["uid"] or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != identity["lock_file_mode"]):
            raise ValueError("identity")
    except (OSError, ValueError):
        _migration_fail("lock_integrity")


def _legacy_selected_copy_matches(recorded: Any, actual: Any,
                                  identity: Mapping[str, Any]) -> bool:
    return bool(
        _identity_shape(recorded) and _identity_shape(actual)
        and recorded.get("mode") == identity["canonical_file_mode"]
        and actual.get("mode") == identity["evidence_file_mode"]
        and all(recorded.get(field) == actual.get(field)
                for field in ("device", "uid", "gid", "nlink", "size", "sha256"))
    )


def _migration_checkpoint(journal: Mapping[str, Any], entry: Mapping[str, Any], lock_fd: int
                          ) -> tuple[str, bytes, bytes, dict[str, Any], dict[str, Any]]:
    """Re-derive every phase-owned named object before mutable progress."""
    _migration_assert_lock_path(lock_fd, entry)
    identity = entry["identity_requirements"]
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    try:
        auth_data, auth_identity = _read_regular_bound(
            Path(fixed["authorization"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=entry["authorization"]["sha256"])
        decision_data, decision_identity = _read_regular_bound(
            Path(fixed["decision"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=entry["decision"]["sha256"])
        auth, decision = json.loads(auth_data), json.loads(decision_data)
    except (OSError, ValueError, json.JSONDecodeError):
        _migration_fail("authority_integrity")
    if (not isinstance(auth, dict) or auth.get("authorization_id") != entry["authorization"]["authorization_id"]
            or auth.get("migration_id") != entry["migration_id"]):
        _migration_fail("authorization_binding")
    if (not isinstance(decision, dict) or decision.get("decision_id") != entry["decision"]["decision_id"]
            or decision.get("migration_id") != entry["migration_id"] or decision.get("disposition") != "approved"
            or (decision.get("judge_result") or {}).get("result_sha256")
            != entry["decision"]["judge_result_sha256"]):
        _migration_fail("decision_binding")

    layout, ledger_data, marker_data, ledger_identity, marker_identity = _migration_layout(entry)
    selected = journal.get("selected_identities") if isinstance(journal, Mapping) else None
    if not isinstance(selected, Mapping):
        _migration_fail("journal_integrity")
    for key, actual in (("authorization", auth_identity), ("decision", decision_identity)):
        if not _json_exact(selected.get(key), actual):
            _migration_fail(f"selected_identity:{key}")
    if layout.startswith("before/") and not _json_exact(selected.get("ledger"), ledger_identity):
        _migration_fail("selected_identity:ledger")
    if layout.endswith("/before") and not _json_exact(selected.get("marker"), marker_identity):
        _migration_fail("selected_identity:marker")

    phase = journal["events"][-1]["phase"]
    phase_index = entry["journal"]["phases"].index(phase)
    def reached(name: str) -> bool:
        return phase_index >= entry["journal"]["phases"].index(name)

    for key, phase_name, digest_key in (
        ("ledger", "before_ledger_snapshotted", "ledger_sha256"),
        ("marker", "before_marker_snapshotted", "marker_sha256"),
    ):
        if not reached(phase_name):
            continue
        try:
            _, snapshot_identity = _read_regular_bound(
                Path(fixed[f"before_{key}"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
                expected_sha256=entry["original"][digest_key])
        except (OSError, ValueError):
            _migration_fail(f"before_{key}_snapshot")
        if not _legacy_selected_copy_matches(selected.get(key), snapshot_identity, identity):
            _migration_fail(f"selected_identity:before_{key}")

    candidate_requirements = (
        ("ledger", "ledger_candidate_fsynced", layout == "before/before"),
        ("marker", "marker_candidate_fsynced", layout != "after/after"),
    )
    for key, phase_name, required in candidate_requirements:
        if not reached(phase_name):
            continue
        path = Path(temps[f"{key}_publication"])
        exists = path.exists() or path.is_symlink()
        if required:
            try:
                _, candidate_identity = _read_regular_bound(
                    path, uid=identity["uid"], mode=identity["canonical_file_mode"],
                    expected_sha256=entry["transformation"][f"after_{key}_sha256"])
            except (OSError, ValueError):
                _migration_fail(f"{key}_candidate_integrity")
            if not _json_exact(selected.get(f"{key}_candidate"), candidate_identity):
                _migration_fail(f"{key}_candidate_identity")
        elif exists:
            _migration_fail(f"{key}_candidate_unexpected")
    for key, side, actual in (("ledger", layout.split("/")[0], ledger_identity),
                              ("marker", layout.split("/")[1], marker_identity)):
        if side != "after":
            continue
        published_phase = "ledger_published" if key == "ledger" else "marker_published"
        binding_key = f"published_{key}" if reached(published_phase) else f"{key}_candidate"
        if not _json_exact(selected.get(binding_key), actual):
            _migration_fail(f"{key}_published_identity")
    return layout, ledger_data, marker_data, ledger_identity, marker_identity


def _migration_replace_canonical_bound(journal: Mapping[str, Any], entry: Mapping[str, Any],
                                       lock_fd: int, key: str) -> dict[str, Any]:
    """Replace one canonical file through a bound parent and prove its inode."""
    if key not in {"ledger", "marker"}:
        _migration_fail("publication_key")
    layout, *_ = _migration_checkpoint(journal, entry, lock_fd)
    expected_layout = "before/before" if key == "ledger" else "after/before"
    if layout != expected_layout:
        _migration_fail(f"{key}_publish_layout")
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    source = Path(temps[f"{key}_publication"])
    target = Path(entry[f"{key}_path"])
    if source.parent != target.parent:
        _migration_fail(f"{key}_publication_parent")
    identity = entry["identity_requirements"]
    directory_fd: int | None = None
    try:
        directory_fd = _open_directory_bound(target.parent, uid=identity["uid"])
        _, source_identity = _read_regular_at(
            directory_fd, source.name, uid=identity["uid"], mode=identity["canonical_file_mode"],
            expected_sha256=entry["transformation"][f"after_{key}_sha256"])
        _, target_identity = _read_regular_at(
            directory_fd, target.name, uid=identity["uid"], mode=identity["canonical_file_mode"],
            expected_sha256=entry["original"][f"{key}_sha256"])
        selected = journal["selected_identities"]
        if (not _json_exact(selected.get(f"{key}_candidate"), source_identity)
                or not _json_exact(selected.get(key), target_identity)):
            _migration_fail(f"{key}_publication_identity")
        _migration_assert_lock_path(lock_fd, entry)
        os.replace(source.name, target.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        _, published_identity = _read_regular_at(
            directory_fd, target.name, uid=identity["uid"], mode=identity["canonical_file_mode"],
            expected_sha256=entry["transformation"][f"after_{key}_sha256"])
        if not _json_exact(source_identity, published_identity):
            _migration_fail(f"{key}_post_publish_identity")
        try:
            os.stat(source.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _migration_fail(f"{key}_candidate_not_consumed")
        return published_identity
    except LegacyMigrationError:
        raise
    except (OSError, ValueError):
        _migration_fail(f"{key}_publication_identity")
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _migration_assert_receipt_inputs(
        journal: Mapping[str, Any], journal_data: bytes, journal_identity: Mapping[str, Any],
        receipt: Mapping[str, Any], receipt_temp_identity: Mapping[str, Any],
        entry: Mapping[str, Any], lock_fd: int) -> None:
    """Rebind every terminal dependency immediately before receipt publication."""
    identity = entry["identity_requirements"]
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    try:
        current_journal_data, current_journal_identity = _read_regular_bound(
            Path(fixed["journal"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=_sha256(journal_data))
        current_journal = json.loads(current_journal_data)
        receipt_temp_data, current_receipt_temp_identity = _read_regular_bound(
            Path(temps["receipt"]), uid=identity["uid"], mode=identity["evidence_file_mode"])
    except (OSError, ValueError, json.JSONDecodeError):
        _migration_fail("receipt_admission")
    if (current_journal_data != journal_data or not _json_exact(current_journal, journal)
            or not _json_exact(current_journal_identity, journal_identity)
            or not _json_exact(current_receipt_temp_identity, receipt_temp_identity)
            or _legacy_journal_reasons(current_journal, entry)
            or _legacy_receipt_reasons(receipt, current_journal_data, current_journal, entry)
            or receipt_temp_data != _migration_journal_bytes(receipt)):
        _migration_fail("receipt_admission")
    layout, _, _, published_ledger, published_marker = _migration_checkpoint(
        current_journal, entry, lock_fd)
    if (layout != "after/after"
            or not _json_exact(receipt.get("published_ledger_identity"), published_ledger)
            or not _json_exact(receipt.get("published_marker_identity"), published_marker)):
        _migration_fail("receipt_admission")
    _migration_assert_lock_path(lock_fd, entry)


def _migration_validate_terminal_receipt(
        entry: Mapping[str, Any], lock_fd: int, expected_receipt_data: bytes | None = None,
        expected_journal_identity: Mapping[str, Any] | None = None,
        expected_receipt_identity: Mapping[str, Any] | None = None
        ) -> dict[str, Any]:
    """Validate the complete terminal state immediately before a success return."""
    identity = entry["identity_requirements"]
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    journal, journal_data = _migration_load_journal(entry)
    if expected_journal_identity is not None:
        try:
            _, current_journal_identity = _read_regular_bound(
                Path(fixed["journal"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
                expected_sha256=_sha256(journal_data))
        except (OSError, ValueError):
            _migration_fail("journal_integrity")
        if not _json_exact(current_journal_identity, expected_journal_identity):
            _migration_fail("journal_integrity")
    layout, _, _, published_ledger, published_marker = _migration_checkpoint(
        journal, entry, lock_fd)
    try:
        receipt_data, receipt_identity = _read_regular_bound(
            Path(fixed["receipt"]), uid=identity["uid"], mode=identity["evidence_file_mode"])
        receipt = json.loads(receipt_data)
    except (OSError, ValueError, json.JSONDecodeError):
        _migration_fail("receipt_integrity")
    if (Path(temps["receipt"]).exists() or Path(temps["receipt"]).is_symlink()
            or (expected_receipt_data is not None and receipt_data != expected_receipt_data)
            or (expected_receipt_identity is not None
                and not _json_exact(receipt_identity, expected_receipt_identity))
            or _legacy_receipt_reasons(receipt, journal_data, journal, entry)
            or layout != "after/after"
            or not _json_exact(receipt.get("published_ledger_identity"), published_ledger)
            or not _json_exact(receipt.get("published_marker_identity"), published_marker)):
        _migration_fail("receipt_integrity")
    # Re-read all terminal dependencies after the receipt itself, then prove
    # the named receipt is still the same single-link object just inspected.
    checked_layout, _, _, checked_ledger, checked_marker = _migration_checkpoint(
        journal, entry, lock_fd)
    try:
        _, checked_receipt_identity = _read_regular_bound(
            Path(fixed["receipt"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
            expected_sha256=_sha256(receipt_data))
    except (OSError, ValueError):
        _migration_fail("receipt_integrity")
    if (checked_layout != "after/after"
            or not _json_exact(checked_ledger, published_ledger)
            or not _json_exact(checked_marker, published_marker)
            or not _json_exact(checked_receipt_identity, receipt_identity)):
        _migration_fail("terminal_layout")
    _migration_assert_lock_path(lock_fd, entry)
    return receipt


def apply_legacy_v6_0_audit_migration(
        migration_id: str = LEGACY_V6_0_AUDIT_MIGRATION_ID, *,
        crash_hook: Callable[[str], None] | None = None) -> Mapping[str, Any]:
    """Explicitly apply or recover the one catalogued descriptor-only migration.

    The function never creates authority.  Exact authorization and decision
    files must already exist, be restrictive regular files, and hash to the
    release catalogue before the durable journal can be selected.
    """
    entry = LEGACY_V6_0_AUDIT_CATALOGUE.get(migration_id)
    if not isinstance(entry, Mapping) or migration_id != LEGACY_V6_0_AUDIT_MIGRATION_ID:
        _migration_fail("catalogue_admission")
    catalogue_data = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")
    if _sha256(catalogue_data) != LEGACY_V6_0_AUDIT_CATALOGUE_SHA256:
        _migration_fail("catalogue_digest")
    descriptor = LEGACY_V6_0_AUDIT_DESCRIPTOR
    if _sha256(_legacy_descriptor_bytes(descriptor)) != entry["descriptor"]["sha256"]:
        _migration_fail("descriptor_digest")
    identity = entry["identity_requirements"]
    migration_dir = Path(entry["migration_dir"])
    fixed, temps = entry["artifacts"]["fixed"], entry["artifacts"]["temporaries"]
    try:
        directory_info = os.lstat(migration_dir)
        if (_path_has_symlink(migration_dir) or not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != identity["uid"]
                or stat.S_IMODE(directory_info.st_mode) != identity["evidence_directory_mode"]):
            _migration_fail("migration_directory_identity")
        auth_data, auth_identity = _read_regular_bound(Path(fixed["authorization"]), uid=identity["uid"],
                                                        mode=identity["evidence_file_mode"],
                                                        expected_sha256=entry["authorization"]["sha256"])
        decision_data, decision_identity = _read_regular_bound(Path(fixed["decision"]), uid=identity["uid"],
                                                                mode=identity["evidence_file_mode"],
                                                                expected_sha256=entry["decision"]["sha256"])
        auth, decision = json.loads(auth_data), json.loads(decision_data)
    except LegacyMigrationError:
        raise
    except (OSError, ValueError, json.JSONDecodeError):
        _migration_fail("authority_integrity")
    if (not isinstance(auth, dict) or auth.get("authorization_id") != entry["authorization"]["authorization_id"]
            or auth.get("migration_id") != migration_id):
        _migration_fail("authorization_binding")
    if (not isinstance(decision, dict) or decision.get("decision_id") != entry["decision"]["decision_id"]
            or decision.get("migration_id") != migration_id or decision.get("disposition") != "approved"
            or (decision.get("judge_result") or {}).get("result_sha256") != entry["decision"]["judge_result_sha256"]):
        _migration_fail("decision_binding")

    receipt_exists = Path(fixed["receipt"]).exists() or Path(fixed["receipt"]).is_symlink()
    lock_existed = Path(fixed["lock"]).exists() or Path(fixed["lock"]).is_symlink()
    lock_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | (0 if receipt_exists else os.O_CREAT)
    try:
        _migration_hit(crash_hook, "before_lock_open")
        lock_fd = os.open(fixed["lock"], lock_flags, identity["lock_file_mode"])
        _migration_hit(crash_hook, "after_lock_open")
    except OSError:
        _migration_fail("lock_integrity")
    try:
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != identity["uid"] or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != identity["lock_file_mode"]):
            _migration_fail("lock_integrity")
        if not lock_existed:
            _migration_fsync_dir(migration_dir, crash_hook, "lock_create")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _migration_fail("lock_busy")
        _migration_assert_lock_path(lock_fd, entry)
        if receipt_exists:
            journal, journal_data = _migration_load_journal(entry)
            try:
                rebound_journal_data, journal_identity = _read_regular_bound(
                    Path(fixed["journal"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
                    expected_sha256=_sha256(journal_data))
            except (OSError, ValueError):
                _migration_fail("journal_integrity")
            if rebound_journal_data != journal_data:
                _migration_fail("journal_integrity")
            layout, _, _, published_ledger, published_marker = _migration_checkpoint(
                journal, entry, lock_fd)
            try:
                receipt_data, initial_receipt_identity, linked_pair = _migration_read_exclusive_target(
                    Path(temps["receipt"]), Path(fixed["receipt"]), entry,
                    identity["evidence_file_mode"])
                receipt = json.loads(receipt_data)
            except (OSError, ValueError, json.JSONDecodeError):
                _migration_fail("receipt_integrity")
            if _legacy_receipt_reasons(receipt, journal_data, journal, entry):
                _migration_fail("receipt_integrity")
            if (layout != "after/after"
                    or not _json_exact(receipt.get("published_ledger_identity"), published_ledger)
                    or not _json_exact(receipt.get("published_marker_identity"), published_marker)):
                _migration_fail("terminal_layout")
            receipt_identity = initial_receipt_identity
            if linked_pair:
                _migration_hit(crash_hook, "before_receipt_temp_unlink")
                checked_receipt, checked_identity, checked_pair = _migration_read_exclusive_target(
                    Path(temps["receipt"]), Path(fixed["receipt"]), entry,
                    identity["evidence_file_mode"])
                if (not checked_pair or checked_receipt != receipt_data
                        or not _json_exact(checked_identity, initial_receipt_identity)):
                    _migration_fail("receipt_integrity")
                os.unlink(temps["receipt"])
                _migration_hit(crash_hook, "after_receipt_temp_unlink")
                _migration_fsync_dir(Path(fixed["receipt"]).parent, crash_hook, "receipt_recovered")
                try:
                    recovered_receipt, receipt_identity = _read_regular_bound(
                        Path(fixed["receipt"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
                        expected_sha256=_sha256(receipt_data))
                except (OSError, ValueError):
                    _migration_fail("receipt_integrity")
                continuity_keys = ("device", "inode", "uid", "gid", "mode", "size", "sha256")
                if (recovered_receipt != receipt_data or initial_receipt_identity.get("nlink") != 2
                        or receipt_identity.get("nlink") != 1
                        or any(initial_receipt_identity.get(key) != receipt_identity.get(key)
                               for key in continuity_keys)):
                    _migration_fail("receipt_integrity")
            _migration_hit(crash_hook, "after_receipt_replay_rebind")
            _migration_validate_terminal_receipt(
                entry, lock_fd, receipt_data, journal_identity, receipt_identity)
            return {"status": "complete", "replay": True, "migration_id": migration_id}

        layout, ledger_data, marker_data, ledger_identity, marker_identity = _migration_layout(entry)
        journal_path = Path(fixed["journal"])
        if journal_path.exists() or journal_path.is_symlink():
            journal, _ = _migration_load_journal(entry)
        else:
            if layout != "before/before":
                _migration_fail("unauthenticated_mixed_state")
            forbidden = [fixed["before_ledger"], fixed["before_marker"], fixed["receipt"],
                         *temps.values()]
            if any(Path(path).exists() or Path(path).is_symlink() for path in forbidden):
                _migration_fail("artifact_collision")
            selected = {"ledger": ledger_identity, "marker": marker_identity,
                        "authorization": auth_identity, "decision": decision_identity}
            journal = _migration_initial_journal(entry, selected)
            _migration_advance(journal, "selected", entry, crash_hook)
        layout, ledger_data, marker_data, ledger_identity, marker_identity = _migration_checkpoint(
            journal, entry, lock_fd)
        phase = journal["events"][-1]["phase"]
        phase_index = entry["journal"]["phases"].index(phase)

        def reached(name: str) -> bool:
            return phase_index >= entry["journal"]["phases"].index(name)

        before_ledger_data = ledger_data if layout == "before/before" else None
        before_marker_data = marker_data if layout in {"before/before", "after/before"} else None
        if reached("before_ledger_snapshotted"):
            try:
                before_ledger_data, _ = _read_regular_bound(Path(fixed["before_ledger"]), uid=identity["uid"],
                                                             mode=identity["evidence_file_mode"],
                                                             expected_sha256=entry["original"]["ledger_sha256"])
            except (OSError, ValueError):
                _migration_fail("before_ledger_snapshot")
        else:
            if not reached("before_ledger_snapshot_intent"):
                _migration_advance(journal, "before_ledger_snapshot_intent", entry, crash_hook); phase_index += 1
            if before_ledger_data is None:
                _migration_fail("before_ledger_unavailable")
            temp = Path(temps["before_ledger"]); target = Path(fixed["before_ledger"])
            _migration_publish_bytes(temp, target, entry, crash_hook, "before_ledger",
                                     before_ledger_data, identity["evidence_file_mode"])
            _migration_advance(journal, "before_ledger_snapshotted", entry, crash_hook); phase_index += 1
        if reached("before_marker_snapshotted"):
            try:
                before_marker_data, _ = _read_regular_bound(Path(fixed["before_marker"]), uid=identity["uid"],
                                                             mode=identity["evidence_file_mode"],
                                                             expected_sha256=entry["original"]["marker_sha256"])
            except (OSError, ValueError):
                _migration_fail("before_marker_snapshot")
        else:
            if not reached("before_marker_snapshot_intent"):
                _migration_advance(journal, "before_marker_snapshot_intent", entry, crash_hook); phase_index += 1
            if before_marker_data is None:
                _migration_fail("before_marker_unavailable")
            temp = Path(temps["before_marker"]); target = Path(fixed["before_marker"])
            _migration_publish_bytes(temp, target, entry, crash_hook, "before_marker",
                                     before_marker_data, identity["evidence_file_mode"])
            _migration_advance(journal, "before_marker_snapshotted", entry, crash_hook); phase_index += 1

        assert before_ledger_data is not None and before_marker_data is not None
        ledger_candidate = _legacy_candidate_bytes(before_ledger_data, descriptor)
        marker_candidate = _legacy_candidate_bytes(before_marker_data, descriptor)
        if (_sha256(ledger_candidate) != entry["transformation"]["after_ledger_sha256"]
                or _sha256(marker_candidate) != entry["transformation"]["after_marker_sha256"]):
            _migration_fail("candidate_digest")
        if not reached("ledger_candidate_fsynced"):
            if not reached("ledger_candidate_intent"):
                _migration_advance(journal, "ledger_candidate_intent", entry, crash_hook); phase_index += 1
            ledger_candidate_path = Path(temps["ledger_publication"])
            _migration_temp_bytes(ledger_candidate_path, ledger_candidate,
                                  identity["canonical_file_mode"], entry, crash_hook, "ledger_candidate")
            try:
                _, candidate_identity = _read_regular_bound(
                    ledger_candidate_path, uid=identity["uid"], mode=identity["canonical_file_mode"],
                    expected_sha256=entry["transformation"]["after_ledger_sha256"])
            except (OSError, ValueError):
                _migration_fail("ledger_candidate_integrity")
            journal["selected_identities"]["ledger_candidate"] = candidate_identity
            _migration_advance(journal, "ledger_candidate_fsynced", entry, crash_hook); phase_index += 1
        if not reached("marker_candidate_fsynced"):
            if not reached("marker_candidate_intent"):
                _migration_advance(journal, "marker_candidate_intent", entry, crash_hook); phase_index += 1
            marker_candidate_path = Path(temps["marker_publication"])
            _migration_temp_bytes(marker_candidate_path, marker_candidate,
                                  identity["canonical_file_mode"], entry, crash_hook, "marker_candidate")
            try:
                _, candidate_identity = _read_regular_bound(
                    marker_candidate_path, uid=identity["uid"], mode=identity["canonical_file_mode"],
                    expected_sha256=entry["transformation"]["after_marker_sha256"])
            except (OSError, ValueError):
                _migration_fail("marker_candidate_integrity")
            journal["selected_identities"]["marker_candidate"] = candidate_identity
            _migration_advance(journal, "marker_candidate_fsynced", entry, crash_hook); phase_index += 1
        if not reached("publication_intent"):
            _migration_advance(journal, "publication_intent", entry, crash_hook); phase_index += 1
        layout, *_ = _migration_layout(entry)
        if not reached("ledger_published"):
            if layout == "before/before":
                _migration_hit(crash_hook, "before_ledger_publish_rename")
                checked_layout, *_ = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "before/before":
                    _migration_fail("ledger_publish_layout")
                _migration_hit(crash_hook, "after_ledger_publish_checkpoint")
                published_identity = _migration_replace_canonical_bound(journal, entry, lock_fd, "ledger")
                _migration_hit(crash_hook, "after_ledger_publish_rename")
                checked_layout, _, _, observed_identity, _ = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/before" or not _json_exact(observed_identity, published_identity):
                    _migration_fail("ledger_post_publish_identity")
            elif layout != "after/before":
                _migration_fail("ledger_publish_layout")
            else:
                checked_layout, _, _, published_identity, _ = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/before":
                    _migration_fail("ledger_publish_layout")
                _migration_hit(crash_hook, "after_ledger_recovery_checkpoint")
                checked_layout, _, _, published_identity, _ = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/before":
                    _migration_fail("ledger_publish_layout")
            journal["selected_identities"]["published_ledger"] = published_identity
            # Recovery may observe the replacement before the directory entry
            # was made durable.  Repeat the parent-directory barrier before
            # recording ledger_published, whether this invocation renamed the
            # canonical ledger or merely recovered its after/before layout.
            _migration_fsync_dir(Path(entry["ledger_path"]).parent, crash_hook, "ledger_publish")
            _migration_advance(journal, "ledger_published", entry, crash_hook); phase_index += 1
        layout, *_ = _migration_layout(entry)
        if not reached("marker_published"):
            if layout == "after/before":
                _migration_hit(crash_hook, "before_marker_publish_rename")
                checked_layout, *_ = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/before":
                    _migration_fail("marker_publish_layout")
                _migration_hit(crash_hook, "after_marker_publish_checkpoint")
                published_identity = _migration_replace_canonical_bound(journal, entry, lock_fd, "marker")
                _migration_hit(crash_hook, "after_marker_publish_rename")
                checked_layout, _, _, _, observed_identity = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/after" or not _json_exact(observed_identity, published_identity):
                    _migration_fail("marker_post_publish_identity")
            elif layout != "after/after":
                _migration_fail("marker_publish_layout")
            else:
                checked_layout, _, _, _, published_identity = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/after":
                    _migration_fail("marker_publish_layout")
                _migration_hit(crash_hook, "after_marker_recovery_checkpoint")
                checked_layout, _, _, _, published_identity = _migration_checkpoint(journal, entry, lock_fd)
                if checked_layout != "after/after":
                    _migration_fail("marker_publish_layout")
            journal["selected_identities"]["published_marker"] = published_identity
            # As above, the after/after recovery observation does not prove
            # that the marker rename survived a power loss.  Persist the
            # canonical directory before advancing the durable journal.
            _migration_fsync_dir(Path(entry["marker_path"]).parent, crash_hook, "marker_publish")
            _migration_advance(journal, "marker_published", entry, crash_hook); phase_index += 1
        layout, _, _, published_ledger, published_marker = _migration_layout(entry)
        if layout != "after/after":
            _migration_fail("pair_layout")
        if not reached("pair_verified"):
            _migration_advance(journal, "pair_verified", entry, crash_hook); phase_index += 1
        if not reached("receipt_intent"):
            _migration_advance(journal, "receipt_intent", entry, crash_hook); phase_index += 1
        journal, journal_data = _migration_load_journal(entry)
        try:
            rebound_journal_data, journal_identity = _read_regular_bound(
                Path(fixed["journal"]), uid=identity["uid"], mode=identity["evidence_file_mode"],
                expected_sha256=_sha256(journal_data))
        except (OSError, ValueError):
            _migration_fail("journal_integrity")
        if rebound_journal_data != journal_data:
            _migration_fail("journal_integrity")
        layout, _, _, published_ledger, published_marker = _migration_checkpoint(journal, entry, lock_fd)
        if layout != "after/after":
            _migration_fail("pair_layout")
        receipt = {
            "schema_version": "mas1-legacy-v6.0-migration-receipt.v1", "record_type": "migration-receipt",
            "receipt_id": entry["receipt"]["receipt_id"], "migration_id": entry["migration_id"],
            "mode": entry["mode"], "catalogue_entry_id": entry["catalogue_entry_id"],
            "task_instance_id": entry["task_instance_id"], "workspace": entry["workspace"],
            "ledger_path": entry["ledger_path"], "marker_path": entry["marker_path"],
            "migration_dir": entry["migration_dir"], "authorization_id": entry["authorization"]["authorization_id"],
            "authorization_sha256": entry["authorization"]["sha256"], "decision_id": entry["decision"]["decision_id"],
            "decision_sha256": entry["decision"]["sha256"], "descriptor_sha256": entry["descriptor"]["sha256"],
            "before_ledger_sha256": entry["original"]["ledger_sha256"],
            "before_marker_sha256": entry["original"]["marker_sha256"],
            "after_ledger_sha256": entry["transformation"]["after_ledger_sha256"],
            "after_marker_sha256": entry["transformation"]["after_marker_sha256"],
            "journal_id": entry["journal"]["journal_id"], "journal_path": entry["journal"]["path"],
            "journal_sha256": _sha256(journal_data), "journal_terminal_phase": "receipt_intent",
            "threshold_evidence": deepcopy(entry["threshold_evidence"]),
            "published_ledger_identity": published_ledger, "published_marker_identity": published_marker,
            "recorded_at": _migration_now(),
            "recorded_at_semantics":
                "Administrative terminal receipt time only; not protocol adoption, threshold discovery, authorization, or adjudication time.",
            "status": "complete",
            "evidence_refs": sorted([
                f"authorization-sha256:{entry['authorization']['sha256']}",
                f"decision-sha256:{entry['decision']['sha256']}",
                f"journal-sha256:{_sha256(journal_data)}",
            ]),
        }
        receipt_bytes = _migration_journal_bytes(receipt)
        receipt_temp = Path(temps["receipt"])
        receipt_target = Path(fixed["receipt"])
        receipt_temp_identity = _migration_temp_bytes(
            receipt_temp, receipt_bytes, identity["evidence_file_mode"], entry, crash_hook, "receipt")
        try:
            staged_receipt_data, _ = _read_regular_bound(
                receipt_temp, uid=identity["uid"], mode=identity["evidence_file_mode"],
                expected_sha256=_sha256(receipt_bytes))
        except (OSError, ValueError):
            _migration_fail("receipt_admission")
        if staged_receipt_data != receipt_bytes:
            _migration_fail("receipt_admission")
        _migration_publish_new(
            receipt_temp, receipt_target, entry, crash_hook, "receipt", receipt_bytes,
            identity["evidence_file_mode"],
            lambda: _migration_assert_receipt_inputs(
                journal, journal_data, journal_identity, receipt, receipt_temp_identity, entry, lock_fd))
        _migration_validate_terminal_receipt(
            entry, lock_fd, receipt_bytes, journal_identity, receipt_temp_identity)
        return {"status": "complete", "replay": False, "migration_id": migration_id}
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _canonical_path_reasons(ledger: Any, loaded_path: Any, marker: Any, cutover: Any,
                            target: Any = None, *, legacy_compatibility: bool = False) -> set[str]:
    reasons: set[str] = set()
    if not isinstance(ledger, dict):
        return {"ledger_not_object"}
    task = ledger.get("task")
    if not isinstance(task, dict):
        return {"task_invalid"}
    declared = task.get("ledger_path")
    if loaded_path is not None:
        try:
            loaded = Path(loaded_path)
            if not loaded.is_absolute() or str(loaded) != declared:
                reasons.add("loaded_path_mismatch")
            if any(part == ".." for part in loaded.parts):
                reasons.add("loaded_path_traversal")
            # This check is intentionally lexical when the file is not yet on
            # disk (fixtures); production paths additionally reject symlinks.
            if loaded.exists() and any(piece.is_symlink() for piece in (loaded, *loaded.parents)):
                reasons.add("loaded_path_symlink")
        except (OSError, TypeError, ValueError):
            reasons.add("loaded_path_invalid")
    ledger_cutover = ledger.get("cutover") if isinstance(ledger.get("cutover"), dict) else {}
    boundary = ledger_cutover.get("post_cutover_boundary")
    adopted_at = ledger_cutover.get("protocol_adopted_at")
    adoption_refs = ledger_cutover.get("protocol_adoption_evidence_refs")
    if not legacy_compatibility:
        if parse_rfc3339(boundary) is None:
            reasons.add("cutover_boundary_invalid")
        if parse_rfc3339(adopted_at) is None:
            reasons.add("protocol_adoption_invalid")
        if not _sorted_unique_nonempty(adoption_refs):
            reasons.add("protocol_adoption_evidence_invalid")
        if parse_rfc3339(boundary) and parse_rfc3339(adopted_at) and parse_rfc3339(adopted_at) < parse_rfc3339(boundary):
            reasons.add("protocol_adoption_before_dispatch")
    if marker is not None:
        if not isinstance(marker, dict):
            reasons.add("marker_invalid")
        else:
            for left, right in (("task_instance_id", task.get("task_instance_id")),
                                ("ledger_path", declared),
                                ("marker_path", task.get("marker_path"))):
                if marker.get(left) != right:
                    reasons.add(f"marker_{left}_mismatch")
            if not legacy_compatibility:
                marker_boundary = marker.get("post_cutover_boundary")
                if parse_rfc3339(marker_boundary) is None:
                    reasons.add("marker_boundary_invalid")
                # Boundary strings are contract identifiers, not merely equivalent
                # instants.  A canonical ledger/marker pair therefore preserves the
                # exact RFC3339 spelling; parsing is used only for chronology.
                if marker_boundary != boundary:
                    reasons.add("marker_boundary_mismatch")
                if marker.get("protocol_adopted_at") != adopted_at:
                    reasons.add("marker_protocol_adoption_mismatch")
                if marker.get("protocol_adoption_evidence_refs") != adoption_refs:
                    reasons.add("marker_protocol_adoption_evidence_mismatch")
    if legacy_compatibility and cutover is not None:
        reasons.add("compat:master_cutover_forbidden")
    elif cutover is not None:
        if not isinstance(cutover, dict):
            reasons.add("cutover_invalid")
        else:
            expected_id = cutover.get("cutoverId")
            expected_sha = (cutover.get("fingerprints") or {}).get("prompt", {}).get("sha256")
            expected_boundary = cutover.get("postCutoverBoundary")
            if expected_id and ledger_cutover.get("cutover_id") != expected_id:
                reasons.add("cutover_id_mismatch")
            if expected_sha and ledger_cutover.get("prompt_sha256") != expected_sha:
                reasons.add("cutover_prompt_sha_mismatch")
            if parse_rfc3339(expected_boundary) is None:
                reasons.add("master_boundary_invalid")
            elif boundary != expected_boundary:
                reasons.add("cutover_boundary_mismatch")
    if legacy_compatibility and target is not None:
        reasons.add("compat:target_adoption_forbidden")
    elif target is not None:
        if not isinstance(target, dict):
            reasons.add("target_invalid")
        else:
            # The target transition itself is canonical core state, not an
            # analyzer-local convention.  Identity/path checks belong to the
            # frozen population loader, while this binding check also supports
            # direct validator callers with a minimal target record.
            reasons.update(_target_dispatch_reasons(target, (cutover or {}).get("postCutoverBoundary")))
            status = target.get("protocolAdoptionStatus")
            if status != "adopted":
                reasons.add("target_protocol_not_adopted")
            else:
                if target.get("protocolAdoptedAt") != adopted_at:
                    reasons.add("target_protocol_adoption_mismatch")
                if target.get("protocolAdoptionEvidenceRefs") != adoption_refs:
                    reasons.add("target_protocol_adoption_evidence_mismatch")
                sent = parse_rfc3339(target.get("messageSentAtUtc"))
                adoption = parse_rfc3339(adopted_at)
                if sent is None or adoption is None or adoption < sent:
                    reasons.add("target_protocol_adoption_before_dispatch")
    return reasons


def _activity_bucket(activity: Mapping[str, Any], dispatch: datetime | None,
                     adoption: datetime | None) -> str:
    if dispatch is None or adoption is None:
        return "unknown-chronology"
    if activity.get("status") != "completed":
        return "incomplete"
    started, completed = parse_rfc3339(activity.get("started_at")), parse_rfc3339(activity.get("completed_at"))
    if started is None or completed is None or completed < started:
        return "unknown-chronology"
    if completed <= dispatch:
        return "pre-dispatch"
    if started >= adoption:
        return "v6"
    if started < adoption < completed:
        return "spanning-adoption"
    if started < dispatch < completed <= adoption:
        return "spanning-dispatch"
    # dispatch <= start and completed <= adoption, including equality at both
    # boundaries, is wholly exposed before the protocol was adopted.
    if started >= dispatch and completed <= adoption:
        return "transition-pre-adoption"
    return "unknown-chronology"


def _derive_facts(ledger: Any) -> dict[str, Any]:
    """Build all cross-record indexes once, even for invalid ledgers.

    Consumers use these facts only after a clean validation result.  Defensively
    handling malformed rows makes the validator fail closed rather than crash.
    """
    if not isinstance(ledger, dict):
        return {"indexes": {}, "roots": [], "escape_incidents": [], "activities": []}
    # Facts are a validation-time snapshot.  Consumers must not be able to
    # change reported metrics by mutating the caller's raw ledger afterwards.
    ledger = deepcopy(ledger)
    collections = ("roots", "observations", "review_bases", "cycles", "test_evidence", "repair_attempts", "strategies", "activities", "events")
    rows = {name: [item for item in ledger.get(name, []) if isinstance(item, dict)] if isinstance(ledger.get(name, []), list) else [] for name in collections}
    id_fields = {"roots": "root_cause_id", "observations": "observation_id", "review_bases": "review_basis_id", "cycles": "cycle_id", "test_evidence": "test_evidence_id", "repair_attempts": "repair_attempt_id", "strategies": "strategy_id", "activities": "activity_id", "events": "event_id"}
    indexes = {name: {str(row.get(id_fields[name])): row for row in values if row.get(id_fields[name]) is not None} for name, values in rows.items()}
    cutover = ledger.get("cutover") if isinstance(ledger.get("cutover"), dict) else {}
    boundary = parse_rfc3339(cutover.get("post_cutover_boundary"))
    adoption = parse_rfc3339(cutover.get("protocol_adopted_at"))
    activities = []
    for row in rows["activities"]:
        record = dict(row)
        record["chronology_bucket"] = _activity_bucket(row, boundary, adoption)
        activities.append(record)
    observation_by_id = indexes["observations"]
    incident_seen: set[tuple[Any, ...]] = set()
    incidents = []
    for event in sorted(rows["events"], key=lambda value: (value.get("sequence", 0), str(value.get("event_id", "")))):
        if event.get("type") != "escape-confirmed":
            continue
        key_data = event.get("escape_key") if isinstance(event.get("escape_key"), dict) else {}
        key = tuple(key_data.get(name) for name in ("root_cause_id", "repair_attempt_id", "review_basis_id", "cycle_id"))
        observation = observation_by_id.get(str(event.get("observation_id")), {})
        incident = {
            "event": event, "event_id": event.get("event_id"), "key": key,
            "root_cause_id": event.get("root_cause_id"), "repair_attempt_id": event.get("repair_attempt_id"),
            "review_basis_id": event.get("review_basis_id"), "cycle_id": event.get("cycle_id"),
            "observation": observation, "unique": key not in incident_seen,
            # This legacy field remains available for lifetime gates only.  It
            # is never evidence that an activity or incident is v6-exposed.
            "post_cutover": not bool(observation.get("pre_cutover")),
        }
        incident_seen.add(key)
        incidents.append(incident)
    # Observation eligibility is derived from actual recorded activities and
    # timestamps, never from the user-controlled pre_cutover marker.  A
    # discovery must resolve to at least one completed wholly-v6 activity.
    activity_by_id = {str(row.get("activity_id")): row for row in activities}
    observation_v6: dict[str, bool] = {}
    observation_v6_exclusion_reasons: dict[str, str] = {}
    for observation in rows["observations"]:
        observation_id = str(observation.get("observation_id"))
        observed = parse_rfc3339(observation.get("observed_at"))
        discovering = observation.get("discovering_activity_ids")
        if adoption is None or observed is None or observed < adoption:
            observation_v6[observation_id] = False
            observation_v6_exclusion_reasons[observation_id] = "observation_timestamp_not_post_adoption"
        elif not isinstance(discovering, list) or not discovering:
            observation_v6[observation_id] = False
            observation_v6_exclusion_reasons[observation_id] = "discovering_activity_missing"
        elif not all(activity_by_id.get(str(activity_id), {}).get("chronology_bucket") == "v6"
                     for activity_id in discovering):
            observation_v6[observation_id] = False
            observation_v6_exclusion_reasons[observation_id] = "discovering_activity_not_wholly_v6"
        else:
            observation_v6[observation_id] = True

    repair_induced_attempt_ids = {
        str(incident["repair_attempt_id"]) for incident in incidents
        if incident["unique"] and incident["post_cutover"]
        and incident["observation"].get("root_relationship") == "repair-induced"
        and incident["repair_attempt_id"] is not None
    }
    events_by_root: dict[str, list[dict[str, Any]]] = {}
    for event in rows["events"]:
        root = event.get("root_cause_id")
        if root is not None:
            events_by_root.setdefault(str(root), []).append(event)
    epochs: dict[str, list[dict[str, Any]]] = {}
    for root_id, events in events_by_root.items():
        epoch, out = 0, []
        for event in sorted(events, key=lambda value: (value.get("sequence", 0), str(value.get("event_id", "")))):
            if event.get("type") == "basis-invalidated":
                epoch += 1
            out.append({"event_id": event.get("event_id"), "type": event.get("type"), "epoch": epoch})
        epochs[root_id] = out
    attempts_by_root: dict[str, list[dict[str, Any]]] = {}
    for attempt in rows["repair_attempts"]:
        if attempt.get("root_cause_id") is not None:
            attempts_by_root.setdefault(str(attempt["root_cause_id"]), []).append(attempt)
    activity_index = indexes["activities"]
    cycle_index = indexes["cycles"]
    eligible_attempt_ids: set[str] = set()
    v6_eligible_attempt_ids: set[str] = set()
    cycle_v6: dict[str, bool] = {}
    for cycle_id, cycle in cycle_index.items():
        cycle_started, cycle_completed = parse_rfc3339(cycle.get("started_at")), parse_rfc3339(cycle.get("completed_at"))
        ids = cycle.get("activity_ids") if isinstance(cycle.get("activity_ids"), list) else []
        cycle_v6[cycle_id] = bool(cycle.get("complete") and cycle_started and cycle_completed
                                  and adoption and cycle_started >= adoption
                                  and all(activity_by_id.get(str(item), {}).get("chronology_bucket") == "v6" for item in ids))
    for attempt in rows["repair_attempts"]:
        cycle = cycle_index.get(str(attempt.get("verifying_cycle_id")))
        root_id = attempt.get("root_cause_id")
        repair_done = parse_rfc3339(attempt.get("completed_at"))
        cycle_started = parse_rfc3339((cycle or {}).get("started_at"))
        cycle_completed = parse_rfc3339((cycle or {}).get("completed_at"))
        if (not cycle or not cycle.get("complete") or cycle.get("kind") != "post-repair"
                or cycle.get("review_basis_id") != attempt.get("review_basis_id")
                or repair_done is None or cycle_started is None or cycle_completed is None
                or cycle_started <= repair_done or cycle_completed <= repair_done):
            continue
        for activity_id in cycle.get("activity_ids", []) if isinstance(cycle.get("activity_ids"), list) else []:
            activity = activity_index.get(str(activity_id), {})
            if (activity.get("status") == "completed" and activity.get("type") in {"review", "post-repair-review"}
                    and activity.get("cycle_id", cycle.get("cycle_id")) == cycle.get("cycle_id")
                    and activity.get("review_basis_id", cycle.get("review_basis_id")) == cycle.get("review_basis_id")
                    and root_id in (activity.get("root_cause_ids") or [])):
                eligible_attempt_ids.add(str(attempt.get("repair_attempt_id")))
                implementation_ids = attempt.get("implementation_activity_ids") if isinstance(attempt.get("implementation_activity_ids"), list) else []
                attempt_started = parse_rfc3339(attempt.get("started_at"))
                attempt_completed = parse_rfc3339(attempt.get("completed_at"))
                if (attempt_started and attempt_completed and adoption
                        and attempt_started >= adoption and attempt_completed >= adoption
                        and cycle_v6.get(str(attempt.get("verifying_cycle_id")), False)
                        and all(activity_by_id.get(str(item), {}).get("chronology_bucket") == "v6" for item in implementation_ids)):
                    v6_eligible_attempt_ids.add(str(attempt.get("repair_attempt_id")))
                break
    def _incident_v6(incident: Mapping[str, Any]) -> bool:
        event, observation = incident["event"], incident["observation"]
        attempt_id = str(incident.get("repair_attempt_id"))
        cycle_id = str(incident.get("cycle_id"))
        return bool(
            incident.get("unique")
            and attempt_id in v6_eligible_attempt_ids
            and cycle_v6.get(cycle_id, False)
            and observation_v6.get(str(observation.get("observation_id")), False)
            and parse_rfc3339(event.get("at")) and parse_rfc3339(event.get("at")) >= adoption
        )
    v6_incidents = [incident for incident in incidents if _incident_v6(incident)]
    v6_escape_discovery_exclusions = [
        incident for incident in incidents
        if incident["unique"] and adoption is not None
        and parse_rfc3339(incident["event"].get("at")) is not None
        and parse_rfc3339(incident["event"].get("at")) >= adoption
        and observation_v6_exclusion_reasons.get(str(incident["observation"].get("observation_id")))
        == "discovering_activity_not_wholly_v6"
    ]
    v6_repair_induced_attempt_ids = {
        str(incident["repair_attempt_id"]) for incident in v6_incidents
        if incident["observation"].get("root_relationship") == "repair-induced"
    }
    v6_initial_root_ids: set[str] = set()
    for root in rows["roots"]:
        first = next((obs for obs in rows["observations"] if obs.get("observation_id") == root.get("first_observation_id")), None)
        if first and observation_v6.get(str(first.get("observation_id")), False):
            v6_initial_root_ids.add(str(root.get("root_cause_id")))
    v6_closed_root_ids: set[str] = set()
    for root in rows["roots"]:
        gate = root.get("closure_gate") if isinstance(root.get("closure_gate"), dict) else {}
        first = next((obs for obs in rows["observations"] if obs.get("observation_id") == root.get("first_observation_id")), None)
        gate_activity_ids = [gate.get(field) for field in ("post_repair_review_activity_id", "following_unchanged_activity_id")]
        gate_cycle_ids = [gate.get(field) for field in ("post_repair_review_cycle_id", "following_unchanged_cycle_id")]
        if (root.get("state") == "closed_verified" and adoption and first
                and str(root.get("root_cause_id")) in v6_initial_root_ids
                and all(activity_by_id.get(str(item), {}).get("chronology_bucket") == "v6" for item in gate_activity_ids)
                and all(cycle_v6.get(str(item), False) for item in gate_cycle_ids)
                and str(gate.get("repair_attempt_id")) in v6_eligible_attempt_ids):
            v6_closed_root_ids.add(str(root.get("root_cause_id")))
    exposure_counts = {bucket: sum(activity.get("chronology_bucket") == bucket for activity in activities)
                       for bucket in ("pre-dispatch", "transition-pre-adoption", "spanning-dispatch", "spanning-adoption", "v6", "incomplete", "unknown-chronology")}
    lifetime_escape_counts = {
        str(root.get("root_cause_id")): (
            root.get("historical_escape_count_baseline") + len(_unique_escape_events(rows["events"], root.get("root_cause_id")))
            if isinstance(root.get("historical_escape_count_baseline"), int) else None
        )
        for root in rows["roots"]
    }
    return {
        "ledger": ledger, "indexes": indexes, "roots": rows["roots"], "activities": activities,
        "events": rows["events"], "observations": rows["observations"], "attempts_by_root": attempts_by_root,
        "eligible_repair_attempt_ids": eligible_attempt_ids,
        "v6_eligible_repair_attempt_ids": v6_eligible_attempt_ids,
        "escape_incidents": incidents, "repair_induced_attempt_ids": repair_induced_attempt_ids,
        "v6_escape_incidents": v6_incidents,
        "v6_escape_discovery_exclusions": v6_escape_discovery_exclusions,
        "v6_repair_induced_attempt_ids": v6_repair_induced_attempt_ids,
        "observation_v6": observation_v6,
        "observation_v6_exclusion_reasons": observation_v6_exclusion_reasons,
        "confirmed_post_adoption_observations": [
            observation for observation in rows["observations"]
            if observation.get("confirmed") is True
            and observation_v6.get(str(observation.get("observation_id")), False)
        ],
        "v6_initial_root_ids": v6_initial_root_ids,
        "v6_closed_root_ids": v6_closed_root_ids,
        "lifecycle_epochs": epochs, "post_cutover_boundary": boundary,
        "protocol_adopted_at": adoption, "exposure_counts": exposure_counts,
        "lifetime_escape_counts": lifetime_escape_counts,
        "token_activities": [activity for activity in activities if activity["chronology_bucket"] == "v6"],
        "model_observations": [activity for activity in activities if activity["chronology_bucket"] == "v6"],
    }




# Native compatibility rules mechanically migrated from the fixture harness.
# They preserve the 134 pinned reason contracts while the later R7 lifecycle
# switch replaces the sole threshold authority atomically.

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


def _native_canonical_task_path_reasons(task: Any) -> Set[str]:
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


def classify_schema_error(err: Any) -> str:
    path = list(err.absolute_path)
    path_text = "/".join(str(p) for p in path)
    validator = str(err.validator)
    message = str(err.message)

    if err.validator == "pattern" and (
        "uuid" in validator or "0-9a-f" in str(err.validator_value)
    ):
        if any(k in path_text for k in ("task_instance_id", "thread_id", "session_id")):
            return "uuid_format"
        return "pattern"

    if err.validator in {"required", "type", "minLength", "const"}:
        if any(
            fragment in path_text
            for fragment in (
                "runtime_verified",
                "runtime_evidence",
                "actual/model",
                "actual/reasoning_effort",
                "actual/profile",
                "runtime_unavailable_reason",
            )
        ):
            if "runtime_unavailable_reason" in path_text:
                return "runtime_unavailable_reason"
            return "runtime_verification_fields"

    if "runtime_evidence" in path_text or "runtime_unavailable_reason" in path_text:
        if err.validator == "required":
            if "runtime_evidence" in err.message:
                return "runtime_verification_fields"
            return "runtime_unavailable_reason"
        if "runtime_verified" in path_text or "actual" in path_text:
            return "runtime_verification_fields"

    if "session_id_unavailable_reason" in path_text or "thread_id_unavailable_reason" in path_text:
        return "session_thread_reason"

    if "same_root_sibling_test_evidence_ids" in path_text:
        return "closure_sibling_probe"

    if "legacy_reconciliation_complete" in path_text:
        return "legacy_reconciliation_required"

    if "reasoning_unavailable_reason" in path_text:
        return "runtime_reasoning_unavailable"

    if err.validator == "required":
        if "runtime_unavailable_reason" in err.message:
            return "runtime_unavailable_reason"
        if "session_id_unavailable_reason" in err.message:
            return "session_thread_reason"
        if "thread_id_unavailable_reason" in err.message:
            return "session_thread_reason"

    return f"schema:{validator}:{path_text or 'root'}"


def add_reason(reasons: Set[str], reason: str) -> None:
    reasons.add(reason)


def check_unique_sequence_and_order(values: Iterable[int], context: str, reasons: Set[str]) -> None:
    seqs = [int(v) for v in values]
    if any(v < 1 for v in seqs):
        add_reason(reasons, f"{context}_sequence_non_positive")
    if len(seqs) != len(set(seqs)):
        add_reason(reasons, f"{context}_sequence_duplicate")
    if any(seqs[i + 1] <= seqs[i] for i in range(len(seqs) - 1)):
        add_reason(reasons, f"{context}_sequence_non_increasing")


def ensure_unique_ids(
    ids: Iterable[Optional[str]],
    context: str,
    reasons: Set[str],
) -> None:
    counter = Counter(i for i in ids if i is not None)
    duplicates = [id_ for id_, count in counter.items() if count > 1]
    if duplicates:
        add_reason(reasons, f"{context}_duplicate_id:{','.join(sorted(duplicates))}")


def required_id_list(values: Iterable[Any]) -> bool:
    return all(value is not None for value in values)


def collect_event_sequence_indices(
    events: List[Dict[str, Any]],
) -> Dict[str, int]:
    return {evt.get("event_id"): evt.get("sequence") for evt in events if evt.get("event_id")}


def collect_activity_sequence_indices(
    activities: List[Dict[str, Any]],
) -> Dict[str, str]:
    return {
        activity.get("activity_id"): activity.get("started_at")
        for activity in activities
        if activity.get("activity_id")
    }


def non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def check_references(
    ledger: Dict[str, Any],
    reasons: Set[str],
) -> None:
    roots = {r["root_cause_id"] for r in ledger.get("roots", []) if r.get("root_cause_id")}
    observations = {o["observation_id"] for o in ledger.get("observations", []) if o.get("observation_id")}
    review_bases = {b["review_basis_id"] for b in ledger.get("review_bases", []) if b.get("review_basis_id")}
    cycles = {c["cycle_id"] for c in ledger.get("cycles", []) if c.get("cycle_id")}
    test_evidence = {t["test_evidence_id"] for t in ledger.get("test_evidence", []) if t.get("test_evidence_id")}
    repair_attempts = {r["repair_attempt_id"] for r in ledger.get("repair_attempts", []) if r.get("repair_attempt_id")}
    strategies = {s["strategy_id"] for s in ledger.get("strategies", []) if s.get("strategy_id")}
    activities = {a["activity_id"] for a in ledger.get("activities", []) if a.get("activity_id")}
    events = {e["event_id"] for e in ledger.get("events", []) if e.get("event_id")}

    def exists(id_value: Optional[str], collection: Set[str], kind: str, location: str) -> None:
        if id_value is not None and id_value not in collection:
            add_reason(reasons, f"{kind}_missing:{location}:{id_value}")

    for root in ledger.get("roots", []):
        for value in root.get("fixing_cycle_ids", []) or []:
            exists(value, cycles, "cycle", f"root:{root.get('root_cause_id')}:fixing_cycle_id")
        for value in root.get("verifying_cycle_ids", []) or []:
            exists(value, cycles, "cycle", f"root:{root.get('root_cause_id')}:verifying_cycle_id")
        exists(root.get("introducing_cycle_id"), cycles, "cycle", f"root:{root.get('root_cause_id')}:introducing_cycle_id")
        exists(root.get("first_observation_id"), observations, "observation", f"root:{root.get('root_cause_id')}:first_observation_id")
        exists(root.get("closure_event_id"), events, "event", f"root:{root.get('root_cause_id')}:closure_event_id")

        closure_gate = root.get("closure_gate", {})
        if closure_gate:
            exists(
                closure_gate.get("original_reproduction_test_evidence_id"),
                test_evidence,
                "test_evidence",
                f"root:{root.get('root_cause_id')}:closure_gate.original_reproduction_test_evidence_id",
            )
            for value in closure_gate.get("exact_recurrence_test_evidence_ids", []) or []:
                exists(
                    value,
                    test_evidence,
                    "test_evidence",
                    f"root:{root.get('root_cause_id')}:closure_gate.exact_recurrence_test_evidence_ids",
                )
            for value in closure_gate.get("same_root_sibling_test_evidence_ids", []) or []:
                exists(
                    value,
                    test_evidence,
                    "test_evidence",
                    f"root:{root.get('root_cause_id')}:closure_gate.same_root_sibling_test_evidence_ids",
                )
            exists(
                closure_gate.get("repair_attempt_id"),
                repair_attempts,
                "repair_attempt",
                f"root:{root.get('root_cause_id')}:closure_gate.repair_attempt_id",
            )
            exists(
                closure_gate.get("post_repair_review_cycle_id"),
                cycles,
                "cycle",
                f"root:{root.get('root_cause_id')}:closure_gate.post_repair_review_cycle_id",
            )
            exists(
                closure_gate.get("post_repair_review_activity_id"),
                activities,
                "activity",
                f"root:{root.get('root_cause_id')}:closure_gate.post_repair_review_activity_id",
            )
            exists(
                closure_gate.get("following_unchanged_cycle_id"),
                cycles,
                "cycle",
                f"root:{root.get('root_cause_id')}:closure_gate.following_unchanged_cycle_id",
            )
            exists(
                closure_gate.get("following_unchanged_activity_id"),
                activities,
                "activity",
                f"root:{root.get('root_cause_id')}:closure_gate.following_unchanged_activity_id",
            )
            exists(
                closure_gate.get("review_basis_id"),
                review_bases,
                "review_basis",
                f"root:{root.get('root_cause_id')}:closure_gate.review_basis_id",
            )

    for obs in ledger.get("observations", []):
        exists(obs.get("root_cause_id"), roots, "root", f"observation:{obs.get('observation_id')}:root")
        for value in obs.get("activity_ids", []) or []:
            exists(value, activities, "activity", f"observation:{obs.get('observation_id')}:activity_ids")
        for value in obs.get("discovering_activity_ids", []) or []:
            exists(
                value,
                activities,
                "activity",
                f"observation:{obs.get('observation_id')}:discovering_activity_ids",
            )
        for field in ("review_basis_id", "introducing_cycle_id", "fixing_cycle_id", "verifying_cycle_id", "cycle_id", "detected_cycle_id"):
            exists(
                obs.get(field),
                cycles if field in {"introducing_cycle_id", "fixing_cycle_id", "verifying_cycle_id", "cycle_id", "detected_cycle_id"} else review_bases,
                "reference",
                f"observation:{obs.get('observation_id')}:{field}",
            )
        exists(obs.get("repair_attempt_id"), repair_attempts, "repair_attempt", f"observation:{obs.get('observation_id')}:repair_attempt_id")

    for attempt in ledger.get("repair_attempts", []):
        exists(attempt.get("root_cause_id"), roots, "root", f"repair_attempt:{attempt.get('repair_attempt_id')}:root")
        exists(
            attempt.get("strategy_id"),
            strategies,
            "strategy",
            f"repair_attempt:{attempt.get('repair_attempt_id')}:strategy",
        )
        exists(attempt.get("introducing_cycle_id"), cycles, "cycle", f"repair_attempt:{attempt.get('repair_attempt_id')}:introducing_cycle_id")
        exists(attempt.get("fixing_cycle_id"), cycles, "cycle", f"repair_attempt:{attempt.get('repair_attempt_id')}:fixing_cycle_id")
        exists(attempt.get("verifying_cycle_id"), cycles, "cycle", f"repair_attempt:{attempt.get('repair_attempt_id')}:verifying_cycle_id")
        exists(attempt.get("review_basis_id"), review_bases, "review_basis", f"repair_attempt:{attempt.get('repair_attempt_id')}:review_basis_id")
        for value in attempt.get("implementation_activity_ids", []) or []:
            # A modern reservation is allowed to reserve an identity before
            # execution.  Its start/settlement rule is the sole place that
            # turns the reservation into a required activity row.
            if attempt.get("record_kind") != "reservation" or value in activities:
                exists(value, activities, "activity", f"repair_attempt:{attempt.get('repair_attempt_id')}:implementation_activity_ids")
        for value in attempt.get("verification_activity_ids", []) or []:
            exists(value, activities, "activity", f"repair_attempt:{attempt.get('repair_attempt_id')}:verification_activity_ids")

    for strategy in ledger.get("strategies", []):
        exists(strategy.get("root_cause_id"), roots, "root", f"strategy:{strategy.get('strategy_id')}:root")
        reserved = any(attempt.get("record_kind") == "reservation" and attempt.get("strategy_id") == strategy.get("strategy_id")
                       for attempt in ledger.get("repair_attempts", []))
        activity_id = strategy.get("astra_adjudication_activity_id")
        if not reserved or activity_id in activities:
            exists(activity_id, activities, "activity", f"strategy:{strategy.get('strategy_id')}:astra_adjudication_activity_id")

    for activity in ledger.get("activities", []):
        for value in activity.get("root_cause_ids", []) or []:
            exists(value, roots, "root", f"activity:{activity.get('activity_id')}:root_cause_id")

    for event in ledger.get("events", []):
        exists(event.get("root_cause_id"), roots, "root", f"event:{event.get('event_id')}:root")
        exists(event.get("observation_id"), observations, "observation", f"event:{event.get('event_id')}:observation")
        exists(event.get("repair_attempt_id"), repair_attempts, "repair_attempt", f"event:{event.get('event_id')}:repair_attempt")
        exists(event.get("review_basis_id"), review_bases, "review_basis", f"event:{event.get('event_id')}:review_basis")
        exists(event.get("cycle_id"), cycles, "cycle", f"event:{event.get('event_id')}:cycle")


def check_closure_and_escape_rules(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    """Enforce all closure evidence and the baseline-plus-escape Astra gate."""
    roots = {r.get("root_cause_id"): r for r in ledger.get("roots", [])}
    tests = {t.get("test_evidence_id"): t for t in ledger.get("test_evidence", [])}
    cycles = {c.get("cycle_id"): c for c in ledger.get("cycles", [])}
    activities = {a.get("activity_id"): a for a in ledger.get("activities", [])}
    events = {e.get("event_id"): e for e in ledger.get("events", [])}
    observations = ledger.get("observations", [])
    attempts = {a.get("repair_attempt_id"): a for a in ledger.get("repair_attempts", [])}
    strategies = {s.get("strategy_id"): s for s in ledger.get("strategies", [])}
    modern_roots = {
        attempt.get("root_cause_id") for attempt in ledger.get("repair_attempts", [])
        if attempt.get("record_kind") == "reservation"
    }

    def fail(root_id: str, rule: str) -> None:
        add_reason(reasons, f"{rule}:{root_id}")

    def test_ok(root_id: str, test_id: Any, kind: str, basis: Any, post_cycle: Any) -> bool:
        item = tests.get(test_id)
        execution = activities.get((item or {}).get("execution_activity_id"))
        if not item or item.get("root_cause_id") != root_id or item.get("kind") != kind or item.get("result") != "pass" or item.get("review_basis_id") != basis or not execution:
            fail(root_id, f"closure_test_{kind.replace('-', '_')}")
            return False
        # Closure probes are part of the cited post-repair cycle, not merely
        # adjacent work.  This prevents a stale earlier probe from proving a
        # later closure gate.
        if (not post_cycle or item.get("execution_activity_id") not in (post_cycle.get("activity_ids") or [])):
            fail(root_id, "closure_test_post_cycle_membership")
            return False
        def parse(value: Any) -> Optional[datetime]:
            try:
                return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except Exception:
                return None
        cycle_start, cycle_end = parse(post_cycle.get("started_at")), parse(post_cycle.get("completed_at"))
        activity_start, activity_end = parse(execution.get("started_at")), parse(execution.get("completed_at"))
        if not (cycle_start and cycle_end and activity_start and activity_end and cycle_start <= activity_start <= activity_end <= cycle_end):
            fail(root_id, "closure_test_post_cycle_interval")
            return False
        return True

    def review_ok(root_id: str, cycle_id: Any, activity_id: Any, basis: Any, kind: str) -> bool:
        cycle = cycles.get(cycle_id)
        activity = activities.get(activity_id)
        if not cycle or not activity or not cycle.get("complete") or cycle.get("kind") != kind or cycle.get("review_basis_id") != basis or activity_id not in (cycle.get("activity_ids") or []) or activity.get("type") not in {"review", "post-repair-review", "unchanged-followup-review"}:
            fail(root_id, f"closure_{kind.replace('-', '_')}_review")
            return False
        return True

    def terra_first_pass_ok(root_id: str, activity_id: Any) -> bool:
        activity = activities.get(activity_id) or {}
        actual = activity.get("actual") or {}
        requested = activity.get("requested") or {}
        route = activity.get("review_route")
        profile = actual.get("profile")
        good = (
            activity.get("runtime_verified") is True
            and actual.get("model") == "gpt-5.6-terra"
            and actual.get("reasoning_effort") == "high"
            and non_empty_string(profile)
            and route in {"named-terra-first-pass", "generic-terra-first-pass"}
        )
        if route == "named-terra-first-pass":
            good = good and profile == "mas1_reviewer_terra" and activity.get("fallback_reason") is None and requested.get("model") == "gpt-5.6-terra" and requested.get("reasoning_effort") == "high" and requested.get("profile") == "mas1_reviewer_terra"
        elif route == "generic-terra-first-pass":
            good = good and profile != "mas1_reviewer_terra" and non_empty_string(activity.get("fallback_reason"))
        if not good:
            fail(root_id, "closure_post_repair_terra_route")

    for root_id, root in roots.items():
        # Reservations derive their terminal instant from a settlement event.
        # Their epoch checks live in the sole modern lifecycle rule below; the
        # historical closure checker intentionally retains its old record-
        # completion interpretation for bounded compatibility records.
        if root_id in modern_roots:
            continue
        state = root.get("state")
        if state not in {"closure_pending", "closed_verified"}:
            continue
        gate = root.get("closure_gate") or {}
        basis = gate.get("review_basis_id")
        post_id, post_activity = gate.get("post_repair_review_cycle_id"), gate.get("post_repair_review_activity_id")
        post_cycle = cycles.get(post_id)
        if not root.get("reconciliation_complete") or not (ledger.get("cutover") or {}).get("legacy_reconciliation_complete"):
            fail(root_id, "closure_reconciliation_required")
        test_ok(root_id, gate.get("original_reproduction_test_evidence_id"), "original-reproduction", basis, post_cycle)
        for test_id in gate.get("exact_recurrence_test_evidence_ids") or []:
            test_ok(root_id, test_id, "exact-recurrence", basis, post_cycle)
        for test_id in gate.get("same_root_sibling_test_evidence_ids") or []:
            test_ok(root_id, test_id, "same-root-sibling", basis, post_cycle)
        review_ok(root_id, post_id, post_activity, basis, "post-repair")
        terra_first_pass_ok(root_id, post_activity)
        cited = {post_id}
        if state == "closed_verified":
            follow_id, follow_activity = gate.get("following_unchanged_cycle_id"), gate.get("following_unchanged_activity_id")
            review_ok(root_id, follow_id, follow_activity, basis, "unchanged-closure")
            cited.add(follow_id)
            post, follow = cycles.get(post_id), cycles.get(follow_id)
            if not post or not follow or follow.get("sequence", 0) <= post.get("sequence", 0) or follow_id == post_id or follow_activity == post_activity:
                fail(root_id, "closure_following_order")
            # No skipped earlier eligible complete unchanged-closure cycle on this basis.
            if post and follow:
                for candidate in cycles.values():
                    if candidate.get("cycle_id") not in {post_id, follow_id} and candidate.get("complete") and candidate.get("kind") == "unchanged-closure" and candidate.get("review_basis_id") == basis and post.get("sequence", 0) < candidate.get("sequence", 0) < follow.get("sequence", 0):
                        fail(root_id, "closure_first_subsequent_skipped")
            event = events.get(root.get("closure_event_id"))
            if not event or event.get("type") != "root-closed-verified" or event.get("root_cause_id") != root_id or event.get("cycle_id") != follow_id or event.get("review_basis_id") != basis or not event.get("causal_refs"):
                fail(root_id, "closure_event_invalid")
        # Only a newly confirmed non-initial relationship in one cited closure cycle reopens.
        for obs in observations:
            if obs.get("root_cause_id") == root_id and not obs.get("pre_cutover") and obs.get("confirmed") and obs.get("root_relationship") != "initial" and obs.get("detected_cycle_id") in cited:
                fail(root_id, "closure_related_observation")


def activity_has_root_attribution(activity: Any, root_id: str) -> bool:
    """Return whether an activity is explicitly attributable to this root."""
    if not isinstance(activity, dict):
        return False
    root_ids = activity.get("root_cause_ids") or []
    if len(root_ids) != len(set(root_ids)):
        return False
    if activity.get("attribution_mode") == "direct":
        return root_ids == [root_id]
    if activity.get("attribution_mode") == "shared":
        return len(root_ids) >= 2 and root_id in root_ids
    return False


def check_root_activity_attribution(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    """Require root-attribution on every activity used as causal evidence.

    A generic/none-attributed activity cannot prove a root's probe, repair,
    closure review, or Astra gate.  This remains procedural because the graph
    of references spans several independently-schema-valid collections.
    """
    activities = {a.get("activity_id"): a for a in ledger.get("activities", [])}
    tests = {t.get("test_evidence_id"): t for t in ledger.get("test_evidence", [])}
    strategies = {s.get("strategy_id"): s for s in ledger.get("strategies", [])}

    def require(root_id: str, activity_id: Any, source: str) -> None:
        if activity_id is None:
            return
        if not activity_has_root_attribution(activities.get(activity_id), root_id):
            add_reason(reasons, f"root_activity_attribution:{root_id}:{source}:{activity_id}")

    for root in ledger.get("roots", []):
        root_id = root.get("root_cause_id")
        if not root_id:
            continue
        gate = root.get("closure_gate") or {}
        for field, source in (
            ("original_reproduction_test_evidence_id", "closure-original-probe"),
        ):
            test = tests.get(gate.get(field))
            if test:
                require(root_id, test.get("execution_activity_id"), source)
        for field, source in (
            ("exact_recurrence_test_evidence_ids", "closure-exact-probe"),
            ("same_root_sibling_test_evidence_ids", "closure-sibling-probe"),
        ):
            for test_id in gate.get(field) or []:
                test = tests.get(test_id)
                if test:
                    require(root_id, test.get("execution_activity_id"), source)
        require(root_id, gate.get("post_repair_review_activity_id"), "closure-post-review")
        require(root_id, gate.get("following_unchanged_activity_id"), "closure-following-review")

        for attempt in ledger.get("repair_attempts", []):
            if attempt.get("root_cause_id") != root_id:
                continue
            for activity_id in attempt.get("implementation_activity_ids") or []:
                if attempt.get("record_kind") != "reservation" or activity_id in activities:
                    require(root_id, activity_id, "repair-implementation")
            for activity_id in attempt.get("verification_activity_ids") or []:
                require(root_id, activity_id, "repair-verification")

        for strategy in strategies.values():
            if strategy.get("root_cause_id") == root_id:
                reserved = any(attempt.get("record_kind") == "reservation" and attempt.get("strategy_id") == strategy.get("strategy_id")
                               for attempt in ledger.get("repair_attempts", []))
                activity_id = strategy.get("astra_adjudication_activity_id")
                if not reserved or activity_id in activities:
                    require(root_id, activity_id, "strategy-astra")

        for event in ledger.get("events", []):
            if event.get("type") == "astra-adjudicated" and event.get("root_cause_id") == root_id:
                require(root_id, event.get("adjudication_activity_id"), "astra-event")


def check_astra_adjudication_event_gate(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    """Compatibility placeholder; core threshold facts own this gate."""
    return


def check_integrity(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    """Cross-entity causal integrity that JSON Schema cannot express."""
    roots={r.get("root_cause_id"):r for r in ledger.get("roots",[])}
    activities={a.get("activity_id"):a for a in ledger.get("activities",[])}
    cycles={c.get("cycle_id"):c for c in ledger.get("cycles",[])}
    events=ledger.get("events",[]); attempts=ledger.get("repair_attempts",[]); strategies={s.get("strategy_id"):s for s in ledger.get("strategies",[])}
    def bad(r, rule): add_reason(reasons, f"{rule}:{r}")
    # Array chronology and attribution.
    cseq=[c.get("sequence",0) for c in ledger.get("cycles",[])]
    check_unique_sequence_and_order(cseq,"cycle",reasons)
    for a in activities.values():
        ids=a.get("root_cause_ids") or []
        if len(ids)!=len(set(ids)): add_reason(reasons,f"attribution_duplicate_root:{a.get('activity_id')}")
        mode=a.get("attribution_mode")
        if (mode=="direct" and len(ids)!=1) or (mode=="shared" and len(ids)<2) or (mode=="none" and ids):
            add_reason(reasons,f"attribution_mode_invalid:{a.get('activity_id')}")
    for rid, root in roots.items():
        modern_root = any(attempt.get("root_cause_id") == rid and attempt.get("record_kind") == "reservation"
                          for attempt in attempts)
        obs=[o for o in ledger.get("observations",[]) if o.get("root_cause_id")==rid]
        initials=[o for o in obs if o.get("root_relationship")=="initial"]
        if len(initials)!=1 or not initials or initials[0].get("observation_id")!=root.get("first_observation_id"):
            bad(rid,"root_initial_observation")
        elif not any(e.get("type")=="root-opened" and e.get("root_cause_id")==rid and e.get("observation_id")==initials[0].get("observation_id") for e in events):
            bad(rid,"root_opened_event")
        for o in obs:
            if o.get("record_kind") == "historical-report-import-v1":
                continue
            if o.get("confirmed") and not o.get("pre_cutover") and o.get("root_relationship")!="initial":
                reopened=any(e.get("type")=="root-reopened" and e.get("root_cause_id")==rid and e.get("observation_id")==o.get("observation_id") and e.get("cycle_id")==o.get("detected_cycle_id") for e in events)
                if not reopened: bad(rid,"root_reopen_event")
                if root.get("state") in {"closure_pending","closed_verified"} and not modern_root: bad(rid,"root_not_reopened")
        # Complete closure reviews must be completed review activities in their cycles.
        if root.get("state") in {"closure_pending","closed_verified"}:
            gate=root.get("closure_gate") or {}
            for cycle_key,act_key in [("post_repair_review_cycle_id","post_repair_review_activity_id"),("following_unchanged_cycle_id","following_unchanged_activity_id")]:
                cid,aid=gate.get(cycle_key),gate.get(act_key)
                if cid is None: continue
                a=activities.get(aid); c=cycles.get(cid)
                if not a or not c or a.get("status")!="completed" or not a.get("completed_at") or a.get("type") not in {"review","post-repair-review","unchanged-followup-review"} or aid not in (c.get("activity_ids") or []):
                    bad(rid,"closure_review_activity")


def check_temporal_and_event_integrity(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    def ts(value: Any) -> Optional[datetime]:
        return parse_rfc3339(value)
    activities={a.get("activity_id"):a for a in ledger.get("activities",[])}
    known=set(activities)|{x.get("root_cause_id") for x in ledger.get("roots",[])}|{x.get("event_id") for x in ledger.get("events",[])}|{x.get("cycle_id") for x in ledger.get("cycles",[])}|{x.get("review_basis_id") for x in ledger.get("review_bases",[])}|{x.get("test_evidence_id") for x in ledger.get("test_evidence",[])}|{x.get("repair_attempt_id") for x in ledger.get("repair_attempts",[])}|{x.get("strategy_id") for x in ledger.get("strategies",[])}|{x.get("observation_id") for x in ledger.get("observations",[])}
    for a in activities.values():
        if a.get("status")=="completed" and (not ts(a.get("started_at")) or not ts(a.get("completed_at")) or ts(a.get("started_at"))>ts(a.get("completed_at"))): add_reason(reasons,f"activity_temporal:{a.get('activity_id')}")
        u=a.get("token_usage") or {}
        if u.get("source")=="runtime-reported" and (u.get("total")!=u.get("input",0)+u.get("output",0) or (u.get("reasoning") is not None and u.get("reasoning")>u.get("output",0))): add_reason(reasons,f"token_integrity:{a.get('activity_id')}")
    for e in ledger.get("events",[]):
        for ref in e.get("causal_refs") or []:
            if ref not in known: add_reason(reasons,f"event_causal_ref:{e.get('event_id')}")


def check_closure_temporal_order(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    def T(v):
        try: return datetime.fromisoformat(str(v).replace("Z","+00:00"))
        except Exception: return None
    acts={a.get("activity_id"):a for a in ledger.get("activities",[])}; cycles={c.get("cycle_id"):c for c in ledger.get("cycles",[])}; events={e.get("event_id"):e for e in ledger.get("events",[])}; attempts={a.get("repair_attempt_id"):a for a in ledger.get("repair_attempts",[])}; tests={t.get("test_evidence_id"):t for t in ledger.get("test_evidence",[])}
    for r in ledger.get("roots",[]):
      if any(a.get("root_cause_id")==r.get("root_cause_id") and a.get("record_kind")=="reservation" for a in ledger.get("repair_attempts", [])): continue
      if r.get("state") not in {"closure_pending","closed_verified"}: continue
      rid=r.get("root_cause_id");g=r.get("closure_gate") or {}; post=cycles.get(g.get("post_repair_review_cycle_id")); pa=acts.get(g.get("post_repair_review_activity_id"))
      pending=[e for e in events.values() if e.get("type")=="closure-pending" and e.get("root_cause_id")==rid and e.get("cycle_id")==g.get("post_repair_review_cycle_id") and e.get("review_basis_id")==g.get("review_basis_id")]
      if len(pending)!=1: add_reason(reasons,f"pending_event:{rid}"); continue
      pe=pending[0]; repair=attempts.get(g.get("repair_attempt_id"))
      tids=[g.get("original_reproduction_test_evidence_id"),*(g.get("exact_recurrence_test_evidence_ids") or []),*(g.get("same_root_sibling_test_evidence_ids") or [])]
      for tid in tids:
        t=tests.get(tid);a=acts.get((t or {}).get("execution_activity_id"))
        if not t or not a or a.get("status")!="completed" or a.get("type") not in {"test","check"} or not T(t.get("executed_at")) or not T(a.get("started_at")) or not T(a.get("completed_at")) or not(T(a["started_at"])<=T(t["executed_at"])<=T(a["completed_at"])): add_reason(reasons,f"closure_test_temporal:{rid}")
        if not repair or repair.get("root_cause_id")!=rid or repair.get("review_basis_id")!=g.get("review_basis_id") or not T(repair.get("completed_at")): add_reason(reasons,f"closure_gate_repair_anchor:{rid}")
        elif T(t.get("executed_at")) and T(t["executed_at"])<T(repair["completed_at"]): add_reason(reasons,f"closure_test_before_repair:{rid}")
        if pa and T(pa.get("started_at")) and T(t.get("executed_at")) and T(t["executed_at"])>T(pa["started_at"]): add_reason(reasons,f"closure_test_after_review:{rid}")
      if not pa or pa.get("status")!="completed" or not T(pa.get("started_at")) or not T(pa.get("completed_at")) or not post or not(T(post.get("started_at"))<=T(pa["started_at"])<=T(pa["completed_at"])<=T(post.get("completed_at"))) or (repair and T(repair.get("completed_at")) and T(pa["started_at"])<T(repair["completed_at"])): add_reason(reasons,f"post_review_temporal:{rid}")
      if post and (not T(pe.get("at")) or T(pe["at"])<T(post.get("completed_at"))): add_reason(reasons,f"pending_before_post_cycle:{rid}")
      if r.get("state")=="closed_verified":
        fc=cycles.get(g.get("following_unchanged_cycle_id"));fa=acts.get(g.get("following_unchanged_activity_id"));ce=events.get(r.get("closure_event_id"))
        if not fc or not fa or fa.get("status")!="completed" or not T(fa.get("started_at")) or not T(fa.get("completed_at")) or not(T(fc.get("started_at"))<=T(fa["started_at"])<=T(fa["completed_at"])<=T(fc.get("completed_at"))): add_reason(reasons,f"following_review_temporal:{rid}")
        if not ce or ce.get("type")!="root-closed-verified" or not T(ce.get("at")) or not fc or T(ce["at"])<T(fc.get("completed_at")) or T(ce["at"])<T(pe.get("at")): add_reason(reasons,f"closed_event_temporal:{rid}")
        needed=set(tids+[g.get("post_repair_review_activity_id"),g.get("post_repair_review_cycle_id"),g.get("following_unchanged_activity_id"),g.get("following_unchanged_cycle_id"),pe.get("event_id")])
        if not needed.issubset(set(ce.get("causal_refs") or [])): add_reason(reasons,f"closure_causal_refs:{rid}")


def check_escape_binding_threshold(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    obs={o.get("observation_id"):o for o in ledger.get("observations",[])}; attempts={a.get("repair_attempt_id"):a for a in ledger.get("repair_attempts",[])}; events=ledger.get("events",[]); acts={a.get("activity_id"):a for a in ledger.get("activities",[])}
    for root in ledger.get("roots",[]):
      rid=root.get("root_cause_id"); esc=sorted([e for e in events if e.get("type")=="escape-confirmed" and e.get("root_cause_id")==rid],key=lambda e:e.get("sequence",0)); keys=[]
      for e in esc:
        o=obs.get(e.get("observation_id")); at=attempts.get(e.get("repair_attempt_id"))
        good=o and o.get("confirmed") and not o.get("pre_cutover") and o.get("root_relationship") in {"exact-recurrence","same-root-sibling","repair-induced","expected-fallout"} and o.get("root_relationship")==e.get("root_relationship") and o.get("root_cause_id")==rid and o.get("detected_cycle_id")==e.get("cycle_id") and o.get("repair_attempt_id")==e.get("repair_attempt_id") and o.get("review_basis_id")==e.get("review_basis_id") and at and at.get("root_cause_id")==rid and at.get("review_basis_id")==e.get("review_basis_id")
        if not good: add_reason(reasons,f"escape_observation_binding:{rid}")
        if o and o.get("root_relationship") != e.get("root_relationship"):
          add_reason(reasons,f"escape_relationship_mismatch:{rid}")
        keys.append(tuple((e.get("escape_key") or {}).get(k) for k in ("root_cause_id","repair_attempt_id","review_basis_id","cycle_id")))


def check_escape_observation_bijection(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    """Every post-cutover escape observation has exactly one causal event.

    The observation identity, rather than only the older four-field tuple, is
    the primary key.  It therefore catches two observations accidentally
    sharing a tuple and duplicate events whose tuple was altered to evade a
    tuple-only check.
    """
    relations = {"exact-recurrence", "same-root-sibling", "repair-induced", "expected-fallout"}
    observations = {o.get("observation_id"): o for o in ledger.get("observations", [])}
    events = [e for e in ledger.get("events", []) if e.get("type") == "escape-confirmed"]
    eligible = {
        oid: o for oid, o in observations.items()
        if oid and o.get("confirmed") and not o.get("pre_cutover")
        and o.get("root_relationship") in relations
        and all(non_empty_string(o.get(field)) for field in ("root_cause_id", "repair_attempt_id", "review_basis_id", "detected_cycle_id"))
    }
    events_by_observation: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        oid = event.get("observation_id")
        if oid not in eligible:
            add_reason(reasons, f"escape_event_orphan:{event.get('event_id')}")
            continue
        observation = eligible[oid]
        if not (
            event.get("root_cause_id") == observation.get("root_cause_id")
            and event.get("root_relationship") == observation.get("root_relationship")
            and event.get("repair_attempt_id") == observation.get("repair_attempt_id")
            and event.get("review_basis_id") == observation.get("review_basis_id")
            and event.get("cycle_id") == observation.get("detected_cycle_id")
        ):
            add_reason(reasons, f"escape_observation_binding:{observation.get('root_cause_id')}")
        events_by_observation[oid].append(event)
    for oid, observation in eligible.items():
        matching = events_by_observation.get(oid, [])
        if not matching:
            add_reason(reasons, f"escape_event_missing:{observation.get('root_cause_id')}")
            continue
        if len(matching) != 1:
            add_reason(reasons, f"escape_event_observation_duplicate:{observation.get('root_cause_id')}")
            continue
        escape = matching[0]
        reopened = [
            event for event in ledger.get("events", [])
            if event.get("type") == "root-reopened"
            and event.get("root_cause_id") == observation.get("root_cause_id")
            and event.get("observation_id") == oid
        ]
        if not any(escape.get("event_id") in (event.get("causal_refs") or []) for event in reopened):
            add_reason(reasons, f"root_reopen_escape_required:{observation.get('root_cause_id')}")


def check_repair_attempt_integrity(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    def T(v):
        try: return datetime.fromisoformat(str(v).replace("Z","+00:00"))
        except Exception: return None
    strategies={s.get("strategy_id"):s for s in ledger.get("strategies",[])}; acts={a.get("activity_id"):a for a in ledger.get("activities",[])}
    events=ledger.get("events",[])
    for attempt in ledger.get("repair_attempts",[]):
      rid=attempt.get("root_cause_id"); s=strategies.get(attempt.get("strategy_id"))
      if not s or s.get("root_cause_id")!=rid: add_reason(reasons,f"repair_strategy_root:{attempt.get('repair_attempt_id')}"); continue
      st,en=T(attempt.get("started_at")),T(attempt.get("completed_at"))
      if st and en and st>en: add_reason(reasons,f"repair_timestamp:{attempt.get('repair_attempt_id')}")
      for aid in (attempt.get("implementation_activity_ids") or [])+(attempt.get("verification_activity_ids") or []):
        ac=acts.get(aid)
        if ac and st and T(ac.get("started_at")) and T(ac["started_at"])<st or ac and en and T(ac.get("completed_at")) and T(ac["completed_at"])>en: add_reason(reasons,f"repair_activity_window:{attempt.get('repair_attempt_id')}")


def check_new_causal_rules(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    def T(v):
      try:return datetime.fromisoformat(str(v).replace("Z","+00:00"))
      except:return None
    acts={a.get("activity_id"):a for a in ledger.get("activities",[])};ev={e.get("event_id"):e for e in ledger.get("events",[])}; attempts={a.get("repair_attempt_id"):a for a in ledger.get("repair_attempts",[])};obs={o.get("observation_id"):o for o in ledger.get("observations",[])}
    for r in ledger.get("roots",[]):
      rid=r.get("root_cause_id"); g=r.get("closure_gate") or {}
      if r.get("state") in {"closure_pending","closed_verified"}:
        if not isinstance(r.get("invariant"),str) or not r["invariant"].strip() or not isinstance(r.get("causal_explanation"),str) or not r["causal_explanation"].strip(): add_reason(reasons,f"closure_nonblank:{rid}")
        ex={next((t for t in ledger.get("test_evidence",[]) if t.get("test_evidence_id")==x),{}).get("identity") for x in g.get("exact_recurrence_test_evidence_ids",[])};si={next((t for t in ledger.get("test_evidence",[]) if t.get("test_evidence_id")==x),{}).get("identity") for x in g.get("same_root_sibling_test_evidence_ids",[])}
        if ex&si:add_reason(reasons,f"closure_probe_identity_overlap:{rid}")


def check_escape_reopen_causality(ledger: Dict[str, Any], reasons: Set[str]) -> None:
 def T(v):
  try:return datetime.fromisoformat(str(v).replace("Z","+00:00"))
  except:return None
 obs={o.get("observation_id"):o for o in ledger.get("observations",[])}; attempts={a.get("repair_attempt_id"):a for a in ledger.get("repair_attempts",[])}; acts={a.get("activity_id"):a for a in ledger.get("activities",[])}; events=ledger.get("events",[])
 context=_validation_context(ledger); modern_event_ids=set()
 if context is not None:
  for root in context.rows["roots"]:
   rid=root.get("root_cause_id")
   if not isinstance(rid,str):continue
   incidents,incident_reasons=_modern_escape_incidents(context,rid); reasons.update(incident_reasons)
   modern_event_ids.update(item.get("event_id") for item in incidents)
 for r in ledger.get("roots",[]):
  rid=r.get("root_cause_id")
  initial=obs.get(r.get("first_observation_id")); opened=[e for e in events if e.get("type")=="root-opened" and e.get("root_cause_id")==rid]
  if initial and initial.get("record_kind") != "historical-report-import-v1" and (not any(T(e.get("at")) and T(initial.get("observed_at")) and T(e["at"])>=T(initial["observed_at"]) and {initial.get("observation_id"),rid}.issubset(set(e.get("causal_refs") or [])) for e in opened)):add_reason(reasons,f"root_opened_causality:{rid}")
  for e in [x for x in events if x.get("type")=="escape-confirmed" and x.get("root_cause_id")==rid]:
   o=obs.get(e.get("observation_id"));a=attempts.get(e.get("repair_attempt_id")); impl=[acts.get(x) for x in (a or {}).get("implementation_activity_ids",[])]
   # Dispatch on the linked attempt representation.  A root can contain both
   # retained ordinary history and modern reservations; root-wide switching
   # would otherwise promote legacy rows into the lower-bound model.
   if not isinstance(a,dict):
    add_reason(reasons,f"escape_causality:{rid}");continue
   if isinstance(a,dict) and a.get("record_kind")=="reservation":
    if e.get("event_id") not in modern_event_ids:add_reason(reasons,f"escape_causality:{rid}")
    continue
   settlement=next((x for x in events if x.get("type")=="repair-threshold-settled" and x.get("repair_attempt_id")==e.get("repair_attempt_id") and x.get("terminal_outcome")=="succeeded"),None)
   completed=T(a.get("completed_at")) or T((settlement or {}).get("settled_at"))
   good=o and a and o.get("confirmed") and not o.get("pre_cutover") and o.get("root_relationship")!="initial" and o.get("root_relationship")==e.get("root_relationship") and (o.get("root_cause_id"),o.get("detected_cycle_id"),o.get("repair_attempt_id"),o.get("review_basis_id"))==(rid,e.get("cycle_id"),e.get("repair_attempt_id"),e.get("review_basis_id")) and T(o.get("observed_at")) and T(e.get("at")) and completed and T(o["observed_at"])>=completed and T(e["at"])>=completed and all(x and T(x.get("completed_at")) and T(o["observed_at"])>=T(x["completed_at"]) for x in impl) and {o.get("observation_id"),a.get("repair_attempt_id"),e.get("cycle_id"),e.get("review_basis_id"),rid}.issubset(set(e.get("causal_refs") or []))
   if not good:add_reason(reasons,f"escape_causality:{rid}");continue
   reopened=[x for x in events if x.get("type")=="root-reopened" and x.get("root_cause_id")==rid and x.get("observation_id")==o.get("observation_id") and x.get("cycle_id")==e.get("cycle_id")]
   if not any(T(x.get("at")) and T(x["at"])>=T(o["observed_at"]) and T(x["at"])>=T(e["at"]) and {o.get("observation_id"),e.get("event_id"),rid}.issubset(set(x.get("causal_refs") or [])) for x in reopened):add_reason(reasons,f"reopen_causality:{rid}")


def check_closure_lifecycle_causality(ledger: Dict[str, Any], reasons: Set[str]) -> None:
 def T(v):
  try:return datetime.fromisoformat(str(v).replace("Z","+00:00"))
  except:return None
 def after(left,right):
  return left is not None and right is not None and left>right
 acts={a.get("activity_id"):a for a in ledger.get("activities",[])};cy={x.get("cycle_id"):x for x in ledger.get("cycles",[])};ev=ledger.get("events",[]);tests={t.get("test_evidence_id"):t for t in ledger.get("test_evidence",[])};attempts=ledger.get("repair_attempts",[])
 for r in ledger.get("roots",[]):
  if any(a.get("root_cause_id")==r.get("root_cause_id") and a.get("record_kind")=="reservation" for a in attempts):continue
  if r.get("state") not in {"closure_pending","closed_verified"}:continue
  rid=r.get("root_cause_id");g=r.get("closure_gate") or {};pc=cy.get(g.get("post_repair_review_cycle_id"));pa=acts.get(g.get("post_repair_review_activity_id")); repair=next((a for a in attempts if a.get("repair_attempt_id")==g.get("repair_attempt_id")),None); tids=[g.get("original_reproduction_test_evidence_id"),*(g.get("exact_recurrence_test_evidence_ids") or []),*(g.get("same_root_sibling_test_evidence_ids") or [])];pe=next((x for x in ev if x.get("type")=="closure-pending" and x.get("root_cause_id")==rid and x.get("cycle_id")==g.get("post_repair_review_cycle_id")),None)
  repair_done=T((repair or {}).get("completed_at")); pending_at=T((pe or {}).get("at"));
  if not repair or repair.get("root_cause_id")!=rid or repair.get("review_basis_id")!=g.get("review_basis_id") or not repair_done or not pending_at or repair_done>pending_at: add_reason(reasons,f"closure_gate_repair_anchor:{rid}")
  if repair and repair.get("fixing_cycle_id") not in (r.get("fixing_cycle_ids") or []): add_reason(reasons,f"closure_gate_repair_fixing_cycle:{rid}")
  if repair_done and pending_at:
   completed=[a for a in attempts if a.get("root_cause_id")==rid and T(a.get("completed_at")) and T(a.get("completed_at"))<=pending_at]
   if completed and max(completed,key=lambda a:T(a.get("completed_at"))).get("repair_attempt_id")!=g.get("repair_attempt_id"): add_reason(reasons,f"closure_gate_repair_not_latest:{rid}")
   for other in attempts:
    if other.get("root_cause_id")!=rid or other.get("repair_attempt_id")==g.get("repair_attempt_id"): continue
    starts,ends=T(other.get("started_at")),T(other.get("completed_at"))
    if (starts and repair_done<starts<=pending_at) or (ends and repair_done<ends<=pending_at): add_reason(reasons,f"closure_gate_later_repair:{rid}")
  deps=[T(pa.get("completed_at")) if pa else None,T(pc.get("completed_at")) if pc else None,repair_done]+[T(tests.get(x,{}).get("executed_at")) for x in tids]
  needed={rid,g.get("repair_attempt_id"),g.get("review_basis_id"),g.get("post_repair_review_cycle_id"),g.get("post_repair_review_activity_id"),*tids}
  if not pe or pe.get("repair_attempt_id")!=g.get("repair_attempt_id") or not T(pe.get("at")) or any(x and T(pe["at"])<x for x in deps) or not needed.issubset(set(pe.get("causal_refs") or [])):add_reason(reasons,f"pending_lifecycle:{rid}")
  if r.get("state")=="closed_verified":
   fc=cy.get(g.get("following_unchanged_cycle_id"));fa=acts.get(g.get("following_unchanged_activity_id"));ce=next((x for x in ev if x.get("event_id")==r.get("closure_event_id")),None)
   if not fc or not fa or not pe or not pc or not pa or not (after(T(fc.get("started_at")),T(pc.get("completed_at"))) and after(T(fa.get("started_at")),T(pa.get("completed_at"))) and after(T(fc.get("started_at")),T(pe.get("at"))) and after(T(fa.get("started_at")),T(pe.get("at")))):add_reason(reasons,f"following_lifecycle:{rid}")
   req={rid,g.get("repair_attempt_id"),g.get("review_basis_id"),g.get("following_unchanged_cycle_id"),g.get("following_unchanged_activity_id"),pe.get("event_id") if pe else None,*tids}
   if not ce or not T(ce.get("at")) or not fc or not fa or not pe or not T(fc.get("completed_at")) or not T(fa.get("completed_at")) or not T(pe.get("at")) or T(ce["at"])<T(fc["completed_at"]) or T(ce["at"])<T(fa["completed_at"]) or T(ce["at"])<T(pe["at"]) or not req.issubset(set(ce.get("causal_refs") or [])):add_reason(reasons,f"closed_lifecycle:{rid}")


def check_basis_invalidation(ledger: Dict[str, Any], reasons: Set[str]) -> None:
 """A changed review basis invalidates a pending/verified closure rather than extending it."""
 def T(v):
  try:return datetime.fromisoformat(str(v).replace("Z","+00:00"))
  except:return None
 acts={a.get("activity_id"):a for a in ledger.get("activities",[])}; cycles=ledger.get("cycles",[]); events=ledger.get("events",[])
 for root in ledger.get("roots",[]):
  rid=root.get("root_cause_id"); gate=root.get("closure_gate") or {}; old_basis=gate.get("review_basis_id")
  modern_root=any(attempt.get("root_cause_id")==rid and attempt.get("record_kind")=="reservation" for attempt in ledger.get("repair_attempts",[]))
  lifecycle=[e for e in events if e.get("root_cause_id")==rid and e.get("type") in {"closure-pending","root-closed-verified"}]
  if not lifecycle or not old_basis: continue
  latest=max(lifecycle,key=lambda e:e.get("sequence",0)); latest_at=T(latest.get("at")); changed=[]
  for cycle in cycles:
   if not cycle.get("complete") or cycle.get("review_basis_id")==old_basis: continue
   root_acts=[acts.get(aid) for aid in cycle.get("activity_ids") or []]
   if any(activity_has_root_attribution(a,rid) for a in root_acts) and T(cycle.get("started_at")) and latest_at and T(cycle.get("started_at"))>latest_at: changed.append((cycle,T(cycle.get("started_at"))))
  for activity in acts.values():
   basis=activity.get("review_basis_id")
   if basis and basis!=old_basis and activity_has_root_attribution(activity,rid) and T(activity.get("started_at")) and latest_at and T(activity.get("started_at"))>latest_at: changed.append((activity,T(activity.get("started_at"))))
  invalidations=[e for e in events if e.get("type")=="basis-invalidated" and e.get("root_cause_id")==rid]
  for event in invalidations:
   evidence=[item for item,at in changed if item.get("review_basis_id")==event.get("review_basis_id") and T(event.get("at")) and at<=T(event.get("at")) and item.get("cycle_id",item.get("activity_id")) in (event.get("causal_refs") or [])]
   if not modern_root and (root.get("state") in {"closure_pending","closed_verified"} or not evidence or rid not in (event.get("causal_refs") or [])): add_reason(reasons,f"basis_invalidation_invalid:{rid}")
  if changed:
   if root.get("state") in {"closure_pending","closed_verified"}: add_reason(reasons,f"basis_change_requires_reset:{rid}")
   for item,at in changed:
    item_id=item.get("cycle_id",item.get("activity_id")); basis=item.get("review_basis_id")
    if not any(e.get("review_basis_id")==basis and T(e.get("at")) and T(e.get("at"))>=at and {rid,item_id}.issubset(set(e.get("causal_refs") or [])) for e in invalidations): add_reason(reasons,f"basis_invalidation_event_required:{rid}")


def check_ids_and_sequences(ledger: Dict[str, Any], reasons: Set[str]) -> None:
    ensure_unique_ids(
        [r.get("root_cause_id") for r in ledger.get("roots", [])],
        "root",
        reasons,
    )
    ensure_unique_ids(
        [o.get("observation_id") for o in ledger.get("observations", [])],
        "observation",
        reasons,
    )
    ensure_unique_ids(
        [b.get("review_basis_id") for b in ledger.get("review_bases", [])],
        "review_basis",
        reasons,
    )
    ensure_unique_ids(
        [c.get("cycle_id") for c in ledger.get("cycles", [])],
        "cycle",
        reasons,
    )
    ensure_unique_ids(
        [t.get("test_evidence_id") for t in ledger.get("test_evidence", [])],
        "test_evidence",
        reasons,
    )
    ensure_unique_ids(
        [a.get("activity_id") for a in ledger.get("activities", [])],
        "activity",
        reasons,
    )
    ensure_unique_ids(
        [e.get("event_id") for e in ledger.get("events", [])],
        "event",
        reasons,
    )

    event_sequences = [e.get("sequence", 0) for e in ledger.get("events", [])]
    check_unique_sequence_and_order(event_sequences, "event", reasons)
    for event in ledger.get("events", []):
        event_id = event.get("event_id")
        refs = event.get("causal_refs")
        if not non_empty_string(event_id):
            add_reason(reasons, "event:identifier")
        if not (isinstance(refs, list) and all(non_empty_string(ref) for ref in refs) and len(refs) == len(set(refs))):
            add_reason(reasons, f"event:causal_refs:{event_id}")


def _run_native_rules(ledger: dict[str, Any], reasons: set[str], context: ValidationContext,
                      legacy_snapshot: Mapping[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """One explicit native registry; rule order is part of deterministic output."""
    telemetry = ledger.get("telemetry") or {}
    activities = ledger.get("activities", []) if isinstance(ledger.get("activities"), list) else []
    activity_ids = {item.get("activity_id") for item in activities if isinstance(item, dict) and item.get("activity_id")}
    if legacy_snapshot is None:
        if telemetry.get("recorded_participating_activity_count") != len(activity_ids):
            reasons.add("telemetry_recorded_count")
        if telemetry.get("activity_inventory_complete") and telemetry.get("expected_participating_activity_count") != len(activity_ids):
            reasons.add("telemetry_expected_count")
    threshold_facts: dict[str, dict[str, Any]] = {}
    for rule in RULE_REGISTRY:
        try:
            if rule is rule_threshold_lifecycle:
                if legacy_snapshot is None:
                    threshold_facts, lifecycle_reasons = rule(context)
                else:
                    threshold_facts, lifecycle_reasons = _legacy_compatibility_threshold_lifecycle(
                        context, legacy_snapshot)
                reasons.update(lifecycle_reasons)
            else:
                rule(ledger, reasons)
        except Exception as exc:
            reasons.add(f"internal:{rule.__name__}:{type(exc).__name__}")
    return threshold_facts


_ESCAPE_KEY_FIELDS = ("root_cause_id", "repair_attempt_id", "review_basis_id", "cycle_id")


def _unique_escape_events(events: Any, root_id: Any) -> list[dict[str, Any]]:
    """Return one deterministic representative for every escape tuple."""
    if not isinstance(events, list):
        return []
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for event in sorted(
        (item for item in events if isinstance(item, dict)
         and item.get("type") == "escape-confirmed" and item.get("root_cause_id") == root_id),
        key=lambda item: (item.get("sequence", 0), str(item.get("event_id", ""))),
    ):
        key_data = event.get("escape_key") if isinstance(event.get("escape_key"), dict) else {}
        key = tuple(key_data.get(field) for field in _ESCAPE_KEY_FIELDS)
        if key not in seen:
            seen.add(key)
            unique.append(event)
    return unique


def _nonblank_sorted_unique(value: Any) -> bool:
    return (isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)
            and value == sorted(set(value)))


def _threshold_prederive_reasons(ledger: Any) -> set[str]:
    """Reject rows unsafe for causal derivation before constructing indexes."""
    reasons: set[str] = set()
    if not isinstance(ledger, dict):
        return reasons
    events = ledger.get("events")
    if not isinstance(events, list):
        return {"threshold_events_not_list"}
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            reasons.add(f"threshold_event_not_object:{index}")
            continue
        event_id = event.get("event_id") if isinstance(event.get("event_id"), str) else str(index)
        if not isinstance(event.get("sequence"), int) or isinstance(event.get("sequence"), bool):
            reasons.add(f"threshold_sequence_invalid:{event_id}")
        if not isinstance(event.get("causal_refs"), list) or not all(isinstance(ref, str) for ref in event.get("causal_refs", [])):
            reasons.add(f"threshold_causal_refs_invalid:{event_id}")
        if event.get("type") == "escape-confirmed":
            key = event.get("escape_key")
            if not isinstance(key, dict) or any(not isinstance(key.get(field), str) for field in _ESCAPE_KEY_FIELDS):
                reasons.add(f"threshold_escape_key_invalid:{event_id}")
    return reasons


def _direct_root_attribution(activity: Any, root_id: str) -> bool:
    return (isinstance(activity, dict) and activity.get("attribution_mode") == "direct"
            and activity.get("root_cause_ids") == [root_id])


def _threshold_reference(item: Mapping[str, Any], kind: str) -> tuple[Any, bool]:
    """Return the typed reference; the old escape-named field is post-only."""
    typed = item.get("threshold_event_id")
    alias = item.get("threshold_escape_event_id")
    if kind == "historical-baseline":
        return typed, alias is None
    if typed is not None and alias is not None and typed != alias:
        return typed, False
    return typed if typed is not None else alias, True


_MODERN_ESCAPE_RELATIONSHIPS = {
    "exact-recurrence", "same-root-sibling", "repair-induced", "expected-fallout",
}


def _attempt_event_rows(
    context: ValidationContext, root_id: str, attempt_id: str, event_type: str,
) -> list[Mapping[str, Any]]:
    return [
        event for event in context.rows["events"]
        if event.get("type") == event_type
        and event.get("root_cause_id") == root_id
        and event.get("repair_attempt_id") == attempt_id
    ]


def _reservation_record_valid(
    context: ValidationContext, root_id: str, attempt: Mapping[str, Any],
) -> tuple[bool, Mapping[str, Any] | None]:
    """Validate the immutable reservation row and its exact event binding."""
    attempt_id = attempt.get("repair_attempt_id")
    reservation = context.indexes["events"].get(attempt.get("reservation_event_id"))
    required = globals().get("_MODERN_RESERVATION_FIELDS", ())
    causal = {
        root_id, attempt_id, attempt.get("strategy_id"),
        attempt.get("authorization_basis_id"), attempt.get("review_basis_id"),
    }
    causal.discard(None)
    valid = bool(
        isinstance(attempt_id, str)
        and not [field for field in required if field not in attempt]
        and attempt.get("record_kind") == "reservation"
        and attempt.get("root_cause_id") == root_id
        and attempt.get("status") == "planned"
        and attempt.get("started_at") is None
        and attempt.get("completed_at") is None
        and attempt.get("authorization_event_id") is None
        and isinstance(attempt.get("expected_authorization_event_id"), str)
        and bool(attempt.get("expected_authorization_event_id").strip())
        and parse_rfc3339(attempt.get("created_at")) is not None
        and isinstance(attempt.get("implementation_activity_ids"), list)
        and all(
            isinstance(value, str) and value.strip()
            for value in attempt.get("implementation_activity_ids") or []
        )
        and len(attempt.get("implementation_activity_ids") or [])
            == len(set(attempt.get("implementation_activity_ids") or []))
        and isinstance(attempt.get("verification_activity_ids"), list)
        and all(
            isinstance(value, str) and value.strip()
            for value in attempt.get("verification_activity_ids") or []
        )
        and len(attempt.get("verification_activity_ids") or [])
            == len(set(attempt.get("verification_activity_ids") or []))
        and not set(attempt.get("implementation_activity_ids") or []).intersection(
            attempt.get("verification_activity_ids") or []
        )
        and isinstance(reservation, Mapping)
        and reservation.get("type") == "repair-reserved"
        and reservation.get("reservation_event_id") == attempt.get("reservation_event_id")
        and reservation.get("root_cause_id") == root_id
        and reservation.get("repair_attempt_id") == attempt_id
        and reservation.get("strategy_id") == attempt.get("strategy_id")
        and reservation.get("review_basis_id") == attempt.get("authorization_basis_id")
        and reservation.get("expected_authorization_event_id")
            == attempt.get("expected_authorization_event_id")
        and parse_rfc3339(reservation.get("at")) == parse_rfc3339(attempt.get("created_at"))
        and isinstance(reservation.get("sequence"), int)
        and not isinstance(reservation.get("sequence"), bool)
        and causal.issubset(set(reservation.get("causal_refs") or []))
    )
    return valid, reservation if isinstance(reservation, Mapping) else None


def _attempt_bound_implementations(
    context: ValidationContext, root_id: str, attempt_id: str,
) -> tuple[list[Mapping[str, Any]], bool]:
    """Return all bound implementations and exact per-root binding validity."""
    rows: list[Mapping[str, Any]] = []
    valid = True
    for activity in context.rows["activities"]:
        if activity.get("type") != "implementation":
            continue
        bindings = activity.get("repair_attempt_bindings")
        matches = [
            binding for binding in bindings or []
            if isinstance(binding, Mapping)
            and binding.get("root_cause_id") == root_id
            and binding.get("repair_attempt_id") == attempt_id
        ]
        if not matches:
            continue
        rows.append(activity)
        root_bindings = [
            binding for binding in bindings or []
            if isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id
        ]
        if (
            len(matches) != 1
            or len(root_bindings) != 1
            or root_id not in (activity.get("root_cause_ids") or [])
        ):
            valid = False
    return rows, valid


def _adjudication_runtime_valid(activity: Any, *, require_astra: bool) -> bool:
    """Validate runtime identity without letting a label manufacture authority."""
    if not isinstance(activity, Mapping) or activity.get("status") != "completed":
        return False
    actual = activity.get("actual")
    if not isinstance(actual, Mapping):
        return False
    started_at = parse_rfc3339(activity.get("started_at"))
    completed_at = parse_rfc3339(activity.get("completed_at"))
    if started_at is None or completed_at is None or started_at > completed_at:
        return False
    if require_astra:
        return bool(
            activity.get("type") == "astra-adjudication"
            and activity.get("runtime_verified") is True
            and actual.get("model") == "gpt-6-astra"
            and actual.get("reasoning_effort") == "xhigh"
            and isinstance(actual.get("profile"), str) and actual.get("profile").strip()
            and isinstance(activity.get("runtime_evidence"), str)
            and activity.get("runtime_evidence").strip()
            and activity.get("runtime_unavailable_reason") is None
        )
    if activity.get("runtime_verified") is True:
        return bool(
            activity.get("type") in {"judgment", "astra-adjudication"}
            and all(isinstance(actual.get(field), str) and actual.get(field).strip()
                for field in ("model", "profile", "reasoning_effort"))
            and isinstance(activity.get("runtime_evidence"), str)
            and activity.get("runtime_evidence").strip()
            and activity.get("runtime_unavailable_reason") is None
        )
    return bool(
        activity.get("runtime_verified") is False
        and all(actual.get(field) is None for field in ("model", "profile", "reasoning_effort"))
        and activity.get("runtime_evidence") is None
        and isinstance(activity.get("runtime_unavailable_reason"), str)
        and activity.get("runtime_unavailable_reason").strip()
    )


def _execution_fact_common(
    context: ValidationContext,
    root_id: str,
    attempt: Mapping[str, Any],
    *,
    authorization_kind: str,
) -> tuple[Mapping[str, Any] | None, set[str]]:
    """Build one evidence-complete ordinary or Astra execution fact."""
    attempt_id = attempt.get("repair_attempt_id")
    reason = f"incident:{authorization_kind}_incomplete:{root_id}:{attempt_id}"
    if not isinstance(attempt_id, str):
        return None, {reason}
    reservation_ok, reservation = _reservation_record_valid(context, root_id, attempt)
    starts = _attempt_event_rows(context, root_id, attempt_id, "repair-attempted")
    settlements = _attempt_event_rows(context, root_id, attempt_id, "repair-threshold-settled")
    grants = _attempt_event_rows(context, root_id, attempt_id, "astra-adjudicated")
    begins = _attempt_event_rows(context, root_id, attempt_id, "astra-adjudication-started")
    start = starts[0] if len(starts) == 1 else None
    settlement = settlements[0] if len(settlements) == 1 else None
    grant = grants[0] if len(grants) == 1 else None
    begin = begins[0] if len(begins) == 1 else None
    impl_ids = (start or {}).get("implementation_activity_ids")
    if not (
        reservation_ok and isinstance(reservation, Mapping)
        and len(starts) == len(settlements) == len(grants) == 1
        and isinstance(impl_ids, list) and bool(impl_ids)
        and all(isinstance(value, str) and value.strip() for value in impl_ids)
        and len(impl_ids) == len(set(impl_ids))
    ):
        return None, {reason}
    bound, bindings_ok = _attempt_bound_implementations(context, root_id, attempt_id)
    bound_ids = [activity.get("activity_id") for activity in bound]
    activities = context.indexes["activities"]
    impl_rows = [activities.get(activity_id) for activity_id in impl_ids]
    strategy = context.indexes["strategies"].get(attempt.get("strategy_id"))
    adjudication = activities.get((grant or {}).get("adjudication_activity_id"))
    terminal = (settlement or {}).get("terminal_outcome")
    completion_times = [parse_rfc3339((activity or {}).get("completed_at")) for activity in impl_rows]
    max_completion = max((value for value in completion_times if value is not None), default=None)
    start_at = parse_rfc3339((start or {}).get("started_at"))
    settled_at = parse_rfc3339((settlement or {}).get("settled_at"))
    mutation_finished_at = parse_rfc3339((settlement or {}).get("mutation_finished_at"))
    event_at = parse_rfc3339((settlement or {}).get("at"))
    seq = lambda row: row.get("sequence") if isinstance(row, Mapping) and isinstance(row.get("sequence"), int) and not isinstance(row.get("sequence"), bool) else None
    statuses = [activity.get("status") for activity in impl_rows if isinstance(activity, Mapping)]
    outcome_ok = (
        (terminal == "succeeded" and bool(statuses) and all(status == "completed" for status in statuses))
        or (terminal == "failed" and any(status == "failed" for status in statuses))
        or (terminal == "cancelled" and bool(statuses) and all(status == "cancelled" for status in statuses))
        or (terminal == "superseded" and any(status in {"failed", "cancelled"} for status in statuses))
    )
    attempt_impl = attempt.get("implementation_activity_ids")
    attempt_verify = attempt.get("verification_activity_ids")
    ordinary = authorization_kind == "ordinary"
    arrays_ok = (
        attempt_impl == [] and attempt_verify == []
        and grant.get("implementation_activity_ids") == []
        if ordinary else
        attempt_impl == impl_ids and isinstance(attempt_verify, list)
        and len(attempt_verify) == len(set(attempt_verify))
        and not set(attempt_impl or []).intersection(attempt_verify)
        and grant.get("implementation_activity_ids") == impl_ids
    )
    sequence_values = [seq(grant), seq(reservation), seq(start), seq(settlement)]
    if not ordinary:
        sequence_values.append(seq(begin))
    sequence_ok = all(value is not None for value in sequence_values) and (
        seq(grant) < seq(reservation) < seq(start) < seq(settlement)
        if ordinary else
        seq(reservation) < seq(begin) < seq(grant) < seq(start) < seq(settlement)
    )
    grant_common = bool(
        grant.get("disposition") == "approved"
        and grant.get("event_id") == attempt.get("expected_authorization_event_id")
        and grant.get("root_cause_id") == root_id
        and grant.get("repair_attempt_id") == attempt_id
        and grant.get("strategy_id") == attempt.get("strategy_id")
        and grant.get("successor_strategy_id") == attempt.get("strategy_id")
        and grant.get("review_basis_id") == attempt.get("review_basis_id")
        and grant.get("authorization_basis_id") == attempt.get("authorization_basis_id")
        and grant.get("authorization_basis_id") == attempt.get("authorization_basis_id")
        and isinstance(strategy, Mapping) and strategy.get("root_cause_id") == root_id
        and strategy.get("strategy_id") == attempt.get("strategy_id")
        and strategy.get("astra_adjudication_activity_id") == grant.get("adjudication_activity_id")
        and _adjudication_runtime_valid(adjudication, require_astra=not ordinary)
        and root_id in (adjudication.get("root_cause_ids") or [])
    )
    astra_common = True
    if not ordinary:
        root = context.indexes["roots"].get(root_id) or {}
        anchor = root.get("threshold_anchor") if isinstance(root.get("threshold_anchor"), Mapping) else {}
        anchor_id = (
            anchor.get("threshold_escape_event_id")
            if anchor.get("kind") == "post-cutover-escape"
            else anchor.get("historical_threshold_reconciled_event_id")
        )
        activation_id = root.get("first_threshold_activation_event_id")
        trigger_id = grant.get("decision_trigger_event_id")
        epoch_id = grant.get("authorization_epoch_event_id")
        trigger = context.indexes["events"].get(trigger_id)
        epoch = context.indexes["events"].get(epoch_id)
        astra_common = bool(
            len(begins) == 1 and isinstance(begin, Mapping)
            and grant.get("adjudication_start_event_id") == begin.get("event_id")
            and begin.get("adjudication_activity_id") == grant.get("adjudication_activity_id")
            and begin.get("strategy_id") == attempt.get("strategy_id")
            and begin.get("review_basis_id") == attempt.get("authorization_basis_id")
            and parse_rfc3339(begin.get("at")) == parse_rfc3339(adjudication.get("started_at"))
            and grant.get("threshold_event_id", grant.get("threshold_escape_event_id")) == anchor_id
            and grant.get("activation_anchor_event_id", anchor_id) == anchor_id
            and grant.get("first_threshold_activation_event_id") == activation_id
            and attempt.get("authorization_epoch_event_id") == epoch_id
            and isinstance(trigger, Mapping) and trigger.get("root_cause_id") == root_id
            and isinstance(epoch, Mapping) and epoch.get("root_cause_id") == root_id
            and seq(trigger) is not None and seq(trigger) < seq(begin)
            and seq(epoch) is not None and seq(epoch) < seq(begin)
            and strategy.get("materially_different_from_predecessors") is True
            and strategy.get("disposition") == "approved"
            and _nonblank_sorted_unique(strategy.get("decision_evidence_refs"))
            and grant.get("decision_evidence_refs") == strategy.get("decision_evidence_refs")
        )
    exact_start = {
        root_id, attempt_id, attempt.get("strategy_id"), attempt.get("review_basis_id"),
        grant.get("event_id"), *impl_ids,
    }
    exact_start.discard(None)
    exact_settlement = {root_id, attempt_id, start.get("event_id")}
    exact_settlement.discard(None)
    valid = bool(
        grant_common and astra_common and arrays_ok and sequence_ok and bindings_ok
        and set(impl_ids) == set(bound_ids) and len(bound_ids) == len(set(bound_ids))
        and start.get("strategy_id") == attempt.get("strategy_id")
        and start.get("review_basis_id") == attempt.get("review_basis_id")
        and start.get("authorization_basis_id", start.get("review_basis_id"))
            == attempt.get("authorization_basis_id")
        and start.get("authorization_event_id") == grant.get("event_id")
        and settlement.get("start_event_id") == start.get("event_id")
        and settlement.get("review_basis_id") == attempt.get("review_basis_id")
        and terminal in {"succeeded", "failed", "superseded", "cancelled"}
        and all(
            isinstance(activity, Mapping)
            and activity.get("type") == "implementation"
            and activity.get("status") in {"completed", "failed", "cancelled"}
            and parse_rfc3339(activity.get("started_at")) is not None
            and parse_rfc3339(activity.get("completed_at")) is not None
            and start_at is not None
            and start_at <= parse_rfc3339(activity.get("started_at"))
                <= parse_rfc3339(activity.get("completed_at"))
            for activity in impl_rows
        )
        and outcome_ok and max_completion is not None
        and mutation_finished_at == max_completion
        and start_at is not None and settled_at is not None and event_at is not None
        and start_at <= max_completion <= settled_at <= event_at
        and exact_start.issubset(set(start.get("causal_refs") or []))
        and exact_settlement.issubset(set(settlement.get("causal_refs") or []))
    )
    if not valid:
        return None, {reason}
    return {
        "authorization_kind": authorization_kind,
        "attempt": attempt,
        "reservation": reservation,
        "grant": grant,
        "adjudication_begin": begin,
        "adjudication_activity": adjudication,
        "start": start,
        "settlement": settlement,
        "implementation_activity_ids": list(impl_ids),
        "terminal_outcome": terminal,
    }, set()


def _ordinary_attempt_fact(context: ValidationContext, root_id: str, attempt: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, set[str]]:
    """Construct one complete, non-authorizing ordinary attempt fact.

    This is intentionally independent of threshold binding.  It is the only
    admissible source for a lower-bound incident, preventing malformed
    reservation history from becoming a convenient fallback to legacy rules.
    """
    fact, reasons = _execution_fact_common(
        context, root_id, attempt, authorization_kind="ordinary",
    )
    if fact is None:
        reasons.add(f"incident:ordinary:{root_id}:{attempt.get('repair_attempt_id')}")
    return fact, reasons


def _astra_attempt_fact(context: ValidationContext, root_id: str, attempt: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, set[str]]:
    return _execution_fact_common(context, root_id, attempt, authorization_kind="astra")


def _modern_escape_incidents(context: ValidationContext, root_id: str) -> tuple[list[Mapping[str, Any]], set[str]]:
    """Return evidence-complete post-cutover incidents for a modern root.

    A lower-bound is deliberately narrower than legacy escape causality.  It
    is only a procedural threshold signal; it cannot reconcile historical
    escapes or manufacture a lifetime count.  Keeping the reconstruction here
    also lets the generic escape rule dispatch on the linked attempt instead
    of accidentally changing the interpretation of a mixed legacy root.
    """
    events = context.indexes["events"]
    attempts = context.indexes["repair_attempts"]
    observations = context.indexes["observations"]
    activities = context.indexes["activities"]
    reasons: set[str] = set()
    incidents: list[Mapping[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    seen_observations: set[str] = set()
    candidates = sorted(
        (event for event in context.rows["events"]
         if event.get("type") == "escape-confirmed" and event.get("root_cause_id") == root_id),
        key=lambda event: (event.get("sequence", -1), event.get("event_id", "")),
    )
    for escape in candidates:
        event_id = str(escape.get("event_id", "none"))
        attempt_id = escape.get("repair_attempt_id")
        attempt = attempts.get(attempt_id) if isinstance(attempt_id, str) else None
        # Non-reservation escape rows remain under the exact legacy rules.
        if not isinstance(attempt, Mapping) or attempt.get("record_kind") != "reservation":
            continue
        execution, ordinary_reasons = _ordinary_attempt_fact(context, root_id, attempt)
        astra_reasons: set[str] = set()
        if execution is None:
            execution, astra_reasons = _astra_attempt_fact(context, root_id, attempt)
        if execution is None:
            reasons.update(ordinary_reasons)
            reasons.update(astra_reasons)
            reasons.add(f"incident:lineage:{root_id}:{event_id}")
            continue
        observation_id = escape.get("observation_id")
        observation = observations.get(observation_id) if isinstance(observation_id, str) else None
        key_data = escape.get("escape_key") if isinstance(escape.get("escape_key"), Mapping) else {}
        key = tuple(key_data.get(field) for field in _ESCAPE_KEY_FIELDS)
        if key in seen_keys:
            reasons.add(f"incident:duplicate_key:{root_id}:{event_id}")
            continue
        valid_key = (all(isinstance(value, str) and value for value in key)
                     and key == (root_id, attempt_id, escape.get("review_basis_id"), escape.get("cycle_id")))
        if not valid_key:
            reasons.add(f"incident:key:{root_id}:{event_id}")
            continue
        if not isinstance(observation_id, str) or observation_id in seen_observations:
            reasons.add(f"incident:duplicate_observation:{root_id}:{event_id}")
            continue
        seen_keys.add(key); seen_observations.add(observation_id)
        start = execution["start"]
        settlement = execution["settlement"]
        impl_ids = execution["implementation_activity_ids"]
        impl_rows = [activities.get(activity_id) for activity_id in impl_ids]
        escape_at = parse_rfc3339(escape.get("at")); observed_at = parse_rfc3339((observation or {}).get("observed_at"))
        settled_at = parse_rfc3339((settlement or {}).get("settled_at")); start_at = parse_rfc3339((start or {}).get("started_at"))
        terminal = (settlement or {}).get("terminal_outcome")
        sequence_ok = all(isinstance(row.get("sequence"), int) and not isinstance(row.get("sequence"), bool)
                          for row in (escape, start or {}, settlement or {}))
        impl_ok = bool(impl_ids) and all(
            isinstance(activity, Mapping) and activity.get("type") == "implementation"
            and activity.get("status") in {"completed", "failed", "cancelled"}
            and parse_rfc3339(activity.get("completed_at")) is not None
            and parse_rfc3339(activity.get("completed_at")) <= observed_at
            and any(isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id
                    and binding.get("repair_attempt_id") == attempt_id
                    for binding in (activity.get("repair_attempt_bindings") or []))
            for activity in impl_rows
        )
        reopen = [event for event in context.rows["events"] if event.get("type") == "root-reopened"
                  and event.get("root_cause_id") == root_id and event.get("observation_id") == observation_id
                  and event.get("repair_attempt_id") == attempt_id and event.get("cycle_id") == escape.get("cycle_id")]
        reopen_ok = any(
            parse_rfc3339(item.get("at")) is not None and escape_at is not None and observed_at is not None
            and parse_rfc3339(item.get("at")) >= max(escape_at, observed_at)
            and item.get("sequence", -1) > escape.get("sequence", -1)
            and {root_id, event_id, observation_id, attempt_id, escape.get("review_basis_id"), escape.get("cycle_id")}
                .issubset(set(item.get("causal_refs") or []))
            for item in reopen
        )
        causal = set(escape.get("causal_refs") or [])
        common = {root_id, attempt_id, escape.get("review_basis_id"), escape.get("cycle_id"), observation_id}
        valid = (
            isinstance(observation, Mapping) and observation.get("confirmed") is True and observation.get("pre_cutover") is False
            and observation.get("root_relationship") in _MODERN_ESCAPE_RELATIONSHIPS
            and observation.get("root_relationship") == escape.get("root_relationship")
            and (observation.get("root_cause_id"), observation.get("repair_attempt_id"), observation.get("review_basis_id"), observation.get("detected_cycle_id"))
                == (root_id, attempt_id, escape.get("review_basis_id"), escape.get("cycle_id"))
            and attempt.get("root_cause_id") == root_id and attempt.get("strategy_id") == (start or {}).get("strategy_id")
            and isinstance(start, Mapping) and isinstance(settlement, Mapping)
            and start.get("authorization_event_id") in (start.get("causal_refs") or [])
            and set(impl_ids).issubset(set(start.get("causal_refs") or []))
            and settlement.get("start_event_id") == start.get("event_id")
            and {root_id, attempt_id, start.get("event_id")}.issubset(set(settlement.get("causal_refs") or []))
            and set(impl_ids).issubset(set(settlement.get("causal_refs") or []) | set(start.get("causal_refs") or []))
            and terminal in {"succeeded", "failed", "superseded", "cancelled"}
            and start_at is not None and settled_at is not None and observed_at is not None and escape_at is not None
            and start_at <= settled_at <= observed_at <= escape_at
            and impl_ok and sequence_ok and common.issubset(causal) and reopen_ok
        )
        if not valid:
            reasons.add(f"incident:lineage:{root_id}:{event_id}")
            continue
        incidents.append(escape)
    return incidents, reasons


def _retained_preactivation_attempt(
    context: ValidationContext, root_id: str, attempt: Mapping[str, Any], activation: Mapping[str, Any],
) -> tuple[bool, Mapping[str, Any] | None]:
    """Validate a completed ordinary repair retained before first binding.

    These rows are evidence, not retroactive authority.  They must be whole
    and causally bounded before activation, or the lower-bound path rejects
    the ledger rather than silently hiding an old mutation.
    """
    events = context.indexes["events"]; activities = context.indexes["activities"]
    attempt_id = attempt.get("repair_attempt_id")
    if not isinstance(attempt_id, str):
        return False, None
    ordinary, ordinary_reasons = _ordinary_attempt_fact(context, root_id, attempt)
    if ordinary is None or ordinary_reasons:
        return False, None
    starts = [event for event in context.rows["events"] if event.get("type") == "repair-attempted"
              and event.get("root_cause_id") == root_id and event.get("repair_attempt_id") == attempt_id]
    settlements = [event for event in context.rows["events"] if event.get("type") == "repair-threshold-settled"
                   and event.get("root_cause_id") == root_id and event.get("repair_attempt_id") == attempt_id]
    grants = [event for event in context.rows["events"] if event.get("type") == "astra-adjudicated"
              and event.get("root_cause_id") == root_id and event.get("repair_attempt_id") == attempt_id
              and event.get("disposition") == "approved"]
    start = ordinary["start"]
    settlement = ordinary["settlement"]
    grant = ordinary["grant"]
    impl_ids = list((start or {}).get("implementation_activity_ids") or [])
    bound = [activity for activity in context.rows["activities"] if any(
        isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id
        and binding.get("repair_attempt_id") == attempt_id
        for binding in (activity.get("repair_attempt_bindings") or [])
    )]
    bound_ids = {activity.get("activity_id") for activity in bound if activity.get("type") == "implementation"}
    activation_at = parse_rfc3339(activation.get("effective_at"))
    created_at = parse_rfc3339(attempt.get("created_at"))
    temporal_values = [
        created_at, parse_rfc3339(ordinary["reservation"].get("at")), parse_rfc3339((start or {}).get("at")), parse_rfc3339((start or {}).get("started_at")),
        parse_rfc3339((grant or {}).get("at")), parse_rfc3339((settlement or {}).get("at")),
        parse_rfc3339((settlement or {}).get("settled_at")),
        *(parse_rfc3339(activity.get("started_at")) for activity in bound),
        *(parse_rfc3339(activity.get("completed_at")) for activity in bound),
    ]
    before_activation = activation_at is not None and all(value is not None and value < activation_at for value in temporal_values)
    terminal = (settlement or {}).get("terminal_outcome")
    impl_ok = bool(impl_ids) and set(impl_ids) == bound_ids and all(
        activity.get("status") in {"completed", "failed", "cancelled"}
        and parse_rfc3339(activity.get("completed_at")) is not None
        for activity in bound
    )
    pointers_ok = (attempt.get("record_kind") == "reservation" and attempt.get("status") == "planned"
                   and attempt.get("implementation_activity_ids") == [] and attempt.get("verification_activity_ids") == []
                   and isinstance(start, Mapping) and isinstance(settlement, Mapping) and isinstance(grant, Mapping)
                   and start.get("authorization_event_id") == grant.get("event_id")
                   and settlement.get("start_event_id") == start.get("event_id")
                   and terminal in {"succeeded", "failed", "superseded", "cancelled"}
                   and start.get("strategy_id") == attempt.get("strategy_id")
                   and start.get("review_basis_id") == attempt.get("review_basis_id")
                   and grant.get("strategy_id") == attempt.get("strategy_id")
                   and grant.get("review_basis_id") == attempt.get("review_basis_id")
                   and {root_id, attempt_id, grant.get("event_id"), *impl_ids}.issubset(set(start.get("causal_refs") or []))
                   and {root_id, attempt_id, start.get("event_id")}.issubset(set(settlement.get("causal_refs") or [])))
    return bool(before_activation and impl_ok and pointers_ok), start


def _unbound_root_admission(
    context: ValidationContext, root_id: str, attempts: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Mapping[str, Any]], set[str]]:
    """Totally admit every reservation and rooted/bound mutation pre-binding.

    This pass deliberately runs before an unresolved or binding-pending root
    can return.  Future pointer values are planning data; an existing event or
    activity behind one of those pointers is evidence and must be complete.
    """
    reasons: set[str] = set()
    facts: dict[str, Mapping[str, Any]] = {}
    consumed: Counter[str] = Counter()
    claimed: set[str] = set()
    attempt_ids = {
        attempt.get("repair_attempt_id") for attempt in attempts
        if isinstance(attempt.get("repair_attempt_id"), str)
    }
    for attempt in attempts:
        attempt_id = attempt.get("repair_attempt_id")
        prefix = f"{root_id}:{attempt_id}"
        reservation_ok, reservation = _reservation_record_valid(context, root_id, attempt)
        starts = _attempt_event_rows(context, root_id, str(attempt_id), "repair-attempted")
        settlements = _attempt_event_rows(context, root_id, str(attempt_id), "repair-threshold-settled")
        grants = _attempt_event_rows(context, root_id, str(attempt_id), "astra-adjudicated")
        begins = _attempt_event_rows(context, root_id, str(attempt_id), "astra-adjudication-started")
        expected = context.indexes["events"].get(attempt.get("expected_authorization_event_id"))
        bound, bindings_ok = _attempt_bound_implementations(context, root_id, str(attempt_id))
        for row in (*starts, *grants):
            claimed.update(
                value for value in (row.get("implementation_activity_ids") or [])
                if isinstance(value, str)
            )
        claimed.update(
            value for value in (attempt.get("implementation_activity_ids") or [])
            if isinstance(value, str)
        )
        strategy = context.indexes["strategies"].get(attempt.get("strategy_id")) or {}
        adjudication_id = strategy.get("astra_adjudication_activity_id")
        adjudication_exists = isinstance(adjudication_id, str) and adjudication_id in context.indexes["activities"]
        harmless = bool(
            reservation_ok and isinstance(reservation, Mapping)
            and attempt.get("implementation_activity_ids") == []
            and attempt.get("verification_activity_ids") == []
            and not starts and not settlements and not grants and not begins
            and expected is None and not bound and not adjudication_exists
        )
        if harmless:
            facts[str(attempt_id)] = {
                "record_kind": "reservation", "lifecycle_state": "planned",
                "reservation_event_id": attempt.get("reservation_event_id"),
                "reservation_sequence": reservation.get("sequence"),
                "grant_event_id": None, "start_event_id": None, "settlement_event_id": None,
                "historical_nonauthorizing": True, "completion_eligible": False,
                "threshold_affected": False, "mutation_activity_ids": [],
            }
            continue
        execution, ordinary_reasons = _ordinary_attempt_fact(context, root_id, attempt)
        astra_reasons: set[str] = set()
        if execution is None:
            execution, astra_reasons = _astra_attempt_fact(context, root_id, attempt)
        if execution is None:
            reasons.update(ordinary_reasons)
            reasons.update(astra_reasons)
            if not reservation_ok:
                reasons.add(f"lc:attempt_record:{prefix}")
            if any((starts, settlements, grants, begins, bound, expected is not None, adjudication_exists)):
                reasons.add(f"auth:unbound_plan_not_empty:{prefix}")
            reasons.add(f"auth:unbound_attempt_incomplete:{prefix}")
            if not bindings_ok or len({row.get('activity_id') for row in bound}) != len(bound):
                reasons.add(f"auth:unbound_binding_cardinality:{prefix}")
            continue
        impl_ids = list(execution.get("implementation_activity_ids") or [])
        consumed.update(impl_ids)
        facts[str(attempt_id)] = {
            "record_kind": "reservation", "lifecycle_state": "retained-preactivation",
            "reservation_event_id": (execution.get("reservation") or {}).get("event_id"),
            "reservation_sequence": (execution.get("reservation") or {}).get("sequence"),
            "grant_event_id": (execution.get("grant") or {}).get("event_id"),
            "start_event_id": (execution.get("start") or {}).get("event_id"),
            "settlement_event_id": (execution.get("settlement") or {}).get("event_id"),
            "admission_authorization_kind": execution.get("authorization_kind"),
            "historical_nonauthorizing": True, "completion_eligible": False,
            "threshold_affected": False, "mutation_activity_ids": impl_ids,
        }

    reservation_boundaries = [
        parse_rfc3339(attempt.get("created_at"))
        for attempt in attempts
        if parse_rfc3339(attempt.get("created_at")) is not None
    ]
    first_reservation_at = min(reservation_boundaries, default=None)
    for activity in context.rows["activities"]:
        activity_id = activity.get("activity_id")
        bindings = activity.get("repair_attempt_bindings") or []
        rooted = root_id in (activity.get("root_cause_ids") or [])
        bound_to_root = any(
            isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id
            for binding in bindings
        )
        mutation = (
            activity.get("type") == "implementation" and (rooted or bound_to_root)
        ) or activity_id in claimed
        if not mutation or not isinstance(activity_id, str):
            continue
        matching = [
            binding for binding in bindings
            if isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id
        ]
        owners = [binding.get("repair_attempt_id") for binding in matching]
        # Retained legacy implementation history predating the first modern
        # reservation is outside that reservation's authority graph.  It stays
        # visible to the legacy validator, but cannot be mistaken for a hidden
        # or unbound modern mutation because it is neither claimed nor bound
        # and its terminal time precedes the reservation boundary.
        completed_at = parse_rfc3339(activity.get("completed_at"))
        if (
            not matching and activity_id not in claimed
            and first_reservation_at is not None and completed_at is not None
            and completed_at < first_reservation_at
        ):
            continue
        if (
            consumed[activity_id] != 1
            or len(matching) != 1
            or owners[0] not in attempt_ids
            or activity.get("type") != "implementation"
        ):
            reasons.add(f"auth:unbound_mutation_unbound:{root_id}:{activity_id}")
            if len(matching) != 1:
                reasons.add(f"auth:unbound_binding_cardinality:{root_id}:{owners[0] if owners else 'none'}")
    return facts, reasons


def _legacy_threshold_lifecycle(context: ValidationContext) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """The sole active threshold/lifecycle interpretation used by production."""
    ledger = context.ledger
    reasons: set[str] = set()
    events = {event.get("event_id"): event for event in ledger.get("events", []) if isinstance(event, dict)}
    strategies = {item.get("strategy_id"): item for item in ledger.get("strategies", []) if isinstance(item, dict)}
    activities = {item.get("activity_id"): item for item in ledger.get("activities", []) if isinstance(item, dict)}
    attempts = [item for item in ledger.get("repair_attempts", []) if isinstance(item, dict)]
    facts: dict[str, dict[str, Any]] = {}
    for root in ledger.get("roots", []):
        if not isinstance(root, dict) or not isinstance(root.get("root_cause_id"), str):
            continue
        root_id = root["root_cause_id"]
        baseline = root.get("historical_escape_count_baseline")
        unique = _unique_escape_events(ledger.get("events"), root_id)
        fact: dict[str, Any] = {"baseline": baseline, "baseline_resolved": isinstance(baseline, int),
                                "unique_incident_count": len(unique), "lifetime_count": None,
                                "threshold_kind": None, "threshold_event_id": None,
                                "reconciliation_valid": False, "anchor_valid": False,
                                "authorization": None, "awaiting_astra": False}
        if not isinstance(baseline, int):
            if root.get("state") in {"closure_pending", "closed_verified"}:
                reasons.add(f"historical_baseline_unresolved:{root_id}")
            facts[root_id] = fact
            continue
        fact["lifetime_count"] = baseline + len(unique)
        raw_escapes = [event for event in ledger.get("events", []) if isinstance(event, dict)
                       and event.get("type") == "escape-confirmed" and event.get("root_cause_id") == root_id]
        if len(raw_escapes) != len(unique):
            reasons.add(f"escape_tuple_duplicate:{root_id}")
        if root.get("escape_count_lifetime") is not None and root.get("escape_count_lifetime") != fact["lifetime_count"]:
            reasons.add(f"escape_lifetime_stale:{root_id}")
        if baseline >= 2:
            fact["threshold_kind"] = "historical-baseline"
            anchor = root.get("threshold_anchor")
            event_id = anchor.get("historical_threshold_reconciled_event_id") if isinstance(anchor, dict) else None
            fact["threshold_event_id"] = event_id
            event = events.get(event_id)
            refs = root.get("historical_escape_evidence_refs")
            canonical_refs = event.get("evidence_refs") if isinstance(event, dict) else None
            legacy_refs = event.get("historical_evidence_refs") if isinstance(event, dict) else None
            adoption = parse_rfc3339((ledger.get("cutover") or {}).get("protocol_adopted_at"))
            historical_legacy = (isinstance(legacy_refs, list) and _nonblank_sorted_unique(legacy_refs)
                                 and parse_rfc3339((event or {}).get("at")) is not None and adoption is not None
                                 and parse_rfc3339(event.get("at")) <= adoption)
            if canonical_refs is not None and legacy_refs is not None and set(canonical_refs) != set(legacy_refs):
                reasons.add(f"compat:conflict:{root_id}")
            valid = (isinstance(anchor, dict) and anchor.get("kind") == "historical-baseline"
                     and anchor.get("reconciled_baseline") == baseline and isinstance(event, dict)
                     and event.get("type") == "historical-threshold-reconciled" and event.get("root_cause_id") == root_id
                     and event.get("reconciled_baseline") == baseline
                     and (historical_legacy or _nonblank_sorted_unique(refs))
                     and ((canonical_refs == refs) or historical_legacy) and root_id in event.get("causal_refs", []))
            fact["reconciliation_valid"] = valid
            fact["anchor_valid"] = valid
            if not valid:
                reasons.add(f"threshold_anchor_historical_invalid:{root_id}")
        elif fact["lifetime_count"] >= 2:
            expected = unique[1 - baseline]
            fact["threshold_kind"] = "post-cutover-escape"
            fact["threshold_event_id"] = expected.get("event_id")
            anchor = root.get("threshold_anchor")
            if anchor is None:
                reasons.add(f"threshold_anchor_required:{root_id}")
            elif not isinstance(anchor, dict):
                reasons.add(f"threshold_anchor_invalid:{root_id}")
            elif anchor.get("kind") != "post-cutover-escape":
                reasons.add(f"threshold_anchor_kind:{root_id}")
            elif anchor.get("threshold_escape_event_id") != expected.get("event_id"):
                reasons.add(f"threshold_anchor_not_threshold:{root_id}")
            else:
                fact["anchor_valid"] = True
        fact.update({"attempt_results": {}, "authorized_attempt_ids": [], "unauthorized_attempt_ids": [],
                     "planned_attempt_ids": [], "uncovered_implementation_activity_ids": [],
                     "current_authorization_epoch_event_id": None})
        if fact["threshold_event_id"] and fact["anchor_valid"]:
            threshold = events.get(fact["threshold_event_id"])
            threshold_at = parse_rfc3339((threshold or {}).get("at"))
            epoch_events = [event for event in [threshold, *unique] if isinstance(event, dict)]

            def epoch_for(attempt_start: Any) -> dict[str, Any]:
                eligible = [event for event in epoch_events if attempt_start is None or (parse_rfc3339(event.get("at")) or attempt_start) <= attempt_start]
                return eligible[-1] if eligible else (threshold or {})

            fact["current_authorization_epoch_event_id"] = epoch_for(None).get("event_id")
            covered: set[str] = set()
            for attempt in attempts:
                if attempt.get("root_cause_id") != root_id:
                    continue
                attempt_id = attempt.get("repair_attempt_id")
                started = parse_rfc3339(attempt.get("started_at"))
                completed = parse_rfc3339(attempt.get("completed_at"))
                # Compatibility is finite: historic summaries retain only the
                # enumerated terminal vocabulary and never acquire a free-form
                # legacy exemption.
                if attempt.get("record_kind") is None and attempt.get("status") not in {
                    "planned", "closed", "completed", "succeeded", "failed", "superseded", "cancelled",
                    "completed-verified-exact-boundary", "completed-with-post-repair-escape",
                }:
                    reasons.add(f"lc:attempt_record:{root_id}:{attempt_id}")
                # Bounded compatibility: a pre-adoption legacy summary is
                # historical evidence only.  It can neither inherit a modern
                # grant nor become an uncovered post-threshold mutation.
                if (baseline >= 2 and attempt.get("record_kind") is None and completed is not None
                        and adoption is not None and completed <= adoption):
                    continue
                implementation_ids = attempt.get("implementation_activity_ids") if isinstance(attempt.get("implementation_activity_ids"), list) else []
                claimed = any(attempt.get(field) is not None for field in ("authorization_event_id", "authorization_basis_id", "authorization_epoch_event_id"))
                relevant = bool(threshold_at and started and started > threshold_at) or (started is None and (claimed or implementation_ids))
                if not relevant:
                    continue
                status = attempt.get("status")
                terminal_statuses = {"closed", "completed", "succeeded", "completed-verified-exact-boundary"}
                active_statuses = {"running", "active"}
                planned = status == "planned" and started is None and completed is None
                attempt_state_ok = (planned or (status in terminal_statuses and started is not None and completed is not None)
                                    or (status in active_statuses and started is not None and completed is None))
                epoch = epoch_for(started)
                epoch_id = epoch.get("event_id")
                strategy = strategies.get(attempt.get("strategy_id"))
                event = events.get(attempt.get("authorization_event_id"))
                activity = activities.get((event or {}).get("adjudication_activity_id"))
                ref, ref_ok = _threshold_reference(strategy or {}, fact["threshold_kind"])
                event_ref, event_ref_ok = _threshold_reference(event or {}, fact["threshold_kind"])
                evidence = (strategy or {}).get("decision_evidence_refs")
                predecessors = (strategy or {}).get("failed_predecessor_strategy_ids")
                predecessor_ok = isinstance(predecessors, list) and bool(predecessors) and len(predecessors) == len(set(predecessors))
                for predecessor in predecessors or []:
                    predecessor_ok = predecessor_ok and bool(strategies.get(predecessor) and any(
                        item.get("root_cause_id") == root_id and item.get("strategy_id") == predecessor and item.get("status") in {"failed", "superseded"} for item in attempts))
                implementation_rows = [activities.get(activity_id) for activity_id in implementation_ids]
                implementation_ok = (len(implementation_ids) == len(set(implementation_ids))
                    and isinstance((event or {}).get("implementation_activity_ids"), list)
                    and (event or {}).get("implementation_activity_ids") == implementation_ids
                    and (planned or all(isinstance(item, dict) and _direct_root_attribution(item, root_id)
                            and item.get("repair_attempt_id") == attempt_id
                            and item.get("type") == "implementation"
                            and parse_rfc3339(item.get("started_at"))
                            and (planned or started <= parse_rfc3339(item.get("started_at")))
                            and ((status in terminal_statuses and item.get("status") == "completed"
                                 and parse_rfc3339(item.get("completed_at"))
                                 and completed is not None and parse_rfc3339(item.get("completed_at")) <= completed)
                                 or (status in active_statuses and item.get("status") == "running"
                                     and item.get("completed_at") is None))
                            for item in implementation_rows)))
                activity_start = parse_rfc3339((activity or {}).get("started_at")); activity_done = parse_rfc3339((activity or {}).get("completed_at"))
                event_at = parse_rfc3339((event or {}).get("at")); epoch_at = parse_rfc3339(epoch.get("at"))
                causal = {fact["threshold_event_id"], epoch_id, root_id, attempt_id, attempt.get("authorization_basis_id"),
                          (strategy or {}).get("strategy_id"), (event or {}).get("adjudication_activity_id"), *implementation_ids}
                causal.discard(None)
                chronology_ok = bool(threshold_at and epoch_at and activity_start and activity_done and event_at
                    and threshold_at <= epoch_at < activity_start <= activity_done <= event_at
                    and (planned or (started and completed and event_at < started)))
                planned_ok = attempt_state_ok and (not planned or not any(isinstance(item, dict) for item in implementation_rows))
                approved = (
                    isinstance(strategy, dict) and strategy.get("root_cause_id") == root_id
                    and ref_ok and event_ref_ok and ref == fact["threshold_event_id"] == event_ref
                    and isinstance(event, dict) and event.get("type") == "astra-adjudicated" and event.get("root_cause_id") == root_id
                    and event.get("repair_attempt_id") == attempt_id and event.get("successor_strategy_id") == strategy.get("strategy_id")
                    and event.get("adjudication_activity_id") == strategy.get("astra_adjudication_activity_id")
                    and event.get("authorization_basis_id") == attempt.get("authorization_basis_id")
                    and event.get("authorization_epoch_event_id") == attempt.get("authorization_epoch_event_id") == epoch_id
                    and event.get("disposition") == strategy.get("disposition") == "approved"
                    and _nonblank_sorted_unique(evidence) and event.get("decision_evidence_refs") == evidence
                    and causal.issubset(set(event.get("causal_refs", []))) and strategy.get("materially_different_from_predecessors") is True and predecessor_ok
                    and isinstance(activity, dict) and activity.get("type") == "astra-adjudication" and activity.get("status") == "completed"
                    and activity.get("runtime_verified") is True and (activity.get("actual") or {}).get("model") == "gpt-6-astra"
                    and isinstance((activity.get("actual") or {}).get("reasoning_effort"), str) and bool((activity.get("actual") or {}).get("reasoning_effort"))
                    and isinstance((activity.get("actual") or {}).get("profile"), str) and bool((activity.get("actual") or {}).get("profile"))
                    and isinstance(activity.get("runtime_evidence"), str) and bool(activity.get("runtime_evidence"))
                    and _direct_root_attribution(activity, root_id) and fact["threshold_event_id"] in (activity.get("causal_refs") or [])
                    and implementation_ok and chronology_ok and planned_ok)
                fact["attempt_results"][str(attempt_id)] = {"authorized": approved, "planned": planned,
                    "authorization_event_id": attempt.get("authorization_event_id"), "authorization_epoch_event_id": epoch_id,
                    "uncovered_implementation_activity_ids": [] if implementation_ok else implementation_ids}
                if planned: fact["planned_attempt_ids"].append(attempt_id)
                if approved:
                    fact["authorized_attempt_ids"].append(attempt_id); covered.update(implementation_ids)
                    if fact["authorization"] is None:
                        fact["authorization"] = {"strategy_id": strategy.get("strategy_id"), "attempt_id": attempt_id, "event_id": event.get("event_id"), "activity_id": activity.get("activity_id")}
                else:
                    fact["unauthorized_attempt_ids"].append(attempt_id)
                    reasons.add(f"astra_attempt_authorization_required:{root_id}:{attempt_id}")
                    if not implementation_ok: reasons.add(f"threshold_implementation_uncovered:{root_id}:{attempt_id}")
                    if not attempt_state_ok:
                        reasons.add(f"lc:attempt_record:{root_id}:{attempt_id}")
                    if not implementation_ok:
                        reasons.add(f"lc:activity_role:{root_id}:{attempt_id}")
                    if not chronology_ok or not planned_ok: reasons.add(f"astra_attempt_authorization_chronology:{root_id}:{attempt_id}")
            for activity_id, implementation in activities.items():
                implementation_start = parse_rfc3339(implementation.get("started_at"))
                if (implementation.get("type") == "implementation" and _direct_root_attribution(implementation, root_id)
                        and implementation_start and threshold_at and implementation_start > threshold_at and activity_id not in covered):
                    fact["uncovered_implementation_activity_ids"].append(activity_id)
                    reasons.add(f"threshold_implementation_uncovered:{root_id}:{activity_id}")
        fact["awaiting_astra"] = bool(fact["threshold_kind"] and (not fact["authorized_attempt_ids"] or fact["unauthorized_attempt_ids"]))
        if fact["awaiting_astra"]:
            if root.get("state") != "blocked":
                reasons.add(f"astra_adjudication_event_required:{root_id}")
                reasons.add(f"astra_successor_invalid:{root_id}")
                reasons.add(f"astra_gate_required:{root_id}")
                reasons.add(f"astra_disposition:{root_id}")
                reasons.add(f"repair_post_threshold_astra:{root_id}")
                reasons.add(f"astra_threshold_ref:{root_id}")
            if root.get("state") != "blocked" or root.get("previous_state") is None or not isinstance(root.get("blocked_reason"), str) or not root.get("blocked_reason").strip():
                reasons.add(f"threshold_awaiting_state:{root_id}")
            if root.get("block_code") != "second-escape-astra-required":
                reasons.add(f"threshold_block_code:{root_id}")
        elif root.get("block_code") == "second-escape-astra-required":
            reasons.add(f"threshold_block_code_stale:{root_id}")
        facts[root_id] = fact
    return facts, reasons


_MODERN_RESERVATION_FIELDS = (
    "record_kind", "repair_attempt_id", "root_cause_id", "strategy_id", "created_at", "status",
    "started_at", "completed_at", "review_basis_id", "authorization_basis_id",
    "authorization_epoch_event_id", "authorization_event_id", "expected_authorization_event_id",
    "reservation_event_id",
    "implementation_activity_ids", "verification_activity_ids", "introducing_cycle_id",
    "fixing_cycle_id", "verifying_cycle_id",
)


def _strategy_predecessor_graph(
    context: ValidationContext, root_id: str,
) -> tuple[set[str], set[str]]:
    """Validate the complete same-root predecessor DAG before prefix folding."""
    strategies = {
        strategy_id: strategy
        for strategy_id, strategy in context.indexes["strategies"].items()
        if strategy.get("root_cause_id") == root_id
    }
    all_strategies = context.indexes["strategies"]
    invalid: set[str] = set()
    reasons: set[str] = set()
    edges: dict[str, list[str]] = {}

    def sequence(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def recorded_sequence(strategy_id: str) -> int | None:
        values = [
            sequence(event.get("sequence"))
            for event in context.rows["events"]
            if event.get("root_cause_id") == root_id
            and event.get("strategy_id") == strategy_id
            and event.get("type") in {
                "strategy-recorded", "repair-reserved", "astra-adjudicated", "repair-attempted",
            }
        ]
        recorded = min((value for value in values if value is not None), default=None)
        if recorded is not None:
            return recorded
        # Bounded compatibility for retained pre-modern strategy history: a
        # terminal legacy attempt is already finalized before every modern
        # event prefix.  It is evidence, never new execution authority.
        legacy_terminal = any(
            attempt.get("root_cause_id") == root_id
            and attempt.get("strategy_id") == strategy_id
            and attempt.get("record_kind") is None
            and attempt.get("status") in {"failed", "superseded"}
            and parse_rfc3339(attempt.get("completed_at")) is not None
            for attempt in context.rows["repair_attempts"]
        )
        return 0 if legacy_terminal else None

    def boundary_sequence(strategy_id: str) -> int | None:
        begins = [
            sequence(event.get("sequence"))
            for event in context.rows["events"]
            if event.get("root_cause_id") == root_id
            and event.get("strategy_id") == strategy_id
            and event.get("type") == "astra-adjudication-started"
        ]
        return min((value for value in begins if value is not None), default=recorded_sequence(strategy_id))

    for strategy_id, strategy in strategies.items():
        predecessors = strategy.get("failed_predecessor_strategy_ids")
        if not isinstance(predecessors, list) or any(
            not isinstance(value, str) or not value for value in predecessors
        ) or len(predecessors) != len(set(predecessors)):
            invalid.add(strategy_id)
            reasons.add(f"auth:predecessor_absent:{root_id}:{strategy_id}")
            edges[strategy_id] = []
            continue
        edges[strategy_id] = list(predecessors)
        current_boundary = boundary_sequence(strategy_id)
        for predecessor in predecessors:
            if predecessor == strategy_id:
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_self:{root_id}:{strategy_id}")
                continue
            candidate = all_strategies.get(predecessor)
            if not isinstance(candidate, Mapping):
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_absent:{root_id}:{strategy_id}:{predecessor}")
                continue
            if candidate.get("root_cause_id") != root_id:
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_cross_root:{root_id}:{strategy_id}:{predecessor}")
                continue
            predecessor_recorded = recorded_sequence(predecessor)
            if predecessor_recorded is None:
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_strategy_recorded:{root_id}:{strategy_id}:{predecessor}")
            elif current_boundary is None or predecessor_recorded >= current_boundary:
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_forward:{root_id}:{strategy_id}:{predecessor}")

    colour: dict[str, int] = {}
    stack: list[str] = []

    def visit(strategy_id: str) -> None:
        colour[strategy_id] = 1
        stack.append(strategy_id)
        for predecessor in edges.get(strategy_id, []):
            if predecessor not in strategies:
                continue
            if colour.get(predecessor, 0) == 0:
                visit(predecessor)
            elif colour.get(predecessor) == 1:
                try:
                    start = stack.index(predecessor)
                except ValueError:
                    start = 0
                cycle = stack[start:]
                invalid.update(cycle)
                reasons.add(f"auth:predecessor_cycle:{root_id}:{':'.join(cycle)}")
        stack.pop()
        colour[strategy_id] = 2

    for strategy_id in strategies:
        if colour.get(strategy_id, 0) == 0:
            visit(strategy_id)
    changed = True
    while changed:
        changed = False
        for strategy_id, predecessors in edges.items():
            if strategy_id not in invalid and any(predecessor in invalid for predecessor in predecessors):
                invalid.add(strategy_id)
                reasons.add(f"auth:predecessor_unfinalized:{root_id}:{strategy_id}")
                changed = True
    return invalid, reasons


def _import_origin_binding_valid(
    context: ValidationContext,
    root_id: str,
    attempt: Mapping[str, Any],
    strategy: Any,
    records: Iterable[Any],
    *,
    decision_trigger_event_id: Any,
    authorization_epoch_event_id: Any,
) -> bool:
    """Validate the closed, content-addressed decision shared by the lifecycle."""
    if root_id != HISTORICAL_REPORT_ROOT_ID or not isinstance(strategy, Mapping):
        return False
    binding = strategy.get("import_origin_decision_binding")
    digest = strategy.get("import_origin_decision_binding_sha256")
    if not isinstance(binding, Mapping) or set(binding) != {
        "schema_version", "task_instance_id", "root_cause_id", "catalogue_entry_id",
        "catalogue_sha256", "report_import_event_id", "activation_event_id",
        "decision_trigger_event_id", "authorization_epoch_event_id", "repair_attempt_id",
        "strategy_id", "authorization_basis_id", "implementation_activity_ids",
        "imported_predecessor_payloads", "failed_predecessor_strategy_ids",
        "material_difference_explanation", "review_basis", "current_artifacts",
    }:
        return False
    try:
        if digest != _sha256(_canonical_json_ascii(binding)):
            return False
    except (TypeError, ValueError, UnicodeError):
        return False
    predecessor_reports = sorted([
        "OBS-RETRY-V2-ASTRA-PERSISTENCE-ESCAPE-002",
        "OBS-RETRY-V2-TERRA-PERSISTENCE-ESCAPE-001",
    ])
    imported_payloads = sorted(
        [
            {"observation_id": payload["observation_id"], "payload_sha256": digest_value}
            for payload, digest_value in zip(
                HISTORICAL_REPORT_IMPORT_PAYLOADS[1:], HISTORICAL_REPORT_IMPORT_PAYLOAD_SHA256[1:]
            )
        ],
        key=lambda item: item["observation_id"],
    )
    basis = context.indexes["review_bases"].get(attempt.get("review_basis_id"))
    basis_fields = {
        "review_basis_id", "artifact_fingerprint", "closure_boundary_fingerprint",
        "requirements_authority_fingerprint", "toolchain_dependency_fingerprint",
        "mandatory_check_set_fingerprint",
    }
    basis_ok = bool(
        isinstance(basis, Mapping)
        and set(binding.get("review_basis") or {}) == basis_fields
        and all(
            isinstance((binding["review_basis"] or {}).get(field), str)
            and len((binding["review_basis"] or {}).get(field)) == 64
            for field in basis_fields - {"review_basis_id"}
        )
        and all(binding["review_basis"].get(field) == basis.get(field) for field in basis_fields)
    )
    artifacts = binding.get("current_artifacts")
    artifacts_ok = bool(
        isinstance(artifacts, list) and artifacts
        and artifacts == sorted(artifacts, key=lambda item: item.get("artifact", "") if isinstance(item, Mapping) else "")
        and len({item.get("artifact") for item in artifacts if isinstance(item, Mapping)}) == len(artifacts)
        and all(
            isinstance(item, Mapping) and set(item) == {"artifact", "sha256"}
            and isinstance(item.get("artifact"), str) and item.get("artifact").strip()
            and isinstance(item.get("sha256"), str) and len(item.get("sha256")) == 64
            for item in artifacts
        )
    )
    if artifacts_ok:
        artifacts_ok = basis.get("artifact_fingerprint") == _sha256(_canonical_json_ascii(artifacts))
    expected = {
        "schema_version": "mas1-import-origin-decision-binding.v1",
        "task_instance_id": (context.ledger.get("task") or {}).get("task_instance_id"),
        "root_cause_id": root_id,
        "catalogue_entry_id": HISTORICAL_REPORT_IMPORT_ENTRY_ID,
        "catalogue_sha256": HISTORICAL_REPORT_IMPORT_CATALOGUE_SHA256,
        "report_import_event_id": HISTORICAL_REPORT_IMPORT_EVENT_ID,
        "activation_event_id": HISTORICAL_REPORT_ACTIVATION_EVENT_ID,
        "decision_trigger_event_id": decision_trigger_event_id,
        "authorization_epoch_event_id": authorization_epoch_event_id,
        "repair_attempt_id": attempt.get("repair_attempt_id"),
        "strategy_id": attempt.get("strategy_id"),
        "authorization_basis_id": attempt.get("authorization_basis_id"),
        "implementation_activity_ids": list(attempt.get("implementation_activity_ids") or []),
        "imported_predecessor_payloads": imported_payloads,
        "failed_predecessor_strategy_ids": list(strategy.get("failed_predecessor_strategy_ids") or []),
        "material_difference_explanation": strategy.get("material_difference_explanation"),
        "review_basis": binding.get("review_basis"),
        "current_artifacts": artifacts,
    }
    if not _json_exact(binding, expected) or not basis_ok or not artifacts_ok:
        return False
    if (
        strategy.get("failed_predecessor_report_observation_ids") != predecessor_reports
        or strategy.get("materially_different_from_predecessors") is not True
        or not isinstance(strategy.get("material_difference_explanation"), str)
        or not strategy.get("material_difference_explanation").strip()
        or len(strategy.get("material_difference_explanation")) > 8192
    ):
        return False
    return all(
        isinstance(record, Mapping)
        and record.get("import_origin_decision_binding_sha256") == digest
        for record in records
    )


def _modern_threshold_lifecycle(
    context: ValidationContext,
    threshold_origins: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Validate the append-only reservation/start/grant/settlement representation.

    This is deliberately a single rule rather than a second authorization
    checker.  The old representation continues through the bounded legacy
    branch above; a ledger becomes modern only when it records an activation or
    a reservation, neither of which can be accidentally inferred from old
    history.
    """
    ledger = context.ledger
    reasons: set[str] = set()
    events = context.indexes["events"]
    activities = context.indexes["activities"]
    strategies = context.indexes["strategies"]
    attempts = context.rows["repair_attempts"]
    facts: dict[str, dict[str, Any]] = {}

    # R005 deliberately has no migration branch.  A prior modern reservation
    # did not carry a durable reservation event, so accepting it as if its
    # chronology had been recorded would manufacture authority.  Keep this
    # single, task-addressable compatibility failure stable for consumers.
    unsupported = [item for item in attempts if item.get("record_kind") == "reservation"
                   and not isinstance(item.get("reservation_event_id"), str)]
    if unsupported:
        task_id = (ledger.get("task") or {}).get("task_instance_id")
        reasons.add(f"compat:unsupported-modern-reservation-version:{task_id}")
        return facts, reasons

    def stamp(value: Any) -> datetime | None:
        return parse_rfc3339(value)

    def exact_ids(value: Any) -> bool:
        return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value) and len(value) == len(set(value))

    for root in context.rows["roots"]:
        root_id = root.get("root_cause_id")
        if not isinstance(root_id, str):
            continue
        origin = (threshold_origins or {}).get(root_id)
        report_origin = bool(
            isinstance(origin, Mapping) and origin.get("version") == "historical-report-lower-bound.v1"
        )
        compatibility_origin = bool(
            isinstance(origin, Mapping) and origin.get("version") == "compatibility-control.v1"
        )
        baseline = root.get("historical_escape_count_baseline")
        baseline_resolved = isinstance(baseline, int) and not isinstance(baseline, bool)
        escapes = sorted((event for event in context.rows["events"]
                          if event.get("type") == "escape-confirmed" and event.get("root_cause_id") == root_id),
                         key=lambda event: (event.get("sequence", 0), event.get("event_id", "")))
        lower_bound_incidents, lower_bound_reasons = ([], set()) if baseline_resolved else _modern_escape_incidents(context, root_id)
        reasons.update(lower_bound_reasons)
        invalid_predecessor_strategies, predecessor_graph_reasons = _strategy_predecessor_graph(context, root_id)
        reasons.update(predecessor_graph_reasons)
        lower_bound = report_origin or (not baseline_resolved and len(lower_bound_incidents) >= 2)
        # Unknown history remains unknown.  Two evidence-complete modern
        # incidents do, however, establish a procedural threshold without
        # pretending to know the lifetime total.
        threshold_applicable: bool | None = (baseline + len(escapes) >= 2 if baseline_resolved
                                             else (True if lower_bound else None))
        anchor = root.get("threshold_anchor") if isinstance(root.get("threshold_anchor"), Mapping) else {}
        if report_origin:
            anchor_id = anchor.get("report_import_event_id")
            activation_id = origin.get("activation_event_id")
        else:
            anchor_id = (anchor.get("threshold_escape_event_id") if anchor.get("kind") == "post-cutover-escape"
                         else anchor.get("historical_threshold_reconciled_event_id"))
            activation_id = root.get("first_threshold_activation_event_id")
        activation = events.get(activation_id) if isinstance(activation_id, str) else None
        activation_status = "not-applicable" if threshold_applicable is False else ("active" if activation else "unresolved")
        effective_at = stamp((activation or {}).get("effective_at"))
        root_attempts = [attempt for attempt in attempts if attempt.get("root_cause_id") == root_id and attempt.get("record_kind") == "reservation"]
        root_facts: dict[str, Any] = {
            "lifetime_count": (baseline + len(escapes)) if baseline_resolved else None,
            "threshold_applicable": threshold_applicable,
            "baseline_resolved": baseline_resolved,
            "threshold_anchor_event_id": anchor_id if isinstance(anchor_id, str) else None,
            "threshold_activation_event_id": activation_id if isinstance(activation_id, str) else None,
            "threshold_activation_status": activation_status,
            "threshold_effective_at": (activation or {}).get("effective_at") if effective_at else None,
            "decision_trigger_event_id": None,
            "authorization_epoch_event_id": None,
            "threshold_relevant_attempt_ids": [], "pre_activation_attempt_ids": [],
            "authorized_attempt_ids": [], "unauthorized_attempt_ids": [],
            "fresh_unused_authorization_event_ids": [], "unsettled_attempt_ids": [],
            "mutation_activity_ids": [], "uncovered_mutation_activity_ids": [],
            "awaiting_astra": True, "gate_state": "blocked", "frontier_attempt_id": None,
            "closure_epoch_id": None, "closure_eligible": False, "incomplete_reasons": [],
            "attempt_facts": {}, "lower_bound_incident_count": (
                origin.get("historical_report_escape_lower_bound") if report_origin else len(lower_bound_incidents)
            ),
            "operational_binding_pending": bool(lower_bound and not anchor),
            "threshold_origin": deepcopy(origin) if isinstance(origin, Mapping) else None,
        }
        if threshold_applicable is None:
            root_facts["incomplete_reasons"].extend(["historical_baseline_unresolved", "threshold_activation_unresolved"])
        elif lower_bound:
            root_facts["threshold_activation_status"] = "binding-pending" if not activation else "active"
            root_facts["incomplete_reasons"].append("historical_baseline_unresolved")
        has_reservation_escape = any(
            escape.get("type") == "escape-confirmed"
            and escape.get("root_cause_id") == root_id
            and context.indexes["repair_attempts"].get(escape.get("repair_attempt_id"), {}).get("record_kind") == "reservation"
            for escape in context.rows["events"]
        )
        if root_attempts and has_reservation_escape and (
            threshold_applicable is not True or (lower_bound and not anchor)
        ):
            admitted, admission_reasons = _unbound_root_admission(context, root_id, root_attempts)
            reasons.update(admission_reasons)
            root_facts["attempt_facts"].update(admitted)
            root_facts["mutation_activity_ids"].extend(
                activity_id
                for fact in admitted.values()
                for activity_id in (fact.get("mutation_activity_ids") or [])
            )
        if threshold_applicable is not True:
            facts[root_id] = _sort_modern_facts(root_facts)
            continue
        if lower_bound and not anchor:
            # A first lower-bound binding is intentionally a valid blocked
            # state.  It carries no authorization until the immutable anchor
            # and its already-recorded activation have both been bound.
            root_facts["threshold_applicable"] = None
            root_facts["threshold_activation_status"] = "binding-pending"
            root_facts["gate_state"] = "blocked"
            root_facts["awaiting_astra"] = True
            facts[root_id] = _sort_modern_facts(root_facts)
            continue
        anchor_event = events.get(anchor_id) if isinstance(anchor_id, str) else None
        anchor_valid = isinstance(anchor_event, Mapping)
        if report_origin:
            anchor_valid = bool(
                anchor.get("kind") == "historical-report-lower-bound"
                and anchor_id == origin.get("report_import_event_id")
                and anchor_valid
                and anchor_event.get("type") == "historical-report-imported"
                and anchor_event.get("root_cause_id") == root_id
            )
        elif anchor.get("kind") == "historical-baseline":
            anchor_valid = bool(
                anchor_valid and anchor_event.get("type") == "historical-threshold-reconciled"
                and anchor_event.get("root_cause_id") == root_id
                and anchor_event.get("reconciled_baseline") == baseline
                and anchor.get("reconciled_baseline") == baseline
                and exact_ids(anchor_event.get("evidence_refs"))
                and root_id in (anchor_event.get("causal_refs") or [])
            )
        elif anchor.get("kind") == "post-cutover-escape":
            anchor_valid = bool(anchor_valid and anchor_event.get("type") == "escape-confirmed"
                                and anchor_event.get("root_cause_id") == root_id)
            if lower_bound:
                anchor_valid = bool(anchor_valid and anchor_id == lower_bound_incidents[1].get("event_id"))
        else:
            anchor_valid = False
        if not anchor_valid:
            reasons.add(f"auth:anchor:{root_id}")
        if not isinstance(activation, Mapping):
            root_facts["incomplete_reasons"].append("threshold_activation_unresolved")
            # Missing activation is a valid blocked state only while no modern
            # execution is claimed.  The attempt pass below enforces that.
        else:
            activation_rows = [event for event in context.rows["events"]
                               if event.get("type") == "threshold-activated" and event.get("root_cause_id") == root_id]
            adopted = stamp((ledger.get("cutover") or {}).get("protocol_adopted_at"))
            first_known = stamp(activation.get("first_threshold_known_at"))
            recorded = stamp(activation.get("at"))
            prescribed = max(first_known, adopted) if first_known and adopted else None
            if report_origin:
                prescribed = stamp(origin.get("enforcement_boundary"))
                activation_ok = bool(
                    len(activation_rows) == 1 and activation.get("event_id") == activation_id
                    and activation.get("activation_anchor_event_id") == anchor_id
                    and activation.get("first_threshold_known_at") is None
                    and activation.get("original_protocol_adopted_at") is None
                    and prescribed is not None and effective_at == prescribed
                    and recorded is not None and recorded >= effective_at
                    and exact_ids(activation.get("evidence_refs"))
                    and {root_id, anchor_id}.issubset(set(activation.get("causal_refs") or []))
                )
            elif compatibility_origin:
                boundary = stamp(origin.get("enforcement_boundary"))
                prescribed = max(first_known, boundary) if first_known and boundary else None
                activation_ok = bool(
                    len(activation_rows) == 1 and activation.get("event_id") == activation_id
                    and activation.get("activation_anchor_event_id") == anchor_id
                    and anchor_event is not None and activation.get("first_threshold_known_at") == anchor_event.get("at")
                    and activation.get("original_protocol_adopted_at") is None
                    and prescribed is not None and effective_at == prescribed
                    and recorded is not None and recorded >= effective_at
                    and exact_ids(activation.get("evidence_refs"))
                    and {root_id, anchor_id}.issubset(set(activation.get("causal_refs") or []))
                )
            else:
                activation_ok = (
                    len(activation_rows) == 1 and activation.get("event_id") == activation_id
                    and activation.get("activation_anchor_event_id") == anchor_id
                    and anchor_event is not None and activation.get("first_threshold_known_at") == anchor_event.get("at")
                    and activation.get("original_protocol_adopted_at") == (ledger.get("cutover") or {}).get("protocol_adopted_at")
                    and prescribed is not None and effective_at == prescribed and recorded is not None and recorded >= effective_at
                    and exact_ids(activation.get("evidence_refs"))
                    and {root_id, anchor_id}.issubset(set(activation.get("causal_refs") or []))
                )
            if lower_bound:
                # Lower-bound binding never reconciles history.  Its anchor is
                # the generic second validated incident, and there must be one
                # and only one already-recorded activation for that anchor.
                activation_ok = activation_ok and len(activation_rows) == 1
            if anchor.get("kind") == "historical-baseline":
                reconciliation_id = root.get("historical_baseline_reconciliation_event_id")
                activation_ok = activation_ok and reconciliation_id == anchor_id and activation.get("historical_baseline_reconciliation_event_id") == reconciliation_id and reconciliation_id in (activation.get("causal_refs") or [])
            if not activation_ok:
                reasons.add(f"auth:activation:{root_id}")
                root_facts["incomplete_reasons"].append("threshold_activation_unresolved")
                activation_status = root_facts["threshold_activation_status"] = "unresolved"
                effective_at = None
        retained_attempt_ids: set[str] = set()
        if lower_bound and not report_origin and isinstance(activation, Mapping):
            for candidate in root_attempts:
                candidate_id = candidate.get("repair_attempt_id")
                candidate_starts = [event for event in context.rows["events"]
                                    if event.get("type") == "repair-attempted" and event.get("root_cause_id") == root_id
                                    and event.get("repair_attempt_id") == candidate_id]
                if candidate_starts and parse_rfc3339(candidate_starts[0].get("at")) and effective_at \
                        and parse_rfc3339(candidate_starts[0].get("at")) < effective_at:
                    retained_ok, retained_start = _retained_preactivation_attempt(context, root_id, candidate, activation)
                    if not retained_ok:
                        reasons.add(f"auth:retained_preactivation:{root_id}:{candidate_id}")
                    else:
                        retained_attempt_ids.add(str(candidate_id))
                        root_facts["pre_activation_attempt_ids"].append(candidate_id)
                        root_facts["attempt_facts"][candidate_id] = {
                            "record_kind": "reservation", "lifecycle_state": "retained-preactivation",
                            "actual_started_at": (retained_start or {}).get("started_at"), "settled_at": None,
                            "start_event_id": (retained_start or {}).get("event_id"), "settlement_event_id": None,
                            "grant_event_id": (retained_start or {}).get("authorization_event_id"),
                            "historical_nonauthorizing": True, "completion_eligible": False,
                            "threshold_affected": False, "mutation_activity_ids": list((retained_start or {}).get("implementation_activity_ids") or []),
                        }
            root_attempts = [attempt for attempt in root_attempts if str(attempt.get("repair_attempt_id")) not in retained_attempt_ids]
        trigger = max(escapes, key=lambda event: event.get("sequence", 0), default=anchor_event)
        epoch_candidates = sorted((event for event in context.rows["events"] if event.get("root_cause_id") == root_id
                                   and event.get("type") in {"threshold-activated", "escape-confirmed", "basis-invalidated"}),
                                  key=lambda event: event.get("sequence", 0))
        epoch = epoch_candidates[-1] if epoch_candidates else None

        # Causality is event-sequence only.  Timestamps constrain occurrence
        # intervals but cannot choose an authorization epoch when equal or
        # offset-equivalent values occur.
        def epoch_prefix(sequence: int | None) -> Mapping[str, Any] | None:
            eligible = [item for item in epoch_candidates if sequence is None or item.get("sequence", 0) < sequence]
            return eligible[-1] if eligible else None

        def trigger_prefix(sequence: int | None) -> Mapping[str, Any] | None:
            candidates = [item for item in escapes if sequence is None or item.get("sequence", 0) < sequence]
            return max(candidates, key=lambda item: item.get("sequence", 0), default=anchor_event)
        root_facts["decision_trigger_event_id"] = trigger.get("event_id") if isinstance(trigger, Mapping) else None
        root_facts["authorization_epoch_event_id"] = epoch.get("event_id") if isinstance(epoch, Mapping) else None
        start_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        settlement_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        adjudication_begin_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for event in context.rows["events"]:
            if event.get("root_cause_id") != root_id:
                continue
            if event.get("type") == "repair-attempted": start_rows[str(event.get("repair_attempt_id"))].append(event)
            if event.get("type") == "repair-threshold-settled": settlement_rows[str(event.get("repair_attempt_id"))].append(event)
            if event.get("type") == "astra-adjudication-started": adjudication_begin_rows[str(event.get("repair_attempt_id"))].append(event)

        for attempt in root_attempts:
            attempt_id = attempt.get("repair_attempt_id")
            prefix = f"{root_id}:{attempt_id}"
            missing = [field for field in _MODERN_RESERVATION_FIELDS if field not in attempt]
            reservation_event = events.get(attempt.get("reservation_event_id"))
            reservation_at = stamp((reservation_event or {}).get("at"))
            reservation_sequence = (reservation_event or {}).get("sequence")
            reservation_ok = (not missing and attempt.get("record_kind") == "reservation" and attempt.get("status") == "planned"
                              and attempt.get("started_at") is None and attempt.get("completed_at") is None
                              and attempt.get("authorization_event_id") is None and isinstance(attempt_id, str)
                              and stamp(attempt.get("created_at")) is not None
                              and isinstance(reservation_event, Mapping) and reservation_event.get("type") == "repair-reserved"
                              and reservation_event.get("reservation_event_id") == attempt.get("reservation_event_id")
                              and reservation_event.get("root_cause_id") == root_id and reservation_event.get("repair_attempt_id") == attempt_id
                              and reservation_event.get("strategy_id") == attempt.get("strategy_id")
                              and reservation_event.get("review_basis_id") == attempt.get("authorization_basis_id")
                              and reservation_at == stamp(attempt.get("created_at")) and isinstance(reservation_sequence, int)
                              and not isinstance(reservation_sequence, bool)
                              and {root_id, attempt_id, attempt.get("strategy_id"), attempt.get("authorization_basis_id"), attempt.get("review_basis_id")}.issubset(set(reservation_event.get("causal_refs") or []))
                              and exact_ids(attempt.get("implementation_activity_ids")) and exact_ids(attempt.get("verification_activity_ids"))
                              and not set(attempt.get("implementation_activity_ids") or []).intersection(attempt.get("verification_activity_ids") or []))
            if not reservation_ok:
                reasons.add(f"lc:attempt_record:{prefix}")
            impl_ids = list(attempt.get("implementation_activity_ids") or [])
            root_facts["mutation_activity_ids"].extend(impl_ids)
            starts = start_rows.get(str(attempt_id), [])
            settlements = settlement_rows.get(str(attempt_id), [])
            begins = adjudication_begin_rows.get(str(attempt_id), [])
            if len(starts) > 1 or len(settlements) > 1 or len(begins) > 1:
                reasons.add(f"lc:terminal:{prefix}")
            start = starts[0] if len(starts) == 1 else None
            settlement = settlements[0] if len(settlements) == 1 else None
            adjudication_begin = begins[0] if len(begins) == 1 else None
            actual_started = stamp((start or {}).get("started_at"))
            started = start is not None
            start_sequence = (start or {}).get("sequence")
            begin_sequence = (adjudication_begin or {}).get("sequence")
            # A grant is judged at adjudication begin and grant append only;
            # later invalidators cannot rewrite historical grant validity.
            begin_epoch = epoch_prefix(begin_sequence if isinstance(begin_sequence, int) else None)
            begin_trigger = trigger_prefix(begin_sequence if isinstance(begin_sequence, int) else None)
            grant_epoch = None
            grant_trigger = None
            if start is not None and (start.get("repair_attempt_id") != attempt_id or start.get("review_basis_id") != attempt.get("authorization_basis_id")
                                      or not stamp(start.get("at")) or not actual_started or stamp(start.get("at")) < actual_started):
                reasons.add(f"lc:link:{prefix}")
            grant_id = (start or {}).get("authorization_event_id") if start else attempt.get("expected_authorization_event_id")
            grant = events.get(grant_id) if isinstance(grant_id, str) else None
            if isinstance(grant, Mapping):
                grant_sequence = grant.get("sequence")
                grant_epoch = epoch_prefix(grant_sequence if isinstance(grant_sequence, int) else None)
                grant_trigger = trigger_prefix(grant_sequence if isinstance(grant_sequence, int) else None)
            adjudication = activities.get((grant or {}).get("adjudication_activity_id"))
            strategy = strategies.get(attempt.get("strategy_id"))
            predecessor_ok = True
            if report_origin:
                predecessors = (strategy or {}).get("failed_predecessor_strategy_ids")
                earlier_attempts = [
                    candidate for candidate in root_attempts
                    if isinstance(reservation_sequence, int)
                    and isinstance((events.get(candidate.get("reservation_event_id")) or {}).get("sequence"), int)
                    and (events.get(candidate.get("reservation_event_id")) or {}).get("sequence") < reservation_sequence
                ]
                if not isinstance(predecessors, list) or len(predecessors) != len(set(predecessors)):
                    predecessor_ok = False
                elif not predecessors:
                    predecessor_ok = not earlier_attempts
                else:
                    frontier = {
                        candidate.get("strategy_id") for candidate in earlier_attempts
                        if any(
                            event.get("type") == "repair-threshold-settled"
                            and event.get("repair_attempt_id") == candidate.get("repair_attempt_id")
                            and event.get("terminal_outcome") in {"failed", "superseded"}
                            and isinstance(begin_sequence, int)
                            and event.get("sequence", -1) < begin_sequence
                            for event in context.rows["events"]
                        )
                    }
                    predecessor_ok = bool(frontier) and set(predecessors) == frontier
            elif lower_bound:
                predecessors = (strategy or {}).get("failed_predecessor_strategy_ids")
                predecessor_ok = (isinstance(predecessors, list) and bool(predecessors)
                                  and len(predecessors) == len(set(predecessors))
                                  and strategy.get("materially_different_from_predecessors") is True)
                for predecessor in predecessors or []:
                    prior_attempts = [candidate for candidate in attempts
                                      if candidate.get("root_cause_id") == root_id
                                      and candidate.get("strategy_id") == predecessor]
                    terminal_prior = False
                    for candidate in prior_attempts:
                        ordinary, ordinary_reasons = _ordinary_attempt_fact(context, root_id, candidate)
                        if ordinary is None or ordinary_reasons:
                            continue
                        reservation_event = ordinary["reservation"]
                        settled = ordinary["settlement"]
                        terminal_prior = terminal_prior or bool(
                            ordinary["terminal_outcome"] in {"failed", "superseded"}
                            and isinstance(begin_sequence, int)
                            and reservation_event.get("sequence", -1) < begin_sequence
                            and settled.get("sequence", -1) < begin_sequence
                        )
                    strategy_recorded = any(
                        event.get("root_cause_id") == root_id and event.get("strategy_id") == predecessor
                        and event.get("sequence", -1) < (begin_sequence if isinstance(begin_sequence, int) else -1)
                        and event.get("type") in {"repair-reserved", "astra-adjudicated", "repair-attempted"}
                        for event in context.rows["events"]
                    )
                    incident_prior = any(
                        event.get("repair_attempt_id") in {candidate.get("repair_attempt_id") for candidate in prior_attempts}
                        and event.get("sequence", -1) < (begin_sequence if isinstance(begin_sequence, int) else -1)
                        for event in lower_bound_incidents
                    )
                    predecessor_ok = predecessor_ok and bool(strategies.get(predecessor)) and strategy_recorded and (terminal_prior or incident_prior)
            binding_records = [
                record for record in (
                    attempt, reservation_event, adjudication_begin, adjudication, grant, start,
                    *[activities.get(item) for item in impl_ids], settlement,
                ) if isinstance(record, Mapping)
            ]
            import_binding_ok = (
                _import_origin_binding_valid(
                    context, root_id, attempt, strategy, binding_records,
                    decision_trigger_event_id=(begin_trigger or {}).get("event_id"),
                    authorization_epoch_event_id=(begin_epoch or {}).get("event_id"),
                )
                if report_origin else True
            )
            if report_origin and isinstance(grant, Mapping):
                import_binding_ok = bool(
                    import_binding_ok
                    and _json_exact(
                        grant.get("import_origin_decision_binding"),
                        (strategy or {}).get("import_origin_decision_binding"),
                    )
                )
            prefix_invalidations = [item for item in epoch_candidates
                                    if item.get("type") == "basis-invalidated"
                                    and isinstance(begin_sequence, int) and item.get("sequence", 0) < begin_sequence]
            latest_prefix_invalidation = prefix_invalidations[-1] if prefix_invalidations else None
            grant_valid = bool(
                isinstance(grant, Mapping) and grant.get("type") == "astra-adjudicated" and grant.get("disposition") == "approved"
                and grant.get("root_cause_id") == root_id and grant.get("repair_attempt_id") == attempt_id
                and grant.get("strategy_id") == attempt.get("strategy_id")
                and grant.get("event_id") == attempt.get("expected_authorization_event_id")
                and grant.get("threshold_event_id", grant.get("threshold_escape_event_id")) == anchor_id
                and grant.get("activation_anchor_event_id", anchor_id) == anchor_id
                and grant.get("first_threshold_activation_event_id") == activation_id
                and grant.get("decision_trigger_event_id") == (begin_trigger or {}).get("event_id") == (grant_trigger or {}).get("event_id")
                and grant.get("authorization_epoch_event_id") == attempt.get("authorization_epoch_event_id") == (begin_epoch or {}).get("event_id") == (grant_epoch or {}).get("event_id")
                and grant.get("authorization_basis_id") == attempt.get("authorization_basis_id")
                and grant.get("review_basis_id") == attempt.get("review_basis_id")
                and grant.get("implementation_activity_ids") == impl_ids and exact_ids(grant.get("decision_evidence_refs"))
                and isinstance(adjudication, Mapping) and adjudication.get("type") == "astra-adjudication" and adjudication.get("status") == "completed"
                and adjudication.get("runtime_verified") is True and (adjudication.get("actual") or {}).get("model") == "gpt-6-astra"
                and (adjudication.get("actual") or {}).get("reasoning_effort") == "xhigh" and _direct_root_attribution(adjudication, root_id)
                and isinstance(adjudication_begin, Mapping) and grant.get("adjudication_start_event_id") == adjudication_begin.get("event_id")
                and adjudication_begin.get("adjudication_activity_id") == grant.get("adjudication_activity_id")
                and adjudication_begin.get("root_cause_id") == root_id and adjudication_begin.get("repair_attempt_id") == attempt_id
                and stamp(adjudication_begin.get("at")) == stamp(adjudication.get("started_at"))
                and isinstance(reservation_sequence, int) and not isinstance(reservation_sequence, bool)
                and isinstance(begin_sequence, int) and not isinstance(begin_sequence, bool)
                and isinstance(grant.get("sequence"), int) and not isinstance(grant.get("sequence"), bool)
                and reservation_sequence < begin_sequence < grant.get("sequence")
                and activation is not None and activation.get("sequence", 0) < begin_sequence
                and isinstance(begin_trigger, Mapping) and stamp(begin_trigger.get("at")) < stamp(adjudication.get("started_at"))
                and isinstance(strategy, Mapping) and strategy.get("root_cause_id") == root_id
                and predecessor_ok and import_binding_ok
                and attempt.get("strategy_id") not in invalid_predecessor_strategies
                and stamp(strategy.get("created_at")) is not None and stamp(strategy.get("created_at")) > stamp(begin_trigger.get("at"))
                and stamp(strategy.get("created_at")) <= stamp(adjudication.get("started_at"))
                and stamp(activation.get("at")) is not None and stamp(activation.get("at")) <= stamp(adjudication.get("started_at"))
                and (latest_prefix_invalidation is None or stamp(latest_prefix_invalidation.get("at")) < stamp(adjudication.get("started_at")))
                and stamp(adjudication.get("started_at")) <= stamp(adjudication.get("completed_at"))
                and stamp(adjudication.get("started_at")) and stamp(adjudication.get("completed_at"))
                and stamp(grant.get("at")) and stamp(adjudication.get("completed_at")) <= stamp(grant.get("at"))
                and {root_id, attempt_id, attempt.get("strategy_id"), attempt.get("authorization_basis_id"), anchor_id, activation_id,
                     (begin_trigger or {}).get("event_id"), (begin_epoch or {}).get("event_id"), (grant or {}).get("adjudication_activity_id"),
                     (adjudication_begin or {}).get("event_id")}.issubset(set(grant.get("causal_refs") or []))
            )
            if isinstance(grant, Mapping) and not grant_valid:
                reasons.add(f"auth:grant_binding:{prefix}")
            start_epoch = epoch_prefix(start_sequence if isinstance(start_sequence, int) else None)
            start_trigger = trigger_prefix(start_sequence if isinstance(start_sequence, int) else None)
            start_authorized = bool(started and grant_valid and actual_started and stamp(grant.get("at")) < actual_started
                                    and effective_at is not None and actual_started >= effective_at
                                    and start.get("authorization_event_id") == attempt.get("expected_authorization_event_id")
                                    and start.get("sequence", 0) > grant.get("sequence", 0)
                                    and (start_epoch or {}).get("event_id") == grant.get("authorization_epoch_event_id")
                                    and (start_trigger or {}).get("event_id") == grant.get("decision_trigger_event_id"))
            impl_rows = [activities.get(item) for item in impl_ids]
            crossing = next((item for item in epoch_candidates
                             if started and item.get("sequence", 0) > start.get("sequence", 0)
                             and stamp(item.get("at")) is not None), None)
            execution_valid = True
            if started:
                if not impl_rows:
                    execution_valid = False
                for activity_id, activity in zip(impl_ids, impl_rows):
                    bindings = (activity or {}).get("repair_attempt_bindings")
                    activity_start = stamp((activity or {}).get("started_at")); activity_end = stamp((activity or {}).get("completed_at"))
                    matching_bindings = [binding for binding in bindings or [] if isinstance(binding, Mapping)
                                         and binding.get("root_cause_id") == root_id and binding.get("repair_attempt_id") == attempt_id]
                    binding_ok = (isinstance(bindings, list) and len(matching_bindings) == 1
                                  and sum(1 for binding in bindings if isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id) == 1
                                  and root_id in ((activity or {}).get("root_cause_ids") or []))
                    if not (isinstance(activity, Mapping) and activity.get("type") == "implementation" and activity.get("status") in {"running", "completed", "failed", "cancelled"}
                            and binding_ok
                            and activity_start and actual_started and activity_start >= actual_started):
                        execution_valid = False; reasons.add(f"lc:activity_role:{root_id}:{attempt_id}:{activity_id}")
                    if activity_start and actual_started and activity_start < actual_started:
                        execution_valid = False; reasons.add(f"lc:window:{root_id}:{attempt_id}:{activity_id}")
                    if activity and activity.get("status") == "running" and activity.get("completed_at") is not None:
                        execution_valid = False; reasons.add(f"lc:activity_state:{root_id}:{attempt_id}:{activity_id}")
                    if activity and activity.get("status") != "running" and not activity_end:
                        execution_valid = False; reasons.add(f"lc:activity_state:{root_id}:{attempt_id}:{activity_id}")
                    if activity_start and activity_end and activity_end < activity_start:
                        execution_valid = False; reasons.add(f"lc:activity_state:{root_id}:{attempt_id}:{activity_id}")
                    if crossing is not None and (activity_end is None or activity_end > stamp(crossing.get("at"))):
                        execution_valid = False; reasons.add(f"auth:crossing:{root_id}:{attempt_id}:{activity_id}")
            else:
                execution_valid = not any(item is not None for item in impl_rows)
            settled_at = stamp((settlement or {}).get("settled_at"))
            outcome = (settlement or {}).get("terminal_outcome")
            lifecycle = "planned"
            completion_eligible = False
            if started and settlement is None:
                lifecycle = "active"
            elif settlement is not None:
                lifecycle = str(outcome) if outcome in {"succeeded", "failed", "superseded", "cancelled"} else "invalid"
                mutation_ends = [stamp((item or {}).get("completed_at")) for item in impl_rows]
                max_end = max((item for item in mutation_ends if item), default=None)
                actual_impl_rows = [item for item in impl_rows if isinstance(item, Mapping)]
                settlement_ok = (settled_at is not None and stamp(settlement.get("at")) and stamp(settlement.get("at")) >= settled_at
                                 and settlement.get("start_event_id") == (start or {}).get("event_id")
                                 and settlement.get("mutation_finished_at") == ((max_end.isoformat().replace("+00:00", "Z")) if max_end else None)
                                 and (not actual_started or settled_at >= actual_started)
                                 and (not actual_started or len(actual_impl_rows) == len(impl_rows))
                                 and all(item.get("status") != "running" and stamp(item.get("completed_at")) <= settled_at for item in actual_impl_rows))
                if outcome == "succeeded":
                    settlement_ok = settlement_ok and bool(actual_started) and bool(actual_impl_rows) and all(item.get("status") == "completed" for item in actual_impl_rows)
                    completion_eligible = settlement_ok
                if crossing is not None and (max_end is None or max_end > stamp(crossing.get("at"))) and outcome not in {"failed", "superseded"}:
                    settlement_ok = False
                if not settlement_ok:
                    lifecycle = "invalid"; completion_eligible = False; reasons.add(f"lc:terminal:{prefix}")
                if max_end is not None and settled_at is not None and max_end > settled_at:
                    reasons.add(f"lc:window:{root_id}:{attempt_id}")
            # A future expected-grant/epoch/basis pointer is reservation data,
            # not execution.  Once the referenced grant exists, or any other
            # lifecycle evidence exists, the attempt is threshold-affected.
            threshold_affected = bool(started or impl_rows or isinstance(grant, Mapping) or begins or settlements)
            if threshold_affected:
                root_facts["threshold_relevant_attempt_ids"].append(attempt_id)
            # A reserved ID becomes a mutation only when an actual activity
            # row appears.  Such a row without its prior start event is an
            # execution attempt, not harmless planning.
            unauthorized = bool((started and (not start_authorized or not execution_valid))
                                or (not started and any(item is not None for item in impl_rows)))
            if (started and not start_authorized) or (not started and any(item is not None for item in impl_rows)):
                reasons.add(f"auth:chronology:{prefix}")
            if unauthorized:
                root_facts["unauthorized_attempt_ids"].append(attempt_id)
            elif started and start_authorized and execution_valid:
                root_facts["authorized_attempt_ids"].append(attempt_id)
            elif not started and grant_valid:
                root_facts["fresh_unused_authorization_event_ids"].append(grant.get("event_id"))
            if lifecycle in {"planned", "active"}:
                root_facts["unsettled_attempt_ids"].append(attempt_id)
            root_facts["attempt_facts"][attempt_id] = {
                "record_kind": "reservation", "lifecycle_state": lifecycle, "actual_started_at": (start or {}).get("started_at"),
                "settled_at": (settlement or {}).get("settled_at"), "start_event_id": (start or {}).get("event_id"),
                "settlement_event_id": (settlement or {}).get("event_id"), "grant_event_id": (grant or {}).get("event_id"),
                "reservation_event_id": attempt.get("reservation_event_id"), "reservation_sequence": reservation_sequence,
                "grant_valid": grant_valid, "start_authorized": start_authorized, "execution_valid": execution_valid,
                "authorization_epoch_event_id": (start_epoch or {}).get("event_id"),
                "completion_eligible": completion_eligible, "threshold_affected": threshold_affected,
                "authorization_required_at_start": bool(started and effective_at), "mutation_activity_ids": impl_ids,
                "verification_only_activity_ids": list(attempt.get("verification_activity_ids") or []), "crossing_invalidator_event_id": (crossing or {}).get("event_id"),
                "historical_nonauthorizing": False, "reason_codes": [],
            }
        # A successor reservation is an ownership hand-off, not merely a
        # later row.  Its causal position is the reservation event sequence;
        # settlement append order, attempt identifiers and wall-clock labels
        # cannot select or revive ownership.
        ordered_attempts = sorted(
            ((fact.get("reservation_sequence"), attempt_id, fact)
             for attempt_id, fact in root_facts["attempt_facts"].items()
             if isinstance(fact.get("reservation_sequence"), int) and not isinstance(fact.get("reservation_sequence"), bool)),
            key=lambda item: item[0],
        )
        for index, (newer_sequence, newer_id, newer_fact) in enumerate(ordered_attempts):
            newer_event = events.get(newer_fact.get("reservation_event_id")) or {}
            newer_at = stamp(newer_event.get("at"))
            for older_sequence, older_id, older_fact in ordered_attempts[:index]:
                older_start = events.get(older_fact.get("start_event_id")) or {}
                older_settlement = events.get(older_fact.get("settlement_event_id")) or {}
                older_mutations = [activities.get(activity_id) for activity_id in older_fact.get("mutation_activity_ids", [])]
                # Any old execution after the hand-off is a direct ownership
                # violation, even if a newer repair later succeeds.
                if older_fact.get("start_event_id") and (
                    older_start.get("sequence", 0) >= newer_sequence
                    or (stamp(older_fact.get("actual_started_at")) and newer_at and stamp(older_fact.get("actual_started_at")) > newer_at)
                ):
                    reasons.add(f"auth:ownership_barrier:{root_id}:{older_id}:{newer_id}")
                if any(
                    not isinstance(activity, Mapping)
                    or activity.get("status") == "running"
                    or stamp(activity.get("completed_at")) is None
                    or (newer_at is not None and stamp(activity.get("completed_at")) > newer_at)
                    or (newer_at is not None and stamp(activity.get("started_at")) > newer_at)
                    for activity in older_mutations
                ):
                    reasons.add(f"auth:ownership_barrier:{root_id}:{older_id}:{newer_id}")
                if older_fact.get("lifecycle_state") == "planned":
                    if older_settlement.get("terminal_outcome") != "cancelled" or older_settlement.get("start_event_id") is not None:
                        reasons.add(f"auth:ownership_barrier:{root_id}:{older_id}:{newer_id}")
                elif older_fact.get("lifecycle_state") not in {"succeeded", "failed", "superseded", "cancelled"}:
                    reasons.add(f"auth:ownership_barrier:{root_id}:{older_id}:{newer_id}")
        # Mutation is a union, never a presentation label: an implementation
        # cannot disappear by being dual-listed as verification or relabelled.
        grant_reserved_ids = {item for event in context.rows["events"] if event.get("type") == "astra-adjudicated"
                              and event.get("root_cause_id") == root_id for item in (event.get("implementation_activity_ids") or [])}
        reserved_ids = {item for attempt in root_attempts for item in (attempt.get("implementation_activity_ids") or [])}
        known_attempt_ids = {attempt.get("repair_attempt_id") for attempt in root_attempts}
        for activity_id, activity in activities.items():
            bindings = activity.get("repair_attempt_bindings") if isinstance(activity.get("repair_attempt_bindings"), list) else []
            rooted = root_id in (activity.get("root_cause_ids") or []) or any(
                isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id for binding in bindings)
            activity_start = stamp(activity.get("started_at"))
            activity_end = stamp(activity.get("completed_at"))
            mutation = activity.get("type") == "implementation" or activity_id in reserved_ids or activity_id in grant_reserved_ids or any(
                isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id for binding in bindings)
            affected = bool(activity_start and effective_at and (activity_start >= effective_at or (activity_end is not None and activity_end > effective_at))) or activity_id in reserved_ids or activity_id in grant_reserved_ids
            if not (rooted and mutation and affected):
                continue
            root_facts["mutation_activity_ids"].append(activity_id)
            matched = [binding for binding in bindings if isinstance(binding, Mapping) and binding.get("root_cause_id") == root_id]
            if len(matched) != 1 or matched[0].get("repair_attempt_id") not in known_attempt_ids:
                root_facts["uncovered_mutation_activity_ids"].append(activity_id)
                reasons.add(f"auth:ownership:{root_id}:none:{activity_id}")
                if activity_start and effective_at and activity_start >= effective_at:
                    reasons.add(f"auth:chronology:{root_id}:none:{activity_id}")
                if activity_start and activity_end and effective_at and activity_start < effective_at < activity_end:
                    reasons.add(f"auth:crossing:{root_id}:none:{activity_id}")
                continue
            owner = matched[0].get("repair_attempt_id")
            attempt_fact = root_facts["attempt_facts"].get(owner)
            if activity_id not in (attempt_fact or {}).get("mutation_activity_ids", []):
                root_facts["uncovered_mutation_activity_ids"].append(activity_id)
                reasons.add(f"lc:link:{root_id}:{owner}:{activity_id}")
        root_facts["mutation_activity_ids"] = sorted(set(root_facts["mutation_activity_ids"]))
        root_facts["uncovered_mutation_activity_ids"] = sorted(set(root_facts["uncovered_mutation_activity_ids"]))
        root_facts["authorized_attempt_ids"] = sorted(root_facts["authorized_attempt_ids"])
        root_facts["unauthorized_attempt_ids"] = sorted(root_facts["unauthorized_attempt_ids"])
        root_facts["fresh_unused_authorization_event_ids"] = sorted(root_facts["fresh_unused_authorization_event_ids"])
        root_facts["threshold_relevant_attempt_ids"] = sorted(root_facts["threshold_relevant_attempt_ids"])
        root_facts["unsettled_attempt_ids"] = sorted(root_facts["unsettled_attempt_ids"])
        if root_facts["threshold_relevant_attempt_ids"]:
            # The selected frontier is based on the reservation/start lineage,
            # never on a delayed older settlement's append position.
            root_facts["frontier_attempt_id"] = max(
                root_facts["threshold_relevant_attempt_ids"],
                key=lambda attempt_id: root_facts["attempt_facts"][attempt_id].get("reservation_sequence", -1),
            )
            selected = root_facts["attempt_facts"][root_facts["frontier_attempt_id"]]
            root_facts["closure_epoch_id"] = (
                f"epoch:{root_id}:{root_facts['authorization_epoch_event_id'] or 'none'}:"
                f"{root_facts['frontier_attempt_id'] or 'none'}:{selected['settlement_event_id'] or 'none'}"
            )
        # Closure is deliberately evaluated from the selected modern epoch,
        # rather than from mutable reservation fields or append order.  This
        # keeps a delayed settlement attached to its own attempt and prevents
        # old probes/reviews from closing a newer repair frontier.
        closure_state = root.get("state")
        if closure_state in {"closure_pending", "closed_verified"}:
            if lower_bound:
                # A procedural lower bound opens the Astra gate but never
                # promotes unknown lifetime history into closure evidence.
                reasons.add(f"closure:lower_bound:{root_id}")
                root_facts["closure_eligible"] = False
                facts[root_id] = _sort_modern_facts(root_facts)
                continue
            gate = root.get("closure_gate") if isinstance(root.get("closure_gate"), Mapping) else {}
            frontier_id = root_facts["frontier_attempt_id"]
            frontier = root_facts["attempt_facts"].get(frontier_id or "", {})
            current_epoch = root_facts["authorization_epoch_event_id"]
            settlement_at = stamp((events.get(frontier.get("settlement_event_id")) or {}).get("settled_at"))
            closure_ok = bool(
                frontier_id and gate.get("repair_attempt_id") == frontier_id
                and frontier.get("completion_eligible")
                and frontier.get("authorization_epoch_event_id") == current_epoch
                and settlement_at is not None
                and not root_facts["unsettled_attempt_ids"]
                and gate.get("review_basis_id") == next((attempt.get("review_basis_id") for attempt in root_attempts
                                                          if attempt.get("repair_attempt_id") == frontier_id), None)
            )
            tests = {item.get("test_evidence_id"): item for item in ledger.get("test_evidence", [])}
            cycles = {item.get("cycle_id"): item for item in ledger.get("cycles", [])}
            probe_ids = [gate.get("original_reproduction_test_evidence_id"),
                         *(gate.get("exact_recurrence_test_evidence_ids") or []),
                         *(gate.get("same_root_sibling_test_evidence_ids") or [])]
            kinds = (["original-reproduction"] + ["exact-recurrence"] * len(gate.get("exact_recurrence_test_evidence_ids") or [])
                     + ["same-root-sibling"] * len(gate.get("same_root_sibling_test_evidence_ids") or []))
            identities: list[str] = []
            post_cycle = cycles.get(gate.get("post_repair_review_cycle_id"))
            post_review = activities.get(gate.get("post_repair_review_activity_id"))
            post_start = stamp((post_cycle or {}).get("started_at")); post_end = stamp((post_cycle or {}).get("completed_at"))
            for test_id, kind in zip(probe_ids, kinds):
                test = tests.get(test_id)
                activity = activities.get((test or {}).get("execution_activity_id"))
                execution_at = stamp((test or {}).get("executed_at"))
                good_probe = bool(
                    isinstance(test, Mapping) and test.get("root_cause_id") == root_id and test.get("kind") == kind
                    and test.get("result") == "pass" and test.get("review_basis_id") == gate.get("review_basis_id")
                    and isinstance(activity, Mapping) and activity.get("type") in {"test", "check"}
                    and activity.get("status") == "completed" and test.get("execution_activity_id") in ((post_cycle or {}).get("activity_ids") or [])
                    and execution_at and stamp(activity.get("started_at")) and stamp(activity.get("completed_at"))
                    and settlement_at and settlement_at < execution_at <= stamp(activity.get("completed_at"))
                    and post_start and post_end and post_start <= stamp(activity.get("started_at")) <= stamp(activity.get("completed_at")) <= post_end
                )
                closure_ok = closure_ok and good_probe
                if isinstance(test, Mapping) and non_empty_string(test.get("identity")):
                    identities.append(test["identity"])
            if len(probe_ids) < 3 or len(identities) != len(probe_ids) or len(set(identities)) != len(identities):
                closure_ok = False
                reasons.add(f"closure_probe_identity_overlap:{root_id}")
            terra_ok = bool(
                isinstance(post_cycle, Mapping) and post_cycle.get("complete") and post_cycle.get("kind") == "post-repair"
                and post_cycle.get("review_basis_id") == gate.get("review_basis_id")
                and isinstance(post_review, Mapping) and post_review.get("status") == "completed"
                and post_review.get("type") in {"review", "post-repair-review"}
                and gate.get("post_repair_review_activity_id") in (post_cycle.get("activity_ids") or [])
                and post_review.get("runtime_verified") is True
                and (post_review.get("actual") or {}).get("model") == "gpt-5.6-terra"
                and (post_review.get("actual") or {}).get("reasoning_effort") == "high"
                and post_review.get("review_route") in {"named-terra-first-pass", "generic-terra-first-pass"}
                and stamp(post_review.get("started_at")) and stamp(post_review.get("completed_at"))
                and post_end and stamp(post_review.get("completed_at")) <= post_end
                and all(stamp((activities.get((tests.get(test_id) or {}).get("execution_activity_id")) or {}).get("completed_at")) <= stamp(post_review.get("started_at")) for test_id in probe_ids)
            )
            if not terra_ok:
                reasons.add(f"closure_post_repair_terra_route:{root_id}")
            closure_ok = closure_ok and terra_ok
            pending = [event for event in context.rows["events"] if event.get("type") == "closure-pending"
                       and event.get("root_cause_id") == root_id and event.get("cycle_id") == gate.get("post_repair_review_cycle_id")
                       and event.get("repair_attempt_id") == frontier_id and event.get("review_basis_id") == gate.get("review_basis_id")]
            pending_event = pending[0] if len(pending) == 1 else None
            closure_ok = closure_ok and bool(pending_event and stamp(pending_event.get("at")) and post_end and stamp(pending_event.get("at")) >= post_end)
            if closure_state == "closed_verified":
                following = cycles.get(gate.get("following_unchanged_cycle_id"))
                following_review = activities.get(gate.get("following_unchanged_activity_id"))
                closed_event = events.get(root.get("closure_event_id"))
                following_ok = bool(
                    isinstance(following, Mapping) and following.get("complete") and following.get("kind") == "unchanged-closure"
                    and following.get("review_basis_id") == gate.get("review_basis_id") and isinstance(following_review, Mapping)
                    and following_review.get("status") == "completed" and gate.get("following_unchanged_activity_id") in (following.get("activity_ids") or [])
                    and post_cycle and following.get("sequence", 0) > post_cycle.get("sequence", 0)
                    and pending_event is not None and stamp(following.get("started_at")) and stamp(pending_event.get("at")) and stamp(following.get("started_at")) > stamp(pending_event.get("at"))
                    and isinstance(closed_event, Mapping) and closed_event.get("type") == "root-closed-verified"
                    and closed_event.get("cycle_id") == following.get("cycle_id") and closed_event.get("review_basis_id") == gate.get("review_basis_id")
                    and stamp(closed_event.get("at")) and stamp(following.get("completed_at")) and stamp(closed_event.get("at")) >= stamp(following.get("completed_at"))
                )
                # The cited following review must be the first complete
                # unchanged cycle on this basis after the pending event.
                if following_ok:
                    for candidate in cycles.values():
                        if candidate.get("cycle_id") not in {post_cycle.get("cycle_id"), following.get("cycle_id")} and candidate.get("complete") and candidate.get("kind") == "unchanged-closure" and candidate.get("review_basis_id") == gate.get("review_basis_id") and post_cycle.get("sequence", 0) < candidate.get("sequence", 0) < following.get("sequence", 0):
                            following_ok = False; reasons.add(f"closure_first_subsequent_skipped:{root_id}")
                closure_ok = closure_ok and following_ok
            root_facts["closure_eligible"] = bool(closure_ok)
            if not closure_ok:
                reasons.add(f"closure:epoch:{root_id}")
        if root_facts["uncovered_mutation_activity_ids"]:
            root_facts["gate_state"] = "blocked"; root_facts["awaiting_astra"] = True
        elif root_facts["unauthorized_attempt_ids"]:
            root_facts["gate_state"] = "blocked"; root_facts["awaiting_astra"] = True
        elif root_facts["fresh_unused_authorization_event_ids"]:
            root_facts["gate_state"] = "open"; root_facts["awaiting_astra"] = False
        elif any(item["lifecycle_state"] == "active" for item in root_facts["attempt_facts"].values()):
            root_facts["gate_state"] = "repairing"; root_facts["awaiting_astra"] = False
        elif (root_facts["frontier_attempt_id"] is not None
              and root_facts["attempt_facts"][root_facts["frontier_attempt_id"]]["completion_eligible"]
              and root_facts["attempt_facts"][root_facts["frontier_attempt_id"]].get("authorization_epoch_event_id") == root_facts["authorization_epoch_event_id"]):
            root_facts["gate_state"] = "awaiting_post_repair_review"; root_facts["awaiting_astra"] = False
        if root_facts["closure_eligible"]:
            root_facts["gate_state"] = closure_state; root_facts["awaiting_astra"] = False
        if root.get("state") != root_facts["gate_state"]:
            reasons.add(f"auth:frontier:{root_id}")
        facts[root_id] = _sort_modern_facts(root_facts)
    return facts, reasons


def _sort_modern_facts(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sort_modern_facts(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return sorted((_sort_modern_facts(item) for item in value), key=lambda item: str(item))
    return value


def _legacy_row_root_ownership(
        context: ValidationContext) -> dict[tuple[str, int], set[str]]:
    """Resolve neutral-row root ownership without expanding explicit ownership."""
    explicit_roots: dict[tuple[str, int], set[str]] = {}
    row_roots: dict[tuple[str, int], set[str]] = {}
    rows_by_id: dict[str, list[tuple[str, int]]] = defaultdict(list)
    all_rows: dict[tuple[str, int], Mapping[str, Any]] = {}
    for collection, identity_key in _LEGACY_COLLECTIONS.items():
        for index, row in enumerate(context.rows[collection]):
            key = (collection, index)
            all_rows[key] = row
            roots = {row.get("root_cause_id")} if isinstance(row.get("root_cause_id"), str) else set()
            roots.update(value for value in (row.get("root_cause_ids") or []) if isinstance(value, str))
            explicit_roots[key] = roots
            row_roots[key] = set(roots)
            row_id = row.get(identity_key)
            if isinstance(row_id, str):
                rows_by_id[row_id].append(key)

    def referenced_ids(value: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(value, str):
            if value in rows_by_id:
                found.add(value)
        elif isinstance(value, Mapping):
            for child in value.values():
                found.update(referenced_ids(child))
        elif isinstance(value, (list, tuple)):
            for child in value:
                found.update(referenced_ids(child))
        return found

    changed = True
    while changed:
        changed = False
        for key, row in all_rows.items():
            # Explicit ownership is authoritative.  Only neutral rows inherit,
            # and inferred ownership never converts a neutral row into an
            # explicit one that would stop before the fixed point is reached.
            if explicit_roots[key]:
                continue
            inherited: set[str] = set()
            for reference in referenced_ids(row):
                for target in rows_by_id[reference]:
                    inherited.update(row_roots[target])
            if inherited != row_roots[key]:
                row_roots[key] = inherited
                changed = True
    return row_roots


def _legacy_frozen_touch_rows(
    context: ValidationContext,
    snapshot: Mapping[str, Any],
    frozen_root_ids: set[str],
) -> set[tuple[str, int]]:
    """Return every row connected by a forward reference to frozen material.

    This is deliberately independent of lifecycle ownership.  Explicit current
    ownership is meaningful to the ordinary lifecycle graph, but it cannot
    erase a nested reference to a frozen root, a neutral bridge, or an identity
    colliding with any namespace in the authenticated snapshot.
    """
    all_rows: dict[tuple[str, int], Mapping[str, Any]] = {}
    rows_by_id: dict[str, set[tuple[str, int]]] = defaultdict(set)
    frozen_identity_values: set[str] = set()
    for collection, identity_key in _LEGACY_COLLECTIONS.items():
        snapshot_rows = snapshot.get(collection)
        boundary = len(snapshot_rows) if isinstance(snapshot_rows, list) else 0
        for row in (snapshot_rows or []):
            if isinstance(row, Mapping) and isinstance(row.get(identity_key), str):
                frozen_identity_values.add(row[identity_key])
        for index, row in enumerate(context.rows[collection]):
            key = (collection, index)
            all_rows[key] = row
            identity = row.get(identity_key)
            if isinstance(identity, str):
                rows_by_id[identity].add(key)

    def referenced_ids(value: Any) -> set[str]:
        if isinstance(value, str):
            return {value} if value in rows_by_id else set()
        if isinstance(value, Mapping):
            return set().union(*(referenced_ids(child) for child in value.values())) if value else set()
        if isinstance(value, (list, tuple)):
            return set().union(*(referenced_ids(child) for child in value)) if value else set()
        return set()

    referenced_rows: dict[tuple[str, int], set[tuple[str, int]]] = {}
    touched: set[tuple[str, int]] = set()
    for key, row in all_rows.items():
        direct_roots = {row.get("root_cause_id")} if isinstance(row.get("root_cause_id"), str) else set()
        direct_roots.update(value for value in (row.get("root_cause_ids") or []) if isinstance(value, str))
        collection, index = key
        identity = row.get(_LEGACY_COLLECTIONS[collection])
        snapshot_rows = snapshot.get(collection)
        boundary = len(snapshot_rows) if isinstance(snapshot_rows, list) else 0
        if direct_roots.intersection(frozen_root_ids) \
                or (index >= boundary and isinstance(identity, str) and identity in frozen_identity_values):
            touched.add(key)
        targets: set[tuple[str, int]] = set()
        for reference in referenced_ids(row):
            targets.update(rows_by_id[reference])
        referenced_rows[key] = targets

    changed = True
    while changed:
        changed = False
        for key, targets in referenced_rows.items():
            if key not in touched and targets.intersection(touched):
                touched.add(key)
                changed = True
    return touched


def _legacy_compatibility_threshold_lifecycle(
        context: ValidationContext, snapshot: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Apply current controls only to post-snapshot, root-local material.

    Frozen v6.0 rows remain nonauthorizing historical evidence.  A current row
    never becomes historical merely by carrying a backdated timestamp.
    """
    snapshot_rows = {
        collection: [row for row in snapshot.get(collection, []) if isinstance(row, Mapping)]
        for collection in _LEGACY_COLLECTIONS
    }
    frozen_ids = {
        collection: {
            row.get(identity) for row in snapshot_rows[collection]
            if isinstance(row, Mapping) and isinstance(row.get(identity), str)
        }
        for collection, identity in _LEGACY_COLLECTIONS.items()
    }
    # Snapshot prefix preservation has already been proven byte-semantically.
    # Membership is therefore positional *and* exact, never inferred from a
    # caller-controlled ID, record_kind, or timestamp.  Every appended row is
    # current material even when it copies the legacy shape or backdates itself.
    current_rows = {
        collection: list(context.rows[collection][len(snapshot_rows[collection]):])
        for collection in _LEGACY_COLLECTIONS
    }
    row_roots = _legacy_row_root_ownership(context)

    report_origins, report_reasons, _ = _historical_report_import_state(context, snapshot)
    current_root_ids: set[str] = set()
    frozen_root_ids = set(
        LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]["frozen_root_ids"]
    )
    frozen_touches = _legacy_frozen_touch_rows(context, snapshot, frozen_root_ids)
    for collection in _LEGACY_COLLECTIONS:
        boundary = len(snapshot_rows[collection])
        for index in range(boundary, len(context.rows[collection])):
            roots = row_roots[(collection, index)]
            identity = context.rows[collection][index].get(_LEGACY_COLLECTIONS[collection])
            if (collection, index) in frozen_touches:
                reasons_key = identity if isinstance(identity, str) else str(index)
                report_reasons.add(f"compat:frozen_root_touch:{collection}:{reasons_key}")
                continue
            current_root_ids.update(roots)
    current_root_ids.update(report_origins)

    # Historical facts are rederived from the authenticated frozen snapshot,
    # not from a current ledger with selected roots removed.  This prevents a
    # neutral/shared appended row from silently altering a frozen root.
    frozen_ledger = deepcopy(snapshot)
    frozen_context = _validation_context(frozen_ledger)
    frozen_facts, frozen_reasons = (
        _legacy_threshold_lifecycle(frozen_context) if frozen_context is not None else ({}, {"compat:context"})
    )
    if not current_root_ids:
        return frozen_facts, set(frozen_reasons) | report_reasons

    reasons = set(frozen_reasons) | report_reasons
    transformed = deepcopy(context.ledger)
    transformed["roots"] = [
        deepcopy(root) for root in context.rows["roots"] if root.get("root_cause_id") in current_root_ids
    ]
    receipt_text = str(LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]
                       ["threshold_evidence"]["threshold_evidence_received_at"])
    receipt_time = parse_rfc3339(receipt_text)
    threshold_root = LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]["threshold_evidence"]["root_cause_id"]
    threshold_origins: dict[str, Mapping[str, Any]] = dict(report_origins)
    for root_id in current_root_ids - set(report_origins):
        threshold_origins[root_id] = {
            "version": "compatibility-control.v1",
            "root_cause_id": root_id,
            "enforcement_boundary": receipt_text,
            "enforcement_boundary_basis": "auditable-receipt-upper-bound",
            "original_protocol_adopted_at": None,
        }

    for attempt in current_rows["repair_attempts"]:
        attempt_id, root_id = attempt.get("repair_attempt_id"), attempt.get("root_cause_id")
        if root_id not in current_root_ids:
            continue
        if attempt.get("record_kind") != "reservation":
            reasons.add(f"compat:current_attempt_contract:{root_id}:{attempt_id}")
            continue
        starts = [event for event in context.rows["events"]
                  if event.get("type") == "repair-attempted" and event.get("repair_attempt_id") == attempt_id]
        implementation_ids = attempt.get("implementation_activity_ids") \
            if isinstance(attempt.get("implementation_activity_ids"), list) else []
        implementations = [context.indexes["activities"].get(item) for item in implementation_ids]
        if starts or any(isinstance(item, Mapping) for item in implementations) or attempt.get("started_at") is not None:
            timestamps = [attempt.get("started_at"), *(item.get("at") for item in starts),
                          *(item.get("started_at") for item in implementations if isinstance(item, Mapping))]
            if receipt_time is None or any((instant := parse_rfc3339(value)) is None or instant < receipt_time
                                           for value in timestamps if value is not None):
                reasons.add(f"compat:backdated_current_attempt:{root_id}:{attempt_id}")
        strategy_id = attempt.get("strategy_id")
        authorization_id = attempt.get("authorization_event_id")
        authorization = context.indexes["events"].get(authorization_id)
        activity_id = authorization.get("adjudication_activity_id") if isinstance(authorization, Mapping) else None
        if (strategy_id in frozen_ids["strategies"] or authorization_id in frozen_ids["events"]
                or activity_id in frozen_ids["activities"]):
            reasons.add(f"compat:frozen_authority_reuse:{root_id}:{attempt_id}")
    transformed_context = _validation_context(transformed)
    modern_facts, modern_reasons = (
        _modern_threshold_lifecycle(transformed_context, threshold_origins)
        if transformed_context is not None else ({}, {"compat:context"})
    )
    reasons.update(modern_reasons)
    return {**frozen_facts, **modern_facts}, reasons


def rule_threshold_lifecycle(context: ValidationContext) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """One threshold/lifecycle rule with a finite legacy compatibility branch."""
    modern = any(item.get("record_kind") == "reservation" for item in context.rows["repair_attempts"])
    # An activation appended to a bounded historical ledger records
    # applicability; it does not convert completed legacy attempts into modern
    # reservations or invent execution authority.
    return _modern_threshold_lifecycle(context) if modern else _legacy_threshold_lifecycle(context)


def _lower_bound_binding_snapshot_ok(previous: Mapping[str, Any], current: Mapping[str, Any], root_id: str) -> bool:
    """The one append-only exception for binding an already-known threshold.

    The exception does not permit a migration: the activation is pre-existing,
    all direct/transitively shared root material is frozen, and only the two
    root pointers change from explicit null to the generic second incident.
    """
    previous_context = _validation_context(previous); current_context = _validation_context(current)
    if previous_context is None or current_context is None:
        return False
    old = previous_context.indexes["roots"].get(root_id); new = current_context.indexes["roots"].get(root_id)
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return False
    if (any(field not in old or old.get(field) is not None for field in (
                "threshold_anchor", "first_threshold_activation_event_id", "historical_baseline_reconciliation_event_id"))
            or new.get("historical_baseline_reconciliation_event_id") is not None
            or new.get("historical_escape_count_baseline") is not None or new.get("escape_count_lifetime") is not None
            or new.get("reconciliation_complete") is not False):
        return False
    incidents, incident_reasons = _modern_escape_incidents(current_context, root_id)
    if incident_reasons or len(incidents) < 2:
        return False
    expected_anchor = incidents[1].get("event_id")
    anchor = new.get("threshold_anchor")
    activation_id = new.get("first_threshold_activation_event_id")
    if not (isinstance(anchor, Mapping) and anchor == {"kind": "post-cutover-escape", "threshold_escape_event_id": expected_anchor}
            and isinstance(activation_id, str)):
        return False
    old_activation = previous_context.indexes["events"].get(activation_id)
    activation = current_context.indexes["events"].get(activation_id)
    all_activations = [event for event in current_context.rows["events"]
                       if event.get("type") == "threshold-activated" and event.get("root_cause_id") == root_id]
    if not (isinstance(old_activation, Mapping) and old_activation == activation and len(all_activations) == 1
            and activation.get("activation_anchor_event_id") == expected_anchor):
        return False
    # Only the two pointer fields are mutable on the root row.
    for key in set(old) | set(new):
        if key not in {"threshold_anchor", "first_threshold_activation_event_id"} and old.get(key) != new.get(key):
            return False

    # Freeze an exhaustive, namespaced support graph from both snapshots.  All
    # nested scalar identities are traversed, including membership containers
    # and every namespace collision.  An explicitly disjoint-root *source* row
    # is a boundary, so an unrelated append may cite target evidence without
    # becoming target history; neutral and shared source rows remain connected.
    collections = {
        "observations": "observation_id", "repair_attempts": "repair_attempt_id", "strategies": "strategy_id",
        "activities": "activity_id", "events": "event_id", "review_bases": "review_basis_id", "cycles": "cycle_id",
        "test_evidence": "test_evidence_id",
    }
    def root_names(row: Mapping[str, Any]) -> set[str]:
        names = {row.get("root_cause_id")} if isinstance(row.get("root_cause_id"), str) else set()
        names.update(value for value in (row.get("root_cause_ids") or []) if isinstance(value, str))
        def nested_bindings(value: Any) -> None:
            if isinstance(value, Mapping):
                if isinstance(value.get("root_cause_id"), str) and (
                    "repair_attempt_id" in value or "strategy_id" in value
                ):
                    names.add(value["root_cause_id"])
                for child in value.values():
                    nested_bindings(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    nested_bindings(child)
        nested_bindings(row.get("repair_attempt_bindings") or [])
        return names
    def graph(context: ValidationContext) -> tuple[dict[tuple[str, str], Mapping[str, Any]], dict[str, set[tuple[str, str]]]]:
        vertices: dict[tuple[str, str], Mapping[str, Any]] = {}
        by_id: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for collection, identity in collections.items():
            for row in context.rows.get(collection, ()):
                value = row.get(identity)
                if isinstance(value, str):
                    vertex = (collection, value); vertices[vertex] = row; by_id[value].add(vertex)
        return vertices, by_id
    old_vertices, old_by_id = graph(previous_context); new_vertices, new_by_id = graph(current_context)
    by_id: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for source in (old_by_id, new_by_id):
        for value, items in source.items(): by_id[value].update(items)
    def refs(value: Any) -> set[str]:
        found: set[str] = set()
        def walk(item: Any) -> None:
            if isinstance(item, str):
                if item in by_id:
                    found.add(item)
            elif isinstance(item, Mapping):
                for child in item.values():
                    walk(child)
            elif isinstance(item, (list, tuple)):
                for child in item:
                    walk(child)
        walk(value)
        return found
    adjacency: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    protected: set[tuple[str, str]] = set()
    for vertices in (old_vertices, new_vertices):
        for vertex, row in vertices.items():
            names = root_names(row)
            if root_id in names:
                protected.add(vertex)
            if names and root_id not in names:
                continue
            for ref in refs(row):
                for target in by_id.get(ref, set()):
                    if target == vertex:
                        continue
                    adjacency[vertex].add(target)
                    adjacency[target].add(vertex)
    queue = list(protected)
    while queue:
        vertex = queue.pop()
        for target in adjacency.get(vertex, set()):
            if target not in protected:
                protected.add(target)
                queue.append(target)
    for collection, identity in collections.items():
        old_rows = {row.get(identity): row for row in previous_context.rows.get(collection, ()) if isinstance(row.get(identity), str)}
        new_rows = {row.get(identity): row for row in current_context.rows.get(collection, ()) if isinstance(row.get(identity), str)}
        for item_id, row in old_rows.items():
            if (collection, item_id) in protected and new_rows.get(item_id) != row:
                return False
        for item_id, row in new_rows.items():
            if (collection, item_id) in protected and item_id not in old_rows:
                return False
    return True


def _previous_snapshot_reasons(previous: Any, current: Any, schema: Any) -> set[str]:
    """Check the append-only portion observable from two ledger snapshots.

    A single snapshot cannot prove non-rewrite.  When a prior snapshot is
    supplied, this is deliberately part of the sole production validator so a
    consumer cannot accept a new authorization/lifecycle history while using a
    different append-only interpretation.
    """
    reasons: set[str] = set()
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return {"event:immutable:previous_snapshot_not_object"}
    previous_task = (previous.get("task") or {}).get("task_instance_id")
    previous_attempts = previous.get("repair_attempts") if isinstance(previous.get("repair_attempts"), list) else []
    if any(isinstance(item, Mapping) and item.get("record_kind") == "reservation" and not isinstance(item.get("reservation_event_id"), str)
           for item in previous_attempts):
        return {f"compat:unsupported-modern-reservation-version:{previous_task}"}
    for reason in _schema_reasons(previous, schema):
        reasons.add(f"previous_{reason}")
    reasons.update(f"previous_{reason}" for reason in _threshold_prederive_reasons(previous))
    if reasons:
        return reasons

    def rows(ledger: Mapping[str, Any], collection: str, identity: str) -> dict[str, Mapping[str, Any]]:
        value = ledger.get(collection)
        if not isinstance(value, list):
            return {}
        return {item[identity]: item for item in value if isinstance(item, Mapping) and isinstance(item.get(identity), str)}

    previous_events = previous.get("events") if isinstance(previous.get("events"), list) else []
    current_events = current.get("events") if isinstance(current.get("events"), list) else []
    if len(current_events) < len(previous_events):
        for event in previous_events[len(current_events):]:
            if isinstance(event, Mapping):
                reasons.add(f"event:immutable:{event.get('event_id')}")
    for index, event in enumerate(previous_events[:len(current_events)]):
        candidate = current_events[index]
        if event != candidate:
            event_id = event.get("event_id") if isinstance(event, Mapping) else index
            reasons.add(f"event:immutable:{event_id}")

    for collection, identity, prefix in (("repair_attempts", "repair_attempt_id", "lc:terminal"),
                                         ("strategies", "strategy_id", "auth:activation_immutable")):
        old_rows, new_rows = rows(previous, collection, identity), rows(current, collection, identity)
        for item_id, old in old_rows.items():
            if new_rows.get(item_id) != old:
                root_id = old.get("root_cause_id")
                reasons.add(f"{prefix}:{root_id}:{item_id}")

    old_roots, new_roots = rows(previous, "roots", "root_cause_id"), rows(current, "roots", "root_cause_id")
    for root_id, old in old_roots.items():
        new = new_roots.get(root_id)
        if not isinstance(new, Mapping):
            reasons.add(f"auth:activation_immutable:{root_id}")
            continue
        protected_fields = ("threshold_anchor", "first_threshold_activation_event_id", "historical_baseline_reconciliation_event_id")
        changed = [field for field in protected_fields if old.get(field) != new.get(field)]
        presence_changed = any((field in old) != (field in new) for field in protected_fields)
        if (changed or presence_changed) and not _lower_bound_binding_snapshot_ok(previous, current, root_id):
            reasons.add(f"auth:activation_binding:{root_id}")
            reasons.add(f"auth:activation_immutable:{root_id}")
        if root_id == HISTORICAL_REPORT_ROOT_ID:
            mutable = {"state", "previous_state", "blocked_reason", "block_code"}
            if any(old.get(field) != new.get(field) or ((field in old) != (field in new))
                   for field in set(old) | set(new) if field not in mutable):
                reasons.add(f"report_import:origin_immutable:{root_id}")
    old_observations, new_observations = rows(previous, "observations", "observation_id"), rows(current, "observations", "observation_id")
    for payload in HISTORICAL_REPORT_IMPORT_PAYLOADS:
        observation_id = payload["observation_id"]
        if observation_id in old_observations and not _json_exact(old_observations[observation_id], new_observations.get(observation_id)):
            reasons.add(f"report_import:origin_immutable:{observation_id}")
    for field in ("cutover_id", "protocol_adopted_at", "post_cutover_boundary"):
        if (previous.get("cutover") or {}).get(field) != (current.get("cutover") or {}).get(field):
            reasons.add(f"auth:activation_immutable:cutover:{field}")

    old_activities, new_activities = rows(previous, "activities", "activity_id"), rows(current, "activities", "activity_id")
    terminal = {"completed", "failed", "cancelled"}
    for activity_id, old in old_activities.items():
        new = new_activities.get(activity_id)
        root_id = next(iter(old.get("root_cause_ids") or []), "none")
        bindings = old.get("repair_attempt_bindings") or []
        attempt_id = bindings[0].get("repair_attempt_id") if bindings and isinstance(bindings[0], Mapping) else old.get("repair_attempt_id") or "none"
        suffix = f"{root_id}:{attempt_id}:{activity_id}"
        if not isinstance(new, Mapping):
            reasons.add(f"lc:terminal:{suffix}")
            continue
        immutable_fields = ("activity_id", "type", "started_at", "root_cause_ids", "attribution_mode", "repair_attempt_id", "repair_attempt_bindings")
        if any(old.get(field) != new.get(field) for field in immutable_fields):
            reasons.add(f"lc:terminal:{suffix}")
            continue
        old_status, new_status = old.get("status"), new.get("status")
        if old_status in terminal:
            if old_status != new_status or old.get("completed_at") != new.get("completed_at"):
                reasons.add(f"lc:terminal:{suffix}")
        elif old_status == "running":
            completed = parse_rfc3339(new.get("completed_at"))
            started = parse_rfc3339(new.get("started_at"))
            evidence_ok = bool(new.get("runtime_evidence")) or bool(new.get("runtime_unavailable_reason"))
            if new_status not in terminal or completed is None or started is None or completed < started or not evidence_ok:
                reasons.add(f"lc:terminal:{suffix}")
        elif old_status != new_status or old.get("completed_at") != new.get("completed_at"):
            reasons.add(f"lc:terminal:{suffix}")
    return reasons


RULE_REGISTRY: tuple[Callable[..., Any], ...] = (
    check_ids_and_sequences, check_references, check_closure_and_escape_rules,
    check_integrity, check_temporal_and_event_integrity, check_closure_temporal_order,
    check_escape_binding_threshold, check_escape_observation_bijection,
    check_repair_attempt_integrity, check_new_causal_rules, check_escape_reopen_causality,
    check_closure_lifecycle_causality, check_basis_invalidation, check_root_activity_attribution,
    rule_threshold_lifecycle,
)


def _activity_inventory_facts(
    ledger: Mapping[str, Any], snapshot: Mapping[str, Any] | None,
) -> dict[str, Any]:
    activities = [row for row in ledger.get("activities", []) if isinstance(row, Mapping)]
    if snapshot is not None:
        frozen = [row for row in snapshot.get("activities", []) if isinstance(row, Mapping)]
        frozen_ids = [row.get("activity_id") for row in frozen if isinstance(row.get("activity_id"), str)]
        post_ids = [
            row.get("activity_id") for row in activities[len(frozen):]
            if isinstance(row.get("activity_id"), str)
        ]
        return {
            "basis": "authenticated-legacy-snapshot-plus-current-rows",
            "snapshot_sha256": LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]["original"]["ledger_sha256"],
            "frozen_activity_ids": frozen_ids,
            "post_snapshot_activity_ids": post_ids,
            "frozen_recorded_activity_count": len(frozen_ids),
            "post_snapshot_recorded_activity_count": len(post_ids),
            "recorded_participating_activity_count": len(frozen_ids) + len(post_ids),
            "expected_participating_activity_count": None,
            "activity_inventory_complete": False,
        }
    telemetry = ledger.get("telemetry") if isinstance(ledger.get("telemetry"), Mapping) else {}
    return {
        "basis": "validated-ledger-telemetry",
        "snapshot_sha256": None,
        "frozen_activity_ids": [],
        "post_snapshot_activity_ids": [
            row.get("activity_id") for row in activities if isinstance(row.get("activity_id"), str)
        ],
        "frozen_recorded_activity_count": 0,
        "post_snapshot_recorded_activity_count": telemetry.get("recorded_participating_activity_count"),
        "recorded_participating_activity_count": telemetry.get("recorded_participating_activity_count"),
        "expected_participating_activity_count": telemetry.get("expected_participating_activity_count"),
        "activity_inventory_complete": telemetry.get("activity_inventory_complete"),
    }


def validate_ledger(ledger: Any, schema: Any, previous_ledger: Any = None, *, loaded_path: Any = None,
                    marker: Any = None, cutover: Any = None, target: Any = None) -> ValidationResult:
    """Validate an MAS1 ledger and return stable reasons plus one facts graph.

    Invalid JSON-shaped values are ordinary validation failures, never exceptions.
    Callers must treat every nonempty reason list as fail-closed.
    """
    reasons: set[str] = set()
    facts: dict[str, Any] = {"indexes": {}, "roots": [], "activities": [], "threshold_facts": {}}
    try:
        reasons.update(_schema_reasons(ledger, schema))
        # Structural validation is a hard boundary for malformed containers and
        # identity types.  Other schema failures still reach safe procedural
        # checks so retained fixtures preserve their causal error obligation.
        unsafe = not isinstance(ledger, dict)
        if isinstance(ledger, dict):
            identity_fields = {"roots": "root_cause_id", "observations": "observation_id", "activities": "activity_id",
                               "events": "event_id", "repair_attempts": "repair_attempt_id", "strategies": "strategy_id",
                               "cycles": "cycle_id", "review_bases": "review_basis_id", "test_evidence": "test_evidence_id"}
            for collection, identity in identity_fields.items():
                rows = ledger.get(collection)
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    unsafe = True; break
                if any(identity in row and not isinstance(row.get(identity), str) for row in rows):
                    unsafe = True; break
        if unsafe:
            return ValidationResult(False, tuple(sorted(reasons)), {"indexes": {}, "roots": [], "activities": [], "threshold_facts": {}})
        compatibility_active, compatibility_reasons, legacy_snapshot = _legacy_compatibility_reasons(
            ledger, loaded_path, marker)
        reasons.update(compatibility_reasons)
        if previous_ledger is not None:
            reasons.update(_previous_snapshot_reasons(previous_ledger, ledger, schema))
        prederive = _threshold_prederive_reasons(ledger)
        reasons.update(prederive)
        if prederive:
            return ValidationResult(False, tuple(sorted(reasons)), {"indexes": {}, "roots": [], "activities": [], "threshold_facts": {}})
        context = _validation_context(ledger)
        facts = _derive_facts(ledger)
        if context is not None:
            facts["validation_context"] = context.normalized
            reasons.update(_historical_report_field_scope_reasons(
                context, compatibility_active=compatibility_active))
        if isinstance(ledger, dict):
            reasons.update(_native_canonical_task_path_reasons(ledger.get("task", {})))
            reasons.update(_canonical_path_reasons(
                ledger, loaded_path, marker, cutover, target, legacy_compatibility=compatibility_active))
            if context is None:
                reasons.add("internal:validation_context_unavailable")
                threshold_facts = {}
            else:
                threshold_facts = _run_native_rules(
                    ledger, reasons, context, legacy_snapshot if compatibility_active else None)
            facts["threshold_facts"] = threshold_facts
            facts["activity_inventory"] = _activity_inventory_facts(ledger, legacy_snapshot if compatibility_active else None)
            facts["lifetime_escape_counts"] = {root_id: fact["lifetime_count"] for root_id, fact in threshold_facts.items()}
            facts["legacy_v6_0_audit"] = {
                "active": compatibility_active,
                "migration_id": LEGACY_V6_0_AUDIT_MIGRATION_ID if compatibility_active else None,
                "original_protocol_adopted_at": None if compatibility_active else (ledger.get("cutover") or {}).get("protocol_adopted_at"),
                "threshold_evidence_received_at": (
                    LEGACY_V6_0_AUDIT_CATALOGUE[LEGACY_V6_0_AUDIT_MIGRATION_ID]
                    ["threshold_evidence"]["threshold_evidence_received_at"] if compatibility_active else None
                ),
            }
        else:
            reasons.add("ledger_not_object")
    except Exception as exc:
        reasons.add(f"internal:validate_ledger:{type(exc).__name__}")
    if "validation_context" in facts:
        facts["validation_context"] = {**facts["validation_context"], "authoritative": not reasons}
    return ValidationResult(not reasons, tuple(sorted(reasons)), facts)


def canonical_task_path_reasons(task: Any) -> tuple[str, ...]:
    """Public lexical task-path check used by cutover population loading."""
    try:
        return tuple(sorted(_native_canonical_task_path_reasons(task)))
    except Exception as exc:
        return (f"internal:task_path:{type(exc).__name__}",)


def validate_cutover_population(manifest: Any) -> CutoverPopulationResult:
    """Validate the frozen rollout cohort and its dispatch/adoption lifecycle.

    This is intentionally a core entry point: metrics consumers may select a
    population only after this exact state machine has accepted it.
    """
    reasons: set[str] = set()
    targets: dict[str, Mapping[str, Any]] = {}
    if not isinstance(manifest, dict):
        return CutoverPopulationResult(False, ("population_manifest_not_object",), {}, {})
    cutover_id = manifest.get("cutoverId")
    if cutover_id in INVALIDATED_CUTOVER_CATALOGUE:
        # Reject by identifier before interpreting a potentially edited copy of
        # the invalid rollout.  A later internally consistent payload cannot
        # rehabilitate this population or make --allow-invalid meaningful.
        return CutoverPopulationResult(
            False,
            (f"population_cutover_invalidated:{cutover_id}",),
            manifest,
            {},
        )
    discovery = manifest.get("targetDiscovery")
    if not isinstance(discovery, dict):
        return CutoverPopulationResult(False, ("population_target_discovery_invalid",), manifest, {})
    status = discovery.get("status")
    entries = discovery.get("targetDispatch")
    if not isinstance(entries, list):
        reasons.add("population_target_dispatch_not_array")
        entries = []
    boundary = manifest.get("postCutoverBoundary")
    if status == "not-dispatched":
        if boundary is not None:
            reasons.add("population_pre_dispatch_boundary_must_be_null")
        if entries:
            reasons.add("population_pre_dispatch_targets_forbidden")
        reasons.add("population_target_discovery_not_ready:not-dispatched")
    elif status in {"dispatched", "adoption-in-progress", "complete"}:
        if parse_rfc3339(boundary) is None:
            reasons.add("population_master_boundary_invalid")
        if not entries:
            reasons.add("population_no_eligible_targets")
    else:
        reasons.add(f"population_target_discovery_not_ready:{status}")
    paths: set[str] = set()
    markers: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            reasons.add("population_target_not_object")
            continue
        task_id = entry.get("taskInstanceId")
        workspace = entry.get("workspace")
        ledger_path = entry.get("ledgerPath")
        marker_path = entry.get("markerPath")
        if not all(isinstance(value, str) and value for value in (task_id, workspace, ledger_path, marker_path)):
            reasons.add(f"population_target_missing_field:{task_id}")
            continue
        if entry.get("eligibleForAnalysis") is not True:
            reasons.add(f"population_target_ineligible_forbidden:{task_id}")
        for reason in _target_dispatch_reasons(entry, boundary, require_identity=True):
            reasons.add(f"population_{reason}:{task_id}")
        if task_id in targets:
            reasons.add(f"population_target_duplicate_task_instance_id:{task_id}")
        if ledger_path in paths:
            reasons.add(f"population_target_duplicate_ledger_path:{ledger_path}")
        if marker_path in markers:
            reasons.add(f"population_target_duplicate_marker_path:{marker_path}")
        if task_id in targets or ledger_path in paths or marker_path in markers:
            continue
        targets[task_id] = entry
        paths.add(ledger_path)
        markers.add(marker_path)
    return CutoverPopulationResult(not reasons, tuple(sorted(reasons)), manifest, targets)
