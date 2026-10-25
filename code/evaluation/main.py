#!/usr/bin/env python3
"""Validate the public examples and deterministic agent invariants."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from main import (  # noqa: E402
    Observation,
    is_deletion_request,
    latest_observations,
    order_steps,
    parse_time,
)


STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def canonical_step(step: dict[str, object]) -> tuple[object, ...]:
    return tuple(step.get(key) for key in STEP_FIELDS)


def evaluate_samples() -> dict[str, object]:
    expected = load_csv(ROOT / "dataset" / "sample_output.csv")
    with tempfile.TemporaryDirectory(prefix="ghost-data-eval-") as temp:
        prediction_path = Path(temp) / "predictions.csv"
        from main import main

        main(
            [
                "--input",
                str(ROOT / "dataset" / "sample_deletion_requests.csv"),
                "--output",
                str(prediction_path),
            ]
        )
        actual = load_csv(prediction_path)

    expected_by_id = {row["case_id"]: row for row in expected}
    actual_by_id = {row["case_id"]: row for row in actual}
    if expected_by_id.keys() != actual_by_id.keys():
        raise AssertionError("Sample prediction case IDs differ from the public sample set")

    status_correct = sum(
        expected_by_id[case_id]["deletion_status"] == actual_by_id[case_id]["deletion_status"]
        for case_id in expected_by_id
    )
    sequence_correct = 0
    field_correct = Counter()
    field_total = Counter()
    expected_steps: Counter[tuple[object, ...]] = Counter()
    actual_steps: Counter[tuple[object, ...]] = Counter()
    expected_count = 0
    actual_count = 0

    for case_id, expected_row in expected_by_id.items():
        expected_array = json.loads(expected_row["steps_json"])
        actual_array = json.loads(actual_by_id[case_id]["steps_json"])
        if expected_array == actual_array:
            sequence_correct += 1
        expected_count += len(expected_array)
        actual_count += len(actual_array)
        expected_steps.update(canonical_step(item) for item in expected_array)
        actual_steps.update(canonical_step(item) for item in actual_array)

        for index in range(max(len(expected_array), len(actual_array))):
            expected_item = expected_array[index] if index < len(expected_array) else {}
            actual_item = actual_array[index] if index < len(actual_array) else {}
            for field in STEP_FIELDS:
                field_total[field] += 1
                field_correct[field] += expected_item.get(field) == actual_item.get(field)

    step_true_positive = sum((expected_steps & actual_steps).values())
    step_precision = step_true_positive / actual_count if actual_count else 0.0
    step_recall = step_true_positive / expected_count if expected_count else 0.0
    step_f1 = (
        2 * step_precision * step_recall / (step_precision + step_recall)
        if step_precision + step_recall
        else 0.0
    )
    field_total_count = sum(field_total.values())
    return {
        "sample_cases": len(expected),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(expected) if expected else 0.0,
        "sequence_correct": sequence_correct,
        "sequence_accuracy": sequence_correct / len(expected) if expected else 0.0,
        "expected_steps": expected_count,
        "actual_steps": actual_count,
        "step_precision": step_precision,
        "step_recall": step_recall,
        "step_f1": step_f1,
        "field_accuracy": sum(field_correct.values()) / field_total_count if field_total_count else 0.0,
        "field_accuracy_by_name": {
            name: field_correct[name] / field_total[name] if field_total[name] else 0.0
            for name in STEP_FIELDS
        },
    }


def run_custom_checks() -> list[tuple[str, bool]]:
    intent_cases = [
        ("Spanish deletion request", "Solicito eliminar definitivamente mi cuenta.", True),
        ("French deletion request", "Je demande la suppression de mon compte.", True),
        (
            "Marketing-only opt-out",
            "Remove me from promotional emails only; I still need the account.",
            False,
        ),
        ("Data access request", "Please send me a copy of my data and keep the account active.", False),
        ("Email correction", "Please change my email address; I want to keep using the service.", False),
    ]
    results = [
        (name, is_deletion_request(text) is expected)
        for name, text, expected in intent_cases
    ]

    cutoff = parse_time("2026-06-01T00:00:00Z")
    before = Observation(
        "account_service",
        "account_101",
        "USER_PROFILE",
        "evidence_before",
        parse_time("2026-05-31T23:00:00Z"),
        available_at=parse_time("2026-05-31T23:30:00Z"),
    )
    after = Observation(
        "account_service",
        "account_102",
        "USER_PROFILE",
        "evidence_after",
        parse_time("2026-06-01T00:01:00Z"),
        available_at=parse_time("2026-06-01T00:02:00Z"),
    )
    results.append(("Audit cutoff excludes later evidence", [o.resource_id for o in latest_observations([before, after], cutoff)] == ["account_101"]))

    unsorted = [
        {
            "step_no": 0,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "VERIFY_RECORD_ABSENT",
        },
        {
            "step_no": 0,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_2",
            "operation": "REPORT_REMAINING_RECORD",
        },
    ]
    ordered = order_steps(unsorted)
    results.append(
        (
            "Phase ordering and consecutive numbering",
            [item["step_no"] for item in ordered] == [1, 2]
            and [item["phase"] for item in ordered] == ["FINDING", "VERIFICATION"],
        )
    )
    return results


def main() -> int:
    metrics = evaluate_samples()
    custom_results = run_custom_checks()
    print("Public sample evaluation:")
    for key in (
        "sample_cases",
        "status_correct",
        "status_accuracy",
        "sequence_correct",
        "sequence_accuracy",
        "expected_steps",
        "actual_steps",
        "step_precision",
        "step_recall",
        "step_f1",
        "field_accuracy",
    ):
        print(f"  {key}: {metrics[key]}")
    print("  field_accuracy_by_name:", metrics["field_accuracy_by_name"])
    print("Additional deterministic checks:")
    for name, passed in custom_results:
        print(f"  {'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(passed for _, passed in custom_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
