
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "validate_review_packets.py"
)

SPEC = importlib.util.spec_from_file_location(
    "validate_review_packets", SCRIPT_PATH
)
assert SPEC is not None
assert SPEC.loader is not None

MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_fixture(tmp_path: Path) -> None:
    criteria = {
        "gates": [{"gate_id": f"G{i}"} for i in range(13)]
    }
    records = []

    for i in range(13):
        records.append({
            "gate_id": f"G{i}",
            "review_status": "NOT_REVIEWED",
            "gate_approval": "NOT_GRANTED",
            "human_review_required": True,
            "candidate_files": [],
            "required_evidence": [{
                "requirement": "Example evidence",
                "evidence_url": None,
                "workflow_run_id": None,
                "commit_sha": None,
                "artifact_name": None,
                "review_result": "NOT_REVIEWED",
                "reviewer_notes": "",
            }],
            "review_checks": [{
                "check": "Example check",
                "result": "NOT_REVIEWED",
                "notes": "",
            }],
            "review_decision": {
                "reviewer": None,
                "reviewed_at": None,
                "decision_notes": "",
            },
        })

    (tmp_path / "review_criteria.json").write_text(
        json.dumps(criteria), encoding="utf-8"
    )

    packets = {
        "protocol": "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS",
        "status": "REVIEW_PACKET_PREPARED",
        "benchmark_status": "DEVELOPMENT_NOT_FROZEN",
        "automatic_approval": False,
        "freeze_authorized": False,
        "gate_count": 13,
        "records": records,
    }

    (tmp_path / "evidence_review_packets.json").write_text(
        json.dumps(packets), encoding="utf-8"
    )


def test_valid_packets_pass(tmp_path: Path, monkeypatch) -> None:
    make_fixture(tmp_path)
    monkeypatch.setattr(MODULE, "GATES_DIR", tmp_path)
    monkeypatch.setattr(
        MODULE, "CRITERIA_PATH", tmp_path / "review_criteria.json"
    )
    monkeypatch.setattr(
        MODULE, "PACKETS_PATH", tmp_path / "evidence_review_packets.json"
    )

    assert MODULE.validate() == []


def test_duplicate_gate_ids_fail(tmp_path: Path, monkeypatch) -> None:
    make_fixture(tmp_path)
    monkeypatch.setattr(MODULE, "GATES_DIR", tmp_path)
    monkeypatch.setattr(
        MODULE, "CRITERIA_PATH", tmp_path / "review_criteria.json"
    )
    monkeypatch.setattr(
        MODULE, "PACKETS_PATH", tmp_path / "evidence_review_packets.json"
    )

    path = tmp_path / "evidence_review_packets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["records"][1]["gate_id"] = data["records"][0]["gate_id"]
    path.write_text(json.dumps(data), encoding="utf-8")

    assert any("Duplicate gate IDs" in error for error in MODULE.validate())


def test_automatic_approval_is_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    make_fixture(tmp_path)
    monkeypatch.setattr(MODULE, "GATES_DIR", tmp_path)
    monkeypatch.setattr(
        MODULE, "CRITERIA_PATH", tmp_path / "review_criteria.json"
    )
    monkeypatch.setattr(
        MODULE, "PACKETS_PATH", tmp_path / "evidence_review_packets.json"
    )

    path = tmp_path / "evidence_review_packets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["automatic_approval"] = True
    path.write_text(json.dumps(data), encoding="utf-8")

    assert any(
        "automatic_approval must be false" in error
        for error in MODULE.validate()
    )


def test_freeze_authorization_is_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    make_fixture(tmp_path)
    monkeypatch.setattr(MODULE, "GATES_DIR", tmp_path)
    monkeypatch.setattr(
        MODULE, "CRITERIA_PATH", tmp_path / "review_criteria.json"
    )
    monkeypatch.setattr(
        MODULE, "PACKETS_PATH", tmp_path / "evidence_review_packets.json"
    )

    path = tmp_path / "evidence_review_packets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["freeze_authorized"] = True
    path.write_text(json.dumps(data), encoding="utf-8")

    assert any(
        "freeze_authorized must be false" in error
        for error in MODULE.validate()
    )


def test_approval_must_remain_not_granted(
    tmp_path: Path, monkeypatch
) -> None:
    make_fixture(tmp_path)
    monkeypatch.setattr(MODULE, "GATES_DIR", tmp_path)
    monkeypatch.setattr(
        MODULE, "CRITERIA_PATH", tmp_path / "review_criteria.json"
    )
    monkeypatch.setattr(
        MODULE, "PACKETS_PATH", tmp_path / "evidence_review_packets.json"
    )

    path = tmp_path / "evidence_review_packets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["records"][0]["gate_approval"] = "PASS"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert any(
        "gate approval must remain NOT_GRANTED" in error
        for error in MODULE.validate()
    )
