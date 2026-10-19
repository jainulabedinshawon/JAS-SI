
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

GATES_DIR = Path(__file__).resolve().parent
PACKETS_PATH = GATES_DIR / "evidence_review_packets.json"
OUTPUT_PATH = GATES_DIR / "human_review_checklist.md"

EXPECTED_PROTOCOL = "JAS-SI-V0.1-EVIDENCE-REVIEW-PACKETS"
EXPECTED_GATE_COUNT = 13


def load_packets() -> dict[str, Any]:
    data = json.loads(PACKETS_PATH.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Review packet must be a JSON object.")

    if data.get("protocol") != EXPECTED_PROTOCOL:
        raise ValueError("Unexpected review packet protocol.")

    if data.get("benchmark_status") != "DEVELOPMENT_NOT_FROZEN":
        raise ValueError("Benchmark must remain DEVELOPMENT_NOT_FROZEN.")

    if data.get("automatic_approval") is not False:
        raise ValueError("Automatic approval must remain disabled.")

    if data.get("freeze_authorized") is not False:
        raise ValueError("Freeze authorization must remain disabled.")

    records = data.get("records")

    if not isinstance(records, list):
        raise ValueError("Review packet records must be a list.")

    if len(records) != EXPECTED_GATE_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_GATE_COUNT} gates; found {len(records)}."
        )

    gate_ids = [
        item.get("gate_id")
        for item in records
        if isinstance(item, dict)
    ]

    if len(gate_ids) != len(records) or len(set(gate_ids)) != len(records):
        raise ValueError("Gate records must be valid and unique.")

    return data


def build_checklist(data: dict[str, Any]) -> str:
    lines = [
        "# JAS-SI v0.1 — Human Evidence Review Checklist",
        "",
        "> **Status: REVIEW PREPARATION ONLY — NOT FROZEN**",
        "",
        "This document supports independent human review. It does not",
        "approve gates, authenticate evidence, or authorize benchmark freeze.",
        "",
        "## Review rules",
        "",
        "- Inspect source files, workflow runs, artifacts, and commit identity.",
        "- Verify evidence independently; filenames alone are not proof.",
        "- Record unresolved issues and limitations explicitly.",
        "- Do not treat synthetic fixtures as real-agent performance evidence.",
        "- Do not mark a gate PASS without completing its required review.",
        "- Keep CONTENT_FREEZE and CONFIG_FREEZE as separate decisions.",
        "- Use exactly 10 seeds if and when the frozen protocol requires it.",
        "",
        "## Reviewer details",
        "",
        "- Reviewer: __________________________________",
        "- Review date and timezone: ____________________",
        "- Review scope / commit SHA: ___________________",
        "- Conflicts or independence limitations: _________",
        "",
        "## Gate-by-gate review",
        "",
    ]

    for record in data["records"]:
        gate_id = record["gate_id"]
        lines.extend([
            f"### {gate_id}",
            "",
            f"- Current recorded status: `{record.get('review_status', 'NOT_REVIEWED')}`",
            "- Gate approval: `NOT_GRANTED`",
            "- Human review required: YES",
            "",
            "**Candidate files — discovery hints only**",
            "",
        ])

        candidates = record.get("candidate_files", [])

        if candidates:
            for candidate in candidates:
                lines.append(f"- `{candidate}`")
        else:
            lines.append("- No candidate files found; investigate and document.")

        lines.extend([
            "",
            "**Required evidence**",
            "",
        ])

        for evidence in record.get("required_evidence", []):
            requirement = evidence.get("requirement", "Unspecified requirement")
            lines.extend([
                f"- [ ] {requirement}",
                "  - Evidence URL: ______________________________",
                "  - Workflow run ID: ___________________________",
                "  - Full commit SHA: ___________________________",
                "  - Artifact name: _____________________________",
                "  - Review result: NOT_REVIEWED / BLOCKED / PASS / FAIL",
                "  - Reviewer notes: ____________________________",
            ])

        lines.extend([
            "",
            "**Review checks**",
            "",
        ])

        for check in record.get("review_checks", []):
            lines.extend([
                f"- [ ] {check.get('check', 'Unspecified check')}",
                "  - Result: NOT_REVIEWED / BLOCKED / PASS / FAIL",
                "  - Evidence and notes: ________________________",
            ])

        lines.extend([
            "",
            "**Gate decision — human entry only**",
            "",
            "- Decision: NOT_REVIEWED / BLOCKED / PASS / FAIL",
            "- Reviewer: ___________________________________",
            "- Review timestamp with timezone: ______________",
            "- Decision rationale and limitations: ___________",
            "- Independent reviewer confirmation: ___________",
            "",
            "---",
            "",
        ])

    lines.extend([
        "## Final review summary",
        "",
        "- Gates reviewed: ______ / 13",
        "- Gates blocked: ______",
        "- Gates failed: ______",
        "- Gates passed with independently reviewed evidence: ______",
        "- Unresolved evidence gaps: ______________________________",
        "- Content freeze decision: NOT AUTHORIZED BY THIS CHECKLIST",
        "- Configuration freeze decision: NOT AUTHORIZED BY THIS CHECKLIST",
        "",
        "This checklist is a generated working document. Completing it does",
        "not modify the review ledger or grant any gate approval.",
        "",
    ])

    return "\n".join(lines)


def main() -> int:
    try:
        data = load_packets()
        content = build_checklist(data)
        OUTPUT_PATH.write_text(content, encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"HUMAN REVIEW CHECKLIST: FAILED — {exc}")
        return 1

    print("HUMAN REVIEW CHECKLIST: GENERATED")
    print(f"Gate sections: {EXPECTED_GATE_COUNT}")
    print(f"Output: {OUTPUT_PATH.relative_to(GATES_DIR.parents[1])}")
    print("Automatic gate approvals: none")
    print("Benchmark freeze: not authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
