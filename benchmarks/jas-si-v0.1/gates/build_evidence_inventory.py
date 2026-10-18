
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GATES_DIR = Path(__file__).resolve().parent
OUTPUT = GATES_DIR / "evidence_inventory.json"

BENCHMARK_ROOT = REPO_ROOT / "benchmarks" / "jas-si-v0.1"
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"

GATE_TERMS = {
    "P0": ["harness", "schema", "fixture"],
    "P1": ["p1", "oracle"],
    "P2": ["p2", "adversarial"],
    "P3": ["p3", "determinism"],
    "P4": ["p4", "independence"],
    "P5": ["p5", "floor", "ceiling"],
    "P6": ["p6", "label", "audit"],
    "P7": ["p7", "leakage"],
    "P8": ["p8", "metric", "recalculation"],
    "P9": ["p9", "corrigibility", "intervention"],
    "P10": ["p10", "heldout", "held-out", "vfl"],
    "CONTENT_FREEZE": ["content", "freeze", "manifest"],
    "CONFIG_FREEZE": ["config", "freeze", "evaluation"],
}


def list_files(root: Path) -> list[Path]:
    if not root.exists():
        return []

    return sorted(
        path for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    )


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def main() -> int:
    benchmark_files = list_files(BENCHMARK_ROOT)
    workflow_files = list_files(WORKFLOW_ROOT)
    all_files = benchmark_files + workflow_files

    records = []

    for gate_id, terms in GATE_TERMS.items():
        matches = [
            relative(path)
            for path in all_files
            if any(term in path.name.lower() for term in terms)
        ]

        records.append({
            "gate_id": gate_id,
            "status": (
                "CANDIDATES_FOUND"
                if matches
                else "NO_CANDIDATES_FOUND"
            ),
            "candidate_files": matches,
            "human_review_required": True,
            "gate_passed": False,
        })

    report = {
        "protocol": "JAS-SI-V0.1-EVIDENCE-INVENTORY",
        "inventory_status": "DISCOVERY_ONLY",
        "benchmark_status": "DEVELOPMENT_NOT_FROZEN",
        "repository_file_count": len(all_files),
        "gate_count": len(records),
        "limitations": [
            "Filename matches are candidate discovery, not proof.",
            "A file may be relevant to more than one gate.",
            "Workflow success and file existence do not prove validity.",
            "Run links, artifacts, commit identity and test results "
            "must be reviewed separately.",
            "No gate is automatically approved by this report."
        ],
        "records": records,
    }

    OUTPUT.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("EVIDENCE INVENTORY: GENERATED")
    print(f"Repository files scanned: {len(all_files)}")
    print(f"Gates indexed: {len(records)}")
    print(f"Report: {relative(OUTPUT)}")
    print("Gate approvals: none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
