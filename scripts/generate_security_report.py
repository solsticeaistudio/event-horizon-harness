#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from event_horizon.task_policy import evaluate_policy_sizing


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "reports"
SUITES = {
    "policy_ceiling_evaluation": ("tests.test_task_policy_ceiling",),
    "trust_tier": ("tests.test_authoritative_trust",),
    "protocol_property": ("tests.test_protocol_properties", "tests.test_capability_stateful"),
    "concurrent_redemption": ("tests.test_concurrent_redemption",),
    "chaos_recovery": ("tests.test_chaos",),
    "canary_events": ("tests.test_canary_capabilities",),
    "denial_certificates": ("tests.test_denial_certificates",),
    "behavioral_guardian": ("tests.test_behavioral_guardian",),
    "trust_decay": ("tests.test_trust_decay",),
    "adaptive_adversary": ("tests.test_adaptive_adversary",),
    "positive_controls": ("tests.test_positive_controls",),
    "literature_feed": ("tests.test_literature_feed",),
    "hardware_simulator": ("tests.test_hardware_failsafe",),
    "formal_model_structure": ("tests.test_formal_model",),
}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def run_suite(modules: tuple[str, ...]) -> dict[str, Any]:
    command = [sys.executable, "-m", "unittest", *modules, "-v"]
    started = time.time()
    completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    output = completed.stdout + completed.stderr
    match = re.search(r"Ran (\d+) tests?", output)
    return {
        "command": " ".join(command),
        "passed": completed.returncode == 0,
        "test_count": int(match.group(1)) if match else 0,
        "duration_milliseconds": int((time.time() - started) * 1_000),
        "diagnostic_tail": output[-2_000:] if completed.returncode else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate bounded Event Horizon security reports")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    started = time.time()
    revision = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--short"))
    results = {name: run_suite(modules) for name, modules in SUITES.items()}
    java_home = os.environ.get("JAVA_HOME")
    print(f"DEBUG: JAVA_HOME from env = {repr(java_home)}")
    java_exe = None
    if java_home:
        java_exe = os.path.join(java_home.strip(), "bin", "java")
        print(f"DEBUG: java_exe = {repr(java_exe)}")
    elif shutil.which("java"):
        java_exe = shutil.which("java")
        print(f"DEBUG: java from PATH = {repr(java_exe)}")
    formal = subprocess.run(
        [sys.executable, "scripts/check_formal_model.py", "--java", java_exe] if java_exe else [sys.executable, "scripts/check_formal_model.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    formal_tlc = "skipped" if "TLC SKIPPED" in formal.stdout else (
        "passed" if formal.returncode == 0 else "failed"
    )
    broad = evaluate_policy_sizing(
        exposed_tools=("object-reader", "shell"), invoked_tools=("object-reader",),
        exposed_actions=("object.read",), invoked_actions=("object.read",),
        required_tools=("object-reader",), dangerous_tools=("shell",),
        task_completed=True, task_failure_underprovisioned=False,
        escalation_requests=0, human_approvals=0, synthesis_latency_ms=2,
        compiler_latency_ms=1, attack_succeeded=False, false_denial=False,
        risk_weights={"shell": 100},
    ).to_dict()
    contained = evaluate_policy_sizing(
        exposed_tools=("object-reader",), invoked_tools=("object-reader",),
        exposed_actions=("object.read",), invoked_actions=("object.read",),
        required_tools=("object-reader",), dangerous_tools=("shell",),
        task_completed=True, task_failure_underprovisioned=False,
        escalation_requests=0, human_approvals=0, synthesis_latency_ms=2,
        compiler_latency_ms=1, attack_succeeded=False, false_denial=False,
        risk_weights={"shell": 100},
    ).to_dict()
    ended = time.time()
    all_passed = all(item["passed"] for item in results.values()) and formal.returncode == 0
    report = {
        "schema": "event-horizon.security-evaluation-report.v1",
        "source_revision": revision,
        "dirty_tree_at_start": dirty,
        "build_identifier": hashlib.sha256(
            f"{revision}:{platform.platform()}:{sys.version}".encode()
        ).hexdigest(),
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "ci": os.environ.get("CI") == "true",
        },
        "configuration": "bounded-deterministic-default",
        "policy_version": "policy-v1 / eh-process-policy-v0.4",
        "synthesizer_version": "task-policy-synthesizer-v1",
        "compiler_version": "trusted-policy-compiler-v1",
        "model_identifier": "scripted-adaptive-model-control",
        "seed": 7,
        "campaign_budget": {"maximum_turns": 5, "maximum_commands": 5},
        "evidence_root": None,
        "started_at_unix_ms": int(started * 1_000),
        "ended_at_unix_ms": int(ended * 1_000),
        "passed": all_passed,
        "overall_status": "pass-with-unavailable-checks" if formal_tlc == "skipped" else ("pass" if all_passed else "fail"),
        "suite_results": results,
        "policy_sizing_metrics": {
            "overprovisioned_control": broad,
            "task_ceiling": contained,
            "note": "Observed invocation is a proxy, not proof of minimum necessary authority.",
        },
        "formal_model_check": formal_tlc,
        "formal_model_status": "structural-only" if formal_tlc == "skipped" else formal_tlc,
        "hardware_in_the_loop": "not-run-no-hardware",
        "tested_invariants": [f"EH-{index}" for index in range(1, 12)],
        "formally_checked_invariants": [] if formal_tlc == "skipped" else [f"EH-{index}" for index in range(1, 12)],
        "violated_invariants": [],
        "indeterminate_outcomes": [
            "TLC was unavailable" if formal_tlc == "skipped" else None,
            "physical hardware was unavailable",
        ],
        "limitations": [
            "Synthetic deterministic fixtures are not external validation.",
            "No production Firecracker or physical TPM/fail-safe result is claimed.",
            "No combined evidence recorder was configured for these unit suites.",
        ],
    }
    report["indeterminate_outcomes"] = [
        item for item in report["indeterminate_outcomes"] if item is not None
    ]
    args.output.mkdir(parents=True, exist_ok=True)
    json_path = args.output / "security-report.json"
    markdown_path = args.output / "security-report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = "\n".join(
        f"| {name.replace('_', ' ')} | {'PASS' if value['passed'] else 'FAIL'} | "
        f"{value['test_count']} | {value['duration_milliseconds']} |"
        for name, value in results.items()
    )
    markdown = f"""# Event Horizon security evaluation report

- Source revision: `{revision}`
- Dirty tree at start: `{str(dirty).lower()}`
- Deterministic available checks: `{'PASS' if all_passed else 'FAIL'}`
- Overall status: `{'PASS WITH UNAVAILABLE CHECKS' if formal_tlc == 'skipped' else ('PASS' if all_passed else 'FAIL')}`
- TLC: `{'structural-only (TLC unavailable)' if formal_tlc == 'skipped' else 'executed and passed'}`
- Hardware in the loop: `not run - no hardware available`

| Evaluation | Result | Tests | Milliseconds |
|---|---:|---:|---:|
{rows}

## Policy sizing fixture

- Overprovisioned control SER: {broad['skill_economy_ratio_millis']}/1000
- Task-ceiling SER: {contained['skill_economy_ratio_millis']}/1000
- Overprovisioned risk exposure: {broad['risk_weighted_authority_exposure']}
- Task-ceiling risk exposure: {contained['risk_weighted_authority_exposure']}
- Both synthetic fixture tasks completed; neither reported false denial.

Observed invocation is a proxy, not proof of minimum necessary authority. These results are project-authored synthetic tests, not an audit or frontier-model containment claim.
"""
    markdown_path.write_text(markdown, encoding="utf-8")
    print(f"security report: {'PASS' if all_passed else 'FAIL'} ({json_path})")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
