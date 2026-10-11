#!/usr/bin/env python3
"""Run bounded deterministic regression cases or actual Atheris/libFuzzer.

Examples:
  python scripts/run_ehh_fuzz.py --target all --smoke --report-dir artifacts/fuzz/smoke
  python scripts/run_ehh_fuzz.py --target frame --seconds 60
  python scripts/run_ehh_fuzz.py --target gateway --seconds 300

Each Atheris target runs in its own process. To avoid fuzzer-induced
side effects, the only effect handler is an in-memory synthetic read with
temporary local SQLite authority; no Docker, root, networking, or external
credentials. Reports count executions, not proof of exploit resistance.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _write_report(directory: Path, name: str, value: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{name}.json"
    temporary = directory / f".{name}-{os.getpid()}.tmp"
    with temporary.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)


def _smoke(target: str, report_dir: Path, iterations: int) -> None:
    from scripts.ehh_fuzz_targets import FuzzTargets, MAX_INPUT_BYTES
    engine = FuzzTargets(target)
    randomizer = random.Random(0xE11 + sum(map(ord, target)))
    counts: dict[str, int] = {}
    current: bytes = b""
    evaluated = 0
    started = time.monotonic()
    try:
        seeds = engine.seeds()
        for n in range(len(seeds) + iterations):
            if n < len(seeds):
                current = seeds[n]
            else:
                sample = randomizer.choice(seeds)
                if target in {"capability", "gateway"} and n % 3 == 0:
                    # Exercise SIGNED but mutated, syntactically valid trees.
                    current = bytes((0xF0, randomizer.randrange(256),
                                     randomizer.randrange(256)))
                elif n % 3 == 1:
                    current = sample[:randomizer.randrange(len(sample) + 1)]
                elif n % 3 == 2 and sample:
                    position = randomizer.randrange(len(sample))
                    current = (sample[:position] +
                               bytes((sample[position] ^ (1 << randomizer.randrange(8)),)) +
                               sample[position + 1:])
                else:
                    current = sample + bytes((randomizer.randrange(256),))
            if len(current) > MAX_INPUT_BYTES:
                current = current[:MAX_INPUT_BYTES]
            outcome = engine.exercise(current)
            counts[outcome] = counts.get(outcome, 0) + 1
            evaluated += 1
    except BaseException as exc:
        _write_report(report_dir, target, {
            "schema": "event-horizon.fuzz-smoke.v1",
            "status": "FAIL",
            "target": target,
            "completed_cases": evaluated,
            "input_sha256": hashlib.sha256(current).hexdigest(),
            "reproduction_input_base64": base64.b64encode(current).decode("ascii"),
            "exception": f"{type(exc).__name__}: {str(exc)[:512]}",
        })
        raise
    finally:
        engine.close()
    _write_report(report_dir, target, {
        "schema": "event-horizon.fuzz-smoke.v1",
        "status": "PASS", "target": target, "cases": evaluated,
        "outcomes": counts, "random_seed": 0xE11 + sum(map(ord, target)),
        "duration_seconds": round(time.monotonic() - started, 3),
        "scope": "bounded reproducible smoke; NOT coverage-guided or a penetration test",
    })
    print(f"PASS {target}: {evaluated} smoke cases; {counts}", flush=True)


def _coverage(target: str, report_dir: Path, seconds: int) -> None:
    try:
        import atheris
    except ImportError as exc:
        raise SystemExit(
            'Coverage guidance requires: python -m pip install -e ".[fuzz]"'
        ) from exc

    # Python bytecode instrumentation must wrap imports of our targets and
    # the EHH modules they exercise, before the fuzzer calls them.
    with atheris.instrument_imports():
        from scripts.ehh_fuzz_targets import FuzzTargets, MAX_INPUT_BYTES

    engine = FuzzTargets(target)
    corpus = report_dir / target / "corpus"
    crashes = report_dir / target / "crashes"
    corpus.mkdir(parents=True, exist_ok=True)
    crashes.mkdir(parents=True, exist_ok=True)
    for seed in engine.seeds():
        name = hashlib.sha256(seed).hexdigest()[:24]
        item = corpus / f"seed-{name}"
        if not item.exists():
            item.write_bytes(seed)

    # The crash artifact is the actual input libFuzzer found, not a
    # generated assurance certificate. Failed runs remain failures.
    arguments = [
        "ehh-atheris-" + target, str(corpus),
        f"-max_total_time={seconds}",
        f"-max_len={MAX_INPUT_BYTES}",
        f"-artifact_prefix={crashes}/",
        "-timeout=3",
        "-rss_limit_mb=512",
        "-print_final_stats=1",
    ]
    atheris.Setup(arguments, engine.exercise)
    try:
        atheris.Fuzz()
    finally:
        engine.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True,
                        choices=("all", "frame", "canonical", "capability", "gateway"))
    parser.add_argument("--smoke", action="store_true",
                        help="reproducible tests without Atheris (not coverage-guided)")
    parser.add_argument("--iterations", type=int, default=150,
                        help="smoke-only mutated cases per target")
    parser.add_argument("--seconds", type=int, default=30,
                        help="libFuzzer runtime seconds for one selected target")
    parser.add_argument("--report-dir", type=Path, default=ROOT / "artifacts/fuzz")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 10_000:
        parser.error("smoke iteration count must be between 1 and 10000")
    if not 1 <= args.seconds <= 3600:
        parser.error("fuzz runtime must be between 1 and 3600 seconds")
    if args.target == "all" and not args.smoke:
        parser.error("libFuzzer requires one --target per worker process")
    selected = ("frame", "canonical", "capability", "gateway") if args.target == "all" else (args.target,)
    for target in selected:
        if args.smoke:
            _smoke(target, args.report_dir, args.iterations)
        else:
            _coverage(target, args.report_dir, args.seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
