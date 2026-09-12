#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"
INVARIANTS = (
    "AtMostOneCommittedEffect", "ConsumedCapabilityCannotRedeem",
    "GuardianNeverAddsAuthority", "BehavioralGuardianNeverAddsAuthority",
    "SynthesizerCannotGrantAuthority", "CompiledCeilingNeverExceedsGlobalMaximum",
    "EffectiveAuthorityNeverExceedsCompiledCeiling",
    "EffectiveAuthorityNeverExceedsSignedAuthority",
    "EffectiveAuthorityNeverExceedsAttestedAuthority",
    "EffectiveAuthorityNeverExceedsPolicyAuthority", "DecayIsMonotonic",
    "TrustDowngradePreventsRestrictedRedemption", "InvalidAttestationCannotAuthorize",
    "CrashRecoveryCannotRestoreConsumedCapability",
    "AmbiguousRetryCannotCreateDuplicateEffect", "CapabilityIsBoundToTaskAndWorkload",
    "ExpiredCapabilityCannotCommitEffect", "CanaryCannotCommitEffect",
    "CanaryAttemptProducesSecurityEvent",
    "DenialCertificateCannotClaimKnownNoEffectWhenStateIsAmbiguous",
)


def structural_check() -> None:
    model = (FORMAL / "EventHorizon.tla").read_text(encoding="utf-8")
    config = (FORMAL / "EventHorizon.cfg").read_text(encoding="utf-8")
    missing = [name for name in INVARIANTS if name not in model or f"INVARIANT {name}" not in config]
    if missing:
        raise RuntimeError(f"formal model is missing invariants: {missing}")
    broken = (FORMAL / "EventHorizonBroken.tla").read_text(encoding="utf-8")
    if "BrokenGuardianAddsAuthority" not in broken or "guardian' = Authority" not in broken:
        raise RuntimeError("broken formal mutation is missing")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the narrow Event Horizon TLA+ model")
    parser.add_argument("--require-tlc", action="store_true")
    parser.add_argument("--java", help="Path to Java executable")
    args = parser.parse_args()
    structural_check()
    
    # Try to find Java: explicit arg > JAVA_HOME > PATH
    java = args.java
    if not java:
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            java = os.path.join(java_home, "bin", "java")
    if not java:
        java = shutil.which("java")
    
    jar_value = os.environ.get("TLA2TOOLS_JAR", str(FORMAL / "tla2tools.jar"))
    jar = Path(jar_value)
    if java is None or not jar.is_file():
        message = "TLC SKIPPED: Java and a pinned TLA2TOOLS_JAR are not available"
        print(message)
        return 2 if args.require_tlc else 0
    good = subprocess.run(
        [java, "-cp", str(jar), "tlc2.TLC", "-config", "EventHorizon.cfg", "EventHorizon.tla"],
        cwd=FORMAL,
        check=False,
    )
    if good.returncode != 0:
        return good.returncode
    broken = subprocess.run(
        [java, "-cp", str(jar), "tlc2.TLC", "-config", "EventHorizonBroken.cfg", "EventHorizonBroken.tla"],
        cwd=FORMAL,
        check=False,
        capture_output=True,
        text=True,
    )
    combined = broken.stdout + broken.stderr
    if broken.returncode == 0 or "Invariant GuardianNeverAddsAuthority is violated" not in combined:
        print("TLC did not detect the deliberately broken guardian mutation")
        return 1
    print("TLC PASS: secure model holds; broken guardian mutation detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
