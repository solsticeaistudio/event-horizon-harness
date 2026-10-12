"""Opt-in checkpoints in the real gateway subprocess, never production logic.

Only the trusted supervisor passes a phase at child launch. A marker means
the child is blocked BEFORE the next step; only the supervisor may SIGKILL.
These hooks alone are portable-process tests, NOT a Firecracker KVM result.
"""
from __future__ import annotations

import signal

PHASES = (
    "before_reservation",
    "after_reservation_before_dispatch",
    "after_recipient_commit_before_gateway_ack",
    "after_handler_return_before_completion",
    "after_completion_before_client_ack",
)


class GatewayCrashProbe:
    def __init__(self, phase: str):
        if phase not in PHASES:
            raise ValueError("unknown trusted gateway crash phase")
        self.phase = phase
        self.used = False

    def mark(self, name: str) -> None:
        if name != self.phase:
            return
        if self.used:
            raise RuntimeError("duplicate crash checkpoint")
        self.used = True
        print("PHASE:" + name, flush=True)
        while True:
            signal.pause()


class ReservationProbe:
    """Observe durable reservation completion before handler dispatch."""

    def __init__(self, journal, probe: GatewayCrashProbe):
        self.journal = journal
        self.probe = probe

    def reserve(self, **kwargs):
        result = self.journal.reserve(**kwargs)
        if result:
            self.probe.mark("after_reservation_before_dispatch")
        return result


class RecorderProbe:
    """Observe handler return before independently durable completion append."""

    def __init__(self, recorder, probe: GatewayCrashProbe):
        self.recorder = recorder
        self.probe = probe

    def append(self, event_type, payload, **kwargs):
        if event_type == "execution.completed":
            self.probe.mark("after_handler_return_before_completion")
        return self.recorder.append(event_type, payload, **kwargs)
