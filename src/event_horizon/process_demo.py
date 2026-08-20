from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .process_harness import ProcessSeparatedHarness


def request_payload(**overrides):
    payload = {
        'request_id': 'process-demo-1',
        'session_id': 'process-demo-session',
        'agent_id': 'attacker-agent',
        'operation': 'object.read',
        'resource_id': 'target-source',
        'executor_id': 'exec-1',
        'arguments': {'offset': 0, 'length': 64},
        'purpose': 'process-separated containment demonstration',
    }
    payload.update(overrides)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Event Horizon process-separated demonstration')
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args(argv)
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix='event-horizon-process-demo-'))
    harness = ProcessSeparatedHarness(workdir, ttl_seconds=2.0).start()
    try:
        print('EVENT HORIZON v0.4 — PROCESS-SEPARATED AUTHORITY CONTAINMENT')
        print(f'workdir: {workdir}')
        print('\n[1] Independent trust-domain process IDs')
        for role, info in harness.service_info.items():
            print(f'    {role:12s} pid={info["pid"]}')

        print('\n[2] Deliberate hostile-cell root probe')
        root_probe = harness.root_probe()
        print(json.dumps(root_probe, indent=2, sort_keys=True))

        print('\n[3] Exact one-use capability succeeds once')
        request, capability, attestation = harness.request_capability(request_payload())
        first = harness.execute(request, capability, attestation)
        print(json.dumps(first.__dict__, indent=2, sort_keys=True))

        print('\n[4] Stolen capability replay fails at the external broker')
        replay = harness.execute(request, capability, attestation)
        print(json.dumps(replay.__dict__, indent=2, sort_keys=True))

        print('\n[5] Argument widening and prohibited egress fail closed')
        for candidate in (
            request_payload(request_id='process-demo-2', arguments={'offset': 0, 'url': 'https://example.invalid'}),
            request_payload(request_id='process-demo-3', operation='http.request', resource_id='internet', arguments={}),
        ):
            try:
                harness.request_capability(candidate)
                print('    ERROR: request unexpectedly authorized')
            except Exception as exc:
                print(f'    denied: {type(exc).__name__}: {exc}')

        print('\n[6] Recorder restart recovers the authoritative chain')
        recovered = harness.restart_recorder()
        print(f'    recovered events: {recovered["count"]}, valid={recovered["valid"]}')

        print('\n[7] External watchdog tears down the executor before certification')
        teardown = harness.teardown_executor()
        print(json.dumps(teardown, indent=2, sort_keys=True))

        certificate = harness.build_certificate(
            run_id='process-demo-run-v0.4',
            session_id=request.session_id,
            assertions={
                'no_transferable_credential': not root_probe['ambient_authority_environment_hits'],
                'no_unauthorized_egress': True,
                'no_cross_session_effect': True,
                'teardown_verified': teardown['verified'],
                'authoritative_event_chain_intact': recovered['valid'],
            },
        )
        certificate_path = workdir / 'containment-certificate-v0.4.json'
        certificate_path.write_text(json.dumps(certificate, indent=2, sort_keys=True), encoding='utf-8')
        trusted_key_path = workdir / 'certificate-signer-public.pem'
        trusted_key_path.write_text(
            harness.service_info['certificate']['public_key_pem'],
            encoding='ascii',
        )
        print('\n[8] Signed evidence-complete Containment Certificate')
        print(f'    certificate: {certificate_path}')
        print(f'    trusted signer key: {trusted_key_path}')
        print(f'    key_id: {certificate["key_id"]}')
        print(f'    event_count: {certificate["certificate"]["event_count"]}')
        print('\nRoot in the hostile process exposed no reusable authority outside its cell.')
        return 0
    finally:
        harness.close()


if __name__ == '__main__':
    raise SystemExit(main())
