from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing

from event_horizon.canonical import digest
from event_horizon.models import ActionRequest
from event_horizon.intent_canonicalizer import AuthorizationDenied
from event_horizon.process_harness import ProcessSeparatedHarness
from event_horizon.protocol import ProtocolError


def payload(**overrides):
    value = {
        'request_id': 'process-1',
        'session_id': 'process-session',
        'agent_id': 'attacker-agent',
        'operation': 'object.read',
        'resource_id': 'target-source',
        'executor_id': 'exec-1',
        'arguments': {'offset': 0, 'length': 64},
        'purpose': 'process test',
    }
    value.update(overrides)
    return value


class ProcessHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.harness = ProcessSeparatedHarness(self.tmp.name, ttl_seconds=1.0).start()

    def tearDown(self):
        self.harness.close()
        self.tmp.cleanup()

    def issue(self, **overrides):
        return self.harness.request_capability(payload(**overrides))

    def test_all_trust_domains_have_unique_processes_and_executor_has_no_private_key(self):
        pids = {info['pid'] for info in self.harness.service_info.values()}
        self.assertEqual(len(pids), 7)
        probe = self.harness.root_probe()
        self.assertEqual(probe['ambient_authority_environment_hits'], [])
        self.assertEqual(probe['requested_environment_hits'], [])
        self.assertFalse(probe['private_key_material_present'])
        self.assertEqual(probe['signer_key_id'], self.harness.service_info['signer']['key_id'])
        executor_config = json.loads(
            self.harness.config_paths['executor'].read_text(encoding='utf-8')
        )
        for role, key_path in (
            ('signer', self.harness.capability_key_path),
            ('recorder', self.harness.recorder_key_path),
            ('certificate', self.harness.certificate_key_path),
        ):
            config = json.loads(self.harness.config_paths[role].read_text(encoding='utf-8'))
            self.assertNotIn('signing_seed_hex', config)
            self.assertEqual(config['signing_key_path'], str(key_path))
            self.assertNotIn('signing_key_path', executor_config)
            self.assertEqual(
                self.harness.service_info[role]['request_authentication'],
                'Ed25519',
            )

    def test_protected_mutation_endpoints_require_authenticated_requests(self):
        protected_calls = (
            (
                'signer',
                'issue',
                {'request': {}, 'guardian_result': {}, 'attestation': {}},
            ),
            (
                'signer',
                'consume',
                {'request': {}, 'capability': {}, 'attestation': {}},
            ),
            (
                'recorder',
                'append',
                {
                    'event_type': 'unauthorized',
                    'payload': {},
                    'source_id': 'coordinator',
                    'source_sequence': 1,
                },
            ),
            (
                'certificate',
                'build',
                {'run_id': 'unauthorized', 'session_id': 'x', 'assertions': {}, 'evidence': {}},
            ),
        )
        for role, message_type, body in protected_calls:
            with self.subTest(role=role, message_type=message_type):
                with self.assertRaises(ProtocolError) as denied:
                    self.harness.call(
                        role,
                        message_type,
                        body,
                        authorize=False,
                    )
                self.assertEqual(denied.exception.code, 'authorization_required')
        self.harness.record('authenticated.after-denial', {'ok': True})

    def test_exact_capability_succeeds_and_external_broker_denies_replay(self):
        request, capability, attestation = self.issue()
        claims = capability.claims
        self.assertEqual(claims.device_id, attestation['deviceId'])
        self.assertEqual(claims.executor_measurement, attestation['measurements']['executor'])
        self.assertEqual(claims.attestation_digest, attestation['resultDigest'])
        self.assertEqual(claims.attestation_bundle_digest, attestation['bundleDigest'])
        self.assertEqual(claims.verifier_policy_digest, attestation['verifierPolicyDigest'])
        self.assertEqual(claims.signer_key_id, capability.key_id)
        self.assertEqual(claims.request_digest, request.request_digest)
        self.assertTrue(self.harness.execute(request, capability, attestation).success)
        replay = self.harness.execute(request, capability, attestation)
        self.assertFalse(replay.success)
        self.assertIn('replay', replay.error)

    def test_durable_replay_state_survives_authority_service_restarts(self):
        request, capability, attestation = self.issue(request_id='durable-service-restart')
        self.assertTrue(self.harness.execute(request, capability, attestation).success)
        with closing(sqlite3.connect(self.harness.authority_replay_path)) as database:
            nonce_states = database.execute(
                "SELECT state, COUNT(*) FROM attestation_nonces GROUP BY state"
            ).fetchall()
            broker_domains = database.execute(
                "SELECT domain, COUNT(*) FROM capability_consumptions GROUP BY domain"
            ).fetchall()
        with closing(sqlite3.connect(self.harness.executor_replay_path)) as database:
            executor_domains = database.execute(
                "SELECT domain, COUNT(*) FROM capability_consumptions GROUP BY domain"
            ).fetchall()
        self.assertIn(('consumed', 1), nonce_states)
        self.assertEqual(dict(broker_domains), {'broker': 1})
        self.assertEqual(dict(executor_domains), {'executor:exec-1': 1})
        executor_config = self.harness.config_paths['executor'].read_text(encoding='utf-8')
        self.assertNotIn(str(self.harness.authority_replay_path), executor_config)

        self.harness.restart_role('verifier')
        self.issue(request_id='after-verifier-restart')
        with closing(sqlite3.connect(self.harness.authority_replay_path)) as database:
            consumed_nonces = database.execute(
                "SELECT COUNT(*) FROM attestation_nonces WHERE state = 'consumed'"
            ).fetchone()[0]
        self.assertEqual(consumed_nonces, 2)

        signer_key = self.harness.service_info['signer']['key_id']
        self.assertEqual(self.harness.restart_role('signer')['key_id'], signer_key)
        self.harness.restart_role('executor')
        replay = self.harness.execute(request, capability, attestation)
        self.assertFalse(replay.success)
        self.assertIn('replay', replay.error)
        direct = self.harness.call(
            'executor',
            'execute',
            {
                'request': request.canonical_payload(),
                'capability': capability.to_dict(),
                'attestation': dict(attestation),
            },
        )
        self.assertFalse(direct['success'])
        self.assertIn('replay', direct['error'])
        with closing(sqlite3.connect(self.harness.authority_replay_path)) as database:
            protected = dict(database.execute(
                """
                SELECT audience, COUNT(*) FROM protected_request_authorizations
                GROUP BY audience
                """
            ).fetchall())
        self.assertGreaterEqual(protected['capability-signer'], 3)

    def test_session_executor_and_attestation_substitution_fail(self):
        request, capability, attestation = self.issue()
        changed_session = ActionRequest.from_dict(payload(session_id='other-session'))
        denied_session = self.harness.execute(changed_session, capability, attestation)
        self.assertFalse(denied_session.success)
        self.assertIn('session_id', denied_session.error)
        changed_executor = ActionRequest.from_dict(payload(executor_id='exec-2'))
        denied_executor = self.harness.execute(changed_executor, capability, attestation)
        self.assertFalse(denied_executor.success)
        self.assertIn('executor_id', denied_executor.error)
        tampered = dict(attestation)
        tampered['measurements'] = dict(attestation['measurements'])
        tampered['measurements']['executor'] = 'wrong-image'
        unsigned = dict(tampered)
        unsigned.pop('resultDigest')
        tampered['resultDigest'] = digest(unsigned)
        denied_attestation = self.harness.execute(request, capability, tampered)
        self.assertFalse(denied_attestation.success)
        self.assertIn('binding mismatch', denied_attestation.error)

    def test_unknown_message_types_and_fields_are_rejected(self):
        with self.assertRaises(ProtocolError) as unknown_type:
            self.harness.call('parser', 'not_registered', {})
        self.assertEqual(unknown_type.exception.code, 'unknown_message_type')
        with self.assertRaises(ProtocolError) as unknown_field:
            self.harness.call('parser', 'parse_action', {'payload': payload(), 'extra': True})
        self.assertEqual(unknown_field.exception.code, 'unknown_field')

    def test_verifier_and_signer_unavailability_fail_closed(self):
        self.harness.stop_role('verifier')
        with self.assertRaises(AuthorizationDenied):
            self.issue(request_id='verifier-down')
        self.harness.close()
        self.harness = ProcessSeparatedHarness(self.tmp.name + '-signer', ttl_seconds=1.0).start()
        self.harness.stop_role('signer')
        with self.assertRaises(AuthorizationDenied):
            self.issue(request_id='signer-down')

    def test_one_permissive_guardian_cannot_override_static_veto(self):
        self.harness.close()
        self.harness = ProcessSeparatedHarness(
            self.tmp.name + '-compromised',
            inject_permissive_guardian=True,
        ).start()
        with self.assertRaises(AuthorizationDenied):
            self.issue(
                request_id='compromised-guardian',
                operation='shell.execute',
                resource_id='host',
                arguments={},
            )

    def test_recorder_restart_recovers_and_source_gaps_are_detected(self):
        self.harness.record('test.before-restart', {'ok': True})
        before = self.harness.call('recorder', 'verify', {})['count']
        before_key_id = self.harness.service_info['recorder']['key_id']
        recovered = self.harness.restart_recorder()
        self.assertEqual(recovered['count'], before)
        self.assertEqual(recovered['key_id'], before_key_id)
        self.harness.record('test.after-restart', {'ok': True})
        with self.assertRaises(ProtocolError) as gap:
            self.harness.call(
                'recorder',
                'append',
                {
                    'event_type': 'test.gap',
                    'payload': {},
                    'source_id': 'coordinator',
                    'source_sequence': 999,
                },
            )
        self.assertEqual(gap.exception.code, 'recording_denied')

    def test_external_recorder_tampering_after_host_compromise_fails_closed(self):
        self.harness.record('host-compromise.before', {'trusted': True})
        path = self.harness.recorder_path
        lines = path.read_text(encoding='utf-8').splitlines()
        event = json.loads(lines[0])
        event['payload']['trusted'] = False
        lines[0] = json.dumps(event, sort_keys=True, separators=(',', ':'))
        path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        status = self.harness.call('recorder', 'verify', {})
        self.assertFalse(status['valid'])
        with self.assertRaises(ProtocolError) as denied:
            self.harness.record('host-compromise.after', {'trusted': False})
        self.assertEqual(denied.exception.code, 'recording_denied')

    def test_output_channel_pressure_is_denied(self):
        request, capability, attestation = self.issue(
            request_id='oversized-output',
            resource_id='oversized-object',
        )
        result = self.harness.execute(request, capability, attestation)
        self.assertFalse(result.success)
        self.assertIn('output envelope', result.error)

    def test_signed_certificate_binds_every_evidence_domain_after_teardown(self):
        request, capability, attestation = self.issue(request_id='certificate')
        self.assertTrue(self.harness.execute(request, capability, attestation).success)
        teardown = self.harness.teardown_executor()
        self.assertTrue(teardown['verified'])
        certificate = self.harness.build_certificate(
            run_id='process-run',
            session_id=request.session_id,
            assertions={
                'no_transferable_credential': True,
                'no_unauthorized_egress': True,
                'teardown_verified': True,
            },
        )
        payload_value = certificate['certificate']
        self.assertEqual(payload_value['schema'], 'event-horizon.containment-certificate.v0.4')
        self.assertEqual(
            set(payload_value['evidence']),
            {'attestation', 'capability', 'policy', 'image', 'recorder', 'teardown', 'egress'},
        )
        self.assertEqual(certificate['key_id'], self.harness.service_info['certificate']['key_id'])
        certificate_key = self.harness.service_info['certificate']['key_id']
        self.assertEqual(
            self.harness.restart_role('certificate')['key_id'],
            certificate_key,
        )

    def test_live_decay_is_one_transition_per_single_use_capability(self):
        first_request, first_capability, first_attestation = self.issue(request_id='decay-first')
        self.assertTrue(
            self.harness.execute(first_request, first_capability, first_attestation).success
        )
        self.assertFalse(
            self.harness.execute(first_request, first_capability, first_attestation).success
        )
        with self.assertRaises(AuthorizationDenied):
            self.harness.request_capability(payload(
                request_id='decay-denied',
                operation='http.request',
                resource_id='internet',
                arguments={},
            ))
        second_request, second_capability, second_attestation = self.issue(
            request_id='decay-second'
        )
        self.assertTrue(
            self.harness.execute(second_request, second_capability, second_attestation).success
        )
        self.assertNotEqual(
            first_capability.claims.capability_id,
            second_capability.claims.capability_id,
        )

        with closing(sqlite3.connect(self.harness.trusted_dir / 'decay-state.sqlite3')) as database:
            rows = database.execute(
                'SELECT capability_id, payload FROM decay_state ORDER BY capability_id'
            ).fetchall()
        states = {capability_id: json.loads(bytes(encoded)) for capability_id, encoded in rows}
        expected_ids = {
            first_capability.claims.capability_id,
            second_capability.claims.capability_id,
        }
        self.assertEqual(set(states), expected_ids)
        for state in states.values():
            self.assertEqual(state['use_count'], 1)
            self.assertEqual(state['denials'], 0)
            self.assertEqual(state['risk_score'], 0)
            self.assertEqual(state['canary_events'], 0)
            self.assertEqual(state['environment_changes'], 0)
            self.assertEqual(state['workload_restarts'], 0)


if __name__ == '__main__':
    unittest.main()
