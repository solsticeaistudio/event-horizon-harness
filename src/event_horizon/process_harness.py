from __future__ import annotations

import json
import hashlib
import os
import queue
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes, digest
from .models import ActionRequest, ExecutionResult, IssuedCapability, ValidationError
from .intent_canonicalizer import AuthorizationDenied
from .statements import (
    TYPE_TEARDOWN_ATTESTATION,
    StatementSigner,
    StatementVerifier,
)
from .protocol import ProtocolError, read_frame, request_envelope, validate_response, write_frame
from .protected_boundary import (
    ProtectedRequestSigner,
    load_private_seed,
    provision_private_seed,
)
from .recorder import ExternalRecorder


class ServiceUnavailable(RuntimeError):
    pass


class ProcessClient:
    def __init__(
        self,
        role: str,
        config_path: Path,
        repository_root: Path,
        *,
        request_signer: ProtectedRequestSigner | None = None,
        protected_types: frozenset[str] = frozenset(),
    ):
        self.role = role
        self.config_path = config_path
        self.repository_root = repository_root
        self.request_signer = request_signer
        self.protected_types = protected_types
        self._lock = threading.RLock()
        self._responses: queue.Queue[dict[str, Any] | BaseException] = queue.Queue()
        safe_names = {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}
        environment = {name: value for name, value in os.environ.items() if name.upper() in safe_names}
        environment.update({
            'PYTHONPATH': str(repository_root / 'src'),
            'PYTHONIOENCODING': 'utf-8',
            'PYTHONUNBUFFERED': '1',
        })
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        self.process = subprocess.Popen(
            [
                sys.executable,
                '-m',
                'event_horizon.service',
                '--role',
                role,
                '--config',
                str(config_path),
            ],
            cwd=repository_root,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
        )
        if self.process.stdin is None or self.process.stdout is None:
            self.process.kill()
            raise ServiceUnavailable(f'{role} service pipes are unavailable')
        self._reader = threading.Thread(target=self._read_responses, name=f'eh-{role}-reader', daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def running(self) -> bool:
        return self.process.poll() is None

    def _read_responses(self) -> None:
        assert self.process.stdout is not None
        while True:
            try:
                self._responses.put(read_frame(self.process.stdout))
            except BaseException as exc:
                self._responses.put(exc)
                return

    def call(
        self,
        message_type: str,
        body: Mapping[str, Any],
        *,
        timeout_seconds: float = 5.0,
        authorize: bool | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if not self.running or self.process.stdin is None:
                raise ServiceUnavailable(f'{self.role} service is unavailable')
            request_id = f'{self.role}-{secrets.token_hex(8)}'
            try:
                envelope = request_envelope(
                    message_type,
                    request_id,
                    body,
                    timeout_seconds=timeout_seconds,
                )
                should_authorize = message_type in self.protected_types if authorize is None else authorize
                if should_authorize:
                    if self.request_signer is None:
                        raise ServiceUnavailable(
                            f'{self.role} protected request signer is unavailable'
                        )
                    envelope['authorization'] = self.request_signer.authorize(envelope)
                write_frame(
                    self.process.stdin,
                    envelope,
                )
                response = self._responses.get(timeout=timeout_seconds + 0.25)
            except (BrokenPipeError, EOFError, OSError, queue.Empty) as exc:
                self.stop()
                raise ServiceUnavailable(f'{self.role} service failed closed') from exc
            if isinstance(response, BaseException):
                raise ServiceUnavailable(f'{self.role} service stream closed') from response
            return validate_response(response, request_id)

    def stop(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self._reader.join(timeout=1)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()


def _write_config(path: Path, payload: Mapping[str, Any]) -> None:
    # Role configuration files are local plaintext, not signed protocol
    # objects: they may contain non-canonical numbers such as float TTLs.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), sort_keys=True), encoding="utf-8")
    if os.name != 'nt':
        path.chmod(0o600)


def _provision_or_load_seed(path: Path) -> bytes:
    try:
        provision_private_seed(path, secrets.token_bytes(32))
    except FileExistsError:
        pass
    return load_private_seed(path)


class ProcessSeparatedHarness:
    ROLES = ('parser', 'verifier', 'guardians', 'signer', 'executor', 'recorder', 'certificate', 'witness')
    PROTECTED_TYPES = {
        'signer': frozenset({'issue', 'consume'}),
        'recorder': frozenset({'append', 'checkpoint'}),
        'certificate': frozenset({'build'}),
        'witness': frozenset({'publish'}),
    }

    def __init__(
        self,
        workdir: str | Path,
        *,
        ttl_seconds: float = 5.0,
        inject_permissive_guardian: bool = False,
    ):
        self.workdir = Path(workdir)
        self.repository_root = Path(__file__).resolve().parents[2]
        self.trusted_dir = self.workdir / 'trusted-control'
        self.authority_replay_path = self.trusted_dir / 'replay-state.sqlite3'
        self.executor_replay_path = self.workdir / 'executor-state' / 'replay-state.sqlite3'
        self.evidence_replay_path = self.workdir / 'evidence-control' / 'replay-state.sqlite3'
        self.capability_key_path = self.workdir / 'authority-secrets' / 'capability-signing.seed'
        self.recorder_key_path = self.workdir / 'evidence-secrets' / 'recorder-signing.seed'
        self.certificate_key_path = self.workdir / 'evidence-secrets' / 'certificate-signing.seed'
        self.verifier_statement_key_path = (
            self.trusted_dir / 'verifier-statement.signing.seed'
        )
        self.guardian_statement_key_path = (
            self.trusted_dir / 'guardian-statement.signing.seed'
        )
        self.watchdog_key_path = self.workdir / 'watchdog' / 'teardown-attestation.seed'
        self.witness_key_path = self.workdir / 'witness' / 'checkpoint-witness.seed'
        self.executor_receipt_key_path = (
            self.workdir / 'executor-state' / 'execution-receipts.seed'
        )
        self.recorder_checkpoint_anchor_path = (
            self.trusted_dir / 'recorder-checkpoints.jsonl'
        )
        self.execution_state_database = (
            self.trusted_dir / 'capability-execution-state.sqlite3'
        )
        self.deployment_root_key_path = (
            self.trusted_dir / 'deployment-root.signing.seed'
        )
        self.deployment_id = f"dep-{secrets.token_hex(8)}"
        self.manifest_digest: str | None = None
        self.manifest_envelope: dict[str, Any] | None = None
        self.recorder_path = self.workdir / 'external-evidence' / 'events.jsonl'
        self.ttl_seconds = ttl_seconds
        self.inject_permissive_guardian = inject_permissive_guardian
        self.clients: dict[str, ProcessClient] = {}
        self.config_paths: dict[str, Path] = {}
        self.service_info: dict[str, dict[str, Any]] = {}
        self.protected_request_signers: dict[str, ProtectedRequestSigner] = {}
        self.source_sequences: dict[str, int] = {}
        self.run_id: str = f'run-{secrets.token_hex(8)}'
        self.attestations: list[dict[str, Any]] = []
        self.attestation_statements: list[dict[str, Any]] = []
        self.capabilities: list[IssuedCapability] = []
        self.teardown_evidence: dict[str, Any] = {'verified': False, 'executor_pid': None}
        self.teardown_statement: dict[str, Any] | None = None
        self._watchdog_signer: StatementSigner | None = None
        self.egress_evidence: dict[str, Any] = {
            'unrestricted_connectors': 0,
            'network_device_default': 'none-in-microvm-target',
            'unauthorized_egress_attempts_succeeded': 0,
        }
        self._started = False

    @staticmethod
    def _policy_config() -> dict[str, Any]:
        return {
            'policy_id': 'eh-process-policy-v0.4',
            'allowed_agents': ['attacker-agent'],
            'allowed_executors': ['exec-1'],
            'denied_argument_keys': [
                'api_key', 'authorization', 'command', 'credential', 'host', 'hostname',
                'ip', 'port', 'recipient', 'shell', 'token', 'uri', 'url',
            ],
            'operations': {
                'object.read': {
                    'resources': ['oversized-object', 'public-evidence', 'target-source'],
                    'allowed_argument_keys': ['length', 'offset'],
                    'max_output_bytes': 1_024,
                },
            },
        }

    def _start_role(self, role: str, config: Mapping[str, Any]) -> ProcessClient:
        config_path = self.trusted_dir / f'{role}.json'
        _write_config(config_path, {'role': role, **dict(config)})
        client = ProcessClient(
            role,
            config_path,
            self.repository_root,
            request_signer=self.protected_request_signers.get(role),
            protected_types=self.PROTECTED_TYPES.get(role, frozenset()),
        )
        self.clients[role] = client
        self.config_paths[role] = config_path
        return client

    def call(
        self,
        role: str,
        message_type: str,
        body: Mapping[str, Any],
        *,
        timeout_seconds: float = 5.0,
        authorize: bool | None = None,
    ) -> dict[str, Any]:
        client = self.clients.get(role)
        if client is None:
            raise ServiceUnavailable(f'{role} service is unavailable')
        return client.call(
            message_type,
            body,
            timeout_seconds=timeout_seconds,
            authorize=authorize,
        )

    def start(self) -> 'ProcessSeparatedHarness':
        if self._started:
            return self
        self.workdir.mkdir(parents=True, exist_ok=True)
        policy = self._policy_config()
        policy_digest = digest(policy)
        simulator_seed = 'event-horizon-attestation-rebuild'
        measurement = hashlib.sha256(f'simulator:executor:{simulator_seed}'.encode()).hexdigest()
        verifier_policy_digest = digest({
            'provider': 'attestation-development-bridge',
            'deviceId': 'exec-1',
            'minimumTrust': 'simulated',
            'expectedExecutorMeasurement': measurement,
        })
        attestation_root = self.repository_root / 'attestation'
        replay_namespace = 'public-process-harness'
        _provision_or_load_seed(self.capability_key_path)
        _provision_or_load_seed(self.recorder_key_path)
        _provision_or_load_seed(self.certificate_key_path)
        verifier_statement_seed = _provision_or_load_seed(self.verifier_statement_key_path)
        guardian_statement_seed = _provision_or_load_seed(self.guardian_statement_key_path)
        watchdog_seed = _provision_or_load_seed(self.watchdog_key_path)
        witness_seed = _provision_or_load_seed(self.witness_key_path)
        executor_receipt_seed = _provision_or_load_seed(self.executor_receipt_key_path)
        verifier_statement_signer = StatementSigner(verifier_statement_seed, subject='verifier')
        guardian_statement_signer = StatementSigner(guardian_statement_seed, subject='guardians')
        self._watchdog_signer = StatementSigner(watchdog_seed, subject='watchdog')
        executor_receipt_signer = StatementSigner(
            executor_receipt_seed,
            subject='executor:exec-1',
        )
        recorder_seed = load_private_seed(self.recorder_key_path)
        recorder_public_pem = Ed25519PrivateKey.from_private_bytes(recorder_seed).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')
        capability_seed = load_private_seed(self.capability_key_path)
        capability_public_pem = Ed25519PrivateKey.from_private_bytes(capability_seed).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')
        certificate_seed = load_private_seed(self.certificate_key_path)
        certificate_public_pem = Ed25519PrivateKey.from_private_bytes(certificate_seed).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')

        # ---- Trust Root Manifest -------------------------------------------
        # One signed manifest authorizes every actor role for this deployment.
        from .trust_manifest import TrustRootAuthority, ManifestChain, make_actor

        deployment_root_seed = _provision_or_load_seed(self.deployment_root_key_path)
        authority = TrustRootAuthority(
            deployment_root_seed,
            deployment_id=self.deployment_id,
            environment='synthetic',
        )
        witness_public_pem = Ed25519PrivateKey.from_private_bytes(witness_seed).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('ascii')
        actors = [
            make_actor(role='certificate-signer', public_key_pem=certificate_public_pem),
            make_actor(role='capability-signer', public_key_pem=capability_public_pem),
            make_actor(role='verifier', public_key_pem=verifier_statement_signer.public_key_pem),
            make_actor(role='guardian', public_key_pem=guardian_statement_signer.public_key_pem),
            make_actor(role='executor', public_key_pem=executor_receipt_signer.public_key_pem),
            make_actor(role='watchdog', public_key_pem=self._watchdog_signer.public_key_pem),
            make_actor(role='recorder', public_key_pem=recorder_public_pem),
            make_actor(
                role='witness',
                public_key_pem=witness_public_pem,
                purposes={'witness-checkpoint'},
            ),
        ]
        self.manifest_envelope = authority.issue_manifest(
            actors,
            manifest_version=1,
            sequence=1,
            issued_at_ms=time.time_ns() // 1_000_000,
            previous_manifest_digest=None,
        )
        chain = ManifestChain(
            authority.public_key_pem,
            deployment_id=self.deployment_id,
            environment='synthetic',
        )
        verified = chain.append(self.manifest_envelope)
        self.manifest_digest = verified.manifest_digest
        (self.trusted_dir / 'trust-manifest.json').write_text(
            json.dumps(self.manifest_envelope, indent=2, sort_keys=True),
            encoding='utf-8',
        )

        def statement_public_key(signer: StatementSigner) -> dict[str, str]:
            return {
                'public_key': signer.public_key_pem,
                'key_id': signer.key_id,
            }

        self.protected_request_signers = {
            'signer': ProtectedRequestSigner(secrets.token_bytes(32), 'capability-signer'),
            'recorder': ProtectedRequestSigner(secrets.token_bytes(32), 'evidence-recorder'),
            'certificate': ProtectedRequestSigner(
                secrets.token_bytes(32),
                'certificate-signer',
            ),
            'witness': ProtectedRequestSigner(
                secrets.token_bytes(32),
                'checkpoint-witness',
            ),
        }

        def protected_config(role: str, database: Path) -> dict[str, Any]:
            request_signer = self.protected_request_signers[role]
            return {
                'authorized_client_public_key': request_signer.public_key_pem,
                'authorized_client_key_id': request_signer.key_id,
                'authorization_replay_database': str(database),
                'authorization_namespace': replay_namespace,
            }

        try:
            self._start_role('parser', {})
            self._start_role(
                'verifier',
                {
                    'attestation_root': str(attestation_root),
                    'device_seeds': {'exec-1': simulator_seed},
                    'replay_database': str(self.authority_replay_path),
                    'replay_namespace': replay_namespace,
                    'statement_signing_key_path': str(self.verifier_statement_key_path),
                },
            )
            self._start_role(
                'guardians',
                {
                    'policy': policy,
                    'max_requests_per_session': 12,
                    'max_denials_per_session': 5,
                    'inject_permissive_guardian': self.inject_permissive_guardian,
                    'behavioral_state_database': str(
                        self.trusted_dir / 'behavioral-state.sqlite3'
                    ),
                    'statement_signing_key_path': str(self.guardian_statement_key_path),
                },
            )
            signer = self._start_role(
                'signer',
                {
                    'ttl_seconds': self.ttl_seconds,
                    'signing_key_path': str(self.capability_key_path),
                    'replay_database': str(self.authority_replay_path),
                    'replay_namespace': replay_namespace,
                    'consumption_domain': 'broker',
                    'decay_database': str(self.trusted_dir / 'decay-state.sqlite3'),
                    'policy': policy,
                    'guardian_statement_public_key': guardian_statement_signer.public_key_pem,
                    **protected_config('signer', self.authority_replay_path),
                },
            )
            self._start_role(
                'recorder',
                {
                    'path': str(self.recorder_path),
                    'signing_key_path': str(self.recorder_key_path),
                    'max_event_bytes': 16_384,
                    'checkpoint_anchor_path': str(self.recorder_checkpoint_anchor_path),
                    'checkpoint_deployment_id': self.deployment_id,
                    'checkpoint_manifest_digest': self.manifest_digest,
                    **protected_config('recorder', self.evidence_replay_path),
                },
            )
            signer_info = signer.call('info', {})
            self._start_role(
                'executor',
                {
                    'executor_id': 'exec-1',
                    'device_id': 'exec-1',
                    'measurement': measurement,
                    'verifier_policy_digest': verifier_policy_digest,
                    'policy_digest': policy_digest,
                    'signer_public_key': signer_info['public_key_pem'],
                    'signer_key_id': signer_info['key_id'],
                    'replay_database': str(self.executor_replay_path),
                    'replay_namespace': replay_namespace,
                    'consumption_domain': 'executor:exec-1',
                    'decay_database': str(
                        self.workdir / 'executor-state' / 'decay-state.sqlite3'
                    ),
                    'receipt_signing_key_path': str(self.executor_receipt_key_path),
                    'objects': {
                        'target-source': {'name': 'synthetic-target', 'content': 'safe fixture'},
                        'public-evidence': {'finding': 'contained'},
                        'oversized-object': {'content': 'X' * 2_048},
                    },
                },
            )
            self._start_role(
                'certificate',
                {
                    'recorder_path': str(self.recorder_path),
                    'signing_key_path': str(self.certificate_key_path),
                    'checkpoint_anchor_path': str(self.recorder_checkpoint_anchor_path),
                    'recorder_public_key_pem': recorder_public_pem,
                    'deployment_id': self.deployment_id,
                    'trust_root_manifest_digest': self.manifest_digest,
                    'witness_public_key_pem': witness_public_pem,
                    'require_witness': True,
                    'approval_policy': None,
                    'trust_root_public_key_pem': authority.public_key_pem,
                    'manifest_envelope': self.manifest_envelope,
                    'executor_statement_public_key': executor_receipt_signer.public_key_pem,
                    'verifier_statement_public_key': verifier_statement_signer.public_key_pem,
                    'guardian_statement_public_key': guardian_statement_signer.public_key_pem,
                    'watchdog_statement_public_key': self._watchdog_signer.public_key_pem,
                    'execution_state_database': str(self.execution_state_database),
                    **protected_config('certificate', self.evidence_replay_path),
                },
            )
            self._start_role(
                'witness',
                {
                    'journal_path': str(self.workdir / 'witness' / 'acknowledgments.jsonl'),
                    'signing_key_path': str(self.witness_key_path),
                    'deployment_id': self.deployment_id,
                    'recorder_public_key_pem': recorder_public_pem,
                    'witness_id': f"witness-{self.deployment_id}"[:128],
                    **protected_config('witness', self.evidence_replay_path),
                },
            )
            for role in self.ROLES:
                self.service_info[role] = self.call(role, 'info', {})
            pids = [info['pid'] for info in self.service_info.values()]
            if len(set(pids)) != len(self.ROLES):
                raise ServiceUnavailable('trust domains did not receive unique process identities')
            self._started = True
            return self
        except Exception:
            self.close()
            raise

    def record(
        self,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        source_id: str = 'coordinator',
    ) -> dict[str, Any]:
        sequence = self.source_sequences.get(source_id, 0) + 1
        stamped = {
            'run_id': self.run_id,
            **dict(payload),
        }
        response = self.call(
            'recorder',
            'append',
            {
                'event_type': event_type,
                'payload': stamped,
                'source_id': source_id,
                'source_sequence': sequence,
            },
        )
        record = response.get('record')
        if not isinstance(record, dict) or 'receipt' not in record:
            raise ServiceUnavailable('recorder omitted signed receipt')
        recorder_info = self.service_info.get('recorder') or self.call('recorder', 'info', {})
        if not ExternalRecorder.verify_receipt(record['receipt'], recorder_info['public_key_pem']):
            raise ServiceUnavailable('recorder receipt signature is invalid')
        receipt_payload = record['receipt']['payload']
        if receipt_payload['source_id'] != source_id or receipt_payload['source_sequence'] != sequence:
            raise ServiceUnavailable('recorder receipt sequence mismatch')
        self.source_sequences[source_id] = sequence
        return record

    def issue_checkpoint(self) -> dict[str, Any]:
        """Anchor the current evidence chain outside the recorder file."""
        response = self.call('recorder', 'checkpoint', {})
        envelope = response.get('checkpoint')
        if not isinstance(envelope, dict) or 'checkpoint' not in envelope:
            raise ServiceUnavailable('recorder omitted signed checkpoint')
        return envelope

    def publish_witness_checkpoint(self) -> dict[str, Any]:
        """Have the independent witness acknowledge the current checkpoint."""
        envelope = self.issue_checkpoint()
        response = self.call(
            'witness',
            'publish',
            {
                'checkpoint_envelope': envelope,
                'manifest_digest': self.manifest_digest,
            },
        )
        acknowledgment = response.get('acknowledgment')
        if not isinstance(acknowledgment, dict):
            raise ServiceUnavailable('witness omitted acknowledgment')
        return {'checkpoint': envelope, 'acknowledgment': acknowledgment}

    def request_capability(
        self,
        payload: Mapping[str, Any],
    ) -> tuple[ActionRequest, IssuedCapability, dict[str, Any]]:
        try:
            parsed = self.call('parser', 'parse_action', {'payload': dict(payload)})
            request = ActionRequest.from_dict(parsed['request'])
            if parsed['request_digest'] != request.request_digest:
                raise AuthorizationDenied('parser digest mismatch')
            self.record(
                'request.received',
                {
                    'request_id': request.request_id,
                    'session_id': request.session_id,
                    'agent_id': request.agent_id,
                    'executor_id': request.executor_id,
                    'operation': request.operation,
                    'resource_id': request.resource_id,
                    'request_digest': request.request_digest,
                },
            )
            attestation_response = self.call(
                'verifier',
                'verify_executor',
                {
                    'executor_id': request.executor_id,
                    'session_id': request.session_id,
                    'purpose': request.purpose,
                },
            )
            attestation = attestation_response['attestation']
            verifier_statement = attestation_response['statement']
            self.record(
                'attestation.verified',
                {
                    'request_id': request.request_id,
                    'device_id': attestation['deviceId'],
                    'result_digest': attestation['resultDigest'],
                    'bundle_digest': attestation['bundleDigest'],
                    'verifier_policy_digest': attestation['verifierPolicyDigest'],
                    'nonce_context': attestation['nonceContext'],
                    'session_id': request.session_id,
                    'statement': verifier_statement,
                },
            )
            guardian_result = self.call(
                'guardians',
                'evaluate',
                {'request': request.canonical_payload(), 'attestation': attestation},
            )
            for decision in guardian_result['decisions']:
                self.record(
                    'guardian.decision',
                    {'request_id': request.request_id, **decision},
                )
            if guardian_result['allowed'] is not True:
                self.record('request.denied', {'request_id': request.request_id})
                raise AuthorizationDenied('guardian veto')
            issued = self.call(
                'signer',
                'issue',
                {
                    'request': request.canonical_payload(),
                    'guardian_result': guardian_result,
                    'attestation': attestation,
                },
            )
            capability = IssuedCapability.from_dict(issued['capability'])
            self.record(
                'capability.issued',
                {
                    'request_id': request.request_id,
                    'request_digest': request.request_digest,
                    'capability_id': capability.claims.capability_id,
                    'key_id': capability.key_id,
                    'device_id': capability.claims.device_id,
                    'executor_measurement': capability.claims.executor_measurement,
                    'policy_digest': capability.claims.policy_digest,
                    'attestation_digest': capability.claims.attestation_digest,
                    'attestation_bundle_digest': capability.claims.attestation_bundle_digest,
                    'verifier_policy_digest': capability.claims.verifier_policy_digest,
                    'expires_at': capability.claims.expires_at,
                },
            )
            self.attestations.append(attestation)
            self.attestation_statements.append(verifier_statement)
            self.capabilities.append(capability)
            return request, capability, attestation
        except AuthorizationDenied:
            raise
        except (ProtocolError, ServiceUnavailable, ValidationError) as exc:
            try:
                self.record('request.denied', {'reason': type(exc).__name__})
            except Exception:
                pass
            raise AuthorizationDenied('authority path failed closed') from exc

    def execute(
        self,
        request: ActionRequest,
        capability: IssuedCapability,
        attestation: Mapping[str, Any],
    ) -> ExecutionResult:
        consume_failed = False
        try:
            self.call(
                'signer',
                'consume',
                {
                    'request': request.canonical_payload(),
                    'capability': capability.to_dict(),
                    'attestation': dict(attestation),
                },
            )
        except (ProtocolError, ServiceUnavailable, ValidationError) as exc:
            result = ExecutionResult(
                False,
                request.operation,
                request.resource_id,
                error=f'{type(exc).__name__}: {exc}',
                effect_state='not_committed',
            )
        else:
            consume_failed = True
            try:
                response = self.call(
                    'executor',
                    'execute',
                    {
                        'request': request.canonical_payload(),
                        'capability': capability.to_dict(),
                        'attestation': dict(attestation),
                    },
                )
                result = ExecutionResult(**response)
            except (ProtocolError, ServiceUnavailable, ValidationError) as exc:
                # The replay store may already hold this capability and the
                # executor may already have acted: an RPC failure is never
                # proof that nothing happened.
                result = ExecutionResult(
                    False,
                    request.operation,
                    request.resource_id,
                    error=f'{type(exc).__name__}: {exc}',
                    effect_state='possibly_committed',
                )
        if result.effect_state in {'possibly_committed', 'unknown'}:
            event_type = 'execution.indeterminate'
        elif result.success:
            event_type = 'execution.completed'
        else:
            event_type = 'execution.denied'
        self.record(
            event_type,
            {
                'request_id': request.request_id,
                'session_id': request.session_id,
                'request_digest': request.request_digest,
                'capability_id': capability.claims.capability_id,
                'success': result.success,
                'output_bytes': result.output_bytes,
                'error': result.error,
                'effect_state': (
                    'possibly_committed'
                    if result.effect_state == 'possibly_committed'
                    else ('committed' if result.success and result.effect_state == 'committed' else 'not_committed')
                ),
                'receipt': result.receipt if isinstance(result.receipt, dict) else None,
            },
        )
        return result

    def root_probe(self, probe_names: list[str] | None = None) -> dict[str, Any]:
        return self.call(
            'executor',
            'root_probe',
            {'probe_names': probe_names or ['AWS_ACCESS_KEY_ID', 'GITHUB_TOKEN', 'KUBECONFIG']},
        )

    def stop_role(self, role: str) -> None:
        client = self.clients.pop(role, None)
        if client is not None:
            client.stop()

    def restart_role(self, role: str) -> dict[str, Any]:
        if role not in {'verifier', 'signer', 'executor', 'recorder', 'certificate'}:
            raise ValueError('role does not support state-preserving restart')
        config_path = self.config_paths.get(role)
        if config_path is None:
            raise ServiceUnavailable(f'{role} service configuration is unavailable')
        config = json.loads(config_path.read_text(encoding='utf-8'))
        if not isinstance(config, dict) or config.pop('role', None) != role:
            raise ServiceUnavailable(f'{role} service configuration is malformed')
        self.stop_role(role)
        client = self._start_role(role, config)
        info = client.call('info', {})
        self.service_info[role] = info
        return info

    def restart_recorder(self) -> dict[str, Any]:
        return self.restart_role('recorder')

    def teardown_executor(self) -> dict[str, Any]:
        client = self.clients.get('executor')
        pid = client.pid if client is not None else self.service_info.get('executor', {}).get('pid')
        self.stop_role('executor')
        stopped = client is None or not client.running
        config_path = self.config_paths.get('executor')
        disk_destroyed = False
        if config_path is not None and config_path.exists():
            config_path.unlink()
            disk_destroyed = not config_path.exists()
        self.teardown_evidence = {
            'verified': bool(stopped and disk_destroyed),
            'executor_pid': pid,
            'process_stopped': stopped,
            'ephemeral_config_destroyed': disk_destroyed,
            'run_id': self.run_id,
        }
        # The watchdog independently authenticates its own teardown conclusion
        # so the certificate signer does not have to trust the coordinator.
        statement = self._watchdog_signer.sign(TYPE_TEARDOWN_ATTESTATION, {
            'run_id': self.run_id,
            'executor_pid': pid,
            'process_stopped': bool(stopped),
            'ephemeral_config_destroyed': bool(disk_destroyed),
            'verified': bool(stopped and disk_destroyed),
        }).to_dict()
        self.teardown_statement = statement
        self.record(
            'teardown.verified',
            {**self.teardown_evidence, 'statement': statement},
            source_id='watchdog',
        )
        return dict(self.teardown_evidence)

    def build_certificate(self, *, run_id: str | None = None) -> dict[str, Any]:
        """Build a witnessed certificate derived entirely from run evidence.

        The recorder checkpoints its chain, the independent witness service
        acknowledges the checkpoint, and the certificate signer binds both.
        The caller supplies only the run selector.
        """
        witnessed = self.publish_witness_checkpoint()
        response = self.call(
            'certificate',
            'build',
            {
                'run_id': run_id or self.run_id,
                'witness_acknowledgment': witnessed['acknowledgment'],
            },
        )
        certificate = response['certificate']
        verified = self.call('certificate', 'verify', {'certificate': certificate})['valid']
        if verified is not True:
            raise ServiceUnavailable('certificate builder could not verify its detached signature')
        return certificate

    def close(self) -> None:
        for role in reversed(self.ROLES):
            self.stop_role(role)
        self._started = False

    def __enter__(self) -> 'ProcessSeparatedHarness':
        return self.start()

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()
