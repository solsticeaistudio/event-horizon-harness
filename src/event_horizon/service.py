from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from .attestation import DevelopmentAttestationProvider
from .broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from .canonical import digest
from .certificate import ContainmentCertificateBuilder
from .behavioral_guardian import BehavioralGuardian, SqliteBehavioralStateStore
from .component_ids import (
    EXECUTOR_ATTESTATION_GUARDIAN,
    REQUIRED_GUARDIANS,
    STATIC_POLICY_GUARDIAN,
)
from .executor import SacrificialExecutor
from .guardians import LineageBudgetGuardian, PolicyGuardian
from .models import ActionRequest, GuardianDecision, IssuedCapability, ValidationError
from .policy import OperationRule, StaticPolicy
from .protocol import MessageSpec, ProtocolError, StrictRpcServer
from .protected_boundary import (
    ProtectedRequestVerifier,
    SqliteAuthorizationReplayStore,
    load_private_seed,
)
from .recorder import ExternalRecorder
from .replay_state import SqliteCapabilityConsumptionStore
from .task_policy import (
    AuthorityReduction,
    ProviderTrustState,
    TaskPolicySynthesizer,
    TrustedPolicyCompiler,
    default_policy_templates,
    task_description_for_request,
)
from .trust_decay import DecayEngine, SqliteDecayStateStore


def _exact(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtocolError('unknown_field', f'{name} fields are invalid')
    return value


def _load_config(path: Path, role: str, fields: set[str]) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError('service configuration is unavailable or malformed') from exc
    _exact(payload, {'role', *fields}, 'service configuration')
    if payload['role'] != role:
        raise RuntimeError('service role does not match configuration')
    return payload


PROTECTED_CONFIG_FIELDS = {
    'authorized_client_public_key',
    'authorized_client_key_id',
    'authorization_replay_database',
    'authorization_namespace',
}


def _protected_authorizer(
    config: Mapping[str, Any],
    audience: str,
) -> ProtectedRequestVerifier:
    replay_store = SqliteAuthorizationReplayStore(
        config['authorization_replay_database'],
        namespace=config['authorization_namespace'],
        audience=audience,
    )
    return ProtectedRequestVerifier(
        config['authorized_client_public_key'],
        config['authorized_client_key_id'],
        audience,
        replay_store,
    )


def _action(value: Any) -> ActionRequest:
    try:
        return ActionRequest.from_dict(value)
    except ValidationError as exc:
        raise ProtocolError('invalid_action', str(exc)) from exc


ATTESTATION_FIELDS = {
    'valid', 'deviceId', 'method', 'trustLevel', 'assuranceLevel', 'keyId',
    'measurements', 'bundleDigest', 'verifiedAt', 'verifierPolicyDigest', 'resultDigest',
    'nonceContext', 'nonceIssuedAt', 'nonceExpiresAt',
}


def _attestation(value: Any) -> dict[str, Any]:
    result = _exact(value, ATTESTATION_FIELDS, 'attestation result')
    if result['valid'] is not True:
        raise ProtocolError('attestation_denied', 'attestation result is not valid')
    unsigned = dict(result)
    claimed = unsigned.pop('resultDigest')
    if not isinstance(claimed, str) or digest(unsigned) != claimed:
        raise ProtocolError('attestation_digest', 'attestation result digest mismatch')
    measurements = result['measurements']
    if not isinstance(measurements, dict) or not measurements.get('executor'):
        raise ProtocolError('attestation_measurement', 'attestation omitted executor measurement')
    return result


def _policy(value: Any) -> StaticPolicy:
    config = _exact(
        value,
        {'policy_id', 'allowed_agents', 'allowed_executors', 'denied_argument_keys', 'operations'},
        'policy',
    )
    operations = config['operations']
    if not isinstance(operations, dict):
        raise RuntimeError('policy operations must be an object')
    rules: dict[str, OperationRule] = {}
    for name, raw_rule in operations.items():
        rule = _exact(raw_rule, {'resources', 'allowed_argument_keys', 'max_output_bytes'}, 'operation rule')
        rules[name] = OperationRule(
            resources=frozenset(rule['resources']),
            allowed_argument_keys=frozenset(rule['allowed_argument_keys']),
            max_output_bytes=int(rule['max_output_bytes']),
        )
    return StaticPolicy(
        policy_id=config['policy_id'],
        operations=rules,
        allowed_agents=frozenset(config['allowed_agents']),
        allowed_executors=frozenset(config['allowed_executors']),
        denied_argument_keys=frozenset(config['denied_argument_keys']),
    )


class _NullRecorder:
    def append(self, _event_type: str, _payload: dict[str, Any]) -> None:
        return None


def _info(role: str) -> dict[str, Any]:
    return {'role': role, 'pid': os.getpid()}


def _parser_specs(config_path: Path) -> dict[str, MessageSpec]:
    _load_config(config_path, 'parser', set())

    def parse_action(body: dict[str, Any]) -> Mapping[str, Any]:
        request = _action(body['payload'])
        return {'request': request.canonical_payload(), 'request_digest': request.request_digest}

    return {
        'info': MessageSpec(frozenset(), lambda _body: _info('parser')),
        'parse_action': MessageSpec(frozenset({'payload'}), parse_action),
    }


def _verifier_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'verifier',
        {'attestation_root', 'device_seeds', 'replay_database', 'replay_namespace'},
    )
    if not isinstance(config['device_seeds'], dict):
        raise RuntimeError('verifier device enrollment is invalid')
    provider = DevelopmentAttestationProvider(
        attestation_root=Path(config['attestation_root']),
        device_seeds=config['device_seeds'],
        replay_database=Path(config['replay_database']),
        replay_namespace=config['replay_namespace'],
    )

    def verify_executor(body: dict[str, Any]) -> Mapping[str, Any]:
        executor_id = body['executor_id']
        session_id = body['session_id']
        purpose = body['purpose']
        if not all(isinstance(item, str) and item for item in (executor_id, session_id, purpose)):
            raise ProtocolError('invalid_attestation_context', 'attestation context is invalid')
        try:
            result = dict(provider.verify_executor(executor_id, session_id, purpose))
        except Exception as exc:
            raise ProtocolError('attestation_unavailable', str(exc)) from exc
        return {'attestation': _attestation(result)}

    return {
        'info': MessageSpec(frozenset(), lambda _body: _info('verifier')),
        'verify_executor': MessageSpec(
            frozenset({'executor_id', 'session_id', 'purpose'}),
            verify_executor,
        ),
    }


def _guardian_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'guardians',
        {
            'policy', 'max_requests_per_session', 'max_denials_per_session',
            'inject_permissive_guardian', 'behavioral_state_database',
        },
    )
    policy = _policy(config['policy'])
    policy_guardian = PolicyGuardian(policy)
    budget = LineageBudgetGuardian(
        max_requests_per_session=int(config['max_requests_per_session']),
        max_denials_per_session=int(config['max_denials_per_session']),
    )
    behavioral = BehavioralGuardian(
        SqliteBehavioralStateStore(config['behavioral_state_database'])
    )
    inject_permissive = config['inject_permissive_guardian'] is True

    def evaluate(body: dict[str, Any]) -> Mapping[str, Any]:
        request = _action(body['request'])
        attestation = _attestation(body['attestation'])
        measurement = attestation['measurements']['executor']
        try:
            trust_state = ProviderTrustState.from_attestation(attestation)
        except ValidationError as exc:
            raise ProtocolError('attestation_trust', str(exc)) from exc
        attestation_allowed = attestation['deviceId'] == request.executor_id
        attestation_decision = GuardianDecision(
            EXECUTOR_ATTESTATION_GUARDIAN,
            attestation_allowed,
            'executor identity and measurement verified' if attestation_allowed else 'device identity mismatch',
            {
                'device_id': attestation['deviceId'],
                'measurement': measurement,
                'bundle_digest': attestation['bundleDigest'],
                'attestation_result_digest': attestation['resultDigest'],
                'verifier_policy_digest': attestation['verifierPolicyDigest'],
                'method': attestation['method'],
                'trust_level': attestation['trustLevel'],
                'assurance_level': attestation['assuranceLevel'],
                'key_id': attestation['keyId'],
                'nonce_context': attestation['nonceContext'],
                'nonce_issued_at': attestation['nonceIssuedAt'],
                'nonce_expires_at': attestation['nonceExpiresAt'],
                'provider_trust_state': trust_state.to_dict(),
                'attestation_result': dict(attestation),
            },
            request.request_digest,
        )
        decisions = [
            policy_guardian.evaluate(request),
            attestation_decision,
            budget.evaluate(request),
            behavioral.evaluate(request),
        ]
        if inject_permissive:
            decisions.append(GuardianDecision(
                'compromised', True, 'injected permissive decision',
                request_digest=request.request_digest,
            ))
        allowed = all(decision.allowed for decision in decisions)
        behavioral.record_outcome(
            request,
            'allowed' if allowed else 'denied',
            now_ms=time.time_ns() // 1_000_000,
        )
        if not allowed:
            budget.record_denial(request.session_id)
        result = {
            'allowed': allowed,
            'request_digest': request.request_digest,
            'policy_digest': policy.policy_digest,
            'decisions': [asdict(decision) for decision in decisions],
        }
        result['quorum_digest'] = digest(result)
        return result

    return {
        'info': MessageSpec(
            frozenset(),
            lambda _body: {**_info('guardians'), 'policy_digest': policy.policy_digest},
        ),
        'evaluate': MessageSpec(frozenset({'request', 'attestation'}), evaluate),
    }


def _guardian_result(value: Any, request: ActionRequest) -> dict[str, Any]:
    result = _exact(
        value,
        {'allowed', 'request_digest', 'policy_digest', 'decisions', 'quorum_digest'},
        'guardian result',
    )
    unsigned = dict(result)
    claimed_digest = unsigned.pop('quorum_digest')
    if not isinstance(claimed_digest, str) or digest(unsigned) != claimed_digest:
        raise ProtocolError('guardian_digest', 'guardian quorum digest mismatch')
    if result['request_digest'] != request.request_digest:
        raise ProtocolError('guardian_request', 'guardian result request mismatch')
    decisions = result['decisions']
    if not isinstance(decisions, list) or not decisions:
        raise ProtocolError('guardian_quorum', 'guardian decisions are missing')
    required = REQUIRED_GUARDIANS
    names: set[str] = set()
    static_decision: dict[str, Any] | None = None
    for decision in decisions:
        _exact(
            decision,
            {'guardian', 'allowed', 'reason', 'evidence', 'request_digest'},
            'guardian decision',
        )
        if not isinstance(decision['allowed'], bool) or not isinstance(decision['evidence'], dict):
            raise ProtocolError('guardian_decision', 'guardian decision types are invalid')
        if decision['request_digest'] != request.request_digest:
            raise ProtocolError('guardian_request', 'guardian decision request mismatch')
        if decision['guardian'] in names:
            raise ProtocolError('guardian_quorum', 'duplicate guardian decision')
        names.add(decision['guardian'])
        if decision['guardian'] == STATIC_POLICY_GUARDIAN:
            static_decision = decision
    if not required.issubset(names):
        raise ProtocolError('guardian_quorum', 'required guardian decision is missing')
    if static_decision is None or static_decision['evidence'].get('policy_digest') != result['policy_digest']:
        raise ProtocolError('policy_digest', 'static policy decision version mismatch')
    for decision in decisions:
        reported_policy = decision['evidence'].get('policy_digest')
        if reported_policy is not None and reported_policy != result['policy_digest']:
            raise ProtocolError('policy_digest', 'guardian policy versions are inconsistent')
    if result['allowed'] is not all(decision['allowed'] for decision in decisions):
        raise ProtocolError('guardian_quorum', 'guardian aggregate is inconsistent')
    return result


def _signer_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'signer',
        {
            'ttl_seconds', 'signing_key_path', 'replay_database',
            'replay_namespace', 'consumption_domain', 'decay_database', 'policy',
            *PROTECTED_CONFIG_FIELDS,
        },
    )
    policy = _policy(config['policy'])
    tool_actions = {'object-reader': frozenset({'object.read'})}
    synthesizer = TaskPolicySynthesizer(default_policy_templates(), mode='rule')
    compiler = TrustedPolicyCompiler(
        policy,
        tool_actions=tool_actions,
        allowed_tenant_environments={'default': frozenset({'synthetic'})},
    )
    signing_seed = load_private_seed(config['signing_key_path'])
    request_authorizer = _protected_authorizer(config, 'capability-signer')
    consumption_store = SqliteCapabilityConsumptionStore(
        config['replay_database'],
        namespace=config['replay_namespace'],
        domain=config['consumption_domain'],
    )
    broker = CapabilityBroker(
        signing_seed,
        ttl_seconds=float(config['ttl_seconds']),
        consumption_store=consumption_store,
        decay_engine=DecayEngine(SqliteDecayStateStore(config['decay_database'])),
    )

    def issue(body: dict[str, Any]) -> Mapping[str, Any]:
        request = _action(body['request'])
        attestation = _attestation(body['attestation'])
        guardians = _guardian_result(body['guardian_result'], request)
        if guardians['allowed'] is not True:
            raise ProtocolError('authorization_denied', 'guardian quorum vetoed the request')
        if attestation['deviceId'] != request.executor_id:
            raise ProtocolError('attestation_device', 'attested device does not match executor')
        static_policy = next(
            item for item in guardians['decisions'] if item['guardian'] == STATIC_POLICY_GUARDIAN
        )
        attestation_decision = next(
            item
            for item in guardians['decisions']
            if item['guardian'] == EXECUTOR_ATTESTATION_GUARDIAN
        )
        if static_policy['evidence'].get('policy_digest') != guardians['policy_digest']:
            raise ProtocolError('policy_digest', 'static policy digest mismatch')
        expected_attestation = {
            'device_id': attestation['deviceId'],
            'measurement': attestation['measurements']['executor'],
            'bundle_digest': attestation['bundleDigest'],
            'attestation_result_digest': attestation['resultDigest'],
            'verifier_policy_digest': attestation['verifierPolicyDigest'],
            'method': attestation['method'],
            'trust_level': attestation['trustLevel'],
            'assurance_level': attestation['assuranceLevel'],
            'key_id': attestation['keyId'],
            'nonce_context': attestation['nonceContext'],
            'nonce_issued_at': attestation['nonceIssuedAt'],
            'nonce_expires_at': attestation['nonceExpiresAt'],
            'provider_trust_state': ProviderTrustState.from_attestation(attestation).to_dict(),
            'attestation_result': dict(attestation),
        }
        if attestation_decision['evidence'] != expected_attestation:
            raise ProtocolError('attestation_binding', 'guardian attestation evidence mismatch')
        max_output_bytes = static_policy['evidence'].get('max_output_bytes')
        if not isinstance(max_output_bytes, int):
            raise ProtocolError('policy_output', 'policy omitted output envelope')
        trust_state = ProviderTrustState.from_attestation(attestation)
        task = task_description_for_request(request, policy, trust_state, tool_actions)
        candidate = synthesizer.synthesize(task)
        compiled_ceiling = compiler.compile(
            task,
            candidate,
            guardian_reductions=tuple(
                AuthorityReduction.from_dict(item['evidence']['authority_reduction'])
                for item in guardians['decisions']
                if 'authority_reduction' in item['evidence']
            ),
            now_ms=int(time.time() * 1000),
        )
        capability = broker.issue(
            request,
            device_id=attestation['deviceId'],
            executor_measurement=attestation['measurements']['executor'],
            trust_state=trust_state,
            compiled_ceiling=compiled_ceiling,
            policy_digest=guardians['policy_digest'],
            max_output_bytes=max_output_bytes,
            guardian_state_digest=digest(guardians['decisions']),
        )
        return {'capability': capability.to_dict()}

    def consume(body: dict[str, Any]) -> Mapping[str, Any]:
        request = _action(body['request'])
        capability = IssuedCapability.from_dict(body['capability'])
        attestation = _attestation(body['attestation'])
        try:
            claims = broker.verify_and_consume(
                capability,
                request,
                executor_measurement=attestation['measurements']['executor'],
                device_id=attestation['deviceId'],
                attestation=attestation,
                verifier_policy_digest=attestation['verifierPolicyDigest'],
                policy_digest=policy.policy_digest,
            )
        except CapabilityError as exc:
            raise ProtocolError('capability_denied', str(exc)) from exc
        return {'capability_id': claims.capability_id, 'claims_digest': digest(claims.to_dict())}

    return {
        'info': MessageSpec(
            frozenset(),
            lambda _body: {
                **_info('signer'),
                'key_id': broker.key_id,
                'public_key_pem': broker.public_key_pem,
                'key_storage': 'restricted-file-development',
                'request_authentication': 'Ed25519',
            },
        ),
        'issue': MessageSpec(
            frozenset({'request', 'guardian_result', 'attestation'}),
            issue,
            request_authorizer.authorize,
        ),
        'consume': MessageSpec(
            frozenset({'request', 'capability', 'attestation'}),
            consume,
            request_authorizer.authorize,
        ),
    }


def _executor_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'executor',
        {
            'executor_id', 'device_id', 'measurement', 'verifier_policy_digest',
            'policy_digest', 'signer_public_key', 'signer_key_id', 'objects',
            'replay_database', 'replay_namespace', 'consumption_domain', 'decay_database',
        },
    )
    if not isinstance(config['objects'], dict):
        raise RuntimeError('executor object fixtures are invalid')
    consumption_store = SqliteCapabilityConsumptionStore(
        config['replay_database'],
        namespace=config['replay_namespace'],
        domain=config['consumption_domain'],
    )
    verifier = CapabilityVerifier(
        config['signer_public_key'],
        config['signer_key_id'],
        consumption_store,
        DecayEngine(SqliteDecayStateStore(config['decay_database'])),
    )
    executor = SacrificialExecutor(
        executor_id=config['executor_id'],
        device_id=config['device_id'],
        measurement=config['measurement'],
        verifier_policy_digest=config['verifier_policy_digest'],
        policy_digest=config['policy_digest'],
        broker=verifier,
        recorder=_NullRecorder(),
        objects=config['objects'],
    )

    def execute(body: dict[str, Any]) -> Mapping[str, Any]:
        request = _action(body['request'])
        capability = IssuedCapability.from_dict(body['capability'])
        attestation = _attestation(body['attestation'])
        return asdict(executor.execute(request, capability, attestation))

    def root_probe(body: dict[str, Any]) -> Mapping[str, Any]:
        probe_names = body['probe_names']
        if not isinstance(probe_names, list) or any(not isinstance(name, str) for name in probe_names):
            raise ProtocolError('invalid_probe', 'probe names must be strings')
        dangerous_fragments = ('token', 'secret', 'password', 'credential', 'private_key', 'aws_', 'azure_', 'google_')
        environment_hits = sorted(
            name for name, value in os.environ.items()
            if value and any(fragment in name.lower() for fragment in dangerous_fragments)
        )
        config_text = config_path.read_text(encoding='utf-8')
        requested_hits = sorted(name for name in probe_names if name in os.environ and os.environ[name])
        return {
            'pid': os.getpid(),
            'effective_uid': os.geteuid() if hasattr(os, 'geteuid') else None,
            'requested_environment_hits': requested_hits,
            'ambient_authority_environment_hits': environment_hits,
            'private_key_material_present': 'PRIVATE KEY' in config_text,
            'signer_key_id': config['signer_key_id'],
        }

    return {
        'info': MessageSpec(
            frozenset(),
            lambda _body: {
                **_info('executor'),
                'executor_id': config['executor_id'],
                'device_id': config['device_id'],
                'signer_key_id': config['signer_key_id'],
            },
        ),
        'execute': MessageSpec(frozenset({'request', 'capability', 'attestation'}), execute),
        'root_probe': MessageSpec(frozenset({'probe_names'}), root_probe),
    }


def _recorder_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'recorder',
        {'path', 'signing_key_path', 'max_event_bytes', *PROTECTED_CONFIG_FIELDS},
    )
    signing_seed = load_private_seed(config['signing_key_path'])
    request_authorizer = _protected_authorizer(config, 'evidence-recorder')
    recorder = ExternalRecorder(
        config['path'],
        signing_seed,
        max_event_bytes=int(config['max_event_bytes']),
    )

    def append(body: dict[str, Any]) -> Mapping[str, Any]:
        payload = body['payload']
        if not isinstance(payload, dict):
            raise ProtocolError('invalid_event', 'event payload must be an object')
        try:
            record = recorder.append(
                body['event_type'],
                payload,
                source_id=body['source_id'],
                source_sequence=body['source_sequence'],
            )
        except Exception as exc:
            raise ProtocolError('recording_denied', str(exc)) from exc
        return {'record': record}

    def status() -> dict[str, Any]:
        valid, detail = recorder.verify()
        return {
            'valid': valid,
            'detail': detail,
            'count': recorder.count(),
            'key_id': recorder.key_id,
            'public_key_pem': recorder.public_key_pem,
        }

    return {
        'info': MessageSpec(
            frozenset(),
            lambda _body: {
                **_info('recorder'),
                **status(),
                'key_storage': 'restricted-file-development',
                'request_authentication': 'Ed25519',
            },
        ),
        'append': MessageSpec(
            frozenset({'event_type', 'payload', 'source_id', 'source_sequence'}),
            append,
            request_authorizer.authorize,
        ),
        'verify': MessageSpec(frozenset(), lambda _body: status()),
    }


def _certificate_specs(config_path: Path) -> dict[str, MessageSpec]:
    config = _load_config(
        config_path,
        'certificate',
        {'recorder_path', 'signing_key_path', *PROTECTED_CONFIG_FIELDS},
    )
    signing_seed = load_private_seed(config['signing_key_path'])
    request_authorizer = _protected_authorizer(config, 'certificate-signer')
    recorder_view = ExternalRecorder(config['recorder_path'], b'R' * 32)
    builder = ContainmentCertificateBuilder(recorder_view, signing_seed)

    def build(body: dict[str, Any]) -> Mapping[str, Any]:
        if not isinstance(body['assertions'], dict) or not isinstance(body['evidence'], dict):
            raise ProtocolError('invalid_certificate', 'certificate assertions and evidence must be objects')
        if any(not isinstance(value, bool) for value in body['assertions'].values()):
            raise ProtocolError('invalid_certificate', 'certificate assertions must be booleans')
        try:
            certificate = builder.build(
                run_id=body['run_id'],
                session_id=body['session_id'],
                assertions=body['assertions'],
                evidence=body['evidence'],
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError('invalid_certificate', str(exc)) from exc
        return {'certificate': certificate}

    def verify(body: dict[str, Any]) -> Mapping[str, Any]:
        return {
            'valid': ContainmentCertificateBuilder.verify(
                body['certificate'],
                public_key_pem=builder.public_key_pem,
                expected_key_id=builder.key_id,
            )
        }

    return {
        'info': MessageSpec(
            frozenset(),
            lambda _body: {
                **_info('certificate'),
                'key_id': builder.key_id,
                'public_key_pem': builder.public_key_pem,
                'key_storage': 'restricted-file-development',
                'request_authentication': 'Ed25519',
            },
        ),
        'build': MessageSpec(
            frozenset({'run_id', 'session_id', 'assertions', 'evidence'}),
            build,
            request_authorizer.authorize,
        ),
        'verify': MessageSpec(frozenset({'certificate'}), verify),
    }


ROLE_BUILDERS = {
    'parser': _parser_specs,
    'verifier': _verifier_specs,
    'guardians': _guardian_specs,
    'signer': _signer_specs,
    'executor': _executor_specs,
    'recorder': _recorder_specs,
    'certificate': _certificate_specs,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Event Horizon strict local service')
    parser.add_argument('--role', choices=sorted(ROLE_BUILDERS), required=True)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        specs = ROLE_BUILDERS[args.role](args.config)
        StrictRpcServer(specs).serve(sys.stdin.buffer, sys.stdout.buffer)
        return 0
    except Exception as exc:
        print(f'{type(exc).__name__}: service failed closed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
