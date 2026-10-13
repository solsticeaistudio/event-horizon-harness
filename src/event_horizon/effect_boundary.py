"""Host-owned dataset boundary for Firecracker and the package worker lab.

The VM controls the request payload, not the authority store, verifier keys,
effect handler, attestation context, or database credentials. Authorization
and effect dispatch happen in the trusted host service.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import socket
from typing import Any

from .authority_backends import EtcdGatewayConfig
from .broker import CapabilityVerifier
from .effect_outcome_journal import DurableEffectJournal
from .fenced_effect_recovery import FencedEffectRecoveryGateway
from .fenced_recipient_transport import FencedRecipientClient
from .models import ActionRequest, ExecutionResult, IssuedCapability
from .trusted_effect_gateway import TrustedEffectGateway, select_consumption_store
from .trust_decay import DecayEngine, SqliteDecayStateStore


class DatasetEffectBoundary:
    """Session-bound, transport-UID constrained read endpoint.

    The selected authority backend lives only in this host-side service.
    The guest protocol is limited to `{"request", "capability"}` and
    cannot select backend, caller identity, policy, or effect callback.
    """

    def __init__(self, config: dict[str, Any], recorder: Any):
        self.config = config
        self.recorder = recorder
        self.active = True
        context = config["verification_context"]
        self.backend = config.get("authority_backend", "sqlite")
        opts: dict[str, Any] = {
            "backend": self.backend,
            "namespace": config["session_id"],
            "domain": "external-effect",
        }
        if self.backend == "sqlite":
            if "etcd_gateway" in config or "etcd_cluster_id" in config:
                raise ValueError("SQLite mode cannot inherit etcd configuration")
            opts["sqlite_path"] = config["replay_database"]
        elif self.backend == "etcd":
            etcd_fields = config.get("etcd_gateway")
            if not isinstance(etcd_fields, dict):
                raise ValueError("etcd authority requires host-only transport configuration")
            opts["etcd_config"] = EtcdGatewayConfig(**etcd_fields)
            opts["expected_cluster_id"] = config["etcd_cluster_id"]
        else:
            raise ValueError("unknown authority backend; no local fallback")
        self.consumption_store = select_consumption_store(**opts)
        recipient = config.get("recipient_socket")
        fenced = config.get("fenced_recipient")
        journal_path = config.get("outcome_journal")
        if fenced is not None:
            if (recipient is not None or type(fenced) is not dict
                    or set(fenced) != {"socket_path", "recipient_id", "auth_key_hex"}
                    or not isinstance(journal_path, str)
                    or not journal_path):
                raise ValueError("fenced recovery requires pinned recipient and journal")
            if (type(fenced["socket_path"]) is not str
                    or type(fenced["recipient_id"]) is not str
                    or type(fenced["auth_key_hex"]) is not str
                    or len(fenced["auth_key_hex"]) != 64):
                raise ValueError("fenced host-owned configuration is malformed")
            try:
                ipc_key = bytes.fromhex(fenced["auth_key_hex"])
            except ValueError as exc:
                raise ValueError("fenced IPC key is not hex") from exc
            fenced_client = FencedRecipientClient(
                fenced["socket_path"], recipient_id=fenced["recipient_id"],
                auth_key=ipc_key,
            )
        else:
            if bool(recipient) != bool(journal_path):
                raise ValueError("external recipient requires durable outcome journal")
            if recipient and (not isinstance(recipient, str)
                              or not isinstance(journal_path, str)):
                raise ValueError("invalid trusted external effect configuration")
        self.outcome_journal = DurableEffectJournal(journal_path) if journal_path else None
        self.decay_store = SqliteDecayStateStore(config["decay_database"])
        verifier = CapabilityVerifier(
            config["public_key_pem"], config["key_id"],
            self.consumption_store, DecayEngine(self.decay_store),
        )
        if fenced is not None:
            # Explicit, trusted-host-only opt-in. The business effect is the
            # recipient's atomic SQLite transaction, not the old socket callback.
            self.gateway = FencedEffectRecoveryGateway(
                verifier, recorder, self.outcome_journal, fenced_client,
                output_factory=self._dataset_output,
                tenant=context["tenant"], environment=context["environment"],
                pre_dispatch_rule=self._preflight_read_ceiling,
            )
        else:
            self.gateway = TrustedEffectGateway(
                verifier, {"object.read": self._read_dataset}, recorder,
                event_prefix="execution",
                tenant=context["tenant"],
                environment=context["environment"],
                outcome_journal=self.outcome_journal,
                pre_dispatch_rules={"object.read": self._preflight_read_ceiling},
            )

    def _preflight_read_ceiling(self, request: ActionRequest, claims: Any) -> bool:
        """Bound the known read response BEFORE invoking a side-effect handler.

        The post-dispatch response-size check stays as defense in depth.
        Unpredictable external actions need a separate trusted preflight policy.
        """
        values = self.config["dataset"]
        offset = request.arguments.get("offset")
        length = request.arguments.get("length")
        ceiling = getattr(claims, "max_output_bytes", None)
        if (type(offset) is not int or type(length) is not int
                or type(ceiling) is not int or ceiling < 0
                or not (0 <= offset < len(values) and
                        0 < length <= 512 and offset + length <= len(values))):
            return False
        output = values[offset:offset + length]
        return len(json.dumps(output, sort_keys=True, default=str).encode("utf-8")) <= ceiling

    def _dataset_output(self, request: ActionRequest) -> str:
        """Pure host-owned precomputed output; never dispatch a legacy callback."""
        offset, length = request.arguments["offset"], request.arguments["length"]
        return self.config["dataset"][offset:offset + length]

    def _read_dataset(self, request: ActionRequest) -> str:
        output = self._dataset_output(request)
        endpoint = self.config.get("recipient_socket")
        if endpoint:
            effect_key = self.config["recipient_effect_key"]
            if not isinstance(effect_key, str) or not effect_key:
                raise ValueError("missing pinned external effect identity")
            message = json.dumps({"effect_key": effect_key,
                                  "request_digest": request.request_digest},
                                 sort_keys=True).encode("utf-8")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as recipient:
                recipient.settimeout(3)
                recipient.connect(endpoint)
                recipient.sendall(message)
                response = recipient.recv(4096)
            if json.loads(response).get("committed") is not True:
                raise RuntimeError("recipient commit was not confirmed")
        return output

    def close(self) -> None:
        self.active = False
        self.decay_store.close()
        close = getattr(self.consumption_store, "close", None)
        if close is not None:
            close()

    def execute(self, message: dict[str, Any], *, peer_uid: int) -> dict[str, Any]:
        try:
            if not self.active or peer_uid != self.config["vm_uid"]:
                raise PermissionError("inactive session or wrong transport principal")
            if not isinstance(message, dict) or set(message) != {"request", "capability"}:
                raise ValueError("invalid effect envelope")
            request = ActionRequest.from_dict(message["request"])
            if request.session_id != self.config["session_id"]:
                raise PermissionError("cross-session request")
            if (request.operation != "object.read"
                    or request.resource_id != self.config.get("resource_id", "synthetic-dataset")):
                raise PermissionError("unsupported effect")
            if set(request.arguments) != {"offset", "length"}:
                raise ValueError("invalid dataset range")
            offset, length = request.arguments["offset"], request.arguments["length"]
            if (type(offset) is not int or type(length) is not int
                    or not (0 <= offset < len(self.config["dataset"])
                            and 0 < length <= 512
                            and offset + length <= len(self.config["dataset"]))):
                raise ValueError("dataset range exceeds service ceiling")
            capability = IssuedCapability.from_dict(message["capability"])
        except (ValueError, TypeError, KeyError, PermissionError):
            result = ExecutionResult(
                False, "object.read", self.config.get("resource_id", "synthetic-dataset"),
                error="request denied", effect_state="not-started",
            )
            self.recorder.append("execution.denied", {
                "effect_state": "not-started", "source": "effect-boundary",
            })
            return asdict(result)
        context = self.config["verification_context"]
        decision = self.gateway.execute(
            request, capability, context["attestation"],
            executor_measurement=context["executor_measurement"],
            device_id=context["device_id"],
            verifier_policy_digest=context["verifier_policy_digest"],
            policy_digest=context["policy_digest"],
        )
        return asdict(ExecutionResult(
            decision.accepted, request.operation, request.resource_id,
            output=decision.output, output_bytes=decision.output_bytes,
            error=decision.error_class, effect_state=decision.effect_state,
        ))
