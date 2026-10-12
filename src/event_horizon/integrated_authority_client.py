"""Deliberately untrusted coordinator subprocess for the owned integration lab."""
import copy
import json
import os
import sys
import time

from .isolated_authority_lab import rpc


def run(config):
    transcript = []

    def call(path, message):
        answer = rpc(path, message)
        transcript.append(copy.deepcopy({"path": path, "message": message, "answer": answer}))
        return answer

    scenario = config["scenario"]
    request = copy.deepcopy(config["request"])
    signer = config["signer"]
    if scenario in {"read_signer_config", "read_signer_memory"}:
        path = config["pins"] if scenario.endswith("config") else f"/proc/{config['signer_pid']}/mem"
        try:
            with open(path, "rb") as source:
                source.read(1)
        except PermissionError:
            return {"os_denied": True, "transcript": []}
        return {"os_denied": False, "transcript": []}
    if scenario == "reuse_challenge":
        call(signer, config["previous_issue"])
        return {"transcript": transcript}
    if scenario == "bypass_signer":
        call(signer, {"method": "broker.issue", "request": request})
        return {"transcript": transcript}
    if scenario in {"guardian_veto", "network_operation", "executor_substitution"}:
        if scenario == "guardian_veto": request["arguments"]["length"] += 1
        if scenario == "network_operation": request["operation"] = "network.connect"
        if scenario == "executor_substitution": request["executor_id"] = "wrong-executor"
    challenge = call(signer, {"method": "challenge", "request": request})["result"]["challenge"]
    approvals = []
    for path in config["guardians"].values():
        approvals.append(call(path, {"method": "evaluate", "request": request,
                                     "challenge": challenge})["result"])
    if scenario == "healthy_probe":
        return {"transcript": transcript}
    if scenario == "forged_signature": approvals[0]["signature"] = "A" * 86
    elif scenario == "missing_guardian": approvals.pop()
    elif scenario == "duplicate_guardian": approvals[1] = copy.deepcopy(approvals[0])
    elif scenario == "modified_approval": approvals[0]["payload"]["reason"] = "coordinator modified"
    elif scenario == "swapped_approval": approvals[0] = config["previous_issue"]["approvals"][0]
    elif scenario == "policy_substitution": approvals[0]["payload"]["policy_digest"] = "0" * 64
    elif scenario == "attestation_substitution":
        for approval in approvals:
            if "attestation_result" in approval["payload"]["evidence"]:
                approval["payload"]["evidence"]["measurement"] = "0" * 64
    elif scenario == "different_request": request["request_id"] = "changed-request"
    elif scenario == "changed_resource": request["resource_id"] = "forbidden-resource"
    elif scenario == "expanded_arguments": request["arguments"]["command"] = "forbidden"
    elif scenario == "expired_challenge": time.sleep(2.1)
    message = {"method": "issue", "request": request, "challenge": challenge, "approvals": approvals}
    if scenario == "expanded_ceiling": message["max_output_bytes"] = 65536
    if scenario == "expanded_budget": message["compiled_ceiling"] = {"maximum_calls": 100}
    if scenario == "signer_key_substitution": message["public_key"] = "coordinator pin"
    call(signer, message)
    return {"transcript": transcript}


def main():
    print(json.dumps({"type":"coordinator-ready","pid":os.getpid(),"uid":os.geteuid()}),flush=True)
    config = json.loads(sys.stdin.buffer.read(65536))
    try:
        result = run(config)
    except (OSError, EOFError) as exc:
        result = {"unavailable": type(exc).__name__}
    print(json.dumps({"pid": os.getpid(), "uid": os.geteuid(), "result": result}), flush=True)


if __name__ == "__main__":
    main()
