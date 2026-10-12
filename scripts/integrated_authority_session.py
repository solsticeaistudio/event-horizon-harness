"""Trusted supervisor for session-bound, separately owned authority processes.

Reuses the original lab RPC/services and signed approval contract. Coordinator
claims are checked against private service audit pipes and pinned signatures.
The supervisor retains public keys only; each service generates its own key.
"""
from __future__ import annotations

import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from event_horizon.broker import CapabilityVerifier
from event_horizon.canonical import canonical_bytes, digest
from event_horizon.component_ids import REQUIRED_GUARDIANS
from event_horizon.isolated_authority_lab import rpc, wrong_uid_probe, confirm_wrong_uid_rejection
from event_horizon.models import IssuedCapability
from event_horizon.session_authority import SessionAuthority
from event_horizon.signed_guardian_authority import PinnedGuardianVerifier, SignedGuardianApproval
from scripts.capability_fixture_support import verify_options
from scripts.run_isolated_authority_lab import _bind, _ready, UIDS

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_ATTACKS = (
    "forged_signature", "missing_guardian", "duplicate_guardian", "modified_approval",
    "swapped_approval", "guardian_veto", "expired_challenge", "reuse_challenge",
    "different_request", "changed_resource", "expanded_arguments", "expanded_ceiling",
    "network_operation", "executor_substitution", "attestation_substitution",
    "policy_substitution", "bypass_signer", "signer_key_substitution",
)


def evidence_digest(value):
    """Hash aggregate evidence without weakening bounded RPC canonicalization."""
    import hashlib
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


class IsolatedSession:
    def __init__(self, *, distinct_uids=True, source_commit):
        self.distinct = distinct_uids
        self.source_commit = source_commit
        self.services = {}
        self.sockets = []
        self.threads = []
        self.audit = {}
        self.evidence = {}
        self.temp = None
        self.paths = {}

    def _spawn(self, module, args, uid, *, fds=(), stdin=subprocess.DEVNULL):
        command = [sys.executable, "-u", "-m", module, *args]
        if self.distinct:
            # Network namespace removes access to host loopback etcd (which has
            # no production credential). Privilege drop happens before Python.
            command = ["unshare", "--net", "--", "setpriv", f"--reuid={uid}",
                       f"--regid={uid}", "--clear-groups", "--bounding-set=-all",
                       "--no-new-privs", "--", *command]
        return subprocess.Popen(command, cwd=self.stage, env=self.env, pass_fds=fds,
                                stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _service(self, role, args):
        listener = _bind(self.base / 'sockets' / (role + '.sock'))
        self.sockets.append(listener)
        proc = self._spawn('event_horizon.isolated_authority_lab', [
            *args, '--listener-fd', str(listener.fileno()),
            '--coordinator-uid', str(self.coordinator_uid),
            '--reference-time', str(self.config['reference_time']),
            '--session-config', str(self.config_paths[role]),
        ], UIDS[role], fds=(listener.fileno(),))
        self.services[role] = proc
        hello = _ready(proc, 'signer-ready' if role == 'signer' else 'guardian-ready')
        expected_uid = UIDS[role] if self.distinct else os.geteuid()
        status = Path(f'/proc/{proc.pid}/status').read_text()
        if hello['uid'] != expected_uid or f'Uid:\t{expected_uid}\t' not in status:
            raise RuntimeError('kernel role identity mismatch')
        network_separate = os.readlink(f'/proc/{proc.pid}/ns/net') != os.readlink('/proc/self/ns/net') if self.distinct else False
        if self.distinct and not network_separate:
            raise RuntimeError('authority service can reach host authority network')
        self.evidence['roles'][role] = {'pid': proc.pid, 'uid': hello['uid'],
                                      'separate_network_namespace': network_separate}
        self.audit[role] = []
        def drain():
            for line in proc.stdout:
                self.audit[role].append(json.loads(line))
        thread = threading.Thread(target=drain, daemon=True)
        thread.start(); self.threads.append(thread)
        return hello

    def prepare(self, request, manifest):
        if self.distinct and os.geteuid() != 0:
            raise PermissionError('distinct authority identities require root')
        if self.distinct:
            for uid in UIDS.values():
                try: pwd.getpwuid(uid)
                except KeyError: continue
                raise PermissionError('reserved authority UID is allocated')
        self.temp = tempfile.TemporaryDirectory(prefix='ehh-integrated-authority-', dir='/var/tmp')
        self.base = Path(self.temp.name); self.base.chmod(0o755)
        self.stage = self.base/'stage'; (self.stage/'src').mkdir(parents=True)
        shutil.copytree(ROOT/'src/event_horizon', self.stage/'src/event_horizon',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pem', '*.key', '.env*'))
        (self.stage/'scripts').mkdir()
        shutil.copy2(ROOT/'scripts/capability_fixture_support.py', self.stage/'scripts/capability_fixture_support.py')
        for path in self.stage.rglob('*'): path.chmod(0o755 if path.is_dir() else 0o644)
        (self.base/'sockets').mkdir(mode=0o755); (self.base/'trusted').mkdir(mode=0o711)
        self.env = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'PYTHONPATH':f'{self.stage}/src:{self.stage}',
                    'PYTHONDONTWRITEBYTECODE':'1', 'LANG':'C.UTF-8'}
        self.coordinator_uid = UIDS['coordinator'] if self.distinct else os.geteuid()
        self.config = {'request':request.canonical_payload(), 'reference_time':time.time(),
                       'build_artifacts':manifest['artifacts'], 'source_commit':self.source_commit}
        self.session = SessionAuthority(self.config)
        self.evidence = {'configuration':self.config, 'roles':{}, 'coordinator_uid':self.coordinator_uid,
                         'os_isolation':self.distinct, 'guardian_public_keys':{}, 'scenarios':[]}
        self.config_paths = {}
        for role in [*sorted(REQUIRED_GUARDIANS), 'signer']:
            path = self.base/'trusted'/(role+'.json'); path.write_bytes(canonical_bytes(self.config))
            path.chmod(0o400)
            if self.distinct: os.chown(path, UIDS[role], UIDS[role])
            self.config_paths[role]=path
        for identity in sorted(REQUIRED_GUARDIANS):
            hello = self._service(identity, ['--role','guardian','--guardian',identity])
            self.paths[identity] = str(self.base/'sockets'/(identity+'.sock'))
            self.evidence['guardian_public_keys'][identity] = hello['public_key']
        self.pins = self.base/'trusted'/'signer-pins.json'
        self.pins.write_bytes(canonical_bytes({'public_keys':self.evidence['guardian_public_keys'],
                                              'reference_time':self.config['reference_time']}))
        self.pins.chmod(0o400)
        if self.distinct: os.chown(self.pins, UIDS['signer'], UIDS['signer'])
        hello = self._service('signer',['--role','signer','--pins-path',str(self.pins)])
        self.signer_path = str(self.base/'sockets/signer.sock')
        self.public_key_pem, self.key_id = hello['public_key'], hello['key_id']
        self.evidence.update(signer_public_key=self.public_key_pem, signer_key_id=self.key_id,
                             guardian_key_ids=PinnedGuardianVerifier(self.evidence['guardian_public_keys']).key_ids)
        return self

    def client(self, scenario, previous=None):
        configuration = {'scenario':scenario,'request':self.config['request'],
                         'guardians':self.paths,'signer':self.signer_path,'pins':str(self.pins),
                         'signer_pid':self.services['signer'].pid,'previous_issue':previous}
        proc=self._spawn('event_horizon.integrated_authority_client',[],self.coordinator_uid,
                         stdin=subprocess.PIPE)
        hello = _ready(proc, 'coordinator-ready')
        status = Path(f'/proc/{proc.pid}/status').read_text()
        if hello['uid'] != self.coordinator_uid or f'Uid:\t{self.coordinator_uid}\t' not in status:
            proc.kill(); proc.wait(); raise RuntimeError('coordinator kernel identity mismatch')
        network_separate = (os.readlink(f'/proc/{proc.pid}/ns/net') != os.readlink('/proc/self/ns/net')
                            if self.distinct else False)
        if self.distinct and not network_separate:
            proc.kill(); proc.wait(); raise RuntimeError('coordinator can reach host loopback authority')
        self.evidence.setdefault('coordinators', []).append({
            'pid':proc.pid,'uid':hello['uid'],'separate_network_namespace':network_separate,
            'scenario':scenario})
        try: output,error=proc.communicate(canonical_bytes(configuration),timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill();proc.communicate();raise RuntimeError('coordinator timed out; outcome unknown')
        if proc.returncode: raise RuntimeError('coordinator failed: '+error.decode()[-500:])
        value=json.loads(output)
        if value['uid']!=self.coordinator_uid or value['pid']!=proc.pid:
            raise RuntimeError('coordinator identity mismatch')
        return value['result']

    def _check_transcript(self, result):
        if 'unavailable' in result: raise RuntimeError('unexpected authority outage')
        for record in result['transcript']:
            if record['path']==self.signer_path:
                expected={'audit':'signer','message_digest':digest(record['message']),
                          'accepted':record['answer']['ok']}
                deadline=time.monotonic()+1
                while not any(all(entry.get(k)==v for k,v in expected.items()) for entry in self.audit['signer']):
                    if time.monotonic()>deadline: raise RuntimeError('coordinator claim lacks private signer observation')
                    time.sleep(.005)
            else:
                role=next(k for k,v in self.paths.items() if v==record['path'])
                if {'audit':'guardian','approval':record['answer']['result']} not in self.audit[role]:
                    raise RuntimeError('approval differs from private guardian observation')

    def authorize_pair(self, request, manifest):
        self.prepare(request,manifest)
        peer=None
        if self.distinct:
            peer=wrong_uid_probe(lambda:rpc(self.signer_path,{'method':'challenge','request':self.config['request']}))
        valid=self.client('legitimate');self._check_transcript(valid)
        issue=valid['transcript'][-1];cap=IssuedCapability.from_dict(issue['answer']['result']['capability'])
        if self.distinct:
            confirm_wrong_uid_rejection(peer,alive=self.services['signer'].poll() is None,
                                        authorized_succeeded=issue['answer']['ok'] is True)
        self.evidence['wrong_uid'] = peer
        approvals=[SignedGuardianApproval(**a) for a in issue['message']['approvals']]
        PinnedGuardianVerifier(self.evidence['guardian_public_keys']).verify_all(
            request,issue['message']['challenge'],self.session.policy.policy_digest,approvals)
        CapabilityVerifier(self.public_key_pem,self.key_id).verify_and_consume(
            cap,request,**verify_options(self.session.context))
        self.evidence['authorization']=issue
        self.evidence['capability_sha256']=digest(cap.to_dict())
        self.evidence['request_digest']=request.request_digest
        self.evidence['policy_digest']=self.session.policy.policy_digest
        for name in AUTHORITY_ATTACKS:
            result=self.client(name,issue['message']);self._check_transcript(result)
            if result['transcript'][-1]['answer']['ok'] is not False:
                raise RuntimeError('unauthorized issuance: '+name)
            self.evidence['scenarios'].append({'name':name,'outcome':'denied','guest_invoked':False,
                                               'effect_dispatches':0,'transcript':result['transcript']})
        for name in ['read_signer_config','read_signer_memory']:
            result=self.client(name)
            if self.distinct and result.get('os_denied') is not True:
                raise RuntimeError('coordinator read protected signer material')
            self.evidence['scenarios'].append({'name':name,'outcome':'denied' if self.distinct else 'NOT_ASSESSED',
                                               'guest_invoked':False,'effect_dispatches':0})
        for name, role in [('guardian_unavailable', sorted(REQUIRED_GUARDIANS)[0]),
                           ('signer_unavailable', 'signer')]:
            proc = self.services[role]
            os.kill(proc.pid, signal.SIGSTOP)
            try:
                result = self.client('healthy_probe')
                if result != {'unavailable': 'TimeoutError'}:
                    raise RuntimeError('injected authority outage did not fail closed')
            finally:
                os.kill(proc.pid, signal.SIGCONT)
            healthy = self.client('healthy_probe'); self._check_transcript(healthy)
            if any(p.poll() is not None for p in self.services.values()):
                raise RuntimeError('authority process crashed during outage')
            self.evidence['scenarios'].append({'name':name,'outcome':'unavailable-no-issuance',
                'guest_invoked':False,'effect_dispatches':0,'resumed_healthy':True})
        spare_result=self.client('legitimate');self._check_transcript(spare_result)
        spare=IssuedCapability.from_dict(spare_result['transcript'][-1]['answer']['result']['capability'])
        self.evidence['spare_authorization']=spare_result['transcript'][-1]
        return cap,spare,self.session.context

    def close(self):
        if getattr(self, '_closed', False): return
        self._closed = True
        for proc in self.services.values():
            if proc.poll() is None: proc.terminate()
        for proc in self.services.values():
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=2)
        for thread in self.threads: thread.join(timeout=2)
        for proc in self.services.values():
            proc.stdout.close(); proc.stderr.close()
        for sock in self.sockets: sock.close()
        self.evidence['service_audit']=self.audit
        self.evidence['process_cleanup']=all(p.poll() is not None for p in self.services.values())
        if self.temp:
            self.temp.cleanup()
            self.evidence['temporary_paths_removed']=not self.base.exists()
