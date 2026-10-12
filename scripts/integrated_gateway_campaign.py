"""Actual guest/gateway and owned Docker quorum faults, never simulated results."""
import copy
import json
import threading
import subprocess
import time

from event_horizon.authority_backends import EtcdGatewayConfig, EtcdV3TransactionTransport
from scripts.package_authority_oracle import _b64, inspect_committed_consumption
from event_horizon.canonical import digest, strict_json_loads
import base64
from scripts.run_linux_isolation import guest_effect
from scripts.run_package_isolation import PackageLab


class OwnedQuorum:
    def __init__(self, containers, config):
        if len(containers) != 3 or len(set(containers)) != 3:
            raise ValueError('exactly three owned containers required')
        self.containers = containers
        self.config = config
        self.paused = set()
        records = json.loads(subprocess.check_output(['docker','inspect',*containers]))
        networks = []
        for row in records:
            name = row['Name'].lstrip('/')
            if not name.startswith('ehh-owned-pkg-') or not row['State']['Running']:
                raise ValueError('refusing fault injection on non-lab container')
            networks.append(set(row['NetworkSettings']['Networks']))
        common = set.intersection(*networks)
        if len(common) != 1 or not next(iter(common)).startswith('ehh-owned-pkg-'):
            raise ValueError('not a single disposable EHH quorum')
        self.identities = [{'container_id':r['Id'],'name':r['Name'],
                            'image_id':r['Image'],'image':r['Config']['Image']} for r in records]
        self.transport=EtcdV3TransactionTransport(EtcdGatewayConfig(**config['etcd_gateway']))
        self.member_headers=[]
        for port in (2379,3379,4379):
            transport=EtcdV3TransactionTransport(EtcdGatewayConfig(
                **(config['etcd_gateway']|{'endpoint':f'http://127.0.0.1:{port}'})))
            header=transport({'compare':[],'success':[{'requestRange':{'key':_b64(b'/event-horizon/lab/health'), 'serializable':False}}],'failure':[]})['header']
            if str(header['cluster_id'])!=config['etcd_cluster_id']:
                raise RuntimeError('member belongs to a different cluster')
            self.member_headers.append(header)
        if len({str(h['member_id']) for h in self.member_headers})!=3:
            raise RuntimeError('three endpoints are not distinct etcd members')

    def pause(self, indices):
        for i in indices:
            subprocess.run(['docker','pause',self.containers[i]],check=True,stdout=subprocess.DEVNULL)
            self.paused.add(i)
        rows=json.loads(subprocess.check_output(['docker','inspect',*[self.containers[i] for i in indices]]))
        if not all(r['State']['Paused'] for r in rows): raise RuntimeError('fault not actually applied')

    def restore(self):
        for i in list(self.paused):
            subprocess.run(['docker','unpause',self.containers[i]],check=True,stdout=subprocess.DEVNULL)
            self.paused.remove(i)
        return self.wait_healthy()

    def wait_healthy(self):
        deadline=time.monotonic()+12
        while True:
            try:
                result=self.transport({'compare':[], 'success':[{'requestRange':{
                    'key':_b64(b'/event-horizon/lab/health'),'serializable':False}}], 'failure':[]})
                if str(result['header']['cluster_id'])!=self.config['etcd_cluster_id']:
                    raise ValueError('cluster identity changed')
                return result['header']
            except Exception:
                if time.monotonic()>deadline: raise
                time.sleep(.1)

    def retired_consumption(self, session, fault):
        prefix=f'/event-horizon/replay/v1/{session}/external-effect/'.encode()
        result=self.transport({'compare':[], 'success':[{'requestRange':{
            'key':_b64(prefix),'range_end':_b64(prefix[:-1]+bytes([prefix[-1]+1])),
            'serializable':False}}],'failure':[]})
        if str(result['header']['cluster_id'])!=self.config['etcd_cluster_id']:
            raise RuntimeError('oracle cluster mismatch')
        value=result['responses'][0]['response_range']
        rows=value.get('kvs', [])
        if len(rows)>1 or int(value.get('count',0))!=len(rows):
            raise RuntimeError('unexpected pre-dispatch authority records')
        if rows:
            if base64.b64decode(rows[0]['key'])!=prefix+fault.claims.capability_id.encode():
                raise RuntimeError('wrong capability consumed during outage')
            record=strict_json_loads(base64.b64decode(rows[0]['value']))
            if (record['claims_digest']!=digest(fault.claims.to_dict()) or
                    record['expires_at']!=fault.claims.expires_at):
                raise RuntimeError('fault consumption binding changed')
        return {'record_count':len(rows),'capability_id':fault.claims.capability_id,
                'claims_digest':digest(fault.claims.to_dict()),'token_retired_without_retry':True,'cluster_id':self.config['etcd_cluster_id'],
                'revision':int(result['header']['revision']),'raft_term':int(result['header']['raft_term'])}


GATE_ATTACKS=('gateway_resource_substitution','gateway_executor_substitution',
              'gateway_ceiling_expansion','gateway_signer_key_substitution','etcd_majority_loss',
              'replay_after_quorum_recovery')


class IntegratedPackageLab(PackageLab):
    def __init__(self,*args,quorum,**kwargs):
        super().__init__(*args,**kwargs)
        self.quorum=quorum
        self.campaign=[]

    def prepare(self,run,control,state,config):
        super().prepare(run,control,state,config)
        config['observe_integrated_dispatch']=True

    def deny(self,name,channel,message,receiver):
        before=receiver.dispatches
        receiver.receipts.append(receiver.recorder.append('integrated.attack',
            {'name':name,'dispatch_before':before},source_id='host-supervisor')['receipt'])
        response=guest_effect(channel,message)
        if response['success'] is not False or response['effect_state']!='not-started':
            raise RuntimeError('guest attempt was not a conclusive gate denial: '+name)
        if receiver.dispatches!=before:
            raise RuntimeError('effect dispatched despite denial: '+name)
        result={'name':name,'outcome':'denied','guest_invoked':True,
                'effect_state':'not-started','dispatch_before':before,'dispatch_after':receiver.dispatches}
        self.campaign.append(result)
        receiver.receipts.append(receiver.recorder.append('integrated.result',result,
                                                         source_id='host-supervisor')['receipt'])

    def before_authorized(self,channel,message,receiver):
        for name in GATE_ATTACKS[:4]:
            attempt=copy.deepcopy(message)
            if name=='gateway_resource_substitution': attempt['request']['resource_id']='forbidden'
            elif name=='gateway_executor_substitution': attempt['request']['executor_id']='wrong'
            elif name=='gateway_ceiling_expansion': attempt['capability']['claims']['max_output_bytes']=999999
            else: attempt['public_key_pem']='coordinator-selected pin'
            self.deny(name,channel,attempt,receiver)
        self.quorum.pause([1,2])
        try:
            attempt=copy.deepcopy(message)
            attempt['capability']=self.fault_capability.to_dict()
            self.deny('etcd_majority_loss',channel,attempt,receiver)
        finally:
            restored=self.quorum.restore()
        # A timed-out consensus operation can commit later. Retire that token;
        # never retry it or equate unknown consumption with an external effect.
        empty=self.quorum.retired_consumption(message['request']['session_id'], self.fault_capability)
        self.campaign[-1]['consumption_after_recovery']=empty
        self.recovery_header=restored
        self.quorum.pause([2])
        self.quorum.wait_healthy()
        # The caller now sends its real valid guest request with two nodes live.

    def after_authorized(self,channel,message,receiver):
        if receiver.dispatches!=1:
            raise RuntimeError('single-node failure did not preserve exactly one useful dispatch')
        header=self.quorum.restore()
        self.deny('replay_after_quorum_recovery',channel,message,receiver)
        if receiver.dispatches!=1: raise RuntimeError('recovery resurrected consumed authority')
        return {'scenarios':self.campaign,'single_node_loss_useful_dispatches':1,
                'recovered_cluster_id':str(header['cluster_id']),
                'containers':self.quorum.identities,'member_headers':self.quorum.member_headers,
                'dispatches':receiver.dispatches}

    def observe_authority(self, config, capability):
        fault=self.fault_capability
        return inspect_committed_consumption(self.quorum.transport,
            cluster_id=config['etcd_cluster_id'], session_id=config['session_id'],
            capability_id=capability.claims.capability_id,
            claims_digest=digest(capability.claims.to_dict()), expires_at=capability.claims.expires_at,
            extra_bindings={fault.claims.capability_id:(digest(fault.claims.to_dict()), fault.claims.expires_at)})

    def close(self):
        try:self.quorum.restore()
        finally:super().close()


class BridgedIntegratedPackageLab(IntegratedPackageLab):
    """Opt-in lab using the real Firecracker guest and an out-of-process gate."""

    bridged_gateway = True

    def receiver(self, observer, recorder, config):
        from scripts.integrated_gateway_process_bridge import BridgedGateReceiver
        self.target_thread = threading.Thread(target=self.target_loop, daemon=True)
        self.gate_receiver = BridgedGateReceiver(
            observer, recorder, config, self.target_thread,
        )
        return self.gate_receiver
