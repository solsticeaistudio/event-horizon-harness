"""Actual guest/gateway and owned Docker quorum faults, never simulated results."""
import copy
import json
import subprocess
import time

from event_horizon.authority_backends import EtcdGatewayConfig, EtcdV3TransactionTransport
from scripts.package_authority_oracle import _b64
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
        deadline=time.monotonic()+12
        while True:
            try:
                result=self.transport({'compare':[], 'success':[], 'failure':[]})
                if str(result['header']['cluster_id'])!=self.config['etcd_cluster_id']:
                    raise ValueError('cluster identity changed')
                return result['header']
            except Exception:
                if time.monotonic()>deadline: raise
                time.sleep(.1)

    def empty(self, session):
        prefix=f'/event-horizon/replay/v1/{session}/external-effect/'.encode()
        result=self.transport({'compare':[], 'success':[{'requestRange':{
            'key':_b64(prefix),'range_end':_b64(prefix[:-1]+bytes([prefix[-1]+1])),
            'serializable':False}}],'failure':[]})
        if str(result['header']['cluster_id'])!=self.config['etcd_cluster_id']:
            raise RuntimeError('oracle cluster mismatch')
        value=result['responses'][0]['response_range']
        if value.get('kvs') or int(value.get('count',0))!=0:
            raise RuntimeError('unexpected committed authority before dispatch')
        return {'record_count':0,'cluster_id':self.config['etcd_cluster_id'],
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
            self.deny('etcd_majority_loss',channel,message,receiver)
        finally:
            restored=self.quorum.restore()
        # Consumption may be indeterminate during the outage; do not call it
        # uncommitted until an independent linearizable read establishes zero.
        empty=self.quorum.empty(message['request']['session_id'])
        self.campaign[-1]['consumption_after_recovery']=empty
        self.recovery_header=restored
        self.quorum.pause([2])
        # The caller now sends its real valid guest request with two nodes live.

    def after_authorized(self,channel,message,receiver):
        if receiver.dispatches!=1:
            raise RuntimeError('single-node failure did not preserve exactly one useful dispatch')
        header=self.quorum.restore()
        self.deny('replay_after_quorum_recovery',channel,message,receiver)
        if receiver.dispatches!=1: raise RuntimeError('recovery resurrected consumed authority')
        return {'scenarios':self.campaign,'single_node_loss_useful_dispatches':1,
                'recovered_cluster_id':str(header['cluster_id']),
                'containers':self.quorum.identities,'dispatches':receiver.dispatches}

    def close(self):
        try:self.quorum.restore()
        finally:super().close()
