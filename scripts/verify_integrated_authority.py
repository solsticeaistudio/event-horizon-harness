"""Additional v4 evidence checks; signatures prove internal integrity only."""
from event_horizon.broker import CapabilityVerifier
from event_horizon.canonical import digest
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.session_authority import SessionAuthority
from event_horizon.signed_guardian_authority import PinnedGuardianVerifier, SignedGuardianApproval
from scripts.capability_fixture_support import verify_options
from scripts.integrated_authority_session import AUTHORITY_ATTACKS, evidence_digest
from scripts.integrated_gateway_campaign import GATE_ATTACKS


def require(condition, message):
    if not condition: raise ValueError(message)


def verify_authority(value, *, require_os=True):
    session=SessionAuthority(value['configuration'])
    request=session.request
    pins=PinnedGuardianVerifier(value['guardian_public_keys'])
    require(pins.key_ids==value['guardian_key_ids'],'guardian fingerprints changed')
    require(set(value['roles'])==set(pins.key_ids)|{'signer'},'missing independent role')
    require(len({v['pid'] for v in value['roles'].values()})==5,'roles share a process')
    if require_os:
        require(value['os_isolation'] is True,'no OS authority isolation')
        require(len({v['uid'] for v in value['roles'].values()}|{value['coordinator_uid']})==6,
                'authority UIDs not distinct')
        require(all(v['separate_network_namespace'] is True for v in value['roles'].values()),
                'authority network was not isolated')
        require(value['wrong_uid'] in {'structured-denial','early-peer-disconnect'},'missing wrong UID control')
    caps=[]
    for field in ('authorization','spare_authorization'):
        record=value[field];message=record['message'];answer=record['answer']
        require(answer['ok'] is True and message['request']==request.canonical_payload(),
                'not the exact supervisor request')
        approvals=[SignedGuardianApproval(**a) for a in message['approvals']]
        pins.verify_all(request,message['challenge'],session.policy.policy_digest,approvals)
        cap=IssuedCapability.from_dict(answer['result']['capability'])
        CapabilityVerifier(value['signer_public_key'],value['signer_key_id']).verify_and_consume(
            cap,request,now=cap.claims.issued_at/1000,**verify_options(session.context))
        signed_state=digest([{'guardian':key,'signature':next(a.signature for a in approvals if a.payload['guardian']==key),
                             'payload':next(dict(a.payload) for a in approvals if a.payload['guardian']==key)}
                            for key in sorted(pins.key_ids)])
        require(cap.claims.guardian_state_digest==signed_state,'capability does not bind the four approvals')
        require(cap.claims.max_output_bytes==512,'output ceiling changed')
        if field=='authorization':
            require(value['capability_sha256']==digest(cap.to_dict()) and
                    value['request_digest']==request.request_digest and
                    value['policy_digest']==session.policy.policy_digest,'authority digest mismatch')
        caps.append(cap)
    require(caps[0].claims.capability_id!=caps[1].claims.capability_id,'spare capability duplicated')
    require(value['process_cleanup'] is True and value['temporary_paths_removed'] is True,
            'authority cleanup missing')
    expected=set(AUTHORITY_ATTACKS)|{'read_signer_config','read_signer_memory',
                                   'guardian_unavailable','signer_unavailable'}
    scenarios=value['scenarios']
    require(len(scenarios)==len(expected) and {x['name'] for x in scenarios}==expected,
            'authority negative controls missing or duplicated')
    audit=value['service_audit']['signer']
    # Exactly two trusted signer success records may contain a capability.
    for field in ('authorization','spare_authorization'):
        record=value[field]
        require(any(e.get('message_digest')==digest(record['message']) and e.get('accepted') is True
                    and e.get('result_digest')==digest(record['answer']['result']) for e in audit),
                'issued capability lacks private signer observation')
    for test in scenarios:
        require(test['guest_invoked'] is False and test['effect_dispatches']==0,
                'pre-execution authority failure dispatched')
        if test['name'] in AUTHORITY_ATTACKS:
            require(test['outcome']=='denied','authority attack not denied')
            final=test['transcript'][-1]
            require(final['answer']=={'ok':False,'result':{'error':'denied'}},'unexpected issuance')
            require(any(e.get('message_digest')==digest(final['message']) and e.get('accepted') is False for e in audit),
                    'coordinator denial not witnessed by signer')
        elif test['name'].endswith('_unavailable'):
            require(test['outcome']=='unavailable-no-issuance' and test['resumed_healthy'] is True,
                    'outage or recovery not established')
        elif require_os: require(test['outcome']=='denied','protected signer access not denied')
    return session,caps


def verify_integrated(report):
    require(report['schema']=='event-horizon.package-isolation.v4','not integrated evidence')
    require(report['experiment_mode']=='isolated-authority-firecracker-etcd','wrong experiment mode')
    require(report['attestation']=='synthetic-fixture' and report['build_manifest']['tpm2_enabled'] is False,
            'synthetic run misrepresents attestation')
    for run in report['rounds']:
        observations=run['observations'];value=run['isolated_authority']
        require(observations['isolated_authority_digest']==evidence_digest(value),
                'authority attachment differs from signed observation')
        context=next(e['payload'] for e in run['events'] if e['event_type']=='isolation.context')
        original={k:v for k,v in value.items() if k not in {
            'service_audit','process_cleanup','temporary_paths_removed'}}
        require(context['isolated_authority_digest']==evidence_digest(original),
                'execution context was not bound to pre-execution authority')
        session,caps=verify_authority(value)
        require(value['configuration']['source_commit']==report['source_commit'],'source revision mismatch')
        require(value['configuration']['build_artifacts']==report['build_manifest']['artifacts'],
                'authority measured a different build')
        oracle=observations['authority_oracle'];cap=caps[0]
        require(oracle['capability_id']==cap.claims.capability_id and
                oracle['claims_digest']==digest(cap.claims.to_dict()),'etcd consumed another capability')
        require(observations['unredeemed_capability_at_teardown']==caps[1].claims.capability_id,
                'prior-session spare was not isolated-signer authority')
        authorized=[e for e in run['events'] if e['event_type']=='execution.authorized']
        require(len(authorized)==1 and authorized[0]['payload']['request_digest']==session.request.request_digest,
                'gateway did not execute independently authorized request')
        gateway=observations['integrated_gateway']
        require(gateway['dispatches']==gateway['single_node_loss_useful_dispatches']==1,
                'missing useful operation under majority')
        require(gateway['recovered_cluster_id']==report['authority']['cluster_id'],'cluster changed during faults')
        require(len(gateway['member_headers'])==3 and
                len({str(h['member_id']) for h in gateway['member_headers']})==3 and
                all(str(h['cluster_id'])==report['authority']['cluster_id'] for h in gateway['member_headers']),
                'three independent member observations missing')
        dispatch=[e for e in run['events'] if e['event_type']=='execution.dispatch']
        require(len(dispatch)==1 and dispatch[0]['source_id']=='host-effect-service' and
                dispatch[0]['payload']['request_digest']==session.request.request_digest,
                'actual handler dispatch does not match authorized request')
        cases=gateway['scenarios']
        require(len(cases)==len(GATE_ATTACKS) and {c['name'] for c in cases}==set(GATE_ATTACKS),
                'missing actual guest fault controls')
        starts=[(i,e) for i,e in enumerate(run['events']) if e['event_type']=='integrated.attack']
        ends=[(i,e) for i,e in enumerate(run['events']) if e['event_type']=='integrated.result']
        require(len(starts)==len(ends)==len(cases),'missing primary gate attack observations')
        for case,(before,start),(after,end) in zip(cases,starts,ends,strict=True):
            require(case['outcome']=='denied' and case['guest_invoked'] is True and
                    case['effect_state']=='not-started' and case['dispatch_before']==case['dispatch_after'],
                    'effect outcome incomplete or contradictory')
            require(start['payload']['name']==case['name'] and
                    all(case.get(k)==v for k,v in end['payload'].items()),'gate summary changed')
            between=run['events'][before+1:after]
            require(sum(e['event_type']=='execution.denied' for e in between)==1 and
                    not any(e['event_type'] in {'execution.dispatch','execution.completed','execution.indeterminate'} for e in between),
                    'negative test lacks primary no-dispatch evidence')
        loss=next(c for c in cases if c['name']=='etcd_majority_loss')
        require(loss['consumption_after_recovery']['record_count']==0,'quorum loss consumed authority unexpectedly')
