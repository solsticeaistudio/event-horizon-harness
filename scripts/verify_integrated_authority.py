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
    for field in ('authorization','spare_authorization','fault_authorization'):
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
    require(len({c.claims.capability_id for c in caps})==3,'capability identifiers duplicated')
    require(value['process_cleanup'] is True and value['temporary_paths_removed'] is True,
            'authority cleanup missing')
    expected=set(AUTHORITY_ATTACKS)|{'issuance_budget_exhausted','read_signer_config','read_signer_memory',
                                   'guardian_unavailable','signer_unavailable'}
    scenarios=value['scenarios']
    require(len(scenarios)==len(expected) and {x['name'] for x in scenarios}==expected,
            'authority negative controls missing or duplicated')
    audit=value['service_audit']['signer']
    require(sum(e.get('method')=='issue' and e.get('accepted') is True for e in audit)==3,
            'unexpected additional capability issuance')
    # Only primary, unused prior-session and retired fault tokens may be issued.
    for field in ('authorization','spare_authorization','fault_authorization'):
        record=value[field]
        require(any(e.get('message_digest')==digest(record['message']) and e.get('accepted') is True
                    and e.get('result_digest')==digest(record['answer']['result']) for e in audit),
                'issued capability lacks private signer observation')
    for test in scenarios:
        require(test['guest_invoked'] is False and test['effect_dispatches']==0,
                'pre-execution authority failure dispatched')
        if test['name'] in (*AUTHORITY_ATTACKS,'issuance_budget_exhausted'):
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


BASE_MODE = 'isolated-authority-firecracker-etcd'
BRIDGED_MODE = 'isolated-authority-firecracker-etcd-bridged'
RECIPIENT_MODE = 'isolated-authority-firecracker-etcd-bridged-recipient'


def verify_gateway_process_mode(report):
    """Mode-specific signed observations; never reinterpret host-only tests as KVM.

    Called *in addition* to all original v4 guardian, etcd, guest, receipt and
    teardown checks, not instead of any existing condition.
    """
    mode = report.get('experiment_mode')
    require(mode in (BASE_MODE, BRIDGED_MODE, RECIPIENT_MODE), 'wrong experiment mode')
    bridged = mode in (BRIDGED_MODE, RECIPIENT_MODE)
    recipient_mode = mode == RECIPIENT_MODE
    require(len(report['rounds']) == 3, 'integrated run must contain three rounds')
    for run in report['rounds']:
        observed = run['observations']
        marker = observed.get('gateway_process_bridge')
        if not bridged:
            require(marker is None and 'gateway_process_bridge' not in observed,
                    'baseline run cannot claim process bridge')
            require('external_recipient' not in observed,
                    'baseline run cannot claim external recipient')
            continue
        required_bridge_fields = {
            'gateway_pid', 'supervisor_pid', 'independent_process',
            'guest_vsock_request_path', 'recorder_resides_in_supervisor',
        }
        bound_identity = isinstance(marker, dict) and 'identity_binding' in marker
        require(isinstance(marker, dict) and set(marker) == (
            required_bridge_fields | ({'identity_binding'} if bound_identity else set())
        ), 'missing or malformed gateway process bridge evidence')
        if bound_identity:
            require(marker['identity_binding'] == 'pidfd-dispatch-v1',
                    'unrecognized process provenance contract')
            dispatch = [event for event in run['events']
                        if event['event_type'] == 'execution.dispatch']
            require(len(dispatch) == 1
                    and dispatch[0]['source_id'] == 'host-effect-service'
                    and dispatch[0]['payload'].get('gateway_pid') == marker['gateway_pid']
                    and dispatch[0]['payload'].get('dispatch_count') == 1,
                    'gateway PID is not bound to independently signed dispatch event')
        else:
            # Preserve verification for two published, immutable pre-hardening
            # reports; newly generated reports must carry the stronger binding.
            legacy = {
                '8be130eb584dfd90d514b754244e26b4434ccda3',
                'ea79595db5a659c6ae543c42e66618edfcd770ba',
            }
            require(report.get('source_commit') is None
                    or report['source_commit'] in legacy,
                    'new integrated KVM report missing process identity binding')
        gateway_pid, supervisor_pid = marker['gateway_pid'], marker['supervisor_pid']
        require(type(gateway_pid) is int and type(supervisor_pid) is int
                and gateway_pid > 1 and supervisor_pid > 1
                and gateway_pid != supervisor_pid,
                'gateway process is not distinct from supervisor')
        require(all(marker[field] is True for field in (
            'independent_process', 'guest_vsock_request_path',
            'recorder_resides_in_supervisor',
        )), 'gateway process or guest path claim missing')
        recipient = observed.get('external_recipient')
        if recipient_mode:
            require(isinstance(recipient, dict) and set(recipient) == {
                'count', 'rows_digest', 'recipient_pid', 'journal_state', 'request_digest',
            }, 'missing or malformed independent recipient observation')
            require(type(recipient['count']) is int and recipient['count'] == 1,
                    'KVM effect recipient did not durably commit exactly once')
            require(recipient['journal_state'] == 'possibly-committed',
                    'durable outcome journal did not reserve the effect')
            require(type(recipient['recipient_pid']) is int
                    and recipient['recipient_pid'] > 1
                    and recipient['recipient_pid'] not in (gateway_pid, supervisor_pid),
                    'recipient reused gateway/supervisor process')
            for key in ('rows_digest', 'request_digest'):
                value = recipient[key]
                require(isinstance(value, str) and len(value) == 64
                        and all(x in '0123456789abcdef' for x in value),
                        'malformed independent recipient digest')
        else:
            require('external_recipient' not in observed,
                    'baseline cannot claim unverified external recipient')
        authority = run['isolated_authority']
        role_pids = {role['pid'] for role in authority['roles'].values()}
        coordinator_pids = {row['pid'] for row in authority.get('coordinators', [])}
        require(gateway_pid not in role_pids | coordinator_pids
                and supervisor_pid not in role_pids | coordinator_pids,
                'gateway or supervisor shares guardian/coordinator process')
        if recipient_mode:
            require(recipient['recipient_pid'] not in role_pids | coordinator_pids,
                    'recipient shares guardian/coordinator process')
            session = SessionAuthority(authority['configuration'])
            require(recipient['request_digest'] == session.request.request_digest,
                    'recipient observation not bound to guardian request')


def verify_integrated(report):
    require(report['schema']=='event-horizon.package-isolation.v4','not integrated evidence')
    verify_gateway_process_mode(report)
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
        retired=loss['consumption_after_recovery']; fault=caps[2]
        require(retired['record_count'] in (0,1) and retired['token_retired_without_retry'] is True and
                retired['capability_id']==fault.claims.capability_id and
                retired['claims_digest']==digest(fault.claims.to_dict()),'uncertain token was not safely retired')
        extras=oracle['additional_consumed_ids']
        require(extras in ([],[fault.claims.capability_id]) and oracle['record_count']==1+len(extras)
                and oracle['primary_record_count']==1,'unexpected consumption beyond primary/fault tokens')
        if retired['record_count']==1:
            require(extras==[fault.claims.capability_id],'consumed fault token disappeared after recovery')
