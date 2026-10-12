"""Portable contract and actual AF_UNIX process tests; never claim KVM coverage."""
import copy
import unittest
from unittest.mock import patch
from event_horizon.component_ids import REQUIRED_GUARDIANS, EXECUTOR_ATTESTATION_GUARDIAN
from event_horizon.models import ActionRequest
from event_horizon.session_authority import SessionAuthority
from scripts.integrated_authority_session import IsolatedSession
from scripts.verify_integrated_authority import verify_authority


def request():
    return ActionRequest('dataset-read','ehk-testsession','attacker-agent','object.read',
                         'pinned-package','exec-1',{'offset':0,'length':74},'read approved inert bytes')


class IntegratedAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        authority=IsolatedSession(distinct_uids=False,source_commit='e13160b55af2b4c3eda93b8e8a10b0026573c80f')
        try:
            authority.authorize_pair(request(),{'artifacts':{'kernel':'1'*64}})
        finally: authority.close()
        cls.evidence=authority.evidence

    def test_real_process_campaign_and_verifier(self):
        verify_authority(self.evidence,require_os=False)
        self.assertEqual(len(self.evidence['scenarios']),22)
        self.assertEqual(len({x['pid'] for x in self.evidence['roles'].values()}),5)

    def test_portable_processes_cannot_claim_os_isolation(self):
        with self.assertRaises(ValueError):verify_authority(self.evidence)

    def test_tampered_approval_capability_and_pins_fail(self):
        for part in ('signature','capability','pins'):
            changed=copy.deepcopy(self.evidence)
            if part=='signature': changed['authorization']['message']['approvals'][0]['signature']='A'*86
            elif part=='capability': changed['authorization']['answer']['result']['capability']['signature']='A'*86
            else:
                keys=list(changed['guardian_public_keys'])
                changed['guardian_public_keys'][keys[0]]=changed['guardian_public_keys'][keys[1]]
            with self.subTest(part=part),self.assertRaises((ValueError,PermissionError)):
                verify_authority(changed,require_os=False)

    def test_missing_negative_and_unobserved_denial_rejected(self):
        for mutation in ('missing','contradictory','audit','cleanup'):
            changed=copy.deepcopy(self.evidence)
            if mutation=='missing':changed['scenarios'].pop()
            elif mutation=='contradictory':changed['scenarios'][0]['effect_dispatches']=1
            elif mutation=='audit':changed['service_audit']['signer']=[]
            else:changed['process_cleanup']=False
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                verify_authority(changed,require_os=False)

    def test_each_guardian_evaluates_actual_session(self):
        session=SessionAuthority(self.evidence['configuration'])
        for role in REQUIRED_GUARDIANS:self.assertTrue(session.evaluate(role,request()).allowed)
        altered=request().canonical_payload();altered['executor_id']='wrong'
        self.assertFalse(session.evaluate(EXECUTOR_ATTESTATION_GUARDIAN,ActionRequest.from_dict(altered)).allowed)
        self.assertEqual(session.context['trust_state'].effective_trust,'simulated')

    def test_coordinator_cannot_install_new_ceiling_or_policy(self):
        bad=copy.deepcopy(self.evidence['configuration']);bad['max_output_bytes']=99999
        with self.assertRaises(ValueError):SessionAuthority(bad)

    def test_no_local_broker_fallback_at_integrated_round(self):
        from pathlib import Path
        from scripts.run_linux_isolation import run_round
        # Fail before cgroup, VM, gateway or issuance work on an incompatible path.
        with self.assertRaises(ValueError):
            run_round(Path('/unused'),{},object(),None,authority_session=object())
