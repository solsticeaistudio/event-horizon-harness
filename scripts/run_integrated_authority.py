#!/usr/bin/env python3
"""Opt-in actual KVM/package/isolated-authority experiment; no portable fallback."""
import argparse
import fcntl
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]
from event_horizon.canonical import canonical_bytes
from scripts.integrated_authority_session import IsolatedSession
from scripts.integrated_gateway_campaign import IntegratedPackageLab, BridgedIntegratedPackageLab, OwnedQuorum
from scripts.package_authority_oracle import owned_etcd_config
from scripts.run_linux_isolation import preflight, checked_assets, run_round
from scripts.run_package_isolation import build_worker
from scripts.verify_package_isolation import verify_report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',type=Path,default=ROOT/'firecracker/build/isolation')
    parser.add_argument('--bridged-gateway',action='store_true',help='Opt-in actual guest to child-gateway bridge')
    parser.add_argument('--etcd-endpoint',required=True)
    parser.add_argument('--etcd-cluster-id',required=True)
    parser.add_argument('--etcd-containers',nargs=3,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists() or Path(str(args.report)+'.sha256').exists():
        raise FileExistsError('never replace an existing experiment artifact')
    source=subprocess.check_output(['git','-c',f'safe.directory={ROOT}','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','-c',f'safe.directory={ROOT}','diff','HEAD','--name-only'],cwd=ROOT).strip():
        raise RuntimeError('commit implementation before running attributable hardware evidence')
    preflight()
    config={'authority_backend':'etcd','etcd_gateway':owned_etcd_config(args.etcd_endpoint,args.etcd_cluster_id),
            'etcd_cluster_id':args.etcd_cluster_id}
    # Inner authority RPC must expire before the existing guest/worker channel
    # deadline. A guest timeout is unknown, never evidence of successful denial.
    config['etcd_gateway']['timeout_seconds']=0.5
    quorum=OwnedQuorum(args.etcd_containers,config)
    lockfd=os.open('/run/event-horizon-isolation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    report={'schema':'event-horizon.package-isolation.v4','status':'INCOMPLETE',
            'experiment_mode':('isolated-authority-firecracker-etcd-bridged' if args.bridged_gateway
                               else 'isolated-authority-firecracker-etcd'),
            'source_commit':source,'rounds':[]}
    try:
        with os.fdopen(lockfd,'w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            assets=args.assets.resolve(); manifest=checked_assets(assets)
            if manifest.get('tpm2_enabled'):raise ValueError('this integrated run pins synthetic attestation only')
            binary=assets/'compromised-package';worker_build=build_worker(binary)
            previous=None
            for i,mode in enumerate(('vulnerable','protected','protected')):
                session=IsolatedSession(source_commit=source)
                try:
                    result,previous,attestation=run_round(assets,manifest,None,previous,
                        stop_mode='supervisor-channel-loss' if i==2 else 'requested',authority_session=session,
                        package_lab=(BridgedIntegratedPackageLab if args.bridged_gateway else IntegratedPackageLab)(
                            mode,binary,worker_build,authority_config=config,quorum=quorum))
                    if attestation!='synthetic-fixture':raise RuntimeError('attestation mode changed')
                    report['rounds'].append(result)
                finally:session.close()
            report.update(status='PASS',build_manifest=manifest,worker_build=worker_build,host_kernel=platform.release(),
                authority={'backend':'etcd','cluster_id':args.etcd_cluster_id,'oracle':'host-supervisor-linearizable-etcd-read'},
                attestation='synthetic-fixture',scope='owned deterministic integrated authority and paired effects',
                unknowns=['host/kernel compromise','hardware attestation','external witness','physical multi-host separation',
                          'arbitrary guest agents','rollback','interrupted effect after dispatch','concurrent tenant VMs'])
            verify_report(report)
    except BaseException as exc:
        report['status']='INCOMPLETE';report['failure_class']=type(exc).__name__
        raise
    finally:
        quorum.restore()
        args.report.parent.mkdir(parents=True,exist_ok=True)
        content=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode('utf-8')
        with args.report.open('xb') as output:output.write(content)
        checksum=hashlib.sha256(content).hexdigest()
        with Path(str(args.report)+'.sha256').open('x') as output:output.write(checksum+'  '+args.report.name+'\n')
        print('Original report:',args.report,'SHA256:',checksum,'status:',report['status'])
    print('PASS: integrated isolated authority, real KVM, real etcd and paired effects; embedded keys only')


if __name__=='__main__':main()
