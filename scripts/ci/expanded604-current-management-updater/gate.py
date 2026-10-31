#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact Root604 prerequisites and immutable carriers, before secrets or actors."""
import argparse
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import contract as C


def own_source(root,revision):
    C.need(C.revision(root)==revision,'implementation revision differs')
    manifest=C.HERE/'source-manifest.json';value=C.read(manifest)
    C.need(value.get('status')=='FROZEN_ROOT_FINAL_SOURCE' and 1<=len(value.get('files',{}))<=512,
         'Root final604 updater source remains UNBOUND')
    for name,row in value['files'].items():C.checked(root,dict(path=name,**row))
    subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',*value['files'],str(manifest.relative_to(root))],
         check=True,capture_output=True,timeout=15)


def installer(root,policy):
    C.need(C.revision(root)==policy['installer_source'],'actual accepted fresh604 source required')
    api=C.load('_root604_installer_contract',root/'scripts/ci/expanded604-current-management-installer/contract.py')
    api.verify_source(root);bound=api.policy();comp=api.COMPOSITION.policy()
    expected=dict(legacy_source=comp['legacy_source'],eight_source=comp['eight_pair_source'],seven_source=comp['retained_seven_source'],
         management_source=comp['management']['packet_source'],setup_source=comp['setup']['source'],welcome_source=comp['welcome']['carrier_source'],
         fresh600_decisions=bound['fresh600']['carrier_source'],native604_decisions=bound['native604']['carrier_source'])
    C.need(policy['installer_inputs']==expected,'exact actual fresh604 carrier bindings required')
    materializer=api.scoped_load('_root604_materializer',api.HERE.parent/'expanded604-current-management/materializer.py',{'contract':api.COMPOSITION})
    return api,materializer,bound


def inputs(args,policy):
    decisions=C.prerequisites(args.decision_source,policy)
    api,materializer,bound=installer(args.installer_source,policy)
    api.legacy(args.legacy_source)
    selected=SimpleNamespace(**{key:getattr(args,key) for key in (*C.INPUTS,'audio_inputs')},code=args.installer_source)
    composition,summary,prior=api.inputs(selected,bound)
    # Join the new Root decision to the same native604 closure accepted by the installer.
    native=decisions['native604'];held=prior['native604']
    C.need(native==held,'copied-root and fresh604 gates must consume the same actual native604 decision')
    C.need(C.revision(args.upgrader_source)==C.SOURCES[args.case],'exact accepted original updater case source required')
    old_gate,_=C.old600();held_pins=C.read(C.HERE.parent/'expanded600-root-upgrade/held-pins.json')[args.case]
    for name,row in held_pins['pins'].items():C.checked(args.upgrader_source,dict(path=name,**row))
    C.need(C.revision(args.setup_source)==C.PAIR,'genuine accepted Setup5 pair checkout required')
    index=args.setup_source/'index.json'
    C.need(C.sha(index)=='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d','genuine Setup5 packet required')
    for name,row in C.read(index)['files'].items():old_gate.packet_member(args.setup_source,name,row)
    return api,materializer,composition,decisions,summary


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','installer_source','decision_source','upgrader_source',*C.INPUTS,'audio_inputs'):
        p.add_argument('--'+name.replace('_','-'),type=Path)
    p.add_argument('--source',required=True);p.add_argument('--workflow-sha',required=True)
    p.add_argument('--case',choices=tuple(C.SOURCES),required=True);p.add_argument('--preflight',action='store_true')
    p.add_argument('--decisions-only',action='store_true')
    args=p.parse_args(argv);policy=C.policy()
    C.need(re.fullmatch('[0-9a-f]{40}',args.source) and args.source==args.workflow_sha,'exact workflow/source identity required')
    C.need(args.implementation is not None,'implementation source required');args.implementation=C.safe(args.implementation.absolute())
    own_source(args.implementation,args.source)
    if args.preflight:
        outputs=dict(policy['installer_inputs'],installer_source=policy['installer_source'],decision_source=policy['decision_source'],
             upgrader_source=C.SOURCES[args.case])
        if os.environ.get('GITHUB_OUTPUT'):
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
                for name,value in outputs.items():stream.write(name+'='+value+'\n')
        print('ROOT604_POLICY_AND_SOURCE=PASS actors=NOT_RUN');return 0
    if args.decisions_only:
        for name in ('decision_source','installer_source'):
            C.need(getattr(args,name) is not None,'actual decision and installer carriers required')
            setattr(args,name,C.safe(getattr(args,name).absolute()))
        C.prerequisites(args.decision_source,policy);installer(args.installer_source,policy)
        print('ROOT604_ACTUAL_DECISIONS_AND_INSTALLER=PASS actors=NOT_RUN');return 0
    for name in ('installer_source','decision_source','upgrader_source',*C.INPUTS,'audio_inputs'):
        C.need(getattr(args,name) is not None,'all immutable input carriers and audio required')
        setattr(args,name,C.safe(getattr(args,name).absolute()))
    inputs(args,policy);print('ROOT604_ACTUAL_INPUTS_AND_DECISIONS=PASS actors=NOT_RUN');return 0


if __name__=='__main__':raise SystemExit(main())
