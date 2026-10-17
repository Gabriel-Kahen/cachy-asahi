# SPDX-License-Identifier: MIT
"""Finite604 copied-root selection; five actual Root decisions precede every actor."""
import importlib.util
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[2]
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
PAIR='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44'
PACKAGE='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'
NATIVE='ec135f26326158591e6d25d5f670083d5306b071'
RECIPE='aa4d6ed7865aab606a55e7de94e50d6966f47f7b926a39efd4b3f64eec403778'
SOURCES={'normal':'de04c6b102890218da4f0b77e938315d601e824f',
         'precommit-exit86':'001f0484ab8b599ddc03a84e62fd81af315a2a03',
         'postcommit-exit87':'4b803ba7daa0eacd978a5bf86d62346363c3b6dc'}
INPUTS=('legacy_source','eight_source','seven_source','management_source','setup_source','welcome_source',
        'fresh600_decisions','native604_decisions','apps6_source','apps6_native_source')
PREREQUISITES=('native604','fresh604','normal600','precommit600','postcommit600')


def _utility():
    spec=importlib.util.spec_from_file_location('_root604_shared_contract',HERE.parent/'expanded600-root-upgrade/contract.py')
    value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;spec.loader.exec_module(value);return value


OLD=_utility()
need,read,sha,encoded,safe,checked,load,revision=OLD.need,OLD.read,OLD.sha,OLD.encoded,OLD.safe,OLD.checked,OLD.load,OLD.revision


def scoped(name,path,aliases):
    missing=object();previous={key:sys.modules.get(key,missing) for key in aliases}
    try:sys.modules.update(aliases);return load(name,path)
    finally:
        for key,value in previous.items():
            if value is missing:sys.modules.pop(key,None)
            else:sys.modules[key]=value


def old600():
    directory=HERE.parent/'expanded600-root-upgrade'
    adapter=scoped('_root604_prior_adapter',directory/'adapter.py',{'contract':OLD})
    gate=scoped('_root604_prior_gate',directory/'gate.py',{'contract':OLD})
    owner=scoped('_root604_prior_owner',directory/'run.py',{'contract':OLD,'adapter':adapter,'gate':gate})
    return gate,owner


def locks():
    raws=[(HERE/name).read_bytes() for name in ('before604.lock','after604.lock')]
    need([__import__('hashlib').sha256(raw).hexdigest() for raw in raws]==[BEFORE,AFTER],'exact604 lock bytes required')
    groups=[[line.split() for line in raw.decode('ascii').splitlines()] for raw in raws]
    need(all(len(rows)==604 and all(len(row)==2 for row in rows) and len(dict(rows))==604 for rows in groups),
         '604 distinct package records required')
    before,after=map(dict,groups)
    need(before['cachy-asahi-apps']=='0.1.0-5' and after==before|{'cachy-asahi-apps':'0.1.0-6'} and before['cachy-asahi-setup']==after['cachy-asahi-setup']=='0.1.0-5' and
         after['cachy-asahi-update']=='4.4.2-2' and after['cachy-asahi-welcome']=='0.1.0-4' and
         all(after.get(name)==version for name,version in {'cachy-asahi-apps':'0.1.0-6','cachy-asahi-cache':'0.2.0-1',
             'cachy-asahi-orphans':'0.1.0-2','cachy-asahi-repository-runtime':'0.1.0-1'}.items()),
         'only genuine Setup3 to5 change; other603 final packages required')
    return before,after


def policy(*,bound=True):
    value=read(HERE/'input-policy.json');locks()
    need(value.get('schema_version')==1 and value.get('before_sha256')==BEFORE and value.get('after_sha256')==AFTER and
         value.get('setup5_pair_source')==PAIR and set(value.get('prerequisites',{}))==set(PREREQUISITES) and
         set(value.get('installer_inputs',{}))==set(INPUTS),'fixed separate604 copied-root policy required')
    need(value.get('baseline_source')=='ed776a706fc711c5bcc4d933f38e88e7791bc9f6' and value.get('baseline_decisions_source')=='1c953fb9b1f9442f40895f886b659534424345ce','exact held Apps5/Setup5 baseline required')
    if bound:
        need(value.get('status')=='ROOT_BOUND_ACTUAL_APPS6_CURRENT604_PREREQUISITES' and
             all(re.fullmatch('[0-9a-f]{40}',value.get(k) or '') for k in ('installer_source','decision_source')) and
             all(re.fullmatch('[0-9a-f]{40}',v or '') for v in value['installer_inputs'].values()) and
             all(type(v) is dict for v in value['prerequisites'].values()),
             'Root native604, fresh604 and three actual600 updater truths remain UNBOUND')
        H=load('apps6_input_authority',HERE.parent/'expanded604-apps6/apps_inputs.py');H.require(load('apps6_composition_ref_helpers',HERE.parent/'expanded604-apps6/contract.py'),value.get('apps6',{}))
        need(value['installer_inputs']['apps6_source']==value['apps6']['carrier_source'] and value['installer_inputs']['apps6_native_source']==NATIVE,'same accepted Apps6 inputs required')
        for row in value['prerequisites'].values():
            need(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=4*1024**2 and
                 re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'exact Root positive-byte decision refs required')
    return value


def prerequisites(root,value):
    need(revision(root)==value['decision_source'],'immutable Root decision carrier required')
    result={key:read(checked(root,row)) for key,row in value['prerequisites'].items()}
    statuses=dict(native604='ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION',fresh604='ROOT_ACCEPTED_SIGNED_APPS6_CURRENT604_FRESH_INSTALLER',
         normal600='ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_NORMAL',precommit600='ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_PRECOMMIT_EXIT86',
         postcommit600='ROOT_ACCEPTED_EXPANDED600_COPIED_ROOT_POSTCOMMIT_EXIT87')
    for key,record in result.items():
        need(record.get('status')==statuses[key] and record.get('cleanup')=='PASS' and record.get('hardware')=='NOT_RUN' and
             record.get('release')=='NOT_ADMITTED' and re.fullmatch('[1-9][0-9]{0,19}',str(record.get('run_id',''))) and
             re.fullmatch('[0-9a-f]{40}',record.get('source_sha') or ''),'actual Root acceptance missing/failed: '+key)
        count=604 if key in ('native604','fresh604') else 600
        need(type(record.get('package_count')) is int and record['package_count']==count,'actual prerequisite package count differs')
        if count==604:need(record.get('expected604_sha256')==AFTER,'actual final604 inventory required')
    need(len({str(r['run_id']) for r in result.values()})==5,'five distinct actual prerequisite runs required')
    need(result['fresh604']['source_sha']==value['installer_source'] and
         all(result['fresh604'].get(k)=='PASS' for k in ('ordinary_parent_retired','independent_root_readback')) and
         all(result['native604'].get(k)=='PASS' for k in ('installed_lifecycle','installed_six_modules')),
         'actual native604 and complete independent fresh604 acceptance required')
    for key,case,truth,exit_code in (('normal600','normal',(1,True,True,True),0),
         ('precommit600','precommit-exit86',(0,False,False,False),86),
         ('postcommit600','postcommit-exit87',(1,True,True,False),87)):
        row=result[key];actual=tuple(row.get(k) for k in ('committed_transactions','commit_started','packages_committed','checkpoint_changed'))
        need(row.get('case')==case and row.get('before_sha256')==OLD.BEFORE and row.get('after_sha256')==OLD.AFTER and
             row.get('package_sha256')=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc' and row.get('copy_cleanup')=='PASS-owned-workspace-removed' and
             type(row.get('fault_exit')) is int and row['fault_exit']==exit_code and actual==truth and
             all(type(a) is type(b) for a,b in zip(actual,truth)),'exact actual600 commit/checkpoint/disposal truth required')
        if case=='normal':need(row.get('checkpoint_directory_synced') is True,'actual normal600 checkpoint sync required')
        elif case=='precommit-exit86':need(row.get('before_inventory_preserved') is True,'actual precommit600 unchanged copy required')
        else:need(all(row.get(k) is True for k in ('after600_database_verified','postcommit_payload_verified','postcommit_preservation_verified')),
             'actual postcommit600 committed-state checks required')
    return result
