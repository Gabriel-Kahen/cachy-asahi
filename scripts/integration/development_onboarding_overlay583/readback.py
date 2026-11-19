#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the exact onboarding controller and reopen its owned result evidence."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import sys

DATA=Path(__file__).resolve().parent
TRIAL='scripts/install/overlay583_trial/trial.py'
EXT4='scripts/integration/arm16k_perl5423_vm/frozen/independent_readback.py'
BOUND_OUTPUT='/out/overlay583-development-onboarding-r2'


def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def support(path):
    reader=module(path,'held_overlay583_owner_checks')
    reader.DATA=DATA
    return reader


def plain(ref):
    return {k:ref[k] for k in ('bytes','sha256')}


def selected(r,data,trial,candidate,nonce,issuer):
    r.need(re.fullmatch('[a-f0-9]{32}',nonce),'exact guest boot nonce')
    template=data['plan_template']
    original=r.decode(r.file(DATA/'plan-template.DATA.json',2**20,plain(template)))
    r.need(original['nonce']==template['nonce'] and original==trial.guest_plan(original['packet'],template['nonce']),
           'unmodified ordinary Overlay583 plan')
    plan=trial.guest_plan(original['packet'],nonce)
    expectation=dict(kind='ROOT_OVERLAY583_QEMU_TCG_SELECTION_V1',issuer=issuer,nonce=nonce,
                     paths={'staging':'/inputs/staging','preflight':'/inputs/preflight/retained583.json',
                            'kernel':'/inputs/kernel/Image','config':'/inputs/kernel/config',
                            'baseline':'/inputs/baseline/guest.raw','output':BOUND_OUTPUT},
                     actor_image=data['actor_image'],preflight=plain(data['preflight']),plan=r.pin(trial.encoded(plan)),
                     references={k:plain(v) for k,v in data['references'].items()},tools=data['tools'],source=data['source'])
    r.need(candidate==expectation,'exact admitted base controller, source, tools and guest plan')
    return plan


def result(r,data,trial,attempt):
    raw=r.file(attempt/'selection.json',128*1024)
    authority=r.decode(raw)
    r.need(r.encode(authority)==raw,'canonical source-bound authority')
    nonce=authority['nonce']
    plan=selected(r,data,trial,authority,nonce,'Root')
    out=attempt/'output'/Path(BOUND_OUTPUT).name
    report=r.file(out/'report.json',256*1024)
    controller=r.decode(report)
    r.need(r.file(attempt/'run.stdout',256*1024)==report and
           controller['authority_sha256']==r.pin(raw)['sha256'] and controller['nonce']==nonce and
           controller['emulation']=='QEMU_TCG_AARCH64_16K' and
           r.file(attempt/'bind.state',64)==r.file(attempt/'run.state',64)==b'exited 0 false\n',
           'same exact owned controller and naturally retired containers')
    raw_qemu=r.file(out/'qemu.json',128*1024,controller['qemu_receipt'])
    child=r.decode(raw_qemu)
    r.need(child['passed'] is True and child['exit']==0 and child['ownership']=='REAPED' and
           child['group_census']=='EMPTY_TWICE' and child['reaped'] is child['output_complete'] is True and
           child['signals']==[] and child['timeout'] is child['command_timed_out'] is False,'owned QEMU natural retirement')
    argv=child['argv']
    kernel=argv[argv.index('-append')+1].split()
    r.need(argv[0]=='/usr/bin/qemu-system-aarch64' and argv[argv.index('-nic')+1]=='none' and
           argv[argv.index('-accel')+1]=='tcg,thread=multi' and
           kernel.count('cachy_overlay583_nonce='+nonce)==1 and
           kernel.count('cachy_overlay583_plan='+authority['plan']['sha256'])==1 and
           kernel.count('cachy_overlay583_worker='+data['source'][TRIAL]['sha256'])==1,'exact selected offline QEMU')
    serial=r.file(out/'qemu.stdout',1024**2,controller['serial'])
    markers=[line for line in serial.splitlines() if line.startswith(b'OVERLAY583 ')]
    r.need(markers==[f'OVERLAY583 {nonce} PASS 16384'.encode()],'exact boot terminal and ARM page size')
    disk=r.file(out/'result.raw',64*1024**2,controller['result_disk'],digest_only=True)
    r.need(disk['bytes']==64*1024**2,'exact local result disk geometry')
    joined=trial.read_result(out/'evidence',plan)
    r.need(all(controller[k]==v for k,v in joined.items()),'separate held DATA replay matches controller')
    ext=module(DATA/'source'/EXT4,'onboarding_read_only_ext4')
    with ext.Ext4Reader(out/'result.raw',max_nodes=64,max_file_bytes=8*1024**2) as fs:
        nodes=fs.inventory()['nodes']
    dirs={'.','lost+found','evidence'}
    r.need(set(nodes)==dirs|{'evidence/'+name for name in joined['files']} and
           all(nodes[n]['type']=='directory' for n in dirs),'exact retained result disk roles')
    for name,want in joined['files'].items():
        n=nodes['evidence/'+name]
        r.need(n['type']=='file' and n['uid']==n['gid']==0 and n['mode']==0o600 and n['links']==1 and
               dict(bytes=n['size'],sha256=n['sha256'])==want,'retained export exactly matches the raw guest disk')
    proof=joined['onboarding']
    return dict(status='PASS_INSTALLED_OVERLAY583_ARM16K_DEVELOPMENT_ONBOARDING' if proof['status']=='PASS' else
                'HOLD_INSTALLED_OVERLAY583_ARM16K_DEVELOPMENT_ONBOARDING',
                scope='SCRIPTED_EDIT_INSTALLED_ARM16K_ONLY',hardware=None,root_acceptance=None,
                controller=r.pin(report),authority=r.pin(raw),owned_qemu=r.pin(raw_qemu),result_disk=disk,
                onboarding=proof,installed_lock=joined['installed_lock'],receipt=joined['files']['installed-onboarding.json'])


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--handoff-sha256',required=True)
    commands=cli.add_subparsers(dest='mode',required=True)
    commands.add_parser('preflight')
    issue=commands.add_parser('issue-from-bind')
    issue.add_argument('--nonce',required=True)
    for p in (issue,commands.add_parser('result'),commands.add_parser('close')):
        p.add_argument('--attempt',type=Path,required=True)
    a=cli.parse_args()
    os.umask(0o077)
    if not sys.flags.isolated or not sys.dont_write_bytecode or not __debug__:
        raise ValueError('isolated bytecode-free reader required')
    donor=DATA/'held-readback.py'
    from hashlib import sha256
    if donor.resolve()!=donor or sha256(donor.read_bytes()).hexdigest()!='2bc376d321305e91448e04af9d7eecd9f2b3366796ffc5271c973e7df376e342':
        raise ValueError('exact retained owner reader')
    r=support(donor)
    raw=r.file(DATA/'HANDOFF.DATA.json',128*1024)
    data=r.decode(raw)
    r.need(r.pin(raw)['sha256']==a.handoff_sha256 and raw==r.encode(data) and
           data['kind']=='OVERLAY583_DEVELOPMENT_ONBOARDING_ROOT_OPERANDS_ONLY_V2','exact dedicated handoff')
    src=DATA/'source'
    r.need({str(p.relative_to(src)) for p in src.rglob('*') if p.is_file() or p.is_symlink()}==set(data['source']),
           'exact nine original-plus-worker source members')
    for name,ref in data['source'].items():
        r.file(src/name,128*1024,ref,digest_only=True)
    trial=module(src/TRIAL,'first_login_separate_onboarding_worker')
    if a.mode=='preflight':
        for ref in [data['preflight'],*data['references'].values()]:
            r.file(Path(ref['path']),ref['bytes'],plain(ref),digest_only=True)
        d=data['docker']
        r.need(r.file(Path(d['path']),64*1024**2,digest_only=True)['sha256']==d['sha256'],'held rootless CLI')
        for name,ref in data['archive_operands'].items():
            r.file(Path(data['staging'])/name,ref['bytes'],ref,digest_only=True)
        print(r.encode(dict(ready=True,Root_authority=None,local_compilation='NOT RUN')).decode(),end='')
        return 0
    p=r.attempt_path(a.attempt)
    scope=r.claimed_attempt(data,p)
    if a.mode=='issue-from-bind':
        r.need(Path('/proc/self/cgroup').read_text()==f'0::{scope}\n' and r.file(p/'bind.state',64)==b'exited 0 false\n',
               'exact scope and naturally retired bind precede selection')
        raw=r.file(p/'binding.json',128*1024)
        candidate=r.decode(raw)
        selected(r,data,trial,candidate,a.nonce,None)
        r.need(r.encode(candidate)==raw,'canonical bind result')
        with (p/'selection.json').open('xb') as stream:
            stream.write(r.encode(dict(candidate,issuer='Root')))
        return 0
    verified=result(r,data,trial,p)
    if a.mode=='close':
        verified['cleanup']=r.natural_closure(data,p)
        with (p/'Root-independent-onboarding-terminal.ACTUAL.json').open('xb') as stream:
            stream.write(r.encode(verified))
    print(r.encode(verified).decode(),end='')
    return 0 if verified['status'].startswith('PASS_') else 1


if __name__=='__main__':
    raise SystemExit(main())
