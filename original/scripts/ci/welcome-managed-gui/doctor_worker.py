# SPDX-License-Identifier: MIT
"""Installed Doctor report commands inside the owned visible terminal PTY."""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import time


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


C=load('doctor_gui_contract','gui_contract.py')


def marker(path,nonce,seconds):
    until=time.monotonic()+seconds
    while not path.exists():C.need(time.monotonic()<until,'Doctor terminal marker deadline');time.sleep(.1)
    value=json.loads(C.read(path));C.need(value.get('nonce')==nonce,'Doctor terminal marker identity differs');return value


def exercise(base,workspace,stage,nonce,pid,env):
    processes=[];original_emit=base.emit
    def record(event,**values):
        C.need(event=='process_exit' and len(processes)<4,'bounded Doctor process events required')
        processes.append(dict(event=event,**values))
    base.emit=record
    try:return commands(base,workspace,stage,nonce,pid,env,processes)
    except BaseException as error:
        error.doctor_processes=processes;raise
    finally:base.emit=original_emit


def commands(base,workspace,stage,nonce,pid,env,processes):
    records=[];count=0
    def command(args,expected=0):
        nonlocal count
        count+=1;actor=base.Logged(['/usr/bin/cachy-asahi-doctor',*args],'doctor-'+str(count),workspace,env)
        error=None
        try:actor.process.wait(timeout=35)
        except BaseException as caught:error=caught
        finally:
            for cleanup in (lambda:base.terminate(actor.process),actor.finish):
                try:cleanup()
                except BaseException as caught:
                    if error is None:error=caught
        if error is not None:raise error
        C.need(actor.process.returncode==expected,'installed Doctor command exit differs')
        stdout=C.read(actor.paths[0]);stderr=C.read(actor.paths[1])
        C.need(len(processes)==count and processes[-1].get('name')=='doctor-'+str(count) and
               processes[-1].get('returncode')==expected,'Doctor process exit proof differs')
        records.append(dict(argv=['/usr/bin/cachy-asahi-doctor',*args],returncode=actor.process.returncode,
                            stdout_sha256=C.sha(stdout),stderr_sha256=C.sha(stderr)))
        return stdout
    printed=json.loads(command(['--json']))
    report=workspace/'doctor-report.json';raw=command(['--json','--output',str(report)])
    C.need(C.read(report)==raw and stat.S_IMODE(report.lstat().st_mode)==0o600 and report.stat().st_uid==23001,
           'private installed Doctor report differs')
    data=json.loads(raw);pin=C.sha(raw);outside=workspace/'outside.txt';outside.write_text('preserve outside report\n')
    protected=C.sha(C.read(outside));alias=workspace/'report-alias';alias.symlink_to(outside.name)
    command(['--output',str(report)],2);command(['--output',str(alias)],2)
    C.need(C.sha(C.read(report))==pin and C.sha(C.read(outside))==protected,'Doctor overwrite/outside preservation failed')
    result=dict(status='PASS_INSTALLED_DOCTOR_REPORT',stage=stage,nonce=nonce,terminal_pid=pid,worker_pid=os.getpid(),
        terminal_isatty=os.isatty(0) and os.isatty(1),pty=os.ttyname(1),doctor=data,printed_doctor=printed,report_sha256=pin,
        report_mode='0600',no_overwrite='PASS',symlink_refusal='PASS',commands=records,processes=processes)
    C.validate_doctor(result,stage,nonce,pid)
    checks={r['check']:r for r in data['checks']};machine=checks['platform']['value']
    model=checks['apple-model'];coverage=data['coverage']
    lines=['CACHY ASAHI DOCTOR | installed local report',
        'Architecture: '+machine['architecture']+' | page: '+str(machine['page_size_bytes'])+' | kernel: '+machine['kernel'],
        'Welcome 0.1.0-1 | Doctor 0.1.0-1 | installed package observations PASS',
        'Apple model: '+model['state']+' | scope: local observations only',
        'Coverage: '+', '.join(str(coverage[k])+' '+k for k in ('checked','unknown','unavailable')),
        'Report mode 0600 | no-overwrite PASS | SHA256 '+pin[:16],
        'Read-only diagnostics; no hardware or rendering certification.']
    result['transcript']='\n'.join(lines)+'\n'
    for line in lines:print(line,flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--nonce',required=True);parser.add_argument('--stage',choices=('minimal','overlay'),required=True)
    args=parser.parse_args();base=load('doctor_gui_base','base_guest.py');base.guard(False)
    C.need('cachy_asahi_welcome_gui=1' in Path('/proc/cmdline').read_text().split(),'Welcome GUI fixture marker required')
    C.need(re.fullmatch('[0-9a-f]{32}',args.nonce),'owned Doctor nonce required')
    workspace=args.workspace
    C.need(workspace==Path('/home/desktop574')/('doctor-'+args.stage+'-'+args.nonce) and not workspace.is_symlink() and
         workspace.stat().st_uid==23001 and stat.S_IMODE(workspace.stat().st_mode)==0o700 and Path.cwd()==workspace,
         'owned Doctor workspace required')
    os.umask(0o077)
    start=marker(workspace/'start.json',args.nonce,120)
    C.need(start.get('terminal_pid')==os.getppid() and os.isatty(0) and os.isatty(1),'owned terminal parent/PTY required')
    try:
        result=exercise(base,workspace,args.stage,args.nonce,os.getppid(),dict(os.environ))
        C.publish(workspace/'result.json',result);marker(workspace/'release.json',args.nonce,450);return 0
    except BaseException as error:
        if not (workspace/'result.json').exists():
            C.publish(workspace/'result.json',dict(status='FAIL',reason=str(error)[:512],error_type=type(error).__name__,
                      processes=getattr(error,'doctor_processes',[])))
        print('DOCTOR REPORT FAILED: '+str(error)[:512],flush=True);return 1


if __name__=='__main__':raise SystemExit(main())
