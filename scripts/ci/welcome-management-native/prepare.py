#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Derive accepted generic4K managed GUI transport; original lanes remain byte-identical."""
import argparse
import ast
import json
from pathlib import Path
import shutil
import sys
import native_contract as C
import candidates
import management_contract as M

HERE=Path(__file__).resolve().parent


def replace(text,old,new):
    C.need(text.count(old)==1,'management adapter anchor differs: '+old[:100]);return text.replace(old,new)


def prepare(source,output,assets):
    C.verify_source(source);policy=C.policy();ui=M.interface(policy)
    C.need(ui['labels']==dict(management='Management',doctor='Run Doctor',orphans='Assess orphan packages'),'final source UI label adapter binding differs')
    # The original prepare API is reused in memory with this lane's explicit same-job candidate adapter.
    sys.modules['candidates']=candidates
    shared=C.load('accepted_welcome_management_prepare',source/'scripts/ci/welcome-managed-gui/prepare.py')
    shared.candidates=candidates;shared.prepare(source,output,assets)
    for name in ('native_contract.py','input-policy.json','infrastructure-pins.json','installed.py','management_contract.py','management_phase.py','management_root.py','doctor_lifetime.py','a11y_driver.c','candidates.py'):
        shutil.copyfile(HERE/name,output/name)
    shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',output/'accepted_lifecycle.py')
    # Both guest.py and the independent Doctor terminal use python -I. Register
    # only these pinned siblings through their existing file loader, in order.
    for filename,anchor,names in (
        ('desktop574_guest.py','\ndef main():',('doctor_lifetime','management_contract','management_root','management_phase')),
        ('doctor_worker.py',"\nC=load('doctor_gui_contract','gui_contract.py')",('doctor_lifetime','management_contract','management_root')),
    ):
        text=(output/filename).read_text()
        if filename=='doctor_worker.py':
            text=replace(text,'import time\n','import time\nimport sys\n')
            text=replace(text,'module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module',
                'module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module')
        imports=''.join("\nload(%r,%r)"%(name,name+'.py') for name in names)
        (output/filename).write_text(replace(text,anchor,imports+'\n'+anchor))
    # Adapter contracts are materialized independently of archive bytes, then hash-bound below.
    gui=(output/'gui_contract.py').read_text()
    gui=replace(gui,"version='0.1.0-1'","version={'cachy-asahi-doctor':'0.1.0-1','cachy-asahi-orphans':'0.1.0-2','cachy-asahi-welcome':'0.1.0-4'}[name]")
    gui+='''\nimport management_contract as MG
BASE_VIEWS=VIEWS
VIEWS=MG.VIEWS
_original_snapshot=validate_snapshot

def validate_snapshot(value,pid,view,text_sha=None):
    if view in MG.MANAGEMENT_VIEWS:return MG.snapshot(value,pid,view,text_sha)
    return _original_snapshot(value,pid,view,text_sha)
'''
    (output/'gui_contract.py').write_text(gui)
    worker=(output/'doctor_worker.py').read_text().replace('Welcome 0.1.0-1 | Doctor','Welcome 0.1.0-4 | Doctor')
    worker=replace(worker,"    start=marker(workspace/'start.json',args.nonce,120)\n    C.need(start.get('terminal_pid')==os.getppid() and os.isatty(0) and os.isatty(1),'owned terminal parent/PTY required')\n    try:\n        result=exercise(base,workspace,args.stage,args.nonce,os.getppid(),dict(os.environ))\n        C.publish(workspace/'result.json',result);marker(workspace/'release.json',args.nonce,450);return 0\n    except BaseException as error:\n        if not (workspace/'result.json').exists():\n            C.publish(workspace/'result.json',dict(status='FAIL',reason=str(error)[:512],error_type=type(error).__name__,\n                      processes=getattr(error,'doctor_processes',[])))\n        print('DOCTOR REPORT FAILED: '+str(error)[:512],flush=True);return 1\n","    return sys.modules['doctor_lifetime'].worker(C,base,workspace,args.stage,args.nonce,exercise)\n")
    worker=replace(worker,"if __name__=='__main__':raise SystemExit(main())","if __name__=='__main__':raise SystemExit(sys.modules['doctor_lifetime'].supervise(main))")
    (output/'doctor_worker.py').write_text(worker)
    session=(output/'session.py').read_text()
    session=replace(session,'import time\n','import time\nimport management_phase as MG\nimport doctor_lifetime as DL\n')
    session=replace(session,'    def a11y(operation,label=None,pending=False):','    def a11y(operation,label=None,pending=False,scope=None):')
    session=replace(session,"([label] if label else [])","([label] if label else [])+([scope] if scope else [])")
    anchor="        target='address:'+C.window(clients(),welcome.process.pid,'welcome')['address']\n        C.need(command(['/usr/bin/hyprctl','dispatch',f'hl.dsp.window.close({{window=\"{target}\"}})'],'close-welcome').strip()=='ok','Welcome close failed')"
    new="""        def adopt(actor):
            nonlocal welcome
            welcome=actor
        welcome=MG.exercise(base,stage,selected,logs,workspace,welcome,doctor,lock['policy'],lock,
            dict(healthy=healthy,a11y=a11y,wait=wait,capture=capture,command=command,place=place,adopt=adopt,
                 window=lambda pid:C.window(clients(),pid,'welcome')))
""".rstrip()
    session=replace(session,anchor,new)
    session=replace(session,"        checkpoint='doctor-startup'","        checkpoint='doctor-startup'\n        MG.request('profile',stage=stage,profile_nonce=nonce)")
    session=replace(session,"C.publish(workspace/'start.json',dict(nonce=nonce,terminal_pid=doctor.process.pid))","DL.start(workspace,stage,nonce,doctor.process.pid)")
    session=replace(session,"C.publish(workspace/'release.json',dict(nonce=nonce));doctor.process.wait(timeout=15)","DL.publish(workspace/'release.json',dict(nonce=nonce),0o600);doctor.process.wait(timeout=15)")
    anchor="        try:C.need(C.snapshot(Path(env['XDG_CONFIG_HOME']))==protected,'existing user configuration changed')"
    session=replace(session,anchor,"        if doctor is not None:\n            lifetime=DL.capture(workspace,stage,nonce,doctor.process.pid,doctor.process.returncode)\n            base.emit('doctor_lifetime',**lifetime)\n            if first is None:\n                try:\n                    DL.validate(lifetime,stage,nonce,doctor.process.pid,doctor_proof['worker_pid'])\n                    MG.request('profile-retired',stage=stage,profile_nonce=nonce,terminal_pid=doctor.process.pid,terminal_exit=doctor.process.returncode,worker_pid=doctor_proof['worker_pid'])\n                except BaseException as error:first=error\n"+anchor)
    (output/'session.py').write_text(session)
    guest=(output/'base_guest.py').read_text()
    guest=replace(guest,'import time\n','import time\nimport management_root\nimport doctor_lifetime as DL\n')
    guest=replace(guest,'code = session.wait(timeout=1080)',"code = management_root.serve(managed_base, session, env, logs, DL.service_lease()['deadline_ns'])")
    guest=replace(guest,'    guard(True)  # Never power off a host that failed the guest guard.','    guard(True)  # Never power off a host that failed the guest guard.\n    DL.service()')
    # base_guest is also the binding module used by managed session; only guarded VM root can transact.
    (output/'base_guest.py').write_text(guest)
    fixture=(output/'desktop574_fixture.sh').read_text()
    anchor='cc -std=c11 -O2 -Wall -Wextra -Werror /runner/a11y_driver.c'
    fixture=replace(fixture,anchor,'cp /runner/native_contract.py /runner/input-policy.json /runner/infrastructure-pins.json /runner/installed.py /runner/accepted_lifecycle.py /runner/management_contract.py /runner/management_phase.py /runner/management_root.py /runner/doctor_lifetime.py "$root/usr/local/share/desktop574/"\n'+
        'cp -a /runner/candidates "$root/usr/local/share/desktop574/management-inputs"\n'+anchor)
    (output/'desktop574_fixture.sh').write_text(fixture)
    legacy=(output/'contract.py').read_text();(output/'legacy_contract.py').write_text(legacy)
    contract='''# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import candidates
import gui_contract as C
import management_contract as M
import doctor_lifetime as DL
legacy=C.load('management_accepted_gui_contract','legacy_contract.py')
verify_source=candidates.verify_source

def verify_result(events,lock):
    baseline=[e for e in events if not(e.get('event')=='frame_ready' and e.get('view') in M.MANAGEMENT_VIEWS)]
    old=dict(lock,products={n:lock['products'][n] for n in ('cachy-asahi-welcome','cachy-asahi-doctor')})
    views=C.VIEWS
    try:
        C.VIEWS=M.BASE_VIEWS
        original=legacy.verify_result(baseline,old)
        C.VIEWS=views
        profile_retirements=[]
        for stage in ('minimal','overlay'):
            finals=[e for e in events if e.get('event')=='doctor_lifetime' and e.get('stage')==stage]
            C.need(len(finals)==1,'one original Doctor lifetime receipt required')
            doctor=next(e for e in events if e.get('event')=='doctor_result' and e.get('stage')==stage)
            proof=doctor['proof'];profile_retirements.append(DL.validate(finals[0],stage,proof['nonce'],proof['terminal_pid'],proof['worker_pid']))
            C.need(proof['report_worker_pid']==finals[0]['receipt']['worker_pid'],'actual Doctor report child identity differs')
            frames=[e for e in events if e.get('event')=='frame_ready' and e.get('stage')==stage]
            phase=next(e for e in events if e.get('event')=='phase_pass' and e.get('stage')==stage)
            C.need(events.index(frames[-1])<events.index(finals[0])<events.index(phase),'Doctor release must follow all original frames')
            reference=next(e for e in baseline if e.get('event')=='frame_ready' and e.get('stage')==stage)
            for frame in (e for e in events if e.get('event')=='frame_ready' and e.get('stage')==stage and e.get('view') in M.MANAGEMENT_VIEWS):
                C.together(list(frame['windows'].values()),frame['welcome_pid'],reference['doctor_pid'],frame['view'])
                C.need(all(frame[k]==reference[k] for k in ('doctor_pid','compositor_pid','worker','doctor_proof_sha256','managed_identity','producer_lifecycle')),
                       'management capture must retain actual managed bus/compositor/Doctor worker')
        DL.validate_profiles(profile_retirements)
    finally:C.VIEWS=views
    return dict(baseline=original,management=M.verify_result(events,lock),visual_review='NOT_RUN',hardware='NOT_RUN')
'''
    (output/'contract.py').write_text(contract)
    runtime=(output/'desktop574_runtime.py').read_text()
    runtime=replace(runtime,'cachy_asahi_welcome_gui=1','cachy_asahi_welcome_gui=1 cachy_asahi_welcome_management=1')
    runtime=runtime.replace('PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_METADATA','PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA')
    oldframes=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in M.BASE_VIEWS)
    newframes=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in M.VIEWS)
    C.need(runtime.count(repr(oldframes))==2,'two exact original frame-set anchors required');runtime=runtime.replace(repr(oldframes),repr(newframes))
    # Use Required local signatures only for the3 management products; existing desktop/tooling policy remains scoped.
    runtime=replace(runtime,'for row in candidate_lock["products"].values():shutil.copyfile(candidate_root/row["archive"],products/row["archive"])',
        'for row in candidate_lock["products"].values():\n            for name in (row["archive"],row["archive"]+".sig"):shutil.copyfile(candidate_root/name,products/name)\n'+
        '        for name in ("TEST-public.asc","control.json"):shutil.copyfile(candidate_root/name,products/name)')
    runtime=replace(runtime,'/tmp/project/desktop.pkg.tar.zst /tmp/products/*.pkg.tar.xz && ldconfig',
        '/tmp/project/desktop.pkg.tar.zst && mkdir -m700 /tmp/management-trust && gpg --batch --no-auto-key-retrieve --homedir /tmp/management-trust --import /tmp/products/TEST-public.asc && '+
        'python3 -c \\\'import json;print(json.load(open("/tmp/products/control.json"))["signer"]+":6:")\\\' | gpg --batch --homedir /tmp/management-trust --import-ownertrust && '+
        'printf "[options]\\\\nArchitecture = aarch64\\\\nSigLevel = Required\\\\nLocalFileSigLevel = Required\\\\nGPGDir = /tmp/management-trust\\\\n" >/tmp/management.conf && '+
        'pacman -U --noconfirm --noscriptlet --config /tmp/management.conf /tmp/products/*.pkg.tar.xz && gpgconf --homedir /tmp/management-trust --kill all && rm -rf /tmp/management-trust /tmp/management.conf && ldconfig')
    (output/'desktop574_runtime.py').write_text(runtime)
    files={p.name:dict(bytes=p.stat().st_size,sha256=C.digest(p)) for p in output.iterdir() if p.is_file() and p.name not in ('candidate-lock.json','runner-proof.json')}
    for path in output.glob('*.py'):ast.parse(path.read_text(),filename=str(path))
    (output/'runner-proof.json').write_bytes(C.encoded(dict(status='DERIVED_SOURCE_ONLY',files=files,native='NOT_RUN',hardware='NOT_RUN')))
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','assets'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(prepare(args.source.absolute(),args.output.absolute(),args.assets.absolute()))
