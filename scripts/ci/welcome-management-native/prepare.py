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
    for name in ('native_contract.py','input-policy.json','infrastructure-pins.json','installed.py','management_contract.py','management_phase.py','management_root.py','a11y_driver.c','candidates.py'):
        shutil.copyfile(HERE/name,output/name)
    shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',output/'accepted_lifecycle.py')
    # Both guest.py and the independent Doctor terminal use python -I. Register
    # only these pinned siblings through their existing file loader, in order.
    for filename,anchor,names in (
        ('desktop574_guest.py','\ndef main():',('management_contract','management_root','management_phase')),
        ('doctor_worker.py',"\nC=load('doctor_gui_contract','gui_contract.py')",('management_contract','management_root')),
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
    (output/'doctor_worker.py').write_text(worker)
    session=(output/'session.py').read_text()
    session=replace(session,'import time\n','import time\nimport management_phase as MG\n')
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
    session=replace(session,anchor,new);(output/'session.py').write_text(session)
    guest=(output/'base_guest.py').read_text()
    guest=replace(guest,'import time\n','import time\nimport management_root\n')
    guest=replace(guest,'code = session.wait(timeout=1080)','code = management_root.serve(managed_base, session, env, logs, 1080)')
    # base_guest is also the binding module used by managed session; only guarded VM root can transact.
    (output/'base_guest.py').write_text(guest)
    fixture=(output/'desktop574_fixture.sh').read_text()
    anchor='cc -std=c11 -O2 -Wall -Wextra -Werror /runner/a11y_driver.c'
    fixture=replace(fixture,anchor,'cp /runner/native_contract.py /runner/input-policy.json /runner/infrastructure-pins.json /runner/installed.py /runner/accepted_lifecycle.py /runner/management_contract.py /runner/management_phase.py /runner/management_root.py "$root/usr/local/share/desktop574/"\n'+
        'cp -a /runner/candidates "$root/usr/local/share/desktop574/management-inputs"\n'+anchor)
    (output/'desktop574_fixture.sh').write_text(fixture)
    legacy=(output/'contract.py').read_text();(output/'legacy_contract.py').write_text(legacy)
    contract='''# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import candidates
import gui_contract as C
import management_contract as M
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
        for stage in ('minimal','overlay'):
            reference=next(e for e in baseline if e.get('event')=='frame_ready' and e.get('stage')==stage)
            for frame in (e for e in events if e.get('event')=='frame_ready' and e.get('stage')==stage and e.get('view') in M.MANAGEMENT_VIEWS):
                C.together(list(frame['windows'].values()),frame['welcome_pid'],reference['doctor_pid'],frame['view'])
                C.need(all(frame[k]==reference[k] for k in ('doctor_pid','compositor_pid','worker','doctor_proof_sha256','managed_identity','producer_lifecycle')),
                       'management capture must retain actual managed bus/compositor/Doctor worker')
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
