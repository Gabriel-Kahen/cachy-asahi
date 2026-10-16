#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the installed GUI runner from current source and exact local asset checkout."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import candidates

HERE=Path(__file__).resolve().parent


def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('Welcome GUI adapter anchor differs: '+old[:80])
    return text.replace(old,new)


def prepare(source,output,assets):
    candidates.verify_source(source)
    if output.exists() or output.is_symlink():raise ValueError('fresh Welcome GUI runner required')
    output.mkdir(mode=0o700)
    lock=candidates.stage(source,assets,output/'candidates')
    shutil.copyfile(output/'candidates/candidate-lock.json',output/'candidate-lock.json')
    names=('compositor_log.py','session.py','doctor_worker.py','gui_contract.py','observed.py','a11y_driver.c','desktop574_guest.py',
           'contract.py','candidates.py','transport.json','managed_session.py','managed_contract.py',
           'terminal_session.py','terminal_workflow.py','source-pins.json')
    for name in names:shutil.copyfile(HERE/name,output/name)
    spec=importlib.util.spec_from_file_location('accepted_welcome_managed_prepare',source/'scripts/ci/desktop-user-session/prepare.py')
    managed=importlib.util.module_from_spec(spec);spec.loader.exec_module(managed)
    guest=managed.transform_guest((source/'scripts/ci/desktop574_guest.py').read_text())
    guest=replace(guest,'session.wait(timeout=480)','session.wait(timeout=1080)')
    (output/'base_guest.py').write_text(guest)
    fixture=(source/'scripts/ci/desktop574_fixture.sh').read_text()
    fixture=replace(fixture,'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service',
        'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service')
    fixture=replace(fixture,'After=basic.target systemd-udev-trigger.service',
        'After=basic.target systemd-udev-trigger.service systemd-user-sessions.service')
    guest_files=('compositor_log.py','base_guest.py','session.py','doctor_worker.py','gui_contract.py','observed.py','candidate-lock.json',
                 'managed_session.py','terminal_session.py','terminal_workflow.py')
    fixture=replace(fixture,'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\n'+
        'cp '+' '.join('/runner/'+n for n in guest_files)+' "$root/usr/local/share/desktop574/"\n'+
        'cc -std=c11 -O2 -Wall -Wextra -Werror /runner/a11y_driver.c -o "$root/usr/local/bin/welcome-a11y" '+
        '$(pkg-config --cflags --libs atspi-2 gobject-2.0)')
    fixture=replace(fixture,'TimeoutStartSec=650','TimeoutStartSec=1200')
    (output/'desktop574_fixture.sh').write_text(fixture)
    runtime=(source/'scripts/ci/desktop574_runtime.py').read_text()
    runtime=replace(runtime,'import time\n','import time\nfrom contract import verify_result, verify_source\nimport candidates\n')
    runtime=replace(runtime,'    require(not out.exists()',
        '    verify_source(source)\n    candidate_root=Path(__file__).with_name("candidates")\n'
        '    candidate_lock=candidates.read(candidate_root/"candidate-lock.json")\n'
        '    require(candidate_lock["status"]=="VERIFIED_NATIVE_CANDIDATES", "verified staged candidates required")\n'
        '    for row in candidate_lock["products"].values():\n'
        '        candidates.regular(candidate_root/row["archive"],8*1024**2)\n'
        '        require(candidates.digest(candidate_root/row["archive"])==row["sha256"],"staged candidate hash differs")\n'
        '    require(not out.exists()')
    runtime=replace(runtime,"report = {'status': 'FAIL',", "report = {'status': 'FAIL', 'workflow_scope': 'installed-welcome-doctor-managed-gui', 'candidate_input': candidate_lock, 'physical_input': 'NOT_RUN', 'visual_review': 'NOT_RUN',")
    runtime=replace(runtime,'        expected = base |',
        '        products=context/"products";products.mkdir()\n'
        '        for row in candidate_lock["products"].values():shutil.copyfile(candidate_root/row["archive"],products/row["archive"])\n'
        '        expected = {n:row["version"] for n,row in candidate_lock["products"].items()} | base |')
    runtime=replace(runtime,'COPY desktop.pkg.tar.zst /tmp/project/desktop.pkg.tar.zst\\n',
                    'COPY desktop.pkg.tar.zst /tmp/project/desktop.pkg.tar.zst\\nCOPY products/ /tmp/products/\\n')
    runtime=replace(runtime,'/tmp/project/desktop.pkg.tar.zst && ldconfig',
                    '/tmp/project/desktop.pkg.tar.zst /tmp/products/*.pkg.tar.xz && ldconfig')
    runtime=replace(runtime,'rm -rf /tmp/tooling /tmp/project /tmp/project.conf',
                    'rm -rf /tmp/tooling /tmp/project /tmp/products /tmp/project.conf')
    runtime=replace(runtime,'cachy_asahi_virtual_proof=1',
                    'cachy_asahi_virtual_proof=1 cachy_asahi_managed_user=1 cachy_asahi_welcome_gui=1')
    runtime=replace(runtime,'deadline = time.monotonic() + 700','deadline = time.monotonic() + 1300')
    frames=tuple(stage+'-'+view for stage in ('minimal','overlay') for view in
                 ('home','terminal-action','files-action','system','first-steps','updates','recovery'))
    runtime=replace(runtime,"                    stage = event.get('stage')",
        "                    stage = str(event.get('stage'))+'-'+str(event.get('view'))")
    runtime=replace(runtime,"stage in ('minimal', 'overlay') and stage not in report['frames']",
                    'stage in '+repr(frames)+" and stage not in report['frames']")
    runtime=replace(runtime,"set(report['frames']) == phases", "set(report['frames']) == set("+repr(frames)+')')
    runtime=replace(runtime,"        active.finish(); active = None\n        report['status']",
        "        active.finish(); active = None\n        report['gui_contract'] = verify_result(report['events'],candidate_lock)\n        report['status']")
    if runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION')!=2:raise ValueError('GUI status anchors differ')
    runtime=runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION','PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_METADATA')
    runtime=replace(runtime,'Same-job native574 configuration and generic QEMU software session exercise.',
                    'Installed original Welcome GUI/Doctor trial on the managed generic ARM runtime.')
    (output/'desktop574_runtime.py').write_text(runtime)
    shutil.copyfile(source/'scripts/ci/test_desktop574_runtime.py',output/'test_desktop574_runtime.py')
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','assets'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(prepare(args.source.resolve(),args.output.resolve(),args.assets.resolve()))
