#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the combined managed-user workflow without any native actors."""
import argparse
import importlib.util
from pathlib import Path
import shutil
from contract import verify_source

HERE = Path(__file__).resolve().parent


def replace(text, old, new):
    if text.count(old) != 1:raise ValueError('combined adapter anchor differs: '+old[:80])
    return text.replace(old,new)


def prepare(source, output):
    verify_source(source)
    if output.exists() or output.is_symlink():raise ValueError('fresh combined runner required')
    output.mkdir(mode=0o700)
    names = ('session.py','combined.py','worker.py','terminal_session.py','terminal_workflow.py',
             'open_probe.py','file_manager.py','desktop574_guest.py','managed_session.py','managed_contract.py',
             'contract.py','source-pins.json','package-inputs.json')
    for name in names:shutil.copyfile(HERE/name,output/name)
    spec = importlib.util.spec_from_file_location('accepted_managed_prepare',source/'scripts/ci/desktop-user-session/prepare.py')
    managed = importlib.util.module_from_spec(spec);spec.loader.exec_module(managed)
    guest = managed.transform_guest((source/'scripts/ci/desktop574_guest.py').read_text())
    guest = replace(guest,'session.wait(timeout=480)','session.wait(timeout=1080)')
    (output/'base_guest.py').write_text(guest)
    fixture = (source/'scripts/ci/desktop574_fixture.sh').read_text()
    fixture = replace(fixture,'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service',
                      'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture,'After=basic.target systemd-udev-trigger.service',
                      'After=basic.target systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture,'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\n'+
        'cp '+ ' '.join('/runner/'+n for n in ('base_guest.py','session.py','combined.py','worker.py',
        'terminal_session.py','terminal_workflow.py','open_probe.py','file_manager.py','managed_session.py'))+
        ' "$root/usr/local/share/desktop574/"')
    fixture = replace(fixture,'TimeoutStartSec=650','TimeoutStartSec=1200')
    (output/'desktop574_fixture.sh').write_text(fixture)
    runtime = (source/'scripts/ci/desktop574_runtime.py').read_text()
    runtime = replace(runtime,'import time\n','import time\nfrom contract import verify_source, verify_result, verify_package_input\n')
    runtime = replace(runtime,"report = {'status': 'FAIL',", "report = {'status': 'FAIL', 'workflow_scope': 'managed-co-resident-terminal-file-manager', 'physical_keyboard': 'NOT_RUN', 'rename_ui': 'NOT_RUN', 'editor_ui': 'NOT_RUN', 'co_resident': False,")
    runtime = replace(runtime,'    require(not out.exists()','    verify_source(source)\n    require(not out.exists()')
    runtime = replace(runtime,'        observed = inventory(',
        "        verify_package_input(json.loads(Path(__file__).with_name('package-inputs.json').read_text()), base)\n"+
        '        observed = inventory(')
    runtime = replace(runtime,'cachy_asahi_virtual_proof=1',
        'cachy_asahi_virtual_proof=1 cachy_asahi_managed_user=1 cachy_asahi_terminal_workflow=1 cachy_asahi_file_manager=1 cachy_asahi_managed_workflow=1')
    runtime = replace(runtime,'deadline = time.monotonic() + 700','deadline = time.monotonic() + 1300')
    runtime = replace(runtime,"        active.finish(); active = None\n        report['status']",
        "        active.finish(); active = None\n        report['managed_session'] = verify_result(report['events'])\n        report['co_resident'] = True\n        report['status']")
    if runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION') != 2:raise ValueError('status anchors differ')
    runtime = runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION','PASS_MANAGED_CORESIDENT_APPS_GENERIC_ARM_SMOKE')
    runtime = replace(runtime,'Same-job native574 configuration and generic QEMU software session exercise.',
                      'Real managed user bus with co-resident terminal and Thunar generic ARM workflow.')
    (output/'desktop574_runtime.py').write_text(runtime)
    shutil.copyfile(source/'scripts/ci/test_desktop574_runtime.py',output/'test_desktop574_runtime.py')
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(prepare(args.source.resolve(),args.output.resolve()))
