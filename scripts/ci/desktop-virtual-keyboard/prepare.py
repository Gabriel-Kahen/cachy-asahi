#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a separate input candidate; no VM, native compiler or Docker actors."""
import argparse
import ast
import importlib.util
from pathlib import Path
import shutil
from contract import verify_source
import keyboard as K
HERE=Path(__file__).resolve().parent


def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('keyboard source anchor differs: '+old[:80])
    return text.replace(old,new)


def prepare(source,output):
    source,output=Path(source),Path(output);verify_source(source)
    K.need(not output.exists() and not output.is_symlink(),'fresh keyboard runner required');output.mkdir(mode=0o700)
    names=('desktop574_guest.py','session.py','keyboard.py','compositor_log.py','observed.py','terminal_session.py','terminal_workflow.py',
           'managed_session.py','managed_contract.py','contract.py','source-pins.json','prerequisites.py','prerequisites.json')
    for name in names:shutil.copyfile(HERE/name,output/name)
    spec=importlib.util.spec_from_file_location('accepted_keyboard_managed_prepare',source/'scripts/ci/desktop-user-session/prepare.py')
    managed=importlib.util.module_from_spec(spec);spec.loader.exec_module(managed)
    guest=managed.transform_guest((source/'scripts/ci/desktop574_guest.py').read_text())
    guest=replace(guest,'session.wait(timeout=480)','session.wait(timeout=1080)')
    anchor="        command(['/usr/bin/modprobe', 'virtio_gpu'], env, logs, 'virtio-gpu')"
    guest=replace(guest,anchor,"        command(['/usr/bin/modprobe', 'virtio_input'], env, logs, 'virtio-input')\n"
                  "        command(['/usr/bin/udevadm', 'settle', '--timeout=15'], env, logs, 'input-udev')\n"+anchor)
    (output/'base_guest.py').write_text(guest)
    fixture=(source/'scripts/ci/desktop574_fixture.sh').read_text()
    fixture=replace(fixture,'root=/out/staged','python3 -I -B /runner/prerequisites.py\nroot=/out/staged')
    fixture=replace(fixture,'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service',
                    'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service')
    fixture=replace(fixture,'After=basic.target systemd-udev-trigger.service',
                    'After=basic.target systemd-udev-trigger.service systemd-user-sessions.service')
    fixture=replace(fixture,'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
                    'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\ncp '+
                    ' '.join('/runner/'+n for n in ('base_guest.py','session.py','keyboard.py','compositor_log.py','observed.py','terminal_session.py',
                    'terminal_workflow.py','managed_session.py'))+' "$root/usr/local/share/desktop574/"')
    fixture=replace(fixture,'> "$root/usr/local/share/desktop574/minimal.lua"',
                    '> "$root/usr/local/share/desktop574/minimal.lua"\n'+
                    "printf '%s\\n' 'hl.config({ input = { kb_layout = \"us\" } })' "+
                    "'hl.bind(\"SUPER + RETURN\", hl.dsp.exec_cmd(\"alacritty\"))' "+
                    "'hl.bind(\"SUPER + Q\", hl.dsp.window.close())' >> \"$root/usr/local/share/desktop574/minimal.lua\"")
    fixture=replace(fixture,'TimeoutStartSec=650','TimeoutStartSec=1200')
    (output/'desktop574_fixture.sh').write_text(fixture)
    runtime=(source/'scripts/ci/desktop574_runtime.py').read_text()
    runtime=replace(runtime,'import time\n','import time\nfrom contract import verify_source, verify_result\nfrom keyboard import Controller\n')
    runtime=replace(runtime,'    require(not out.exists()','    verify_source(source)\n    require(not out.exists()')
    runtime=replace(runtime,"report = {'status': 'FAIL',","report = {'status': 'FAIL', 'workflow_scope': 'managed-virtual-keyboard', 'physical_input': 'NOT_RUN',")
    runtime=replace(runtime,'    qmp = None','    qmp = None\n    keyboard_controller = Controller()')
    runtime=replace(runtime,'-device virtio-gpu-pci,id=gpu,xres=1024,yres=768',
                    '-device virtio-gpu-pci,id=gpu,xres=1024,yres=768 -device virtio-keyboard-pci,id=keyboard')
    runtime=replace(runtime,'cachy_asahi_virtual_proof=1','cachy_asahi_virtual_proof=1 cachy_asahi_managed_user=1 cachy_asahi_virtual_keyboard=1')
    runtime=replace(runtime,'deadline = time.monotonic() + 700','deadline = time.monotonic() + 1300')
    runtime=replace(runtime,"                if event.get('event') == 'frame_ready':",
                    "                if event.get('event') == 'keyboard_request':\n"
                    "                    require(qmp is not None, 'QMP keyboard not ready')\n"
                    "                    report['events'].append(keyboard_controller.handle(qmp,event))\n"
                    "                if event.get('event') == 'frame_ready':")
    runtime=replace(runtime,"                if event.get('event') == 'frame_ready':",
                    "                if event.get('event') == 'keyboard_failure_diagnostic':\n"
                    "                    phase = event.get('stage')\n"
                    "                    require(phase in ('minimal','overlay') and event.get('diagnostic_only') is True and event.get('success_evidence') is False, 'invalid keyboard diagnostic')\n"
                    "                    if event.get('capture_requested') is True:\n"
                    "                        try:\n"
                    "                            require(qmp is not None and event.get('nonce') == keyboard_controller.nonces.get(phase), 'failure capture identity differs')\n"
                    "                            require(phase not in report.setdefault('failure_frames',{}), 'duplicate failure capture')\n"
                    "                            leaf = phase + '-failure.ppm'\n"
                    "                            qmp.execute('screendump', {'filename': '/out/' + leaf})\n"
                    "                            metadata = ppm(fixture / leaf)\n"
                    "                            shutil.copyfile(fixture / leaf, frames / leaf)\n"
                    "                            report['failure_frames'][phase] = dict(metadata, nonce=event['nonce'], last_step=event.get('last_step'), diagnostic_only=True)\n"
                    "                        except Exception as error:\n"
                    "                            report.setdefault('failure_frame_errors',[]).append(type(error).__name__ + ': ' + str(error)[:256])\n"
                    "                if event.get('event') == 'frame_ready':")
    runtime=replace(runtime,"stage in ('minimal', 'overlay') and stage not in report['frames']",
                    'stage in '+repr(K.FRAMES)+" and stage not in report['frames']")
    runtime=replace(runtime,"set(report['frames']) == phases",'set(report[\'frames\']) == set('+repr(K.FRAMES)+')')
    runtime=replace(runtime,"        active.finish(); active = None\n        report['status']",
                    "        active.finish(); active = None\n        report['keyboard_contract'] = verify_result(report['events'])\n        report['status']")
    K.need(runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION')==2,'runtime status anchors differ')
    runtime=runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION',K.STATUS)
    (output/'desktop574_runtime.py').write_text(runtime)
    shutil.copyfile(source/'scripts/ci/test_desktop574_runtime.py',output/'test_desktop574_runtime.py')
    for path in output.glob('*.py'):ast.parse(path.read_bytes())
    return output


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(prepare(a.source.resolve(),a.output.resolve()))
