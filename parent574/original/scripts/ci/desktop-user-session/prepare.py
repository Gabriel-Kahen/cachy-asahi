#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage an explicit managed-session candidate; never execute fixture/VM actors."""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError('managed source anchor differs: ' + old[:80])
    return text.replace(old, new)


def transform_guest(text):
    text = replace(text, "RUNTIME = Path('/run/desktop574/runtime')", "RUNTIME = Path('/run/user/23001')")
    text = replace(text, '    seatd = session = None\n', '    seatd = session = None\n    manager = None\n')
    text = replace(text, '        for path in (HOME, RUNTIME):', '        for path in (HOME,):')
    anchor = "        command(['/usr/bin/modprobe', 'virtio_gpu'], env, logs, 'virtio-gpu')"
    text = replace(text, anchor, '        manager = managed_session.ManagedSession(managed_base, logs, env)\n'
                   '        env.update(manager.start())\n' + anchor)
    text = replace(text, "               DBUS_SESSION_BUS_ADDRESS=os.environ['DBUS_SESSION_BUS_ADDRESS'])",
                   "               DBUS_SESSION_BUS_ADDRESS=os.environ['DBUS_SESSION_BUS_ADDRESS'])\n"
                   '    managed_session.validate_user(managed_base, logs, env)')
    text = replace(text, "session = subprocess.Popen(['/usr/bin/runuser', '-u', 'desktop574', '--',\n"
                   "            '/usr/bin/dbus-run-session', '--', '/usr/bin/python3', '-I', '-B', str(SHARE / 'guest.py'), 'user'],",
                   "session = subprocess.Popen(managed_session.SETPRIV +\n"
                   "            ['/usr/bin/python3', '-I', '-B', str(SHARE / 'guest.py'), 'user'],")
    text = replace(text, '    finally:\n        for child in (session, seatd.process if seatd else None):',
                   '    finally:\n        if first is not None and manager is not None:\n'
                   '            try:\n                manager.diagnose()\n'
                   '            except BaseException:\n                pass  # Original failure stays primary.\n'
                   '        for child in (session, seatd.process if seatd else None):')
    text = replace(text, "        try:\n            if first is None:\n                emit('complete'",
                   '        if manager is not None:\n            try:\n                manager.stop()\n'
                   '            except BaseException as error:\n                if first is None:\n                    first = error\n'
                   '                try:\n                    manager.diagnose()\n'
                   '                except BaseException:\n                    pass  # Cleanup remains failed.\n'
                   "        try:\n            if first is None:\n                emit('complete'")
    ast.parse(text)
    return text


def prepare(source, output):
    source, output = Path(source), Path(output)
    spec = importlib.util.spec_from_file_location('managed_stage_contract', HERE / 'managed_contract.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_source(source)
    if output.exists() or output.is_symlink():
        raise ValueError('fresh managed runner required')
    output.mkdir(mode=0o700)
    for name in ('managed_session.py', 'managed_contract.py', 'source-pins.json'):
        shutil.copyfile(HERE / name, output / name)
    shutil.copyfile(HERE / 'managed_guest.py', output / 'desktop574_guest.py')
    (output / 'base_guest.py').write_text(transform_guest((source / 'scripts/ci/desktop574_guest.py').read_text()))
    fixture = (source / 'scripts/ci/desktop574_fixture.sh').read_text()
    fixture = replace(fixture, 'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service',
                      'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture, 'After=basic.target systemd-udev-trigger.service',
                      'After=basic.target systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture, 'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
                      'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\n'
                      'cp /runner/base_guest.py /runner/managed_session.py "$root/usr/local/share/desktop574/"')
    (output / 'desktop574_fixture.sh').write_text(fixture)
    runtime = (source / 'scripts/ci/desktop574_runtime.py').read_text()
    runtime = replace(runtime, 'import time\n', 'import time\nfrom managed_contract import verify_source, verify_result\n')
    runtime = replace(runtime, '    require(not out.exists()', '    verify_source(source)\n    require(not out.exists()')
    runtime = replace(runtime, 'cachy_asahi_virtual_proof=1', 'cachy_asahi_virtual_proof=1 cachy_asahi_managed_user=1')
    runtime = replace(runtime, "        active.finish(); active = None\n        report['status']",
                      "        active.finish(); active = None\n        report['managed_session'] = verify_result(report['events'])\n        report['status']")
    if runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION') != 2:
        raise ValueError('runtime acceptance anchors differ')
    runtime = runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION', 'PASS_MANAGED_USER_GENERIC_ARM_SESSION')
    (output / 'desktop574_runtime.py').write_text(runtime)
    for path in output.glob('*.py'):
        ast.parse(path.read_bytes())
    receipt = {'profile': 'OPT_IN_MANAGED_USER_VM', 'native_run': 'NOT RUN', 'hardware': 'NOT RUN',
               'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir())}}
    (output / 'profile.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.source.resolve(), args.output.resolve()))
