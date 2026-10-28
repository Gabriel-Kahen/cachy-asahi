#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a fresh runnable source-only lane; never execute its native actors."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
from contract import verify_source

HERE = Path(__file__).resolve().parent


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError('base adapter anchor differs: ' + old[:80])
    return text.replace(old, new)


def prepare(source, output):
    verify_source(source)
    if output.exists() or output.is_symlink():
        raise ValueError('fresh stage required')
    output.mkdir(mode=0o700)
    for name in ('session.py', 'desktop574_guest.py', 'contract.py', 'capture.py', 'source-pins.json', 'package-inputs.json'):
        shutil.copyfile(HERE / name, output / name)
    managed_dir = source / 'scripts/ci/desktop-user-session'
    spec = importlib.util.spec_from_file_location('bar_managed_prepare', managed_dir / 'prepare.py')
    managed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(managed)
    for name in ('managed_session.py', 'managed_contract.py'):
        shutil.copyfile(managed_dir / name, output / name)
    guest = (source / 'scripts/ci/desktop574_guest.py').read_text()
    guest = managed.transform_guest(guest)
    guest = replace(guest, 'session.wait(timeout=480)', 'session.wait(timeout=650)')
    (output / 'base_guest.py').write_text(guest)
    fixture = (source / 'scripts/ci/desktop574_fixture.sh').read_text()
    fixture = replace(fixture,
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\n'
        'cp /runner/base_guest.py /runner/session.py /runner/managed_session.py "$root/usr/local/share/desktop574/"')
    fixture = replace(fixture, 'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service',
        'Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture, 'After=basic.target systemd-udev-trigger.service',
        'After=basic.target systemd-udev-trigger.service systemd-user-sessions.service')
    fixture = replace(fixture, 'TimeoutStartSec=650', 'TimeoutStartSec=850')
    (output / 'desktop574_fixture.sh').write_text(fixture)
    runtime = (source / 'scripts/ci/desktop574_runtime.py').read_text()
    runtime = replace(runtime, 'import time\n', 'import time\nfrom contract import verify_source, verify_result, verify_package_input\nfrom capture import capture_frame\nfrom session import trace_command\n')
    runtime = replace(runtime, '    require(not out.exists()', '    verify_source(source)\n    require(not out.exists()')
    runtime = replace(runtime, "    parser.add_argument('--output', type=Path, required=True)",
        "    parser.add_argument('--output', type=Path, required=True)\n"
        "    parser.add_argument('--trace-waybar',action='store_true',help='explicit diagnostic G_DBUS_DEBUG=call; default ordinary startup')")
    runtime = replace(runtime, "report = {'status': 'FAIL',", "report = {'status': 'FAIL', 'trace_waybar': args.trace_waybar,")
    runtime = replace(runtime, 'cmd = qemu_command(derived, name, fixture, source, runner)',
        'cmd = trace_command(qemu_command(derived, name, fixture, source, runner), args.trace_waybar)')
    runtime = replace(runtime, "        observed = inventory(",
        "        verify_package_input(json.loads(Path(__file__).with_name('package-inputs.json').read_text()), base)\n"
        "        observed = inventory(")
    runtime = replace(runtime, 'cachy_asahi_virtual_proof=1',
        'cachy_asahi_virtual_proof=1 cachy_asahi_bar_notifications=1 cachy_asahi_managed_user=1')
    runtime = replace(runtime,
        "                    qmp.execute('screendump', {'filename': '/out/' + stage + '.ppm'})\n"
        "                    report['frames'][stage] = ppm(fixture / (stage + '.ppm'))\n"
        "                    shutil.copyfile(fixture / (stage + '.ppm'), frames / (stage + '.ppm'))",
        '                    capture_frame(event, qmp, fixture, frames, report, ppm)')
    runtime = replace(runtime, 'deadline = time.monotonic() + 700', 'deadline = time.monotonic() + 900')
    runtime = replace(runtime, "        active.finish(); active = None\n        report['status']",
        "        active.finish(); active = None\n        verify_result(report['events'])\n        report['status']")
    if runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION') != 2:
        raise ValueError('base acceptance anchors differ')
    runtime = replace(runtime, "        verify_result(report['events'])\n",
        "        require(all(e.get('trace_waybar') is args.trace_waybar for e in report['events'] if e.get('event')=='frame_ready'), 'host/guest Waybar trace selection differs')\n"
        "        verify_result(report['events'])\n")
    runtime = runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION',
                              'PASS_BAR_NOTIFICATION_GENERIC_ARM_SMOKE')
    runtime = replace(runtime, 'Same-job native574 configuration and generic QEMU software session exercise.',
        'Separate optional Waybar/Mako generic ARM smoke; no hardware claim.')
    (output / 'desktop574_runtime.py').write_text(runtime)
    shutil.copyfile(source / 'scripts/ci/test_desktop574_runtime.py', output / 'test_desktop574_runtime.py')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.source.resolve(), args.output.resolve()))
