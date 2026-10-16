#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a fresh runnable source-only lane; never execute its native actors."""
import argparse
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
    for name in ('session.py', 'desktop574_guest.py', 'contract.py', 'source-pins.json', 'package-inputs.json'):
        shutil.copyfile(HERE / name, output / name)
    guest = (source / 'scripts/ci/desktop574_guest.py').read_text()
    guest = replace(guest, 'session.wait(timeout=480)', 'session.wait(timeout=650)')
    (output / 'base_guest.py').write_text(guest)
    fixture = (source / 'scripts/ci/desktop574_fixture.sh').read_text()
    fixture = replace(fixture,
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"',
        'cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"\n'
        'cp /runner/base_guest.py /runner/session.py "$root/usr/local/share/desktop574/"')
    fixture = replace(fixture, 'TimeoutStartSec=650', 'TimeoutStartSec=850')
    (output / 'desktop574_fixture.sh').write_text(fixture)
    runtime = (source / 'scripts/ci/desktop574_runtime.py').read_text()
    runtime = replace(runtime, "report = {'status': 'FAIL',",
        "report = {'status': 'FAIL', 'rendering_mode': 'reload-assisted', "
        "'cold_start_body_rendering': 'NOT_ESTABLISHED',")
    runtime = replace(runtime, 'import time\n', 'import time\nfrom contract import verify_source, verify_result, verify_package_input\n')
    runtime = replace(runtime, '    require(not out.exists()', '    verify_source(source)\n    require(not out.exists()')
    runtime = replace(runtime, "        observed = inventory(",
        "        verify_package_input(json.loads(Path(__file__).with_name('package-inputs.json').read_text()), base)\n"
        "        observed = inventory(")
    runtime = replace(runtime, 'cachy_asahi_virtual_proof=1',
        'cachy_asahi_virtual_proof=1 cachy_asahi_bar_notifications=1')
    runtime = replace(runtime, 'deadline = time.monotonic() + 700', 'deadline = time.monotonic() + 900')
    runtime = replace(runtime, "        active.finish(); active = None\n        report['status']",
        "        active.finish(); active = None\n        verify_result(report['events'])\n        report['status']")
    if runtime.count('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION') != 2:
        raise ValueError('base acceptance anchors differ')
    runtime = runtime.replace('PASS_NATIVE_CONFIGURATION_AND_GENERIC_SOFTWARE_SESSION',
                              'PASS_RELOAD_ASSISTED_BAR_NOTIFICATION_DIAGNOSTIC')
    runtime = replace(runtime, 'Same-job native574 configuration and generic QEMU software session exercise.',
        'Reload-assisted Waybar/Mako diagnostic; cold-start body rendering NOT_ESTABLISHED.')
    (output / 'desktop574_runtime.py').write_text(runtime)
    shutil.copyfile(source / 'scripts/ci/test_desktop574_runtime.py', output / 'test_desktop574_runtime.py')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.source.resolve(), args.output.resolve()))
