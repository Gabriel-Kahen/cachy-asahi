# SPDX-License-Identifier: MIT
"""Bind current job source and reconstruct the reviewed kernel producer inputs."""
from pathlib import Path
import re
from types import ModuleType

import packet

MANIFEST = 'scripts/port/kernel-native-job-v2/packet.lock.json'
CHECKER = 'scripts/checks/package_checks.py'
CHECKER_SHA = '306ea3dfa1ce4eb14796c0526a8ca9086043bdcb8e6698c0993d640d076f19cd'
PARENT_SHA = '3cc6631797d804086686e88ddd2240455561420430bedb4ea6e4ce9eade9c53f'
SETUP = 'packages/settings/cachy-asahi-setup'
ENROLL = 'scripts/repository/enroll.py'
HELD_SETUP = 'scripts/port/kernel-native-job-v2/setup-producer-source.json'
HELD_SETUP_SHA = '466eb04d1c3f7402c04ce8bd311cf141e29d9a59d3b7e1206a2cfa34b89e7366'
SETUP_PINS = {
    '.SRCINFO': 'e8802c5182975d37ea40bea2d93990dd19eb2712edc7bf486ed7d14f3774dce0',
    'PKGBUILD': '8b315d064c96cbfe341adb09c13110c62993e3d61915d2313dae8ddcaa8ebabd',
    'check-sync.py': '9097a0743e0f86827b97da2e5a4e29dca74c787b5c1fa9afe9f4e5b316080138',
    'test-sync.py': '484fde2423e3c8c7be6faefc824d62e3f9e23eec260363ef7beaf2ebc53f1381',
}


def _policy():
    path = Path(__file__).with_name('packet.py')
    body = packet.read(path, 32 * 1024)
    packet.need(packet.sha(body) == PARENT_SHA, 'packet-parent-policy')
    # Keep the v1 policy used by intake and #622 isolated from this substitution.
    policy = ModuleType('kernel_native_packet_v2_policy')
    exec(compile(body, str(path), 'exec'), vars(policy))
    # The live recipe reads the vendored enrollment member. The historical
    # producer gets its own verified copy at the original source path below.
    policy.HELPERS.pop(ENROLL)
    policy.HELPERS.update({CHECKER: (CHECKER_SHA, 0o644), HELD_SETUP: (HELD_SETUP_SHA, 0o644)})
    inherited_closure = policy.closure

    def closure(root):
        names, kernel, recipes = inherited_closure(root)
        policy.need(SETUP_PINS.keys() <= recipes[SETUP].keys(), 'packet-v2-setup-scope')
        recipes[SETUP].update(SETUP_PINS)
        return names, kernel, recipes

    policy.closure = closure
    return policy


def preview(root):
    return _policy().preview(root)


def verify(root, manifest_path, manifest_sha, commit, runner, output):
    packet.need(manifest_path == root / MANIFEST, 'packet-v2-path')
    packet.need(type(manifest_sha) is str and re.fullmatch(r'[0-9a-f]{64}', manifest_sha), 'packet-pin')
    return _policy().verify(root, manifest_path, manifest_sha, commit, runner, output)


def producer_snapshot(source, output, rows):
    """Build an independent producer view with the exact historical recipe lock."""
    recipes = packet.load(source / packet.RECIPES_LOCK, packet.RECIPES_SHA)
    held = packet.load(source / HELD_SETUP, HELD_SETUP_SHA)
    packet.need(held.keys() == SETUP_PINS.keys() and all(type(value) is str for value in held.values()),
                'packet-v2-held-setup')
    restored = {f'{SETUP}/{name}': value.encode() for name, value in held.items()}
    for name, raw in restored.items():
        packet.need(packet.sha(raw) == recipes[SETUP][Path(name).name], 'packet-v2-held-setup')
    enrollment, enrollment_mode = packet.capture(source / SETUP / 'cachy-asahi-repository')
    packet.need((packet.sha(enrollment), enrollment_mode) == packet.HELPERS[ENROLL], 'packet-v2-held-enrollment')
    packet.need(restored.keys() <= rows.keys() and ENROLL not in rows, 'packet-v2-producer-source')

    output.mkdir(mode=0o700)
    for name, expected in rows.items():
        relative = packet.relative(name)
        data, file_mode = packet.capture(source / relative)
        packet.need(packet.row(data, file_mode) == expected, 'packet-v2-producer-copy')
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(restored.get(name, data))
        target.chmod(file_mode)
    target = output / ENROLL
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(enrollment)
    target.chmod(enrollment_mode)
    return output
