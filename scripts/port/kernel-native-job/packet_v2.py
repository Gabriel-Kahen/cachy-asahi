# SPDX-License-Identifier: MIT
"""Select the reviewed current checker under the historical packet policy."""
from pathlib import Path
import re
from types import ModuleType

import packet

MANIFEST = 'scripts/port/kernel-native-job-v2/packet.lock.json'
CHECKER = 'scripts/checks/package_checks.py'
CHECKER_SHA = '306ea3dfa1ce4eb14796c0526a8ca9086043bdcb8e6698c0993d640d076f19cd'
PARENT_SHA = '3cc6631797d804086686e88ddd2240455561420430bedb4ea6e4ce9eade9c53f'


def _policy():
    path = Path(__file__).with_name('packet.py')
    body = packet.read(path, 32 * 1024)
    packet.need(packet.sha(body) == PARENT_SHA, 'packet-parent-policy')
    # Keep the v1 policy used by intake and #622 isolated from this substitution.
    policy = ModuleType('kernel_native_packet_v2_policy')
    exec(compile(body, str(path), 'exec'), vars(policy))
    policy.HELPERS = {**policy.HELPERS, CHECKER: (CHECKER_SHA, 0o644)}
    return policy


def preview(root):
    return _policy().preview(root)


def verify(root, manifest_path, manifest_sha, commit, runner, output):
    packet.need(manifest_path == root / MANIFEST, 'packet-v2-path')
    packet.need(type(manifest_sha) is str and re.fullmatch(r'[0-9a-f]{64}', manifest_sha), 'packet-pin')
    return _policy().verify(root, manifest_path, manifest_sha, commit, runner, output)
