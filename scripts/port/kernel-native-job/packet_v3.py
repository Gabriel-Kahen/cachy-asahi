# SPDX-License-Identifier: MIT
"""Prepare or verify the kernel packet with the reviewed build helpers."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packet
import packet_v2


MANIFEST = 'scripts/port/kernel-native-job-v3/packet.lock.json'
MANIFEST_LIMIT = 1024**2
KERNEL_LOCK = 'scripts/port/kernel-native-job-v3/stage.lock.json'
KERNEL_SHA = '65e7e39d5a7e236407a835f741d3e4b274634763ff238b0437675571c4e13fc9'
PARENT_SHA = '2fd77c8d22c322008f9f43d9b574fd797d6bd52be4ab26463699a165134ce9c6'
BUILD_HELPERS = {
    'scripts/build/build.py': ('a90ee5930f600de37d8af2ef0135be3c3d5ff08173207da8e465b60517467ce2', 0o644),
    'scripts/build/compare.py': ('f28a02dd1b19847df8870e2ded18117c39d11e7d62d990b68292e37c11f19d9a', 0o644),
    'scripts/build/container-entry.sh': ('558ab9333301807c740bfe6e782907c8d20aafc57ebabfa9889816a6e44da529', 0o644),
}


def _policy():
    parent = Path(__file__).with_name('packet_v2.py')
    packet.need(packet.sha(packet.read(parent, 32 * 1024)) == PARENT_SHA, 'packet-v3-parent-policy')
    policy = packet_v2._policy()
    policy.KERNEL_LOCK, policy.KERNEL_SHA = KERNEL_LOCK, KERNEL_SHA
    policy.HELPERS.update(BUILD_HELPERS)
    policy.HELPERS.update({packet.PREFIX + 'packet.py': (packet_v2.PARENT_SHA, 0o644),
                           packet.PREFIX + 'packet_v2.py': (PARENT_SHA, 0o644)})
    return policy


def preview(root):
    return _policy().preview(root)


def verify(root, manifest_path, manifest_sha, commit, runner, output):
    packet.need(manifest_path == root / MANIFEST, 'packet-v3-path')
    packet.need(type(manifest_sha) is str and re.fullmatch(r'[0-9a-f]{64}', manifest_sha), 'packet-pin')
    packet.need(type(commit) is str and re.fullmatch(r'[0-9a-f]{40}', commit)
                and os.environ.get('GITHUB_SHA') == commit
                and os.environ.get('GITHUB_WORKFLOW_SHA') == commit, 'packet-workflow-commit')
    held = packet.capture(manifest_path, MANIFEST_LIMIT)
    body, mode = held
    packet.need(mode == 0o644 and packet.sha(body) == manifest_sha, 'packet-pin')
    git = packet.git_command(root)
    blob = runner.run(git + ['show', commit + ':' + MANIFEST], timeout=10, limit=MANIFEST_LIMIT)
    tree = runner.run(git + ['ls-tree', '--format=%(objectmode)', commit, '--', MANIFEST],
                      timeout=10, limit=4096)
    packet.need(blob.returncode == tree.returncode == 0 and blob.stdout == body
                and tree.stdout == b'100644\n', 'packet-v3-manifest-Git-binding')
    policy = _policy()
    original_load = policy.load

    def recheck():
        packet.need(packet.capture(manifest_path, MANIFEST_LIMIT) == held, 'packet-v3-manifest-race')

    def load(path, pin=None):
        if path != manifest_path:
            return original_load(path, pin)
        packet.need(pin == manifest_sha, 'packet-pin')
        recheck()
        return packet.decode(body)

    policy.load = load
    verified = policy.verify(root, manifest_path, manifest_sha, commit, runner, output)
    recheck()
    return verified


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(preview(args.root), sort_keys=True, indent=2, allow_nan=False))
