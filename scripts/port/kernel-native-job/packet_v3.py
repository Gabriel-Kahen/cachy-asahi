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
PARENT_SHA = '4d69abec079102b2f0ad1566961dd3e663a19ca5668cb5d68215f97bbdced68e'
BUILD_HELPERS = {
    'scripts/build/build.py': ('bb1d506ee443102073b4265d848b505afa18a5176af10780de487731529a137f', 0o644),
    'scripts/build/compare.py': ('f28a02dd1b19847df8870e2ded18117c39d11e7d62d990b68292e37c11f19d9a', 0o644),
}


def _policy():
    parent = Path(__file__).with_name('packet_v2.py')
    packet.need(packet.sha(packet.read(parent, 32 * 1024)) == PARENT_SHA, 'packet-v3-parent-policy')
    policy = packet_v2._policy()
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
    body, mode = packet.capture(manifest_path, 1024**2)
    packet.need(mode == 0o644 and packet.sha(body) == manifest_sha, 'packet-pin')
    git = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
           '--no-optional-locks', '-C', str(root)]
    blob = runner.run(git + ['show', commit + ':' + MANIFEST], timeout=10, limit=1024**2)
    tree = runner.run(git + ['ls-tree', '--format=%(objectmode)', commit, '--', MANIFEST],
                      timeout=10, limit=4096)
    packet.need(blob.returncode == tree.returncode == 0 and blob.stdout == body
                and tree.stdout == b'100644\n', 'packet-v3-manifest-Git-binding')
    return _policy().verify(root, manifest_path, manifest_sha, commit, runner, output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(preview(args.root), sort_keys=True, indent=2, allow_nan=False))
