# SPDX-License-Identifier: MIT
"""Check exact-object Git command boundaries with inert results."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/port/kernel-native-job'))
import packet
import packet_v2
import packet_v3
from test_public import bootstrap


class GitBindingTests(unittest.TestCase):
    def test_inline_git_helper_disables_replacement_refs(self):
        inline = bootstrap()
        with (patch.dict(os.environ, {'RUNNER_TEMP': '/inert/private-git-home'}),
              patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout=b'blob', stderr=b'')) as run):
            self.assertEqual(inline['git'](ROOT, 'cat-file', 'blob', 'a' * 40), b'blob')
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ['/usr/bin/git', '--no-replace-objects'])
        self.assertEqual(argv[-3:], ['cat-file', 'blob', 'a' * 40])

    def test_packet_verifiers_disable_replacement_refs_for_manifest_and_payload(self):
        commit = 'a' * 40
        name, content = 'held.txt', b'ordinary source fixture\n'
        for version, module, manifest_name in (
                ('v1', packet, packet.PREFIX + 'packet.lock.json'),
                ('v2', packet_v2, packet_v2.MANIFEST),
                ('v3', packet_v3, packet_v3.MANIFEST)):
            with (self.subTest(version=version), TemporaryDirectory(prefix='kernel-git-binding-') as temporary,
                  patch.dict(os.environ, {'GITHUB_SHA': commit, 'GITHUB_WORKFLOW_SHA': commit})):
                root = Path(temporary) / 'root'
                manifest = root / manifest_name
                manifest.parent.mkdir(parents=True)
                payload = root / name
                payload.write_bytes(content)
                payload.chmod(0o644)
                body = json.dumps({'schema_version': 1, 'files': {name: packet.row(content, 0o644)}}).encode()
                manifest.write_bytes(body)
                manifest.chmod(0o644)
                output = Path(temporary) / 'snapshot'
                calls = []

                def run(argv, *, timeout, limit):
                    self.assertEqual(argv[:2], ['/usr/bin/git', '--no-replace-objects'])
                    verb, *args = argv[argv.index('-C') + 2:]
                    calls.append((verb, args[-1]))
                    if verb == 'show':
                        stdout = {commit + ':' + manifest_name: body, commit + ':' + name: content}[args[-1]]
                    elif verb == 'ls-tree':
                        stdout = b'100644\n'
                    else:
                        self.assertEqual((verb, args), ('rev-parse', ['--verify', 'HEAD']))
                        stdout = (commit + '\n').encode()
                    return SimpleNamespace(returncode=0, stdout=stdout)

                runner = SimpleNamespace(run=run)
                if module is packet:
                    with patch.multiple(packet, closure=lambda root: ({name}, {}, {}), frozen=lambda *args: None):
                        result = module.verify(root, manifest, packet.sha(body), commit, runner, output)
                else:
                    policy = module._policy()
                    policy.closure = lambda root: ({name}, {}, {})
                    policy.frozen = lambda *args: None
                    with patch.object(module, '_policy', return_value=policy):
                        result = module.verify(root, manifest, packet.sha(body), commit, runner, output)
                payload_calls = [('rev-parse', 'HEAD'), ('show', commit + ':' + name), ('ls-tree', name)]
                manifest_calls = [('show', commit + ':' + manifest_name), ('ls-tree', manifest_name)]
                self.assertEqual(calls, (manifest_calls if version == 'v3' else []) + payload_calls)
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual(packet.capture(output / name), (content, 0o644))


if __name__ == '__main__':
    unittest.main()
