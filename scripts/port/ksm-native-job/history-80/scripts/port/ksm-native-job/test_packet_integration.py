# SPDX-License-Identifier: MIT
"""Full-source temporary Git fixture; native identity is explicitly synthetic."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location('fixture_' + name, HERE / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    exec(compile((HERE / (name + '.py')).read_bytes(), str(HERE / (name + '.py')), 'exec'), result.__dict__)
    return result


class PacketIntegrationTests(unittest.TestCase):
    def test_workflow_bootstrap_python_compiles_and_refusal_is_terminal(self):
        source = (ROOT / '.github/workflows/native-arm-ksm.yml').read_text()
        start = source.index("          python3 -I -B - <<'PY'\n") + len("          python3 -I -B - <<'PY'\n")
        end = source.index('\n          PY', start)
        body = '\n'.join(line[10:] for line in source[start:end].splitlines())
        tree = ast.parse(body)
        compile(tree, 'reviewed-workflow-bootstrap-fixture', 'exec')
        self.assertIn("raise SystemExit(78 if result['status'] == 'BLOCKED' else 1)", body)
        self.assertNotIn('upload-artifact', source)
        self.assertNotIn('subprocess', body)

    def test_complete_source_packet_is_accepted_but_never_native_pass(self):
        a, required = module('acceptance'), module('required_paths')
        with tempfile.TemporaryDirectory(prefix='ksm-full-packet-fixture-') as temporary:
            root = Path(temporary)
            files = {}
            for name in sorted(required.EXPECTED_PATHS):
                # Receipt/checkpoint fixtures are inert documentation-only files.
                original = ROOT / name
                data = original.read_bytes() if original.exists() else b'{}\n'
                mode = original.stat().st_mode & 0o777 if original.exists() else 0o644
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(mode)
                files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data), 'mode': f'{mode:04o}'}
            packet = root / 'scripts/port/ksm-native-job/packet.lock.json'
            packet.write_text(json.dumps({'schema_version': 1, 'files': files}, sort_keys=True))
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LC_ALL': 'C',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-C', str(root), *args], env=env,
                                               stderr=subprocess.PIPE, timeout=10).decode().strip()
            git('init', '--quiet')
            git('add', '--force', '--all')
            git('-c', 'user.name=Source Fixture', '-c', 'user.email=fixture@invalid',
                '-c', 'commit.gpgSign=false', 'commit', '--quiet', '-m', 'synthetic committed source fixture')
            commit = git('rev-parse', 'HEAD')
            pin = hashlib.sha256(packet.read_bytes()).hexdigest()
            jobenv = {'GITHUB_REPOSITORY': 'Gabriel-Kahen/cachy-asahi', 'GITHUB_SHA': commit,
                      'GITHUB_WORKFLOW_SHA': commit, 'GITHUB_RUN_ID': '1', 'PACKET_SHA256': pin}
            snapshot = a.capture(root, packet, pin, required.EXPECTED_PATHS, required.WORKFLOW, commit, environ=jobenv)
            job = snapshot.module('scripts/port/ksm-native-job/job.py', 'captured_fixture_job', imports={
                'hashlib': hashlib, 'json': json, 'os': os, 'pathlib': __import__('pathlib'),
                'platform': platform, 're': re, 'time': time})
            result = job.assess(snapshot, jobenv, identity=(1000, 1000, 1000, 1000, 'Linux', 'aarch64'))
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(result['owned_resources'], [])
            for key in ('producer', 'ksm_builds', 'comparison', 'lifecycle', 'cleanup', 'public_export', 'hardware'):
                self.assertEqual(result[key], 'NOT RUN', key)


if __name__ == '__main__':
    unittest.main()
