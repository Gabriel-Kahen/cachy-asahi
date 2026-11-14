#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Private staged package, moved-prefix and pre-import runtime refusals."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_package_data_check', HERE / 'check_package.py')
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)


def invoke(root, prefix, recipe, hidden, *arguments):
    # Only the copied runtime and caller data are rebound writable; no checkout/home/network.
    script = ('import os,socket,sys; '
              'assert not os.path.exists(sys.argv[1]+"/scripts"); '
              'assert not os.path.exists(sys.argv[2]+"/PKGBUILD"); '
              'assert {n for _,n in socket.if_nameindex()} <= {"lo"}; '
              'os.execv(sys.argv[3],sys.argv[3:])')
    command = ['bwrap', '--die-with-parent', '--ro-bind', '/', '/', '--unshare-net',
               '--dev', '/dev', '--tmpfs', '/home', '--tmpfs', str(recipe),
               '--bind', str(root), str(root), '--chdir', '/',
               '/usr/bin/python3', '-I', '-B', '-c', script, str(hidden), str(recipe),
               str(prefix / 'usr/bin/cachy-asahi-audio-sources'), *map(str, arguments)]
    env = dict(os.environ, PATH='/usr/bin:/bin', LC_ALL='C', TMPDIR=str(root))
    env.pop('PYTHONPYCACHEPREFIX', None)
    return subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)


def runtime_refusals(case, root, prefix, recipe, hidden):
    runtime = prefix / 'usr/lib/cachy-asahi/audio-sources'
    path = runtime / 'scripts/port/platform-audio-source-delivery/delivery.py'
    raw = path.read_bytes()
    mutations = ('changed', 'missing', 'symlink', 'extra', 'map')
    for kind in mutations:
        with case.subTest(mutation=kind):
            target = path; original = raw
            if kind == 'changed':
                path.write_bytes(raw + b'\nraise RuntimeError("MUST_NOT_EXECUTE")\n')
            elif kind in ('missing', 'symlink'):
                path.unlink()
                if kind == 'symlink':
                    path.symlink_to('/etc/passwd')
            elif kind == 'extra':
                target = runtime / 'unexpected.py'; original = None
                target.write_text('raise RuntimeError("MUST_NOT_EXECUTE")\n'); target.chmod(0o644)
            else:
                target = runtime / 'runtime-map.json'; original = target.read_bytes()
                target.write_bytes(original + b' ')
            try:
                child = invoke(root, prefix, recipe, hidden, 'check')
                case.assertEqual(child.returncode, 2, child.stderr)
                case.assertEqual(json.loads(child.stdout)['status'], 'REFUSED_AUDIO_SOURCE_TOOL_RUNTIME')
                case.assertNotIn('MUST_NOT_EXECUTE', child.stderr)
            finally:
                if target.exists() or target.is_symlink():
                    target.unlink()
                if original is not None:
                    target.write_bytes(original); target.chmod(0o644)


class StagedPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipe = Path(ARGS.recipe_root).absolute()
        cls.hidden = Path(ARGS.hide_checkout).absolute()
        C.audit(cls.recipe)
        cls.temp = tempfile.TemporaryDirectory(prefix='audio-tool-stage-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        original = cls.root / 'stage'
        child = subprocess.run(['bash', '-c', 'source "$1"; srcdir=$2; pkgdir=$3; package',
            'audio-package-stage', str(cls.recipe / 'PKGBUILD'), str(Path(ARGS.srcdir).absolute()), str(original)],
            capture_output=True, text=True, timeout=15)
        if child.returncode:
            raise AssertionError(child.stderr)
        cls.prefix = cls.root / 'moved-prefix'; original.rename(cls.prefix)
        C.audit(cls.recipe, cls.prefix)

    def test_moved_frozen_runtime_without_checkout_or_network(self):
        child = invoke(self.root, self.prefix, self.recipe, self.hidden, 'check')
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['files'], 10)

    def test_missing_tampered_extra_and_aliased_runtime_refuse(self):
        runtime_refusals(self, self.root, self.prefix, self.recipe, self.hidden)

    def test_full_unique_options_and_repository_override_refuse(self):
        cases = [('verify', '--pac', 'a', '--sha256', '0'*64),
                 ('verify', '--packet', 'a', '--packet=a', '--sha256', '0'*64),
                 ('--trusted-checkout', '/private', 'check')]
        for args in cases:
            with self.subTest(args=args):
                child = invoke(self.root, self.prefix, self.recipe, self.hidden, *args)
                self.assertEqual(child.returncode, 2)
                self.assertIn('error:', child.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('recipe-root', 'srcdir', 'hide-checkout'):
        parser.add_argument('--' + name, required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
