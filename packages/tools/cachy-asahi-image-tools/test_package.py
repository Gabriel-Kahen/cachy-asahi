#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite private package-layout controls; no GPG or filesystem actors."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

RECIPE_ROOT = Path(__file__).resolve().parent
NAME = 'cachy-asahi-image-tools'


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Package(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        specification = importlib.util.spec_from_file_location('_image_package_check', RECIPE_ROOT/'check_package.py')
        cls.checker = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(cls.checker)
        cls.summary = cls.checker.check(RECIPE_ROOT)
        cls.payload = json.loads((RECIPE_ROOT/'payload-map.json').read_bytes())
        cls.bodies = {}
        with tarfile.open(RECIPE_ROOT/'private-source.tar.gz', 'r:gz') as archive:
            for member in archive:
                with archive.extractfile(member) as source:
                    cls.bodies[member.name] = source.read()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='image-tools-package-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        original = self.root/'original-prefix'
        original.mkdir()
        for name, row in self.payload.items():
            target = original/name
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = self.bodies[row['source']] if row['source'].startswith('private/') else (RECIPE_ROOT/row['source']).read_bytes()
            target.write_bytes(raw)
            target.chmod(row['mode'])
        self.prefix = self.root/'moved-prefix'
        original.rename(self.prefix)
        self.runtime = self.prefix/'usr/lib/cachy-asahi/image-tools'
        self.launcher = self.prefix/'usr/bin'/NAME
        self.recipe = dict(schema_version=1, kind='cachy-asahi-policy-signed-payload-ext4-v1', epoch=1700000000, inputs={})
        package = dict(name='owned-fixture', version='1-1', arch='any')
        references = {key: dict(path='/UNOPENED/owned-fixture.' + key, size=1, sha256='a'*64,
                               identity=[1, 1, stat.S_IFREG|0o600, 1, 0, 0, 1, 0, 0])
                      for key in ('archive', 'signature')}
        selection = dict(schema_version=1, scope='EXACT_LOCAL_SIGNED_ARCHIVE_SELECTION_V1', release_set=None,
                         packages=[dict(identity=package, **references, primary_fingerprint='A'*40,
                                        metadata=dict(package, depends=[], provides=[], conflicts=[], replaces=[], license=['MIT']))])
        now = int(time.time())
        policy = dict(schema_version=1, profile='operator-policy-offline-signed-pristine-v1',
                      selection_sha256=digest(encoded(selection)), release_set=None, issued=now-60, expires=now+3600,
                      signers=[dict(primary='A'*40, signature_not_before=1, not_after=now+3600)])
        for name in ('gpg', 'public_keyring', 'trusted', 'revoked'):
            policy[name] = dict(path='/UNOPENED/' + name, bytes=1, sha256='a'*64)
        inputs = dict(selection=selection, authentication=policy, tool_pins=dict(schema_version=2),
                      metadata_pins=dict(schema_version=2), root_policy=dict(mode=0o755, uid=0, gid=0, acl=None, xattrs={}))
        for name, value in inputs.items():
            target = self.root/(name + '.json')
            raw = encoded(value)
            target.write_bytes(raw)
            self.recipe['inputs'][name] = dict(path=str(target), sha256=digest(raw))
        self.recipe_path = self.root/'recipe.json'
        self.save_recipe()

    def save_recipe(self):
        raw = encoded(self.recipe)
        self.recipe_path.write_bytes(raw)
        self.recipe_hash = digest(raw)

    def invoke(self, *arguments):
        # The child may read installed trusted sources and JSON only. Opening
        # the checkout or fake operands, or spawning any actor, fails the call.
        forbidden = str(RECIPE_ROOT.resolve())
        for ancestor in RECIPE_ROOT.resolve().parents:
            if (ancestor/'.git').exists():
                forbidden = str(ancestor)
                break
        runner = '''import os, runpy, sys
launcher, forbidden = sys.argv[1:3]
arguments = sys.argv[3:]
def audit(event, values):
    if event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.exec', 'os.fork', 'pty.spawn'):
        raise AssertionError('package test actor forbidden: ' + event)
    if event == 'open' and isinstance(values[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(values[0])
        if path.startswith('/UNOPENED/') or path == forbidden or path.startswith(forbidden + '/'):
            raise AssertionError('package test operand/checkout read forbidden: ' + path)
sys.addaudithook(audit)
sys.argv = [launcher] + arguments
runpy.run_path(launcher, run_name='__main__')
'''
        return subprocess.run([sys.executable, '-IB', '-c', runner, str(self.launcher), forbidden, *arguments],
                              cwd=self.root, env=dict(PATH='/usr/bin:/bin', HOME=str(self.root), LC_ALL='C', TZ='UTC'),
                              capture_output=True, text=True, timeout=20, check=False)

    def plan(self, recipe_hash=None):
        return self.invoke('plan', '--recipe', str(self.recipe_path), '--recipe-sha256', recipe_hash or self.recipe_hash)

    def refused(self, expected):
        result = self.plan()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(expected, result.stderr)

    def source(self):
        return self.runtime/'scripts/platform/release_image.py'

    def test_exact_staged_payload_and_literal_recipe(self):
        self.assertEqual(self.checker.check(RECIPE_ROOT, self.prefix), dict(status='PASS', original_files=65, runtime_files=60, payload_files=66))

    def test_moved_prefix_help_and_version(self):
        version = self.invoke('--version')
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout.strip(), NAME + ' 0.1.0')
        help_result = self.invoke('--help')
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn('plan,assemble,verify,resume', help_result.stdout)

    def test_moved_plan_without_checkout_archives_or_actors(self):
        result = self.plan()
        self.assertEqual(result.returncode, 0, result.stderr)
        observation = json.loads(result.stdout)
        self.assertEqual(observation['status'], 'PLANNED_ONLY_NO_ARCHIVE_OR_NATIVE_ACTOR_EXECUTED')
        self.assertEqual(observation['binding']['recipe_sha256'], self.recipe_hash)
        self.assertEqual(observation['binding']['payload_state']['package_transaction'], 'NOT_RUN')
        self.assertFalse(list(self.runtime.rglob('__pycache__')))

    def test_runtime_tamper_refused(self):
        self.source().write_bytes(self.source().read_bytes() + b'\n# altered\n')
        self.refused('private-runtime-member-pin')

    def test_runtime_missing_refused(self):
        self.source().unlink()
        self.refused('private-runtime-incomplete-closure')

    def test_runtime_extra_refused(self):
        (self.runtime/'extra.py').write_text('raise AssertionError("never execute")\n')
        self.refused('private-runtime-unexpected-member')

    def test_runtime_symlink_refused(self):
        saved = self.root/'source-copy.py'
        self.source().rename(saved)
        self.source().symlink_to(saved)
        self.refused('image tools refused:')

    def test_runtime_hardlink_refused(self):
        os.link(self.source(), self.root/'linked-source.py')
        self.refused('private-runtime-member-state')

    def test_runtime_group_writable_file_refused(self):
        self.source().chmod(0o664)
        self.refused('private-runtime-member-state')

    def test_runtime_group_writable_directory_refused(self):
        self.source().parent.chmod(0o775)
        self.refused('private-runtime-directory-mode')

    def test_unsigned_recipe_refused(self):
        self.recipe['kind'] = 'cachy-asahi-pristine-payload-ext4-v1'
        self.save_recipe()
        self.refused('installed-image-tools-require-policy-signed-recipe')

    def test_wrong_recipe_hash_refused(self):
        result = self.plan('0'*64)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('input-or-source-pin', result.stderr)

    def test_removal_inverse_preserves_user_file(self):
        sentinel = self.prefix/'home/fixture/user-note'
        sentinel.parent.mkdir(parents=True)
        sentinel.write_bytes(b'USER OWNED\n')
        for name in self.payload:
            (self.prefix/name).unlink()
        for path in sorted(self.prefix.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
        self.assertEqual({path.relative_to(self.prefix).as_posix() for path in self.prefix.rglob('*') if path.is_file()},
                         {'home/fixture/user-note'})
        self.assertEqual(sentinel.read_bytes(), b'USER OWNED\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=RECIPE_ROOT)
    arguments, remaining = parser.parse_known_args()
    RECIPE_ROOT = arguments.recipe_root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
