# SPDX-License-Identifier: MIT
"""Pure static/refusal controls; no candidate, helper, archive or actor execution."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('test_llvm23_'+name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mode = load('container_mode')
runtime = load('runtime')
entry = load('entry')


def runtime_fixture():
    mounts = '\n'.join([
        '1 0 0:1 / / ro - overlay overlay ro',
        '2 1 0:2 / /inputs ro - ext4 /dev/data ro',
        '3 1 0:3 / /source ro - ext4 /dev/data ro',
        '4 1 0:4 / /work rw - ext4 /dev/data rw',
        '5 1 0:5 / /tmp rw,noexec,nosuid,nodev - tmpfs tmpfs rw,size=64m,uid=1001,gid=1001',
        '6 1 0:6 / /run rw,noexec,nosuid,nodev - tmpfs tmpfs rw,size=8m,uid=1001,gid=1001',
    ])
    shared = dict(uid=1001, euid=1001, gid=1001, egid=1001, groups=[1001], architecture='aarch64', page_bytes=4096,
                  namespaces={name:name+':[123]' for name in ('user','mnt','net','pid')}, uid_map=[[0,0,4294967295]], gid_map=[[0,0,4294967295]],
                  status={**{key:'0000000000000000' for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')}, 'NoNewPrivs':'1'},
                  limits={'cpu.max':'200000 100000','memory.max':'8589934592','memory.swap.max':'0','pids.max':'512'},
                  cgroup='0::/\n', mountinfo=mounts, interfaces=['lo'], hostname='llvm23-native')
    entry = dict(**copy.deepcopy(shared), pid=2, ppid=1, starttime=20, cmdline=['/usr/bin/python3','-I','-B','/inputs/actor/entry.py'], exe='/usr/bin/python3.14', cwd='/work/recipe')
    parent = dict(**copy.deepcopy(shared), pid=1, ppid=0, starttime=10, cmdline=['/sbin/docker-init','--','/usr/bin/bash','--noprofile','--norc','/inputs/actor/entry.sh'], exe='/sbin/docker-init', cwd='/work')
    return entry, parent


class ActorDataTests(unittest.TestCase):
    def test_protected_candidate_modes_and_derived_recipe_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory)/'input', Path(directory)/'output'
            source.mkdir(); destination.mkdir()
            for name, permission in [('PKGBUILD', 0o444), ('build.sh', 0o555), ('inputs.json', 0o444)]:
                (source/name).write_bytes(b'original DATA')
                (source/name).chmod(permission)
            entry.copy_candidate_files(source, destination, ['PKGBUILD', 'build.sh', 'inputs.json'], b'derived DATA')
            self.assertEqual((destination/'PKGBUILD').read_bytes(), b'derived DATA')
            for name in ['PKGBUILD', 'build.sh', 'inputs.json']:
                self.assertEqual((destination/name).stat().st_mode & 0o7777, (source/name).stat().st_mode & 0o7777)
            self.assertEqual((destination/'build.sh').read_bytes(), b'original DATA')
            self.assertEqual((destination/'inputs.json').read_bytes(), b'original DATA')

    def test_all_python_parses_without_running_operational_entry(self):
        for path in HERE.glob('*.py'):
            ast.parse(path.read_bytes(), filename=str(path))

    def test_recipe_literal_inverse_and_single_delta(self):
        original = ('before\n_reference() {\n'+mode.ORIGINAL_CALL+'\n}\nafter\n').encode()
        effective = mode.transform_recipe(original)
        self.assertEqual(effective.replace(mode.CONTAINER_CALL.encode(), mode.ORIGINAL_CALL.encode()), original)
        self.assertEqual(effective.count(mode.CONTAINER_CALL.encode()), 1)
        self.assertIn(b'/inputs/actor/container_mode.py', effective)

    def test_recipe_missing_or_multiple_seam_refuses(self):
        for raw in (b'no seam', mode.ORIGINAL_CALL.encode()*2):
            with self.assertRaises(ValueError):
                mode.transform_recipe(raw)

    def test_context_rejects_unbound_admission_before_import(self):
        with patch.object(mode, 'read', return_value=b'{}'), patch.dict(os.environ, {}, clear=True), patch.object(mode, 'module') as imported:
            with self.assertRaisesRegex(ValueError, 'admission hash'):
                mode.context()
            imported.assert_not_called()

    def test_fixed_work_argument_refuses_before_context(self):
        with patch.object(mode, 'context') as context:
            with self.assertRaisesRegex(ValueError, 'srcdir'):
                mode.action('prepare', Path('/tmp/work'))
            context.assert_not_called()

    def test_runtime_literal_inverse_restores_frozen_whole_hash(self):
        proof = json.loads((HERE/'runtime-derivation.json').read_text())
        raw = (HERE/'runtime.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['emitted_sha256'])
        for row in reversed(proof['changes']):
            self.assertEqual(raw.count(row['new'].encode()), row['count'])
            raw = raw.replace(row['new'].encode(), row['old'].encode())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['original_sha256'])

    def test_runtime_fixed_rootful_domain_data(self):
        runtime.validate(*runtime_fixture())

    def test_runtime_source_mount_must_exist_and_be_readonly(self):
        for replacement in ('', '3 1 0:3 / /source rw - ext4 /dev/data rw'):
            entry, parent = runtime_fixture()
            for value in (entry, parent):
                value['mountinfo'] = value['mountinfo'].replace('3 1 0:3 / /source ro - ext4 /dev/data ro', replacement)
            with self.assertRaises(ValueError):
                runtime.validate(entry, parent)

    def test_runtime_old_perl_resource_domain_refuses(self):
        entry, parent = runtime_fixture()
        entry['limits']['memory.max'] = '4294967296'
        with self.assertRaises(ValueError):
            runtime.validate(entry, parent)

    def test_natural_retirement_requires_all_original_ownership_witnesses(self):
        row = dict(natural_exit=True, forced_cleanup=False, group_absent=True, retirement='REAPED', ownership_lost=False, leader_held_until_group_inspection=True, exit_observed_via_waitpid=True, exit=0)
        self.assertTrue(mode.natural(row))
        for key in ('natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid'):
            self.assertFalse(mode.natural(dict(row, **{key:False})))

    def test_proposed_deadlines_and_no_nested_sandbox_call(self):
        self.assertEqual((mode.ACTOR_SECONDS, mode.MAKEPKG_SECONDS), (14400, 13800))
        self.assertEqual(mode.STAGES, {'probe':60,'tools':10800,'runtimes':1800,'check':600})
        source = (HERE/'container_mode.py').read_text()
        self.assertNotIn('/usr/bin/bwrap', source)
        tree = ast.parse(source)
        candidate_calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'candidate'}
        self.assertEqual(candidate_calls, {'tree_digest','check_stage'})

    def test_environment_is_private_and_explicit(self):
        with patch.dict(os.environ, {'ADMISSION_SHA256':'a'*64}, clear=True):
            value = mode.environment()
        self.assertEqual(value['PATH'], '/usr/bin:/bin')
        self.assertEqual(value['HOME'], '/work/home')
        self.assertEqual(value['TMPDIR'], '/work/tmp')
        self.assertFalse(any(key.startswith(('LD_', 'DOCKER_', 'GIT_')) for key in value))

    def test_packaged_inventory_includes_notices_and_makepkg_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'package'
            root.mkdir()
            for name in ('.PKGINFO', '.BUILDINFO', '.MTREE', 'opt/cachy-asahi/llvm23-source-reference/share/licenses/llvm23-source-reference/LICENSE.packaging'):
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'PASSIVE TEST DATA\n')
            with patch.object(entry.mode, 'remaining', return_value=60):
                result = entry.inventory(root)
            self.assertTrue({'.PKGINFO','.BUILDINFO','.MTREE'} <= set(result['files']))
            notice = result['files']['opt/cachy-asahi/llvm23-source-reference/share/licenses/llvm23-source-reference/LICENSE.packaging']
            self.assertEqual(notice['sha256'], hashlib.sha256(b'PASSIVE TEST DATA\n').hexdigest())

    def test_inventory_json_cap_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'inventory.json'
            with patch.object(entry, 'inventory', return_value={'test':'too large'}), patch.object(entry.mode, 'LOG_LIMIT', 1):
                with self.assertRaisesRegex(ValueError, 'export cap'):
                    entry.write_inventory(Path(directory), target)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
