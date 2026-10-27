# SPDX-License-Identifier: MIT
"""Portable synthetic image-environment controls; all actors are forbidden."""
import ast
import copy
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_gui_signer_environment_controls', HERE / 'environment.py')
E = importlib.util.module_from_spec(spec)
with ExitStack() as import_fences:
    for process_name in ('Popen', 'run', 'check_output'):
        import_fences.enter_context(patch.object(subprocess, process_name,
            side_effect=AssertionError('SYNTHETIC_IMPORT_FORBIDS_PROCESS_ACTORS')))
    import_fences.enter_context(patch.object(socket, 'socket',
        side_effect=AssertionError('SYNTHETIC_IMPORT_FORBIDS_NETWORK')))
    spec.loader.exec_module(E)


def fixture_contract():
    """Format-valid invented pins used only behind mocked actor boundaries."""
    return dict(schema_version=1, purpose=E.CONTRACT_PURPOSE, source_sha='1' * 40,
                oci_ref='ghcr.io/synthetic/fixture@sha256:' + '2' * 64,
                image_id='sha256:' + '3' * 64, alarm_uid=max(1, os.getuid()),
                alarm_gid=os.getgid(), packages_sha256='4' * 64,
                tools={name: dict(bytes=1, sha256='5' * 64) for name in E.TOOLS})


def fixture_image(contract):
    return dict(id=contract['image_id'], architecture='arm64', os='linux',
                repo_digests=[contract['oci_ref']], repo_tags=[])


class Controls(unittest.TestCase):
    def setUp(self):
        self.fences = ExitStack()
        self.addCleanup(self.fences.close)
        for name in ('Popen', 'run', 'check_output'):
            self.fences.enter_context(patch.object(E.subprocess, name,
                side_effect=AssertionError('SYNTHETIC_CONTROL_FORBIDS_PROCESS_ACTORS')))
        self.fences.enter_context(patch.object(socket, 'socket',
            side_effect=AssertionError('SYNTHETIC_CONTROL_FORBIDS_NETWORK')))
        self.temporary = tempfile.TemporaryDirectory(prefix='gui-signer-environment-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.contract = fixture_contract()
        self.raw = E.enc(self.contract)
        self.path = self.work / 'contract.json'
        self.path.write_bytes(self.raw)
        self.nonce, self.cid = '6' * 32, '7' * 64
        self.name = 'cachy-asahi-gui-signer-env-' + self.nonce

    def args(self, suffix=''):
        return types.SimpleNamespace(contract=self.path, sha256=E.sha(self.raw),
                                     output=self.work / ('environment' + suffix))

    def prepared(self, preexisting=True, acquired=False, suffix=''):
        args = self.args(suffix)
        args.output.mkdir(mode=0o700)
        (args.output / 'contract.json').write_bytes(self.raw)
        E.save(args.output / 'environment.json', dict(schema_version=1, purpose=E.PURPOSE,
            status='PASS', source_sha=self.contract['source_sha'], contract_sha256=E.sha(self.raw),
            image_id=self.contract['image_id'], oci_ref=self.contract['oci_ref'], uid=os.getuid(),
            gid=os.getgid(), preexisting_image=preexisting, acquired_image=acquired))
        return args

    def container(self):
        return dict(Id=self.cid, Name='/' + self.name, Image=self.contract['image_id'],
                    Config={'Labels': {'org.cachy-asahi.gui-signer-environment': self.nonce}})

    def test_contract_resolved_and_strictly_typed(self):
        self.assertEqual(E.validate(self.contract), self.contract)
        for key in self.contract:
            value = copy.deepcopy(self.contract)
            value[key] = None
            with self.subTest(null=key), self.assertRaises((ValueError, TypeError)):
                E.validate(value)
        invalid = [dict(self.contract, extra=1), dict(self.contract, schema_version=True),
                   dict(self.contract, purpose='production'), dict(self.contract, alarm_uid=True),
                   dict(self.contract, alarm_uid=0), dict(self.contract, alarm_uid=-1),
                   dict(self.contract, alarm_uid=2**31), dict(self.contract, alarm_gid=True),
                   dict(self.contract, alarm_gid=-1), dict(self.contract, source_sha=[]),
                   dict(self.contract, image_id='sha256:' + '3' * 63)]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                E.validate(value)

    def test_no_floating_tag_implicit_registry_or_shell_reference(self):
        references = ['ubuntu:latest', 'namespace/image@sha256:' + '2' * 64,
                      'ghcr.io/n/i:tag@sha256:' + '2' * 64,
                      'ghcr.io/n/i@sha256:' + 'a' * 63, 'ghcr.io/n/i;touch /x',
                      'ghcr.io/n/i@sha256:' + 'A' * 64, 'ghcr.io/n/i\n@sha256:' + '2' * 64]
        for reference in references:
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                E.validate(dict(self.contract, oci_ref=reference))

    def test_tool_inventory_is_complete_exact_and_typed(self):
        for kind in ('missing', 'extra', 'bool', 'zero', 'bad_hash'):
            value = copy.deepcopy(self.contract)
            row = value['tools']['/usr/bin/python3']
            if kind == 'missing': value['tools'].pop('/usr/bin/gpg-agent')
            if kind == 'extra': value['tools']['/usr/bin/other'] = row
            if kind == 'bool': row['bytes'] = True
            if kind == 'zero': row['bytes'] = 0
            if kind == 'bad_hash': row['sha256'] = 'x' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                E.validate(value)

    def test_duplicate_nonfinite_and_nonobject_JSON(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"tools":{"a":1,"a":2}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): E.decode(raw)
        for raw in (b'true', b'1', b'[]', b'null'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): E.validate(E.decode(raw))

    def test_native_UID_and_local_endpoint_host_requirements(self):
        with patch.object(E.platform, 'system', return_value='Linux'), \
             patch.object(E.platform, 'machine', return_value='x86_64'), \
             patch.object(E, 'command', side_effect=AssertionError('NO_DOCKER')) as actor:
            with self.assertRaises(ValueError): E.host(self.contract)
            actor.assert_not_called()
        contract = dict(self.contract, alarm_uid=1001, alarm_gid=1001)
        with ExitStack() as stack:
            stack.enter_context(patch.object(E.platform, 'system', return_value='Linux'))
            stack.enter_context(patch.object(E.platform, 'machine', return_value='aarch64'))
            stack.enter_context(patch.object(E.os, 'getuid', return_value=1001))
            stack.enter_context(patch.object(E.os, 'getgid', return_value=1001))
            lookup = stack.enter_context(patch.object(E.shutil, 'which', return_value='/usr/bin/present'))
            for endpoint in E.ENDPOINTS:
                context = E.enc([{'Endpoints': {'docker': {'Host': endpoint}}}])
                with patch.dict(os.environ, {'DOCKER_HOST': endpoint}), \
                     patch.object(E, 'command', side_effect=[(0, b'aarch64\n'), (0, context)]):
                    E.host(contract)
            self.assertEqual({call.args[0] for call in lookup.call_args_list}, {'docker', 'lscpu'})
            for endpoint in ('tcp://remote:2375', 'ssh://remote'):
                context = E.enc([{'Endpoints': {'docker': {'Host': endpoint}}}])
                with patch.object(E, 'command', side_effect=[(0, b'arm64\n'), (0, context)]):
                    with self.assertRaises(ValueError): E.host(contract)
            with patch.object(E, 'command', return_value=(0, b'x86_64\n')):
                with self.assertRaises(ValueError): E.host(contract)
            with patch.object(E, 'command', side_effect=AssertionError('NO_DOCKER')) as actor:
                with self.assertRaises(ValueError): E.host(dict(contract, alarm_uid=1002))
                actor.assert_not_called()

    def test_hash_and_source_fail_before_host_or_output(self):
        for wrong in ('hash', 'source'):
            args = self.args()
            if wrong == 'hash': args.sha256 = 'f' * 64
            with patch.dict(os.environ, {'SOURCE_SHA': 'f' * 40}), \
                 patch.object(E, 'host', side_effect=AssertionError('NO_ACTOR')) as actor:
                with self.assertRaises(ValueError): E.prepare(args)
                self.assertFalse(args.output.exists())
                actor.assert_not_called()

    def test_preexisting_prepare_never_pulls(self):
        args = self.args()
        with patch.dict(os.environ, {'SOURCE_SHA': self.contract['source_sha']}), \
             patch.object(E, 'host'), patch.object(E, 'inspect_image', return_value=fixture_image(self.contract)), \
             patch.object(E, 'qualify', return_value={}), \
             patch.object(E, 'command', side_effect=AssertionError('NO_PULL')):
            E.prepare(args)
        value = E.decode((args.output / 'environment.json').read_bytes())
        self.assertEqual(value['status'], 'PASS')
        self.assertTrue(value['preexisting_image'])
        self.assertFalse(value['acquired_image'])

    def test_acquisition_uses_only_exact_digest(self):
        args = self.args()
        with patch.dict(os.environ, {'SOURCE_SHA': self.contract['source_sha']}), \
             patch.object(E, 'host'), patch.object(E, 'inspect_image', side_effect=[None, fixture_image(self.contract)]), \
             patch.object(E, 'qualify', return_value={}), patch.object(E, 'command', return_value=(0, b'')) as actor:
            E.prepare(args)
        self.assertEqual(actor.call_args.args[0], ['docker', 'pull', '--platform=linux/arm64', self.contract['oci_ref']])
        self.assertTrue(E.decode((args.output / 'environment.json').read_bytes())['acquired_image'])

    def test_image_identity_and_qualification_failure_cannot_emit_PASS(self):
        for number, kind in enumerate(('id', 'architecture', 'os', 'qualification')):
            image = fixture_image(self.contract)
            if kind == 'id': image['id'] = 'sha256:' + '8' * 64
            if kind == 'architecture': image['architecture'] = 'amd64'
            if kind == 'os': image['os'] = 'other'
            args = self.args(str(number))
            with patch.dict(os.environ, {'SOURCE_SHA': self.contract['source_sha']}), \
                 patch.object(E, 'host'), patch.object(E, 'inspect_image', return_value=image), \
                 patch.object(E, 'qualify', side_effect=ValueError('SYNTHETIC')) as qualify:
                with self.assertRaises(ValueError): E.prepare(args)
                if kind != 'qualification': qualify.assert_not_called()
            self.assertEqual(E.decode((args.output / 'environment.json').read_bytes())['status'], 'FAIL')

    def test_preexisting_cleanup_uses_no_Docker(self):
        args = self.prepared()
        with patch.object(E, 'host', side_effect=AssertionError('NO_ACTOR')), \
             patch.object(E, 'command', side_effect=AssertionError('NO_ACTOR')):
            E.cleanup(args)
        self.assertTrue(E.decode((args.output / 'cleanup.json').read_bytes())['preserved_preexisting'])

    def test_new_cleanup_uses_exact_ref_without_force_or_parent_pruning(self):
        args = self.prepared(False, True)
        with patch.object(E, 'host'), patch.object(E, 'inspect_image', side_effect=[fixture_image(self.contract), None]), \
             patch.object(E, 'command', return_value=(0, b'')) as actor:
            E.cleanup(args)
        self.assertEqual(actor.call_args.args[0], ['docker', 'image', 'rm', '--no-prune', self.contract['oci_ref']])
        self.assertTrue(E.decode((args.output / 'cleanup.json').read_bytes())['removed_new_image'])

    def test_foreign_tags_refs_or_ID_refuse_image_cleanup(self):
        for number, kind in enumerate(('tag', 'other_ref', 'multiple_refs', 'id')):
            image = fixture_image(self.contract)
            if kind == 'tag': image['repo_tags'] = ['foreign:tag']
            if kind == 'other_ref': image['repo_digests'] = ['ghcr.io/foreign/image@sha256:' + '8' * 64]
            if kind == 'multiple_refs': image['repo_digests'].append('ghcr.io/foreign/image@sha256:' + '8' * 64)
            if kind == 'id': image['id'] = 'sha256:' + '8' * 64
            args = self.prepared(False, True, str(number))
            with patch.object(E, 'host'), patch.object(E, 'inspect_image', return_value=image), \
                 patch.object(E, 'command', side_effect=AssertionError('NO_REMOVAL')) as actor:
                with self.assertRaises(ValueError): E.cleanup(args)
                actor.assert_not_called()

    def test_qualification_argv_is_offline_unprivileged_without_binds(self):
        result = dict(guard={}, tools={}, packages_sha256='4' * 64, packages_count=1)
        with patch.object(E, 'command', side_effect=[(0, b''), (0, E.enc(result))]) as actor, \
             patch.object(E, 'remove_container'):
            E.qualify(self.contract, self.nonce)
        argv = actor.call_args.args[0]
        for flag in ('--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--read-only', '--cgroupns=private', '--pids-limit=128'):
            self.assertIn(flag, argv)
        for flag in ('--privileged', '--mount', '-v'): self.assertNotIn(flag, argv)
        self.assertEqual(argv[argv.index('--entrypoint=/usr/bin/python3') + 1], self.contract['image_id'])

    def test_qualifier_compiles_and_uses_real_inventory_LF(self):
        ast.parse((HERE / 'environment.py').read_bytes())
        tree = ast.parse(E.QUALIFY)
        self.assertTrue(any(isinstance(node, ast.Constant) and node.value == '\n' for node in ast.walk(tree)))

    def test_failed_image_inventory_cannot_prove_absence(self):
        with patch.object(E, 'command', side_effect=ValueError('SYNTHETIC_DAEMON_FAILURE')):
            with self.assertRaises(ValueError): E.inspect_image(self.contract['image_id'])

    def test_successful_image_list_proves_absence_without_inspect(self):
        with patch.object(E, 'command', return_value=(0, b'')) as actor:
            self.assertIsNone(E.inspect_image(self.contract['image_id']))
        self.assertEqual(actor.call_count, 1)
        self.assertEqual(actor.call_args.args[0], ['docker', 'image', 'ls', '--no-trunc', '--quiet'])

    def test_ambient_Docker_configuration_is_refused(self):
        output = self.work / 'output'
        output.mkdir()
        config = output / 'docker-config'
        config.mkdir(mode=0o700)
        (config / 'config.json').write_text('{"auths":{}}')
        with self.assertRaises(ValueError):
            with E.docker_config(output): pass

    def test_foreign_container_refuses_image_removal(self):
        args = self.prepared(False, True)
        with patch.object(E, 'host'), patch.object(E, 'inspect_image', return_value=fixture_image(self.contract)), \
             patch.object(E, 'command', return_value=(0, b'foreign-container\n')) as actor:
            with self.assertRaises(ValueError): E.cleanup(args)
        self.assertEqual(actor.call_count, 1)

    def test_retirement_uses_validated_full_CID_and_ID_absence_query(self):
        results = [(0, self.cid.encode()), (0, E.enc([self.container()])), (0, b''), (0, b'')]
        with patch.object(E, 'command', side_effect=results) as actor:
            self.assertEqual(E.remove_container(self.name, self.nonce, self.contract['image_id'])['status'], 'PASS')
        self.assertEqual(actor.call_args_list[1].args[0], ['docker', 'container', 'inspect', self.cid])
        self.assertEqual(actor.call_args_list[2].args[0], ['docker', 'rm', '-f', self.cid])
        self.assertIn('id=' + self.cid, actor.call_args_list[3].args[0])
        self.assertNotIn('name=^/' + self.name + '$', actor.call_args_list[3].args[0])

    def test_unexpected_CID_name_image_and_label_are_preserved(self):
        for kind in ('id', 'name', 'image', 'label', 'no_labels'):
            row = self.container()
            if kind == 'id': row['Id'] = '8' * 64
            if kind == 'name': row['Name'] = '/foreign'
            if kind == 'image': row['Image'] = 'sha256:' + '8' * 64
            if kind == 'label': row['Config']['Labels']['org.cachy-asahi.gui-signer-environment'] = '8' * 32
            if kind == 'no_labels': row['Config']['Labels'] = None
            with self.subTest(kind=kind), \
                 patch.object(E, 'command', side_effect=[(0, self.cid.encode()), (0, E.enc([row]))]) as actor:
                with self.assertRaises(ValueError): E.remove_container(self.name, self.nonce, self.contract['image_id'])
                self.assertEqual(actor.call_count, 2)

    def test_fresh_name_collision_prevents_actor_and_foreign_retirement(self):
        with patch.object(E, 'command', return_value=(0, self.cid.encode())) as actor, \
             patch.object(E, 'remove_container', side_effect=AssertionError('NO_FOREIGN_RETIREMENT')) as remove:
            with self.assertRaises(ValueError): E.qualify(self.contract, self.nonce)
            self.assertEqual(actor.call_count, 1)
            remove.assert_not_called()

    def test_short_or_multiple_CIDs_refused_before_inspect(self):
        for raw in (b'abc', (self.cid + '\n' + '8' * 64).encode()):
            with patch.object(E, 'command', return_value=(0, raw)) as actor:
                with self.assertRaises(ValueError): E.remove_container(self.name, self.nonce, self.contract['image_id'])
                self.assertEqual(actor.call_count, 1)

    def test_failed_retirement_query_cannot_claim_absence(self):
        with patch.object(E, 'command', side_effect=ValueError('SYNTHETIC_QUERY_FAILURE')):
            with self.assertRaises(ValueError): E.remove_container(self.name, self.nonce, self.contract['image_id'])

    def test_still_present_retired_CID_refuses_success(self):
        results = [(0, self.cid.encode()), (0, E.enc([self.container()])), (0, b''), (0, self.cid.encode())]
        with patch.object(E, 'command', side_effect=results):
            with self.assertRaises(ValueError): E.remove_container(self.name, self.nonce, self.contract['image_id'])

    def buildx_directory(self, name='buildx-state'):
        path = self.work / name
        path.mkdir(mode=0o700)
        return path

    def test_buildx_writes_separate_state_then_credential_reentry_succeeds(self):
        state = self.buildx_directory()
        seen = []
        def fake(argv, **kwargs):
            environment = kwargs['env']
            seen.append(dict(environment))
            if argv[:2] == ['docker', 'build']:
                self.assertEqual(environment['BUILDX_CONFIG'], str(state))
                self.assertNotEqual(environment['BUILDX_CONFIG'], environment['DOCKER_CONFIG'])
                (Path(environment['BUILDX_CONFIG']) / 'activity').mkdir(mode=0o700)
                (Path(environment['BUILDX_CONFIG']) / 'history').write_bytes(b'synthetic state')
            else:
                self.assertNotIn('BUILDX_CONFIG', environment)
            kwargs['stdout'].write(b'synthetic Docker output\n')
            return types.SimpleNamespace(returncode=0, wait=lambda timeout: 0)
        with patch.object(E.subprocess, 'Popen', side_effect=fake):
            with E.docker_config(self.work):
                self.assertEqual(E.command(['docker', 'build', '.'], buildx_config=state),
                                 (0, b'synthetic Docker output\n'))
            for command in (['docker', 'image', 'inspect', self.contract['image_id']],
                            ['docker', 'container', 'ls', '-a']):
                with E.docker_config(self.work): E.command(command)
            with E.docker_config(self.work), self.assertRaises(ValueError):
                E.command(['docker', 'build', '.'], buildx_config=state)
        self.assertEqual(len(seen), 3)
        self.assertEqual(list((self.work / 'docker-config').iterdir()), [])
        self.assertEqual((state / 'history').read_bytes(), b'synthetic state')
        self.assertTrue((state / 'activity').is_dir())

    def test_buildx_requires_Path_and_only_the_Docker_build_command(self):
        state = self.buildx_directory()
        with E.docker_config(self.work):
            with self.assertRaises(ValueError): E.command(['docker', 'build', '.'], buildx_config=str(state))
            for argv in (['docker', 'info'], ['docker', 'build'], ['podman', 'build', '.'],
                         ['/usr/bin/docker', 'build', '.'], 'docker build .'):
                with self.subTest(argv=argv), self.assertRaises(ValueError):
                    E.command(argv, buildx_config=state)

    def test_buildx_rejects_nonempty_without_deleting_unknown_files(self):
        state = self.buildx_directory()
        unknown = state / 'unreviewed'
        unknown.write_bytes(b'preserve synthetic unknown state')
        with E.docker_config(self.work), self.assertRaises(ValueError):
            E.command(['docker', 'build', '.'], buildx_config=state)
        self.assertEqual(unknown.read_bytes(), b'preserve synthetic unknown state')

    def test_buildx_rejects_alias_relative_and_nondirectory_paths(self):
        state = self.buildx_directory()
        alias = self.work / 'buildx-alias'
        alias.symlink_to(state, target_is_directory=True)
        ancestor_alias = self.work / 'ancestor-alias'
        ancestor_alias.symlink_to(self.work, target_is_directory=True)
        plain = self.work / 'plain-state-file'
        plain.write_bytes(b'preserve')
        plain.chmod(0o700)
        for path in (alias, ancestor_alias / state.name, Path('relative-state'), plain):
            with self.subTest(path=path), E.docker_config(self.work), self.assertRaises(ValueError):
                E.command(['docker', 'build', '.'], buildx_config=path)
        self.assertEqual(plain.read_bytes(), b'preserve')

    def test_buildx_rejects_bad_mode_owner_group_and_link_count(self):
        state = self.buildx_directory()
        original = Path.lstat
        for key, value in (('st_mode', state.stat().st_mode & ~0o777 | 0o755),
                           ('st_uid', os.getuid() + 1), ('st_gid', os.getgid() + 1),
                           ('st_nlink', 0), ('st_nlink', 3)):
            def altered(path, *, follow_symlinks=False):
                info = original(path)
                if path != state: return info
                fields = {name: getattr(info, name) for name in
                          ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                           'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                fields[key] = value
                return types.SimpleNamespace(**fields)
            with self.subTest(key=key, value=value), E.docker_config(self.work), \
                 patch.object(Path, 'lstat', altered), self.assertRaises(ValueError):
                E.command(['docker', 'build', '.'], buildx_config=state)

    def test_buildx_rejects_overlap_in_both_directions(self):
        with E.docker_config(self.work):
            credential = Path(E.DOCKER_CONFIG)
            child = credential / 'buildx-state'
            child.mkdir(mode=0o700)
            for path in (credential, self.work, child):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    E.command(['docker', 'build', '.'], buildx_config=path)
        self.assertTrue(child.is_dir())

    def test_buildx_rejects_same_inode_alias_even_with_distinct_canonical_paths(self):
        state = self.buildx_directory()
        with E.docker_config(self.work):
            pin = E._directory_identity(state.stat())
            with patch.object(E, '_directory_identity', return_value=pin), self.assertRaises(ValueError):
                E.command(['docker', 'build', '.'], buildx_config=state)

    def test_buildx_rejects_changed_directory_identity_before_process(self):
        state = self.buildx_directory()
        real = os.fstat
        count = 0
        def changed(fd):
            nonlocal count
            info = real(fd)
            count += 1
            if count < 3: return info
            fields = {name: getattr(info, name) for name in
                      ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                       'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            fields['st_ino'] += 1
            return types.SimpleNamespace(**fields)
        with E.docker_config(self.work), patch.object(E.os, 'fstat', side_effect=changed), \
             self.assertRaises(ValueError):
            E.command(['docker', 'build', '.'], buildx_config=state)

    def test_buildx_unknown_credential_files_still_refuse_before_process(self):
        state = self.buildx_directory()
        with E.docker_config(self.work):
            unknown = Path(E.DOCKER_CONFIG) / 'unknown-credential-state'
            unknown.write_bytes(b'preserve synthetic credential directory entry')
            with self.assertRaises(ValueError): E.command(['docker', 'build', '.'], buildx_config=state)
        with self.assertRaises(ValueError):
            with E.docker_config(self.work): pass
        self.assertEqual(unknown.read_bytes(), b'preserve synthetic credential directory entry')

    def test_default_command_environment_does_not_inherit_ambient_Buildx_state(self):
        seen = []
        def fake(argv, **kwargs):
            seen.append(kwargs['env'])
            return types.SimpleNamespace(returncode=0, wait=lambda timeout: 0)
        with patch.dict(os.environ, {'BUILDX_CONFIG': '/unreviewed/ambient/state'}), \
             E.docker_config(self.work), patch.object(E.subprocess, 'Popen', side_effect=fake):
            E.command(['docker', 'image', 'ls'])
        self.assertEqual(set(seen[0]), {'PATH', 'LANG', 'HOME', 'DOCKER_CONFIG'})
        self.assertNotIn('BUILDX_CONFIG', seen[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
