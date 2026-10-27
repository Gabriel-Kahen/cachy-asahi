# SPDX-License-Identifier: MIT
"""Source and mocked owner controls; never start Git, Docker, build or guest actors."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('c01_source_owner_controls', HERE / 'owner.py')
O = importlib.util.module_from_spec(spec)
spec.loader.exec_module(O)


def environment():
    source = 'a' * 40
    return dict(GITHUB_SHA=source, GITHUB_WORKFLOW_SHA=source,
                GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi', GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_RUN_ATTEMPT='1', GITHUB_RUN_ID='1234',
                GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/' + O.ALIASES[0] + '@refs/heads/control',
                GITHUB_ACTIONS='true', RUNNER_OS='Linux', RUNNER_ARCH='ARM64')


class FakeActors:
    """In-memory Docker observation model, with no subprocess or signal operations."""
    def __init__(self, own, *, stubborn=False, foreign=False, named_only=False):
        self.own = own
        self.container = not named_only
        self.named_only = named_only
        self.image = True
        self.stubborn = stubborn
        self.foreign = foreign
        self.calls = []
        self.cid, self.iid = 'c' * 64, 'sha256:' + 'b' * 64

    def docker(self, *argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv[:3] == ('ps', '-aq', '--no-trunc'):
            query = argv[-1]
            if query.startswith('label='):
                return self.cid if self.container else ''
            return self.cid if (self.container or self.named_only) and self.own['consumer'] in query else ''
        if argv[:4] == ('image', 'ls', '-aq', '--no-trunc'):
            return self.iid if self.image else ''
        if argv[:3] == ('image', 'ls', '-q'):
            return self.iid if self.image else ''
        if argv[0] == 'inspect':
            return json.dumps([dict(Id=self.cid, Name='/' + self.own['consumer'],
                                   Config=dict(Labels={O.LABEL: 'foreign' if self.foreign else self.own['token']}))])
        if argv[:2] == ('rm', '-f'):
            if not self.stubborn:
                self.container = False
            return self.cid
        if argv[:2] == ('image', 'inspect'):
            return json.dumps([dict(Id=self.iid, Architecture='arm64', Os='linux',
                Config=dict(Labels={O.LABEL: self.own['token'], O.LABEL + '.source': self.own['source_sha'],
                                    O.LABEL + '.run': self.own['run_id']}), RepoTags=[self.own['tag']])])
        if argv[:3] == ('image', 'rm', '--no-prune'):
            self.image = False
            return self.iid
        raise AssertionError('unexpected simulated Docker call: ' + repr(argv))

    def run(self, *args, **kwargs):
        raise AssertionError('no real or simulated non-Docker actor expected')


class OwnerControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='c01-source-controls-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('Popen', 'run', 'check_output'):
            guard = patch.object(O.subprocess, name, side_effect=AssertionError('source controls forbid actors'))
            guard.start(); self.addCleanup(guard.stop)
        guard = patch.object(O.os, 'killpg', side_effect=AssertionError('source controls forbid signals'))
        guard.start(); self.addCleanup(guard.stop)
        self.env = environment()
        self.own = O.identity('a' * 40, self.env)
        self.args = NS(source_root=O.ROOT, source_sha='a' * 40, manifest_sha256='d' * 64,
                       proof=self.root / 'c01-proof.json', work=self.root / 'c01-installable',
                       cache=self.root / 'alarm-cache', public=self.root / 'c01-public', execute=True)

    def test_identity_exact_source_manual_attempt_and_registered_alias(self):
        for alias in O.ALIASES:
            env = self.env | {'GITHUB_WORKFLOW_REF': 'Gabriel-Kahen/cachy-asahi/' + alias + '@refs/heads/control'}
            self.assertEqual(O.identity('a' * 40, env)['attempt'], 1)
        for key, value in (('GITHUB_SHA', 'b' * 40), ('GITHUB_WORKFLOW_SHA', 'b' * 40),
                           ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_EVENT_NAME', 'push'),
                           ('GITHUB_REPOSITORY', 'other/repository'), ('GITHUB_RUN_ID', '0'),
                           ('GITHUB_WORKFLOW_REF', 'Gabriel-Kahen/cachy-asahi/.github/workflows/other.yml@main')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                O.identity('a' * 40, self.env | {key: value})
        for source in ('main', 'A' * 40, 'a' * 39, None):
            with self.subTest(source=source), self.assertRaises(ValueError):
                O.identity(source, self.env)

    def test_private_or_docker_environment_refuses_before_bootstrap_actors(self):
        with patch.object(O, 'source', return_value={}), patch.object(O, 'identity', return_value=self.own), \
                patch.object(O.platform, 'system', return_value='Linux'), \
                patch.object(O.platform, 'machine', return_value='aarch64'), \
                patch.object(O.os, 'getuid', return_value=1000), patch.object(O.os, 'geteuid', return_value=1000), \
                patch.object(O, 'Actors', side_effect=AssertionError('admission must precede actors')):
            for key in ('DOCKER_HOST', 'DOCKER_API_VERSION', 'LD_PRELOAD',
                        'CACHY_OLD_FOUR_SCHEMA', 'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01'):
                with self.subTest(key=key), patch.dict(os.environ, self.env | {key: 'denied'}, clear=True), \
                        self.assertRaisesRegex(ValueError, 'environment refused'):
                    O.bootstrap(self.args)
            self.args.execute = False
            with patch.dict(os.environ, self.env, clear=True), self.assertRaisesRegex(ValueError, 'explicit non-root'):
                O.bootstrap(self.args)

    def test_consumer_argv_is_finite_offline_and_has_only_two_scoped_binds(self):
        context, output = self.root / 'context', self.root / 'output'
        argv = O.consumer_argv(self.own, 'sha256:' + 'b' * 64, context, output, 'e' * 64)
        self.assertEqual(argv[:3], [*O.DOCKER, 'run'])
        for option in ('--network=none', '--ipc=private', '--cgroupns=private', '--cpus=2',
                       '--memory=4g', '--memory-swap=4g', '--pids-limit=256', '--cap-drop=ALL',
                       '--security-opt=no-new-privileges', '--tmpfs=/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777'):
            self.assertIn(option, argv)
        self.assertEqual([a for a in argv if a.startswith('--cap-add=')], ['--cap-add=' + c for c in O.CAPS])
        self.assertFalse(any(a == '--privileged' or a.startswith(('--device', '--pid=', '--volumes-from')) for a in argv))
        mounts = [argv[i + 1] for i, value in enumerate(argv) if value == '--mount']
        self.assertEqual(mounts, ['type=bind,src=' + str(context) + ',dst=/inputs,readonly',
                                  'type=bind,src=' + str(output) + ',dst=/out'])
        self.assertEqual(argv[-6:], ['--context', '/inputs', '--context-sha256', 'e' * 64, '--output', '/out'])

    def consumer(self):
        context, output = self.root / 'context', self.root / 'output'
        row = dict(Name='/' + self.own['consumer'], Image='sha256:' + 'b' * 64,
                   Config=dict(Labels={O.LABEL: self.own['token']}, User='0:0'),
                   State=dict(Status='exited', ExitCode=0, OOMKilled=False),
                   HostConfig=dict(NetworkMode='none', IpcMode='private', PidMode='', Privileged=False,
                       NanoCpus=2_000_000_000, Memory=4 * 1024**3, MemorySwap=4 * 1024**3, PidsLimit=256,
                       CapDrop=['ALL'], CapAdd=['CAP_' + cap for cap in O.CAPS], SecurityOpt=['no-new-privileges'],
                       Devices=[], DeviceRequests=[], VolumesFrom=[], Tmpfs={'/tmp': 'rw,exec,nosuid,nodev,size=2g,mode=1777'},
                       CgroupnsMode='private'),
                   Mounts=[dict(Destination='/inputs', Source=str(context), RW=False, Type='bind'),
                           dict(Destination='/out', Source=str(output), RW=True, Type='bind'),
                           dict(Destination='/tmp', Source='', RW=True, Type='tmpfs')])
        return row, context, output

    def test_consumer_observation_refuses_identity_isolation_limits_and_extra_mounts(self):
        row, context, output = self.consumer()
        O.check_consumer(row, self.own, row['Image'], context, output)
        changes = [('State', 'ExitCode', 1), ('State', 'OOMKilled', True),
                   ('HostConfig', 'NetworkMode', 'host'), ('HostConfig', 'Privileged', True),
                   ('HostConfig', 'NanoCpus', 0), ('HostConfig', 'Memory', 0), ('HostConfig', 'PidsLimit', 0),
                   ('HostConfig', 'Devices', [{'PathOnHost': '/dev/mem'}]),
                   ('HostConfig', 'DeviceRequests', [{'Count': -1}]), ('HostConfig', 'VolumesFrom', ['host']),
                   ('HostConfig', 'CapAdd', [*O.CAPS, 'SYS_ADMIN']), ('HostConfig', 'CgroupnsMode', 'host')]
        for group, key, value in changes:
            bad = copy.deepcopy(row); bad[group][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                O.check_consumer(bad, self.own, row['Image'], context, output)
        for kind in ('foreign-label', 'writable-input', 'extra-bind', 'unexpected-volume', 'unbounded-tmpfs'):
            bad = copy.deepcopy(row)
            if kind == 'foreign-label': bad['Config']['Labels'][O.LABEL] = 'foreign'
            elif kind == 'writable-input': bad['Mounts'][0]['RW'] = True
            elif kind == 'extra-bind': bad['Mounts'][2] = dict(Destination='/host', Source='/', RW=True, Type='bind')
            elif kind == 'unexpected-volume': bad['Mounts'][2] = dict(Destination='/etc', Source='/daemon/volume', RW=True, Type='volume')
            else: bad['HostConfig']['Tmpfs']['/tmp'] = 'rw,size=64g'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                O.check_consumer(bad, self.own, row['Image'], context, output)

    def test_actual_closed_source_map_and_original11_then_temp_mutations(self):
        if not (O.ROOT / O.MAP).is_file():
            self.skipTest('Root has not generated the final source-map and rendered aliases yet')
        pin = O.sha(O.read(O.ROOT / O.MAP))
        manifest = O.source(O.ROOT, pin)
        self.assertEqual(len(O.load(O.ROOT / O.LANE / 'reviewed11.json')), 11)
        self.assertEqual(O.sha(O.read(O.ROOT / O.LANE / 'expected-packages.lock')), O.PACKAGES)
        for kind in ('bytes', 'mode', 'alias', 'map', 'extra', 'empty-directory', 'alias-mode', 'hardlink', 'carrier-before-proof'):
            with self.subTest(kind=kind):
                root = self.root / kind
                shutil.copytree(O.ROOT, root, ignore=shutil.ignore_patterns('.git', 'source-public14', 'source-retained', '__pycache__'))
                target = root / next(iter(manifest['files']))
                if kind == 'bytes': target.write_bytes(target.read_bytes() + b'changed')
                elif kind == 'mode': target.chmod(target.stat().st_mode ^ 0o100)
                elif kind == 'alias': (root / O.ALIASES[0]).write_bytes(b'changed alias')
                elif kind == 'map': (root / O.MAP).write_bytes((root / O.MAP).read_bytes() + b' ')
                elif kind == 'extra': (root / 'unreviewed-extra').write_bytes(b'extra')
                elif kind == 'empty-directory': (root / 'unreviewed-empty').mkdir()
                elif kind == 'alias-mode': (root / O.ALIASES[0]).chmod(0o755)
                elif kind == 'hardlink': os.link(target, self.root / 'extra-hardlink')
                else:
                    (root / 'source-public14').mkdir(); (root / 'source-public14/data').write_bytes(b'unproved')
                with self.assertRaises(ValueError):
                    O.source(root, pin)

    def test_binding_rejects_checkout_head_mismatch_with_git_mocked(self):
        with patch.object(O, 'source', return_value={}), patch.object(O, 'identity', return_value=self.own), \
                patch.object(O.subprocess, 'check_output', return_value='b' * 40 + '\n'), \
                self.assertRaisesRegex(ValueError, 'HEAD mismatch'):
            O.binding(self.args, first=True)

    def test_actor_mock_preserves_leader_until_group_observation_without_real_process(self):
        events = []
        actor = O.Actors(self.root / 'mock-actor', 60)
        def wait(**kwargs):
            events.append('reap')
            return 0
        child = NS(pid=123456, wait=wait)
        def groups(*args):
            self.assertNotIn('reap', events)
            events.append('inspect-group')
            return []
        state = NS(si_status=0, si_code=O.os.CLD_EXITED)
        with patch.object(O.subprocess, 'Popen', return_value=child) as spawn, \
                patch.object(O.os, 'waitid', return_value=state) as observe, \
                patch.object(O, 'group_members', side_effect=groups):
            self.assertEqual(actor.run(['synthetic-no-execution']), '')
        self.assertEqual(events[-1], 'reap')
        self.assertGreaterEqual(events.count('inspect-group'), 2)
        self.assertTrue(observe.call_args.args[2] & O.os.WNOWAIT)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        row = O.load(actor.directory / 'actors.json')[0]
        self.assertTrue(row['natural_exit'] and row['group_absent'] and row['leader_held_until_group_inspection'])

    def test_actor_timeout_mock_kills_owned_group_before_reap_and_cannot_pass(self):
        events = []
        actor = O.Actors(self.root / 'mock-timeout', 60)
        child = NS(pid=123456, wait=lambda **kwargs: events.append('reap') or -9)
        def kill(pid, sig):
            self.assertEqual(pid, child.pid)
            self.assertNotIn('reap', events)
            events.append('kill')
        with patch.object(O.subprocess, 'Popen', return_value=child), patch.object(O.os, 'waitid', return_value=None), \
                patch.object(O, 'group_members', return_value=[]), patch.object(O.os, 'killpg', side_effect=kill), \
                self.assertRaises(O.subprocess.TimeoutExpired):
            actor.run(['synthetic-no-execution'], timeout=0)
        self.assertEqual(events, ['kill', 'reap'])
        row = O.load(actor.directory / 'actors.json')[0]
        self.assertEqual(row['status'], 'FAIL')
        self.assertFalse(row['natural_exit'])

    def test_cleanup_consumers_and_observed_absence_precede_image_removal(self):
        self.args.work.mkdir()
        actor = FakeActors(self.own)
        with patch.object(O, 'admitted', return_value=({}, self.own)), patch.object(O, 'Actors', return_value=actor):
            O.cleanup(self.args)
        result = O.load(self.args.work / 'cleanup-owner.json')
        self.assertEqual(result['status'], 'PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE')
        self.assertEqual(result['removed_containers'], [actor.cid])
        self.assertEqual(result['removed_images'], [actor.iid])
        remove = next(i for i, a in enumerate(actor.calls) if a[:2] == ('rm', '-f'))
        image = next(i for i, a in enumerate(actor.calls) if a[:3] == ('image', 'rm', '--no-prune'))
        self.assertLess(remove, image)
        self.assertTrue(any(a[:3] == ('ps', '-aq', '--no-trunc') for a in actor.calls[remove + 1:image]))

    def test_cleanup_refuses_foreign_surviving_or_unlabelled_named_consumers_before_image(self):
        self.args.work.mkdir()
        for kind in ('foreign', 'surviving', 'named-only'):
            actor = FakeActors(self.own, foreign=kind == 'foreign', stubborn=kind == 'surviving', named_only=kind == 'named-only')
            with self.subTest(kind=kind), patch.object(O, 'admitted', return_value=({}, self.own)), \
                    patch.object(O, 'Actors', return_value=actor), self.assertRaises(ValueError):
                O.cleanup(self.args)
            self.assertFalse(any(a[:2] == ('image', 'rm') for a in actor.calls))
            self.assertEqual(O.load(self.args.work / 'cleanup-owner.json')['status'], 'FAIL')

    def test_unfinished_bootstrap_cannot_gain_cleanup_acceptance_from_cli_absence(self):
        (self.args.work / 'bootstrap').mkdir(parents=True)
        O.save(self.args.work / 'bootstrap/build-started.json', {'identity': self.own})
        O.save(self.args.work / 'bootstrap/bootstrap.json', {'status': 'failed'})
        actor = FakeActors(self.own)
        with patch.object(O, 'admitted', return_value=({}, self.own)), patch.object(O, 'Actors', return_value=actor), \
                self.assertRaisesRegex(ValueError, 'unfinished bootstrap'):
            O.cleanup(self.args)
        self.assertEqual(O.load(self.args.work / 'cleanup-owner.json')['status'], 'FAIL')

    def test_incomplete_declared_guest_result_refuses_without_loading_or_running_helper(self):
        output = self.root / 'guest'; output.mkdir()
        row = dict(status='PASS', native_build='PASS', installed_behavior='PASS', base_commit=self.args.source_sha,
                   context_sha256='e' * 64, machine='aarch64', inventory_sha256=O.PACKAGES, selected_for_release=False,
                   generic16k_execution='NOT RUN', hardware_validation='NOT RUN', performance_acceptance='NOT RUN',
                   system_sentinels={str(i): 'f' * 64 for i in range(4)}, phases=[], rebuilds={})
        for kind in ('failed', 'hardware', 'missing-phases', 'missing-sentinels'):
            bad = copy.deepcopy(row)
            if kind == 'failed': bad['native_build'] = 'NOT RUN'
            elif kind == 'hardware': bad['hardware_validation'] = 'PASS'
            elif kind == 'missing-sentinels': bad['system_sentinels'].pop('0')
            O.save(output / 'result.json', bad)
            with self.subTest(kind=kind), patch.object(O, 'module', side_effect=AssertionError('no helper execution')), \
                    self.assertRaises(ValueError):
                O.validate_result(output, 'e' * 64, self.args.source_sha)

    def test_retention_missing_package_cleanup_receipts_never_passes(self):
        self.args.work.mkdir()
        source = self.root / 'source'
        for relative in (O.MAP, *O.ALIASES):
            p = source / relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'fixture source')
        O.save(self.args.proof, {'status': 'PASS_PRESECRET_SOURCE_PROOF'})
        O.save(self.args.work / 'bootstrap-owner.json', {'status': 'PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP', 'identity': self.own})
        with patch.object(O, 'binding', return_value=({'files': {}}, self.own)), patch.object(O, 'ROOT', source), \
                patch.object(O, 'validate_result', side_effect=AssertionError('incomplete receipts cannot reach acceptance')):
            self.assertEqual(O.retain(self.args), 1)
        result = O.load(self.args.public / 'receipt.json')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['native_build'], 'NOT ACCEPTED')
        self.assertEqual(result['installed_behavior'], 'NOT ACCEPTED')


if __name__ == '__main__':
    unittest.main()
