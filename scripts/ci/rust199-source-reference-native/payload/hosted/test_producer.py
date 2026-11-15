#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""FENCED structural DATA controls only: no Root qualification, Docker or actors."""
import ast
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import resource

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('rust199_producer_data', HERE/'producer.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

# These rows describe API structure, not an image or an admitted native job.
NAME, VOLUME, IMAGE = 'FENCED-actor-DATA', 'FENCED-volume-DATA', 'UNQUALIFIED-image-DATA'
INPUTS, SOURCE, VOLUME_PATH = Path('/FENCED/inputs'), Path('/FENCED/source'), Path('/FENCED/volume/_data')
MATERIALS = {f'FENCED-{n}.tar.xz': Path(f'/FENCED/materials/{n}.tar.xz') for n in range(5)}
LABELS = P.labels(dict(sha='FENCED-source', run='FENCED-run', job='FENCED-job'), 'FENCED-token', 'makepkg')
ENV = {key: 'd'*64 for key in ('ROOT_ADMISSION_SHA256', 'SOURCE_MAP_SHA256', 'CONTRACT_SHA256')}


def data_actor(phase='makepkg', init=False):
    mounts = ([dict(Type='volume', Source=VOLUME, Target='/work', ReadOnly=False)] if init else
              P.mount_specs(VOLUME, INPUTS, SOURCE, MATERIALS, phase))
    real = []
    for row in mounts:
        item = dict(Type=row['Type'], Destination=row['Target'], RW=not row['ReadOnly'], Propagation='')
        if row['Type'] == 'volume':
            item.update(Name=VOLUME, Driver='local', Source=str(VOLUME_PATH/row.get('VolumeOptions', {}).get('Subpath', '')))
        else:
            item['Source'] = row['Source']
        real.append(item)
    host = dict(ReadonlyRootfs=True, NetworkMode='none', CapDrop=['ALL'], CapAdd=['CHOWN'] if init else [],
                SecurityOpt=['no-new-privileges'], Privileged=False, UsernsMode='', PidMode='', IpcMode='private',
                CgroupnsMode='private', Memory=128*1024**2 if init else 8*1024**3,
                MemorySwap=128*1024**2 if init else 8*1024**3, NanoCpus=2000000000,
                PidsLimit=32 if init else 512, Init=True, Mounts=mounts, RestartPolicy=dict(Name='no'),
                LogConfig=dict(Type='none', Config={}),
                Ulimits=[dict(Name='nofile', Soft=1024, Hard=1024), dict(Name='core', Soft=0, Hard=0)])
    host['Tmpfs'] = {} if init else {'/tmp': 'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001',
                                    '/run': 'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'}
    config = dict(User='0:0' if init else '1001:1001', Labels=LABELS, Hostname='rust199-native', WorkingDir='/work',
                  Entrypoint=['/usr/bin/chown'] if init else ['/usr/bin/python'],
                  Cmd=['1001:1001', '/work'] if init else ['-I', '-B', '/source/actor/entry.py', phase],
                  Env=[k+'='+v for k, v in ENV.items()])
    return dict(Name='/'+NAME, Image=IMAGE, HostConfig=host, Config=config, Mounts=real,
                State=dict(Status='created', Running=False))


def inspect_data(row, phase='makepkg'):
    P.inspect_actor(row, NAME, VOLUME, IMAGE, INPUTS, SOURCE, MATERIALS, phase, ENV, LABELS, VOLUME_PATH)


class ProducerDataTests(unittest.TestCase):
    def test_exact_two_phase_vectors_and_only_chown_init(self):
        for phase in ('prepare', 'makepkg'):
            options = P.actor_options(NAME, VOLUME, IMAGE, INPUTS, SOURCE, MATERIALS, phase, ENV, LABELS)
            self.assertEqual(options[:len(P.DOCKER)], P.DOCKER)
            self.assertEqual(options[-5:], [IMAGE, '-I', '-B', '/source/actor/entry.py', phase])
            self.assertIn('--cap-drop=ALL', options)
            self.assertNotIn('--cap-add=CHOWN', options)
            self.assertIn('--user=1001:1001', options)
            self.assertIn('--memory=8g', options)
            self.assertIn('--memory-swap=8g', options)
            self.assertEqual(sum('volume-subpath=build/stage0' in x for x in options), 2 if phase == 'makepkg' else 0)
        init = P.init_options(NAME, VOLUME, IMAGE, LABELS)
        self.assertIn('--cap-add=CHOWN', init)
        self.assertIn('--memory=128m', init)
        self.assertEqual(init[-3:], [IMAGE, '1001:1001', '/work'])
        with self.assertRaises(ValueError):
            P.mount_specs(VOLUME, INPUTS, SOURCE, MATERIALS, 'other')

    def test_exact_structural_inspect_and_omitted_false_docker_flag(self):
        for phase in ('prepare', 'makepkg'):
            row = data_actor(phase)
            for item in row['HostConfig']['Mounts']:
                if item['ReadOnly'] is False:
                    del item['ReadOnly']  # Docker uses omitempty on this bool.
            inspect_data(row, phase)
        P.inspect_init(data_actor(init=True), NAME, VOLUME, IMAGE, LABELS, VOLUME_PATH)

    def test_resource_namespace_and_capability_drift_refused(self):
        mutations = [('MemorySwap', 16*1024**3), ('Memory', 4*1024**3), ('NanoCpus', 4000000000),
                     ('PidsLimit', 1024), ('Privileged', True), ('NetworkMode', 'host'), ('ReadonlyRootfs', False),
                     ('Init', False), ('CapAdd', ['CHOWN']), ('CapDrop', []), ('SecurityOpt', []),
                     ('Devices', [dict(PathOnHost='/dev/anything')]), ('VolumesFrom', ['OTHER']),
                     ('Binds', ['/HOST:/host']), ('PidMode', 'host'), ('IpcMode', 'host'),
                     ('CgroupnsMode', 'host'), ('LogConfig', dict(Type='json-file', Config={})),
                     ('RestartPolicy', dict(Name='always'))]
        for key, value in mutations:
            with self.subTest(key=key):
                row = data_actor(); row['HostConfig'][key] = value
                with self.assertRaises(ValueError):
                    inspect_data(row)

    def test_actual_alias_must_match_readonly_named_subpath(self):
        for target in ('/stage0', '/work/build/stage0'):
            for field, value in [('RW', True), ('Source', str(VOLUME_PATH)), ('Name', 'OTHER'), ('Type', 'bind')]:
                with self.subTest(target=target, field=field):
                    row = data_actor()
                    next(x for x in row['Mounts'] if x['Destination'] == target)[field] = value
                    with self.assertRaises(ValueError):
                        inspect_data(row)

    def test_configured_subpath_cannot_be_omitted_or_changed(self):
        for target in ('/stage0', '/work/build/stage0'):
            for value in ({}, {'Subpath': 'build/OTHER'}, {'Subpath': 'build/stage0', 'DriverConfig': {'Name': 'OTHER'}}):
                row = data_actor()
                next(x for x in row['HostConfig']['Mounts'] if x['Target'] == target)['VolumeOptions'] = value
                with self.assertRaises(ValueError):
                    inspect_data(row)

    def test_extra_writable_or_duplicate_mount_refused(self):
        for configured in (True, False):
            row = data_actor()
            array = row['HostConfig']['Mounts'] if configured else row['Mounts']
            array.append(copy.deepcopy(array[0]))
            with self.assertRaises(ValueError):
                inspect_data(row)
        row = data_actor()
        row['HostConfig']['Mounts'][0]['VolumeOptions'] = {'Subpath': 'unexpected'}
        with self.assertRaises(ValueError):
            inspect_data(row)

    def test_source_material_binds_and_all_identity_labels_exact(self):
        for target in ('/source', '/inputs', '/materials/FENCED-0.tar.xz'):
            row = data_actor()
            next(x for x in row['Mounts'] if x['Destination'] == target)['Source'] = '/OTHER'
            with self.assertRaises(ValueError):
                inspect_data(row)
        for key in LABELS:
            row = data_actor(); row['Config']['Labels'] = {**LABELS, key: 'OTHER'}
            with self.assertRaises(ValueError):
                inspect_data(row)

    def test_chown_inspect_refuses_extra_capabilities_and_entry_mutation(self):
        for alter in ('cap', 'vector', 'started'):
            row = data_actor(init=True)
            if alter == 'cap': row['HostConfig']['CapAdd'].append('DAC_OVERRIDE')
            elif alter == 'vector': row['Config']['Cmd'] = ['-R', '1001:1001', '/work']
            else: row['State']['Status'] = 'running'
            with self.assertRaises(ValueError):
                P.inspect_init(row, NAME, VOLUME, IMAGE, LABELS, VOLUME_PATH)

    def test_actor_loader_override_entry_and_pin_drift_refused(self):
        for change in ('loader', 'pin', 'entry', 'user', 'started'):
            row = data_actor()
            if change == 'loader': row['Config']['Env'].append('LD_PRELOAD=/OTHER')
            elif change == 'pin': row['Config']['Env'][0] = 'ROOT_ADMISSION_SHA256='+'0'*64
            elif change == 'entry': row['Config']['Cmd'][-1] = 'shell'
            elif change == 'user': row['Config']['User'] = '0:0'
            else: row['State']['Status'] = 'running'
            with self.assertRaises(ValueError):
                inspect_data(row)

    def test_natural_retirement_requires_every_observed_predicate(self):
        row = dict(natural_exit=True, forced_cleanup=False, group_absent=True, retirement='REAPED',
                   ownership_lost=False, leader_held_until_group_inspection=True, exit_observed_via_waitpid=True)
        self.assertTrue(P.natural(row))  # FENCED receipt shape; never an actual receipt.
        for key in row:
            altered = dict(row); del altered[key]
            self.assertFalse(P.natural(altered))
        self.assertFalse(P.natural({**row, 'forced_cleanup': True}))

    def test_daemon_completion_refuses_nonzero_oom_running_and_error(self):
        state = dict(Status='exited', ExitCode=0, OOMKilled=False, Running=False, Restarting=False, Error='')
        for key, value in [('ExitCode', 1), ('OOMKilled', True), ('Running', True), ('Status', 'dead'), ('Error', 'failure')]:
            with self.assertRaises(ValueError):
                P.finished({'State': {**state, key: value}})

    def test_active_reserve_boundaries(self):
        row = dict(available_bytes=8*1024**3, available_inodes=120000)
        P.reserve(4*1024**3, [row, row])
        for memory, data in [(4*1024**3-1, row), (4*1024**3, {**row, 'available_bytes': 8*1024**3-1}),
                             (4*1024**3, {**row, 'available_inodes': 119999})]:
            with self.assertRaises(ValueError):
                P.reserve(memory, [data])

    def test_export_preserves_both_inherited_file_size_limits(self):
        unlimited = resource.RLIM_INFINITY
        for previous in ((unlimited, unlimited), (P.EXPORT_CAP, unlimited),
                         (P.EXPORT_CAP, P.EXPORT_CAP), (2*P.EXPORT_CAP, 2*P.EXPORT_CAP)):
            self.assertEqual(P.export_limit(previous), P.EXPORT_CAP)
        for previous in ((P.EXPORT_CAP-1, unlimited), (P.EXPORT_CAP-1, P.EXPORT_CAP),
                         (unlimited, P.EXPORT_CAP-1), (0, unlimited)):
            with self.assertRaises(ValueError):
                P.export_limit(previous)

    def test_image_declared_volumes_refused_before_resource_mutation(self):
        row = dict(Id=IMAGE, Os='linux', Architecture='arm64', Config={})
        for declared in ({'/unexpected': {}}, {'/work': {}}, {'/source': {}}):
            with self.assertRaises(ValueError):
                P.inspect_image({**row, 'Config': {'Volumes': declared}}, IMAGE)
        for declared in (None, {}):
            P.inspect_image({**row, 'Config': {'Volumes': declared}}, IMAGE)
        source = (HERE/'producer.py').read_text()
        self.assertLess(source.index('inspect_image(inspected, image)', source.index('def run(')),
                        source.index("intent('volume'", source.index('def run(')))

    def test_failed_diagnostic_export_does_not_resurrect_acceptance(self):
        state = dict(Status='exited', Running=False, Restarting=False, ExitCode=1, OOMKilled=True)
        self.assertEqual(P.diagnostic_action(state), 'EXPORT_FAILED_EVIDENCE')
        for status in ('running', 'restarting', 'paused'):
            self.assertEqual(P.diagnostic_action({**state, 'Status': status}), 'STOP_MARK_FAILED')
        for status in ('created', 'dead', 'removing'):
            with self.assertRaises(ValueError):
                P.diagnostic_action({**state, 'Status': status})
        data = dict(prepare_completed=True, makepkg_completed=True, export={'FENCED': 'DATA'},
                    owned_resources_absent=True, errors=['FENCED first failure'], diagnostic_export_only=True)
        self.assertFalse(P.completed(data))
        self.assertFalse(P.completed({**data, 'errors': [], 'forced_daemon_cleanup': True}))
        self.assertFalse(P.completed({**data, 'errors': [], 'cleanup_errors': ['FENCED cleanup failure']}))

    def test_no_synthetic_admission_can_reach_command(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-rust-producer-DATA-') as temporary:
            def forbidden(*args, **kwargs):
                self.fail('DATA control attempted a Docker/actor command')
            with self.assertRaises(ValueError):
                P.run(Path(temporary), Path(temporary), {'source': {}, 'image': {'id': IMAGE}}, forbidden)

    def test_source_contains_no_image_authority_or_direct_child_fallback(self):
        tree = ast.parse((HERE/'producer.py').read_text())
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any('subprocess' in ast.unparse(node) for node in imports))
        text = (HERE/'producer.py').read_text()
        for forbidden in ("DOCKER+['build'", "DOCKER+['pull'", "DOCKER+['commit'", "DOCKER+['image', 'rm'", 'bwrap'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(P.EXPORT_CAP, 4*1024**3)
        self.assertEqual(P.LOG_CAP, 64*1024**2)


if __name__ == '__main__':
    unittest.main()
