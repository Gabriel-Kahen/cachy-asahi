# SPDX-License-Identifier: MIT
"""MODEL image/qualification DATA, never native loads, installs or grants."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        ACTORS.append(event)
        raise AssertionError('PROJECT_IMAGE_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


I = load('project_image_controls', HERE / 'image.py')
F = load('project_image_existing_models', HERE.parent / 'successor_v18/test_dependencies.py')
D = I.official()
IMAGE = 'sha256:' + 'a' * 64


def policy():
    rows = []
    for suffix in ('libgit2', 'llhttp'):
        row = F.package(); row.update(name='cachy-asahi-' + suffix + '-reference', version='0.0MODEL-1')
        row['metadata']['pkgname'] = [row['name']]
        row['filename'] = row['name'] + '-0.0MODEL-1-aarch64.pkg.tar.xz'
        if suffix == 'llhttp':
            row['providers'] = {'usr/lib/libllhttp.so.9.3.1': dict(kind='file', mode=0o755, **D.pin(F.BODY)),
                'usr/lib/libllhttp.so': dict(kind='symlink', mode=0o777, target='libllhttp.so.9.3.1')}
            row['metadata']['depend'] = ['glibc']
        else: row['metadata']['depend'].append('llhttp=9.3.1')
        rows.append(row)
    return dict(schema=1, kind='MODEL_PROJECT_TEST_POLICY_NO_GRANT', packages=rows,
        trust=dict(scope='PROJECT_TEST_ONLY', public_key=dict(path='public/model-test.gpg', **D.pin(b'MODEL_PUBLIC_ONLY')),
            primary_fingerprint='F' * 40, signing_fingerprint='E' * 40, ALARM_authentication=False),
        qualification=copy.deepcopy(I.QUALIFICATION))


def natural(seconds=1):
    return dict(natural_exit=True, forced_cleanup=False, group_absent=True, retirement='REAPED', ownership_lost=False,
                leader_held_until_group_inspection=True, exit_observed_via_waitpid=True, exit=0, elapsed_seconds=seconds)


class ImageControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='project-image-MODEL-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.source = self.root / 'source'; self.source.mkdir()
        self.image = self.root / 'image'; self.image.mkdir(); self.p = policy()
        (self.source / 'expected349.lock').write_bytes((HERE.parent / 'expected349.lock').read_bytes())
        baseline = D.inventory((HERE.parent / 'successor_v18/fixtures/parent350.ACTUAL367.lock').read_bytes())
        lookup = {r['name']: r for r in self.p['packages']}
        baseline.update({name: row['version'] for name, row in lookup.items()})
        mapping = dict(pkgname='%NAME%', pkgver='%VERSION%', arch='%ARCH%', license='%LICENSE%', depend='%DEPENDS%',
                       provides='%PROVIDES%', conflict='%CONFLICTS%', replaces='%REPLACES%')
        for name, version in baseline.items():
            folder = self.image / 'var/lib/pacman/local' / (name + '-' + version.replace(':', '_')); folder.mkdir(parents=True)
            metadata = lookup[name]['metadata'] if name in lookup else dict(pkgname=[name], pkgver=[version])
            (folder / 'desc').write_text(''.join(mapping[k] + '\n' + '\n'.join(v) + '\n\n' for k, v in metadata.items() if v))
            if name in lookup:
                (folder / 'files').write_text('%FILES%\n' + '\n'.join(lookup[name]['providers']) + '\n')
        for row in self.p['packages']:
            for name, item in row['providers'].items():
                path = self.image / name; path.parent.mkdir(parents=True, exist_ok=True)
                if item['kind'] == 'file': path.write_bytes(F.BODY); path.chmod(item['mode'])
                else: path.symlink_to(item['target'])
        self.host = I.observe(self.image, self.source, self.p, image_id=IMAGE, D=D)

    def qualification(self):
        native = dict(copy.deepcopy(self.host), native_uid_gid_checked=True, runtime_loads=D.expected_loads(self.p))
        phases = {}
        for phase in ('data', 'probe'):
            kernel = dict(phase=phase, image_id=IMAGE, policy=self.host['policy'], architecture='aarch64', uid=[1001] * 4, gid=[1001] * 4,
                capabilities=dict.fromkeys(I.CAPS, 0), NoNewPrivs=1, cgroup=I.CGROUP, offline=True, readonly_root=True,
                readonly_inputs=True, mount_proof_sha256='c' * 64, elapsed_seconds=1)
            phases[phase] = dict(observation=copy.deepcopy(native), kernel=copy.deepcopy(kernel), lifecycle=natural())
        expected, _ = I.qualification_predicates()
        probes = [dict(argv=argv, returncode=0, lifecycle=natural(), kernel_mount_proof_sha256='c' * 64) for argv in expected]
        return phases, probes

    def validate(self, phases, probes):
        return I.validate_qualification(self.host, phases, probes, self.source, self.p, image_id=IMAGE, D=D)

    def test_separate_required_test_stage_preserves_parent_and_normal_dependencies(self):
        original = b'MODEL_PARENT\nUSER alarm\nWORKDIR /tmp\n'
        result = I.extend_dockerfile(original, self.p, D)
        self.assertTrue(result.startswith(original)); self.assertTrue(result.endswith(b'USER alarm\nWORKDIR /tmp\n'))
        for wanted in (b'COPY project-test-dependencies/', b'/tmp/rust-project-test-gpg', b'LocalFileSigLevel = Required',
                       b'SigLevel = Required', b'--import-ownertrust', b'--noscriptlet', b' -T ', b'llhttp=9.3.1',
                       b'cachy-asahi-llvm23-source-reference=23.1.1', b'cmp -s /builder-qualified.lock', b'--kill gpg-agent'):
            self.assertIn(wanted, result)
        for refused in (b'/etc/pacman.d/gnupg', b'--nodeps', b'--sync', b'--upgrade', b'--lsign', b'--generate-key', b'--trust-model always'):
            self.assertNotIn(refused, result)

    def test_wrong_scope_alarm_key_qualifier_policy_and_shell_operands_refuse(self):
        for mutate in (lambda p: p['trust'].update(scope='ALARM'), lambda p: p['trust'].update(ALARM_authentication=True),
                       lambda p: p['trust'].update(primary_fingerprint=D.SIGNER),
                       lambda p: p['qualification'].update(resources_changed=True), lambda p: p['qualification'].update(cli_probes=8),
                       lambda p: p['packages'][0].update(filename='bad;COMMAND-aarch64.pkg.tar.xz'),
                       lambda p: p['packages'][0]['metadata'].update(depend=['--nodeps'])):
            p = copy.deepcopy(self.p); mutate(p)
            with self.assertRaises(ValueError): I.extend_dockerfile(b'USER alarm\nWORKDIR /tmp\n', p, D)

    def test_observation_is_explicit_test_scope_with_complete352_owned_bytes(self):
        self.assertEqual(self.host['kind'], I.KIND); self.assertFalse(self.host['ALARM_authentication'])
        self.assertEqual(len(D.inventory(D.expected_inventory(self.source, self.p))), 352)
        self.assertEqual(len(self.host['providers']), 4)
        I.validate_observation(self.host, self.source, self.p, image_id=IMAGE, native=False, D=D)
        for mutate in (lambda v: v.update(kind='OBSERVED_EXACT_SIGNED_BUILD_DEPENDENCIES_DATA_ONLY'),
                       lambda v: v.update(image_id='sha256:' + 'b' * 64), lambda v: v['inventory'].update(bytes=float(v['inventory']['bytes'])),
                       lambda v: v['providers']['usr/lib/libgit2.so.0'].update(mode=493.0), lambda v: v.update(native_acceptance=True)):
            changed = copy.deepcopy(self.host); mutate(changed)
            with self.assertRaises(ValueError): I.validate_observation(changed, self.source, self.p, image_id=IMAGE, native=False, D=D)

    def test_host_substitution_or_extra_package_never_observed(self):
        path = self.image / 'usr/lib/libgit2.so.0'; path.write_bytes(b'SUBSTITUTED')
        with self.assertRaises(ValueError): I.observe(self.image, self.source, self.p, image_id=IMAGE, D=D)

    def test_model_both_cap0_phases_nine_exact_probes_retains_all_holds(self):
        phases, probes = self.qualification(); result = self.validate(phases, probes)
        self.assertEqual(result['cli_probes'], 9); self.assertEqual(result['cap0_phases'], ['data', 'probe'])
        self.assertFalse(result['full_Rust_qualification']); self.assertFalse(result['native_acceptance'])
        self.assertFalse(result['ALARM_authentication']); self.assertIsNone(result['Root_acceptance'])

    def test_phase_image_capability_uid_resource_load_or_retirement_drift_refuses(self):
        for mutate in (lambda p: p.pop('data'), lambda p: p['data']['observation'].update(image_id='sha256:' + 'b' * 64),
                       lambda p: p['probe']['kernel']['capabilities'].update(CapEff=1),
                       lambda p: p['probe']['kernel'].update(uid=[0] * 4), lambda p: p['data']['kernel']['cgroup'].update(**{'pids.max': '1024'}),
                       lambda p: p['data']['observation'].update(runtime_loads={}), lambda p: p['probe']['lifecycle'].update(forced_cleanup=True)):
            phases, probes = self.qualification(); mutate(phases)
            with self.assertRaises(ValueError): self.validate(phases, probes)

    def test_probe_count_argv_kernel_timing_and_natural_exit_refuse(self):
        for mutate in (lambda p: p.pop(), lambda p: p[0].update(argv=['/bin/true']),
                       lambda p: p[0].update(kernel_mount_proof_sha256='d' * 64),
                       lambda p: p[0]['lifecycle'].update(forced_cleanup=True),
                       lambda p: p[0]['lifecycle'].update(elapsed_seconds=31),
                       lambda p: [row['lifecycle'].update(elapsed_seconds=10) for row in p]):
            phases, probes = self.qualification(); mutate(probes)
            with self.assertRaises(ValueError): self.validate(phases, probes)

    def test_no_actor_attempt(self):
        self.assertEqual(ACTORS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
