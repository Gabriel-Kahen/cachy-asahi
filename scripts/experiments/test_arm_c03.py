"""Synthetic C03 training/receiver fixtures; no native execution or real /tmp writes."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

import pgo
import test_arm_c01 as fixtures
from test_arm_c02 import load

a = fixtures.a
stage = load('c03_export_fixture', 'stage.py', {'arm_c01': a})


class C03Tests(fixtures.IsolatedTests):
    def setUp(self):
        super().setUp()
        self.addCleanup(a.select_experiment, 'ARM-C01')
        a.select_experiment('ARM-C03')
        self.enterContext(patch.dict(sys.modules, {a.__name__: a, 'pgo': pgo}))

    def manifest(self):
        return a.corpus.create(self.root / 'corpus', b'public heldout fixture')

    def profile_fixture(self, directory, changed=False):
        directory.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(pgo.PROFILE_NAMES):
            (directory / name).write_bytes(b'adcgB62*' + bytes([index, int(changed)]) + b'\0' * 14)

    def test_closed_flags_keep_generic_o2_and_serial_generation(self):
        cflags, ldflags = pgo.generation_flags(a)
        self.assertEqual(cflags, a.BASE_FLAGS + ' -fno-lto -fprofile-generate=/tmp/profile -fprofile-reproducible=serial')
        self.assertEqual(ldflags, a.LINK_FLAGS + ' -fno-lto -fprofile-generate=/tmp/profile -fprofile-reproducible=serial')
        for flags in a.build_flags('pgo'):
            self.assertIn('-fprofile-use=/tmp/profile', flags)
            self.assertIn('-Werror=missing-profile', flags)
            self.assertIn('-Werror=coverage-mismatch', flags)
            self.assertIn('-fno-lto', flags)
        self.assertIn('-O2 -g -march=armv8-a -mtune=generic', cflags)
        self.assertNotIn('-O3', cflags)
        self.assertEqual(a.strict_flags('pgo-1'), a.build_flags('baseline'))

    def test_exact_plan_trains_no_heldout_and_gun_has_no_filename(self):
        manifest = self.manifest()
        plans = pgo.command_plan(a, manifest)
        self.assertEqual(len(plans), 50)
        for attempt in (1, 2):
            prefix = f'pgo-training-{attempt}'
            selected = [p for p in plans if p['name'].startswith(prefix + '-')]
            training = [p for p in selected if '-train-' in p['name']]
            self.assertEqual(len(training), 4)
            self.assertEqual(training[0]['source'], '/tmp/corpus/repeated.txt')
            self.assertEqual(training[3]['argv'], ['/tmp/build/gun'])
            self.assertEqual([p['argv'] for p in selected if '-dump-' in p['name']],
                             [['gcov-dump', '-l', '/out/' + prefix + '/profiles/' + n] for n in pgo.PROFILE_NAMES])
            self.assertFalse(any('heldout' in str(p) or 'teststatic' in str(p) for p in selected))
            gun_compile = selected[2]['argv']
            self.assertFalse(any('-fprofile-' in v for v in gun_compile))
            self.assertIn('-fprofile-generate=/tmp/profile', selected[3]['argv'])
        full = a.command_plan(manifest)
        self.assertEqual(full[5:55], plans)
        self.assertEqual(full[55]['name'], 'baseline-1-configure')

    def test_training_role_bytes_and_extra_train_are_refused(self):
        manifest = self.manifest()
        train = next(r for r in manifest['files'] if r['role'] == 'train')
        for key, value in (('role', 'heldout'), ('sha256', '0' * 64), ('bytes', 1)):
            bad = copy.deepcopy(manifest)
            next(r for r in bad['files'] if r['path'] == 'repeated.txt')[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'training corpus'):
                pgo.command_plan(a, bad)
        bad = copy.deepcopy(manifest); bad['files'].append(dict(train))
        with self.assertRaises(ValueError):
            pgo.command_plan(a, bad)

    def test_host_copies_and_pins_adapter_and_propagates_c03(self):
        args = fixtures.ControllerTests.args(self)
        calls = []
        def command(runner, name, argv, **kwargs):
            calls.append((name, argv))
            if name == 'context':
                return json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]).encode()
            if name == 'daemon':
                return json.dumps({'Architecture': 'aarch64', 'OSType': 'linux'}).encode()
            if name == 'image':
                return json.dumps([{'Id': args.image, 'Architecture': 'arm64', 'Config': {}}]).encode()
            if name == 'container':
                return b''
            raise AssertionError(name)
        with patch.object(a.platform, 'machine', return_value='aarch64'), \
             patch.object(a, 'SOURCE_SHA', a.sha(args.source)), \
             patch.object(a.Commands, 'run', autospec=True, side_effect=command), \
             patch.object(a.Commands, 'stop', return_value=True), \
             patch.object(a.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
             patch.object(a, 'verify_result', return_value={'receiver_verification': {}}), \
             patch.object(a.sys, 'stdout', io.StringIO()):
            self.assertEqual(a.host(args), 0)
        copied = args.output / 'inputs/pgo.py'
        self.assertEqual(copied.read_bytes(), Path(pgo.__file__).read_bytes())
        contract = json.loads((args.output / 'inputs/contract.json').read_text())
        self.assertEqual(contract['pgo_sha256'], a.sha(copied))
        argv = next(argv for name, argv in calls if name == 'container')
        self.assertEqual(argv[-2:], ['--experiment', 'ARM-C03'])
        self.assertIn('CACHY_ASAHI_ARM_C03=', ' '.join(argv))
        self.assertTrue(argv[argv.index('--name') + 1].startswith('cachy-asahi-arm-c03-'))

    def test_profile_closure_refuses_missing_extra_header_links_and_version(self):
        directory = self.root / 'profiles'; self.profile_fixture(directory)
        self.assertEqual(len(pgo.profile_map(a, directory)), 17)
        file = directory / pgo.PROFILE_NAMES[0]; original = file.read_bytes()
        for kind in ('missing', 'extra', 'magic', 'short', 'version', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                if kind == 'missing':
                    file.unlink()
                elif kind == 'extra':
                    (directory / 'extra.gcda').write_bytes(original)
                elif kind == 'symlink':
                    file.unlink(); file.symlink_to(directory / pgo.PROFILE_NAMES[1])
                elif kind == 'hardlink':
                    (self.root / 'hardlink').hardlink_to(file)
                else:
                    file.write_bytes(b'bad!' + original[4:] if kind == 'magic' else b'adcg' if kind == 'short' else original[:4] + b'old!' + original[8:])
                with self.assertRaises(ValueError):
                    pgo.profile_map(a, directory)
                if kind == 'extra':
                    (directory / 'extra.gcda').unlink()
                elif kind == 'hardlink':
                    (self.root / 'hardlink').unlink()
                else:
                    file.unlink(missing_ok=True); file.write_bytes(original)

    def test_restore_reuses_first_profiles_and_checks_immutability(self):
        first = self.root / 'raw/pgo-training-1/profiles'; self.profile_fixture(first)
        private = self.root / 'private-profile'
        with patch.object(pgo, 'PROFILE', private):
            for attempt in (1, 2):
                restored = pgo.restore(a, self.root / 'raw', attempt)
                self.assertEqual(restored['profiles'], pgo.profile_map(a, first))
                self.assertEqual(pgo.assert_unchanged(a, self.root / 'raw', attempt), restored)
                (private / pgo.PROFILE_NAMES[0]).write_bytes(b'adcgB62*changed unchanged test')
                with self.assertRaisesRegex(ValueError, 'mutated'):
                    pgo.assert_unchanged(a, self.root / 'raw', attempt)
            with self.assertRaises(ValueError):
                pgo.restore(a, self.root / 'raw', 3)

    def test_profile_use_switch_preserves_real_probe_flags_and_other_makefile_bytes(self):
        work = self.root / 'build'; work.mkdir()
        baseline = fixtures.config_bytes('baseline')
        original = b'# unchanged Makefile prefix\n' + baseline + b'OTHER = retained\n'
        (work / 'Makefile').write_bytes(original); (work / 'configure.log').write_bytes(baseline)
        pgo.apply_use_flags(a, work)
        updated = (work / 'Makefile').read_bytes()
        self.assertEqual(updated, b'# unchanged Makefile prefix\n' + fixtures.config_bytes('pgo') + b'OTHER = retained\n')
        self.assertEqual((work / 'configure.log').read_bytes(), baseline)
        effective = a.configured_flags(updated, baseline, 'pgo')
        self.assertIn('configure_probe', effective)
        for bad_log in (baseline.replace(b'-O2 ', b'-O3 ', 1), baseline.replace(b' -DHAVE_HIDDEN', b'')):
            with self.subTest(log=bad_log), self.assertRaises(ValueError):
                a.configured_flags(updated, bad_log, 'pgo')
        (work / 'Makefile').write_bytes(original.replace(b'-O2 ', b'-O3 ', 1))
        before = (work / 'Makefile').read_bytes()
        with self.assertRaises(ValueError):
            pgo.apply_use_flags(a, work)
        self.assertEqual((work / 'Makefile').read_bytes(), before)

    def receipt(self, different_profiles=False):
        # Reuse the complete existing 505-command receiver fixture, then splice
        # only the adapter's real plan into its common tool/final-build boundary.
        original_configured = a.configured_flags
        def configured(makefile, log, variant):
            return original_configured(makefile, fixtures.config_bytes('baseline') if variant == 'pgo' else log, variant)
        with patch.object(a, 'profile_adapter', return_value=None), patch.object(a, 'configured_flags', side_effect=configured):
            raw, contract, report, manifest, common = fixtures.ReceiverTests.receipt(self)
        for build in report['builds']:
            if build['variant'] == 'pgo':
                directory = raw / f"pgo-{build['attempt']}"
                probe_log = directory / 'configure.log.txt'; probe_log.write_bytes(fixtures.config_bytes('baseline'))
                build['generated_configuration_sha256']['configure.log'] = a.sha(probe_log)
        source = self.root / 'inputs/zlib.tar.gz'
        with tarfile.open(source, 'r:gz') as archive:
            material = {m.name.removeprefix('zlib-1.3.2/'): archive.extractfile(m).read() for m in archive if m.isfile()}
        material.update({name: ('synthetic public training source ' + name).encode() for name in pgo.SOURCES})
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, data in material.items():
                member = tarfile.TarInfo('zlib-1.3.2/' + name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        source.write_bytes(buffer.getvalue())
        self.enterContext(patch.object(a, 'SOURCE_SHA', a.sha(source)))
        self.enterContext(patch.object(pgo, 'SOURCES', {n: hashlib.sha256(material[n]).hexdigest() for n in pgo.SOURCES}))
        contract.update(source_sha256=a.SOURCE_SHA, pgo_sha256=a.sha(Path(pgo.__file__).resolve()))
        report['contract'] = contract
        environment = json.loads((raw / 'environment.json').read_text())
        environment['tool_files']['gcov-dump'] = {'path': '/usr/bin/gcov-dump', 'sha256': 'b' * 64}
        a.save(raw / 'environment.json', environment); report['environment_sha256'] = a.sha(raw / 'environment.json')
        private = self.root / 'private'; private.mkdir()
        work, profile = private / 'build', private / 'profile'
        clock, commands, clean_training = [0.0], [], []
        def path(value):
            if value is None:
                return None
            value = str(value)
            if value.startswith('/out/'):
                return raw / value.removeprefix('/out/')
            if value.startswith('/tmp/corpus/'):
                return raw / 'corpus' / value.removeprefix('/tmp/corpus/')
            raise AssertionError('unexpected fake command path: ' + value)
        def extract(_, destination):
            for name, data in material.items():
                file = destination / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(data)
        def run(name, argv, **kwargs):
            if name.endswith('-configure'):
                cflags, ldflags = pgo.generation_flags(a)
                config = f'CC=gcc\nAR=gcc-ar\nRANLIB=gcc-ranlib\nCFLAGS={cflags} -fPIC -DHAVE_HIDDEN\nLDFLAGS={ldflags}\n'.encode()
                for config_name in ('Makefile', 'configure.log', 'zconf.h'):
                    (work / config_name).write_bytes(config)
                (profile / 'configure-probe.gcda').write_bytes(b'not a training profile')
            if name.endswith('-build'):
                for filename in pgo.BUILD_FILES:
                    (work / filename).write_bytes(('synthetic nonexecutable ' + filename).encode())
            if name.endswith('-train-encode'):
                clean_training.append(not any(profile.iterdir()))
            if '-train-' in name:
                self.profile_fixture(profile, different_profiles and name.startswith('pgo-training-2'))
            if name.endswith('-train-example'):
                destination = raw / name.removesuffix('-train-example') / 'example.gz'
                destination.write_bytes(gzip.compress(b'hello, hello!\0', mtime=0))
            target, source_path = path(kwargs.get('target')), path(kwargs.get('source'))
            if target:
                target.write_bytes(gzip.compress(a.corpus.TRAIN, mtime=0) if name.endswith('-encode') else a.corpus.TRAIN)
            data = b"synthetic: data:magic `gcda' COUNTERS arcs\n" if '-dump-' in name else b'synthetic retained adapter log\n'
            log = raw / ('adapter-' + name + '.log'); log.write_bytes(data)
            def binding(logical, actual):
                return {'path': str(logical), 'sha256': a.sha(actual), 'bytes': actual.stat().st_size} if actual else None
            commands.append({'name': name, 'argv': argv, 'cwd': kwargs.get('cwd'), 'environment': kwargs['env'],
                             'status': 'PASS', 'cleanup': 'PASS', 'exit_code': 0, 'allowed_exit_codes': [0],
                             'stdin': binding(kwargs.get('source'), source_path), 'stdout': binding(kwargs.get('target'), target),
                             'log': log.name, 'log_sha256': a.sha(log), 'log_bytes': len(data),
                             'timeout_seconds': kwargs['timeout'], 'elapsed_seconds': 1.0})
            clock[0] += 1.0
            return b'' if target is None else 0
        with patch.object(pgo, 'WORK', work), patch.object(pgo, 'PROFILE', profile), \
             patch.object(a, 'extract', side_effect=extract), patch.object(pgo.time, 'monotonic', side_effect=lambda: clock[0]):
            profile_report = pgo.prepare(a, SimpleNamespace(run=run), self.root / 'inputs', raw, a.trial_env(), raw / 'corpus', manifest)
            for attempt in (1, 2):
                profile_report['restores'].append(pgo.restore(a, raw, attempt))
                profile_report['unchanged_after_build'].append(pgo.assert_unchanged(a, raw, attempt))
        self.assertEqual(clean_training, [True, True], 'configure probes must be discarded before training')
        profile_report.update(profile_path='/tmp/profile', build_path='/tmp/build')
        report['profile'] = profile_report
        combined = common[:5] + commands + common[5:]
        # Rename through private temporary names to avoid collisions with later
        # common log names when inserting the fifty adapter commands.
        for index, row in enumerate(combined):
            old = raw / row['log']; old.rename(raw / f'renumber-{index}')
        for index, row in enumerate(combined, 1):
            file = raw / f"{index:03d}-{row['name']}.log"
            (raw / f'renumber-{index-1}').rename(file); row['log'] = file.name
        a.save(raw / 'commands.json', combined); a.save(raw / 'result.json', report)
        return raw, contract, report, manifest, combined

    def test_complete_c03_receiver_and_export_without_execution(self):
        raw, contract, report, _, _ = self.receipt()
        verified = a.verify_result(raw, contract)
        self.assertEqual(verified['receiver_verification']['command_count'], 555)
        self.assertEqual(verified['profile_verification']['profile_regeneration'], 'identical')
        exported = stage.export_artifacts(raw, self.root / 'export', verified)
        self.assertEqual(exported['purpose'], 'ARM-C03-same-job-followup')
        with tarfile.open(self.root / 'export/development-ARM-C03-outputs.tar.gz') as archive:
            self.assertEqual(len(archive.getmembers()), 145)
            self.assertEqual(sum(n.endswith('.gcda') for n in archive.getnames()), 34)

    def test_independent_profile_regeneration_difference_is_honest_not_a_gate(self):
        raw, contract, report, _, _ = self.receipt(different_profiles=True)
        self.assertEqual(a.verify_result(raw, contract)['profile_verification']['profile_regeneration'], 'different')
        report['profile']['profile_regeneration'] = 'identical'; a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'regeneration observation'):
            a.verify_result(raw, contract)

    def test_receiver_rejects_profile_and_training_artifact_tampering(self):
        raw, contract, report, _, _ = self.receipt()
        file = raw / 'pgo-training-1/profiles' / pgo.PROFILE_NAMES[0]
        before = file.read_bytes(); file.write_bytes(before + b'changed')
        with self.assertRaisesRegex(ValueError, 'profile map'):
            a.verify_result(raw, contract)
        file.write_bytes(before)
        file = raw / 'pgo-training-1/train.decoded'; file.write_bytes(b'wrong decoded bytes')
        with self.assertRaisesRegex(ValueError, 'training artifact'):
            a.verify_result(raw, contract)

    def test_receiver_rejects_dump_binding_and_profile_restore_mismatch(self):
        raw, contract, report, _, commands = self.receipt()
        row = next(r for r in commands if '-dump-' in r['name'])
        log = raw / row['log']; log.write_bytes(b"data:magic `gcda' no counters or usable coverage\n")
        row.update(log_sha256=a.sha(log), log_bytes=log.stat().st_size); a.save(raw / 'commands.json', commands)
        with self.assertRaisesRegex(ValueError, 'gcov-dump'):
            a.verify_result(raw, contract)
        log.write_bytes(b"data:magic `gcda' COUNTERS arcs\n")
        row.update(log_sha256=a.sha(log), log_bytes=log.stat().st_size); a.save(raw / 'commands.json', commands)
        report['profile']['restores'][1]['profiles'] = []; a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'unchanged first-attempt'):
            a.verify_result(raw, contract)

    def test_receiver_rejects_excess_training_time_and_changed_source(self):
        raw, contract, report, _, _ = self.receipt()
        report['profile']['attempts'][0]['training_elapsed_seconds'] = 121; a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'training elapsed'):
            a.verify_result(raw, contract)
        report['profile']['attempts'][0]['training_elapsed_seconds'] = 4; a.save(raw / 'result.json', report)
        file = raw / 'pgo-training-1/test-example.c'; file.write_bytes(b'heldout training substituted')
        report['profile']['attempts'][0]['files'][file.name] = pgo._binding(a, file); a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'training source differs'):
            a.verify_result(raw, contract)
