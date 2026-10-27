#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed-map compatibility and unchanged lane checks; no native actors."""
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
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('fixed_native_source', HERE/'prepare.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
SOURCE = HERE.parents[2]


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = tempfile.TemporaryDirectory(prefix='default-native-seed-'); cls.addClassCleanup(cls.seed.cleanup)
        cls.original = Path(cls.seed.name)/'source'; cls.original.mkdir()
        names = set(p.BUILD)
        for profile in p.PROFILES:
            name = p.profile_path(profile); raw = (SOURCE/name).read_bytes()
            if p.pin(raw) != p.row(p.PROFILES[profile]):raise ValueError('independently pinned manifest required: '+profile)
            names.add(name); names.update(p.source_map(profile,json.loads(raw))); names.update(p.EXTRA.get(profile, {}))
        names.update(p.SHARED+'/'+Path(name).name for name in p.BUILD)
        for name in names:
            target = cls.original/name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(SOURCE/name, target)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='default-native-test-'); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.source = self.base/'source'; shutil.copytree(self.original, self.source)
        self.output = self.base/'view'; self.profile = 'apps7-client-native'

    def prepare(self):return p.prepare(self.source, self.output, self.profile)

    def refused(self):
        with self.assertRaises((ValueError, OSError, KeyError)):self.prepare()
        self.assertFalse(self.output.exists())

    def evolve(self):
        for name in p.BUILD:
            path = self.source/name; path.write_bytes(path.read_bytes()+b'\n# evolved current helper; never run in old controls\n')

    def command(self, argv, cwd):
        result = subprocess.run([str(v)for v in argv], cwd=cwd, capture_output=True, timeout=120,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace')+result.stderr.decode(errors='replace'))
        return result

    def test_complete_disjoint_views_keep_every_original_declared_byte(self):
        self.evolve()
        for profile, expected_manifest in p.PROFILES.items():
            with self.subTest(profile=profile):
                output = self.base/profile
                with patch.object(subprocess, 'Popen', side_effect=AssertionError('emitter cannot start actors')):
                    receipt = p.prepare(self.source, output, profile)
                name = p.profile_path(profile)
                original=json.loads((self.source/name).read_bytes())
                expected = {**p.source_map(profile,original), name:p.row(expected_manifest),
                            **{key:p.row(want)for key,want in p.EXTRA.get(profile, {}).items()}}
                actual={f.relative_to(output).as_posix():p.pin(f.read_bytes())for f in output.rglob('*')if f.is_file()}
                self.assertEqual(actual.keys(),expected.keys())
                self.assertTrue(all(p.matches(actual[name],want)for name,want in expected.items()))
                self.assertEqual(receipt['files'], len(expected)); self.assertFalse(receipt['current_helpers_used'])
                self.assertFalse(receipt['acceptance']); self.assertIsNone(receipt['run_id']); self.assertEqual(receipt['native'], 'NOT_RUN')
                for helper in receipt['substituted']:
                    self.assertNotEqual(receipt['current_build_helpers'][helper], receipt['substituted'][helper])
                    self.assertNotEqual(os.stat(self.source/helper).st_ino, os.stat(output/helper).st_ino)

    def test_evolution_rejected_directly_but_accepted_only_through_view(self):
        self.evolve()
        run = subprocess.run([sys.executable, '-I', '-B', str(self.source/'scripts/ci/apps7-client-native/preflight.py'),
                              '--source', str(self.source)], capture_output=True, timeout=30)
        self.assertNotEqual(run.returncode, 0); self.assertIn(b'scripts/build/build.py', run.stderr)
        self.prepare()
        run = self.command([sys.executable, '-I', '-B', self.output/'scripts/ci/apps7-client-native/preflight.py', '--source', self.output], self.output)
        self.assertEqual(json.loads(run.stdout)['native'], 'NOT_RUN')

    def test_unchanged_preflights_and_lane_suites_use_each_fixed_view(self):
        self.evolve()
        for profile in p.PROFILES.keys()-p.DESKTOP-p.CONFIGS.keys():
            with self.subTest(profile=profile):
                view = self.base/profile; p.prepare(self.source, view, profile)
                if profile == 'ksm2-upgrade-native':
                    emitted = self.base/'ksm2-prepared'
                    self.command([sys.executable, '-I', '-B', view/'scripts/ci'/profile/'prepare.py', '--source', view,
                        '--output', emitted, '--baseline-recipe', view/'packages/tools/cachy-asahi-ksmctl',
                        '--candidate-recipe', view/'packages/tools/cachy-asahi-ksmctl2'], view)
                    view = emitted
                self.command([sys.executable, '-I', '-B', view/'scripts/ci'/profile/'preflight.py', '--source', view], view)
                result = self.command([sys.executable, '-B', '-Werror::ResourceWarning', '-m', 'unittest', 'discover',
                    '-s', view/'scripts/ci'/profile, '-p', 'test_lane.py', '-v'], view)
                self.assertRegex(result.stderr, rb'Ran [1-9][0-9]* tests?'); self.assertIn(b'\nOK\n', result.stderr)
                self.assertNotIn(b'skipped=', result.stderr)
                print(json.dumps(dict(profile=profile, original_tests='PASS',
                    tests=int(result.stderr.rsplit(b'\nRan ',1)[1].split()[0]), native='NOT_RUN')), flush=True)

    def test_unchanged_desktop_suites_use_fixed_views(self):
        self.evolve()
        for profile,pattern in (('desktop-user-session','test_managed.py'),('desktop-file-manager-workflow','test_workflow.py')):
            with self.subTest(profile=profile):
                view=self.base/profile;p.prepare(self.source,view,profile)
                result=self.command([sys.executable,'-B','-Werror::ResourceWarning','-m','unittest','discover',
                    '-s',view/'scripts/ci'/profile,'-p',pattern,'-v'],self.source)
                self.assertIn(b'\nOK\n',result.stderr);self.assertNotIn(b'skipped=',result.stderr)
                print(json.dumps(dict(profile=profile,original_tests='PASS',
                    tests=int(result.stderr.rsplit(b'\nRan ',1)[1].split()[0]),native='NOT_RUN')),flush=True)

    def test_desktop_map_and_supplemental_source_drift_refused(self):
        for profile in p.DESKTOP:
            self.profile=profile
            for name in ('scripts/ci/'+profile+'/source-pins.json',next(iter(p.EXTRA[profile]))):
                path=self.source/name;raw=path.read_bytes();path.write_bytes(raw+b'\n# drift\n')
                with self.subTest(profile=profile,name=name):self.refused()
                path.write_bytes(raw)

    def test_desktop_substitutes_only_declared_two_helpers(self):
        (self.source/'scripts/build/compare.py').unlink();(self.source/p.SHARED/'compare.py').unlink()
        for profile in p.DESKTOP:
            output=self.base/profile;receipt=p.prepare(self.source,output,profile)
            self.assertEqual(set(receipt['substituted']),set(p.BUILD)-{'scripts/build/compare.py'})
            self.assertFalse((output/'scripts/build/compare.py').exists())
            self.assertNotIn('scripts/build/compare.py',receipt['current_build_helpers'])

    def test_unrelated_declared_source_drift_refused(self):
        path = self.source/'scripts/checks/package_checks.py'; path.write_bytes(path.read_bytes()+b'\n# drift\n'); self.refused()

    def test_changed_map_cannot_authorize_changed_nonhelper_source(self):
        path = self.source/'scripts/ci/apps7-client-native/source-manifest.json'; value = json.loads(path.read_bytes())
        name = 'scripts/checks/package_checks.py'; changed = self.source/name; changed.write_bytes(changed.read_bytes()+b'\n# drift\n')
        value['files'][name] = p.pin(changed.read_bytes()); path.write_text(json.dumps(value)); self.refused()

    def test_supplemental_original_workflow_drift_refused(self):
        path=self.source/'.github/workflows/native-arm-apps7-client.yml'
        path.write_bytes(path.read_bytes()+b'\n# workflow drift\n');self.refused()

    def test_each_selected_snapshot_drift_refused(self):
        for helper in p.BUILD:
            path = self.source/p.SHARED/Path(helper).name; raw = path.read_bytes(); path.write_bytes(raw+b'\n# drift\n')
            with self.subTest(helper=helper):self.refused()
            path.write_bytes(raw)

    def test_missing_snapshot_has_no_live_original_fallback(self):
        (self.source/p.SHARED/'build.py').unlink(); self.refused()

    def test_missing_unrelated_source_and_hardlink_refused(self):
        path = self.source/'scripts/checks/package_checks.py'; raw = path.read_bytes(); path.unlink(); self.refused()
        path.write_bytes(raw); os.link(path, self.base/'hardlinked-source'); self.refused()

    def test_source_snapshot_and_parent_alias_refused(self):
        path = self.source/p.SHARED/'build.py'; path.unlink(); path.symlink_to(self.source/'scripts/build/build.py'); self.refused()
        path.unlink(); shutil.copy2(self.original/p.SHARED/'build.py', path)
        alias = self.base/'alias'; alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):p.prepare(alias, self.output, self.profile)
        self.assertFalse(self.output.exists())

    def test_unknown_selector_cannot_supply_arbitrary_manifest_authority(self):
        for value in ('all', '../apps7-client-native', 'tools-native', '', None):
            self.profile = value
            with self.subTest(value=value):self.refused()

    def test_output_overlap_or_existing_output_preserved(self):
        with self.assertRaises(ValueError):p.prepare(self.source, self.source/'nested-view', self.profile)
        self.output.mkdir(); marker = self.output/'keep'; marker.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(marker.read_bytes(), b'keep')

    def test_double_leading_slash_cannot_hide_source_output_overlap(self):
        nested=self.source/'nested-view'
        for source,output in ((self.source,'/'+str(nested)),('/'+str(self.source),self.output)):
            with self.subTest(source=str(source),output=str(output)),self.assertRaises(ValueError):
                p.prepare(source,output,self.profile)
        self.assertFalse(nested.exists());self.assertFalse(self.output.exists())

    def test_view_excludes_current_inventory_and_enhanced_builder_inputs(self):
        self.prepare(); names = {f.relative_to(self.output).as_posix()for f in self.output.rglob('*')if f.is_file()}
        self.assertTrue({'manifests/packages.toml','scripts/build/source_materials.py','tests/test_offline_sources.py'}.isdisjoint(names))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--source', type=Path, default=SOURCE)
    args, remaining = parser.parse_known_args(); SOURCE = args.source.absolute()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
