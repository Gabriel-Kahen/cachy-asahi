#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual-input export/relocation/refusal controls, with actors and sockets fenced."""
import argparse
import builtins
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_delivery_tests', HERE / 'delivery.py')
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class ActualDelivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='actual-audio-source-export-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.packet = cls.root / 'export'
        cls.checkout = HERE.parents[2]
        with mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('actor forbidden')):
            result = d.export(cls.checkout, Path(ARGS.handoff), Path(ARGS.materials), Path(ARGS.wmidi), cls.packet)
        cls.checksum = result['delivery_sha256']
        cls.result = result
        # This recipient runtime contains only trusted Python/data APIs, no package sources/cache.
        cls.runtime = cls.root / 'trusted-runtime'
        paths = [
            'scripts/port/platform-audio-source-delivery/delivery.py',
            'scripts/port/platform-audio-source-delivery/delivery-profile.json',
            'scripts/port/platform-audio-registry-sources/join.py',
            'scripts/port/platform-audio-registry-sources/registry-inputs.json',
            'scripts/port/platform-audio-vendor-audit/audit.py',
            'scripts/port/platform-audio-sources/intake.py',
            'scripts/release/platform_audio_source_delivery.py',
            'scripts/release/platform_audio_source_profiles.json',
            'scripts/release/source_delivery.py', 'scripts/checks/package_checks.py',
        ]
        for name in paths:
            target = cls.runtime / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(cls.checkout / name, target)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='audio-delivery-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.copy = self.root / 'relocated packet'
        shutil.copytree(self.packet, self.copy)
        self.sha = self.checksum

    def resign(self, edit=None):
        path = self.copy / 'delivery.json'; saved = json.loads(path.read_bytes())
        j, a, intake, inputs, profile = d.load(self.checkout)
        material = d.packet_files(intake, self.copy); material.pop('delivery.json')
        saved['files'] = {p: d.desc(b) for p, b in sorted(material.items())}
        if edit:
            edit(saved)
        raw = d.encoded(saved); path.write_bytes(raw); self.sha = d.sha(raw)

    def refused(self):
        with self.assertRaises((ValueError, OSError, KeyError, TypeError)):
            d.verify(self.checkout, self.copy, self.sha)

    def test_relocation_with_original_reads_sockets_and_actors_forbidden(self):
        original_open, original_os_open = builtins.open, os.open
        denied = [str(Path(ARGS.handoff).absolute()), str(Path(ARGS.materials).absolute()),
                  str(Path(ARGS.wmidi).absolute()), str(self.checkout / 'packages')]
        def guard(path):
            if isinstance(path, (str, bytes, os.PathLike)):
                text = os.fsdecode(path)
                if any(text == prefix or text.startswith(prefix + '/') for prefix in denied):
                    raise AssertionError('original acquisition/source read forbidden')
        def checked_open(path, *args, **kwargs):
            guard(path); return original_open(path, *args, **kwargs)
        def checked_os_open(path, *args, **kwargs):
            guard(path); return original_os_open(path, *args, **kwargs)
        with mock.patch('builtins.open', side_effect=checked_open), mock.patch('os.open', side_effect=checked_os_open), \
             mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('actor forbidden')):
            result = d.verify(self.runtime, self.copy, self.sha)
        self.assertEqual(result['registry']['exact_crates'], 117)
        self.assertEqual(result['registry']['exact_member_files'], 4292)
        self.assertEqual(result['registry']['metadata_reachable_registry_identities'], 88)
        self.assertFalse(result['holds']['legal_acceptance'])
        self.assertFalse(result['holds']['complete_corresponding_source_accepted'])

    def test_cli_from_unrelated_directory_with_minimal_trusted_runtime(self):
        result = subprocess.run([sys.executable, '-I', '-B',
            str(self.runtime / 'scripts/port/platform-audio-source-delivery/delivery.py'),
            '--trusted-checkout', str(self.runtime), 'verify', '--packet', str(self.copy), '--sha256', self.sha],
            cwd='/', capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)['registry']['exact_member_files'], 4292)

    def test_all_original_handoff_files_and_raw_archives_preserved(self):
        j, a, intake, inputs, profile = d.load(self.checkout)
        for name, raw in intake.files(Path(ARGS.handoff)).items():
            self.assertEqual((self.copy / 'handoff' / name).read_bytes(), raw)
        for row in inputs['sources']:
            for key in ('archive', 'index'):
                name = row[key]['path']
                self.assertEqual((self.copy / 'registry' / name).read_bytes(), (Path(ARGS.materials) / name).read_bytes())

    def test_public_projections_exclude_private_receipt_and_environment(self):
        original = (Path(ARGS.materials) / 'acquisition.json').read_bytes()
        self.assertIn(b'original_path', original)
        for path in self.copy.rglob('*.json'):
            raw = path.read_bytes()
            for forbidden in (b'/home/gabe/', b'/tmp/', b'original_path', b'CARGO_HOME', b'tool_probes'):
                self.assertNotIn(forbidden, raw, str(path))
        receipt = json.loads((self.copy / 'registry/acquisition.json').read_bytes())
        self.assertEqual(len(receipt['objects']), 168)
        self.assertEqual(len(receipt['cache_reuse']), 57)
        self.assertEqual(receipt['downloaded_body_bytes'], 11859347)
        self.assertNotEqual(d.sha(original), d.sha(d.encoded(receipt)))

    def test_wmidi_exact_tree_gap_remains_explicit(self):
        report = json.loads((self.copy / 'wmidi-source-observation.json').read_bytes())
        self.assertEqual(report['reconstructed_git_tree'], d.WMIDI_TREE)
        self.assertEqual(report['exact_upstream_regular_files'], 8)
        self.assertFalse(report['exact_tree_license_observation']['text_presence'])
        self.assertFalse(report['grant_or_legal_acceptance'])
        j, a, intake, inputs, profile = d.load(self.checkout)
        info = json.loads((self.copy / 'wmidi/commit.json').read_bytes()); info['tree']['sha'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'WMIDI_COMMIT_TREE_IDENTITY'):
            d.wmidi_report(j, a, (self.copy / 'registry/crates/wmidi-3.1.0.crate').read_bytes(),
                           (self.copy / 'wmidi/source.tar.gz').read_bytes(), d.encoded(info))

    def test_missing_each_critical_input_class_refuses(self):
        paths = ['registry/crates/wmidi-3.1.0.crate', 'registry/indexes/wmidi.jsonl',
                 'handoff/sources/bankstown/source.tar', 'wmidi/source.tar.gz']
        # The actual sparse snapshot filename is independently selected from public inputs.
        j, a, intake, inputs, profile = d.load(self.checkout)
        paths[1] = 'registry/' + next(r for r in inputs['sources'] if r['name'] == 'wmidi')['index']['path']
        paths.append('handoff/archives/' + next(iter(json.loads((self.copy / 'handoff/native-inputs.json').read_bytes())['packages'].values()))['archive']['filename'])
        for name in paths:
            with self.subTest(name=name):
                path = self.copy / name; raw = path.read_bytes(); path.unlink()
                self.refused(); path.write_bytes(raw); path.chmod(0o600)

    def test_tampered_archive_and_wrong_trusted_digest_refuse(self):
        self.sha = '0' * 64; self.refused(); self.sha = self.checksum
        path = self.copy / 'registry/crates/wmidi-3.1.0.crate'
        path.write_bytes(path.read_bytes() + b'changed'); self.refused()
        self.resign(); self.refused()

    def test_receipt_cannot_smuggle_private_fields_even_with_new_outer_hash(self):
        path = self.copy / 'registry/acquisition.json'; value = json.loads(path.read_bytes())
        value['cache_reuse'][0]['original_path'] = '/private/operator/cache'
        path.write_bytes(d.encoded(value)); self.resign(); self.refused()

    def test_metadata_cannot_change_even_with_new_outer_hash(self):
        path = self.copy / 'registry/metadata-replay.json'
        path.write_bytes(path.read_bytes() + b' '); self.resign(); self.refused()

    def test_acceptance_or_recomputed_report_cannot_be_forged(self):
        self.resign(lambda saved: saved['holds'].update(legal_acceptance=True))
        self.refused()
        path = self.copy / 'registry-source-join.json'; value = json.loads(path.read_bytes())
        value['legal_acceptance'] = True; path.write_bytes(d.encoded(value))
        self.resign(); self.refused()

    def test_extra_links_empty_directories_and_modes_refuse(self):
        path = self.copy / 'unexpected'; path.write_bytes(b'not authorized'); path.chmod(0o600)
        self.resign(); self.refused(); path.unlink()
        path.mkdir(mode=0o700); self.refused(); path.rmdir()
        path.symlink_to('/etc/passwd'); self.refused(); path.unlink()
        path = self.copy / 'wmidi/source.tar.gz'; path.chmod(0o644); self.refused()

    def test_existing_destination_preserved(self):
        before = (self.copy / 'delivery.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'OUTPUT_ALREADY_EXISTS'):
            d.export(self.checkout, Path(ARGS.handoff), Path(ARGS.materials), Path(ARGS.wmidi), self.copy)
        self.assertEqual((self.copy / 'delivery.json').read_bytes(), before)

    def test_missing_original_material_refuses_before_output(self):
        materials = self.root / 'materials'; materials.mkdir(mode=0o700)
        output = self.root / 'must-not-exist'
        with self.assertRaises(OSError):
            d.export(self.checkout, Path(ARGS.handoff), materials, Path(ARGS.wmidi), output)
        self.assertFalse(output.exists())

    def test_output_below_original_inputs_refuses_without_mutation(self):
        for original in (Path(ARGS.handoff), Path(ARGS.materials), Path(ARGS.wmidi)):
            output = original / 'must-never-be-created-source-export'
            with self.subTest(original=original), self.assertRaisesRegex(ValueError, 'OUTPUT_OVERLAPS_ORIGINAL_INPUT'):
                d.export(self.checkout, Path(ARGS.handoff), Path(ARGS.materials), Path(ARGS.wmidi), output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('handoff', 'materials', 'wmidi'):
        parser.add_argument('--' + name, required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
