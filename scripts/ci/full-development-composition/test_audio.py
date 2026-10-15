#!/usr/bin/env python3
"""Finite audio selection/refusal/transaction-order fixtures; no system actors."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/checks/package_checks.py').is_file())


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


inputs = load('audio_preparation', 'audio_inputs.py')
audio = load('audio_trial', 'audio.py')
api = load('audio_composition_api', 'run.py')
container = load('audio_container_api', 'container.py')


class Audio(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows = json.loads((HERE / 'audio-inputs.json').read_text())
        self.before = container.lock((ROOT / 'scripts/ci/full-development-composition/expected-installed.lock').read_text())
        (self.root / 'expected-audio.lock').write_bytes((HERE / 'expected-audio.lock').read_bytes())

    def report(self, row):
        members = {p.removeprefix('/'): {'type': '0', 'mode': 0o644, 'uid': 0, 'gid': 0, 'sha256': '0' * 64}
                   for p in ('.PKGINFO', '.BUILDINFO', '.MTREE')}
        members.update({p: {'type': '5', 'mode': 0o755, 'uid': 0, 'gid': 0} for p in row['directories']})
        members.update({p['path'].removeprefix('/'): {'type': '0', 'mode': p['mode'], 'uid': 0, 'gid': 0, 'sha256': p['sha256']} for p in row['payload']})
        return {'sha256': row['sha256'], 'metadata': {'.PKGINFO': copy.deepcopy(row['metadata'])},
                'members': members, 'errors': row['generic_errors'][:], 'elf': {p: {'errors': []} for p in row['elf_paths']}}

    def test_exact_six_inventory_and_upstream_signature_selection(self):
        self.assertEqual(api.sha(HERE / 'audio-inputs.json'), inputs.POLICY)
        self.assertEqual(api.sha(HERE / 'expected-audio.lock'), audio.EXPECTED)
        self.assertEqual(len(audio.expected_inventory(self.root, self.before, self.rows, container)), 593)
        self.assertEqual({r['name'] for r in self.rows if r['origin'] == 'ALARM'}, {'lsp-plugins-lv2'})
        self.assertEqual(sum(len(r['metadata'].get('depend', [])) for r in self.rows), 22)
        self.assertEqual([len(r['generic_errors']) for r in self.rows], [10, 54, 5, 0, 0, 0])
        bad = dict(self.before); bad['bash'] = '99-1'
        with self.assertRaisesRegex(ValueError, 'checkpoint'): audio.expected_inventory(self.root, bad, self.rows, container)
        (self.root / 'expected-audio.lock').write_text((HERE / 'expected-audio.lock').read_text().replace('bash ', 'unexpected-bash '))
        with self.assertRaisesRegex(ValueError, 'inventory pin'): audio.expected_inventory(self.root, self.before, self.rows, container)

    def test_exact_payloads_and_closed_generic_errors(self):
        for row in self.rows:
            report = self.report(row)
            self.assertEqual(inputs.inspect(row, report, api)['depends'], row['metadata'].get('depend', []))
        row = self.rows[0]
        for mutate in (lambda r: r['errors'].append('unrelated failure'), lambda r: r['errors'].pop(),
                       lambda r: r.update(sha256='0' * 64),
                       lambda r: r['metadata']['.PKGINFO'].update(depend=[]),
                       lambda r: r['members'].update({'.INSTALL': {'type': '0'}}),
                       lambda r: r['members'][row['payload'][0]['path'].removeprefix('/')].update(sha256='0' * 64),
                       lambda r: r['members'][row['payload'][0]['path'].removeprefix('/')].update(mode=0o755),
                       lambda r: r['members'][row['payload'][0]['path'].removeprefix('/')].update(uid=1000)):
            report = self.report(row); mutate(report)
            with self.subTest(mutation=mutate), self.assertRaises((AssertionError, KeyError)):
                inputs.inspect(row, report, api)
        row = self.rows[2]; report = self.report(row)
        report['elf'][row['elf_paths'][0]]['errors'] = ['bad AArch64 layout']
        with self.assertRaisesRegex(AssertionError, 'ELF'): inputs.inspect(row, report, api)

    def simulate(self, drift=None, signature_failure=False):
        state = dict(self.before); events = []
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row.update(payload=[], signature_sha256='a' * 64, signature_size=1)
        plan = {'audio': {'packages': rows, 'expected_inventory_sha256': audio.EXPECTED}, 'projects': []}
        def command(argv):
            if '-U' in argv:
                state.update({r['name']: r['version'] for r in rows}); events.append(('install', len(state)))
                if drift == 'install': state['bash'] = '99-1'
            elif '-R' in argv:
                for name in argv[argv.index('-R') + 1:]: del state[name]
                events.append(('remove', len(state)))
                if drift == 'remove': state['bash'] = '99-1'
            self.assertNotIn('--nodeps', argv); self.assertNotIn('-Rdd', argv); self.assertNotIn('-Rs', argv)
            return ''
        c = SimpleNamespace(guard=Mock(), inventory=lambda: dict(state), need=container.need, lock=container.lock,
            run=Mock(side_effect=command), pin=Mock(side_effect=ValueError('signature drift') if signature_failure else None),
            archive_metadata=lambda row, source: row['metadata'])
        helper = SimpleNamespace(payloads=Mock(side_effect=lambda *args: events.append(('payload', len(state)))))
        with patch.object(audio, 'database', return_value={}), patch.object(audio.Path, 'exists', return_value=False):
            result = audio.run(['pacman', '--config', '/inert/private.conf'], plan, self.before, self.root, self.root, c, helper)
        return result, events, c

    def test_signed_install_dependency_aware_removal_restores_original587(self):
        result, events, c = self.simulate()
        self.assertEqual(events, [('install', 593), ('payload', 593), ('remove', 592), ('remove', 587), ('payload', 587)])
        self.assertEqual(result['final_inventory_sha256'], audio.BASE)
        self.assertEqual(c.pin.call_count, 12)
        for call in c.run.call_args_list:
            argv = call.args[0]
            if '-U' in argv or '-R' in argv: self.assertIn('--noscriptlet', argv)
        self.assertTrue(any('-T' in call.args[0] for call in c.run.call_args_list))

    def test_transaction_or_signature_failure_cannot_be_reported_pass(self):
        for phase in ('install', 'remove'):
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, 'inventory|unrelated'):
                self.simulate(drift=phase)
        with self.assertRaisesRegex(ValueError, 'signature drift'): self.simulate(signature_failure=True)

    def test_original_package_database_changes_are_detected(self):
        directory = self.root / 'database'; directory.mkdir()
        (directory / 'desc').write_text('original')
        before = audio.database(directory)
        (directory / 'addition').write_text('new')
        audio.originals_preserved(before, directory, container)
        with self.assertRaisesRegex(ValueError, 'database changed'):
            audio.originals_preserved(before, directory, container, final=True)
        (directory / 'desc').write_text('changed original')
        with self.assertRaisesRegex(ValueError, 'database changed'):
            audio.originals_preserved(before, directory, container)


if __name__ == '__main__': unittest.main()
