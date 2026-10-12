#!/usr/bin/env python3
import importlib.util
import copy
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
import struct
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gate', HERE / 'build-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def elf(alignment=16384, offset=0, virtual=0):
    data = bytearray(120)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, 183)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, offset, virtual, 0, 120, 120, alignment)
    return data


class GateTests(unittest.TestCase):
    def test_policy_flags_are_not_execution_evidence(self):
        with self.assertRaisesRegex(ValueError, 'PASS flags'):
            gate.policy_check({'license_closure': 'PASS', 'build_script_review': 'PASS'})

    def test_checked_policy_contains_constraints_not_acceptance(self):
        policy = json.loads((HERE / 'build-policy.json').read_text())
        gate.policy_check(policy)
        self.assertNotIn('license_closure', policy)
        changed = copy.deepcopy(policy)
        changed['evidence_sha256']['build-script-review.json'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'constraints differ'):
            gate.policy_check(changed)
        changed = copy.deepcopy(policy)
        changed['module_sha256']['worker-metadata.py'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'code pins differ'):
            gate.policy_check(changed)

    def script_fixture(self):
        script, included, helper = b'// inert reviewed script', b'inert source input', b'// inert helper'
        ledger, reviewed = [], []
        for i in range(38):
            row = {'name': 'fixture' + str(i), 'version': '1.0.0', 'archive_sha256': 'a' * 64,
                   'source_files_sha256': 'b' * 64, 'normalized_manifest_sha256': 'c' * 64,
                   'build_dependencies': {}, 'target_build_dependencies': {},
                   'build_scripts': [{'path': 'build.rs', 'sha256': gate.sha(script)}]}
            ledger.append(row)
            reviewed.append({'name': row['name'], 'version': row['version'], 'archive_sha256': row['archive_sha256'],
                             'source_files_sha256': row['source_files_sha256'], 'manifest_sha256': row['normalized_manifest_sha256'],
                             'build_dependencies': {}, 'target_build_dependencies': {},
                             'scripts': [{'path': 'build.rs', 'sha256': gate.sha(script), 'bytes': len(script)}],
                             'input_files': [{'path': 'input.txt', 'sha256': gate.sha(included), 'bytes': len(included)}],
                             'helper_dependencies': ['fixture1-1.0.0'] if i == 0 else []})
        audit = {'registry_sources': ledger, 'cargo_lock_sha256': 'd' * 64}
        review = {'packages': reviewed, 'cargo_lock_sha256': audit['cargo_lock_sha256'],
                  'audit_input_sha256': gate.EVIDENCE['cargo-audit.json'],
                  'helper_paths': [{'package': 'fixture1-1.0.0', 'files': [{'path': 'helper.rs', 'sha256': gate.sha(helper), 'bytes': len(helper)}]}]}
        sources = {(row['name'], row['version']): {'build.rs': script, 'input.txt': included, 'helper.rs': helper} for row in ledger[:2]}
        return review, audit, sources

    def test_entrypoints_and_helpers_match_actual_files(self):
        review, audit, sources = self.script_fixture()
        self.assertEqual(gate.script_gate(review, audit, sources), 2)
        sources[('fixture1', '1.0.0')]['helper.rs'] = b'changed'
        with self.assertRaisesRegex(ValueError, 'helper source differs'):
            gate.script_gate(review, audit, sources)

    def test_script_changed_without_new_grant_refused(self):
        review, audit, sources = self.script_fixture()
        sources[('fixture0', '1.0.0')]['build.rs'] = b'changed'
        with self.assertRaisesRegex(ValueError, 'actual script'):
            gate.script_gate(review, audit, sources)

    def test_missing_selected_build_helper_refused(self):
        review, audit, sources = self.script_fixture()
        sources.pop(('fixture1', '1.0.0'))
        with self.assertRaisesRegex(ValueError, 'helper missing'):
            gate.script_gate(review, audit, sources)

    def test_review_cannot_skip_or_invent_scripts(self):
        for kind in ('missing', 'duplicate', 'hash'):
            review, audit, sources = self.script_fixture()
            if kind == 'missing':
                review['packages'].pop()
            elif kind == 'duplicate':
                review['packages'][-1] = review['packages'][0]
            else:
                review['packages'][0]['scripts'][0]['sha256'] = '0' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                gate.script_gate(review, audit, sources)

    def test_included_source_rechecked(self):
        review, audit, sources = self.script_fixture()
        sources[('fixture0', '1.0.0')].pop('input.txt')
        with self.assertRaisesRegex(ValueError, 'actual script'):
            gate.script_gate(review, audit, sources)

    def test_current_guard_failure_precedes_source_or_receipt_reads(self):
        worker = SimpleNamespace(observe=Mock(return_value={}), guard=Mock(side_effect=ValueError('host refused')))
        closure = Mock()
        with self.assertRaisesRegex(ValueError, 'host refused'):
            gate.compile_inputs(SimpleNamespace(), {}, worker, closure)
        closure.read.assert_not_called()

    def test_controller_pin_is_externally_injected(self):
        worker = SimpleNamespace(observe=Mock(return_value={}), guard=Mock(), verify_controller=Mock())
        closure = Mock()
        args = SimpleNamespace(controller_input=Path('/inputs/controller-input.json'), controller_input_sha256='a' * 64)
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'externally injected'):
            gate.compile_inputs(args, {}, worker, closure)
        worker.verify_controller.assert_not_called()
        closure.read.assert_not_called()

    def test_actual_tray_bytes_and_extra_build_inputs_refused(self):
        data = {'Cargo.toml': b'manifest', 'Cargo.lock': b'lock', 'src/main.rs': b'// pinned source'}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, value in data.items():
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(value)
            closure = SimpleNamespace(PINS={'manifest': gate.sha(data['Cargo.toml']), 'lock': gate.sha(data['Cargo.lock'])},
                                      read=lambda path, limit: path.read_bytes())
            source = {'files_sha256': {'src/tray/' + n: gate.sha(v) for n, v in data.items()}}
            gate.source_gate(source, root / 'Cargo.toml', closure)
            (root / 'src/main.rs').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                gate.source_gate(source, root / 'Cargo.toml', closure)
            (root / 'src/main.rs').write_bytes(data['src/main.rs'])
            (root / 'build.rs').write_bytes(b'// unexpected code')
            with self.assertRaisesRegex(ValueError, 'extra tray'):
                gate.source_gate(source, root / 'Cargo.toml', closure)

    def test_only_canonical_target_output_pruned(self):
        data = {'Cargo.toml': b'manifest', 'Cargo.lock': b'lock', 'src/main.rs': b'// pinned source'}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, value in data.items():
                output = root / name
                output.parent.mkdir(exist_ok=True)
                output.write_bytes(value)
            (root / 'target/release').mkdir(parents=True)
            (root / 'target/release/output').write_bytes(b'generated output')
            closure = SimpleNamespace(PINS={'manifest': gate.sha(data['Cargo.toml']), 'lock': gate.sha(data['Cargo.lock'])},
                                      read=lambda path, limit: path.read_bytes())
            source = {'files_sha256': {'src/tray/' + n: gate.sha(v) for n, v in data.items()}}
            gate.source_gate(source, root / 'Cargo.toml', closure)
            (root / 'src/target').mkdir()
            (root / 'src/target/extra.rs').write_bytes(b'new code')
            with self.assertRaisesRegex(ValueError, 'extra tray'):
                gate.source_gate(source, root / 'Cargo.toml', closure)

    def test_generated_target_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'target').symlink_to('/tmp', target_is_directory=True)
            closure = SimpleNamespace(PINS={'manifest': 'a', 'lock': 'b'})
            source = {'files_sha256': {'src/tray/Cargo.toml': 'a', 'src/tray/Cargo.lock': 'b'}}
            with self.assertRaisesRegex(ValueError, 'symlink'):
                gate.source_gate(source, root / 'Cargo.toml', closure)

    def test_repeated_selected_report_requires_identical_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'selected-closure.json'
            reader = lambda p, limit: p.read_bytes()
            gate.save_report(output, b'fresh selected graph', reader)
            gate.save_report(output, b'fresh selected graph', reader)
            with self.assertRaisesRegex(ValueError, 'evidence differs'):
                gate.save_report(output, b'old or edited graph', reader)
            self.assertEqual(output.read_bytes(), b'fresh selected graph')

    def receipt_fixture(self, root):
        inventory = b'fixture 1.0\n'
        native = 'aarch64-unknown-linux-gnu'
        version = ('rustc 1.99.0\nrelease: 1.99.0\nhost: ' + native + '\n').encode()
        metadata, cfg = b'{"fixture":true}', b'fixture-cfg\n'
        facts = {'image_id': 'sha256:' + 'a' * 64, 'nonce': 'b' * 32}
        tools = {'schema_version': 1, 'tools': {'/usr/bin/cargo': {'resolved_path': '/usr/bin/cargo', 'sha256': 'c' * 64}}}
        controller = {**facts, 'builder_inventory_sha256': gate.sha(inventory), 'tool_pins': tools}
        worker = {'observed_worker': facts, **facts, 'builder_inventory_sha256': gate.sha(inventory),
                  'controller_sha256': 'd' * 64, 'verified_tool_pins': tools, 'tool_sha256': {'cargo': 'c' * 64},
                  'metadata_argv': ['/usr/bin/cargo', 'metadata'], 'rustc_vv_sha256': gate.sha(version)}
        commands = {'cargo-metadata': (worker['metadata_argv'], metadata),
                    'target-cfg': (['/usr/bin/rustc', '--print', 'cfg', '--target', native], cfg),
                    'rustc-version': (['/usr/bin/rustc', '-vV'], version),
                    'inventory': (['/usr/bin/pacman', '-Q'], inventory)}
        for stem, (argv, stdout) in commands.items():
            (root / (stem + '.command.json')).write_text(json.dumps({'argv': argv, 'exit_code': 0, 'failure': None}))
            (root / (stem + '.stdout')).write_bytes(stdout)
            (root / (stem + '.stderr')).write_bytes(b'')
        return worker, controller, facts, metadata, cfg

    def test_receipt_requires_successful_actual_command_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            values = self.receipt_fixture(root)
            with patch.object(gate, 'INVENTORY', gate.sha(b'fixture 1.0\n')), patch.dict(os.environ, CACHY_ASAHI_CONTROLLER_SHA256='d' * 64):
                gate.receipt_gate(*values, root, lambda p, limit: p.read_bytes())
                command = root / 'cargo-metadata.command.json'
                data = json.loads(command.read_text());data['exit_code'] = 1;command.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, 'command evidence failed'):
                    gate.receipt_gate(*values, root, lambda p, limit: p.read_bytes())

    def test_receipt_cleanup_error_refuses_compilation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            values = self.receipt_fixture(root)
            path = root / 'cargo-metadata.command.json'
            record = json.loads(path.read_text())
            record['cleanup_errors'] = ['fixture process group not reaped']
            path.write_text(json.dumps(record))
            with patch.object(gate, 'INVENTORY', gate.sha(b'fixture 1.0\n')), patch.dict(os.environ, CACHY_ASAHI_CONTROLLER_SHA256='d' * 64), self.assertRaisesRegex(ValueError, 'command evidence failed'):
                gate.receipt_gate(*values, root, lambda p, limit: p.read_bytes())

    def test_receipt_stale_worker_cfg_or_tool_binding_refused(self):
        for changed in ('nonce', 'cfg', 'tools', 'controller'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                worker, controller, facts, metadata, cfg = self.receipt_fixture(root)
                if changed == 'nonce':controller['nonce'] = 'e' * 32
                elif changed == 'cfg':cfg = b'wrong'
                elif changed == 'tools':worker['tool_sha256']['cargo'] = 'e' * 64
                else:worker['controller_sha256'] = 'e' * 64
                with patch.object(gate, 'INVENTORY', gate.sha(b'fixture 1.0\n')), patch.dict(os.environ, CACHY_ASAHI_CONTROLLER_SHA256='d' * 64), self.assertRaises(ValueError):
                    gate.receipt_gate(worker, controller, facts, metadata, cfg, root, lambda p, limit: p.read_bytes())

    def test_valid_16k_header_is_only_static_alignment(self):
        gate.elf_gate(elf())

    def test_4k_alignment_and_incongruent_mapping_refused(self):
        for data in (elf(4096), elf(16384, 0, 4096)):
            with self.assertRaisesRegex(ValueError, '16K'):
                gate.elf_gate(data)

    def test_wrong_arch_truncated_and_missing_load_refused(self):
        wrong = elf()
        struct.pack_into('<H', wrong, 18, 62)
        missing = elf()
        struct.pack_into('<I', missing, 64, 0)
        for data in (wrong, elf()[:80], missing):
            with self.assertRaises(ValueError):
                gate.elf_gate(data)


if __name__ == '__main__':
    unittest.main()
