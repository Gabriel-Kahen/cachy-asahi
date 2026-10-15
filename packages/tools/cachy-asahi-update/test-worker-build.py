#!/usr/bin/env python3
"""Synthetic Cargo output validation only; never execute Cargo or compiled code."""
import copy
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('worker_build', Path(__file__).with_name('worker-build.py'))
worker_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker_build)


def fixture():
    packages = [{'id': name, 'name': name, 'targets': [{'kind': ['bin'] if name == 'arch-update-tray' else ['custom-build']}]} for name in ('arch-update-tray', 'gettext-sys', 'system-deps')]
    metadata = {'packages': packages, 'resolve': {'nodes': [
        {'id': p['id'], 'features': ['gettext-system'] if p['name'] == 'gettext-sys' else ['default']} for p in packages]}}
    events = [{'reason': 'compiler-artifact', 'package_id': p['id'], 'features': list(node['features']),
               'target': p['targets'][0], 'executable': '/tmp/target/tray' if p['name'] == 'arch-update-tray' else None} for p, node in zip(packages, metadata['resolve']['nodes'])]
    events += [{'reason': 'build-script-executed', 'package_id': 'gettext-sys', 'cfgs': [], 'env': [], 'linked_libs': [], 'linked_paths': []}, {'reason': 'build-finished', 'success': True}]
    return metadata, events


def parse(metadata, events):
    return worker_build.unit_evidence(json.dumps(metadata).encode(),
                                      b'\n'.join(json.dumps(e).encode() for e in events), Path('/tmp/target/tray'))


class UnitTests(unittest.TestCase):
    def test_diagnostic_io_failure_preserves_unit_refusal_and_control_signals(self):
        for error in (OSError('synthetic diagnostic failure'), KeyboardInterrupt()):
            diagnostic = types.SimpleNamespace(fail=mock.Mock(side_effect=error))
            metadata, events = fixture(); events[0]['package_id'] = 'unreviewed'
            expected = ValueError if isinstance(error, Exception) else KeyboardInterrupt
            with self.subTest(error=type(error).__name__), self.assertRaises(expected):
                worker_build.unit_evidence(json.dumps(metadata).encode(),
                    b'\n'.join(json.dumps(event).encode() for event in events), Path('/tmp/target/tray'), diagnostic)
            self.assertEqual(diagnostic.fail.call_args.args[0], 'unit-source')

    def test_actual_records_remain_distinct_from_metadata_union(self):
        metadata, events = fixture()
        metadata['resolve']['nodes'][0]['features'].append('uncompiled-union-feature')
        result = parse(metadata, events)
        self.assertEqual(len(result['compiler_artifacts']), 3)
        self.assertNotIn('uncompiled-union-feature', result['compiler_artifacts'][0]['features'])

    def test_extra_source_or_actual_feature_refused(self):
        for key, value in [('package_id', 'unreviewed-source'), ('features', ['unreviewed-feature'])]:
            metadata, events = fixture();events[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): parse(metadata, events)

    def test_gettext_system_and_system_deps_binary_conditions_enforced(self):
        metadata, events = fixture();events[1]['features'] = []
        with self.assertRaisesRegex(ValueError, 'gettext'): parse(metadata, events)
        metadata, events = fixture();metadata['resolve']['nodes'][2]['features'].append('binary');events[2]['features'].append('binary')
        with self.assertRaisesRegex(ValueError, 'system-deps'): parse(metadata, events)

    def test_build_script_run_requires_compiled_script_feature_record(self):
        metadata, events = fixture();events.pop(1)
        with self.assertRaisesRegex(ValueError, 'retained compiled unit'): parse(metadata, events)

    def test_failed_incomplete_or_wrong_binary_cannot_pass(self):
        for failure in ('failed', 'missing-end', 'wrong-binary'):
            metadata, events = fixture()
            if failure == 'failed': events[-1]['success'] = False
            if failure == 'missing-end': events.pop()
            if failure == 'wrong-binary': events[0]['executable'] = '/tmp/another-tray'
            with self.subTest(failure=failure), self.assertRaises(ValueError): parse(metadata, events)


class DiagnosticBuildTests(unittest.TestCase):
    """Real Recorder/files, synthetic worker/ELF results; no native commands."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'out'; self.output.mkdir(mode=0o700)
        self.work = self.root / 'work'; self.work.mkdir()
        self.entry = self.root / 'entry.py'; self.entry.write_bytes(b'synthetic entry')
        self.helper = worker_build.module('test_compile_diagnostic', Path(__file__).with_name('worker-diagnostic.py'))
        self.recorder = None
        self.commands = []
        self.fault = None

    def setup_worker(self):
        def recorder(**kwargs):
            self.recorder = self.helper.Recorder(**kwargs)
            return self.recorder
        helper = types.SimpleNamespace(Recorder=recorder, binding_values=lambda: self.helper.binding_values(self.entry))
        def observe():
            if self.fault == 'pre-metadata': raise ValueError('synthetic observation refusal')
            return {}
        def metadata(*args):
            with self.recorder.step('metadata-source'):
                if self.fault == 'source':
                    error = ValueError('synthetic source mismatch')
                    self.recorder.fail('source-pins', error); raise error
                if self.fault == 'nested-unknown': raise RuntimeError('synthetic unknown metadata failure')
            args[4].mkdir(mode=0o700)
            data, _ = fixture()
            return json.dumps(data).encode(), {'image_id':'sha256:'+'2'*64,
                'observed_worker':{'nonce':'3'*32}, 'sha256':{key:'4'*64 for key in ('manifest','lock','audit','metadata','cfg')}}, {}, {}
        def run(argv, cwd, env, output, stem, timeout=None):
            self.commands.append((argv, stem, timeout))
            self.recorder.command_start(stem)
            if self.fault == 'cancel' and stem == 'cargo-build': raise KeyboardInterrupt()
            self.recorder.command_result(stem, True, True, 0)
            if stem == 'cargo-build':
                binary = self.work / 'target/aarch64-unknown-linux-gnu/release/arch-update-tray'
                binary.parent.mkdir(parents=True); binary.write_bytes(b'synthetic ELF fixture')
                if self.fault == 'hardlink':
                    (binary.parent / 'deps').mkdir()
                    worker_build.os.link(binary, binary.parent / 'deps/arch-update-tray-hash')
                data, events = fixture(); events[0]['executable'] = str(binary)
                if self.fault == 'unit-source': events[0]['package_id'] = 'unreviewed'
                if self.fault == 'incomplete': events[-1]['success'] = False
                (output / 'cargo-build.stdout').write_text('\n'.join(json.dumps(event) for event in events))
                (output / 'cargo-build.stderr').write_bytes(b'')
                if self.fault == 'unit-log-read': (output / 'cargo-build.stdout').unlink()
                if self.fault == 'unit-json': (output / 'cargo-build.stdout').write_bytes(b'not JSON raw/private/source')
            if stem == 'elf-inspection':
                (output / 'elf-inspection.stdout').write_bytes(b'synthetic readelf fixture')
                if self.fault in ('snapshot-replaced', 'source-replaced'):
                    path = output / 'arch-update-tray' if self.fault == 'snapshot-replaced' else self.work / 'target/aarch64-unknown-linux-gnu/release/arch-update-tray'
                    replacement = self.work / 'replacement'; replacement.write_bytes(path.read_bytes())
                    worker_build.os.replace(replacement, path)
                if self.fault == 'upstream-preexisting':
                    path = self.work / 'target/release/arch-update-tray'; path.parent.mkdir(); path.write_bytes(b'untouched upstream')
        def regular(path, limit, singly_linked=True, *, elf_observation=False):
            if self.fault == 'binary-drift' and len(self.commands) == 3: return b'changed fixture'
            return path.read_bytes()
        if self.fault == 'hardlink':
            regular = worker_build.module('real_cargo_output_reader', Path(__file__).with_name('worker-metadata.py')).regular
        worker = types.SimpleNamespace(TARGET='aarch64-unknown-linux-gnu', set_diagnostic=lambda value: None,
            observe=observe, verify_controller=lambda *args:{'builder_inventory_sha256':'5'*64},
            metadata=metadata, run=run, regular=regular, digest=lambda data:hashlib.sha256(data).hexdigest())
        def elf(data):
            if self.fault == 'elf': raise ValueError('synthetic ELF refusal')
        gate = types.SimpleNamespace(elf=elf)
        def module(name, path):
            if path.name == 'worker-diagnostic.py': return helper
            if path.name == 'worker-metadata.py':
                if self.fault == 'import': raise ImportError('synthetic worker import refusal')
                return worker
            if path.name == 'build-gate.py': return gate
            raise AssertionError('unexpected module')
        def path(value):
            if str(value) == '/out': return self.output
            if str(value) == '/out/target-metadata': return self.output / 'target-metadata'
            return Path(value)
        args = types.SimpleNamespace(manifest=self.work / 'Cargo.toml', vendor=self.root / 'vendor', cargo_audit=self.root / 'audit.json')
        return args, module, path

    def execute(self, fault=None):
        self.fault = fault
        self.commands = []
        args, module, path = self.setup_worker()
        original_write = Path.write_text
        def write_text(target, *args, **kwargs):
            if target.name == 'compile-result.json':
                self.assertFalse(self.diagnostic()['compilation_accepted'])
            if fault == 'unit-receipt-write' and target.name == 'compilation-units.json': raise OSError('synthetic private receipt write refusal')
            if fault == 'receipt-write' and target.name == 'compile-result.json': raise OSError('synthetic receipt write refusal')
            return original_write(target, *args, **kwargs)
        with mock.patch.object(worker_build, 'module', side_effect=module), \
             mock.patch.object(worker_build, 'Path', side_effect=path), \
             mock.patch.object(Path, 'write_text', write_text), \
             mock.patch.dict(worker_build.os.environ, {'CACHY_ASAHI_CONTROLLER_SHA256':'1'*64,'CACHY_ASAHI_IMAGE_ID':'sha256:'+'2'*64}):
            worker_build.build(args)

    def diagnostic(self):
        return json.loads((self.output / 'worker-diagnostic.json').read_bytes())

    def test_pre_metadata_failure_is_unknown_and_bound(self):
        with self.assertRaisesRegex(ValueError, 'observation'): self.execute('pre-metadata')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-controller')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['controller_validated'])
        self.assertFalse(value['compiler_launch_attempted'])

    def test_worker_import_failure_has_startup_record_before_metadata(self):
        with self.assertRaises(ImportError): self.execute('import')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-worker-import')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['controller_validated'])
        self.assertFalse(value['compiler_launch_attempted'])

    def test_elf_refusal_stays_unknown_and_blocks_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'ELF'): self.execute('elf')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-elf')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['compilation_accepted'])

    def test_nested_first_unknown_or_specific_refusal_survives_outer_step(self):
        for fault, predicate in [('nested-unknown','UNKNOWN'), ('source','source-pins')]:
            with self.subTest(fault=fault):
                with self.assertRaises((ValueError, RuntimeError)): self.execute(fault)
                value = self.diagnostic()
                self.assertEqual(value['first_failure']['operation'], 'metadata-source')
                self.assertEqual(value['first_failure']['predicate'], predicate)
                self.assertFalse(value['compilation_accepted'])
                (self.output / 'worker-diagnostic.json').unlink()

    def test_cancellation_is_not_compiler_acceptance(self):
        with self.assertRaises(KeyboardInterrupt): self.execute('cancel')
        value = self.diagnostic()
        self.assertTrue(value['cancelled'])
        self.assertEqual(value['first_failure']['error_kind'], 'Cancelled')
        self.assertTrue(value['compiler_launch_attempted'])
        self.assertFalse(value['compiler_return_observed'])
        self.assertFalse(value['compilation_accepted'])

    def test_original_unit_and_copy_gates_refuse_diagnostic_acceptance(self):
        for fault, predicate in [('unit-source','unit-source'), ('incomplete','unit-complete'), ('binary-drift','compile-binary-drift')]:
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError): self.execute(fault)
                value = self.diagnostic()
                self.assertEqual(value['first_failure']['predicate'], predicate)
                self.assertFalse(value['compilation_accepted'])
                shutil.rmtree(self.work / 'target'); shutil.rmtree(self.output / 'target-metadata')
                (self.output / 'worker-diagnostic.json').unlink()

    def test_receipt_write_failure_cannot_set_compiler_accepted(self):
        with self.assertRaises(OSError): self.execute('receipt-write')
        value = self.diagnostic()
        self.assertEqual(value['first_failure']['operation'], 'compile-receipt')
        self.assertEqual(value['first_failure']['predicate'], 'UNKNOWN')
        self.assertFalse(value['compilation_accepted'])

    def test_positive_fixture_preserves_commands_gates_and_receipt_before_acceptance(self):
        self.execute()
        value = self.diagnostic()
        receipt = json.loads((self.output / 'target-metadata/compile-result.json').read_bytes())
        self.assertTrue(value['compilation_accepted'])
        self.assertIsNone(value['first_failure'])
        self.assertEqual(receipt['native_compilation'], 'PASS')
        self.assertEqual(receipt['elf_16k_segments'], 'PASS-static; loader NOT RUN')
        self.assertEqual([(row[1], row[2]) for row in self.commands], [('compile-gate',180),('cargo-build',1200),('elf-inspection',None)])
        self.assertEqual(self.commands[1][0], ['/usr/bin/cargo','build','--release','--frozen','--offline','--locked',
            '--target','aarch64-unknown-linux-gnu','--jobs','2','--message-format=json-render-diagnostics',
            '--manifest-path',str(self.work / 'Cargo.toml')])
        self.assertEqual(self.commands[2][0][:4], ['/usr/bin/readelf','-h','-l','-d'])


    def test_hardlinked_cargo_output_detached_and_receipt_joins_exact_bytes(self):
        self.execute('hardlink')
        original = self.work / 'target/aarch64-unknown-linux-gnu/release/arch-update-tray'
        detached = self.output / 'target-metadata/arch-update-tray'
        upstream = self.work / 'target/release/arch-update-tray'
        self.assertEqual(original.stat().st_nlink, 2)
        self.assertEqual(detached.stat().st_nlink, 1)
        self.assertEqual(upstream.stat().st_nlink, 1)
        self.assertEqual(detached.read_bytes(), original.read_bytes())
        self.assertEqual(upstream.read_bytes(), original.read_bytes())
        self.assertNotEqual(detached.stat().st_ino, original.stat().st_ino)
        receipt = json.loads((self.output / 'target-metadata/compile-result.json').read_bytes())
        self.assertEqual(receipt['binary_sha256'], hashlib.sha256(detached.read_bytes()).hexdigest())
        self.assertEqual(self.commands[2][0][-1], str(detached))
        units = json.loads((self.output / 'target-metadata/compilation-units.json').read_bytes())
        self.assertEqual(units['compiler_artifacts'][0]['executable'], str(original))
        self.assertTrue(self.diagnostic()['compilation_accepted'])


    def assert_custody_failure(self, fault):
        with self.assertRaises(ValueError): self.execute(fault)
        self.assertFalse(self.diagnostic()['compilation_accepted'])
        self.assertEqual(json.loads((self.output / 'target-metadata/compile-result.json').read_bytes())['native_compilation'], 'FAIL')

    def test_same_bytes_snapshot_replacement_after_readelf_refuses_acceptance(self):
        self.assert_custody_failure('snapshot-replaced')

    def test_same_bytes_source_replacement_after_readelf_refuses_acceptance(self):
        self.assert_custody_failure('source-replaced')

    def test_preexisting_upstream_destination_refuses_acceptance_and_preserves_bytes(self):
        self.assert_custody_failure('upstream-preexisting')
        self.assertEqual((self.work / 'target/release/arch-update-tray').read_bytes(), b'untouched upstream')


    def test_missing_compiler_log_reports_closed_read_boundary_without_acceptance(self):
        with self.assertRaises(FileNotFoundError): self.execute('unit-log-read')
        self.assertEqual(self.diagnostic()['first_failure']['predicate'], 'unit-log-read')
        self.assertFalse(self.diagnostic()['compilation_accepted'])

    def test_malformed_compiler_json_reports_closed_parse_boundary_without_acceptance(self):
        with self.assertRaises(json.JSONDecodeError): self.execute('unit-json')
        self.assertEqual(self.diagnostic()['first_failure']['predicate'], 'unit-compiler-json')
        self.assertFalse(self.diagnostic()['compilation_accepted'])

    def test_unit_receipt_write_failure_reports_closed_boundary_without_acceptance(self):
        with self.assertRaises(OSError): self.execute('unit-receipt-write')
        self.assertEqual(self.diagnostic()['first_failure']['predicate'], 'unit-receipt-write')
        self.assertFalse(self.diagnostic()['compilation_accepted'])


class ElfObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.binary = self.root / 'binary'
        self.output = self.root / 'out'; self.output.mkdir(mode=0o700)
        base = Path(__file__).parent
        self.gate = worker_build.module('leaf_gate', base / 'build-gate.py')
        self.worker = worker_build.module('leaf_worker', base / 'worker-metadata.py')
        self.helper = worker_build.module('leaf_recorder', base / 'worker-diagnostic.py')
        self.public = worker_build.module('leaf_public', base / 'public-evidence.py')
        tree = ast.parse((base / 'worker-build.py').read_bytes())
        block = next(n for n in ast.walk(tree) if isinstance(n, ast.Try) and n.body and
                     isinstance(n.body[0], ast.Assign) and any(isinstance(t, ast.Tuple) and any(isinstance(x, ast.Name) and x.id == 'binary_data' for x in t.elts) for t in n.body[0].targets))
        self.code = compile(ast.fix_missing_locations(ast.Module([block], type_ignores=[])), 'captured-compile-elf-reporting', 'exec')

    def data(self, tag=None):
        data = bytearray(120); data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 183); struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1); struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 120, 120, 16384)
        changes = {'elf-machine': ('<H',18,62), 'elf-program-headers': ('<H',54,1),
                   'elf-load-alignment': ('<Q',112,4096), 'elf-load-bounds': ('<Q',96,121), 'elf-load-absent': ('<I',64,0)}
        if tag == 'elf-header': data[0] = 0
        elif tag: struct.pack_into(*changes[tag][:1], data, *changes[tag][1:])
        return bytes(data)

    def invoke(self, diagnostic, gate=None):
        snapshot = self.output / 'arch-update-tray'
        if snapshot.exists(): snapshot.unlink()
        scope = dict(worker_build.__dict__, worker=self.worker, gate=gate or self.gate,
                     binary=self.binary, output=self.output, diagnostic=diagnostic)
        exec(self.code, scope)
        return scope['binary_data']

    def test_all_six_source_leaf_tags_reach_bounded_real_recorder_and_projector(self):
        for tag in ('elf-header','elf-machine','elf-program-headers','elf-load-alignment','elf-load-bounds','elf-load-absent'):
            output = self.root / tag; output.mkdir(mode=0o700); rec = self.helper.Recorder(output)
            self.binary.write_bytes(self.data(tag))
            with self.subTest(tag=tag), self.assertRaises(ValueError) as caught:
                with rec.step('compile-elf'): self.invoke(rec)
            row = rec.snapshot(); self.assertEqual(caught.exception.updater_elf_predicate, tag)
            self.assertEqual(row['first_failure']['predicate'], tag); self.assertFalse(row['compilation_accepted'])
            self.assertEqual(self.public.diagnostic(row), row)
            self.assertLessEqual(len(self.helper.encoded(row)), 4096)
        self.binary.write_bytes(self.data()); diagnostic = types.SimpleNamespace(fail=mock.Mock(side_effect=OSError()))
        self.assertEqual(self.invoke(diagnostic), self.data()); diagnostic.fail.assert_not_called()

    def test_reporting_failure_preserves_original_refusal_and_control(self):
        self.binary.write_bytes(self.data('elf-header'))
        for report_error in (OSError('private report unavailable'), KeyboardInterrupt('private cancellation')):
            diagnostic = types.SimpleNamespace(fail=mock.Mock(side_effect=report_error))
            expected = ValueError if isinstance(report_error, Exception) else KeyboardInterrupt
            with self.subTest(control=expected.__name__), self.assertRaises(expected) as caught: self.invoke(diagnostic)
            original = diagnostic.fail.call_args.args[1]
            self.assertEqual(original.updater_elf_predicate, 'elf-header')
            self.assertIs(caught.exception, original if expected is ValueError else report_error)

    def test_first_failure_and_write_failed_remain_sticky(self):
        rec = self.helper.Recorder(self.output); rec.operation = 'metadata-source'; rec.fail('source-pins', ValueError('prior refusal'))
        first = rec.snapshot()['first_failure']; self.binary.write_bytes(self.data('elf-header'))
        with mock.patch.object(self.helper.os, 'replace', side_effect=OSError('private write unavailable')):
            with self.assertRaises(ValueError):
                with rec.step('compile-elf'): self.invoke(rec)
        row = rec.snapshot(); self.assertEqual(row['first_failure'], first)
        self.assertTrue(row['diagnostic_write_failed']); self.assertFalse(row['compilation_accepted'])
        self.helper.validate(row)

    def test_nonleaf_or_opaque_predicate_stays_unknown(self):
        self.binary.write_bytes(self.data())
        for tag in ('raw/private/path', 'source-pins', True, None):
            error = ValueError('untyped gate error'); error.updater_elf_predicate = tag
            diagnostic = types.SimpleNamespace(fail=mock.Mock())
            gate = types.SimpleNamespace(elf=mock.Mock(side_effect=error))
            with self.subTest(tag=tag), self.assertRaises(ValueError) as caught: self.invoke(diagnostic, gate)
            self.assertIs(caught.exception, error); self.assertEqual(diagnostic.fail.call_args.args[0], 'UNKNOWN')

    def test_descriptor_fault_old_red_new_original_identity_without_getter(self):
        calls = []
        class Poison(ValueError):
            @property
            def updater_elf_predicate(self):
                calls.append(True); raise RuntimeError('controlled descriptor refusal')
        error = Poison('original source refusal')
        with self.assertRaises(RuntimeError): getattr(error, 'updater_elf_predicate', 'UNKNOWN')
        self.assertEqual(calls, [True]); calls.clear(); self.binary.write_bytes(self.data())
        diagnostic = types.SimpleNamespace(fail=mock.Mock()); gate = types.SimpleNamespace(elf=mock.Mock(side_effect=error))
        with self.assertRaises(Poison) as caught: self.invoke(diagnostic, gate)
        self.assertIs(caught.exception, error); self.assertEqual(calls, [])
        self.assertEqual(diagnostic.fail.call_args.args, ('UNKNOWN', error))

    def test_exact_instance_plain_tag_positive_and_class_or_extra_state_unknown(self):
        self.binary.write_bytes(self.data())
        class ClassTag(ValueError): updater_elf_predicate = 'elf-header'
        plain = ValueError('issued shape'); plain.updater_elf_predicate = 'elf-header'
        extra = ValueError('unissued extra state'); extra.updater_elf_predicate = 'elf-header'; extra.other = None
        subclass = ClassTag('class tag'); subclass.updater_elf_predicate = 'elf-machine'
        for error, expected in ((plain,'elf-header'),(ClassTag('class only'),'UNKNOWN'),(subclass,'UNKNOWN'),(extra,'UNKNOWN'),(ValueError('no tag'),'UNKNOWN')):
            diagnostic = types.SimpleNamespace(fail=mock.Mock()); gate = types.SimpleNamespace(elf=mock.Mock(side_effect=error))
            with self.subTest(expected=expected), self.assertRaises(type(error)) as caught: self.invoke(diagnostic, gate)
            self.assertIs(caught.exception, error); self.assertEqual(diagnostic.fail.call_args.args, (expected,error))

    def test_hostile_tag_value_key_or_dictionary_never_executes(self):
        calls = []; self.binary.write_bytes(self.data())
        class Hostile:
            def __hash__(self): calls.append('hash'); raise RuntimeError('hostile tag hash')
            def __eq__(self, other): calls.append('eq'); raise RuntimeError('hostile tag equality')
            def __str__(self): calls.append('str'); raise RuntimeError('hostile tag conversion')
        class HostileKey:
            def __hash__(self): return hash('updater_elf_predicate')
            def __eq__(self, other): calls.append('key'); raise RuntimeError('hostile key equality')
        class HostileDict(dict):
            def items(self): calls.append('items'); raise RuntimeError('hostile dictionary lookup')
        value = ValueError('opaque tag'); value.updater_elf_predicate = Hostile()
        key = ValueError('opaque key'); key.__dict__ = {HostileKey():'elf-header'}
        dictionary = ValueError('opaque dictionary'); dictionary.__dict__ = HostileDict(updater_elf_predicate='elf-header')
        for error in (value,key,dictionary):
            diagnostic = types.SimpleNamespace(fail=mock.Mock()); gate = types.SimpleNamespace(elf=mock.Mock(side_effect=error))
            with self.assertRaises(ValueError) as caught: self.invoke(diagnostic, gate)
            self.assertIs(caught.exception,error); self.assertEqual(diagnostic.fail.call_args.args,('UNKNOWN',error))
        self.assertEqual(calls,[])



class CargoOutputCustodyTests(unittest.TestCase):
    """Real isolated files/inodes; no Cargo, commands or native actors."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'cargo-binary'; self.binary.write_bytes(b'bounded compiler bytes')
        self.alias = self.root / 'cargo-deps'; worker_build.os.link(self.binary, self.alias)
        self.snapshot = self.root / 'snapshot'
        self.worker = worker_build.module('cargo_custody_reader', Path(__file__).with_name('worker-metadata.py'))

    def test_old_reader_refuses_real_hardlink_new_detaches_without_global_relaxation(self):
        with self.assertRaisesRegex(ValueError, 'singly-linked'): self.worker.regular(self.binary, 1024)
        data, identity, snapshot_identity = worker_build.cargo_snapshot(self.worker, self.binary, self.snapshot)
        self.assertEqual(data, b'bounded compiler bytes')
        self.assertEqual(identity, worker_build.output_identity(self.binary))
        self.assertEqual(snapshot_identity, worker_build.output_identity(self.snapshot))
        self.assertEqual(self.snapshot.stat().st_nlink, 1)
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o755)
        self.assertNotEqual(self.snapshot.stat().st_ino, self.binary.stat().st_ino)
        self.assertEqual(self.worker.regular(self.snapshot, 1024), data)
        with self.assertRaisesRegex(ValueError, 'singly-linked'): self.worker.regular(self.binary, 1024)

    def test_preexisting_snapshot_and_upstream_paths_never_overwritten(self):
        for name, kind in (('snapshot', 'file'), ('upstream', 'link'), ('directory', 'dir')):
            destination = self.root / name
            if kind == 'file': destination.write_bytes(b'untouched')
            elif kind == 'link': destination.symlink_to(self.binary)
            else: destination.mkdir()
            with self.subTest(kind=kind), self.assertRaises(OSError):
                worker_build.write_compiled_output(self.worker, destination, b'replacement')
            if kind == 'file': self.assertEqual(destination.read_bytes(), b'untouched')
            elif kind == 'link': self.assertTrue(destination.is_symlink())
            else: self.assertTrue(destination.is_dir())

    def test_source_symlink_parent_symlink_nonregular_and_oversize_refuse(self):
        link = self.root / 'link'; link.symlink_to(self.binary)
        directory = self.root / 'dir'; directory.mkdir()
        parent = self.root / 'parent-link'; parent.symlink_to(directory, target_is_directory=True)
        child = directory / 'child'; child.write_bytes(b'x')
        huge = self.root / 'huge'
        with huge.open('wb') as stream: stream.truncate(64 * 1024 * 1024 + 1)
        for source in (link, directory, parent/'child', huge):
            with self.subTest(source=source.name), self.assertRaises(ValueError): worker_build.cargo_output(self.worker, source)

    def test_source_path_replacement_during_descriptor_capture_refuses(self):
        read = worker_build.os.read
        replaced = False
        def replacement(fd, size):
            nonlocal replaced
            data = read(fd, size)
            if not replaced:
                replaced = True
                other = self.root / 'replacement'; other.write_bytes(data)
                worker_build.os.replace(other, self.binary)
            return data
        with mock.patch.object(worker_build.os, 'read', side_effect=replacement):
            with self.assertRaisesRegex(ValueError, 'changed'): worker_build.cargo_output(self.worker, self.binary)

    def test_mutated_alias_after_capture_refuses_and_detached_bytes_stay_original(self):
        write = worker_build.write_compiled_output
        def mutate(*args):
            identity = write(*args); self.alias.write_bytes(b'changed alias bytes'); return identity
        with mock.patch.object(worker_build, 'write_compiled_output', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'changed during snapshot'):
                worker_build.cargo_snapshot(self.worker, self.binary, self.snapshot)
        self.assertEqual(self.snapshot.read_bytes(), b'bounded compiler bytes')

    def test_source_symlink_replacement_after_capture_refuses(self):
        write = worker_build.write_compiled_output
        def replace(*args):
            identity = write(*args); self.binary.unlink(); self.binary.symlink_to(self.alias); return identity
        with mock.patch.object(worker_build, 'write_compiled_output', side_effect=replace):
            with self.assertRaisesRegex(ValueError, 'symlink'):
                worker_build.cargo_snapshot(self.worker, self.binary, self.snapshot)

    def test_single_link_source_and_empty_data_keep_reader_and_elf_authorities_separate(self):
        self.alias.unlink()
        data, _, _ = worker_build.cargo_snapshot(self.worker, self.binary, self.snapshot)
        self.assertEqual(self.worker.regular(self.snapshot, 1024), data)
        gate = worker_build.module('cargo_unchanged_elf_gate', Path(__file__).with_name('build-gate.py'))
        with self.assertRaises(ValueError): gate.elf(data)

    def test_destination_parent_symlink_alias_and_replacement_refuse(self):
        folder = self.root / 'folder'; folder.mkdir(); link = self.root / 'folder-link'; link.symlink_to(folder, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'canonical'): worker_build.write_compiled_output(self.worker, link/'binary', b'x')
        fsync = worker_build.os.fsync
        for action in ('alias', 'replace'):
            destination = self.root / action
            def tamper(fd):
                fsync(fd)
                if action == 'alias': worker_build.os.link(destination, self.root / 'external-alias')
                else:
                    other = self.root / 'new'; other.write_bytes(b'x'); worker_build.os.replace(other, destination)
            with mock.patch.object(worker_build.os, 'fsync', side_effect=tamper):
                with self.subTest(action=action), self.assertRaises(ValueError): worker_build.write_compiled_output(self.worker, destination, b'x')

    def test_descriptor_drift_and_control_exceptions_preserve_original_failure(self):
        original_read = self.worker.os.read
        calls = []
        def drift(fd, size):
            data = original_read(fd, size)
            if not calls: calls.append(True); self.alias.write_bytes(b'replaced')
            return data
        with mock.patch.object(self.worker.os, 'read', side_effect=drift):
            with self.assertRaises(ValueError): worker_build.cargo_output(self.worker, self.binary)
        for error in (OSError('bounded write failure'), KeyboardInterrupt(), SystemExit(9)):
            with mock.patch.object(worker_build.os, 'fsync', side_effect=error):
                path = self.root / ('control-' + type(error).__name__)
                with self.subTest(error=type(error).__name__), self.assertRaises(type(error)) as caught:
                    worker_build.write_compiled_output(self.worker, path, b'validated bytes')
                self.assertIs(caught.exception, error)



class DescriptorCustodyCorrectionTests(unittest.TestCase):
    setUp = CargoOutputCustodyTests.setUp
    def test_ancestor_ABA_foreign_descriptor_refuses_before_snapshot_creation(self):
        original = self.root / 'cargo'; original.mkdir()
        source = original / 'binary'; source.write_bytes(b'original')
        foreign = self.root / 'foreign'; foreign.mkdir(); (foreign/'binary').write_bytes(b'foreign!')
        held = self.root / 'held'; open_fd = worker_build.os.open
        def swap(path, flags, *args, **kwargs):
            if Path(path) != source: return open_fd(path, flags, *args, **kwargs)
            original.rename(held); foreign.rename(original)
            try: return open_fd(path, flags, *args, **kwargs)
            finally: original.rename(foreign); held.rename(original)
        with mock.patch.object(worker_build.os, 'open', side_effect=swap):
            with self.assertRaisesRegex(ValueError, 'descriptor differs'):
                worker_build.cargo_snapshot(self.worker, source, self.snapshot)
        self.assertFalse(self.snapshot.exists())
        self.assertEqual(source.read_bytes(), b'original')

    def test_destination_parent_swap_at_create_never_writes_foreign_directory(self):
        parent = self.root / 'output'; parent.mkdir()
        foreign = self.root / 'foreign'; foreign.mkdir(); held = self.root / 'held'
        destination = parent / 'binary'; open_fd = worker_build.os.open
        def swap(path, flags, *args, **kwargs):
            if str(path) == 'binary' and 'dir_fd' in kwargs:
                parent.rename(held); parent.symlink_to(foreign, target_is_directory=True)
            return open_fd(path, flags, *args, **kwargs)
        with mock.patch.object(worker_build.os, 'open', side_effect=swap):
            with self.assertRaises((OSError, ValueError)): worker_build.write_compiled_output(self.worker, destination, b'bounded')
        self.assertFalse((foreign/'binary').exists())
        self.assertEqual((held/'binary').read_bytes(), b'bounded')

    def test_foreign_parent_descriptor_refuses_before_creating_any_file(self):
        parent = self.root / 'output'; parent.mkdir()
        foreign = self.root / 'foreign'; foreign.mkdir(); held = self.root / 'held'
        open_fd = worker_build.os.open
        def swap(path, flags, *args, **kwargs):
            if Path(path) != parent: return open_fd(path, flags, *args, **kwargs)
            parent.rename(held); foreign.rename(parent)
            try: return open_fd(path, flags, *args, **kwargs)
            finally: parent.rename(foreign); held.rename(parent)
        with mock.patch.object(worker_build.os, 'open', side_effect=swap):
            with self.assertRaisesRegex(ValueError, 'parent changed'):
                worker_build.write_compiled_output(self.worker, parent/'binary', b'bounded')
        self.assertFalse((foreign/'binary').exists()); self.assertFalse((parent/'binary').exists())

    def test_write_chmod_fsync_first_error_survives_both_descriptor_close_errors(self):
        class Falsey(OSError):
            def __bool__(self): return False
        actual_close = worker_build.os.close
        for operation in ('write', 'fchmod', 'fsync'):
            for primary in (OSError('primary'), Falsey('falsey primary'), KeyboardInterrupt(), SystemExit(7)):
                closed = []
                def close(fd):
                    actual_close(fd); closed.append(fd); raise OSError('secondary close')
                path = self.root / (operation + '-' + type(primary).__name__)
                with mock.patch.object(worker_build.os, operation, side_effect=primary), mock.patch.object(worker_build.os, 'close', side_effect=close):
                    with self.subTest(operation=operation, primary=type(primary).__name__), self.assertRaises(type(primary)) as caught:
                        worker_build.write_compiled_output(self.worker, path, b'bytes')
                    self.assertIs(caught.exception, primary)
                self.assertEqual(len(closed), 2); self.assertEqual(len(set(closed)), 2)
                for fd in closed:
                    with self.assertRaises(OSError): worker_build.os.fstat(fd)

    def test_source_read_primary_survives_close_error_and_fd_is_retired(self):
        primary = KeyboardInterrupt(); actual_close = worker_build.os.close; closed = []
        def close(fd): actual_close(fd); closed.append(fd); raise OSError('secondary close')
        with mock.patch.object(worker_build.os, 'read', side_effect=primary), mock.patch.object(worker_build.os, 'close', side_effect=close):
            with self.assertRaises(KeyboardInterrupt) as caught: worker_build.cargo_output(self.worker, self.binary)
        self.assertIs(caught.exception, primary); self.assertEqual(len(closed), 1)
        with self.assertRaises(OSError): worker_build.os.fstat(closed[0])

    def test_successful_write_close_failure_is_not_success_and_parent_retires(self):
        actual_close = worker_build.os.close; error = OSError('close failed'); closed = []
        def close(fd):
            actual_close(fd); closed.append(fd)
            if len(closed) == 1: raise error
        with mock.patch.object(worker_build.os, 'close', side_effect=close):
            with self.assertRaises(OSError) as caught:
                worker_build.write_compiled_output(self.worker, self.snapshot, b'bytes')
        self.assertIs(caught.exception, error); self.assertEqual(len(closed), 2)

    def test_failed_create_retires_parent_and_never_uses_fdopen(self):
        self.snapshot.write_bytes(b'keep'); actual_close = worker_build.os.close; closed = []
        def close(fd): actual_close(fd); closed.append(fd)
        with mock.patch.object(worker_build.os, 'fdopen', side_effect=AssertionError('stream transfer forbidden')) as stream, mock.patch.object(worker_build.os, 'close', side_effect=close):
            with self.assertRaises(FileExistsError): worker_build.write_compiled_output(self.worker, self.snapshot, b'bytes')
        stream.assert_not_called(); self.assertEqual(len(closed), 1)
        self.snapshot.unlink()
        with mock.patch.object(worker_build.os, 'fdopen', side_effect=AssertionError('stream transfer forbidden')) as stream:
            worker_build.write_compiled_output(self.worker, self.snapshot, b'bytes')
        stream.assert_not_called(); self.assertEqual(self.snapshot.read_bytes(), b'bytes')

    def test_partial_writes_complete_and_zero_write_refuses(self):
        write = worker_build.os.write
        def partial(fd, data): return write(fd, data[:2])
        with mock.patch.object(worker_build.os, 'write', side_effect=partial):
            worker_build.write_compiled_output(self.worker, self.snapshot, b'bounded bytes')
        self.assertEqual(self.snapshot.read_bytes(), b'bounded bytes')
        with mock.patch.object(worker_build.os, 'write', return_value=0):
            with self.assertRaisesRegex(ValueError, 'complete'):
                worker_build.write_compiled_output(self.worker, self.root/'zero', b'bytes')



class UnitDiagnosticTests(unittest.TestCase):
    def inputs(self):
        metadata, events = fixture()
        return json.dumps(metadata).encode(), b'\n'.join(json.dumps(event).encode() for event in events)

    def test_success_and_original_executable_path_binding_preserved(self):
        metadata, compiler = self.inputs(); diagnostic = types.SimpleNamespace(fail=mock.Mock())
        result = worker_build.unit_evidence(metadata, compiler, Path('/tmp/target/tray'), diagnostic)
        self.assertEqual(len(result['compiler_artifacts']), 3); diagnostic.fail.assert_not_called()
        with self.assertRaises(ValueError): worker_build.unit_evidence(metadata, compiler, Path('/tmp/detached'), diagnostic)
        self.assertEqual(diagnostic.fail.call_args.args[0], 'unit-complete')

    def test_json_and_field_errors_keep_original_exception_and_exact_closed_phase(self):
        metadata, compiler = self.inputs()
        cases = ((b'{', compiler, 'unit-metadata-json', json.JSONDecodeError),
                 (b'{}', compiler, 'unit-metadata-fields', KeyError),
                 (metadata, b'{', 'unit-compiler-json', json.JSONDecodeError),
                 (metadata, b'[]', 'unit-event-fields', AttributeError),
                 (metadata, b'{"reason":"compiler-artifact"}', 'unit-event-fields', KeyError))
        for left, right, predicate, error_kind in cases:
            diagnostic = types.SimpleNamespace(fail=mock.Mock())
            with self.subTest(predicate=predicate), self.assertRaises(error_kind) as caught:
                worker_build.unit_evidence(left, right, Path('/tmp/target/tray'), diagnostic)
            diagnostic.fail.assert_called_once_with(predicate, caught.exception)

    def test_known_unit_refusal_is_not_reported_twice_or_reclassified(self):
        metadata, events = fixture(); events[0]['package_id'] = 'foreign'
        diagnostic = types.SimpleNamespace(fail=mock.Mock())
        with self.assertRaises(ValueError) as caught:
            worker_build.unit_evidence(json.dumps(metadata).encode(), b'\n'.join(json.dumps(e).encode() for e in events), Path('/tmp/target/tray'), diagnostic)
        diagnostic.fail.assert_called_once_with('unit-source', caught.exception)

    def test_diagnostic_io_failure_preserves_parse_exception_and_control_stays_outward(self):
        _, compiler = self.inputs()
        for secondary in (OSError('private diagnostic unavailable'), KeyboardInterrupt()):
            diagnostic = types.SimpleNamespace(fail=mock.Mock(side_effect=secondary))
            expected = json.JSONDecodeError if isinstance(secondary, Exception) else KeyboardInterrupt
            with self.subTest(error=type(secondary).__name__), self.assertRaises(expected) as caught:
                worker_build.unit_evidence(b'{', compiler, Path('/tmp/target/tray'), diagnostic)
            original = diagnostic.fail.call_args.args[1]
            self.assertIs(caught.exception, original if expected is json.JSONDecodeError else secondary)

    def test_no_diagnostic_keeps_original_parse_error(self):
        with self.assertRaises(json.JSONDecodeError): worker_build.unit_evidence(b'{', b'', Path('/tmp/target/tray'))

    def test_six_new_codes_survive_real_closed_projectors_without_private_content(self):
        import re
        base = Path(__file__).parent
        helper = worker_build.module('unit_phase_recorder', base/'worker-diagnostic.py')
        public = worker_build.module('unit_phase_public', base/'public-evidence.py')
        stage = base.parents[2]/'scripts/port/updater-native-stage/stage.py'
        tree = ast.parse(stage.read_bytes())
        names = {'need', 'native_diagnostic_need', 'native_diagnostic_encoded', 'native_diagnostic_nullable_hash', 'native_diagnostic_command', 'native_diagnostic'}
        nodes = [n for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id.startswith('NATIVE_DIAGNOSTIC_') or isinstance(n, ast.FunctionDef) and n.name in names]
        env = dict(json=json,re=re); exec(compile(ast.Module(body=nodes,type_ignores=[]),'pure-stage-diagnostic-validator','exec'),env)
        predicates = ('unit-metadata-json','unit-metadata-fields','unit-compiler-json','unit-event-fields','unit-log-read','unit-receipt-write')
        for predicate in predicates:
            with tempfile.TemporaryDirectory() as folder:
                rec = helper.Recorder(Path(folder)); rec.operation = 'compile-units'
                rec.fail(predicate, ValueError('raw/private/source never exported'))
                row = rec.snapshot(); self.assertEqual(public.diagnostic(row), row); self.assertEqual(env['native_diagnostic'](row), row)
                raw = helper.encoded(row); self.assertLessEqual(len(raw),4096); self.assertNotIn(b'raw/private/source',raw)
                self.assertFalse(row['compilation_accepted']); rec.fail('UNKNOWN', OSError('later')); self.assertEqual(rec.snapshot()['first_failure'],row['first_failure'])
                bad = copy.deepcopy(row); bad['first_failure']['predicate'] = 'raw/private/source'
                with self.assertRaises(ValueError): public.diagnostic(bad)
                with self.assertRaises(ValueError): env['native_diagnostic'](bad)


if __name__ == '__main__':
    unittest.main()
