# SPDX-License-Identifier: MIT
"""MODEL controls: inert archives/records are never genuine Qt/native evidence."""
import ast
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qt612_family_qualify_MODEL', HERE/'qualify.py')
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)
C = Q._local('common')
sys.addaudithook(C.M.fence)
LOCK = C.load_lock()


class Controls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-family-qualify-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def records(self, component='gui_server'):
        row = dict(LOCK['components'][component], component=component)
        inputs = {name: value['sha256'] for name, value in row['recipe_inputs'].items()}
        inputs['PKGBUILD'] = 'a'*64  # Explicit MODEL projected identity, not frozen recipe bytes.
        inputs['family-contract.json'] = row['contracts']['BUILD-CONTRACT.json']['sha256']
        expected = dict(image='sha256:'+'b'*64, inventory_pin=dict(bytes=1, sha256='c'*64),
            entry_pin=dict(bytes=1, sha256='d'*64), nonce='e'*32, source_date_epoch=1,
            inventory_path=str(self.root/'external-inventory.lock'))
        records = [dict(status='built-package-static-pass', exit_code=0, mode='native', network='none',
            builder_host_arch='aarch64', image=expected['image'], image_id=expected['image'],
            expected_packages_sha256=expected['inventory_pin']['sha256'], entry_script_sha256=expected['entry_pin']['sha256'],
            source_date_epoch=1, recipe_inputs=inputs, recipe_metadata=row['metadata'],
            clean_environment_id='cachy-qt612-family-'+expected['nonce']+'-'+component+'-'+str(i),
            artifacts={row['filename']: 'f'*64}, source_material=dict(MODEL_inert=True)) for i in (1, 2)]
        comparison = dict(status='contents-reproduced', errors=[], packages={row['filename']: dict.fromkeys(
            ('installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'), True)},
            hardware_status='NOT RUN', independence_limit='Distinct recorded container runs; independent machine execution is not attested.')
        return records, comparison, row, expected, inputs

    def validate(self, values):
        records, comparison, row, expected, inputs = values
        return Q.validate_records(*records, comparison, row=row, expected=expected, recipe_inputs=inputs)

    def model_archive(self, extra=None, link='inert.txt'):
        metadata = dict(pkgbase=['cachy-asahi-MODEL-inert'], pkgname=['cachy-asahi-MODEL-inert'], pkgver=['6.12.0'], pkgrel=['1'], arch=['aarch64'],
                        depends=['glibc'], provides=['MODEL-only=6.12.0'], license=['MIT'])
        row = dict(package='cachy-asahi-MODEL-inert', metadata=metadata)
        recipe_inputs = {'PKGBUILD': 'a'*64}
        info = b'pkgbase = cachy-asahi-MODEL-inert\npkgname = cachy-asahi-MODEL-inert\npkgver = 6.12.0-1\narch = aarch64\ndepend = glibc\nprovides = MODEL-only=6.12.0\nlicense = MIT\n'
        build = b'format = 2\npkgname = cachy-asahi-MODEL-inert\npkgver = 6.12.0-1\npkgarch = aarch64\npkgbuild_sha256sum = '+b'a'*64+b'\n'
        bodies = {'.PKGINFO': info, '.BUILDINFO': build, '.MTREE': b'MODEL inert metadata, never installed\n',
                  'usr/lib/inert.txt': b'MODEL inert payload, never executable\n'}
        if extra:
            bodies.update(extra)
        path = self.root/'MODEL-inert.pkg.tar.xz'
        with tarfile.open(path, mode='w:xz') as archive:
            for name in ('usr', 'usr/lib'):
                member = tarfile.TarInfo(name)
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(member)
            for name, body in bodies.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(body), 0o644
                archive.addfile(member, io.BytesIO(body))
            member = tarfile.TarInfo('usr/lib/inert-link')
            member.type, member.mode, member.linkname = tarfile.SYMTYPE, 0o777, link
            archive.addfile(member)
        path.chmod(0o644)
        return path, row, recipe_inputs

    def test_all_five_strict_record_MODELS(self):
        for component in Q.COMPONENTS:
            values = self.records(component)
            with self.subTest(component=component):
                self.assertEqual(self.validate(values), values[2]['filename'])

    def test_wrong_native_context_and_bool_exit_refuse(self):
        changes = [('mode', 'emulated'), ('network', 'bridge'), ('builder_host_arch', 'x86_64'),
                   ('exit_code', False), ('image_id', 'sha256:'+'0'*64), ('entry_script_sha256', '0'*64),
                   ('expected_packages_sha256', '0'*64), ('source_date_epoch', True)]
        for key, value in changes:
            values = self.records()
            values[0][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_NATIVE_BUILD_RECORD'):
                self.validate(values)

    def test_reused_clean_environment_or_source_material_refuses(self):
        values = self.records()
        values[0][1]['clean_environment_id'] = values[0][0]['clean_environment_id']
        with self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_NATIVE_BUILD_RECORD'):
            self.validate(values)
        values = self.records()
        values[0][1]['source_material'] = dict(MODEL_other=True)
        with self.assertRaisesRegex(ValueError, 'SAME_SOURCE_MATERIAL'):
            self.validate(values)

    def test_frozen_old_PKG_hash_cannot_replace_actual_projection(self):
        values = self.records()
        values[0][0]['recipe_inputs'] = dict(values[4], PKGBUILD=values[2]['recipe_inputs']['PKGBUILD']['sha256'])
        with self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_NATIVE_BUILD_RECORD'):
            self.validate(values)

    def test_missing_or_nonboolean_comparison_flag_refuses(self):
        for value in (None, 1, False):
            values = self.records()
            values[1]['packages'][values[2]['filename']]['bytes_equal'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'FOUR_WAY_STRICT'):
                self.validate(values)
        values = self.records()
        del values[1]['packages'][values[2]['filename']]['buildinfo_equal']
        with self.assertRaisesRegex(ValueError, 'FOUR_WAY_STRICT'):
            self.validate(values)

    def test_old_component_or_foreign_extra_package_refuses(self):
        values = self.records('declarative')
        values[0][0]['clean_environment_id'] = values[0][0]['clean_environment_id'].replace('declarative', 'gui_server')
        with self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_NATIVE_BUILD_RECORD'):
            self.validate(values)
        values = self.records()
        values[1]['packages']['foreign.pkg.tar.xz'] = dict(bytes_equal=True)
        with self.assertRaisesRegex(ValueError, 'NORMAL_FAMILY_STRICT_COMPARISON'):
            self.validate(values)

    def test_only_inert_generic_archive_inspection_and_secure_copy_MODEL(self):
        path, row, inputs = self.model_archive()
        observed = {}
        actual = C.F.inspect_archive(path, io=C.M, observed=observed)
        Q.validate_package(actual, row, inputs)
        stage = Q.extract_payload(path, actual, self.root/'MODEL-private-stage', c=C, observed=observed)
        before = Q.verify_extraction(stage, actual, c=C, observed=observed)
        self.assertEqual((stage/'usr/lib/inert.txt').read_bytes(), b'MODEL inert payload, never executable\n')
        self.assertEqual((stage/'usr/lib/inert-link').readlink(), Path('inert.txt'))
        self.assertFalse((stage/'.PKGINFO').exists())
        self.assertFalse(actual['elf'])
        self.assertFalse(actual['version_header'])
        Q.require_snapshot(stage, before, c=C)
        C.M.unchanged(observed)
        # This does not call a genuine Qt checker or claim qualify_pair success.

    def test_changed_archive_between_inspection_and_extraction_refuses(self):
        path, _, _ = self.model_archive()
        observed = {}
        actual = C.F.inspect_archive(path, io=C.M, observed=observed)
        path.write_bytes(b'MODEL changed current archive')
        with self.assertRaisesRegex(ValueError, 'SAME_QUALIFIED_ARCHIVE'):
            Q.extract_payload(path, actual, self.root/'MODEL-stage', c=C, observed=observed)

    def test_changed_copied_payload_and_added_member_refuse(self):
        path, _, _ = self.model_archive()
        observed = {}
        actual = C.F.inspect_archive(path, io=C.M, observed=observed)
        stage = Q.extract_payload(path, actual, self.root/'MODEL-stage', c=C, observed=observed)
        before = Q.verify_extraction(stage, actual, c=C, observed=observed)
        (stage/'usr/lib/inert.txt').write_bytes(b'MODEL changed')
        with self.assertRaises(ValueError):
            Q.verify_extraction(stage, actual, c=C, observed=observed)
        with self.assertRaisesRegex(ValueError, 'PRIVATE_STAGE_OR_PROOF_CHANGED'):
            Q.require_snapshot(stage, before, c=C)
        (stage/'usr/extra').write_bytes(b'MODEL extra')
        with self.assertRaisesRegex(ValueError, 'EXACT_EXTRACTED_PAYLOAD_NAMESPACE'):
            Q.verify_extraction(stage, actual, c=C, observed=observed)

    def test_external_alias_and_undeclared_install_script_refuse(self):
        path, _, _ = self.model_archive(link='../../../../outside')
        with self.assertRaisesRegex(ValueError, 'NONESCAPING_ARCHIVE_LINK'):
            C.F.inspect_archive(path, io=C.M, observed={})
        path, row, inputs = self.model_archive(extra={'.INSTALL': b'MODEL never execute'})
        actual = C.F.inspect_archive(path, io=C.M, observed={})
        with self.assertRaisesRegex(ValueError, 'NO_INSTALL_SCRIPT_HOOK_OR_FOREIGN_ROOT'):
            Q.validate_package(actual, row, inputs)

    def test_wrong_metadata_and_old_BUILDINFO_hash_refuse(self):
        path, row, inputs = self.model_archive()
        actual = C.F.inspect_archive(path, io=C.M, observed={})
        changed = copy.deepcopy(actual)
        changed['metadata']['.PKGINFO']['depend'].append('MODEL foreign')
        with self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_PACKAGE_FIELD_depend'):
            Q.validate_package(changed, row, inputs)
        changed = copy.deepcopy(actual)
        changed['metadata']['.BUILDINFO']['pkgbuild_sha256sum'] = ['0'*64]
        with self.assertRaisesRegex(ValueError, 'ACTUAL_PROJECTED_FAMILY_BUILDINFO'):
            Q.validate_package(changed, row, inputs)

    def test_pinned_local_modules_do_not_use_global_source_or_elf(self):
        old = sys.modules.get('source')
        sys.modules['source'] = types.SimpleNamespace(PACKAGE='FOREIGN', TOKEN='FOREIGN')
        self.addCleanup(lambda: sys.modules.pop('source', None) if old is None else sys.modules.__setitem__('source', old))
        raw = {'source.py': b"PACKAGE='MODEL'\nTOKEN='HELD'\n",
               'elf.py': b'from source import TOKEN\n',
               'check_stage.py': b'from source import TOKEN\nfrom elf import TOKEN as ELF_TOKEN\n'}
        loader, _ = Q._checker_modules(raw, self.root, component='svg', row=dict(package='MODEL'))
        value = loader('check_stage')
        self.assertEqual((value.TOKEN, value.ELF_TOKEN), ('HELD', 'HELD'))
        self.assertEqual(sys.modules['source'].PACKAGE, 'FOREIGN')

    def test_passive_import_cannot_start_actor(self):
        raw = {'source.py': b"PACKAGE='MODEL'\n", 'check_stage.py': b"import sys\nsys.audit('subprocess.Popen')\n"}
        loader, _ = Q._checker_modules(raw, self.root, component='svg', row=dict(package='MODEL'))
        with self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
            loader('check_stage')
        self.assertEqual(Q._PASSIVE, 0)

    def test_MODEL_final_result_binds_original_records_and_exact_stage_inputs(self):
        expected = self.records()[3]
        raw = [b'{"MODEL_attempt":1}\n', b'{"MODEL_attempt":2}\n']
        observed = {}
        for number, body in enumerate(raw, 1):
            leaf = self.root/('MODEL-provenance-'+str(number)+'.json')
            leaf.write_bytes(body)
            C.M.stream(leaf, C.pin(body), observed)
        result = Q.finalize_result(dict(status='MODEL_ONLY'), expected=expected,
            provenance_raw=raw, observed=observed, c=C)
        self.assertEqual(result['nonce'], expected['nonce'])
        self.assertEqual(result['entry_pin'], expected['entry_pin'])
        self.assertEqual(result['source_date_epoch'], expected['source_date_epoch'])
        self.assertEqual(result['provenance_pins'], {'build-1': C.pin(raw[0]), 'build-2': C.pin(raw[1])})
        self.assertEqual(result['status'], 'MODEL_ONLY')
        self.assertIsNot(result['entry_pin'], expected['entry_pin'])

    def test_MODEL_mutation_before_final_result_and_incomplete_provenance_refuse(self):
        expected = self.records()[3]
        leaf = self.root/'MODEL-provenance.json'
        raw = b'{"MODEL_attempt":1}\n'
        leaf.write_bytes(raw)
        observed = {}
        C.M.stream(leaf, C.pin(raw), observed)
        leaf.write_bytes(b'{"MODEL_changed_after_read":true}\n')
        with self.assertRaisesRegex(ValueError, 'OPERAND_CHANGED_AFTER_READ'):
            Q.finalize_result(dict(status='MODEL_ONLY'), expected=expected,
                provenance_raw=[raw, raw], observed=observed, c=C)
        with self.assertRaisesRegex(ValueError, 'TWO_WHOLE_ORIGINAL_PROVENANCE_RECORDS'):
            Q.finalize_result(dict(status='MODEL_ONLY'), expected=expected,
                provenance_raw=[raw], observed={}, c=C)

    def test_held_normal_package_report_matches_generic_inspector_MODEL(self):
        path, row, inputs = self.model_archive()
        row['filename'] = path.name
        # The Source95 runtime retains the framework bytes pinned by this family.
        held_framework = (HERE.parents[2]/'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
                          /'scripts/ci/llhttp-reference-native-source/base/runtime')
        name = 'scripts/checks/package_checks.py'
        held = held_framework/name
        raw = C.M.stream(held, LOCK['framework_files'][name], {}, collect=True)
        scope = dict(__name__='held_normal_package_checks_MODEL', __file__=str(held))
        exec(compile(raw, str(held), 'exec'), scope)
        report = scope['package'](path)
        self.assertEqual(report['status'], 'artifact-static-pass')
        self.assertEqual(report['errors'], [])
        actual = C.F.inspect_archive(path, io=C.M, observed={})
        Q.validate_validation(actual, report, row=row, recipe_inputs=inputs, c=C)
        for key, value in (('status', 'fail'), ('errors', ['MODEL error'])):
            bad = dict(report, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'ACTUAL_NORMAL_PACKAGE_VALIDATION_SCHEMA'):
                Q.validate_validation(actual, bad, row=row, recipe_inputs=inputs, c=C)
        # Execute the pinned compare function with an explicit MODEL
        # verify seam; this checks its schema, never a genuine native pair.
        compare_name = 'scripts/build/compare_v2.py'
        held_compare = held_framework/compare_name
        compare_raw = C.M.stream(held_compare, LOCK['framework_files'][compare_name], {}, collect=True)
        tree = ast.parse(compare_raw, str(held_compare))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'compare')
        model = dict(clean_environment_id='MODEL-1', image='sha256:'+'a'*64, image_id='sha256:'+'a'*64,
            mode='native', source_date_epoch=1, recipe_inputs=inputs, recipe_metadata=row['metadata'],
            expected_packages_sha256='b'*64, entry_script_sha256='c'*64, source_material=dict(MODEL=True))
        def verify(root):
            return dict(model, clean_environment_id=Path(root).name), {path.name: report}
        environment = dict(Path=Path, verify=verify, PACKAGE_METADATA=scope['PACKAGE_METADATA'])
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(held_compare), 'exec'), environment)
        compared = environment['compare'](self.root/'MODEL-1', self.root/'MODEL-2')
        self.assertEqual(set(compared), {'status', 'errors', 'packages', 'hardware_status', 'independence_limit'})
        self.assertEqual(compared['status'], 'contents-reproduced')
        self.assertEqual(compared['hardware_status'], 'NOT RUN')
        self.assertEqual(set(compared['packages'][path.name]), {'installed_contents_equal', 'pkginfo_equal', 'buildinfo_equal', 'bytes_equal'})
        self.assertTrue(all(value is True for value in compared['packages'][path.name].values()))

    def test_full_normal_metadata_buildinfo_format_and_size_limits(self):
        path, row, inputs = self.model_archive()
        actual = C.F.inspect_archive(path, io=C.M, observed={})
        for package_key in ('makedepend', 'checkdepend', 'optdepend', 'backup', 'pkgbase'):
            bad = copy.deepcopy(actual)
            bad['metadata']['.PKGINFO'][package_key] = ['MODEL undeclared']
            with self.subTest(key=package_key), self.assertRaisesRegex(ValueError, 'EXACT_FAMILY_PACKAGE_FIELD_'+package_key):
                Q.validate_package(bad, row, inputs)
        bad = copy.deepcopy(actual)
        bad['metadata']['.BUILDINFO']['format'] = ['1']
        with self.assertRaisesRegex(ValueError, 'ACTUAL_PROJECTED_FAMILY_BUILDINFO'):
            Q.validate_package(bad, row, inputs)
        bad = copy.deepcopy(actual)
        bad['members']['usr/lib/inert.txt']['size'] = Q.NORMAL_PACKAGE_TOTAL+1
        with self.assertRaisesRegex(ValueError, 'NORMAL_PACKAGE_EXPANDED_BYTE_CAP'):
            Q.validate_package(bad, row, inputs)

    def test_real_serial_autogen_cache_requires_exactly_one_typed_value(self):
        Q.require_serial_cache(b'# MODEL cache\nCMAKE_AUTOGEN_PARALLEL:STRING=1\n')
        for raw in (b'', b'CMAKE_AUTOGEN_PARALLEL:STRING=2\n',
                    b'CMAKE_AUTOGEN_PARALLEL:BOOL=1\n',
                    b'CMAKE_AUTOGEN_PARALLEL:STRING=1\nCMAKE_AUTOGEN_PARALLEL:STRING=1\n',
                    b'CMAKE_AUTOGEN_PARALLEL:STRING=1\n"CMAKE_AUTOGEN_PARALLEL":STRING=2\n',
                    b' CMAKE_AUTOGEN_PARALLEL:STRING=1\n'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'EXACT_ONE_SERIAL_AUTOGEN'):
                Q.require_serial_cache(raw)

    def request(self):
        expected = self.records()[3]
        return dict(schema=1, kind=Q.REQUEST_KIND, first=str(self.root/'MODEL-build-1'),
            second=str(self.root/'MODEL-build-2'), comparison=str(self.root/'MODEL-comparison.json'),
            source=str(self.root/'MODEL-Source'), source_map_sha256='f'*64, component='gui_server',
            expected=expected, work=str(self.root/'MODEL-work'))

    def test_pinned_request_and_standalone_main_use_exact_arguments_MODEL(self):
        request = self.request()
        path = self.root/'MODEL-request.json'
        raw = C.encoded(request)
        path.write_bytes(raw)
        result = dict(status='MODEL_ONLY_NOT_A_GENUINE_QUALIFICATION')
        with patch.object(Q, 'qualify_pair', return_value=result) as called:
            self.assertEqual(Q.run_request(path, C.pin(raw)['sha256']), result)
            called.assert_called_once_with(**{k: v for k, v in request.items() if k not in ('schema', 'kind')})
        output = io.StringIO()
        with patch.object(Q, 'qualify_pair', return_value=result), patch.object(sys, 'stdout', output):
            Q.main(['--request', str(path), '--request-sha256', C.pin(raw)['sha256']])
        self.assertEqual(output.getvalue().encode(), C.encoded(result))

    def test_request_wrong_pin_unknown_fields_and_relative_paths_refuse(self):
        request = self.request()
        path = self.root/'MODEL-request.json'
        raw = C.encoded(request)
        path.write_bytes(raw)
        with patch.object(Q, 'qualify_pair') as called:
            with self.assertRaises(ValueError):
                Q.run_request(path, '0'*64)
            called.assert_not_called()
        for key, value in (('extra', True), ('kind', 'FOREIGN'), ('first', 'relative'), ('schema', True)):
            bad = dict(request, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                Q.validate_request(bad)
        path.write_bytes(b'{"schema":1,"schema":1}')
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            Q.run_request(path, C.pin(path.read_bytes())['sha256'])

    def test_request_mutation_during_worker_refuses_result(self):
        path = self.root/'MODEL-request.json'
        raw = C.encoded(self.request())
        path.write_bytes(raw)
        def model_worker(**kwargs):
            path.write_bytes(b'MODEL replaced request')
            return dict(status='MODEL_ONLY')
        with patch.object(Q, 'qualify_pair', side_effect=model_worker):
            with self.assertRaisesRegex(ValueError, 'OPERAND_CHANGED_AFTER_READ'):
                Q.run_request(path, C.pin(raw)['sha256'])

    def test_no_unlisted_local_source_execution(self):
        raw = {'source.py': b"PACKAGE='MODEL'\n"}
        loader, _ = Q._checker_modules(raw, self.root, component='svg', row=dict(package='MODEL'))
        with self.assertRaisesRegex(ValueError, 'PINNED_LOCAL_STAGE_IMPORT'):
            loader('unverified_helper')


if __name__ == '__main__':
    unittest.main()
