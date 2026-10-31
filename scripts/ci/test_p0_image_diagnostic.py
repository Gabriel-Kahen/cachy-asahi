"""Closed preparation refusal records survive the existing workflow codec."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'scripts/ci/root-administration/p0_launch.py'
WORKFLOW = ROOT / '.github/workflows/native-arm-p0.yml'
spec = importlib.util.spec_from_file_location('p0_image_diagnostic_test', LAUNCHER)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def workflow_codec():
    lines = WORKFLOW.read_text().splitlines()
    selected = [i for i, line in enumerate(lines) if line ==
                '      - name: Root observe, freeze and materialize, then prepare signed inputs and enter P0']
    if len(selected) != 1:
        raise ValueError('exact Root P0 workflow step required')
    stop = next((i for i in range(selected[0] + 1, len(lines)) if lines[i].startswith('      - ')), len(lines))
    starts = [i for i in range(selected[0] + 1, stop) if lines[i].strip() == 'run: |']
    if len(starts) != 1:
        raise ValueError('exact Root P0 workflow body required')
    start = starts[0] + 1
    script = []
    for line in lines[start:]:
        if line.strip() and not line.startswith(' ' * 10):
            break
        script.append(line[10:] if line.strip() else '')
    tree = ast.parse('\n'.join(script))
    names = {'DIAGNOSTIC_STAGES', 'DIAGNOSTIC_CODES', 'DIAGNOSTIC_TYPES',
             'DOWNLOAD_OPERATIONS', 'DOWNLOAD_CODE_TYPES', 'DOWNLOAD_CODES',
             'DOWNLOAD_GUARD_CODES', 'WORKFLOW_CODES'}
    nodes = [node for node in tree.body if
             isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id in names
                                                 for target in node.targets for n in ast.walk(target)) or
             isinstance(node, ast.FunctionDef) and node.name in {'consult_launcher_codes', 'validate_diagnostic'}]
    namespace = {'types': types}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(WORKFLOW), 'exec'), namespace)
    namespace['consult_launcher_codes'](launcher)
    wanted = next(ast.literal_eval(node.value) for node in ast.walk(tree)
                  if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'wanted'
                                                         for t in node.targets))
    return namespace['validate_diagnostic'], wanted


class ImageDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow_validate, cls.wanted = workflow_codec()

    def test_codec_uses_unique_named_root_step_with_other_python_steps(self):
        raw = WORKFLOW.read_text()
        prefix = '      - name: Other Python preparation\n        run: |\n          unrelated = True\n'
        with patch.object(Path, 'read_text', return_value=prefix + raw):
            validate, wanted = workflow_codec()
            self.assertEqual(wanted, type(self).wanted)
            self.assertEqual(validate({'stage':'pipeline', 'operation':'prepare-image',
                'exception_type':'ValueError', 'refusal_code':'UNKNOWN', 'domain':'pipeline'}),
                type(self).workflow_validate({'stage':'pipeline', 'operation':'prepare-image',
                'exception_type':'ValueError', 'refusal_code':'UNKNOWN', 'domain':'pipeline'}))
        name = '      - name: Root observe, freeze and materialize, then prepare signed inputs and enter P0'
        for changed in (raw.replace(name, '      - name: Unselected'), raw + '\n' + name + '\n'):
            with self.subTest(kind='missing' if 'Unselected' in changed else 'duplicate'):
                with patch.object(Path, 'read_text', return_value=changed), self.assertRaises(ValueError):
                    workflow_codec()

    def project(self, error, operation='prepare-image'):
        original_args = error.args
        error.nativeci_pipeline_operation = operation
        launcher.attach_diagnostic(error, 'pipeline', 'run-pipeline', 'pipeline')
        self.assertEqual(error.args, original_args)
        record = error.nativeci_diagnostic
        self.assertEqual(type(self).workflow_validate(record), record)
        return record

    def test_audit_and_image_failures_survive_workflow_without_raw_details(self):
        cases = {
            'signature does not match the pinned primary fingerprint': 'prep-signature-audit',
            'rootfs inventory differs from frozen signed-rootfs metadata': 'prep-input-metadata',
            'signed package metadata differs from frozen database: PRIVATE_ARCHIVE PRIVATE_FIELD': 'prep-input-metadata',
            'audited input changed during Docker context copy': 'prep-image-contract',
            'bootstrap image architecture differs from native ARM contract': 'prep-image-contract',
            'offline transaction changed the frozen package set; review packages.lock': 'prep-packages',
            'IMAGE_CONFIG PRIVATE_FIELD:PRIVATE_TYPE': 'prep-image-contract',
        }
        for message, code in cases.items():
            with self.subTest(code=code):
                record = self.project(ValueError(message))
                self.assertEqual(record['operation'], 'prepare-image')
                self.assertEqual(record['refusal_code'], code)
                self.assertNotIn('PRIVATE', json.dumps(record))

    def test_unknown_errors_and_other_boundaries_remain_unclassified(self):
        message = 'offline transaction changed the frozen package set; review packages.lock'
        for error, operation in ((ValueError('PRIVATE_RAW_ERROR'), 'prepare-image'),
                                 (TypeError(message), 'prepare-image'),
                                 (ValueError(message), 'run-P0')):
            with self.subTest(kind=type(error).__name__, operation=operation):
                self.assertEqual(self.project(error, operation)['refusal_code'], 'UNKNOWN')

    def test_classification_preserves_primary_cancellation_and_cleanup_flags(self):
        error = ValueError('bootstrap produced no immutable image ID')
        error.native_preflight_cancelled = True
        error.native_preflight_cleanup_uncertain = True
        self.assertEqual(self.project(error)['refusal_code'], 'prep-image-id')
        self.assertTrue(error.native_preflight_cancelled)
        self.assertTrue(error.native_preflight_cleanup_uncertain)
        self.assertEqual(self.project(KeyboardInterrupt())['exception_type'], 'KeyboardInterrupt')

    def test_existing_child_failure_code_remains_unchanged(self):
        record = self.project(ValueError('prep-command-exit'), 'check-child-outcome')
        self.assertEqual(record['operation'], 'check-child-outcome')
        self.assertEqual(record['refusal_code'], 'prep-command-exit')

    def test_workflow_loads_the_exact_changed_launcher(self):
        raw = LAUNCHER.read_bytes()
        self.assertEqual(type(self).wanted, {'bytes': len(raw), 'mode': 0o644,
                                             'sha256': hashlib.sha256(raw).hexdigest()})


if __name__ == '__main__':
    unittest.main()
