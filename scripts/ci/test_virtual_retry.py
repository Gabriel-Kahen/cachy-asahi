# SPDX-License-Identifier: MIT
"""Focused direct-VM wiring checks; all VM/Docker execution is inert."""
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import hashlib
import unittest
from unittest.mock import patch

import virtual_retry as v


class DirectRetry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.source = self.repo / 'scripts/virtual'; self.source.mkdir(parents=True)
        self.cache = self.root / 'cache'; self.cache.mkdir()
        self.output = self.root / 'virtual'
        self.c = SimpleNamespace(native_out=self.root/'native', work=self.root/'integration/work',
            archives=self.root/'integration/work/archive-inputs', commit='a'*40,
            installed='sha256:'+'b'*64, installed_owned={'tag': None, 'image_id': None, 'reply_valid': True},
            image='sha256:'+'c'*64, cancelled=False,
            report={'stages': {'lifecycle': {'status': 'PASS'}}}, rows={'baseline': []})
        paths = [self.c.native_out/'inputs.lock.json', self.c.native_out/'packages.lock',
            *(self.c.work/'lifecycle-raw'/name for name in ('installed-packages.lock', 'lifecycle/result.json',
                'installed-image.json', 'committed-config.json', 'committed-image/result.json', 'commit-receipt.json')),
            self.source/'tooling-audit.json', self.source/'controller.py']
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
        for n in range(4):
            archive = 'baseline/package-'+str(n)+'.pkg.tar.xz'
            path = self.c.archives/archive; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'archive')
            self.c.rows['baseline'].append({'archive': archive, 'sha256': v.native.sha(path)})
        (self.c.work/'lifecycle-raw/committed-image/result.json').write_text(json.dumps({'baseline': self.c.rows['baseline']}))
        def blob(name):
            path = self.cache/name; path.write_bytes(name.encode())
            return {'filename': name, 'size': path.stat().st_size, 'sha256': v.native.sha(path)}
        keys = [blob('key'+str(n)) for n in range(3)]
        packages = []
        for n in range(21):
            row = blob('package'+str(n)); signature = blob(row['filename']+'.sig')
            packages.append(row | {'signature_size': signature['size'], 'signature_sha256': signature['sha256']})
        (self.source/'tooling.lock.json').write_text(json.dumps({'keyring_files': keys, 'packages': packages}))
        self.common = SimpleNamespace(TRANSACTION_PURPOSE='installer-transaction-only',
            BARRIER_SOURCE='d4313163538f51d85bc03e6a4adfde0c850cbc30',
            TRANSACTION_PROFILE={'path':'fixed','size':1,'sha256':'e'*64},TRANSACTION_LAUNCHER={'files':{},'aliases':{}}, TRANSACTION_FILES={})
        for name, data in (('scripts/install/local_transaction.py', b'inert worker'),
                           ('scripts/install/test_local_transaction.py', b'inert test'),
                           ('scripts/port/kernel-native-job/runtime.py', b'inert runtime')):
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            self.common.TRANSACTION_FILES[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        common_patch = patch.dict(sys.modules, {'common': self.common})
        common_patch.start(); self.addCleanup(common_patch.stop)
        self.result = {'status': 'PASS_TRANSACTION_ONLY', 'private_workspace_cleanup': 'PASS', 'cleanup': [{'status': 'PASS'}]}
        self.owner_passed = True
        self.owner = SimpleNamespace(CORE={}, AUDITOR_PIN='d'*64, main=self.owner_main)
        self.patch_root = patch.object(v.native, 'ROOT', self.repo)
        self.patch_root.start(); self.addCleanup(self.patch_root.stop)
        self.patch_env = patch.dict(v.os.environ, {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'})
        self.patch_env.start(); self.addCleanup(self.patch_env.stop)

    def owner_main(self, argv):
        self.assertEqual(self.c.installed, 'sha256:'+'b'*64)
        path = Path(argv[argv.index('--contract')+1])
        self.contract = json.loads(path.read_text())
        self.assertEqual(argv[argv.index('--contract-sha256')+1], v.native.sha(path))
        target = Path(argv[argv.index('--output')+1]); target.mkdir()
        (target/'result.json').write_text(json.dumps(self.result))
        return self.owner_passed

    def consume(self):
        with patch.object(v, 'owner_module', return_value=nullcontext(self.owner)):
            return v.consume(self.c, self.cache, self.output)

    def test_copies_existing_inputs_and_calls_owner_before_image_cleanup(self):
        self.consume()
        self.assertEqual(len(list((self.output/'inputs/tooling-cache').iterdir())), 45)
        self.assertEqual(len(self.contract['files']), 10)
        self.assertEqual(self.contract['baseline'], self.c.rows['baseline'])
        self.assertEqual(self.contract['installed_image_id'], self.c.installed)
        self.assertEqual(self.c.report['virtual']['status'], 'PASS_TRANSACTION_ONLY')
        self.assertEqual(self.c.report['virtual']['visual_review'], 'NOT RUN')
        self.assertEqual(self.contract['purpose'], self.common.TRANSACTION_PURPOSE)
        self.assertEqual(self.contract['transaction_fixture'], {'source_commit': self.c.commit,
            'sources': self.common.TRANSACTION_FILES, 'tool_profile': self.common.TRANSACTION_PROFILE})
        for name, row in self.common.TRANSACTION_FILES.items():
            path = self.output / 'inputs' / name
            self.assertEqual(path.stat().st_size, row['bytes'])
            self.assertEqual(v.native.sha(path), row['sha256'])

    def test_missing_or_changed_tooling_is_refused_without_owner_execution(self):
        (self.cache/'package0').write_bytes(b'drift')
        with patch.object(v, 'owner_module') as owner, self.assertRaises(ValueError):
            v.consume(self.c, self.cache, self.output)
        owner.assert_not_called()

    def test_failed_lifecycle_refused_before_output(self):
        self.c.report['stages']['lifecycle']['status'] = 'FAIL'
        with self.assertRaises(ValueError): self.consume()
        self.assertFalse(self.output.exists())

    def test_missing_size_or_hash_changed_fixture_refuses_owner_execution(self):
        for change in ('missing', 'size', 'hash'):
            with self.subTest(change=change):
                path = self.repo / 'scripts/install/local_transaction.py'
                original = path.read_bytes()
                if change == 'missing': path.unlink()
                else: path.write_bytes(original + b'changed' if change == 'size' else b'X' * len(original))
                with patch.object(v, 'owner_module', return_value=nullcontext(self.owner)), patch.object(self.owner, 'main') as main:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        v.consume(self.c, self.cache, self.output)
                    main.assert_not_called()
                path.write_bytes(original)
                import shutil
                shutil.rmtree(self.output)

    def test_desktop_status_and_unclean_barrier_result_are_refused(self):
        variants = [{'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW'}, {'status': 'FAIL'},
                    {'private_workspace_cleanup': 'FAIL'}, {'cleanup': [{'status': 'FAIL'}]}]
        for variant in variants:
            with self.subTest(variant=variant):
                self.result = {'status': 'PASS_TRANSACTION_ONLY', 'private_workspace_cleanup': 'PASS', 'cleanup': [{'status': 'PASS'}]} | variant
                with self.assertRaisesRegex(ValueError, 'virtual trial failed'): self.consume()
                self.assertEqual(self.c.report['virtual']['status'], 'FAIL')
                self.assertEqual(self.c.report['virtual']['visual_review'], 'NOT RUN')
                import shutil
                shutil.rmtree(self.output)

    def test_false_owner_return_cannot_accept_barrier_result(self):
        self.owner_passed = False
        with self.assertRaisesRegex(ValueError, 'virtual trial failed'): self.consume()
        self.assertEqual(self.c.report['virtual']['status'], 'FAIL')

    def test_owner_failure_and_cancellation_keep_outer_owned_image_cleanup(self):
        for failure in (ValueError('trial failed'), KeyboardInterrupt()):
            with self.subTest(kind=type(failure).__name__):
                self.c.cancelled = False
                self.c.report = {'stages': {'lifecycle': {'status': 'PASS'}}}
                self.c.installed = 'sha256:'+'b'*64
                self.c.run_stages = lambda: None
                self.c.finish = lambda: not (self.c.cancelled or self.c.report.get('controller_execution') == 'FAIL')
                def consumer(current):
                    self.assertIs(current, self.c)
                    self.assertIsNotNone(current.installed)
                    raise failure
                with patch.object(v.integration, 'remove_derivative', return_value={'status': 'PASS'}) as cleanup:
                    result = v.integration.Controller.run(self.c, consumers=consumer)
                self.assertFalse(result)
                cleanup.assert_called_once()
                self.assertIsNone(self.c.installed)

    def test_owner_imports_restore_existing_modules_on_exception(self):
        marker = SimpleNamespace(sentinel=True)
        (self.source/'controller.py').write_text('import common\nraise ValueError("inert import failure")\n')
        (self.source/'common.py').write_text('SELECTED = True\n')
        before = list(sys.path)
        with patch.dict(sys.modules, {'common': marker}):
            with self.assertRaisesRegex(ValueError, 'inert import failure'):
                with v.owner_module(self.source): pass
            self.assertIs(sys.modules['common'], marker)
        self.assertEqual(sys.path, before)

    def test_owner_cancellation_marks_outer_controller_and_keeps_image_cleanup(self):
        def cancelled(argv):
            self.owner.CANCELLED = True
            raise ValueError('controller interrupted/deadline')
        self.owner.main = cancelled
        self.c.run_stages = lambda: None
        self.c.finish = lambda: not self.c.cancelled
        with patch.object(v.integration, 'remove_derivative', return_value={'status': 'PASS'}) as cleanup:
            result = v.integration.Controller.run(self.c, consumers=lambda _: self.consume())
        self.assertFalse(result)
        self.assertTrue(self.c.cancelled)
        self.assertIsNone(self.c.installed)
        cleanup.assert_called_once()

    def test_resume_cli_adds_consumer_only_when_explicitly_selected(self):
        import integration_resume as resume
        (self.c.native_out/'inputs.lock.json').write_text('{"source_date_epoch": 1}')
        (self.c.native_out/'packages.lock').write_text('base 1-1\n')
        image = 'sha256:'+'c'*64
        with patch.object(resume.platform, 'system', return_value='Linux'), \
             patch.object(resume.platform, 'machine', return_value='aarch64'), \
             patch.object(resume.os, 'getuid', return_value=1000), \
             patch.object(resume, 'prepared_build', return_value=image), \
             patch.object(resume.integration, 'preflight', return_value={}), \
             patch.object(resume.native, 'probe'), \
             patch.object(resume.native, 'run', side_effect=[json.dumps([dict(
                 Id=image, Architecture='arm64', Os='linux')]), 'base 1-1']), \
             patch.object(resume.integration, 'Controller') as controller, \
             patch.object(v, 'consume') as consume:
            controller.return_value.run.side_effect = lambda consumers: (consumers(self.c), True)[1]
            self.assertEqual(resume.main(['--native-output', str(self.c.native_out),
                '--integration-lock', 'unused', '--integration-sha256', 'a'*64,
                '--recipes-sha256', 'b'*64, '--source-commit', 'c'*40,
                '--output', str(self.root/'new-integration'), '--virtual-tooling-cache', str(self.cache),
                '--virtual-output', str(self.output)]), 0)
        consume.assert_called_once_with(self.c, self.cache, self.output)


if __name__ == '__main__':
    unittest.main()
