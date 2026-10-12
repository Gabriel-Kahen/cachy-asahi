#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""No compiler/Docker calls: original-module isolation and late cancellation."""
from contextlib import contextmanager
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import worker
from evidence import load, save
from runtime import Cancelled


class WorkerTests(unittest.TestCase):
    def test_original_builder_patch_is_module_local_and_checker_keeps_real_subprocess(self):
        original_run = subprocess.run
        builder = worker.module('build', HERE.parents[1] / 'build/build.py')
        checker = sys.modules['package_checks']
        original_builder_subprocess = builder.subprocess
        try:
            broker = mock.Mock()
            broker.capture.return_value = 'aarch64'
            broker.build.return_value = subprocess.CompletedProcess(['fixture'], 0, b'owned output\n')
            builder.subprocess = worker.BuilderCommands(broker)
            self.assertEqual(builder.capture(['docker', 'info', '--format', '{{.Architecture}}']), 'aarch64')
            log = io.BytesIO()
            result = builder.subprocess.run(['fixture'], stdout=log, stderr=subprocess.STDOUT, timeout=7)
            self.assertEqual((result.returncode, log.getvalue()), (0, b'owned output\n'))
            broker.build.assert_called_once_with(['fixture'], 7)
            self.assertIs(checker.subprocess, subprocess)
            self.assertIs(checker.subprocess.run, original_run)
        finally:
            builder.subprocess = original_builder_subprocess

    def test_late_cancellation_invalidates_owned_worker_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'build-1-receipt.json'
            @contextmanager
            def late():
                yield
                raise Cancelled(15)
            def executed(config, state):
                receipt = {'status': 'PASS', 'action': 'build-1'}
                state.update(receipt=receipt, path=path)
                save(path, receipt)
                return 0
            with mock.patch.object(sys, 'argv', ['worker.py', '--config', '/unused', '--config-sha256', '0' * 64]), \
                 mock.patch.object(worker, 'load', return_value={}), \
                 mock.patch.object(worker, 'execute', side_effect=executed), \
                 mock.patch.object(worker, 'cancellation_handlers', late), \
                 mock.patch.object(sys, 'stderr', io.StringIO()):
                self.assertEqual(worker.main(), 1)
            self.assertEqual(load(path)['status'], 'FAIL')
            self.assertIs(load(path)['cancelled'], True)

    def test_builder_remove_request_cannot_remove_an_unregistered_name_directly(self):
        broker = mock.Mock()
        broker.cleanup.return_value = {'status': 'FAIL', 'absence_verified': False}
        proxy = worker.BuilderCommands(broker)
        result = proxy.run(['docker', 'rm', '-f', 'fixture-name'])
        self.assertEqual(result.returncode, 1)
        broker.cleanup.assert_called_once_with()
        broker.build.assert_not_called()


if __name__ == '__main__':
    unittest.main()
