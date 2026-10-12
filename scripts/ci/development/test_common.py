#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_nonregular_links_duplicates_and_bounds_refused(self):
        path = self.root / 'data.json'; path.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError): common.read_json(path)
        with self.assertRaises(ValueError): common.read_regular(path, 1)
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): common.read_regular(link)
        os.link(path, self.root / 'hardlink')
        with self.assertRaises(ValueError): common.read_regular(path)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): common.read_regular(fifo)

    def test_pinned_copy_requires_exact_bytes_and_fresh_destination(self):
        path = self.root / 'source'; path.write_bytes(b'correct')
        target = self.root / 'copy'
        pin = common.digest(path)
        self.assertEqual(common.copy_pinned(path, target, pin)['sha256'], pin)
        with self.assertRaises(FileExistsError): common.copy_pinned(path, target, pin)
        with self.assertRaises(ValueError): common.copy_pinned(path, self.root / 'other', '0' * 64)

    def test_opened_descriptor_rechecks_link_count_before_read_or_hash(self):
        from unittest.mock import patch
        for operation in (common.read_regular, common.digest):
            source = self.root / operation.__name__; source.write_bytes(b'fixture')
            original = os.open
            def changed(path, flags):
                descriptor = original(path, flags)
                os.link(source, self.root / (operation.__name__ + '-link'))
                return descriptor
            with patch.object(common.os, 'open', side_effect=changed):
                with self.assertRaises(ValueError): operation(source)

    def test_interrupted_atomic_status_write_can_retry_without_deleting_unowned_partial(self):
        from unittest.mock import patch
        target = self.root / 'result.json'
        common.save(target, {'status':'PASS'})
        unowned = self.root / 'result.json.partial'; unowned.write_text('unowned')
        def interrupted(value, stream, **kwargs):
            stream.write('{'); raise KeyboardInterrupt()
        with patch.object(common.json, 'dump', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt): common.save(target, {'status':'FAIL'})
        common.save(target, {'status':'FAIL'})
        self.assertEqual(common.read_json(target)['status'], 'FAIL')
        self.assertEqual(unowned.read_text(), 'unowned')
        self.assertEqual(list(self.root.glob('*.partial')), [unowned])

    def test_deadline_allows_owner_term_handler_to_finalize(self):
        helper = self.root / 'worker.py'
        receipt = self.root / 'cleanup.json'
        helper.write_text('import signal,time,sys\nfrom pathlib import Path\n'
                          'def stop(*_):\n Path(sys.argv[1]).write_text("cleaned")\n raise SystemExit(0)\n'
                          'signal.signal(signal.SIGTERM,stop)\nprint("started",flush=True)\ntime.sleep(30)\n')
        with self.assertRaises(ValueError):
            common.command([sys.executable, str(helper), str(receipt)], self.root / 'log', 0.5)
        self.assertEqual(receipt.read_text(), 'cleaned')

    def test_alarm_after_spawn_before_registration_cannot_lose_owned_process(self):
        import signal
        from unittest.mock import patch
        original = common.subprocess.Popen
        owned = []
        def spawning(*args, **kwargs):
            process = original(*args, **kwargs)
            owned.append(process)
            os.kill(os.getpid(), signal.SIGALRM)
            return process
        def interrupted(*_): raise KeyboardInterrupt()
        previous = signal.signal(signal.SIGALRM, interrupted)
        reaped_by_command = False
        try:
            with patch.object(common.subprocess, 'Popen', side_effect=spawning):
                with self.assertRaises(KeyboardInterrupt):
                    common.command([sys.executable, '-c', 'import time; time.sleep(30)'], self.root / 'log', 5)
            reaped_by_command = len(owned) == 1 and owned[0].poll() is not None
        finally:
            signal.signal(signal.SIGALRM, previous)
            for process in owned:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
        self.assertEqual(len(owned), 1)
        self.assertTrue(reaped_by_command)

    def test_output_bound_still_drains_cleanup_output(self):
        helper = self.root / 'worker.py'; receipt = self.root / 'cleaned'
        helper.write_text('import signal,time,sys,os\nfrom pathlib import Path\n'
                          'def stop(*_):\n os.write(1,b"z"*200000)\n'
                          ' Path(sys.argv[1]).write_text("cleaned")\n raise SystemExit(0)\n'
                          'signal.signal(signal.SIGTERM,stop)\n'
                          'while True:\n os.write(1,b"x"*65536);time.sleep(.002)\n')
        with self.assertRaises(ValueError):
            common.command([sys.executable, str(helper), str(receipt)], self.root / 'log', 5)
        self.assertEqual(receipt.read_text(), 'cleaned')
        self.assertLessEqual((self.root / 'log').stat().st_size, common.LOG_LIMIT)

    def test_controlled_environment_omits_credentials_and_python_overrides(self):
        helper = self.root / 'env.py'
        helper.write_text('import os,json\nprint(json.dumps(dict(os.environ)))\n')
        from unittest.mock import patch
        with patch.dict(os.environ, {'AUTHORIZATION': 'hidden', 'PYTHONPATH': '/untrusted', 'DOCKER_HOST': 'tcp://remote'}):
            self.assertEqual(common.command([sys.executable, str(helper)], self.root / 'log', 5), 0)
        value = json.loads((self.root / 'log').read_text())
        self.assertNotIn('AUTHORIZATION', value)
        self.assertNotIn('PYTHONPATH', value)
        self.assertNotIn('DOCKER_HOST', value)

    def test_matching_count_without_authenticated_bootstrap_is_refused(self):
        from types import SimpleNamespace
        controller = SimpleNamespace(native_out=self.root, image='sha256:' + 'a' * 64, commit='b' * 40)
        inputs = {'rootfs_packages': [{'name':[f'package-{i}'],'version':['1']} for i in range(341)], 'packages':[]}
        common.save(self.root / 'inputs.lock.json', inputs)
        lock = ''.join(f'package-{i} 1\n' for i in sorted(range(341), key=lambda i:f'package-{i}'))
        (self.root / 'packages.lock').write_text(lock)
        (self.root / 'image-id').write_text(controller.image)
        common.save(self.root / 'result.json', {'native_build':'PASS','reviewed_inputs_sha256':common.digest(self.root / 'inputs.lock.json')})
        boot = {'status':'image-provisioned','image_id':controller.image,'packages_lock_sha256':common.digest(self.root / 'packages.lock'),
                'inputs_sha256':common.digest(self.root / 'inputs.lock.json')}
        common.save(self.root / 'bootstrap.json', boot)
        self.assertEqual(common.base_prerequisite(controller)['package_count'], 341)
        boot['inputs_sha256'] = '0' * 64; common.save(self.root / 'bootstrap.json', boot)
        with self.assertRaises(ValueError): common.base_prerequisite(controller)


if __name__ == '__main__':
    unittest.main()
