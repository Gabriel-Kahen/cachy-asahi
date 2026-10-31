#!/usr/bin/env python3
"""Inert network fixtures for fixed source retrieval; no external actors."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixed_source_subject', HERE / 'sources.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class Response(io.BytesIO):
    def __init__(self, payload, url, interrupted=False):
        super().__init__(payload); self.url = url; self.interrupted = interrupted; self.calls = 0

    def read(self, size=-1):
        self.calls += 1
        if self.interrupted:
            if self.calls > 1:
                raise KeyboardInterrupt('fixture interruption')
            size = 1
        return super().read(size)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o077); self.addCleanup(os.umask, self.old_umask)
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.output = self.root / 'handoff'; self.api = s.native()
        self.data = {'one': b'fixed one\n', 'two': b'fixed two\n'}
        self.policy = dict(source=s.SOURCE, actual_run='38801968699', total_bytes=20,
                           objects=[dict(filename=name, size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                         url='https://source.invalid/' + name) for name, data in self.data.items()])
        self.enterContext(patch.object(subprocess, 'run', side_effect=AssertionError('process actor')))
        self.enterContext(patch.object(subprocess, 'check_output', side_effect=AssertionError('process actor')))
        self.enterContext(patch.object(subprocess, 'Popen', side_effect=AssertionError('process actor')))
        for name in ('run', 'probe', 'build', 'audit'):
            if hasattr(self.api, name):
                self.enterContext(patch.object(self.api, name, side_effect=AssertionError('native actor')))

    def cached(self, name, payload=None):
        self.output.mkdir(mode=0o700, exist_ok=True)
        cache = self.output / 'cache'; cache.mkdir(mode=0o700, exist_ok=True)
        path = cache / name; path.write_bytes(self.data[name] if payload is None else payload)
        return path

    def retrieve(self, response):
        with patch.object(self.api.urllib.request, 'urlopen', side_effect=response) as network:
            report = s.retrieve(self.api, self.policy, self.output)
        return report, network

    def test_exact_resume_verifies_cache_without_network_or_actors(self):
        self.cached('one'); self.cached('two')
        report, network = self.retrieve(AssertionError('cache must avoid network'))
        network.assert_not_called()
        self.assertEqual(report['status'], 'PASS_LOCAL_SOURCE_HANDOFF')
        self.assertEqual([x['origin'] for x in report['objects']], ['verified_cache'] * 2)
        self.assertEqual(report['public_hosting'], 'NOT_RUN')
        self.assertEqual(report['compiler_correspondence'], 'NOT_ESTABLISHED')
        self.assertEqual(report['downloader_sha256'], s.sha(HERE.parent / 'native_arm.py'))

    def test_dependency_byte_drift_refused_before_import(self):
        here = self.root / 'subject/scripts/ci/asahi-audio-rust'
        here.mkdir(parents=True)
        paths = (here.parent / 'native_arm.py', here.parents[1] / 'checks/package_checks.py')
        originals = ((HERE.parent / 'native_arm.py').read_bytes(),
                     (HERE.parents[1] / 'checks/package_checks.py').read_bytes())
        for changed in paths:
            with self.subTest(changed=changed.name):
                for path, raw in zip(paths, originals):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
                changed.write_bytes(changed.read_bytes() + b'\n# fixture byte drift\n')
                with patch.object(s, 'HERE', here), patch.object(
                        s.importlib.util, 'spec_from_file_location',
                        side_effect=AssertionError('untrusted dependency import')) as loader:
                    with self.assertRaisesRegex(ValueError, 'source downloader API differs'):
                        s.native()
                    loader.assert_not_called()

    def test_corrupt_cache_fails_whole_handoff_and_preserves_valid_objects(self):
        bad = self.cached('one', b'wrong one\n'); good = self.cached('two')
        report, network = self.retrieve(AssertionError('bad cache must not refresh'))
        network.assert_not_called(); self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(bad.read_bytes(), b'wrong one\n'); self.assertEqual(good.read_bytes(), self.data['two'])
        self.assertEqual(report['objects'][0]['status'], 'FAIL')

    def test_truncated_response_removes_partial_and_preserves_verified_cache(self):
        good = self.cached('one')
        report, network = self.retrieve(lambda url, **kw: Response(b'short', url))
        self.assertEqual(network.call_count, 1); self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(good.read_bytes(), self.data['one'])
        self.assertFalse((self.output / 'cache/two').exists())
        self.assertEqual(sorted(x.name for x in (self.output / 'cache').iterdir()), ['one'])
        self.assertEqual(report['objects'][0]['status'], 'VERIFIED')
        self.assertEqual(report['objects'][1]['status'], 'FAIL')

    def test_interrupted_partial_can_resume_only_missing_exact_object(self):
        self.cached('one')
        failed, first = self.retrieve(lambda url, **kw: Response(self.data['two'], url, interrupted=True))
        self.assertEqual(failed['status'], 'FAIL'); self.assertEqual(failed['error_kind'], 'KeyboardInterrupt')
        self.assertEqual(first.call_count, 1)
        self.assertEqual(sorted(x.name for x in (self.output / 'cache').iterdir()), ['one'])
        passed, second = self.retrieve(lambda url, **kw: Response(self.data['two'], url))
        self.assertEqual(passed['status'], 'PASS_LOCAL_SOURCE_HANDOFF'); self.assertEqual(second.call_count, 1)
        self.assertEqual([x['origin'] for x in passed['objects']], ['verified_cache', 'download'])
        second.assert_called_once_with('https://source.invalid/two', timeout=60)

    def test_fixed_policy_and_unsafe_destinations_refuse_before_transfer(self):
        policy = s.inputs()
        self.assertEqual(len(policy['objects']), 12); self.assertEqual(policy['total_bytes'], 6193014)
        (self.root / 'source-inputs.json').write_text('{}')
        with patch.object(s, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'policy differs'):
            s.inputs()
        with patch.object(self.api.urllib.request, 'urlopen', side_effect=AssertionError('must not transfer')) as network:
            public = self.root / 'public'; public.mkdir(); public.chmod(0o755)
            link = self.root / 'link'; link.symlink_to(public, target_is_directory=True)
            for path in (public, link):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    s.retrieve(self.api, self.policy, path)
            target = self.cached('one'); outside = self.root / 'outside'
            os.link(target, outside)
            report = s.retrieve(self.api, self.policy, self.output)
            self.assertEqual(report['status'], 'FAIL'); self.assertEqual(outside.read_bytes(), self.data['one'])
            network.assert_not_called()


if __name__ == '__main__':
    unittest.main()
