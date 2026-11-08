"""Source-only command controls using retained real zlib bytes; no recipe runs."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/build/source_materials.py').is_file())
spec = importlib.util.spec_from_file_location('offline_preflight', HERE / 'preflight.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
FIXTURE = ROOT / 'tests/fixtures/offline-build-v2-c01'
EVENTS = []


def deny(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.fork', 'os.spawn', 'os.posix_spawn')) or event == 'os.system':
        EVENTS.append(event)
        raise AssertionError('DATA controls forbid network/process actors')


sys.addaudithook(deny)


def fingerprint(path):
    return {str(p.relative_to(path)): (p.stat().st_mode, p.stat().st_mtime_ns,
            p.stat().st_ctime_ns, p.read_bytes() if p.is_file() else None)
            for p in (path, *sorted(path.rglob('*')))}


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        manifest = json.loads((FIXTURE / 'fixture-files.json').read_bytes())
        for name, pin in manifest['files'].items():
            raw = (FIXTURE / name).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (pin['bytes'], pin['sha256']))
        self.cache = self.root / 'cache'; shutil.copytree(FIXTURE / 'accepted-cache', self.cache)
        for p in (self.cache, *self.cache.rglob('*')):
            p.chmod(0o700 if p.is_dir() else 0o600)
        (self.cache / '.partial').mkdir(mode=0o700)
        self.recipe = self.root / 'recipe'
        shutil.copytree(ROOT / 'packages/experiments/cachy-asahi-zlib-baseline', self.recipe)
        self.plan = FIXTURE / 'baseline-source-plan.json'
        self.catalog = FIXTURE / 'inputs/source-inputs.json'

    def check(self, **changes):
        args = dict(recipe_path=self.recipe, plan_path=self.plan,
                    plan_sha256=hashlib.sha256(self.plan.read_bytes()).hexdigest(),
                    catalog_path=self.catalog, cache_path=self.cache, repo_root=ROOT)
        args.update(changes)
        return M.check(**args)

    def command(self):
        return ['--recipe', str(self.recipe), '--source-plan', str(self.plan),
                '--source-plan-sha256', hashlib.sha256(self.plan.read_bytes()).hexdigest(),
                '--source-catalog', str(self.catalog), '--source-cache', str(self.cache)]

    def test_real_retained_baseline_command_is_read_only_and_needs_no_builder_arguments(self):
        before = fingerprint(self.cache); output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = M.main(self.command(), repo_root=ROOT)
        self.assertEqual(code, 0); result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'VERIFIED_OFFLINE_SOURCE_BINDING_ONLY')
        self.assertEqual(result['sources'][0]['bytes'], 1502830)
        self.assertEqual(result['sources'][0]['sha256'], 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16')
        self.assertFalse(result['cache_writes']); self.assertFalse(result['builder_started'])
        self.assertEqual(before, fingerprint(self.cache)); self.assertEqual(EVENTS, [])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_same_cache_accepts_independently_pinned_lto_plan(self):
        result = self.check(recipe_path=ROOT / 'packages/experiments/cachy-asahi-zlib-lto',
                            plan_path=FIXTURE / 'lto-source-plan.json',
                            plan_sha256=hashlib.sha256((FIXTURE / 'lto-source-plan.json').read_bytes()).hexdigest())
        self.assertEqual(result['sources'][0]['id'], 'zlib-1.3.2')
        self.assertEqual(result['build_status'], 'NOT RUN'); self.assertFalse(result['legal_acceptance'])

    def test_missing_object_refuses_without_fallback_or_cache_writes(self):
        next((self.cache / 'objects').iterdir()).unlink(); before = fingerprint(self.cache)
        with self.assertRaisesRegex(ValueError, 'offline source object missing'): self.check()
        self.assertEqual(before, fingerprint(self.cache)); self.assertEqual(EVENTS, [])

    def test_changed_object_and_missing_receipt_refuse_without_repair(self):
        obj = next((self.cache / 'objects').iterdir()); original = obj.read_bytes(); obj.write_bytes(b'changed')
        before = fingerprint(self.cache)
        with self.assertRaises(ValueError): self.check()
        self.assertEqual(before, fingerprint(self.cache)); obj.write_bytes(original)
        next((self.cache / 'receipts').iterdir()).unlink(); before = fingerprint(self.cache)
        with self.assertRaisesRegex(ValueError, 'offline provenance receipt missing'): self.check()
        self.assertEqual(before, fingerprint(self.cache))

    def test_valid_cached_archive_does_not_accept_changed_recipe(self):
        self.check()
        (self.recipe / 'review-note.txt').write_bytes(b'additional recipe input\n')
        import source_materials
        source_materials.cache.run(self.cache, self.catalog,
            hashlib.sha256(self.catalog.read_bytes()).hexdigest(), ['zlib-1.3.2'], offline=True)
        with self.assertRaisesRegex(ValueError, 'recipe inputs mismatch'): self.check()

    def test_plan_hash_and_coverage_and_duplicate_json_refuse(self):
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'): self.check(plan_sha256='0' * 64)
        plan = json.loads(self.plan.read_bytes()); plan['sources'][0]['source'] += '.wrong'
        local = self.root / 'plan.json'; local.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError, 'cover every remote source'):
            self.check(plan_path=local, plan_sha256=hashlib.sha256(local.read_bytes()).hexdigest())
        local.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate source JSON key'):
            self.check(plan_path=local, plan_sha256=hashlib.sha256(local.read_bytes()).hexdigest())

    def test_changed_license_notice_and_public_cache_refuse(self):
        notices = self.root / 'inputs'; shutil.copytree(FIXTURE / 'inputs', notices)
        (notices / 'notices/LICENSE.zlib').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'license evidence'):
            self.check(catalog_path=notices / 'source-inputs.json')
        self.cache.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'private owned cache'): self.check()

    def test_cli_failure_restores_handler_and_respects_existing_outer_alarm(self):
        prior = signal.getsignal(signal.SIGALRM); output = io.StringIO()
        with patch.object(M, 'check', side_effect=lambda *a, **k: signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)), contextlib.redirect_stdout(output):
            self.assertEqual(M.main(self.command(), repo_root=ROOT), 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'REFUSED_OFFLINE_SOURCE_BINDING')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), prior)
        signal.setitimer(signal.ITIMER_REAL, 60)
        try:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): M.main(self.command(), repo_root=ROOT)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        finally: signal.setitimer(signal.ITIMER_REAL, 0)
        self.assertEqual(EVENTS, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
