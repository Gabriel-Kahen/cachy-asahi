#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Actor-fenced ordinary filesystem DATA; actual inner failure cause is unknown."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PARENT = Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v5-20261117/artifacts/development/llhttp93-canonical-v5-20261117-r1/Source93-DATA')
PUBLIC95 = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp93-native-result-r1/public-files/llhttp-reference-owned-public-r9e2i41a')
MODEL = None
ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'fcntl.')) or event in {
        'os.system', 'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.kill', 'os.killpg',
        'os.pidfd_open', 'resource.setrlimit'}:
        ACTORS.append(event)
        raise RuntimeError('FENCED actor')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        if (args[2] or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            need = Path(os.fsdecode(args[0])).absolute()
            if MODEL is None or not need.is_relative_to(MODEL):
                raise RuntimeError('FENCED write outside MODEL')
    if event.startswith(('os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.chmod', 'os.link', 'os.symlink')):
        for value in args[:2]:
            if isinstance(value, (str, bytes, os.PathLike)):
                path = Path(os.fsdecode(value)).absolute()
                if not ((MODEL is not None and path.is_relative_to(MODEL)) or path.parent == Path('/home/gabe') and path.name.startswith('llhttp-v6-MODEL-')):
                    raise RuntimeError('FENCED mutation outside MODEL')


sys.addaudithook(fence)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


E = load(HERE/'public_evidence.py', 'public_v6_DATA')
P = load(HERE/'prepare.py', 'prepare_v6_DATA')


def functions(raw):
    return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(raw).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}


class Controls(unittest.TestCase):
    def setUp(self):
        global MODEL
        MODEL = Path(tempfile.mkdtemp(prefix='llhttp-v6-MODEL-', dir='/home/gabe'))
        self.area = MODEL
        self.addCleanup(self.cleanup)
        self.addCleanup(self.assertEqual, ACTORS, [])
        self.outer = MODEL/'operation'
        self.inner = self.outer/'volume/work/llhttp-reference-native'
        self.inner.mkdir(parents=True, mode=0o700)
        self.public = self.outer/'evidence'
        self.context = dict(source='a'*40, ref='refs/heads/codex/MODEL-v6', source_map_sha256='b'*64,
                            run='44069765332', attempt=1, job='pair', nonce='c'*32)

    def cleanup(self):
        for q in sorted(self.area.rglob('*'), key=lambda q: len(q.parts), reverse=True):
            if q.is_symlink() or not q.is_dir():
                q.unlink()
            else:
                q.rmdir()
        self.area.rmdir()

    def put(self, name, raw):
        path = self.inner/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def fixture(self, status='HOLD'):
        report = dict(self.context, status=status, Root_acceptance=None, hardware='NOT RUN', release='NOT ADMITTED')
        self.put('report.json', E.encode(report))
        self.put('cleanup.json', E.encode(dict(errors=[], MODEL=True)))
        self.put('commands/000.json', E.encode(dict(MODEL=True, argv=['/usr/bin/docker', 'info'])))
        self.put('commands/000.stdout', b'MODEL-public-output\n')
        self.put('commands/000.stderr', b'')
        return report

    def test_actual95_public_status_readonly_and_reporting_gap_without_cause_guess(self):
        self.assertTrue(PUBLIC95.is_dir(), 'retained public fixture required')
        raw = (PUBLIC95/'owner.log').read_bytes()
        lines = raw.decode().splitlines()
        mount = json.loads(next(n.removeprefix('MOUNT_CLASS: ') for n in lines if n.startswith('MOUNT_CLASS: ')))
        for key in ('root', 'source', 'tmp', 'var_tmp'):
            self.assertFalse(mount['paths'][key]['writable'])
            self.assertTrue(mount['paths'][key]['statvfs_readonly'])
            self.assertTrue(mount['paths'][key]['cover']['mount_readonly'])
        self.assertTrue(mount['paths']['work']['writable'])
        payload = json.loads(lines[-1])
        self.assertEqual(payload['status'], 'HOLD')
        self.assertIsNone(payload['Root_acceptance'])
        self.assertNotIn('HOLD_PAYLOAD', raw.decode())
        self.assertFalse((PUBLIC95/'evidence').exists())
        outer = json.loads((PUBLIC95/'owner-report.json').read_bytes())
        self.assertEqual(outer['failure'], dict(type='ValueError', message='ordinary payload natural success required'))
        self.assertEqual(outer['native_pair'], 'NOT RUN')
        self.assertEqual(outer['cleanup']['errors'], [])
        self.assertTrue(outer['cleanup']['owned_storage_absent'])

    def test_hold_exports_exact_public_receipts_before_modeled_storage_removal(self):
        self.fixture()
        row = E.export(self.inner, self.public, self.context, os.getuid())
        self.assertEqual((row['status'], row['payload_status'], row['accepting']), ('EXPORTED', 'HOLD', False))
        originals = {str(q.relative_to(self.inner)): q.read_bytes() for q in self.inner.rglob('*') if q.is_file()}
        for q in sorted(self.inner.rglob('*'), key=lambda q: len(q.parts), reverse=True):
            q.rmdir() if q.is_dir() else q.unlink()
        self.inner.rmdir()
        for name, raw in originals.items():
            self.assertEqual((self.public/name).read_bytes(), raw)
        manifest = json.loads((self.public/'inner-public-manifest.json').read_bytes())
        self.assertEqual(manifest['files'], {n: E.pin(raw) for n, raw in originals.items()})
        self.assertFalse(manifest['accepting'])

    def test_success_is_only_nonaccepting_snapshot_never_payload_upgrade(self):
        self.fixture('PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY')
        for name in E.SUCCESS_REQUIRED:
            if name not in ('report.json', 'cleanup.json'):
                self.put(name, b'{"MODEL":true}\n')
        report = dict(status='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP')
        E.preserve(report, self.inner, self.public, self.context, os.getuid())
        self.assertEqual(report['status'], 'PAIR_PASSED_PENDING_EXTERNAL_CLEANUP')
        self.assertFalse(report['inner_public_evidence']['accepting'])
        self.assertEqual((self.public/'pair.json').read_bytes(), b'{"MODEL":true}\n')

    def test_success_missing_archive_downgrades_export_and_keeps_payload_checks(self):
        self.fixture('PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY')
        report = dict(status='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP')
        row = E.preserve(report, self.inner, self.public, self.context, os.getuid())
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertIn('build-1/artifacts/'+E.PACKAGE+'.pkg.tar.xz', row['missing_required'])
        self.assertEqual(report['status'], 'HOLD')
        self.assertFalse(row['accepting'])

    def test_no_cache_context_keyring_environment_or_arbitrary_file_reads(self):
        self.fixture()
        for name in ('cache/private', 'bootstrap/context/private', 'bootstrap/gpg-home/private',
                     'bootstrap/environment', 'launch.json', 'arbitrary-secret'):
            self.put(name, b'MODEL_PRIVATE_SENTINEL')
        calls = []
        original = os.open
        def opened(name, *args, **kwargs):
            calls.append(str(name))
            return original(name, *args, **kwargs)
        with patch.object(E.os, 'open', side_effect=opened):
            E.export(self.inner, self.public, self.context, os.getuid())
        self.assertFalse(any(x in calls for x in ('cache', 'context', 'gpg-home', 'environment', 'launch.json', 'arbitrary-secret')))
        self.assertFalse(any(b'MODEL_PRIVATE_SENTINEL' in q.read_bytes() for q in self.public.rglob('*') if q.is_file()))
        self.assertTrue(set(str(q.relative_to(self.public)) for q in self.public.rglob('*') if q.is_file()) <= set(E.PUBLIC_LEAVES) | {'inner-public-manifest.json'})

    def test_context_duplicate_status_and_unexpected_environment_fields_refuse(self):
        report = self.fixture()
        for changed in (dict(report, source='f'*40), dict(report, source_map_sha256='f'*64),
                        dict(report, nonce='f'*32), dict(report, status='NEW_UNKNOWN'), dict(report, environment={'PRIVATE':'MODEL'})):
            self.put('report.json', E.encode(changed))
            with self.assertRaises(ValueError):
                E.export(self.inner, self.public, self.context, os.getuid())
            self.assertFalse(self.public.exists())
        self.put('report.json', E.encode(report).replace(b'"status":', b'"status":"HOLD","status":'))
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())

    def test_symlink_hardlink_nonregular_mode_and_uid_refuse(self):
        self.fixture()
        path = self.inner/'commands/000.stdout'
        raw = path.read_bytes(); path.unlink()
        os.symlink(str(self.inner/'cleanup.json'), path)
        with self.assertRaises(OSError):
            E.export(self.inner, self.public, self.context, os.getuid())
        path.unlink(); os.link(self.inner/'cleanup.json', path)
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())
        path.unlink(); self.put('commands/000.stdout', raw); path.chmod(0o622)
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid()+1)
        path.unlink(); path.mkdir()
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())

    def test_changed_file_budget_paths_and_existing_destination_refuse(self):
        self.fixture()
        path = self.inner/'commands/000.stdout'
        real = os.read; changed = []
        def reading(fd, size):
            raw = real(fd, size)
            if raw == b'MODEL-public-output\n' and not changed:
                path.write_bytes(raw+b'changed'); changed.append(True)
            return raw
        with patch.object(E.os, 'read', side_effect=reading), self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())
        with patch.object(E, 'MAX_BYTES', 8), self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())
        with self.assertRaises(ValueError):
            E.export(self.inner, self.outer/'wrong', self.context, os.getuid())
        self.public.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            E.export(self.inner, self.public, self.context, os.getuid())

    def test_missing_refused_and_exception_paths_keep_hold_cleanup_reachable(self):
        report = dict(status='HOLD')
        row = E.preserve(report, self.inner, self.public, self.context, os.getuid())
        self.assertEqual(row['status'], 'INCOMPLETE')
        self.assertEqual(row['missing_required'], ['report.json', 'cleanup.json'])
        self.assertEqual(report['status'], 'HOLD')
        self.assertFalse(row['accepting'])
        private = 'MODEL_PRIVATE_PATH_ENV_SECRET'
        with patch.object(E, 'export', side_effect=ValueError(private)):
            row = E.preserve(report, self.inner, self.public, self.context, os.getuid())
        self.assertEqual(row['status'], 'REFUSED')
        self.assertNotIn(private, json.dumps(row))
        self.assertEqual(report['status'], 'HOLD')

    def test_complete95_compact93_inverse_tamper_and_unchanged_bounds(self):
        old = P.parent_bodies(PARENT)
        output = self.area/'Source95'
        result = P.construct(PARENT, output)
        bodies = {str(q.relative_to(output)): q.read_bytes() for q in output.rglob('*') if q.is_file()}
        self.assertEqual((result['files'], len(bodies)), (95, 95))
        self.assertLess(result['bytes'], 2*1024**2)
        self.assertEqual(P.inverse(bodies), old)
        self.assertTrue(all(v is None for v in result['actual'].values()))
        self.assertEqual(set(bodies)-set(old), {P.HELPER, P.MARKER})
        policy = json.loads(bodies[P.PREFIX+'policy.json']); policy.pop('inner_public_retention')
        self.assertEqual(policy, json.loads(old[P.PREFIX+'policy.json']))
        for name in (P.MARKER, P.HELPER, P.PREFIX+'hosted_owner.py', P.PREFIX+'policy.json', P.PREFIX+'owner-program.json', 'source-map.json'):
            with self.subTest(leaf=name), self.assertRaises((ValueError, KeyError, json.JSONDecodeError)):
                P.inverse(dict(bodies, **{name: bodies[name]+b'\n# changed'}))
        self.assertEqual(bodies[P.PREFIX+'payload.py'], old[P.PREFIX+'payload.py'])
        self.assertEqual(bodies[P.PREFIX+'data.py'], old[P.PREFIX+'data.py'])

    def test_real_controller_finally_hook_precedes_unchanged_cleanup_and_pass_guards(self):
        old = P.parent_bodies(PARENT)
        raw, seams = P.projection(old)
        before, after = functions(old[P.PREFIX+'hosted_owner.py']), functions(raw)
        self.assertEqual({k:v for k,v in before.items() if k != 'main'}, {k:v for k,v in after.items() if k != 'main'})
        main = next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        block = next(n for n in main.body if isinstance(n, ast.Try) and n.finalbody)
        call = block.finalbody[0]
        self.assertEqual(ast.unparse(call.value.func), 'E.preserve')
        calls = []
        class Fake:
            host_facts = {}; host_policy = {}
            def cleanup(self): calls.append('cleanup'); return dict(errors=[], owned_storage_absent=True)
        class Cancel:
            ITIMER_REAL = 0
            @staticmethod
            def setitimer(*args): calls.append('timer')
        class Args:
            output = self.outer; source_map_sha256 = self.context['source_map_sha256']; runner_uid = os.getuid()
        scope = dict(E=E, a=Args(), actual=dict(source=self.context['source'], ref=self.context['ref'], nonce=self.context['nonce']),
                     os=type('MODEL_OS', (), {'environ':dict(GITHUB_RUN_ID=self.context['run'],GITHUB_JOB=self.context['job'])}),
                     owner=Fake(), report=dict(status='HOLD'), signal=Cancel())
        # Execute the actual finally prefix through cleanup, before final report I/O.
        end = next(i for i,n in enumerate(block.finalbody) if isinstance(n, ast.Expr) and ast.unparse(n.value).startswith('signal.setitimer(signal.ITIMER_REAL, 0)'))
        with patch.object(E, 'export', side_effect=ValueError('MODEL-private')):
            exec(compile(ast.Module(body=block.finalbody[:end+1], type_ignores=[]), 'actual-finally-MODEL', 'exec'), scope)
        self.assertIn('cleanup', calls)
        self.assertEqual(scope['report']['status'], 'HOLD')
        self.assertEqual(scope['report']['inner_public_evidence']['status'], 'REFUSED')
        self.assertIn("ordinary payload natural success required", raw.decode())
        self.assertIn("if report['status']=='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP' and not report['cleanup']['errors'] and report['cleanup']['owned_storage_absent']:", raw.decode())


if __name__ == '__main__':
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not __debug__:
        raise SystemExit('Run DATA controls with python -I -B, unoptimized')
    unittest.main(verbosity=2)
