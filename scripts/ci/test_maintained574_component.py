#!/usr/bin/env python3
"""Inert fixture control checks: every external command is mocked."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


c = module('component_test_subject', 'maintained574_component.py')
h = module('component_helper_subject', 'maintained_desktop574.py')
OLD = 'sha256:' + '0' * 64


class CommandExit(ValueError):
    def __init__(self, code):
        self.code = code


class Daemon:
    def __init__(self):
        self.images = {OLD: {'Id': OLD, 'RepoTags': ['baseline:keep']}}
        self.containers = {}; self.commands = []; self.sequence = 0
        self.build_code = 0; self.create_code = 0; self.build_timeout = False

    def query(self, *args):
        if args[0] == 'rm':
            self.commands.append(('/usr/bin/docker', *args))
            self.containers.pop(args[1]); return args[1]
        if args[:2] == ('image', 'inspect'):
            return json.dumps([self.images[args[2]]])
        if args[:2] == ('container', 'inspect'):
            return json.dumps([next(v for v in self.containers.values()
                                    if v['Id'] == args[2] or v['Name'] == '/' + args[2])])
        if args[:2] == ('image', 'ls'):
            rows = list(self.images)
            if '--filter' in args:
                value = args[args.index('--filter') + 1]
                if value.startswith('reference='):
                    rows = [i for i in rows if value[10:] in self.images[i]['RepoTags']]
                elif value.startswith('label='):
                    key, value = value[6:].split('=', 1)
                    rows = [i for i in rows if self.images[i].get('Config', {}).get('Labels', {}).get(key) == value]
                else:
                    raise AssertionError(args)
            return '\n'.join(rows)
        if args[:2] == ('container', 'ls'):
            value = args[args.index('--filter') + 1]
            rows = list(self.containers.values())
            if value.startswith('name=^/'):
                rows = [v for v in rows if v['Name'] == value[6:-1]]
            elif value.startswith('id='):
                rows = [v for v in rows if v['Id'] == value[3:]]
            elif value.startswith('ancestor='):
                rows = [v for v in rows if v['Image'] == value[9:]]
            else:
                raise AssertionError(args)
            return '\n'.join(v['Id'] if args[-1] == '{{.ID}}' else v['Name'][1:] for v in rows)
        raise AssertionError(args)

    def run(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        if argv[0] == sys.executable:
            self.assert_cli_unlocked(Path(argv[argv.index('--output') + 1]))
            output = io.StringIO()
            with patch.dict(os.environ, dict(os.environ)), patch.object(sys, 'argv', argv[2:]), \
                    contextlib.redirect_stdout(output):
                rc = h.main()
            kwargs['stdout'].write(output.getvalue().encode())
            return SimpleNamespace(returncode=rc)
        assert argv[0] == '/usr/bin/docker', argv
        if argv[1] == 'build':
            out = Path(argv[argv.index('--iidfile') + 1]).parent
            state = json.loads((out / 'report.json').read_text())
            assert state['ownership']['build_started'] is True
            assert state['ownership']['build_complete'] is False
            assert 'build_returncode' not in state
            assert (Path(argv[-1]) / 'Dockerfile').read_text() == c.DOCKERFILE
            if self.build_timeout:
                raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
            if self.build_code:
                return SimpleNamespace(returncode=self.build_code)
            self.sequence += 1; image = 'sha256:' + f'{self.sequence:064x}'
            label = argv[argv.index('--label') + 1].split('=', 1)[1]
            self.images[image] = dict(Id=image, Architecture='arm64', Os='linux',
                                     Config={'Labels': {h.OWNER_LABEL: label}},
                                     RepoTags=[argv[argv.index('--tag') + 1]], RepoDigests=[])
            (out / 'image-id').write_text(image)
        elif argv[1] == 'create':
            cidfile = Path(argv[argv.index('--cidfile') + 1]); out = cidfile.parent
            state = json.loads((out / 'report.json').read_text())
            assert state['ownership']['probe_started'] is True
            assert state['ownership']['probe_complete'] is False
            assert state['build_returncode'] == 0
            if self.create_code:
                return SimpleNamespace(returncode=self.create_code)
            cid = f'{len(self.commands) + 1000:064x}'
            label = argv[argv.index('--label') + 1].split('=', 1)[1]
            self.containers[cid] = dict(Id=cid, Name='/' + argv[argv.index('--name') + 1],
                                       Image=argv[-1], Config={'Labels': {h.OWNER_LABEL: label}},
                                       State={'Running': False, 'Status': 'created'})
            cidfile.write_text(cid)
        elif argv[1:3] == ['rm', '-f']:
            self.containers.pop(argv[3])
        elif argv[1:4] == ['image', 'rm', '--no-prune']:
            image = argv[4]
            assert not any(v['Image'] == image for v in self.containers.values())
            assert image != OLD
            self.images.pop(image)
        else:
            raise AssertionError(argv)
        return SimpleNamespace(returncode=0)

    def command(self, argv, log, env, limit):
        with log.open('wb') as stream:
            rc = self.run(argv, stdout=stream, env=env, timeout=limit).returncode
        if rc:
            raise CommandExit(rc)

    @staticmethod
    def assert_cli_unlocked(out):
        fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        task_tmp = Path(os.environ.get('TMPDIR', tempfile.gettempdir()))
        self.temp = tempfile.TemporaryDirectory(dir=task_tmp); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700); self.daemon = Daemon()
        self.enterContext(patch.dict(os.environ, dict(os.environ)))
        self.enterContext(patch.object(h, 'docker', side_effect=self.daemon.query))
        self.enterContext(patch.object(subprocess, 'run', side_effect=self.daemon.run))
        self.enterContext(patch.object(subprocess, 'check_output', side_effect=AssertionError('unmocked actor')))
        self.enterContext(patch.object(c, 'process', SimpleNamespace(command=self.daemon.command, CommandExit=CommandExit)))

    def test_five_fixed_cases_use_actual_helper_cli_and_preserve_baseline(self):
        for index, name in enumerate(c.CASES):
            with self.subTest(case=name):
                result = c.case(h, self.root, name, f'{index + 1:016x}')
                self.assertEqual(result['status'], 'PASS')
                report = json.loads((self.root / name / 'report.json').read_text())
                self.assertEqual(report['ownership']['before_images'], [OLD])
                self.assertIs(report['ownership']['probe_complete'], False)
                self.assertIn(OLD, self.daemon.images)
        self.assertEqual(set(self.daemon.images), {OLD}); self.assertEqual(self.daemon.containers, {})
        commands = self.daemon.commands
        self.assertEqual(sum(a[1] == 'build' for a in commands), 5)
        self.assertEqual(sum(a[1] == 'create' for a in commands), 6)
        self.assertEqual(sum(a[0] == sys.executable for a in commands), 7)
        self.assertFalse(any(a[1] in ('start', 'run', 'pull', 'push', 'prune') for a in commands))

    def test_failed_create_has_no_fallback_or_probe_completion(self):
        self.daemon.create_code = 125
        with self.assertRaisesRegex(ValueError, 'no fallback'):
            c.case(h, self.root, 'normal', 'a' * 16)
        report = json.loads((self.root / 'normal/report.json').read_text())
        self.assertEqual(report['create_returncode'], 125)
        self.assertIs(report['ownership']['probe_complete'], False)
        self.assertEqual(len(self.daemon.images), 2)
        self.assertEqual(len(self.daemon.commands), 2)

    def test_build_failure_and_timeout_never_fabricate_completion(self):
        for index, timeout in enumerate((False, True)):
            self.daemon.build_code = 7; self.daemon.build_timeout = timeout
            name = f'failed-{index}'
            with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                c.case(h, self.root, name, f'{index + 1:016x}')
            report = json.loads((self.root / name / 'report.json').read_text())
            self.assertIs(report['ownership']['build_complete'], False)
            self.assertEqual(report.get('build_returncode'), None if timeout else 7)
            self.assertIs(report['ownership']['probe_started'], False)
        self.assertEqual(set(self.daemon.images), {OLD})

    def test_pin_mismatch_refuses_before_module_execution(self):
        path = self.root / 'untrusted.py'; path.write_text('raise AssertionError("must not execute")')
        with self.assertRaisesRegex(ValueError, 'binding'):
            c.load('must_not_execute', path, '0' * 64)
        self.assertFalse(self.daemon.commands)

    def test_main_creates_guard_directory_before_cases(self):
        events = []
        def guard(path):
            self.assertTrue(path.is_dir()); events.append('guard')
        def fixed_case(helper, root, name, token):
            self.assertEqual(events[0], 'guard'); events.append(name)
            return dict(case=name, status='PASS')
        runtime = c.process
        with patch.object(c, 'load', side_effect=[h, SimpleNamespace(probe=guard), runtime]), \
                patch.object(c, 'case', side_effect=fixed_case), \
                patch.object(sys, 'argv', ['component', '--output', str(self.root / 'main')]):
            self.assertEqual(c.main(), 0)
        self.assertEqual(events, ['guard', *c.CASES])
        result = json.loads((self.root / 'main/public/component.json').read_text())
        self.assertTrue(result['pre_fixture_image_ids_preserved'])
        self.assertEqual(result['status'], 'PASS'); self.assertFalse(self.daemon.commands)


if __name__ == '__main__':
    unittest.main()
