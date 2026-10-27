# SPDX-License-Identifier: MIT
"""Synthetic raw-file join controls; no collection, ALPM or native evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import contract as C
import job as J
import cli_fixture as F

SOURCE = next(p for p in HERE.parents if (p / 'packages/tools/cachy-asahi-session-diagnostics/PKGBUILD').is_file())


class RawJoins(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='diagnostics-raw-joins-')
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)
        self.prefix = 'fixture-evidence/staged-before-install/session-diagnostics-home-fresh/'
        self.rows, self.public = {}, {}
        probe = C.load('synthetic_raw_report_probe', SOURCE / 'packages/tools/cachy-asahi-session-diagnostics/session_probe.py')
        def refuse(*_):
            raise AssertionError('synthetic raw join control must never launch tools')
        actual = probe.collect(dict(execution_context='virtual'), run=refuse, read=lambda _: None, environ={}, context={})
        actual['identity'].update(architecture='aarch64', page_size_bytes=4096)
        proof = dict(headless_checks=F.assert_headless(actual, architecture='aarch64', page_size=4096),
                     missing_tool_control=dict(scope='SYNTHETIC_ONLY'), owned_process_cleanup=dict(scope='SYNTHETIC_ONLY'))
        commands = []
        for case in ('help', 'headless', 'tamper-changed', 'tamper-missing', 'tamper-oversized', 'tamper-symlink', 'tamper-restored'):
            refusal = case.startswith('tamper-') and case != 'tamper-restored'
            stdout = json.dumps(actual).encode() if case == 'headless' else b'' if refusal else b'SYNTHETIC HELP\n'
            stderr = b'runtime missing or changed\n' if refusal else b''
            for suffix, raw in (('.stdout', stdout), ('.stderr', stderr)):
                self.put(case + suffix, raw)
            commands.append(dict(case=case, returncode=2 if refusal else 0, stdout_bytes=len(stdout),
                                 stderr_bytes=len(stderr), hostile_python_environment_ignored=True))
        self.put('missing-tool-control.json', json.dumps(proof['missing_tool_control']).encode())
        self.put('owned-process-control.json', json.dumps(proof['owned_process_cleanup']).encode())
        self.put('commands.json', json.dumps(commands).encode())
        proof['public_evidence'] = self.public
        self.put('report.json', json.dumps(proof).encode(), nested=False)
        key, archive = 'A' * 40, 'SYNTHETIC-NOT-ALPM.pkg.tar.zst'
        signing = dict(archive='/private/' + archive, fingerprint=key)
        for name, raw in ((archive, b'SYNTHETIC ARCHIVE'), (archive + '.sig', b'SYNTHETIC SIGNATURE'),
                          ('TEST-public.asc', b'SYNTHETIC CERTIFICATE'),
                          ('verification.txt', ('[GNUPG:] GOODSIG TEST test\n[GNUPG:] VALIDSIG ' + key + ' 1\n').encode())):
            relative = 'fixture-evidence/package-signing/' + name
            path = self.runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.rows[relative] = F.pin(raw)
        signing['archive_sha256'] = self.rows['fixture-evidence/package-signing/' + archive]['sha256']
        signing['signature_sha256'] = self.rows['fixture-evidence/package-signing/' + archive + '.sig']['sha256']
        self.life = dict(staged_observations=[dict(home='session-diagnostics-home-fresh', session_diagnostics=proof)],
                         events=[], package_test_signing=signing, native_architecture='aarch64', actual_page_size=4096)
        self.source = self.runtime / 'source'
        (self.source / C.LANE).mkdir(parents=True)
        for name in ('cli_fixture.py', 'installed.py'):
            (self.source / C.LANE / name).write_bytes((HERE / name).read_bytes())

    def put(self, name, raw, nested=True):
        path = self.runtime / (self.prefix + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.rows[self.prefix + name] = F.pin(raw)
        if nested:
            self.public[name] = F.pin(raw)

    def gate(self, life=None, rows=None):
        J.fixture_evidence(self.source, self.runtime, life or self.life, self.rows if rows is None else rows)

    def test_portable_complete_raw_report_joins(self):
        self.gate()

    def test_nested_pin_and_omitted_raw_file_refused(self):
        for change in ('missing', 'changed'):
            rows = copy.deepcopy(self.rows)
            if change == 'missing':
                del rows[self.prefix + 'headless.stdout']
            else:
                rows[self.prefix + 'headless.stdout']['sha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'hash join differs'):
                self.gate(rows=rows)

    def test_changed_raw_report_or_control_refused(self):
        for name in ('report.json', 'owned-process-control.json', 'missing-tool-control.json'):
            path = self.runtime / (self.prefix + name)
            original = path.read_bytes()
            path.write_text('{}')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.gate()
            path.write_bytes(original)

    def test_raw_runtime_sha_and_physical_pass_refused(self):
        path = self.runtime / (self.prefix + 'headless.stdout')
        original = json.loads(path.read_bytes())
        for change in ('runtime', 'physical'):
            value = copy.deepcopy(original)
            if change == 'runtime':
                value['tool_sha256'] = '0' * 64
            else:
                value['physical_checks']['lock_unlock'] = 'PASS'
            path.write_text(json.dumps(value))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.gate()

    def test_raw_tamper_refusal_and_command_exit_required(self):
        path = self.runtime / (self.prefix + 'tamper-changed.stderr')
        path.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'integrity refusal'):
            self.gate()
        path.write_bytes(b'runtime missing or changed\n')
        command = self.runtime / (self.prefix + 'commands.json')
        rows = json.loads(command.read_bytes())
        rows[2]['returncode'] = 0
        command.write_text(json.dumps(rows))
        with self.assertRaisesRegex(ValueError, 'command/control receipts'):
            self.gate()

    def test_extra_public_file_and_signature_digest_refused(self):
        rows = copy.deepcopy(self.rows)
        rows['fixture-evidence/unexpected'] = F.pin(b'extra')
        with self.assertRaisesRegex(ValueError, 'exact raw fixture'):
            self.gate(rows=rows)
        life = copy.deepcopy(self.life)
        life['package_test_signing']['signature_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'signing/installed archive'):
            self.gate(life=life)

    def test_bad_raw_signature_status_refused(self):
        path = self.runtime / 'fixture-evidence/package-signing/verification.txt'
        path.write_bytes(path.read_bytes() + b'[GNUPG:] EXPKEYSIG TEST\n')
        with self.assertRaisesRegex(ValueError, 'signature refused'):
            self.gate()


if __name__ == '__main__':
    unittest.main()
