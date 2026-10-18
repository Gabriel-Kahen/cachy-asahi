# SPDX-License-Identifier: MIT
import copy
import hashlib
import http.client
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

M = runpy.run_path(str(Path(__file__).with_name('cachy-asahi-mirrors')))
BODY = b'exact selected repository database\n'


def fixture():
    return dict(schema_version=1, architecture='aarch64', base='asahi-alarm', repository='core',
        database=dict(bytes=len(BODY), sha256=hashlib.sha256(BODY).hexdigest()),
        mirrors=[dict(id='one', server='https://one.example/$arch/$repo'),
                 dict(id='two', server='https://two.example/$arch/$repo')])


class Response(io.BytesIO):
    status = 200
    headers = {}


class Mirrors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def read(self, value):
        p = self.root/'catalog.json'
        p.write_text(json.dumps(value))
        return M['catalog'](p)

    def test_valid_catalog_is_local(self):
        with patch('urllib.request.build_opener', side_effect=AssertionError('network')):
            value, digest = self.read(fixture())
        self.assertEqual(value, fixture())
        self.assertEqual(len(digest), 64)

    def test_platform_and_reference_required(self):
        for field, replacement in [('architecture', 'x86_64'), ('base', 'archlinux'),
                                   ('repository', 'core\nServer=bad'), ('database', {'bytes': 1})]:
            value = fixture(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read(value)

    def test_bad_server_templates(self):
        for server in ['http://one.example/$arch/$repo', 'https://u:p@one.example/$arch/$repo',
                       'https://one.example/$arch/$repo?token=x', 'https://one.example/$architecture/$repo',
                       'https://one.example/$arch/../$repo', 'https://one.example/$arch/$repo\n',
                       'https://one.example/$arch/%2e%2e/$repo', 'https://$arch.example/$repo']:
            value = fixture(); value['mirrors'][0]['server'] = server
            with self.subTest(server=server), self.assertRaises(ValueError):
                self.read(value)

    def test_duplicate_ids_and_servers(self):
        for field in ['id', 'server']:
            value = fixture(); value['mirrors'][1][field] = value['mirrors'][0][field]
            with self.assertRaises(ValueError):
                self.read(value)

    def test_duplicate_json_keys_refused(self):
        p = self.root/'catalog.json'; p.write_text('{"base":1,"base":2}')
        with self.assertRaises(ValueError):
            M['catalog'](p)

    def probe(self, body, headers=None, deadline=1000):
        response = Response(body)
        response.headers = headers or {}
        class Opener:
            def open(self, request, timeout):
                self.request = request; self.timeout = timeout
                return response
        opener = Opener()
        with patch('time.monotonic', return_value=1):
            result = M['probe'](fixture()['mirrors'][0], fixture(), opener, deadline)
        return result, opener

    def test_exact_bytes_and_url_required(self):
        result, opener = self.probe(BODY)
        self.assertEqual(result['status'], 'PASS_EXACT_SNAPSHOT')
        self.assertEqual(opener.request.full_url, 'https://one.example/aarch64/core/core.db')
        self.assertEqual(opener.timeout, 10)

    def test_stale_truncated_and_oversized_database_refused(self):
        for body in [BODY[:-1], BODY+b'x', b'x'*len(BODY)]:
            result, _ = self.probe(body)
            self.assertEqual(result['status'], 'FAIL')

    def http_response(self, wire):
        # Exercise the actual stdlib HTTP parser without a network connection.
        class Socket:
            def makefile(self, *args):
                return io.BytesIO(wire)
        response = http.client.HTTPResponse(Socket())
        response.begin()
        return response

    def test_truncated_chunked_mirror_does_not_abort_healthy_fallback(self):
        broken = self.http_response(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nshort')
        good = self.http_response(b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                                  str(len(BODY)).encode() + b'\r\n\r\n' + BODY)
        responses, urls = [broken, good], []
        class Opener:
            def open(self, request, timeout):
                urls.append(request.full_url)
                return responses.pop(0)
        output = self.root/'fallback-candidate'
        with patch('urllib.request.build_opener', return_value=Opener()):
            report = M['rank'](fixture(), 'a'*64, output)
        self.assertEqual(report['status'], 'PASS_CANDIDATE_WRITTEN')
        self.assertEqual([r['status'] for r in report['results']], ['FAIL', 'PASS_EXACT_SNAPSHOT'])
        self.assertIn('IncompleteRead', report['results'][0]['reason'])
        self.assertEqual(len(urls), 2)
        self.assertNotIn('one.example', output.read_text())
        self.assertIn('two.example', output.read_text())
        self.assertEqual(report['activation'], 'NOT_PERFORMED')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_invalid_http_status_is_a_failed_probe(self):
        test = self
        class Opener:
            def open(self, request, timeout):
                return test.http_response(b'not an HTTP status\r\n\r\n')
        result = M['probe'](fixture()['mirrors'][0], fixture(), Opener(), float('inf'))
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('not an HTTP status', result['reason'])

    def test_headers_and_total_deadline(self):
        for headers in [{'Content-Length': '1'}, {'Content-Encoding': 'gzip'}]:
            self.assertEqual(self.probe(BODY, headers)[0]['status'], 'FAIL')
        self.assertEqual(self.probe(BODY, deadline=0)[0]['status'], 'FAIL')

    def test_redirects_never_followed(self):
        with self.assertRaises(ValueError):
            M['NoRedirect']().redirect_request(None, None, 302, 'moved', {}, 'https://other.example')

    def test_candidate_has_only_exact_matches_in_measured_order(self):
        output = self.root/'candidate'
        def result(row, config, opener, deadline):
            return dict(row, status='PASS_EXACT_SNAPSHOT', elapsed_seconds=2 if row['id']=='one' else 1)
        with patch.dict(M['rank'].__globals__, probe=result):
            report = M['rank'](fixture(), 'a'*64, output)
        self.assertEqual(report['status'], 'PASS_CANDIDATE_WRITTEN')
        text = output.read_text()
        self.assertLess(text.index('two.example'), text.index('one.example'))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(report['activation'], 'NOT_PERFORMED')

    def test_all_failed_creates_no_candidate(self):
        output = self.root/'candidate'
        def failed(row, config, opener, deadline):
            return dict(row, status='FAIL', elapsed_seconds=1, reason='different snapshot')
        with patch.dict(M['rank'].__globals__, probe=failed):
            report = M['rank'](fixture(), 'a'*64, output)
        self.assertEqual(report['status'], 'FAIL')
        self.assertFalse(output.exists())

    def test_publication_preserves_existing_file_and_symlink(self):
        output = self.root/'existing'; output.write_bytes(b'user data')
        alias = self.root/'alias'; alias.symlink_to(output.name)
        for target in [output, alias]:
            with self.assertRaises(FileExistsError):
                M['publish'](target, b'candidate')
        self.assertEqual(output.read_bytes(), b'user data')
        self.assertTrue(alias.is_symlink())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['alias', 'existing'])



class Activation(unittest.TestCase):
    def setUp(self):
        import os
        self.os = os
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.catalog = self.root/'catalog.json'; self.catalog.write_text(json.dumps(fixture()))
        self.config, self.digest = M['catalog'](self.catalog)
        self.candidate = self.root/'candidate'
        raw = ('# Separate candidate; selected repository: core\n# Exact catalog SHA256: ' + self.digest + '\n' +
               'Server = https://two.example/$arch/$repo\nServer = https://one.example/$arch/$repo\n').encode()
        M['publish'](self.candidate, raw)
        self.target = self.root/'mirrorlist'; self.target.write_bytes(b'# existing user configuration\nServer = original\n'); self.target.chmod(0o640)
        self.before = self.target.read_bytes(); self.metadata = self.meta()
        self.state = self.root/'journal.json'

    def meta(self):
        s = self.target.stat(); return (s.st_mode, s.st_uid, s.st_gid)

    def activate(self, checkpoint=None):
        return M['activate'](self.catalog, self.candidate, self.target, self.state, 'core', checkpoint)

    def restore(self, checkpoint=None):
        return M['restore'](self.target, self.state, 'core', checkpoint)

    def journal(self):
        return json.loads(self.state.read_bytes())

    def interrupt(self, operation, phase):
        import os, signal, time
        pid = os.fork()
        if pid == 0:
            def checkpoint(name):
                if name == phase: os.kill(os.getpid(), signal.SIGKILL)
            try: operation(checkpoint)
            except BaseException: os._exit(98)
            os._exit(99)
        until = time.monotonic() + 5
        try:
            while time.monotonic() < until:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done:
                    self.assertTrue(os.WIFSIGNALED(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                    return
                time.sleep(.01)
            self.fail('private temporary-file child deadline')
        finally:
            try:
                os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
            except ProcessLookupError: pass
            except ChildProcessError: pass

    def test_real_atomic_activation_backup_metadata_and_explicit_restore(self):
        with self.target.open('rb') as original:
            inode = self.target.stat().st_ino
            result = self.activate()
            self.assertEqual(result['status'], 'PASS_ACTIVATED')
            self.assertEqual(original.read(), self.before)
            self.assertNotEqual(self.target.stat().st_ino, inode)
        self.assertEqual(self.target.read_bytes(), self.candidate.read_bytes()); self.assertEqual(self.meta(), self.metadata)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        import base64
        self.assertEqual(base64.b64decode(self.journal()['before']['data']), self.before)
        self.assertEqual(self.journal()['phase'], 'ACTIVE')
        self.restore(); self.assertEqual(self.target.read_bytes(), self.before); self.assertEqual(self.meta(), self.metadata)
        self.assertEqual(self.journal()['phase'], 'RESTORED')
        self.assertFalse(any(f.name.endswith('.tmp') for f in self.root.iterdir()))

    def test_retries_do_not_replace_backup_or_overwrite_completed_user_edits(self):
        self.activate(); first = self.journal()['before']; active_inode = self.target.stat().st_ino
        self.activate(); self.assertEqual(self.journal()['before'], first); self.assertEqual(self.target.stat().st_ino, active_inode)
        self.restore(); restored_inode = self.target.stat().st_ino
        self.restore(); self.assertEqual(self.target.stat().st_ino, restored_inode)
        self.target.write_bytes(b'user edit after restore')
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.target.read_bytes(), b'user edit after restore')
        with self.assertRaises(ValueError): self.activate()

    def test_restore_refuses_content_mode_and_replacement_conflicts(self):
        for change in ('content', 'mode', 'replacement'):
            with self.subTest(change=change):
                self.state = self.root/(change+'.json'); self.target.write_bytes(self.before); self.target.chmod(0o640)
                self.activate()
                if change == 'content': self.target.write_bytes(b'user changed active target')
                elif change == 'mode': self.target.chmod(0o644)
                else:
                    other = self.root/'new'; other.write_bytes(self.candidate.read_bytes()); other.chmod(0o640); other.replace(self.target)
                raw, meta, inode = self.target.read_bytes(), self.meta(), self.target.stat().st_ino
                with self.assertRaises(ValueError): self.restore()
                self.assertEqual((self.target.read_bytes(), self.meta(), self.target.stat().st_ino), (raw, meta, inode))
                self.assertEqual(self.journal()['phase'], 'ACTIVE')

    def test_candidate_catalog_repository_and_unknown_server_binding(self):
        original = self.candidate.read_bytes()
        for change in ('catalog', 'repository', 'server', 'duplicate', 'mode'):
            self.candidate.write_bytes(original); self.candidate.chmod(0o600)
            if change == 'catalog': self.candidate.write_bytes(original.replace(self.digest.encode(), b'a'*64))
            elif change == 'repository': self.candidate.write_bytes(original.replace(b'repository: core', b'repository: extra'))
            elif change == 'server': self.candidate.write_bytes(original.replace(b'two.example', b'bad.example'))
            elif change == 'duplicate': self.candidate.write_bytes(original+original.splitlines(keepends=True)[-1])
            else: self.candidate.chmod(0o644)
            with self.subTest(change=change), self.assertRaises(ValueError): self.activate()
            self.assertEqual(self.target.read_bytes(), self.before); self.assertFalse(self.state.exists())

    def test_symlink_hardlink_parent_and_state_alias_refused(self):
        for which in ('target', 'candidate', 'state'):
            original = getattr(self, which); alias = self.root/(which+'-alias'); alias.symlink_to(original.name)
            setattr(self, which, alias)
            with self.subTest(which=which), self.assertRaises((ValueError, OSError)): self.activate()
            setattr(self, which, original); alias.unlink()
        hard = self.root/'hard'; self.os.link(self.target, hard)
        with self.assertRaises(ValueError): self.activate()
        hard.unlink()
        alias = self.root/'parent-alias'; alias.symlink_to(self.root, target_is_directory=True)
        original = self.target; self.target = alias/original.name
        with self.assertRaises(OSError): self.activate()
        self.target = original; self.assertEqual(self.target.read_bytes(), self.before)

    def test_candidate_and_journal_hardlinks_are_refused_with_real_inodes(self):
        hard = self.root/'candidate-hard'; self.os.link(self.candidate, hard)
        with self.assertRaises(ValueError): self.activate()
        hard.unlink(); self.activate()
        hard = self.root/'journal-hard'; self.os.link(self.state, hard)
        active = self.target.read_bytes()
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.target.read_bytes(), active)
        hard.unlink(); self.restore(); self.assertEqual(self.target.read_bytes(), self.before)

    def test_restore_after_uncommitted_publish_and_pending_edit_conflict(self):
        self.interrupt(self.activate, 'activated'); self.restore()
        self.assertEqual(self.target.read_bytes(), self.before)
        self.state = self.root/'edited-prepared.json'; self.interrupt(self.activate, 'prepared')
        self.target.write_bytes(b'user changed original before publish')
        with self.assertRaises(ValueError): self.activate()
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.target.read_bytes(), b'user changed original before publish')

    def test_edit_after_restore_intent_is_refused_and_preserved(self):
        self.activate()
        def edit(phase):
            if phase == 'restoring': self.target.write_bytes(b'user edit after restore intent')
        with self.assertRaises(ValueError): self.restore(edit)
        self.assertEqual(self.target.read_bytes(), b'user edit after restore intent')
        self.assertEqual(self.journal()['phase'], 'RESTORING')

    def test_absent_target_restore_and_later_creation_conflict(self):
        self.target.unlink(); self.activate()
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600); self.assertIsNone(self.journal()['before'])
        self.restore(); self.assertFalse(self.target.exists()); self.restore()
        self.target.write_bytes(b'new user file')
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.target.read_bytes(), b'new user file')

    def test_prepared_interruption_retries_or_cancels_without_losing_original(self):
        self.interrupt(self.activate, 'prepared')
        self.assertEqual(self.journal()['phase'], 'PREPARED'); self.assertEqual(self.target.read_bytes(), self.before)
        self.activate(); self.assertEqual(self.journal()['phase'], 'ACTIVE'); self.restore()
        self.state = self.root/'cancel.json'; self.interrupt(self.activate, 'prepared'); self.restore()
        self.assertEqual(self.journal()['phase'], 'RESTORED'); self.assertEqual(self.target.read_bytes(), self.before)
        self.assertFalse(any(f.name.endswith('.tmp') for f in self.root.iterdir()))

    def test_activation_kill_after_replace_recovers_and_preserves_original_journal(self):
        self.interrupt(self.activate, 'activated')
        self.assertEqual(self.journal()['phase'], 'PREPARED'); self.assertEqual(self.target.read_bytes(), self.candidate.read_bytes())
        self.activate(); self.assertEqual(self.journal()['phase'], 'ACTIVE'); self.restore()
        self.assertEqual(self.target.read_bytes(), self.before); self.assertEqual(self.meta(), self.metadata)

    def test_restore_kill_before_and_after_replace_recovers(self):
        for phase in ('restoring', 'restored'):
            with self.subTest(phase=phase):
                self.state = self.root/(phase+'.json'); self.activate(); self.interrupt(self.restore, phase)
                self.assertEqual(self.journal()['phase'], 'RESTORING'); self.restore()
                self.assertEqual(self.target.read_bytes(), self.before); self.assertEqual(self.meta(), self.metadata)
                self.assertEqual(self.journal()['phase'], 'RESTORED')

    def test_user_edit_after_interruption_is_preserved(self):
        self.interrupt(self.activate, 'activated'); self.target.write_bytes(b'user changed pending target')
        with self.assertRaises(ValueError): self.activate()
        with self.assertRaises(ValueError): self.restore()
        self.assertEqual(self.target.read_bytes(), b'user changed pending target')

    def test_journal_corruption_foreign_metadata_and_repo_mismatch_refused(self):
        self.activate(); original = self.state.read_bytes()
        for change in ('uid', 'bytes', 'phase', 'repo', 'restore-data'):
            value = json.loads(original)
            if change == 'uid': value['before']['uid'] += 1
            elif change == 'bytes': value['before']['data'] = 'dGFtcGVy'
            elif change == 'phase': value['phase'] = 'UNKNOWN'
            elif change == 'repo': value['repository'] = 'extra'
            else: value['phase'] = 'RESTORING'; value['restored'] = None
            self.state.write_text(json.dumps(value)); current = self.target.read_bytes()
            with self.subTest(change=change), self.assertRaises(ValueError): self.restore()
            self.assertEqual(self.target.read_bytes(), current)
        self.state.write_bytes(original); self.restore()

    def test_explicit_cli_roundtrip_uses_only_real_temporary_paths(self):
        import subprocess, sys
        script = str(Path(__file__).with_name('cachy-asahi-mirrors'))
        common = ['--repository','core','--target',str(self.target),'--state',str(self.state)]
        args = [sys.executable,'-B',script,'activate',str(self.catalog),'--candidate',str(self.candidate)]+common
        row = subprocess.run(args, capture_output=True, timeout=5)
        self.assertEqual(row.returncode,0,row.stderr); self.assertEqual(json.loads(row.stdout)['status'],'PASS_ACTIVATED')
        self.assertEqual(self.target.read_bytes(),self.candidate.read_bytes())
        row = subprocess.run([sys.executable,'-B',script,'restore']+common, capture_output=True, timeout=5)
        self.assertEqual(row.returncode,0,row.stderr); self.assertEqual(json.loads(row.stdout)['status'],'PASS_RESTORED')
        self.assertEqual(self.target.read_bytes(),self.before); self.assertEqual(self.meta(),self.metadata)

    def test_bounded_backup_and_nonprivate_mutable_parent_refused(self):
        self.target.write_bytes(b'x'*65537)
        with self.assertRaises(ValueError): self.activate()
        self.assertFalse(self.state.exists())
        self.target.write_bytes(self.before); self.root.chmod(0o777)
        try:
            with self.assertRaises(ValueError): self.activate()
        finally: self.root.chmod(0o700)

    def test_target_lock_serializes_different_journals_without_target_changes(self):
        import fcntl, os
        path = self.target.with_name(self.target.name+'.caa-lock')
        handle = os.open(path, os.O_RDWR|os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.activate()
            self.assertEqual(self.target.read_bytes(), self.before); self.assertFalse(self.state.exists())
        finally: os.close(handle)


if __name__ == '__main__':
    unittest.main()
