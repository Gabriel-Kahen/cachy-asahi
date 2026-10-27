#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unmodified mirror CLI, owned loopback TLS fixture and real SIGKILL recovery.

All mutable inputs, raw transcripts, journals and original bytes stay in --work.
The JSON report contains fixture hashes/observations only. No public mirror trust,
network ranking performance, host configuration, physical-M2 or power-loss claim.
"""
import argparse
import ast
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time

BODY = b'locally controlled snapshot; not a public repository\n'
ORIGINAL = b'# original user mirrorlist\n\x00\xff\r\nServer = preserve-exactly\n'
EDIT = b'# user edit must survive\n\x00\xfe\r\n'
TRACE = '''import json,os,runpy,signal,sys
cli,phase,function,line,marker,*args=sys.argv[1:]
line=int(line)
def trace(frame,event,arg):
 if event=='line' and frame.f_code.co_filename==cli and frame.f_code.co_name==function and frame.f_lineno==line:
  if function!='install_pending' or bool(frame.f_locals.get('restoring'))==(phase=='restored'):
   with open(marker,'x') as out:
    json.dump(dict(phase=phase,function=function,line=line,pid=os.getpid()),out);out.flush();os.fsync(out.fileno())
   os.kill(os.getpid(),signal.SIGSTOP)
 return trace
sys.argv=[cli,*args];sys.settrace(trace);runpy.run_path(cli,run_name='__main__')
'''


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def entry(path):
    if not path.exists():
        return None
    info = path.stat()
    return dict(sha256=sha(path.read_bytes()), bytes=info.st_size,
                mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
                inode=info.st_ino, mtime_ns=info.st_mtime_ns)


def metadata(path):
    row = entry(path)
    return {key: row[key] for key in ('mode', 'uid', 'gid')} if row else None


def pause_point(cli, phase):
    """AST-bound line events after fsync, before the next state transition."""
    tree = ast.parse(cli.read_bytes())
    function = 'activate' if phase == 'prepared' else 'restore' if phase == 'restoring' else 'install_pending'
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function]
    need(len(selected) == 1, 'expected transaction function missing')
    if phase in ('prepared', 'restoring'):
        points = [node for node in ast.walk(selected[0]) if isinstance(node, ast.If)
                  and isinstance(node.test, ast.Name) and node.test.id == 'checkpoint'
                  and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                          and call.func.id == 'checkpoint' and call.args
                          and isinstance(call.args[0], ast.Constant) and call.args[0].value == phase
                          for call in ast.walk(node))]
    else:
        points = [node for node in ast.walk(selected[0]) if isinstance(node, ast.Expr)
                  and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                  and node.value.func.id == 'checkpoint' and node.value.args
                  and isinstance(node.value.args[0], ast.IfExp)]
    need(len(points) == 1, 'durable transaction trace point missing or ambiguous')
    return function, points[0].lineno


class Driver:
    def __init__(self, cli, work):
        self.cli, self.work = cli, work
        self.events, self.commands = [], []
        self.transcripts = work/'transcripts'
        self.transcripts.mkdir(mode=0o700)
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def command(self, args, expected=0, env=None):
        command = [str(self.cli), *map(str, args)]
        row = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=20, env=env or self.env)
        self.record(command, row.returncode, row.stdout, row.stderr)
        need(row.returncode == expected, 'CLI exit differs: '+str(args[0]))
        result = json.loads(row.stdout)
        need(result['status'].startswith('PASS_') == (expected == 0), 'CLI status differs')
        return result

    def record(self, command, code, stdout, stderr):
        index = len(self.commands)
        prefix = self.transcripts/('%03d' % index)
        prefix.with_suffix('.stdout').write_bytes(stdout)
        prefix.with_suffix('.stderr').write_bytes(stderr)
        prefix.with_suffix('.command.json').write_text(json.dumps(command)+'\n')
        self.commands.append(dict(index=index, exit=code, command_sha256=sha((json.dumps(command)+'\n').encode()),
                                  stdout_sha256=sha(stdout), stderr_sha256=sha(stderr)))

    def args(self, case, verb):
        common = ['--repository', 'core', '--target', str(case/'mirrorlist'), '--state', str(case/'journal.json')]
        return [verb, str(self.work/'catalog.json'), '--candidate', str(self.work/'candidate'), *common] if verb == 'activate' else [verb, *common]

    def case(self, name, absent=False):
        case = self.work/name
        case.mkdir(mode=0o700)
        (case/'original.bytes').write_bytes(ORIGINAL)
        if not absent:
            (case/'mirrorlist').write_bytes(ORIGINAL)
            (case/'mirrorlist').chmod(0o640)
        return case

    def journal(self, case):
        row = json.loads((case/'journal.json').read_bytes())
        before = row['before']
        if before is not None:
            need(base64.b64decode(before['data']) == ORIGINAL, 'journal lost original user bytes')
        need(stat.S_IMODE((case/'journal.json').stat().st_mode) == 0o600, 'journal is not private')
        return row

    def restored(self, case, prior_meta, absent=False):
        target = case/'mirrorlist'
        need(not target.exists() if absent else target.read_bytes() == ORIGINAL, 'restore lost original bytes/absence')
        need(metadata(target) == prior_meta, 'restore changed POSIX ownership/mode')
        need(self.journal(case)['phase'] == 'RESTORED', 'restore phase differs')
        need(not list(case.glob('.caa-mirrors-*.tmp')), 'referenced temporary remained after completed restore')

    def interrupted(self, case, phase, verb):
        function, line = pause_point(self.cli, phase)
        marker = case/(phase+'.stopped.json')
        command = [sys.executable, '-I', '-B', '-c', TRACE, str(self.cli), phase, function,
                   str(line), str(marker), *self.args(case, verb)]
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env)
        recorded = False
        try:
            until = time.monotonic()+8
            stopped = False
            while time.monotonic() < until:
                if child.poll() is not None:
                    break
                status = Path('/proc')/str(child.pid)/'status'
                if marker.exists() and status.exists():
                    states = [row for row in status.read_text().splitlines() if row.startswith('State:')]
                    if states and states[0].split()[1] in ('T', 't'):
                        stopped = True
                        break
                time.sleep(.005)
            need(stopped, 'real CLI did not stop at durable boundary '+phase)
            observed = self.journal(case)
            expected = 'PREPARED' if phase in ('prepared', 'activated') else 'RESTORING'
            need(observed['phase'] == expected, 'interrupted journal phase differs')
            target = case/'mirrorlist'
            desired = ORIGINAL if phase in ('prepared', 'restored') else (self.work/'candidate').read_bytes()
            need(target.read_bytes() == desired, 'interrupted target bytes differ')
            (case/('journal.'+phase+'.json')).write_bytes((case/'journal.json').read_bytes())
            child.kill()
            stdout, stderr = child.communicate(timeout=3)
            self.record(command, child.returncode, stdout, stderr)
            recorded = True
            need(child.returncode == -signal.SIGKILL, 'child was not killed by SIGKILL')
            return dict(phase=phase, journal_phase=expected, signal='SIGKILL',
                        method='unmodified CLI main under sys.settrace; SIGSTOP observed, parent SIGKILL',
                        function=function, line=line, target_sha256=sha(desired),
                        journal_sha256=sha((case/('journal.'+phase+'.json')).read_bytes()))
        finally:
            if child.poll() is None:
                child.kill()
            if not recorded:
                stdout, stderr = child.communicate(timeout=3)
                self.record(command, child.returncode, stdout, stderr)

    def lifecycle(self):
        for absent in (False, True):
            case = self.case('absent' if absent else 'roundtrip', absent)
            target = case/'mirrorlist'; prior_meta = metadata(target)
            self.command(self.args(case, 'activate'))
            need(target.read_bytes() == (self.work/'candidate').read_bytes(), 'active bytes differ')
            active, journal = entry(target), (case/'journal.json').read_bytes()
            self.command(self.args(case, 'activate'))
            need(entry(target) == active and (case/'journal.json').read_bytes() == journal, 'activation retry changed state')
            self.command(self.args(case, 'restore')); self.restored(case, prior_meta, absent)
            restored = entry(target)
            self.command(self.args(case, 'restore'))
            need(entry(target) == restored, 'restore retry changed state')
            self.events.append(dict(case=case.name, prior_bytes_restored=True, metadata_restored=True, retries_preserved=True))
        case = self.case('active-user-edit')
        self.command(self.args(case, 'activate'))
        target = case/'mirrorlist'; target.write_bytes(EDIT)
        unchanged = entry(target)
        for verb in ('restore', 'activate'):
            self.command(self.args(case, verb), 1)
            need(entry(target) == unchanged and self.journal(case)['phase'] == 'ACTIVE', 'user edit overwritten')
        self.events.append(dict(case=case.name, refusal_preserves_edit=True, edit_sha256=sha(EDIT)))
        for phase, action in (('prepared', 'activate'), ('prepared', 'restore'), ('activated', 'activate'),
                              ('activated', 'restore'), ('restoring', 'restore'), ('restored', 'restore')):
            case = self.case(phase+'-'+action)
            prior_meta = metadata(case/'mirrorlist')
            if phase in ('restoring', 'restored'):
                self.command(self.args(case, 'activate'))
            event = self.interrupted(case, phase, 'restore' if phase in ('restoring', 'restored') else 'activate')
            self.command(self.args(case, action))
            if action == 'activate':
                self.command(self.args(case, 'restore'))
            self.restored(case, prior_meta)
            event.update(case=case.name, recovery=action, original_bytes_restored=True, metadata_restored=True)
            self.events.append(event)
        for phase in ('prepared', 'activated', 'restoring'):
            case = self.case(phase+'-user-edit')
            if phase == 'restoring':
                self.command(self.args(case, 'activate'))
            event = self.interrupted(case, phase, 'restore' if phase == 'restoring' else 'activate')
            target = case/'mirrorlist'; target.write_bytes(EDIT); unchanged = entry(target)
            for verb in ('activate', 'restore'):
                self.command(self.args(case, verb), 1)
                need(entry(target) == unchanged, 'pending transaction overwrote user edit')
            self.journal(case)
            event.update(case=case.name, refusal_preserves_edit=True, edit_sha256=sha(EDIT))
            self.events.append(event)

    def tls(self):
        cert, key = self.work/'fixture-cert.pem', self.work/'fixture-key.pem'
        command = ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                   '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                   '-addext', 'basicConstraints=critical,CA:TRUE',
                   '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
                   '-keyout', str(key), '-out', str(cert)]
        row = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        self.record(command, row.returncode, row.stdout, row.stderr)
        need(row.returncode == 0, 'private loopback TLS certificate creation failed')
        key.chmod(0o600)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                data = BODY if self.path == '/good/aarch64/core/core.db' else b'X'*len(BODY)
                self.send_response(200); self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data)
        server = HTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        env = dict(self.env, SSL_CERT_FILE=str(cert))
        catalog = dict(schema_version=1, architecture='aarch64', base='asahi-alarm', repository='core',
                       database=dict(bytes=len(BODY), sha256=sha(BODY)),
                       mirrors=[dict(id=kind, server='https://localhost:'+str(server.server_port)+'/'+kind+'/$arch/$repo')
                                for kind in ('good', 'bad')])
        path = self.work/'catalog.json'; path.write_text(json.dumps(catalog)+'\n')
        try:
            checked = self.command(['check', path])
            need(checked['network'] == 'NOT_USED', 'check accessed network')
            ranked = self.command(['rank', path, '--output', self.work/'candidate'], env=env)
            need([row['status'] for row in ranked['results']] == ['PASS_EXACT_SNAPSHOT', 'FAIL'], 'exact/mismatched snapshot differs')
            candidate = self.work/'candidate'; raw = candidate.read_bytes()
            need(stat.S_IMODE(candidate.stat().st_mode) == 0o600 and b'/good/' in raw and b'/bad/' not in raw, 'candidate differs')
            need(ranked['activation'] == 'NOT_PERFORMED' and ranked['candidate']['sha256'] == sha(raw), 'rank publication receipt differs')
            self.command(['rank', path, '--output', candidate], 1, env)
            need(candidate.read_bytes() == raw, 'rank overwrote candidate')
            failed = dict(catalog, mirrors=catalog['mirrors'][1:])
            failed_path = self.work/'all-failed-catalog.json'; failed_path.write_text(json.dumps(failed)+'\n')
            self.command(['rank', failed_path, '--output', self.work/'all-failed-output'], 1, env)
            need(not (self.work/'all-failed-output').exists(), 'failed rank published output')
            self.events.append(dict(case='loopback-TLS', exact_and_mismatched_snapshot=True,
                                    existing_candidate_preserved=True, all_failed_no_output=True,
                                    snapshot_sha256=sha(BODY), catalog_sha256=sha(path.read_bytes()), candidate_sha256=sha(raw)))
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=3)
            key.unlink(missing_ok=True)
            need(not worker.is_alive(), 'loopback HTTPS worker remained')


def run(cli, work):
    need(cli.is_absolute() and cli.is_file() and not cli.is_symlink() and os.access(cli, os.X_OK), 'absolute regular CLI required')
    need(work.is_absolute() and work.is_dir() and not work.is_symlink() and not list(work.iterdir()), 'empty absolute private workspace required')
    info = work.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'workspace must be owned mode0700')
    os.umask(0o077)
    driver = Driver(cli, work)
    result = dict(status='FAIL', cli_sha256=sha(cli.read_bytes()), architecture=os.uname().machine,
                  page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.geteuid(),
                  fixture='EXPLICIT_LOCAL_CONTROLLED_SNAPSHOT_ONLY', public_mirror_trust='NOT_ESTABLISHED',
                  ranking_performance='NOT_MEASURED', host_configuration='NOT_TOUCHED',
                  physical_M2='NOT_RUN', power_loss='NOT_RUN', release='NOT_ADMITTED')
    try:
        driver.tls(); driver.lifecycle()
        result.update(status='PASS_LOCAL_MIRROR_LIFECYCLE', real_cli=True, interrupted_recovery=True, original_bytes_preserved=True)
    except Exception as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        (work/'fixture-key.pem').unlink(missing_ok=True)
    result.update(events=driver.events, commands=driver.commands, private_TLS_key_removed=not (work/'fixture-key.pem').exists(),
                  private_inputs='work retains catalogs, candidates, exact originals, journals and raw transcripts; export only this report',
                  cleanup='only generated fixture-key.pem removed; server closed; owned children killed/reaped')
    (work/'private-receipt.json').write_text(json.dumps(result, sort_keys=True)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    result = run(args.cli, args.work)
    raw = json.dumps(result, sort_keys=True)+'\n'
    if args.report:
        need(args.report.is_absolute() and not args.report.exists() and not args.report.is_symlink(), 'fresh absolute report path required')
        args.report.write_text(raw)
    print(raw, end='')
    return 0 if result['status'].startswith('PASS_') else 1


if __name__ == '__main__':
    raise SystemExit(main())
