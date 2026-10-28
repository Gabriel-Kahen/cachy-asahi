#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline installed/moved package CLI controls; caller owns ALPM and network isolation."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
FIXTURE_SHA256 = 'c9ba4819a815b7c10d9e96c4afce1190d1097dc24ecf93f415a9d623a0b7cde5'
SNAPSHOT_SHA256 = '3dd395daaf0cab61b24616697ae59b5bcde28853f913bceb87af1c5d0cc42d76'
PRIVATE = 'usr/lib/cachy-asahi/security-maintenance-v2'
PUBLIC = 'usr/bin/cachy-asahi-security-maintenance'
INTERRUPT = '''import os, runpy, sys
launcher, *args = sys.argv[1:]
def interrupt(event, values):
    if event == "os.link" and str(values[1]).endswith("/events/000002.json"):
        raise OSError("ORIGINAL TEST fault before second event publication")
sys.addaudithook(interrupt)
sys.argv = [launcher] + args
runpy.run_path(launcher, run_name="__main__")
'''


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def describe(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode), 'ordinary file required: ' + str(path))
    body = path.read_bytes()
    return dict(bytes=len(body), sha256=digest(body), mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid)


def inventory(root):
    root = Path(root)
    need(root.is_dir() and root == root.resolve(), 'ordinary directory required')
    rows = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat(); key = str(path.relative_to(root))
        if stat.S_ISREG(info.st_mode):
            rows[key] = describe(path)
        elif stat.S_ISDIR(info.st_mode):
            rows[key] = dict(directory=True, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        else:
            raise ValueError('private evidence tree contains special entry: ' + key)
    return rows


def package_inventory(prefix):
    listing = prefix / 'usr/share/doc/cachy-asahi-security-maintenance/installed-files.txt'
    rows = {}
    for line in listing.read_text().splitlines():
        mode, relative = line.split()
        need(relative.startswith('/usr/') and '..' not in Path(relative).parts, 'package path')
        path = prefix / relative.lstrip('/')
        need(path == path.resolve(), 'package alias')
        rows[relative] = describe(path)
        need(rows[relative]['mode'] == int(mode, 8), 'package mode')
    need(len(rows) == 29, 'exact 29-file current package required')
    return rows


class Workflow:
    def __init__(self, prefix, fixture, snapshot, snapshot_sha256, output, home):
        self.prefix, self.output = prefix.resolve(), output.absolute()
        self.launcher = self.prefix / PUBLIC; self.runtime = self.prefix / PRIVATE
        need(fixture.is_file() and digest(fixture.read_bytes()) == FIXTURE_SHA256, 'retained fixture pin differs')
        need(snapshot_sha256 == SNAPSHOT_SHA256 and digest((snapshot / 'snapshot.json').read_bytes()) == SNAPSHOT_SHA256,
             'retained snapshot pin differs')
        need(not self.output.exists() and self.output.parent.is_dir(), 'fresh output beneath existing parent required')
        need(home == home.resolve() and home.is_dir(), 'existing private test home required')
        need(not self.output.is_relative_to(home) and not home.is_relative_to(self.output), 'output must be disjoint from private home')
        self.home, self.snapshot = home, snapshot.resolve()
        self.before = dict(package=package_inventory(self.prefix), snapshot=inventory(self.snapshot), home=inventory(home))
        self.output.mkdir(mode=0o700)
        self.logs = self.output / 'commands'; self.logs.mkdir(mode=0o700)
        self.commands, self.controls = [], []
        self.env = dict(os.environ, HOME=str(home), PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
        self.env.pop('PYTHONHOME', None); self.env.pop('PYTHONPATH', None)
        spec = importlib.util.spec_from_file_location('native_retained_security_fixture', fixture)
        self.fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.fixture)
        self.fixture.bind(self.runtime)

    def call(self, label, arguments, expected=0, helper=False, interrupt=False):
        command = ([sys.executable, '-I', '-B', str(self.runtime / 'scripts/maintenance/source_cache.py')]
                   if helper else [str(self.launcher)]) + list(map(str, arguments))
        if interrupt:
            command = [sys.executable, '-I', '-B', '-c', INTERRUPT, *command]
        result = subprocess.run(command, env=self.env, cwd=self.output, capture_output=True, timeout=90)
        self.commands.append(dict(label=label, argv=command, returncode=result.returncode,
                                  stdout_sha256=digest(result.stdout), stderr_sha256=digest(result.stderr)))
        for name, body in (('stdout', result.stdout), ('stderr', result.stderr)):
            (self.logs / (label + '.' + name)).write_bytes(body)
        need(result.returncode == expected, label + ': unexpected exit: ' + result.stderr.decode(errors='replace')[:1500])
        need(b'Traceback' not in result.stderr, label + ': traceback')
        return json.loads(result.stdout) if expected == 0 and result.stdout.lstrip().startswith(b'{') else result

    def operation(self, name):
        root = self.output / name; root.mkdir(mode=0o700)
        return self.fixture.Fixture(root)

    def selected(self, f, action, selection=None, checksum=None, retry=False):
        args = [action, '--operation', f.store.path]
        if selection:
            args += ['--selection', selection, '--selection-sha256', checksum or digest(selection.read_bytes())]
        if retry:
            args.append('--retry')
        return args

    def run(self):
        self.call('version', ['--version']); self.call('help', ['--help'])
        verify = ['verify-advisories', '--snapshot', self.snapshot, '--snapshot-sha256', SNAPSHOT_SHA256]
        result = self.call('retained-advisory-verify', [*verify, '--as-of', '2026-10-28T01:42:00Z'])
        need(result['status'] == 'VERIFIED_RETAINED_DATA_OFFLINE' and result['arm_security_status'] == 'UNKNOWN', 'retained verify result')
        stale = self.call('stale-advisory-verify', [*verify, '--as-of', '2026-10-30T01:42:00Z'])
        need(stale['cache']['cache_stale'] and stale['arm_security_status'] == 'UNKNOWN', 'stale security interpretation')
        self.call('advisory-pin-refusal', ['verify-advisories', '--snapshot', self.snapshot,
                  '--snapshot-sha256', '0' * 64], expected=2)
        tampered = self.output / 'tampered-snapshot'; shutil.copytree(self.snapshot, tampered)
        body = tampered / 'advisories.json'; original = body.read_bytes(); body.write_bytes(original + b'\n')
        self.call('advisory-tamper-refusal', ['verify-advisories', '--snapshot', tampered,
                  '--snapshot-sha256', SNAPSHOT_SHA256], expected=2)
        need(body.read_bytes() == original + b'\n', 'verification rewrote corrupt advisory data')
        body.write_bytes(original)
        self.call('advisory-explicit-byte-restore', ['verify-advisories', '--snapshot', tampered,
                  '--snapshot-sha256', SNAPSHOT_SHA256, '--as-of', '2026-10-28T01:42:00Z'])
        self.controls += ['retained-offline-verify', 'stale-remains-unknown', 'bad-snapshot-pin-refused',
                          'tampered-advisory-refused-and-retained', 'operator-byte-restore']
        f = self.operation('ordinary-operation')
        seed = {name: describe(f.root / name) for name in ('inventory.json', 'advisories.json', 'provenance.json', 'graph.json', 'candidate_graph.json')}
        self.call('selection-pin-refusal', self.selected(f, 'prepare', f.selected, '0' * 64), expected=2)
        need(not f.store.path.exists(), 'bad selected hash created operation')
        prepared = self.call('prepare', self.selected(f, 'prepare', f.selected))
        need(prepared['required_packages'] == ['app', 'middle', 'seed'], 'fixture campaign coverage')
        status = self.call('status', self.selected(f, 'status'))
        need(status['security_status'] == 'UNKNOWN_PLANNING_IS_NOT_REMEDIATION', 'planning promoted remediation')
        self.call('repeat-prepare-refused', self.selected(f, 'prepare', f.selected), expected=2)
        source_args = ['verify', '--cache', f.cache, '--inputs', f.catalog,
                       '--inputs-sha256', digest(f.catalog.read_bytes()), '--id', 'original-fixture']
        cache_before = inventory(f.cache)
        cache_result = self.call('source-cache-verify', source_args, helper=True)
        need(cache_result['sources'][0]['status'] == 'verified', 'offline source not verified')
        original = f.object.read_bytes(); f.object.write_bytes(original + b'\n')
        self.call('source-cache-tamper-refused', source_args, expected=1, helper=True)
        need(f.object.read_bytes() == original + b'\n', 'verifier overwrote corrupt source')
        f.object.write_bytes(original); self.call('source-cache-restored', source_args, helper=True)
        need(inventory(f.cache) == cache_before, 'source cache changed')
        self.controls += ['selected-hash-refused-before-operation', 'prepare-exact-impact', 'status-remains-unknown',
                          'repeat-prepare-refused', 'packaged-source-cache-verify', 'cache-tamper-retained-and-restored']
        self.call('batch-plan-bad-pin', self.selected(f, 'plan-builds', f.batch_selected, '0' * 64), expected=2)
        failed = self.call('failed-planning-status', self.selected(f, 'status'))
        need(failed['phases']['batch_planning'] == 'FAILED', 'failed planning state missing')
        self.call('batch-plan-retry-required', self.selected(f, 'plan-builds', f.batch_selected), expected=2)
        planned = self.call('batch-plan-retry', self.selected(f, 'plan-builds', f.batch_selected, retry=True))
        rows = planned['commands']['batches']
        need(len(rows) == 2 and planned['batch_planning_attempts'] == 2, 'exact pair/retry result')
        for row in rows:
            need(row['execution'] == 'NOT_RUN' and str(self.runtime) in row['plan_command'][2], 'batch execution/runtime binding')
            need(not Path(row['output']).exists(), 'planning executed a batch')
        self.call('batch-help-only', ['batch', '--help'])
        need(seed == {name: describe(f.root / name) for name in seed}, 'fixture inputs changed')
        self.controls += ['batch-plan-failure-recorded', 'planning-requires-explicit-retry', 'planning-retry-exact-pair-not-executed']
        interrupted = self.operation('interrupted-prepare')
        self.call('prepare-second-event-fault', self.selected(interrupted, 'prepare', interrupted.selected), expected=2, interrupt=True)
        events = list((interrupted.store.path / 'events').glob('*.json'))
        need(len(events) == 1 and events[0].name == '000001.json', 'first committed event retention')
        event_before = events[0].read_bytes()
        self.call('interrupted-status-refusal', self.selected(interrupted, 'status'), expected=2)
        restored = self.call('interrupted-prepare-retry', self.selected(interrupted, 'prepare', interrupted.selected, retry=True))
        need(restored['security_status'] == 'UNKNOWN_PLANNING_IS_NOT_REMEDIATION' and events[0].read_bytes() == event_before,
             'recovery changed first event/security boundary')
        self.call('recovered-status', self.selected(interrupted, 'status'))
        self.controls += ['prepublication-fault-first-event-retained', 'incomplete-status-refused', 'original-selection-recovery']
        after = dict(package=package_inventory(self.prefix), snapshot=inventory(self.snapshot), home=inventory(self.home))
        need(after == self.before, 'package, original snapshot or private home changed')
        receipt = dict(schema_version=1, status='PASS_OFFLINE_SECURITY_WORKFLOWS', prefix=str(self.prefix), launcher=str(self.launcher),
                       direct_launcher=True, source_cache_interface='PACKAGED_PRIVATE_HELPER',
                       fault_scope='Original TEST exception before second event publication; not power-loss/hardware recovery',
                       controls=self.controls, commands=self.commands, preserved_before=self.before, preserved_after=after,
                       remediation='NOT_ESTABLISHED', arm_security='UNKNOWN', batch_execution='NOT_RUN',
                       network_path='NOT_RUN; caller must provide kernel isolation', alpm_lifecycle='CALLER_OWNED')
        (self.output / 'workflow-result.json').write_bytes(encoded(receipt))
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True, help='/ for installed /usr, or moved private prefix')
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--home', type=Path, default=Path(os.environ.get('HOME', '/nonexistent')))
    args = parser.parse_args()
    result = Workflow(args.prefix, args.fixture, args.snapshot, args.snapshot_sha256, args.output, args.home).run()
    print(json.dumps(dict(status=result['status'], controls=len(result['controls']), commands=len(result['commands']))))


if __name__ == '__main__':
    main()
