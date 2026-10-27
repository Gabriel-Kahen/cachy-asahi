#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise delivered CLIs in explicit private fixtures; never install a package."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import tempfile

ENGINE_SHA = '1368a1fa0586d946f33945b0be7e5c1deb4fe929509e34a81d55cfb9f5cb800b'
PROFILES = ('fresh', 'existing', 'conflict', 'interrupted')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def load(path):
    loader = SourceFileLoader('_delivered_setup8_fixture', str(path))
    module = module_from_spec(spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def snapshot(root):
    result = {}
    for path in (root, *sorted(root.rglob('*'))):
        item = path.lstat()
        need(not path.is_symlink() and (path.is_file() or path.is_dir()), 'ordinary private fixture tree required')
        result[str(path.relative_to(root))] = dict(mode=stat.S_IMODE(item.st_mode), uid=item.st_uid,
            gid=item.st_gid, inode=item.st_ino, links=item.st_nlink, size=item.st_size,
            mtime_ns=item.st_mtime_ns, ctime_ns=item.st_ctime_ns,
            sha256=sha(path.read_bytes()) if path.is_file() else None,
            xattrs={key: sha(os.getxattr(path, key)) for key in os.listxattr(path)})
    return result


class Delivery:
    def __init__(self, root, work):
        self.root, self.work = Path(root), Path(work)
        need(self.root.is_absolute() and self.work.is_absolute(), 'explicit absolute delivery/fixture roots required')
        self.setup_cli = self.root / 'usr/bin/cachy-asahi-setup'
        self.cli = self.root / 'usr/bin/cachy-asahi-config-migrate'
        self.private = self.root / 'usr/lib/cachy-asahi/setup8'
        need(all(p.is_file() and not p.is_symlink() for p in (self.setup_cli, self.cli,
             self.private / 'setup.py', self.private / 'config_migrate.py')), 'complete delivered setup8 layout required')
        need(self.setup_cli.read_bytes() == (self.private / 'setup.py').read_bytes(), 'CLI/private setup contract differs')
        need(sha((self.private / 'config_migrate.py').read_bytes()) == ENGINE_SHA, 'original migration engine pin differs')
        self.module = load(self.private / 'setup.py')
        self.old, self.new = self.work / 'old-1.0-1', self.work / 'new-2.0-1'
        self.manifest_path = self.work / 'migration.json'
        self.cases = {}
        self.cli_observations = []

    def invoke(self, executable, operation, home, extra=(), expected=0):
        env = dict(PATH='/usr/bin:/bin', HOME=str(home), LANG='C.UTF-8', LC_ALL='C.UTF-8',
                   XDG_CONFIG_HOME='/must-not-be-used', XDG_STATE_HOME='/must-not-be-used', ZDOTDIR='/must-not-be-used')
        argv = [sys.executable, '-I', '-B', str(executable), operation, '--home', str(home), *map(str, extra)]
        result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
        need(result.returncode == expected, 'delivered CLI result differs: ' + operation + ': ' + result.stderr[:1024])
        need('PRIVATE_FIXTURE_CANARY' not in result.stdout + result.stderr, 'configuration contents leaked')
        value = json.loads(result.stdout if expected != 1 else result.stderr)
        self.cli_observations.append(dict(executable=executable.name, operation=operation, profile=home.name, exit_code=result.returncode, status=value.get('status'), mode=value.get('mode')))
        return value

    def setup(self, operation, home, extra=(), expected=0, new=False):
        return self.invoke(self.setup_cli, operation, home, ('--template-root', self.new if new else self.old, *extra), expected)

    def migrate(self, operation, home, expected=0):
        return self.invoke(self.cli, operation, home,
                           ('--manifest', self.manifest_path, '--sha256', sha(self.manifest_path.read_bytes())), expected)

    def initialize(self):
        need(not self.work.exists() and self.work.parent.is_dir(), 'fresh caller-selected fixture directory required')
        self.work.mkdir(mode=0o700)
        for root, version in ((self.old, 'old'), (self.new, 'new')):
            root.mkdir(mode=0o700)
            for name, relative in self.module.TEMPLATES.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_text('# inert fixture ' + name + ' ' + version + '\n')
                path.chmod(0o600)
        manifest = dict(schema_version=1, id='setup8-explicit-fixture-1-to-2', package='cachy-asahi-fixture-config',
                        from_version='1.0-1', to_version='2.0-1', entries=[])
        for name in self.module.ALL_COMPONENTS:
            manifest['entries'].append(dict(component=name,
                old=dict(root=str(self.old), sha256=sha((self.old / self.module.TEMPLATES[name]).read_bytes())),
                new=dict(root=str(self.new), sha256=sha((self.new / self.module.TEMPLATES[name]).read_bytes()))))
        self.manifest_path.write_bytes(encode(manifest));self.manifest_path.chmod(0o600)
        for profile in PROFILES:
            home = self.work / profile;home.mkdir(mode=0o700)
            if profile != 'fresh':
                for relative, raw in (('.config/fish/config.fish', b'# PRIVATE_FIXTURE_CANARY fish\n'),
                                      ('.zshrc', b'# PRIVATE_FIXTURE_CANARY zsh without newline')):
                    path = home / relative;path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path.write_bytes(raw);path.chmod(0o640)
            self.setup('activate', home, ('--components', *self.module.ALL_COMPONENTS, '--apply'))
            owner = self.module.Setup(home, self.old)
            try:
                need(all((home / owner.targets[c]).is_file() for c in self.module.ALL_COMPONENTS),
                     'old fixture activation missing target')
            finally:owner.close()
        self.cases['fresh-existing-old-activation'] = 'PASS'

    def crash(self, home):
        code = '''import os,signal,sys
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
import config_migrate as m
e=m.Migration(sys.argv[2],sys.argv[3],sys.argv[4]);original=e.fs.atomic
def atomic(path,data,expected,private=False):
 original(path,data,expected,private)
 if path==e.setup.targets['fish']:os.kill(os.getpid(),signal.SIGKILL)
e.fs.atomic=atomic
e.run('apply')
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(self.private), str(home),
                                 str(self.manifest_path), sha(self.manifest_path.read_bytes())],
                                capture_output=True, text=True, timeout=15)
        need(result.returncode == -signal.SIGKILL, 'genuine installed-engine SIGKILL checkpoint missing')
        need((home / '.local/state/cachy-asahi/setup/journal.json').is_file(), 'durable migration intent absent')
        return result.returncode

    def controls(self):
        self.initialize()
        for profile in PROFILES:
            home = self.work / profile
            before = snapshot(home)
            need(self.migrate('preview', home)['status'] == 'ready', 'migration preview not ready')
            need(self.migrate('status', home)['status'] == 'ready', 'migration status not ready')
            need(snapshot(home) == before, 'preview/status mutated private home')
            self.cases['preview-status-readonly-fresh-existing'] = 'PASS'
            if profile == 'conflict':
                path = home / '.zshrc';raw = path.read_bytes();path.write_bytes(raw.replace(b'source ', b'# edited source ', 1))
                conflict = snapshot(home)
                self.migrate('apply', home, 1)
                need(snapshot(home) == conflict, 'managed conflict changed another target or metadata')
                path.write_bytes(raw)
                self.cases['managed-conflict-preserves-all-targets'] = 'PASS'
            if profile == 'interrupted':
                killed = self.crash(home)
                pending = snapshot(home)
                setup_status = self.setup('status', home, expected=2)
                need(setup_status['pending']['status'] == 'migration-owned'
                     and setup_status['pending']['can_resume'] is None
                     and setup_status['pending']['validated_by_setup'] is False
                     and setup_status['pending']['manifest_sha256'] == sha(self.manifest_path.read_bytes())
                     and any('cachy-asahi-config-migrate' in text for text in setup_status['guidance']),
                     'migration-owned status/guidance absent')
                need(snapshot(home) == pending, 'setup pending status mutated journal/home')
                need(self.migrate('status', home, 2)['status'] == 'pending', 'installed migration status lacks pending intent')
                self.setup('recover', home, ('--apply',), expected=1)
                self.migrate('apply', home, 1)
                need(snapshot(home) == pending, 'wrong recovery path changed pending work')
                path = home / '.zshrc';raw = path.read_bytes();path.write_bytes(raw + b'\n# PRIVATE_FIXTURE_CANARY interrupted edit\n')
                conflict = snapshot(home);self.migrate('recover', home, 1)
                need(snapshot(home) == conflict, 'interrupted user edit was overwritten')
                path.write_bytes(raw)
                need(self.migrate('recover', home)['status'] == 'recovered', 'installed migration recovery failed')
                self.cases['real-sigkill-installed-engine'] = 'PASS'
                self.cases['migration-owned-setup-status-guidance'] = 'PASS'
                self.cases['wrong-recovery-and-interrupted-edits-refuse'] = 'PASS'
                self.child_returncode = killed
            else:
                need(self.migrate('apply', home)['status'] == 'applied', 'installed migration apply failed')
            state = self.module.Setup(home, self.new)
            try:
                for name in ('fish', 'zsh'):
                    path = home / state.targets[name]
                    with path.open('ab') as stream:stream.write(b'# PRIVATE_FIXTURE_CANARY outside managed blocks\n')
                    os.setxattr(path, 'user.setup8-fixture', b'preserved')
                before = snapshot(home)
                need(self.migrate('apply', home)['status'] == 'already-applied', 'repeat changed config version')
                need(self.migrate('status', home)['status'] == 'already-applied', 'completed status differs')
                need(snapshot(home) == before, 'completed repeat/status changed bytes or metadata')
                self.cases['installed-apply-repeat-status'] = 'PASS'
                report = self.setup('status', home, new=True)
                need(all(a['status'] == 'clean' for a in report['actions']), 'held status no longer recognizes clean ownership')
                self.cases['held-setup-status-clean'] = 'PASS'
                ledger = home / '.local/state/cachy-asahi/setup/migrations.json';old_ledger = ledger.read_bytes()
                self.setup('remove', home, ('--apply',), new=True)
                need(ledger.read_bytes() == old_ledger, 'setup removal erased migration version history')
                self.cases['setup-remove-retains-ledger'] = 'PASS'
                for name in ('fish', 'zsh'):
                    path = home / state.targets[name]
                    need(b'outside managed blocks' in path.read_bytes() and os.getxattr(path, 'user.setup8-fixture') == b'preserved',
                         'setup removal changed outside bytes or xattrs')
                self.cases['outside-user-bytes-modes-xattrs-preserved'] = 'PASS'
                before = snapshot(home);self.migrate('apply', home, 1)
                need(snapshot(home) == before, 'migration inferred activation after removal')
                self.cases['removed-components-not-auto-adopted'] = 'PASS'
                self.setup('activate', home, ('--components', *self.module.ALL_COMPONENTS, '--apply'), new=True)
                need(self.migrate('apply', home)['status'] == 'already-applied', 'reactivation of exact new version not idempotent')
                self.cases['exact-new-version-reactivation'] = 'PASS'
            finally:state.close()
        expected = {p:snapshot(self.work / p) for p in PROFILES}
        (self.work / 'expected-homes.json').write_bytes(encode(expected));(self.work / 'expected-homes.json').chmod(0o600)
        report = self.report('PASS_SETUP8_DELIVERED_CLI_PRIVATE_FIXTURES')
        (self.work / 'fixture-receipt.json').write_bytes(encode(report));(self.work / 'fixture-receipt.json').chmod(0o600)
        return report

    def verify_reinstall(self):
        expected = json.loads((self.work / 'expected-homes.json').read_bytes())
        need({p:snapshot(self.work / p) for p in PROFILES} == expected, 'ALPM removal/reinstall changed private user homes')
        for profile in PROFILES:
            home = self.work / profile;before = snapshot(home)
            need(self.migrate('status', home)['status'] == self.migrate('apply', home)['status'] == 'already-applied',
                 'reinstalled migration CLI cannot validate exact completed versions')
            need(all(a['status'] == 'clean' for a in self.setup('status', home, new=True)['actions']), 'reinstalled setup status differs')
            need(snapshot(home) == before, 'reinstalled CLI changed completed private home')
        self.cases['post-package-reinstall-user-version-preserved'] = 'PASS'
        return self.report('PASS_SETUP8_DELIVERED_CLI_REINSTALL_FIXTURES')

    def report(self, status):
        return dict(status=status, scope='EXPLICIT_INERT_PRIVATE_FIXTURES_ONLY', cases=self.cases, cli_observations=self.cli_observations, uid=os.getuid(),
            architecture=platform.machine(), actual_page_size=os.sysconf('SC_PAGE_SIZE'), profiles=list(PROFILES),
            setup_sha256=sha(self.setup_cli.read_bytes()), engine_sha256=sha((self.private / 'config_migrate.py').read_bytes()),
            launcher_sha256=sha(self.cli.read_bytes()), manifest_sha256=sha(self.manifest_path.read_bytes()),
            actual_sigkill_returncode=getattr(self, 'child_returncode', None), package_installation='EXTERNAL_CALLER_REQUIRED',
            native_qualification='NOT_GRANTED_BY_FIXTURE_DRIVER', hardware='NOT_RUN', performance='NOT_MEASURED',
            release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--keep-fixtures', action='store_true')
    parser.add_argument('--verify-reinstall', action='store_true')
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() > 0, 'ordinary intended-user fixture execution required')
    if args.work is None:
        need(not args.verify_reinstall and not args.keep_fixtures, 'persistent fixture use requires explicit --work')
        with tempfile.TemporaryDirectory(prefix='setup8-delivery-') as td:
            report = Delivery(args.root, Path(td) / 'fixtures').controls()
            report['private_fixtures_retired'] = True
    else:
        need(args.work.is_absolute() and (args.keep_fixtures or args.verify_reinstall), 'explicit persistent fixture intent required')
        engine = Delivery(args.root, args.work)
        report = engine.verify_reinstall() if args.verify_reinstall else engine.controls()
        report['private_fixtures_retired'] = False
        report['fixture_work'] = str(args.work)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
