# SPDX-License-Identifier: MIT
"""Runs only in the read-only, offline disposable x86_64 lifecycle actor."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import tarfile

HERE = Path('/opt/python314-inputs')


def load(name):
    spec = importlib.util.spec_from_file_location('python314_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime, repository = load('runtime'), load('repository')
need, sha = repository.need, repository.sha
ARCHIVE = 'python-3.14.8-1.1-x86_64.pkg.tar.zst'
BASELINE = 'python-3.14.9-1-x86_64.pkg.tar.zst'
BASELINE_SHA = 'e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55'


def guard():
    need(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file(),
         'x86_64 disposable Docker actor required')
    observed = repository.mounts(Path('/proc/self/mountinfo').read_text())
    standard_devices = set(repository.STANDARD_DEVICES) - {'/dev/pts/ptmx'}
    allowed = ({'/', '/scratch', '/tmp', '/run', '/test-home'} | repository.RUNTIME_FILES |
               set(repository.STANDARD_MOUNTS) | standard_devices)
    need(set(observed) <= allowed and 'ro' in observed['/']['options'] and
         observed['/']['fs'] in {'overlay', 'fuse-overlayfs'}, 'unexpected/host mount or writable image root')
    for path in standard_devices & set(observed):
        need(observed[path]['fs'] == 'devtmpfs' and {'rw', 'nosuid'} <= observed[path]['options'],
             'unexpected standard character-device mount')
    need('rw' in observed['/scratch']['options'] and observed['/scratch']['fs'] in repository.BIND_FILESYSTEMS,
         'owned scratch storage required')
    for path in ('/tmp', '/run', '/test-home'):
        need(observed[path]['fs'] == 'tmpfs' and {'rw', 'nosuid', 'nodev'} <= observed[path]['options'],
             'private runtime tmpfs required')
    rows = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps = {key: int(rows[key].strip(), 16) for key in repository.CAP_FIELDS}
    need(rows['NoNewPrivs'].strip() == '1' and
         all(caps[key] == (1 | (1 << 18)) for key in ('CapEff', 'CapPrm', 'CapBnd')) and
         caps['CapInh'] == caps['CapAmb'] == 0, 'only CHOWN/SYS_CHROOT with no-new-privileges allowed')
    need(set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}, 'network must be none')
    need(not any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock', '/run/dbus/system_bus_socket',
             '/dev/dri', '/dev/snd', '/dev/input', '/dev/kvm', '/dev/mem', '/dev/fuse')), 'host bus/device exposure')
    repository.validate_exposure(repository.exposed_nodes())
    pins = json.loads((HERE / 'inputs.json').read_text())
    for name, digest in pins.items():
        need(sha(HERE / name) == digest, 'input changed: ' + name)
    need(sha(HERE / 'baseline' / BASELINE) == BASELINE_SHA, 'exact baseline rollback asset missing')
    return {'capabilities': caps, 'interfaces': ['lo'], 'inputs': pins,
            'mounts': {p: dict(row, options=sorted(row['options'])) for p, row in observed.items()}}


def metadata(path):
    payload, info = {}, {}
    with tarfile.open(path, 'r:zst') as archive:
        members = archive.getmembers()
        need(len(members) < 6000 and sum(m.size for m in members) < 256 * 1024**2, 'package bounds exceeded')
        for member in members:
            name = member.name.rstrip('/')
            need(name and not name.startswith('/') and '..' not in Path(name).parts and name not in payload,
                 'unsafe/duplicate package member')
            if name.startswith('.'):
                need(name in {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL', '.CHANGELOG'}, 'unknown metadata')
                if name == '.PKGINFO':
                    with archive.extractfile(member) as stream:
                        for line in stream.read().decode().splitlines():
                            if line and not line.startswith('#'):
                                key, value = line.split(' = ', 1)
                                info.setdefault(key, []).append(value)
                continue
            need(name == 'usr' or name.startswith('usr/'), 'payload outside /usr')
            need(member.isfile() or member.isdir() or member.issym(), 'special/hardlinked package payload')
            row = {'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
            if member.isfile():
                with archive.extractfile(member) as stream:
                    row.update(type='regular', sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            elif member.issym():
                need(not Path(member.linkname).is_absolute(), 'absolute package link')
                row.update(type='symlink', target=member.linkname)
            else:
                row['type'] = 'directory'
            payload[name] = row
    need(info.get('pkgname') == ['python'] and info.get('arch') == ['x86_64'], 'wrong package identity')
    return {'info': info, 'payload': payload, 'sha256': sha(path)}


class Trial(repository.Integration):
    def __init__(self):
        super().__init__({'source_commit': 'bounded-python314-host-lifecycle'})
        self.out = self.scratch / 'output'
        self.out.mkdir()
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': '/test-home', 'TMPDIR': '/tmp', 'LC_ALL': 'C', 'TZ': 'UTC'}
        self.runner = runtime.Runner(650, self.env, self.out / 'logs')
        self.result = {'schema_version': 1, 'status': 'RUNNING', 'commands': self.receipts, 'cases': self.cases}

    def command(self, label, argv, *, env=None, expected=0, signature_failure=False, binary=False,
                stdout_only=False, clean_diagnostics=False):
        need(env is None or env == self.env, 'unexpected command environment')
        name = f'{len(self.receipts):03d}-{label}.txt'
        process = self.runner.run(list(map(str, argv)), timeout=90, log=name, limit=2 * 1024**2)
        text = process.stdout.decode(errors='replace')
        self.receipts.append({'label': label, 'argv': list(map(str, argv)), 'exit': process.returncode,
                              'log': 'logs/' + name, 'sha256': sha(self.out / 'logs' / name)})
        need(process.returncode != 0 if expected == 'nonzero' else process.returncode == expected,
             label + ': unexpected exit ' + str(process.returncode))
        if signature_failure:
            need(re.search(r'(signature|public key|unknown trust|untrusted|required key missing from keyring)', text, re.I),
                 'missing signature refusal')
        if clean_diagnostics:
            need(not re.search(r'^(error\s*:|could not change (?:the root directory|directory))', text, re.I | re.M),
                 label + ': ancillary error despite zero exit')
        return process.stdout if binary else text

    def inventory(self, label):
        return repository.package_inventory(self.pacman(label, ['-Q']))

    def state(self):
        paths = sorted(self.target.rglob('*'))
        need(len(paths) < 100000, 'private root snapshot node bound exceeded')
        return {p.relative_to(self.target).as_posix(): repository.owned_state(self.target, p.relative_to(self.target).as_posix())
                for p in paths}

    def installed(self, expected):
        listing = self.pacman('ownership', ['-Ql', 'python'])
        owned = set()
        for line in listing.splitlines():
            owner, filename = line.split(maxsplit=1)
            path = Path(filename)
            need(owner == 'python' and path.is_relative_to(self.target), 'ownership escaped private root')
            owned.add(path.relative_to(self.target).as_posix())
        need(owned == set(expected['payload']), 'exact package ownership differs from archive')
        for name, row in expected['payload'].items():
            need(repository.owned_state(self.target, name) == row, 'installed payload/metadata mismatch: ' + name)
        self.pacman('dependency-integrity', ['-Dk'])
        self.pacman('candidate-dependencies', ['-T', *expected['info'].get('depend', [])])

    def sentinels(self):
        return {name: repository.owned_state(self.target, name) for name in
                ('etc/python314-operator.conf', 'home/operator/.config/python/startup.py',
                 'usr/bin/bash')}

    def retired(self, previous, current):
        for name in set(previous['payload']) - set(current['payload']):
            if previous['payload'][name]['type'] != 'directory':
                need(repository.owned_state(self.target, name)['type'] == 'missing',
                     'previous-version-only file survived: ' + name)

    def smoke(self, label):
        base = self.target / 'usr'
        python = base / 'bin/python3.14'
        tcl_paths = [p for p in (base / 'lib/tcl8.6', base / 'share/tcl8.6') if (p / 'init.tcl').is_file()]
        need(len(tcl_paths) == 1, 'unique installed Tcl script library required')
        env = dict(self.env, LD_LIBRARY_PATH=str(base / 'lib'), TCL_LIBRARY=str(tcl_paths[0]))
        previous = self.runner.env
        self.runner.env = env
        try:
            self.command(label + '-runtime', [python, '-I', '-B', HERE / 'check_runtime.py', '--prefix', base])
            code = """import _tkinter,tkinter,sys,json
from pathlib import Path
base=Path(sys.argv[1]); t=tkinter.Tcl()
assert sys.version_info[:3]==(3,14,8) and Path(sys.prefix)==base
assert Path(_tkinter.__file__).is_relative_to(base)
assert t.eval('info patchlevel')=='8.6.16' and t.eval('info exists tk_version')=='0'
assert Path(t.eval('info library'))==Path(sys.argv[2])
maps=sorted({x.split()[-1] for x in Path('/proc/self/maps').read_text().splitlines() if 'libpython' in x})
assert maps==[str(base/'lib/libpython3.14.so.1.0')]
print(json.dumps(dict(python=sys.version,prefix=sys.prefix,Tcl=t.eval('info patchlevel'),Tk_loaded=False,mapped_library=maps)))
"""
            headless = json.loads(self.command(label + '-headless', [python, '-I', '-S', '-B', '-c', code, base, tcl_paths[0]]))
            envdir = self.scratch / (label + '-venv')
            self.command(label + '-venv', [python, '-I', '-B', '-m', 'venv', '--copies', '--without-pip', envdir])
            check = "import sys; from pathlib import Path; assert sys.version_info[:3]==(3,14,8); assert Path(sys.prefix)==Path(sys.argv[1]); assert Path(sys.base_prefix)==Path(sys.argv[2]); print(sys.version)"
            self.command(label + '-venv-runtime', [envdir / 'bin/python3.14', '-I', '-B', '-c', check, envdir, base])
            suffix = self.command(label + '-suffix', [base / 'bin/python3.14-config', '--extension-suffix']).strip()
            need(re.fullmatch(r'\.cpython-314-x86_64-linux-gnu\.so', suffix), 'foreign extension suffix')
            module = self.scratch / ('consumer_full' + suffix)
            self.command(label + '-compile', ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                         '-I' + str(base / 'include/python3.14'), HERE / 'full.c', '-o', module])
            check = "import sys; sys.path.insert(0,sys.argv[1]); import consumer_full as c; assert c.total([2,5,-3])==4; assert c.versions()[0]=='3.14.8'; print(c.versions())"
            self.command(label + '-consumer', [python, '-I', '-S', '-B', '-c', check, self.scratch])
            return headless
        finally:
            self.runner.env = previous

    def run(self):
        self.result['guard'] = guard()
        candidate, baseline = metadata(HERE / ARCHIVE), metadata(HERE / 'baseline' / BASELINE)
        need(candidate['info']['pkgver'] == ['3.14.8-1.1'] and baseline['info']['pkgver'] == ['3.14.9-1'], 'wrong before/after versions')
        self.copy_base()  # Reuse bounded copied-root construction and hook masks.
        for name, target in {'bin': 'usr/bin', 'sbin': 'usr/bin', 'lib': 'usr/lib', 'lib64': 'usr/lib'}.items():
            (self.target / name).symlink_to(target)
        options = '[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n'
        self.config.write_text(options)
        self.query_config.write_text(options)
        shutil.copyfile(self.config, self.out / 'TEST-pacman.conf')
        shutil.copyfile(self.query_config, self.out / 'TEST-query-pacman.conf')
        for role, usage in [('signer', 'sign'), ('verifier', 'cert')]:
            self.key(role, usage)
        for home in (self.keys['signer']['home'], self.keys['verifier']['home']):
            (home / 'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\n')
        versions = self.inventory('baseline-inventory')
        need(versions['python'] == '3.14.9-1', 'baseline is not the retained 3.14.9 package')
        self.installed(baseline)
        (self.target / 'etc/python314-operator.conf').write_text('operator edited configuration sentinel\n')
        edited = self.target / 'home/operator/.config/python/startup.py'
        edited.parent.mkdir(parents=True)
        edited.write_text('# operator edited startup; preserve exactly\n')
        edited.chmod(0o644)
        os.chown(edited, 1000, 1000)
        need((self.target / 'usr/bin/bash').is_file(), 'vendor sentinel absent')
        need('owned by bash ' in self.pacman('vendor-ownership', ['-Qo', self.target / 'usr/bin/bash']),
             'vendor sentinel must remain package-owned')
        sentinels = self.sentinels()
        packages = self.scratch / 'packages'
        packages.mkdir()
        local, rollback = packages / ARCHIVE, packages / BASELINE
        shutil.copyfile(HERE / ARCHIVE, local)
        shutil.copyfile(HERE / 'baseline' / BASELINE, rollback)
        self.sign(local, 'signer')
        self.sign(rollback, 'signer')
        before = self.state()
        self.pacman('unknown-key-refusal', ['-U', '--noscriptlet', local], reject=True)
        need(self.state() == before, 'unknown-key refusal changed private root')
        self.cases.append({'name': 'unknown-key unchanged-state refusal', 'result': 'PASS'})
        self.trust('signer')
        tampered = self.scratch / 'tampered'
        tampered.mkdir()
        altered = tampered / ARCHIVE
        with tarfile.open(local, 'r:zst') as source, tarfile.open(altered, 'w:zst') as target:
            for member in source:
                if member.isfile():
                    with source.extractfile(member) as stream:
                        if member.name == 'usr/lib/python3.14/EXTERNALLY-MANAGED':
                            import io
                            data = stream.read() + b'tampered\n'
                            member.size = len(data)
                            target.addfile(member, io.BytesIO(data))
                        else:
                            target.addfile(member, stream)
                else:
                    target.addfile(member)
        shutil.copyfile(str(local) + '.sig', str(altered) + '.sig')
        before = self.state()
        self.pacman('tamper-refusal', ['-U', '--noscriptlet', altered], reject=True)
        need(self.state() == before, 'tamper refusal changed private root')
        self.cases.append({'name': 'valid-archive changed-byte signature refusal with unchanged state', 'result': 'PASS'})
        self.pacman('candidate-downgrade', ['-U', '--noscriptlet', local])
        expected = dict(versions, python='3.14.8-1.1')
        need(self.inventory('candidate-inventory') == expected, 'downgrade changed other package versions')
        self.installed(candidate)
        self.retired(baseline, candidate)
        first = self.smoke('installed')
        need(self.sentinels() == sentinels, 'install changed edit/operator/vendor sentinels')
        self.pacman('remove-candidate', ['-R', '--noscriptlet', 'python'])
        need(self.inventory('removed-inventory') == {k: v for k, v in versions.items() if k != 'python'}, 'remove inventory differs')
        for name, row in candidate['payload'].items():
            if row['type'] != 'directory':
                need(repository.owned_state(self.target, name)['type'] == 'missing', 'owned file survived removal: ' + name)
        need(self.sentinels() == sentinels, 'remove changed sentinels')
        self.pacman('reinstall-candidate', ['-U', '--noscriptlet', local])
        need(self.inventory('reinstalled-inventory') == expected, 'reinstall inventory differs')
        self.installed(candidate)
        second = self.smoke('reinstalled')
        self.pacman('restore-exact-baseline', ['-U', '--noscriptlet', rollback])
        need(self.inventory('restored-inventory') == versions, 'baseline inventory not restored')
        self.installed(baseline)
        self.retired(candidate, baseline)
        need(self.sentinels() == sentinels, 'restoration changed sentinels')
        self.result.update(status='PASS TEST-signed x86_64 private-root lifecycle',
            operation='downgrade python3.14.9-1 ->3.14.8-1.1; remove/reinstall; restore3.14.9-1',
            baseline=versions, candidate_inventory=expected, restored_inventory=versions,
            candidate_sha256=candidate['sha256'], candidate_payload_nodes=len(candidate['payload']),
            baseline_archive_sha256=baseline['sha256'], baseline_payload_nodes=len(baseline['payload']),
            rollback='PASS exact archive reacquired through frozen verified repo and retained before lifecycle',
            payload_ownership_dependencies='PASS exact before/after archive payload/mode/uid/gid/link/ALPM ownership and dependency checks',
            sentinels=sentinels, installed_headless=first, reinstalled_headless=second,
            hooks='masked; --noscriptlet mandatory; libalpm ldconfig allowed only in copied root',
            holds=['not an Asahi3.14.7 upgrade', 'no native ARM/16K/M2/GUI/performance acceptance',
                   'source/legal/signature freshness/production trust/release gates unchanged'])
        (self.out / 'candidate-payload.json').write_text(json.dumps(candidate, sort_keys=True, indent=2) + '\n')
        (self.out / 'baseline-payload.json').write_text(json.dumps(baseline, sort_keys=True, indent=2) + '\n')
        shutil.copyfile(rollback, self.out / BASELINE)
        shutil.copyfile(HERE / 'baseline' / (BASELINE + '.sig'), self.out / (BASELINE + '.sig'))
        shutil.copyfile(HERE / 'baseline-packages.txt', self.out / 'provisioned-packages.txt')


def main():
    def deadline(signum, frame):
        raise RuntimeError('700-second actor deadline exceeded')
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(700)
    guard()  # Refuse before creating output or private state outside the contract.
    trial = Trial()
    error = None
    try:
        with runtime.cancellation_handlers():
            trial.run()
    except BaseException as exc:
        error = exc
        trial.result.update(status='FAIL', failure=type(exc).__name__ + ': ' + str(exc))
        (trial.out / 'failure.json').write_text(json.dumps({'status': 'FAIL', 'error': str(exc)}) + '\n')
    finally:
        signal.alarm(0)
        # Only private TEST key homes/agents are retired; no key material exported.
        cleanup = runtime.Runner(30, trial.env, trial.out / 'cleanup-logs')
        failures = []
        for home in trial.home.iterdir():
            if home.is_dir():
                try:
                    result = cleanup.run(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'], timeout=10)
                    need(result.returncode == 0, 'private TEST gpg-agent retirement failed')
                    shutil.rmtree(home)
                except BaseException as exc:
                    failures.append(str(exc))
        trial.result['private_TEST_state_removed'] = not failures and not any(trial.home.iterdir())
        if not trial.result['private_TEST_state_removed']:
            trial.result['status'] = 'FAIL private TEST cleanup'
        (trial.out / 'result.json').write_text(json.dumps(trial.result, sort_keys=True, indent=2) + '\n')
    if error:
        raise error
    print(trial.result['status'])
    return 0 if trial.result['status'].startswith('PASS') else 2


if __name__ == '__main__':
    raise SystemExit(main())
