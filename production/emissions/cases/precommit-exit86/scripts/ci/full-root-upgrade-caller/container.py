#!/usr/bin/env python3
"""One disposable, signed, offline development composition transaction."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tempfile

PROJECTS = (({'cachy-asahi-' + name for name in (
    'hyprland-settings', 'fish-config', 'zsh-config', 'setup', 'ksmctl', 'update',
    'fdk-aac', 'zsh-autosuggestions', 'topmem', 'fish-bang-bang')}) | {'cachy-asahi-doctor', 'cachy-asahi-fish-autopair', 'cachy-asahi-fish-done', 'cachy-asahi-mirrors', 'cachy-asahi-welcome', 'cachy-asahi-zsh-history-substring-search', 'cachy-asahi-zsh-syntax-highlighting'}) | {'cachy-asahi-apps', 'cachy-asahi-cache', 'cachy-asahi-orphans', 'cachy-asahi-repository-runtime'} | {'cachy-asahi-boot-report','cachy-asahi-dns','cachy-asahi-sysctl'}
EXTRAS = ({'htmlq', 'pacman-contrib', 'archlinux-contrib', 'pyalpm'}) | {'alsa-ucm-conf-asahi', 'asahi-audio', 'bankstown', 'lsp-plugins-lv2', 'speakersafetyd', 'triforce-lv2'}
HELPERS = {'core-lifecycle.py': 'c3223a1bd4002683071f4442e1f5b9caf439c68c4e231da10039cc9cebcdb52b',
           'provider-helpers.py': 'b10bc7037d2994538fa5bd853a2b98cd549a55b6d30c8b84354a369f67980672'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def run(args, *, data=None):
    print('$', ' '.join(map(str, args)), flush=True)
    proc = subprocess.run(args, input=data, capture_output=True, text=True, timeout=180)
    need(len(proc.stdout) + len(proc.stderr) <= 4 * 1024**2, 'command output exceeded bound')
    if proc.returncode:
        signature_failure(args, proc)
        print(proc.stdout[-8192:], proc.stderr[-8192:], flush=True)
    proc.check_returncode()
    return proc.stdout


_SIGNATURE_FAILURE_DATA = None

def signature_failure(args, proc):
    """Existing failed -U capture only. No key contents or acceptance authority."""
    global _SIGNATURE_FAILURE_DATA
    if not (args[0] == 'pacman' and '-U' in args and proc.returncode):
        return
    import stat, time
    try:
        conf = Path(args[args.index('--config') + 1])
        need(re.fullmatch(r'/tmp/composition-[a-z0-9_]{8}/pacman\.conf', str(conf)), 'owned private signature diagnostic path')
        trust = conf.parent / 'trust'
        need(not any(p.is_symlink() for p in (trust, *trust.parents)), 'ordinary private trust diagnostic')
        st = trust.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700, 'exact original private keyring lease')
        files = {}
        for name in ('pubring.gpg', 'pubring.kbx', 'trustdb.gpg', 'common.conf', 'gpg.conf'):
            p = trust / name
            try:
                v = p.lstat()
            except FileNotFoundError:
                files[name] = {'present': False}
                continue
            files[name] = dict(present=True, regular=stat.S_ISREG(v.st_mode), symlink=stat.S_ISLNK(v.st_mode), mode=stat.S_IMODE(v.st_mode), uid=v.st_uid, bytes=v.st_size)
        messages = []
        for line in (proc.stdout + '\n' + proc.stderr).splitlines():
            for marker in ('gpg error: ', 'GPGME version: ', 'signature timestamp is greater than system time.'):
                if marker in line:
                    messages.append((marker + line.split(marker, 1)[1])[:160])
        _SIGNATURE_FAILURE_DATA = dict(schema_version=1, status='FAILED_REQUIRED_SIGNATURE_OPERANDS_NOT_ACCEPTANCE', epoch_ns=time.time_ns(), exit_code=proc.returncode, trust=dict(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid, readonly=bool(os.statvfs(trust).f_flag & os.ST_RDONLY), read=os.access(trust,os.R_OK), write=os.access(trust,os.W_OK), search=os.access(trust,os.X_OK)), files=files, GPGME_messages=messages[-4:], messages_omitted=max(0,len(messages)-4), original_crypto_error='UNKNOWN_IF_NOT_IN_CAPTURE', acceptance_authority=False)
        need(len(json.dumps(_SIGNATURE_FAILURE_DATA).encode()) <= 2048, 'bounded signature diagnostic')
    except Exception as error:
        _SIGNATURE_FAILURE_DATA = dict(schema_version=1, status='SIGNATURE_OPERANDS_UNAVAILABLE_NOT_ACCEPTANCE', error_type=type(error).__name__, acceptance_authority=False)


def guard():
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and os.uname().release == '7.1.13-generic16k-managed-gui' and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()
         and re.fullmatch('[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_COMPOSITION', '')),
         'explicit disposable native ARM Docker container required')


def lock(text):
    rows = [line.split() for line in text.splitlines()]
    need(all(len(row) == 2 for row in rows) and len({r[0] for r in rows}) == len(rows),
         'invalid or duplicate package inventory')
    return dict(rows)


def inventory():
    return lock(run(['pacman', '-Q']))


def pin(path, digest, size):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size == size
         and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
         'input byte pin differs: ' + path.name)


def inputs(plan, base, expected, directory):
    packages, projects = plan['packages'], plan['projects']
    need(len(packages) == 34 and {r['name'] for r in packages} == PROJECTS | EXTRAS
         and len(projects) == 24 and {r['name'] for r in projects} == PROJECTS,
         "exact21 projects and10 auxiliary additions required")
    need(len(base) == 574 and 'libfdk-aac' in base and not (set(base) & (PROJECTS | EXTRAS)),
         'exact untouched 574-package namespace required')
    derived = {k: v for k, v in base.items() if k != 'libfdk-aac'}
    derived.update({r['name']: r['version'] for r in packages})
    need(len(expected) == 607 and expected == derived, 'expected inventory changes more than composition')
    filenames = set()
    for row in packages:
        name = row['filename']
        need(re.fullmatch(r'[A-Za-z0-9+_.:@-]+\.pkg\.tar\.(?:xz|zst|gz)', name)
             and name not in filenames, 'unsafe or duplicate archive filename')
        filenames.add(name)
        pin(directory / name, row['sha256'], row['size'])
        pin(directory / (name + '.sig'), row['signature_sha256'], row['signature_size'])
    byname = {r['name']: r for r in packages}
    for project in projects:
        row = byname[project['name']]
        need((row['version'], row['filename'], row['sha256']) ==
             (project['version'], project['archive'], project['sha256']), 'project archive binding differs')
        paths = [r['path'] for r in project['payload']]
        need(paths and len(paths) == len(set(paths)), 'empty or duplicate project payload')
        for item in project['payload']:
            path = PurePosixPath(item['path'])
            need(str(path) == item['path'] and path.is_absolute() and str(path).startswith('/usr/')
                 and '..' not in path.parts and item['type'] in ('file', 'symlink'),
                 'unsafe project payload namespace')
    return byname


def archive_metadata(row, directory):
    text = run(['bsdtar', '-xOf', str(directory / row['filename']), '.PKGINFO'])
    fields = {}
    for line in text.splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(' = ', 1)
            fields.setdefault(key, []).append(value)
    need(fields.get('pkgname') == [row['name']] and fields.get('pkgver') == [row['version']]
         and fields.get('arch') in (['any'], ['aarch64']), 'actual archive identity differs')
    return fields


def install(pacman, archives, expected):
    # Conflict answer bit 4 is allowed only after validating the sole FDK conflict.
    run(pacman + ['--debug', '--noconfirm', '--noscriptlet', '--ask', '4', '-U', *archives])
    actual = inventory()
    need(actual == expected, "installed inventory differs from exact 604-package composition")
    return actual


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def lifecycle_helpers(plan, source):
    need(set(plan['helpers']) == set(HELPERS), 'exact existing lifecycle/provider helpers required')
    values = {}
    for name, digest in HELPERS.items():
        row = plan['helpers'][name]
        need(row['sha256'] == digest, 'existing lifecycle helper pin differs')
        pin(source / name, digest, row['size'])
        values[name] = load(name.replace('-', '_'), source / name)
    return values['core-lifecycle.py'], values['provider-helpers.py']



class UpgradeFailure(ValueError):
    def __init__(self, reason, evidence):
        super().__init__(reason)
        self.evidence = evidence


def upgrade(pacman, plan, expected, source, work):
    """Run the sole successor route before live-root ownership checks."""
    import sys
    need(plan.get('full_root_upgrade') is True and 'setup4' in plan
         and not ({'measurement_only', 'footprint', 'lifecycle', 'updater_v2'} & set(plan)),
         'dedicated copied-root upgrade selection required')
    hook = load('composition_full_root_upgrade', Path('/upgrade-hook.py'))
    value = hook.run(pacman, plan, expected, source, work, sys.modules[__name__])
    try:
        need(value['status'] == 'PASS', 'copied-root upgrade did not pass')
        need(inventory() == expected, 'source inventory changed during copied-root upgrade')
    except Exception as error:
        raise UpgradeFailure(str(error), value) from error
    return value


def main():
    result = {'status': 'FAIL', 'phase': 'container-guard', 'scope': 'generic-offline-composition',
              'hardware': 'NOT RUN', 'target_lifecycle': 'NOT RUN', 'app_sessions': 'NOT RUN',
              'bluetooth_transport': 'NOT RUN', 'publication': 'NOT ACCEPTED'}
    work = None
    try:
        guard()
        source = Path('/inputs')
        plan = json.loads((source / 'plan.json').read_text())
        need(plan.get('full_root_upgrade') is True and 'setup4' in plan, 'dedicated upgrade route required')
        base = lock((source / 'expectedbase.lock').read_text())
        expected = lock((source / 'expected-installed.lock').read_text())
        result['phase'] = 'input-pins-and-base'
        byname = inputs(plan, base, expected, source)
        need(inventory() == base, 'actual base differs from exact 574-package lock')
        result['phase'] = 'actual-archive-policy'
        metadata = {name: archive_metadata(row, source) for name, row in byname.items()}
        universe = set(base) | set(byname)
        conflicts = {(name, dep) for name, fields in metadata.items()
                     for dep in fields.get('conflict', [])
                     if re.split('[<>=]', dep)[0] in universe}
        need(conflicts == {('cachy-asahi-fdk-aac', 'libfdk-aac')}, 'unexpected replacement conflict')
        for project in plan['projects']:
            fields = metadata[project['name']]
            for supplied, actual in (('depends', 'depend'), ('provides', 'provides'), ('conflicts', 'conflict')):
                need(sorted(project[supplied]) == sorted(fields.get(actual, [])), 'project package metadata differs')
            listing = run(['pacman', '-Qqlp', str(source / project['archive'])]).splitlines()
            need({p for p in listing if not p.endswith('/')} == {p['path'] for p in project['payload']},
                 'actual archive payload differs')
        work = Path(tempfile.mkdtemp(prefix='composition-', dir='/tmp'))
        trust, hooks = work / 'trust', work / 'hooks'
        trust.mkdir(mode=0o700); hooks.mkdir()
        result['phase'] = 'private-test-trust'
        gpg = ['gpg', '--batch', '--no-options', '--homedir', str(trust), '--no-auto-key-retrieve']
        public = source / 'TEST-public.asc'
        shown = run(gpg + ['--with-colons', '--import-options', 'show-only', '--import', str(public)])
        fingerprints = [line.split(':')[9] for line in shown.splitlines() if line.startswith('fpr:')]
        need(fingerprints == [plan['test_signer_fingerprint']] and
             all(re.fullmatch('[0-9A-F]{40}', plan[k]) for k in ('signer_fingerprint', 'test_signer_fingerprint')),
             'exact TEST and upstream signers required')
        run(gpg + ['--import', str(source / 'archlinuxarm.gpg'), str(public)])
        run(gpg + ['--import-ownertrust'], data=''.join(plan[k] + ':6:\n' for k in
                                                      ('signer_fingerprint', 'test_signer_fingerprint')))
        names = set(plan['hooks'])
        for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
            names.update(p.name for p in Path(directory).glob('*.hook'))
        for row in plan['packages']:
            listing = run(['pacman', '-Qqlp', str(source / row['filename'])]).splitlines()
            names.update(PurePosixPath(p).name for p in listing if
                         p.startswith(('/usr/share/libalpm/hooks/', '/etc/pacman.d/hooks/')) and p.endswith('.hook'))
        for name in names:
            need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook', name), 'unsafe hook name')
            (hooks / name).symlink_to('/dev/null')
        conf = work / 'pacman.conf'
        conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\n'
                        'LocalFileSigLevel = Required\nHookDir = ' + str(hooks) + '\nGPGDir = ' + str(trust) + '\n')
        pacman = ['pacman', '--config', str(conf)]
        result['phase'] = 'required-signature-offline-transaction'
        installed = install(pacman, [str(source / r['filename']) for r in plan['packages']], expected)
        result['phase'] = 'copied-root-full-upgrade'
        result['full_root_upgrade'] = upgrade(pacman, plan, expected, source, work)
        result['phase'] = 'installed-dependencies-and-ownership'
        run(pacman + ['-Dk'])
        depends = sorted({dep for fields in metadata.values() for dep in fields.get('depend', [])})
        run(pacman + ['-T', *depends])
        run(pacman + ['-Qkk', *sorted(PROJECTS)])
        for project in plan['projects']:
            for item in project['payload']:
                path = Path(item['path'])
                need(path.is_symlink() if item['type'] == 'symlink' else path.is_file() and not path.is_symlink(),
                     'installed payload type differs: ' + str(path))
                if item['type'] == 'symlink':
                    need(os.readlink(path) == item['target'], 'installed symlink target differs')
                need(run(pacman + ['-Qqo', str(path)]).strip() == project['name'], 'project file owner differs')
        need('libfdk-aac' not in installed, 'upstream FDK unexpectedly remains installed')
        for path in ('/usr/lib/libfdk-aac.so.2', '/usr/lib/libfdk-xhe-aac.so.0'):
            need(run(pacman + ['-Qqo', path]).strip() == 'cachy-asahi-fdk-aac', 'FDK provider owner differs')
        result['phase'] = 'native-pyalpm-and-fdk-load'
        run(['python', '-I', '-B', '-c', 'import pyalpm,ctypes; '
             'assert pyalpm.Handle("/", "/var/lib/pacman"); '
             'ctypes.CDLL("/usr/lib/libfdk-aac.so.2"); ctypes.CDLL("/usr/lib/libfdk-xhe-aac.so.0")'])
        result.update(phase='completed', project_sha256={p['name']: p['sha256'] for p in plan['projects']},
                      installed_inventory_sha256=hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(installed.items())).encode()).hexdigest(),
                      package_count=len(installed), dependency_checks='PASS-no-waivers', payload_ownership='PASS',
                      pyalpm='PASS-native-import', fdk='PASS-installed-provider-load', scriptlets='DISABLED', hooks='MASKED')
        final = inventory()
        need(final == expected, "outer root differs from initial signed604 checkpoint")
        result.update(final_package_count=len(final),
                      final_inventory_sha256=hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(final.items())).encode()).hexdigest())
        result['status'] = 'PASS'
    except Exception as error:
        if isinstance(error, UpgradeFailure): result['full_root_upgrade'] = error.evidence
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:2048])
    finally:
        if work:
            try:
                run(['gpgconf', '--homedir', str(work / 'trust'), '--kill', 'all'])
                shutil.rmtree(work)
            except Exception as error:
                result.update(status='FAIL', cleanup_error=str(error)[:1024])
        Path('/out/result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True), flush=True)
    if _SIGNATURE_FAILURE_DATA is not None:
        print('APPS6_KEYRING_FAILURE_DATA '+json.dumps(_SIGNATURE_FAILURE_DATA,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
