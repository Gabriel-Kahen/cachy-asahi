# SPDX-License-Identifier: MIT
"""Small extension of the unchanged disposable FirstLogin package owner."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile

spec = importlib.util.spec_from_file_location('installed_ui_owner', '/driver/borrowed/owner.py')
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
spec = importlib.util.spec_from_file_location('desktop_positive_checks', '/driver/checks.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
CANDIDATE = 'python-3.14.8-1.1-x86_64.pkg.tar.zst'
PROVIDER = 'python-3.14.9-1-x86_64.pkg.tar.zst'
ROOT = Path('/work/python-desktop')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def package(path):
    rows, info = {}, {}
    with tarfile.open(path, 'r:zst') as archive:
        members = archive.getmembers()
        if len(members) > 5000 or sum(m.size for m in members) > 256 * 1024**2:
            raise ValueError('Python archive bounds exceeded')
        for member in members:
            name = member.name.rstrip('/')
            if name.startswith('.'):
                if name == '.PKGINFO':
                    with archive.extractfile(member) as stream:
                        for line in stream.read().decode().splitlines():
                            if line and not line.startswith('#'):
                                key, value = line.split(' = ', 1)
                                info.setdefault(key, []).append(value)
                continue
            if name in rows or not name.startswith(('usr/',)) and name != 'usr' or '..' in Path(name).parts:
                raise ValueError('unsafe Python payload')
            row = {'uid': member.uid, 'gid': member.gid, 'mode': member.mode}
            if member.isfile():
                with archive.extractfile(member) as stream:
                    row.update(type='file', sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            elif member.issym():
                row.update(type='link', target=member.linkname)
            elif member.isdir():
                row['type'] = 'directory'
            else:
                raise ValueError('unexpected Python special/hardlink member')
            rows[name] = row
    if info.get('pkgname') != ['python'] or info.get('arch') != ['x86_64']:
        raise ValueError('wrong Python archive identity')
    return {'info': info, 'payload': rows, 'sha256': sha(path)}


def verify(expected, retired=None):
    listed = set(ui.call(['pacman', '-Qlq', 'python']).stdout.splitlines())
    if {p.rstrip('/').lstrip('/') for p in listed} != set(expected['payload']):
        raise ValueError('Python ALPM ownership differs')
    for name, row in expected['payload'].items():
        path = Path('/') / name
        item = path.lstat()
        if (item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) != (row['uid'], row['gid'], row['mode']):
            raise ValueError('Python installed ownership/mode differs: ' + name)
        if row['type'] == 'file' and (not stat.S_ISREG(item.st_mode) or sha(path) != row['sha256']):
            raise ValueError('Python installed bytes differ: ' + name)
        if row['type'] == 'link' and (not path.is_symlink() or str(path.readlink()) != row['target']):
            raise ValueError('Python installed link differs: ' + name)
        if row['type'] == 'directory' and not stat.S_ISDIR(item.st_mode):
            raise ValueError('Python directory differs')
    if retired:
        for name in set(retired['payload']) - set(expected['payload']):
            if retired['payload'][name]['type'] != 'directory' and (Path('/' + name).exists() or Path('/' + name).is_symlink()):
                raise ValueError('obsolete Python-owned file survived: ' + name)
    ui.call(['pacman', '-Dk'])
    ui.call(['pacman', '-T', *expected['info'].get('depend', [])])


def prepare():
    ROOT.mkdir(mode=0o1777)
    ROOT.chmod(0o1777)
    output = Path('/work/build/output')
    output.mkdir(parents=True)
    archive = Path('/opt/ui-integration/ui-archive')
    source = next(archive.glob('*.pkg.tar.zst'))
    shutil.copyfile(source, output / source.name)
    ui.install()  # Unchanged actual TEST install/24-file ownership/unsigned refusal.


def backend():
    ui.backend()
    for folder, source in [('python-candidate', Path('/inputs/materials') / CANDIDATE),
                           ('ui-archive', Path('/inputs/materials/cachy-asahi-first-login-ui-0.1.0-2-any.pkg.tar.zst'))]:
        target = Path('/opt/ui-integration') / folder
        target.mkdir(mode=0o700)
        shutil.copyfile(source, target / source.name)
    for folder in ('python-provider', 'packages'):
        (Path('/opt/ui-integration') / folder).chmod(0o700)


def candidate():
    expected = package(Path('/opt/ui-integration/python-candidate') / CANDIDATE)
    original = package(Path('/opt/ui-integration/python-provider') / PROVIDER)
    if expected['info']['pkgver'] != ['3.14.8-1.1'] or original['info']['pkgver'] != ['3.14.9-1']:
        raise ValueError('exact provider versions required')
    verify(original)
    before = ui.call(['pacman', '-Q']).stdout
    gi = Path('/usr/lib/python3.14/site-packages/gi/_gi.cpython-314-x86_64-linux-gnu.so')
    record = {'before_inventory': before, 'provider': original, 'candidate': expected,
              'gi_extension': {'path': str(gi), 'sha256': sha(gi)}, 'before_version': '3.14.9-1'}
    folder = Path('/root/python-desktop-packages')
    folder.mkdir()
    for source in (Path('/opt/ui-integration/python-candidate') / CANDIDATE,
                   Path('/opt/ui-integration/python-provider') / PROVIDER):
        target = folder / source.name
        shutil.copyfile(source, target)
        ui.sign(target)
    hooks = Path('/opt/ui-integration/masked-python-hooks')
    hooks.mkdir()
    for directory in (Path('/usr/share/libalpm/hooks'), Path('/etc/pacman.d/hooks')):
        for hook in directory.glob('*.hook'):
            path = hooks / hook.name
            if not path.is_symlink(): path.symlink_to('/dev/null')
    result = ui.pacman('--hookdir', str(hooks), '-U', '--noscriptlet', str(folder / CANDIDATE))
    checks.clean_positive(result.stdout, result.stderr)
    after = ui.call(['pacman', '-Q']).stdout
    if after != before.replace('python 3.14.9-1\n', 'python 3.14.8-1.1\n'):
        raise ValueError('candidate changed another package version')
    verify(expected, original)
    if sha(gi) != record['gi_extension']['sha256']:
        raise ValueError('GI consumer was changed instead of testing compatibility')
    record.update(candidate_inventory=after, candidate_version='3.14.8-1.1')
    (ui.PUBLIC / 'python-provider.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')


def restore():
    record = json.loads((ui.PUBLIC / 'python-provider.json').read_text())
    hooks = '/opt/ui-integration/masked-python-hooks'
    result = ui.pacman('--hookdir', hooks, '-U', '--noscriptlet', str(Path('/root/python-desktop-packages') / PROVIDER))
    checks.clean_positive(result.stdout, result.stderr)
    verify(record['provider'], record['candidate'])
    after = ui.call(['pacman', '-Q']).stdout
    if after != record['before_inventory'] or sha(Path(record['gi_extension']['path'])) != record['gi_extension']['sha256']:
        raise ValueError('original provider/inventory/GI extension not restored')
    (ui.PUBLIC / 'python-restored.json').write_text(json.dumps({'status': 'PASS exact provider and full inventory restored',
        'version': '3.14.9-1', 'inventory': after, 'native_ARM': 'NOT RUN'}))


if __name__ == '__main__':
    os.umask(0o022)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (os.geteuid() != 0 or not sys.flags.isolated or not Path('/.dockerenv').is_file()
            or int(status['CapEff'].strip(), 16) or int(status['CapBnd'].strip(), 16)
            or status['NoNewPrivs'].strip() != '1' or not Path(ui.CONFIG).is_file()):
        raise SystemExit('zero-capability private disposable owner only')
    {'backend': backend, 'prepare': prepare, 'candidate': candidate, 'restore': restore,
     'remove': ui.remove}[sys.argv[1]]()
