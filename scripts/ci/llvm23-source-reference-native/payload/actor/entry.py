#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Future Root-only LLVM actor. No action occurs on import."""
import hashlib
import importlib.util
import os
from pathlib import Path
import posixpath
import shutil
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm23_container_mode', HERE/'container_mode.py')
mode = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mode)

TOOLS = ('bash', 'uname', 'grep', 'gcc', 'g++', 'gcc-ar', 'gcc-ranlib', 'ld', 'as', 'cmake', 'ninja', 'python', 'bsdtar', 'make', 'perl', 'pkg-config', 'fakeroot', 'pacman', 'zstd', 'env', 'sort', 'cp', 'timeout')


def tools_data():
    rows = []
    for name in TOOLS:
        path = Path('/usr/bin')/name
        current, links = path, []
        for _ in range(8):
            if not current.is_symlink():
                break
            target = os.readlink(current)
            links.append({'path': str(current), 'target': target})
            current = Path(posixpath.normpath(target if target.startswith('/') else str(current.parent/target)))
            mode.need(Path('/usr') in current.parents, 'tool link escapes qualified /usr')
        info = current.lstat()
        mode.need(not current.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and info.st_size <= 256*mode.MIB, 'required native tool missing or unbounded: '+name)
        rows.append(dict(name=name, path=str(path), resolved=str(current), links=links, mode=stat.S_IMODE(info.st_mode), bytes=info.st_size, sha256=mode.digest(current)))
    return rows


def inventory(root):
    """Passive staged payload provenance; never read an entire binary into RAM."""
    rows = {}
    total = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs+files):
            path = Path(current)/name
            info = path.lstat()
            row = {'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                row.update(kind='link', target=os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                row.update(kind='dir')
            else:
                mode.need(stat.S_ISREG(info.st_mode) and info.st_size <= 2*1024**3, 'ordinary bounded staged file required')
                total += info.st_size
                row.update(kind='file', bytes=info.st_size, sha256=mode.digest(path))
            rows[path.relative_to(root).as_posix()] = row
            mode.need(len(rows) <= 200000 and total <= 16*1024**3 and mode.remaining() > 2, 'staged provenance resource bound')
    return {'schema': 1, 'scope': 'STAGED_PAYLOAD_DATA_ONLY', 'files': rows, 'file_bytes': total, 'runtime_qualification': False}


def write_inventory(root, destination):
    raw = mode.encode(inventory(root))
    mode.need(len(raw) <= mode.LOG_LIMIT, 'tree inventory JSON exceeds 64 MiB export cap')
    destination.write_bytes(raw)


def export_metadata(c, a, *, packaged=False):
    out = mode.OUT
    for source, target in ((Path('/work/tools/CMakeCache.txt'), 'tools-CMakeCache.txt'), (Path('/work/runtimes/CMakeCache.txt'), 'runtimes-CMakeCache.txt')):
        if source.is_file():
            (out/target).write_bytes(mode.read(source, mode.LOG_LIMIT))
    for name in ('prepared.json', 'built.json', 'checked.json'):
        source = mode.WORK/name
        if source.is_file():
            (out/name).write_bytes(mode.read(source))
    if (mode.WORK/'dest').is_dir():
        write_inventory(mode.WORK/'dest', out/'staged-tree.json')
    if packaged:
        package_root = mode.WORK/'recipe/pkg/cachy-asahi-llvm23-source-reference'
        mode.need(package_root.is_dir() and not package_root.is_symlink(), 'actual packaged tree missing')
        write_inventory(package_root, out/'packaged-tree.json')
    environment = {'schema': 1, 'mode': mode.MODE, 'operation': mode.OPERATION, 'admission_sha256': os.environ['ADMISSION_SHA256'], 'source': a['source'], 'run': a['run'], 'job': a['job'], 'image': a['image'], 'environment': mode.environment(), 'page_bytes': os.sysconf('SC_PAGE_SIZE'), 'native_acceptance': False, 'holds_preserved': True}
    (out/'environment.json').write_bytes(mode.encode(environment))


def output_namespace():
    rows = {}
    total = 0
    for path in sorted(mode.OUT.iterdir()):
        info = path.lstat()
        mode.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o111, 'flat regular non-executable output DATA required')
        limit = 2*1024**3 if path.name == mode.PACKAGE else mode.LOG_LIMIT
        mode.need(0 <= info.st_size <= limit and len(rows) < 64, 'output file count/size bound')
        total += info.st_size
        mode.need(total <= 4*1024**3, 'output aggregate cap')
        rows[path.name] = dict(bytes=info.st_size, sha256=mode.digest(path), mode=stat.S_IMODE(info.st_mode))
    return rows


def run():
    mode.need(sys.flags.isolated and not sys.flags.optimize, 'isolated unoptimized actor required')
    os.umask(0o022)
    c, a = mode.context()
    mode.need(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 1001, 'ordinary alarm1001 actor required')
    mode.need(Path.cwd() == Path('/work') and not any(mode.WORK.iterdir()), 'empty fresh work volume required')
    mode.need(mode.PREFIX.is_symlink() and os.readlink(mode.PREFIX) == '/work/dest/opt/cachy-asahi/llvm23-source-reference', 'exact bootstrap private-prefix symlink required')
    for name in ('home', 'tmp', 'dest', 'output', 'recipe'):
        (mode.WORK/name).mkdir(mode=0o700)
    (mode.WORK/'actor-clock.json').write_bytes(mode.encode({'schema': 1, 'deadline_monotonic': time.monotonic()+mode.ACTOR_SECONDS}))
    os.chdir(mode.WORK/'recipe')
    runtime = mode.module('llvm23_actual_runtime', HERE/'runtime.py')
    observed = dict(schema=1, admission_sha256=os.environ['ADMISSION_SHA256'], operation=mode.OPERATION, entry=runtime.context(), parent=runtime.context(1))
    (mode.OUT/'runtime.json').write_bytes(mode.encode(observed))
    runtime.validate(observed['entry'], observed['parent'])
    raw_admission = mode.read(mode.INPUTS/'admission.json')
    (mode.OUT/'admission.json').write_bytes(raw_admission)
    original = mode.read(mode.CANDIDATE/'PKGBUILD')
    effective = mode.transform_recipe(original)
    (mode.OUT/'PKGBUILD-original').write_bytes(original)
    (mode.OUT/'PKGBUILD-effective').write_bytes(effective)
    delta = dict(schema=1, mode=mode.MODE, original=mode.pin(original), effective=mode.pin(effective), old=mode.ORIGINAL_CALL, new=mode.CONTAINER_CALL, count=1, inverse='EXACT_LITERAL_REPLACEMENT_RESTORES_WHOLE_ORIGINAL', native_acceptance=False)
    (mode.OUT/'recipe-delta.json').write_bytes(mode.encode(delta))
    for name in c['candidate_files']:
        shutil.copyfile(mode.CANDIDATE/name, mode.WORK/'recipe'/name)
    (mode.WORK/'recipe/PKGBUILD').write_bytes(effective)
    archive = mode.INPUTS/'archive.tar.xz'
    mode.need(archive.stat().st_size == mode.ARCHIVE_BYTES and mode.digest(archive) == mode.ARCHIVE_SHA, 'exact read-only LLVM archive required')
    (mode.WORK/'recipe/llvm-project-23.1.1.src.tar.xz').symlink_to(archive)
    source_pins = dict(schema=1, archive=dict(bytes=mode.ARCHIVE_BYTES, sha256=mode.ARCHIVE_SHA), source_tree_sha256=a['source_tree_sha256'], candidate_files=c['candidate_files'], actor_files=c['actor_files'], owned_child=c['owned_child'], contract_sha256=a['contract_sha256'], source_map_sha256=a['source_map_sha256'], expected349_sha256=mode.EXPECTED349, mode=mode.MODE)
    (mode.OUT/'source-input.json').write_bytes(mode.encode(source_pins))
    base = mode.read(Path('/etc/makepkg.conf'))
    suffix = b'\n# LLVM23 container adapter: fixed private paths; no package installation.\nMAKEFLAGS="-j2"\nBUILDDIR=/work/recipe\nSRCDEST=/work/recipe\nPKGDEST=/work/output\nLOGDEST=/work/output\nPKGEXT=\'.pkg.tar.zst\'\nCOMPRESSZST=(zstd -c -T2 -9 -)\nPACKAGER="Cachy-Asahi private source reference"\n'
    config = base+suffix
    (mode.WORK/'makepkg.conf').write_bytes(config)
    (mode.OUT/'makepkg-base.conf').write_bytes(base)
    (mode.OUT/'makepkg-effective.conf').write_bytes(config)
    previous_env = dict(os.environ)
    previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    def cancel(number, frame):
        (mode.WORK/'cancelled').write_text(str(number)+'\n')
    result = dict(schema=1, status='FAIL_LLVM23_ACTOR', native_acceptance=False, mode=mode.MODE, admission_sha256=os.environ['ADMISSION_SHA256'], source=a['source'], run=a['run'], job=a['job'], image=a['image'])
    failure = None
    makepkg_completed = False
    try:
        for number in previous_handlers:
            signal.signal(number, cancel)
        child_environment = mode.environment()
        os.environ.clear()
        os.environ.update(child_environment)
        mode.command(['/usr/bin/pacman', '-Q'], 'packages-unsorted', 30)
        packages = mode.read(mode.OUT/'packages-unsorted.log')
        lock = ('\n'.join(sorted(packages.decode().splitlines()))+'\n').encode()
        mode.need(len(lock.decode().splitlines()) == 349 and mode.pin(lock)['sha256'] == mode.EXPECTED349, 'actual complete signed349 ALPM inventory differs')
        (mode.OUT/'packages.txt').write_bytes(lock)
        tools = tools_data()
        mode.command(['/usr/bin/pacman', '-Qqo', '--', *[row['path'] for row in tools]], 'tool-owners', 30)
        owners = mode.read(mode.OUT/'tool-owners.log').decode().splitlines()
        baseline = {line.split(' ', 1)[0]: line.split(' ', 1)[1] for line in lock.decode().splitlines()}
        mode.need(len(owners) == len(tools) and all(owner in baseline for owner in owners), 'every required tool needs an actual signed349 ALPM owner')
        for row, owner in zip(tools, owners):
            row.update(owner=owner, owner_version=baseline[owner])
        (mode.OUT/'tools.json').write_bytes(mode.encode(dict(schema=1, tools=tools, command_receipt='tool-owners.json', expected349_sha256=mode.EXPECTED349, scope='ACTUAL_PATH_BYTES_AND_ALPM_OWNERSHIP_ONLY_NOT_COMPILER_RUNTIME_QUALIFICATION')))
        mode.command(['/usr/bin/makepkg', '--config', '/work/makepkg.conf', '--cleanbuild', '--nosign', '--noconfirm', '--log'], 'makepkg', mode.MAKEPKG_SECONDS)
        makepkg_completed = True
        package = mode.OUT/mode.PACKAGE
        mode.need(package.is_file() and not package.is_symlink() and package.stat().st_size <= 2*1024**3, 'bounded exact package required')
        candidate = mode.pure_candidate()
        candidate.check_stage(mode.WORK/'dest')
        for member, name in (('.PKGINFO', 'PKGINFO'), ('.BUILDINFO', 'BUILDINFO')):
            mode.command(['/usr/bin/bsdtar', '-xOf', str(package), member], name.lower(), 60)
            shutil.copyfile(mode.OUT/(name.lower()+'.log'), mode.OUT/name)
        result.update(status='PASS_LLVM23_ACTOR_DATA', package=dict(bytes=package.stat().st_size, sha256=mode.digest(package)))
    except BaseException as error:
        failure = error
        result['failure'] = type(error).__name__+': '+str(error)[:2048]
    finally:
        try:
            export_metadata(c, a, packaged=makepkg_completed)
            result['output_files'] = output_namespace()
        except BaseException as error:
            result.update(status='FAIL_LLVM23_ACTOR', provenance_failure=type(error).__name__+': '+str(error)[:2048])
            if failure is None:
                failure = error
        (mode.OUT/'actor-result.json').write_bytes(mode.encode(result))
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        os.environ.clear()
        os.environ.update(previous_env)
    if failure is not None:
        raise failure
    return result


if __name__ == '__main__':
    run()
