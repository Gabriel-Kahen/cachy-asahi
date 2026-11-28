#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in, offline native LLVM reference build; never install on the host."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREFIX = Path('/opt/cachy-asahi/llvm23-source-reference')
SOURCE = 'llvm-project-23.1.1.src'
TARGET = 'aarch64-unknown-linux-gnu'
ENV = 'CACHY_ASAHI_LLVM23_'
GIB = 1024**3
ET_REL, ET_EXEC, ET_DYN = 1, 2, 3
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_FLAGS_1, DF_1_PIE = 0x6ffffffb, 0x08000000


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def is_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def load(path):
    need(path.is_file() and path.stat().st_size <= 4*1024**2, f'missing/oversized JSON: {path}')
    return json.loads(path.read_bytes())


def tree_digest(root):
    """Same ordered path/type/mode/content inventory as rust199 reference.py."""
    need(root.is_dir() and not root.is_symlink(), 'real inventory root required')
    h = hashlib.sha256()
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            p = Path(current) / name
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                kind, content = 'link', os.readlink(p)
            elif stat.S_ISREG(mode):
                kind, content = 'file', digest(p)
            elif stat.S_ISDIR(mode):
                kind, content = 'dir', ''
            else:
                raise ValueError(f'special file forbidden: {p}')
            h.update((json.dumps([p.relative_to(root).as_posix(), kind, stat.S_IMODE(mode), content], separators=(',', ':'))+'\n').encode())
    return h.hexdigest()


def ordinary(path):
    return path.is_absolute() and path.resolve() == path and not any(p.is_symlink() for p in (path, *path.parents))


def helper(relative, pins):
    path = ROOT / relative
    pin = pins['helpers'][relative]
    need(ordinary(path) and path.is_file() and digest(path) == pin['sha256'], f'changed helper: {relative}')
    spec = importlib.util.spec_from_file_location('llvm23_'+path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admission(path, expected, pins):
    need(is_digest(expected) and path.is_file() and digest(path) == expected, 'explicit admission SHA256 required')
    a = load(path)
    need(a['schema'] == 1 and a['scope'] == 'LLVM23_PRIVATE_SOURCE_REFERENCE_INPUTS', 'wrong qualification scope')
    need(a['status'] == 'QUALIFIED_FOR_PRIVATE_BUILD_ONLY' and a['holds_preserved'] is True, 'inputs remain unqualified')
    need(a['inputs_sha256'] == digest(HERE/'inputs.json'), 'different candidate inputs')
    need(a['native_target'] == TARGET and a['page_size'] in (4096, 16384), 'native AArch64 geometry required')
    for value in (a['environment']['tree_sha256'], a['source']['tree_sha256']):
        need(is_digest(value), 'qualified image/source inventory missing')
    need(a['source']['archive_sha256'] == pins['archive']['sha256'], 'different qualified archive')
    need(all(a['source'][key] is True for key in ('authentication_rejoined', 'consumed_paths_and_notices_reviewed', 'no_downloads_reviewed')), 'source consumption review missing')
    evidence = a['qualification_evidence']
    need(is_digest(evidence['sha256']) and digest(Path(evidence['path'])) == evidence['sha256'], 'qualification evidence missing or changed')
    need(a['resources']['dedicated_cgroup'] is True, 'externally assigned dedicated cgroup required')
    return a


def resource_check(work, a, pins):
    """Read existing limits only; no reservation, cgroup creation or writes."""
    rows = Path('/proc/self/cgroup').read_text().splitlines()
    need(len(rows) == 1 and rows[0].startswith('0::/'), 'unified cgroup v2 required')
    relative = rows[0][3:]
    need(relative != '/' and '..' not in Path(relative).parts, 'dedicated non-root cgroup required')
    group = Path('/sys/fs/cgroup') / relative.lstrip('/')
    need(str(group) == a['resources']['cgroup'], 'assigned cgroup differs')
    expected = {'memory.max': str(8*GIB), 'memory.swap.max': '0', 'cpu.max': '200000 100000', 'pids.max': '512'}
    for key, value in expected.items():
        need((group/key).read_text().strip() == value, f'cgroup bound differs: {key}')
    available = int(next(s.split()[1] for s in Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
    need(available >= 12*GIB, '8 GiB build plus 4 GiB host memory reserve unavailable')
    capacity = helper('scripts/update/capacity.py', pins)
    # Includes extracted source, two build trees, staged/package copies and reserve.
    capacity.check([{'path':work, 'bytes':64*GIB, 'inodes':600000}])


def preflight(work, path, expected, packaging=False):
    need(os.environ.get(ENV+'BUILD') == '1', 'explicit CACHY_ASAHI_LLVM23_BUILD=1 required')
    uids = next(s.split()[1:] for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('Uid:'))
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and all(int(n) != 0 for n in uids), 'non-root native AArch64 Linux required')
    need(packaging or os.geteuid() != 0, 'real non-root build required')
    need(ordinary(work) and work.is_dir() and work != Path('/') and work != HERE, 'separate ordinary work required')
    pins = load(HERE/'inputs.json')
    for name, pin in pins['files'].items():
        need(digest(HERE/name) == pin, f'changed candidate input: {name}')
    a = admission(path, expected, pins)
    need(os.sysconf('SC_PAGE_SIZE') == a['page_size'], 'qualified native page size differs')
    image = Path(a['environment']['root'])
    need(ordinary(image) and image != Path('/') and image != work and image not in work.parents and work not in image.parents, 'disjoint ordinary image/work required')
    check_environment(image, a, pins)
    for relative, pin in pins['evidence'].items():
        need(digest(ROOT/relative) == pin, f'retained source evidence changed: {relative}')
    auth = load(ROOT/pins['authentication_report'])['source_signatures']['llvm']
    need(auth['signature_mathematics'] == 'PASS' and auth['archive']['sha256'] == pins['archive']['sha256'], 'retained LLVM authentication join failed')
    archive = work/pins['archive']['filename']
    need(archive.is_file() and archive.stat().st_size == pins['archive']['bytes'] and digest(archive) == pins['archive']['sha256'], 'exact local LLVM archive required; no downloader')
    need(Path('/usr/bin/bwrap').is_file(), 'bubblewrap required; no unsandboxed fallback')
    resource_check(work, a, pins)
    return pins, a, image


def check_environment(image, a, pins):
    for name in ('work', 'source', 'proc', 'dev', 'tmp', str(PREFIX.relative_to('/'))):
        p = image/name
        need(p.is_dir() and not p.is_symlink(), f'image mount directory missing: {name}')
    need(not any((image/PREFIX.relative_to('/')).iterdir()), 'image private-prefix mountpoint must be empty')
    for name in pins['environment_tools']:
        tool = image/'usr/bin'/name
        need(tool.is_file() and tool.stat().st_mode & 0o111 and image in tool.resolve().parents, f'image tool missing/escaping: {name}')
    packages = a['environment']['packages']
    need(all(isinstance(packages.get(name), str) and packages[name].strip() for name in pins['environment_development']), 'exact development package versions required')
    development = a['environment']['development_files']
    need(set(development) == set(pins['development_roles']), 'qualified header/CRT/library roles incomplete')
    for role, row in development.items():
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'development path escapes image')
        file = image/relative
        need(image in file.resolve().parents and file.is_file() and is_digest(row['sha256']) and digest(file) == row['sha256'], f'missing/changed development input: {role}')
    need(tree_digest(image) == a['environment']['tree_sha256'], 'qualified image changed')


def sandbox(work, image, command, source=False, private=False):
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--ro-bind', str(image), '/', '--bind', str(work), '/work', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--clearenv', '--setenv', 'PATH', str(PREFIX/'bin')+':/usr/bin:/bin', '--setenv', 'HOME', '/work/home', '--setenv', 'LC_ALL', 'C', '--setenv', 'TZ', 'UTC', '--setenv', 'TMPDIR', '/tmp', '--chdir', '/work']
    if source:
        argv += ['--ro-bind', str(work/SOURCE), '/source', '--ro-bind', str(work/SOURCE), '/work/'+SOURCE]
    if (work/'reference-build.sh').is_file():
        argv += ['--ro-bind', str(work/'reference-build.sh'), '/work/reference-build.sh']
    if private:
        argv += ['--ro-bind', str(work/'dest'/PREFIX.relative_to('/')), str(PREFIX)]
    return argv + ['--', *command]


def run(work, pins, a, image, command, label, **mounts):
    resource_check(work, a, pins)
    owned = helper('scripts/ci/perl5423-native-namespace/helpers/owned_child.py', pins)
    logs = work/'logs'
    logs.mkdir(exist_ok=True)
    row = {}
    try:
        with (logs/(label+'.log')).open('xb') as log:
            owned.run(sandbox(work, image, command, **mounts), timeout=3600, stdout=log, stderr=subprocess.STDOUT, check=True, lifecycle=row, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, stdout_limit=32*1024**2)
        need(row.get('retirement') == 'REAPED' and row.get('group_absent'), 'owned command retirement unverified')
    finally:
        (logs/(label+'.json')).write_text(json.dumps(row, sort_keys=True)+'\n')


def prepare(work, pins, a, image):
    for name in (SOURCE, 'home', 'dest', 'tools', 'runtimes', 'logs', 'reference-build.sh', 'material.tar.xz', 'prepared.json', 'built.json', 'checked.json'):
        need(not os.path.lexists(work/name), f'fresh work required: {name}')
    shutil.copyfile(work/pins['archive']['filename'], work/'material.tar.xz')
    need(digest(work/'material.tar.xz') == pins['archive']['sha256'], 'copied source changed')
    shutil.copyfile(HERE/'build.sh', work/'reference-build.sh')
    for name in ('home', 'dest'):
        (work/name).mkdir()
    run(work, pins, a, image, ['/usr/bin/bsdtar', '--no-same-owner', '--no-same-permissions', '-xf', '/work/material.tar.xz', '-C', '/work'], 'extract')
    need(tree_digest(work/SOURCE) == a['source']['tree_sha256'], 'extracted source differs from qualified inventory')
    for component in ('llvm', 'clang', 'lld', 'compiler-rt', 'libunwind', 'runtimes', 'cmake'):
        need((work/SOURCE/component/'CMakeLists.txt').is_file() or component == 'cmake' and (work/SOURCE/component).is_dir(), f'source component missing: {component}')
    for component, expected in pins['notices'].items():
        need(digest(work/SOURCE/component/'LICENSE.TXT') == expected, f'notice differs: {component}')
    (work/'prepared.json').write_text(json.dumps({'admission_sha256':os.environ[ENV+'ADMISSION_SHA256'], 'build_sha256':digest(HERE/'build.sh')})+'\n')


def binding(work, a):
    row = load(work/'prepared.json')
    need(row['admission_sha256'] == os.environ[ENV+'ADMISSION_SHA256'] and row['build_sha256'] == digest(HERE/'build.sh') == digest(work/'reference-build.sh'), 'prepared input binding changed')
    need(tree_digest(work/SOURCE) == a['source']['tree_sha256'], 'prepared source changed')
    return row


def elf(path, prefix=None, *, role=None):
    """Check the ELF role and load geometry without executing the file."""
    with path.open('rb') as stream:
        header = stream.read(64)
        if header[:4] != b'\x7fELF':
            return False
        need(len(header) == 64 and header[4:6] == b'\x02\x01', f'ELF64 LE required: {path}')
        kind, machine = struct.unpack_from('<HH', header, 16)
        need(machine == 183, f'non-AArch64 ELF: {path}')
        if kind not in (ET_REL, ET_EXEC, ET_DYN) or (role == 'library' and kind != ET_DYN):
            return False
        if kind == ET_REL:
            return role is None
        offset = struct.unpack_from('<Q', header, 32)[0]
        width, count = struct.unpack_from('<HH', header, 54)
        file_size = os.fstat(stream.fileno()).st_size
        need(width == 56 and 0 < count <= 1024 and 64 <= offset <= file_size-width*count, 'invalid program headers')
        stream.seek(offset)
        loads, dynamic, interpreters = [], None, []
        for _ in range(count):
            row = struct.unpack('<IIQQQQQQ', stream.read(width))
            segment_type, _, file_offset, vaddr, _, filesz, memsz, alignment = row
            if segment_type in (PT_LOAD, PT_DYNAMIC, PT_INTERP):
                need(file_offset+filesz <= file_size, f'ELF segment bounds refused: {path}')
            if segment_type == PT_LOAD:
                loads.append(row)
                need(filesz <= memsz, f'invalid PT_LOAD file/memory size: {path}')
                need(alignment >= 16384 and alignment & (alignment-1) == 0
                     and file_offset % alignment == vaddr % alignment, f'16K PT_LOAD geometry refused: {path}')
            elif segment_type == PT_DYNAMIC:
                need(dynamic is None, f'duplicate ELF dynamic segment: {path}')
                dynamic = row
            elif segment_type == PT_INTERP:
                interpreters.append(row)
        need(loads, f'ELF lacks PT_LOAD: {path}')
        entries = []
        if dynamic and (prefix is not None or role is not None):
            need(0 < dynamic[5] <= 1024**2 and dynamic[5] % 16 == 0, 'dynamic table bound')
            stream.seek(dynamic[2])
            entries = [struct.unpack('<qQ', stream.read(16)) for _ in range(dynamic[5]//16)]
            end = next((i for i,r in enumerate(entries) if r[0] == 0), None)
            need(end is not None, 'dynamic table terminator missing')
            entries = entries[:end]
        if role is not None:
            need(len(interpreters) <= 1, f'duplicate ELF interpreter segment: {path}')
            pie = any(tag == DT_FLAGS_1 and value & DF_1_PIE for tag, value in entries)
            if role == 'library' and (interpreters or pie):
                return False
            if role == 'tool':
                if kind == ET_DYN and not (interpreters or pie):
                    return False
                if pie:
                    _, _, start, address, _, size, _, _ = dynamic
                    need(any(r[3] <= address and address+size <= r[3]+r[5]
                             and start == r[2]+address-r[3] for r in loads),
                         f'ELF PIE flags outside file-backed PT_LOAD: {path}')
                if interpreters:
                    _, _, start, _, _, size, _, _ = interpreters[0]
                    need(2 <= size <= 4096, f'ELF interpreter length refused: {path}')
                    stream.seek(start)
                    name = stream.read(size)
                    need(len(name) == size and name.startswith(b'/') and name.endswith(b'\0')
                         and b'\0' not in name[:-1], f'ELF interpreter path refused: {path}')
                entry = struct.unpack_from('<Q', header, 24)[0]
                need(entry and any(r[1] & 1 and r[3] <= entry < r[3]+r[5] for r in loads),
                     f'ELF tool entry outside executable file-backed PT_LOAD: {path}')
        if dynamic and prefix is not None:
            table = next((v for k,v in entries if k == 5), None)
            size = next((v for k,v in entries if k == 10), 0)
            need(table is not None and 0 < size <= 16*1024**2, 'dynamic string table bound')
            segment = next((r for r in loads if r[3] <= table and table+size <= r[3]+r[5]), None)
            need(segment is not None, 'dynamic strings outside file-backed PT_LOAD')
            stream.seek(segment[2]+table-segment[3])
            strings = stream.read(size)
            def string(index):
                need(index < len(strings) and b'\0' in strings[index:], 'invalid dynamic string')
                return strings[index:strings.index(b'\0', index)].decode()
            needed = [string(v) for k,v in entries if k == 1]
            paths = [p for k,v in entries if k in (15,29) for p in string(v).split(':')]
            resolved = []
            for item in paths:
                need(item and '/work' not in item and '/source' not in item, 'non-private build RPATH')
                expanded = item.replace('${ORIGIN}', str(path.parent)).replace('$ORIGIN', str(path.parent))
                if expanded.startswith(str(PREFIX)):
                    expanded = str(prefix)+expanded[len(str(PREFIX)):]
                target = Path(expanded).resolve()
                need('$' not in expanded and (target == prefix or prefix in target.parents), 'RPATH escapes private prefix')
                resolved.append(target)
            if any(n.startswith('libLLVM') for n in needed):
                need(prefix/'lib' in resolved, 'shared LLVM consumer lacks private library RPATH')
    return True


def check_stage(root):
    need(root.is_dir() and not root.is_symlink(), 'real stage root required')
    prefix = root/PREFIX.relative_to('/')
    need(prefix.is_dir() and not prefix.is_symlink(), 'private prefix missing')
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs+files:
            p = Path(current)/name
            need(p == prefix or prefix in p.parents or p.is_dir() and p in prefix.parents, f'payload outside private prefix: {p}')
            if p.is_symlink():
                target = os.readlink(p)
                need(not target.startswith('/') and prefix in (p.parent/target).resolve().parents and p.exists(), f'escaping/broken symlink: {p}')
            elif p.is_file():
                elf(p, prefix)
            else:
                need(p.is_dir(), f'special payload forbidden: {p}')
    for name in ('bin/llvm-config', 'bin/clang', 'bin/clang++', 'bin/ld.lld', 'bin/llvm-ar', 'bin/llvm-ranlib', 'lib/cmake/llvm/LLVMConfig.cmake', 'lib/libunwind.a'):
        p = prefix/name
        need(p.is_file(), f'required staged component missing: {name}')
        if name.startswith('bin/'):
            need(p.stat().st_mode & 0o111 and elf(p, prefix, role='tool'), f'native executable required: {name}')
    for pattern in ('lib/libLLVM*.so*', 'lib/libunwind.so*', 'lib/clang/23/lib/linux/libclang_rt.builtins-aarch64.a', 'lib/clang/23/lib/linux/libclang_rt.profile-aarch64.a'):
        matches = list(prefix.glob(pattern))
        need(matches, f'required runtime missing: {pattern}')
        for p in matches:
            if '.so' in p.name:
                need(elf(p, prefix, role='library'), f'native shared library required: {p}')
            else:
                with p.open('rb') as stream:
                    need(stream.read(8) == b'!<arch>\n', f'static runtime archive required: {p}')


def build(work, pins, a, image):
    receipt = binding(work, a)
    need(not any((work/n).exists() for n in ('tools','runtimes','built.json','checked.json')), 'fresh build required')
    run(work, pins, a, image, ['/usr/bin/bash', '/work/reference-build.sh', 'probe'], 'probe', source=True)
    run(work, pins, a, image, ['/usr/bin/bash', '/work/reference-build.sh', 'tools'], 'tools', source=True)
    run(work, pins, a, image, ['/usr/bin/bash', '/work/reference-build.sh', 'runtimes'], 'runtimes', source=True, private=True)
    check_stage(work/'dest')
    (work/'built.json').write_text(json.dumps({**receipt,'staged_tree_sha256':tree_digest(work/'dest')})+'\n')


def check(work, pins, a, image):
    receipt = binding(work, a)
    built = load(work/'built.json')
    need(all(built[k] == v for k,v in receipt.items()) and built['staged_tree_sha256'] == tree_digest(work/'dest'), 'built stage binding differs')
    check_stage(work/'dest')
    run(work, pins, a, image, ['/usr/bin/bash','/work/reference-build.sh','check'], 'check', source=True, private=True)
    (work/'checked.json').write_text(json.dumps(built)+'\n')


def package(work, destination, a):
    receipt = binding(work, a)
    checked = load(work/'checked.json')
    need(all(checked[k] == v for k,v in receipt.items()) and checked['staged_tree_sha256'] == tree_digest(work/'dest'), 'checked stage binding differs')
    need(ordinary(destination) and destination.is_dir() and not list(destination.iterdir()) and work.parent in destination.parents and work not in destination.parents and destination != work.parent, 'empty separate package staging required')
    check_stage(work/'dest')
    shutil.copytree(work/'dest', destination, symlinks=True, dirs_exist_ok=True)
    notices = destination/PREFIX.relative_to('/')/'share/licenses/llvm23-source-reference'
    notices.mkdir(parents=True, exist_ok=True)
    for component in ('llvm','clang','lld','compiler-rt','libunwind'):
        shutil.copyfile(work/SOURCE/component/'LICENSE.TXT', notices/(component+'-LICENSE.TXT'))
    for name in ('LICENSE.packaging','inputs.json','build.sh'):
        shutil.copyfile(HERE/name, notices/name)
    check_stage(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight','prepare','build','check','package','inventory'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.action == 'inventory':
        print(tree_digest(args.work))
        return
    need(ordinary(args.work), 'ordinary absolute work path required')
    pins, a, image = preflight(args.work, Path(os.environ.get(ENV+'ADMISSION','')), os.environ.get(ENV+'ADMISSION_SHA256',''), packaging=args.action == 'package')
    if args.action == 'prepare':
        prepare(args.work, pins, a, image)
    elif args.action == 'build':
        build(args.work, pins, a, image)
    elif args.action == 'check':
        check(args.work, pins, a, image)
    elif args.action == 'package':
        need(args.destination is not None, 'package destination required')
        package(args.work, args.destination, a)
    print(args.action+': completed; no source-to-binary/release/hardware acceptance implied')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, struct.error, subprocess.SubprocessError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        sys.exit(2)
