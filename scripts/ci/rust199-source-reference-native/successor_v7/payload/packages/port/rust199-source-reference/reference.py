#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private, offline Rust reference recipe support. No fetch or host installation path."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tomllib

HERE = Path(__file__).resolve().parent
PREFIX = Path('/opt/cachy-asahi/rust199-source-reference')
LLVM_PREFIX = Path('/opt/cachy-asahi/llvm23-source-reference')
TARGET = 'aarch64-unknown-linux-gnu'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def is_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def load(path):
    require(path.is_file() and path.stat().st_size <= 4 * 1024**2, f'missing/oversized input: {path}')
    return json.loads(path.read_bytes())


def tree_digest(root):
    """Canonical ordered path/type/mode/content inventory; no symlink traversal."""
    require(root.is_dir() and not root.is_symlink(), 'tree root must be a real directory')
    h = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(directories + files):
            p = Path(current) / name
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                kind, content = 'link', os.readlink(p)
            elif stat.S_ISREG(mode):
                kind, content = 'file', digest(p)
            elif stat.S_ISDIR(mode):
                kind, content = 'dir', ''
            else:
                raise ValueError(f'special file forbidden in admitted image: {p}')
            h.update((json.dumps([p.relative_to(root).as_posix(), kind, stat.S_IMODE(mode), content], separators=(',', ':')) + '\n').encode())
    return h.hexdigest()


def admission(path, expected, inputs):
    require(is_digest(expected) and path.is_file() and digest(path) == expected, 'missing or changed explicit admission digest')
    a = load(path)
    require(a['schema'] == 1 and a['scope'] == 'PRIVATE_SOURCE_REFERENCE_INPUT_QUALIFICATION_ONLY', 'wrong admission scope')
    require(a['status'] == 'QUALIFIED_FOR_PRIVATE_BUILD_ONLY' and a['holds_preserved'] is True, 'inputs are unqualified; existing holds must remain')
    require(a['inputs_sha256'] == digest(inputs), 'admission is for different source inputs')
    require(a['environment']['native_target'] == TARGET and a['environment']['llvm_version'] == '23.1.1', 'wrong native LLVM environment')
    require(a['environment'].get('llvm_prefix') == str(LLVM_PREFIX), 'qualified private LLVM prefix required')
    require(a['stage0']['native_target'] == TARGET and a['stage0']['version'] == '1.98.0' and a['stage0']['compatibility'] == 'QUALIFIED_FOR_THIS_SOURCE', 'unqualified stage0 compatibility')
    for field in [a['environment']['tree_sha256'], a['stage0']['assembled_tree_sha256'], a['source_audit']['library_cargo_config_sha256']]:
        require(is_digest(field), 'missing fixed material digest')
    audit = a['source_audit']
    require(audit['status'] == 'REVIEWED_FOR_THIS_PRIVATE_BUILD' and all(audit[k] is True for k in ['consumed_git_dependencies_and_paths_reviewed', 'compiler_rt_libunwind_members_and_notices_reviewed', 'retained_source_authentication_rejoined']), 'source inputs need review; no inferred closure')
    proof = a['qualification_evidence']
    require(isinstance(proof, dict) and is_digest(proof.get('sha256')), 'missing qualification evidence')
    require(digest(Path(proof['path'])) == proof['sha256'], 'qualification evidence changed')
    return a


def nonroot_user(allow_fakeroot):
    if os.geteuid() != 0:
        return True
    if not allow_fakeroot:
        return False
    # fakeroot changes libc's UID answers, not the kernel's proc status.
    uids = next(line.split()[1:] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('Uid:'))
    return all(int(uid) != 0 for uid in uids)


def preflight(work, admission_path, expected, allow_fakeroot=False):
    require(os.environ.get('CACHY_ASAHI_RUST199_BUILD') == '1', 'explicit CACHY_ASAHI_RUST199_BUILD=1 required')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and nonroot_user(allow_fakeroot), 'non-root native aarch64 Linux required')
    require(work.is_dir() and not work.is_symlink() and work != Path('/'), 'invalid private work directory')
    inputs = HERE / 'inputs.json'
    a = admission(admission_path, expected, inputs)
    m = load(inputs)
    require(digest(HERE / 'bootstrap.toml') == m['bootstrap_config_sha256'], 'candidate configuration changed')
    image = Path(a['environment']['root'])
    require(image.is_absolute() and image != Path('/') and image.resolve() == image, 'explicit separate environment image required')
    require(work not in image.parents and image not in work.parents and image != work, 'image and writable work must be disjoint')
    require(not os.path.lexists(image / '.cargo') and not os.path.lexists(work / '.cargo'), 'ambient ancestor Cargo config forbidden')
    for name in ['work', 'stage0', 'proc', 'dev', 'tmp', 'usr/bin']:
        require((image / name).is_dir() and not (image / name).is_symlink(), f'image mount directory missing: {name}')
    for name in ['python', 'gcc', 'g++', 'gcc-ar', 'gcc-ranlib', 'cmake', 'ninja', 'make', 'pkg-config', 'perl', 'bash']:
        require(os.path.lexists(image / 'usr/bin' / name), f'qualified image tool missing: {name}')
    for name in ['llvm-config', 'clang', 'ld.lld']:
        require(os.path.lexists(image / LLVM_PREFIX.relative_to('/') / 'bin' / name), f'qualified private LLVM tool missing: {name}')
    require(tree_digest(image) == a['environment']['tree_sha256'], 'environment tree inventory changed')
    for name, pin in m['archives'].items():
        path = work / name
        require(path.is_file(), f'local material missing (no downloader): {name}')  # makepkg local-source symlinks are authenticated by content
        require(pin['bytes'] is None or path.stat().st_size == pin['bytes'], f'wrong material size: {name}')
        require(digest(path) == pin['sha256'], f'wrong material digest: {name}')
    require(Path('/usr/bin/bsdtar').is_file() and Path('/usr/bin/bwrap').is_file(), 'host bsdtar/bwrap unavailable; no fallback')
    return m, a, image


def source_config(path, rust):
    config = tomllib.loads(path.read_text())
    require(set(config) <= {'source', 'net'}, f'unreviewed Cargo configuration keys: {path}')
    sources = config.get('source', {})
    require('crates-io' in sources, f'missing crates-io replacement: {path}')
    for name in sources:
        current, seen = name, set()
        while 'replace-with' in sources[current]:
            require(current not in seen, 'Cargo replacement cycle')
            seen.add(current)
            current = sources[current]['replace-with']
            require(current in sources, 'unknown Cargo replacement')
        end = sources[current]
        require(set(end) == {'directory'}, 'all Cargo sources must terminate in a local directory')
        directory = (path.parent.parent / end['directory']).resolve()
        require(rust.resolve() in directory.parents and directory.is_dir(), 'Cargo vendor path escapes or is missing')


def check_vendor(directory):
    require(directory.is_dir() and not directory.is_symlink(), f'missing vendor directory: {directory}')
    packages = set()
    for crate in sorted(directory.iterdir()):
        require(crate.is_dir() and not crate.is_symlink(), 'unreviewed vendor entry')
        checksums = load(crate / '.cargo-checksum.json')
        declared = checksums['files']
        observed = set()
        for current, dirs, files in os.walk(crate):
            require(not any((Path(current) / n).is_symlink() for n in dirs), 'vendor directory symlink forbidden')
            for name in files:
                p = Path(current) / name
                relative = p.relative_to(crate).as_posix()
                require(not p.is_symlink() and p.is_file(), 'vendor nonregular file forbidden')
                if relative == '.cargo-checksum.json':
                    continue
                observed.add(relative)
                require(relative in declared and digest(p) == declared[relative], f'vendor checksum mismatch: {p}')
        require(observed == set(declared), f'vendor file set differs: {crate}')
        package = tomllib.loads((crate / 'Cargo.toml').read_text())['package']
        packages.add((package['name'], package['version'], checksums['package']))
    require(packages, 'empty vendor set')
    return packages


def check_sources(work, m, a):
    rust = work / 'rustc-1.99.0-src'
    llvm = work / 'llvm-project-23.1.1.src'
    require(not os.path.lexists(rust / '.git') and (rust / 'git-commit-info').read_text().splitlines()[0] == m['rust_commit'], 'release commit stamp/source mode differs')
    for name, expected in m['source_member_sha256'].items():
        require(digest(rust / name) == expected, f'pinned source member differs: {name}')
    require(digest(rust / 'library/.cargo/config.toml') == a['source_audit']['library_cargo_config_sha256'], 'library Cargo configuration differs')
    for name in ['compiler-rt/lib/builtins', 'compiler-rt/lib/profile', 'libunwind/src']:
        require((llvm / name).is_dir() and any((llvm / name).iterdir()), f'required LLVM source path missing: {name}')
    for name in ['compiler-rt/LICENSE.TXT', 'libunwind/LICENSE.TXT']:
        require((llvm / name).is_file(), f'required LLVM notice missing: {name}')
    for name in ['x.py', 'library/backtrace/src/lib.rs', 'src/tools/cargo/Cargo.toml', 'src/tools/rustfmt/Cargo.toml', 'src/tools/clippy/Cargo.toml']:
        require((rust / name).is_file(), f'active Rust source missing: {name}')
    for path in [rust / '.cargo/config.toml', rust / 'library/.cargo/config.toml']:
        source_config(path, rust)
    packages = check_vendor(rust / 'vendor') | check_vendor(rust / 'library/vendor')
    for name in ['Cargo.lock', 'src/tools/cargo/Cargo.lock', 'src/bootstrap/Cargo.lock', 'library/Cargo.lock']:
        for package in tomllib.loads((rust / name).read_text())['package']:
            if package.get('source', '').startswith('registry+'):
                require((package['name'], package['version'], package['checksum']) in packages, f'lock dependency absent from vendor: {name}: {package["name"]}')
    return rust, llvm


def prepare(work, m, a):
    for name in ['rustc-1.99.0-src', 'llvm-project-23.1.1.src', 'stage0', 'stage0-unpack', 'verified-materials', 'reference-sandbox.py', 'dest', 'home', 'cargo-home', 'prepared.json', 'built.json']:
        require(not (work / name).exists(), f'clean private work required: {name}')
    materials = work / 'verified-materials'
    materials.mkdir()
    for name, pin in m['archives'].items():
        shutil.copyfile(work / name, materials / name)
        require(digest(materials / name) == pin['sha256'], f'copied local material changed: {name}')
    shutil.copyfile(HERE / 'reference.py', work / 'reference-sandbox.py')
    unpack = work / 'stage0-unpack'
    unpack.mkdir()
    stage0 = work / 'stage0'
    stage0.mkdir()
    for name, pin in m['archives'].items():
        destination = unpack if pin['role'] == 'stage0' else work
        subprocess.run(['/usr/bin/bsdtar', '--no-same-owner', '--no-same-permissions', '-xf', str(materials / name), '-C', str(destination)], check=True)
        if pin['role'] == 'stage0':
            component = unpack / pin['archive_root'] / pin['component']
            require(component.is_dir() and not component.is_symlink(), 'admitted stage0 component layout differs')
            for item in component.iterdir():
                if item.name == 'manifest.in':
                    continue
                target = stage0 / item.name
                if item.is_dir() and not item.is_symlink():
                    shutil.copytree(item, target, symlinks=True, dirs_exist_ok=True)
                else:
                    require(not target.exists(), 'stage0 component collision')
                    shutil.copy2(item, target, follow_symlinks=False)
    require(tree_digest(stage0) == a['stage0']['assembled_tree_sha256'], 'assembled stage0 differs from qualified image')
    for binary in ['rustc', 'cargo', 'rustdoc']:
        require((stage0 / 'bin' / binary).is_file(), f'missing stage0 binary: {binary}')
    require((stage0 / f'lib/rustlib/{TARGET}/lib').is_dir(), 'missing matching stage0 standard library')
    rust, llvm = check_sources(work, m, a)
    link = rust / 'src/llvm-project'
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        shutil.rmtree(link)
    link.symlink_to(os.path.relpath(llvm, link.parent))
    shutil.copyfile(HERE / 'bootstrap.toml', rust / 'bootstrap.toml')
    for name in ['home', 'cargo-home', 'dest']:
        (work / name).mkdir()
    (work / 'prepared.json').write_text(json.dumps({'admission_sha256': os.environ['CACHY_ASAHI_RUST199_ADMISSION_SHA256'], 'config_sha256': digest(HERE / 'bootstrap.toml')}, sort_keys=True) + '\n')


def sandbox_command(work, image, command):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--ro-bind', str(image), '/', '--bind', str(work), '/work', '--ro-bind', str(work / 'stage0'), '/stage0', '--ro-bind', str(work / 'stage0'), '/work/stage0', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--clearenv', '--setenv', 'PATH', f'/stage0/bin:{LLVM_PREFIX}/bin:/usr/bin:/bin', '--setenv', 'HOME', '/work/home', '--setenv', 'CARGO_HOME', '/work/cargo-home', '--setenv', 'LIBGIT2_NO_VENDOR', '1', '--setenv', 'LIBSSH2_SYS_USE_PKG_CONFIG', '1', '--setenv', 'LIBSQLITE3_SYS_USE_PKG_CONFIG', '1', '--setenv', 'CARGO_NET_OFFLINE', 'true', '--setenv', 'CACHY_ASAHI_RUST199_STAGE0_SHA256', tree_digest(work / 'stage0'), '--setenv', 'LC_ALL', 'C', '--setenv', 'TZ', 'UTC', '--setenv', 'DESTDIR', '/work/dest', '--chdir', '/work/rustc-1.99.0-src', '--', *command]


def probe():
    expected = os.environ.get('CACHY_ASAHI_RUST199_STAGE0_SHA256')
    require(is_digest(expected) and tree_digest(Path('/stage0')) == expected, 'internal sandbox probe requires qualified stage0 inventory')
    def output(args):
        return subprocess.check_output(args, text=True).strip()
    require('release: 1.98.0' in output(['/stage0/bin/rustc', '-vV']).splitlines() and f'host: {TARGET}' in output(['/stage0/bin/rustc', '-vV']).splitlines(), 'stage0 version/host differs')
    require(output(['/stage0/bin/rustc', '--print', 'sysroot']) == '/stage0', 'stage0 sysroot differs')
    require(output(['/stage0/bin/cargo', '--version']).startswith('cargo 1.98.0 '), 'initial Cargo version differs')
    require(output(['/stage0/bin/rustdoc', '--version']).startswith('rustdoc 1.98.0 '), 'initial rustdoc version differs')
    require(output([str(LLVM_PREFIX / 'bin/llvm-config'), '--version']) == '23.1.1', 'external LLVM version differs')
    require('AArch64' in output([str(LLVM_PREFIX / 'bin/llvm-config'), '--targets-built']).split(), 'LLVM lacks AArch64 target')
    gcc = output(['/usr/bin/gcc', '-dumpmachine'])
    require(gcc.startswith('aarch64-') and gcc.endswith('linux-gnu'), 'native GCC target differs')
    require('23.1.1' in output([str(LLVM_PREFIX / 'bin/ld.lld'), '--version']), 'external LLD version differs')


def build(work, m, a, image):
    receipt = load(work / 'prepared.json')
    require(receipt['admission_sha256'] == os.environ['CACHY_ASAHI_RUST199_ADMISSION_SHA256'], 'prepared admission changed')
    require(receipt['config_sha256'] == digest(HERE / 'bootstrap.toml') == digest(work / 'rustc-1.99.0-src/bootstrap.toml'), 'prepared config changed')
    require(tree_digest(work / 'stage0') == a['stage0']['assembled_tree_sha256'], 'stage0 tree changed')
    check_sources(work, m, a)
    require((work / 'rustc-1.99.0-src/src/llvm-project').resolve() == work / 'llvm-project-23.1.1.src', 'LLVM source join changed')
    subprocess.run(sandbox_command(work, image, ['/usr/bin/python', '-I', '/work/reference-sandbox.py', 'probe']), check=True)
    subprocess.run(sandbox_command(work, image, ['/usr/bin/python', '-I', './x.py', '--config', 'bootstrap.toml', 'install', '-j', '2']), check=True)
    check_stage(work / 'dest')
    (work / 'built.json').write_text(json.dumps({'admission_sha256': receipt['admission_sha256'], 'config_sha256': receipt['config_sha256'], 'staged_tree_sha256': tree_digest(work / 'dest')}, sort_keys=True) + '\n')


def check_stage(root):
    require(root.is_dir() and not root.is_symlink(), 'staging root must be a real directory')
    prefix = root / PREFIX.relative_to('/')
    require(prefix.is_dir(), 'missing private staged prefix')
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(current) / name
            require(p == prefix or prefix in p.parents or (p.is_dir() and p in prefix.parents), f'payload escaped private prefix: {p}')
            if p.is_symlink():
                target = os.readlink(p)
                require(not target.startswith('/') and prefix in (p.parent / target).resolve().parents, 'staged symlink escapes prefix')
    for name in ['bin/rustc', 'bin/cargo', 'bin/rustdoc', 'bin/rustfmt', 'bin/clippy-driver', 'libexec/rust-analyzer-proc-macro-srv', 'lib/rustlib/src/rust/library/Cargo.toml']:
        path = prefix / name
        require(path.is_file(), f'requested component missing: {name}')
        if name.startswith(('bin/', 'libexec/')):
            require(path.stat().st_mode & 0o111, f'component is not executable: {name}')


def package(work, destination):
    require(destination.is_absolute() and not destination.is_symlink() and destination not in [Path('/'), work, HERE] and work.parent != Path('/') and work.parent in destination.parents and work not in destination.parents and destination.resolve() == destination and not list(destination.iterdir()), 'empty separate package staging directory required')
    receipt = load(work / 'built.json')
    require(receipt['admission_sha256'] == os.environ.get('CACHY_ASAHI_RUST199_ADMISSION_SHA256') and receipt['config_sha256'] == digest(HERE / 'bootstrap.toml'), 'built input binding differs')
    require(receipt['staged_tree_sha256'] == tree_digest(work / 'dest'), 'built stage changed')
    check_stage(work / 'dest')
    shutil.copytree(work / 'dest', destination, symlinks=True, dirs_exist_ok=True)
    prefix = destination / PREFIX.relative_to('/')
    ledger = prefix / 'lib/rustlib'
    for path in [ledger / n for n in ['components', 'install.log', 'rust-installer-version', 'uninstall.sh']] + list(ledger.glob('manifest-*')):
        if path.is_file() and not path.is_symlink():
            path.unlink()
    notices = prefix / 'share/licenses/rust199-source-reference'
    notices.mkdir(parents=True, exist_ok=True)
    rust = work / 'rustc-1.99.0-src'
    for name in ['COPYRIGHT', 'LICENSE-MIT', 'LICENSE-APACHE']:
        shutil.copyfile(rust / name, notices / name)
    for component in ['compiler-rt', 'libunwind']:
        shutil.copyfile(work / f'llvm-project-23.1.1.src/{component}/LICENSE.TXT', notices / f'{component}-LICENSE.TXT')
    for name in ['inputs.json', 'LICENSE.packaging']:
        shutil.copyfile(HERE / name, notices / name)
    # Preserve complete authenticated files containing catalogue notice contexts.
    import importlib.util
    notice_helper = HERE / 'notice_preservation.py'
    require(digest(notice_helper) == '07b193b850b28d93a04672e8586a63549168766314dc0b4ab291038bf928c774', 'notice preservation helper changed')
    spec = importlib.util.spec_from_file_location('rust199_notice_preservation', notice_helper)
    notice_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(notice_module)
    notice_module.stage(work / 'verified-materials/rustc-1.99.0-src.tar.xz',
                        HERE / 'notice-catalogue.DATA.json', notices / 'source-notices',
                        '515d3ec9add3b04ac1bde8b6de150c28525fd3262c92223ca0444c6fd8af3df3')
    check_stage(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['preflight', 'prepare', 'build', 'package', 'probe', 'inventory'])
    parser.add_argument('--work', type=Path, default=HERE)
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.action == 'inventory':
        print(tree_digest(args.work))
    elif args.action == 'probe':
        probe()
    else:
        work = args.work.resolve()
        path = os.environ.get('CACHY_ASAHI_RUST199_ADMISSION', '')
        expected = os.environ.get('CACHY_ASAHI_RUST199_ADMISSION_SHA256', '')
        m, a, image = preflight(work, Path(path), expected, allow_fakeroot=args.action == 'package')
        if args.action == 'prepare':
            prepare(work, m, a)
        elif args.action == 'build':
            build(work, m, a, image)
        elif args.action == 'package':
            require(args.destination is not None, 'package destination required')
            package(work, args.destination)
        print(f'{args.action}: input checks passed; no release/hardware/license acceptance implied')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        sys.exit(2)
