#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build-only generic 16KiB ARM64 kernel; never install or change host configuration."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent
ARCHIVE_SHA = '874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'
ARCHIVE_BYTES = 262965559
ARCHIVE_ROOT = 'linux-asahi-7.1.13-3'
COMMIT = '94fb23346d522edf53722357c426a3e58030beea'
TOOLS = ('make', 'clang', 'clang++', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-strip',
         'llvm-objcopy', 'llvm-objdump', 'llvm-readelf', 'bison', 'flex', 'bc', 'perl', 'sh')
TOTAL_LIMIT = 16 * 1024**3
DIAGNOSTIC_FRAGMENT = 'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\n'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    path = Path(path).resolve(strict=True)
    require(path.is_file(), 'regular input required')
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def config_check(path, boot_diagnostics=False):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            values[key] = value
    expected = (HERE / 'kernel.fragment').read_text()
    if boot_diagnostics:
        expected += DIAGNOSTIC_FRAGMENT
    for line in expected.splitlines():
        key, value = line.split('=', 1)
        require(values.get(key, 'n') == value, 'generated configuration differs: ' + key)
    require(values.get('CONFIG_ARM64_4K_PAGES', 'n') == 'n' and
            values.get('CONFIG_ARM64_64K_PAGES', 'n') == 'n', 'other granule selected')
    return {'page_size': 16384, 'modules': 'DISABLED', 'all_fragment_values_match': True}


def image_check(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(64)
    require(len(raw) == 64 and raw[56:60] == b'ARM\x64', 'ARM64 Image header required')
    flags = struct.unpack_from('<Q', raw, 24)[0]
    require(flags & 1 == 0 and (flags >> 1) & 3 == 2, 'little-endian 16KiB Image required')
    return {'header_page_size': 16384, 'flags': flags, 'boot': 'NOT RUN'}


def extract(archive, destination):
    """Only the pinned source; data filter rejects escaping links and special files."""
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        members = []
        for member in source:
            name = PurePosixPath(member.name)
            require(name.parts and name.parts[0] == ARCHIVE_ROOT and not name.is_absolute() and
                    '..' not in name.parts, 'unexpected source member')
            require(member.isdir() or member.isfile() or member.issym() or member.islnk(),
                    'special source member refused')
            require(member.size <= 64 * 1024**2, 'source member exceeds bound')
            total += member.size
            require(total <= 4 * 1024**3 and len(members) < 150000, 'source exceeds bounds')
            members.append(member)
        source.extractall(destination, members=members, filter='data')
    return {'members': len(members), 'logical_bytes': total}


def usage(path, active_child=None):
    path = Path(path)
    root = path.lstat()
    require(stat.S_ISDIR(root.st_mode), 'ordinary workspace root required')
    compiler = path / 'build'
    compiler_root = compiler.lstat() if active_child is not None else None
    if compiler_root is not None:
        require(stat.S_ISDIR(compiler_root.st_mode), 'ordinary compiler output root required')
    def transient(missing):
        return (active_child is not None and missing != compiler and missing.is_relative_to(compiler)
                and active_child.poll() is None)
    total = 0
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as stream:
                entries = [Path(entry.path) for entry in stream]
        except FileNotFoundError:
            if transient(directory):
                continue
            raise
        for entry in entries:
            try:
                info = entry.lstat()
            except FileNotFoundError:
                if transient(entry):
                    continue
                raise
            if stat.S_ISLNK(info.st_mode):
                continue
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                pending.append(entry)
    final = path.lstat()
    require((final.st_dev, final.st_ino) == (root.st_dev, root.st_ino), 'workspace root changed')
    if compiler_root is not None:
        final = compiler.lstat()
        require((final.st_dev, final.st_ino) == (compiler_root.st_dev, compiler_root.st_ino),
                'compiler output root changed')
    return total


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
    os.umask(0o077)


def run(argv, log, env, workspace, deadline, records):
    record = {'argv': argv, 'log': str(log), 'returncode': None}
    records.append(record)
    with log.open('xb') as stream:
        child = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, env=env,
                                 start_new_session=True, preexec_fn=limits)
        try:
            while child.poll() is None:
                require(time.monotonic() < deadline, 'whole build deadline exceeded')
                require(log.stat().st_size <= 16 * 1024**2, 'command log limit exceeded')
                require(usage(workspace, active_child=child) <= TOTAL_LIMIT, 'workspace allocation limit exceeded')
                time.sleep(2)
            record['returncode'] = child.returncode
            require(child.returncode == 0, 'build command failed: ' + log.name)
            require(log.stat().st_size <= 16 * 1024**2 and usage(workspace) <= TOTAL_LIMIT,
                    'completed command exceeded output bounds')
        finally:
            # Retire descendants even when the direct make process has already exited.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            until = time.monotonic() + 5
            while time.monotonic() < until:
                child.poll()
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            record.update(returncode=child.returncode, log_sha256=sha(log), log_bytes=log.stat().st_size)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--build', action='store_true', help='explicitly execute build-only Makefile targets')
    parser.add_argument('--configure-only', action='store_true', help='configure and check without compiling Image')
    parser.add_argument('--boot-diagnostics', action='store_true')
    args = parser.parse_args()
    report = {'status': 'INPUTS_CHECKED', 'kernel_build': 'NOT RUN', 'guest_boot': 'NOT RUN',
              'hardware': 'NOT RUN', 'performance': 'NOT RUN', 'source_commit': COMMIT,
              'source_url': 'https://github.com/AsahiLinux/linux/archive/asahi-7.1.13-3.tar.gz',
              'source_license': 'GPL-2.0-only WITH Linux-syscall-note', 'commands': []}
    require(args.archive.stat().st_size == ARCHIVE_BYTES and sha(args.archive) == ARCHIVE_SHA,
            'source archive identity differs')
    report['profile'] = 'MANAGED_GUI_GENERIC16K_DIAGNOSTIC_V1'
    report['derivation'] = {'base_helper_sha256': 'e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa',
                            'base_fragment_sha256': '6d91180b80138d2d8039efafaaa9ca31349baea22b90430cbb15e07bce02e8f6',
                            'workspace_scan': 'ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',
                            'accepted_profiles_modified': False}
    report['boot_diagnostics'] = args.boot_diagnostics
    report['archive'] = identity(args.archive)
    report['fragment'] = identity(HERE / 'kernel.fragment')
    report['helper'] = identity(__file__)
    report['tools'] = {name: identity(path) if (path := shutil.which(name, path='/usr/bin:/bin')) else None for name in TOOLS}
    report['build_environment'] = {'host_uname': list(os.uname()), 'jobs': 2,
                                 'build_seconds': 3600, 'workspace_limit_bytes': TOTAL_LIMIT,
                                 'per_file_limit_bytes': 2 * 1024**3,
                                 'limit_note': 'periodic aggregate check; bounded overshoot possible before next poll'}
    missing = [name for name, row in report['tools'].items() if row is None]
    report['missing_tools'] = missing
    require(not (args.build and args.configure_only), 'choose build or configure-only')
    if not (args.build or args.configure_only):
        print(json.dumps(report, sort_keys=True, indent=2))
        return
    required_missing = [name for name in missing if not (args.configure_only and name == 'bc')]
    require(not required_missing, 'missing build tools: ' + ', '.join(required_missing))
    # All mutations belong to one newly created child of this candidate directory.
    output = args.output.absolute()
    require(output.parent.resolve() == HERE and not output.exists() and not output.is_symlink(),
            'fresh direct candidate child output required')
    require(shutil.disk_usage(HERE).free >= TOTAL_LIMIT, '16GiB free build headroom required')
    output.mkdir(mode=0o700)
    report['status'] = 'FAILED'
    try:
        report['extraction'] = extract(args.archive, output)
        source = output / ARCHIVE_ROOT
        build = output / 'build'
        build.mkdir()
        fragment = HERE / 'kernel.fragment'
        if args.boot_diagnostics:
            fragment = output / 'diagnostic.fragment'
            fragment.write_text((HERE / 'kernel.fragment').read_text() + DIAGNOSTIC_FRAGMENT)
            report['diagnostic_fragment'] = identity(fragment)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'TMPDIR': str(output), 'LC_ALL': 'C',
               'TZ': 'UTC', 'ARCH': 'arm64', 'LLVM': '1', 'KBUILD_BUILD_USER': 'generic16k',
               'KBUILD_BUILD_HOST': 'owned-build-fixture', 'KBUILD_BUILD_VERSION': '1',
               'KBUILD_BUILD_TIMESTAMP': 'Fri Oct 16 00:00:00 UTC 2026',
               'KCONFIG_ALLCONFIG': str(fragment)}
        argv = ['/usr/bin/make', '-C', str(source), 'O=' + str(build), 'ARCH=arm64', 'LLVM=1']
        deadline = time.monotonic() + 3600
        run(argv + ['allnoconfig'], output / 'configure.log', env, output, deadline, report['commands'])
        report['config_check'] = config_check(build / '.config', args.boot_diagnostics)
        report['config'] = identity(build / '.config')
        if args.configure_only:
            report['status'] = 'CONFIGURED_ONLY'
            return
        # CONFIG_MODULES=n: all selected runtime drivers built into this Image, no modules_install.
        run(argv + ['-j2', 'Image'], output / 'build.log', env, output, deadline, report['commands'])
        report['image_check'] = image_check(build / 'arch/arm64/boot/Image')
        report['kernel_release'] = (build / 'include/config/kernel.release').read_text().strip()
        require(report['kernel_release']=='7.1.13-generic16k-managed-gui', 'wrong kernel release')
        report['image'] = identity(build / 'arch/arm64/boot/Image')
        report['config'] = identity(build / '.config')
        report['system_map'] = identity(build / 'System.map')
        report['builtin_drivers'] = ['PL011 console','generic PCI host','virtio-pci','virtio-blk','virtio-console','virtio GPU','ext4','UNIX98 PTY','systemd user namespace/cgroup APIs']
        report['module_policy'] = {'CONFIG_MODULES': 'n', 'external_modules_allowed': False}
        report.update(status='BUILT_ONLY', kernel_build='PASS', allocated_bytes=usage(output))
    finally:
        (output / 'build-receipt.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    def interrupt(signum, frame):
        raise KeyboardInterrupt('build interrupted')
    signal.signal(signal.SIGTERM, interrupt)
    main()
