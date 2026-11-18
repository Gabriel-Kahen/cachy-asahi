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
TOOL_PATH = '/usr/lib/llvm-18/bin:/usr/bin:/bin'
PERL_BIN = Path('usr/bin/perl')
PERL_LIB = Path('usr/lib/aarch64-linux-gnu/perl-base')
PERL_VERSION = '5.38.2-3.2ubuntu0.6'
PERL_URL = ('https://snapshot.ubuntu.com/ubuntu/20261020T000000Z/pool/main/p/perl/'
            'perl-base_5.38.2-3.2ubuntu0.6_arm64.deb')
PERL_DEB = {'bytes': 1780386, 'sha256': '52ff69555911c8ef4350a80b12bbdc823b6c096cb15eb39c540cd84e6c726cc0'}
PERL_FILES = 616
PERL_TREE = '64034a200f39b4f27baf04416b39fee8bd8f11c1fb921ae08b577b1a47a4b50c'
TOTAL_LIMIT = 16 * 1024**3
DIAGNOSTIC_FRAGMENT = 'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\n'

# Exact R5 KSM baseline and executable inventory from its accepted build receipt.
BASE_CONFIG_SHA = '5f1f5e507586734c0955607960ceecfe822b5c908bfc1da9d29fe80ac627a8e9'
BASE_RECEIPT_SHA = 'fdd538c9e3c73f906da0c82f0b381b0385306a52d0dc1539ab13ceaa69938398'
PROFILE = 'KSM_ADVICE_VIRTIO_INPUT_IPV6_GENERIC16K_DIAGNOSTIC_V2'
EXPECTED_CONFIG_SHA = '8f9c37958a64701c8e0459ba29c78def06810291018a75cc657ab736a10bb917'
EXPLICIT_DELTA = {'CONFIG_VIRTIO_INPUT': {'before': 'n', 'after': 'y'}, 'CONFIG_IPV6': {'before': 'n', 'after': 'y'}}



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


def expected_config():
    baseline = (HERE / 'base.config').read_bytes()
    require(hashlib.sha256(baseline).hexdigest() == BASE_CONFIG_SHA, 'exact R5 KSM baseline config required')
    configured = (HERE / 'expected-ipv6.config').read_bytes()
    require(hashlib.sha256(configured).hexdigest() == EXPECTED_CONFIG_SHA, 'exact reviewed IPv6 config required')
    return configured


def expected_tools(private_perl=None):
    baseline = (HERE / 'base-build-receipt.json').read_bytes()
    require(hashlib.sha256(baseline).hexdigest() == BASE_RECEIPT_SHA,
            'exact R5 KSM build receipt required')
    tools = json.loads(baseline)['tools']
    if private_perl is not None:
        tools['perl']['path'] = private_perl['perl']['path']
    return tools


def deb_identity(archive):
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == PERL_DEB['bytes'],
            'exact ordinary historical Ubuntu Perl archive size required')
    actual = identity(archive)
    require(actual['sha256'] == PERL_DEB['sha256'], 'exact historical Ubuntu Perl archive digest required')
    return actual


def private_perl(work):
    """Verify both the pinned archive and the exact relocated module tree."""
    kit, archive = work/'perl-base', work/'perl-base.deb'
    if not os.path.lexists(kit) and not os.path.lexists(archive):
        return None
    require(stat.S_ISDIR(kit.lstat().st_mode) and kit.resolve() == kit, 'ordinary owned Perl directory required')
    archive_pin = deb_identity(archive)
    files = {}
    for path in kit.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        part = path.relative_to(kit)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and part != PERL_LIB and
                (part == PERL_BIN or part.is_relative_to(PERL_LIB)) and info.st_size <= 4*1024**2,
                'only ordinary historical Perl package members permitted')
        require(len(files) < PERL_FILES and stat.S_IMODE(info.st_mode) == (0o700 if part == PERL_BIN else 0o600),
                'exact private Perl file count bound and member mode required')
        files[part.as_posix()] = {'bytes': info.st_size, 'sha256': sha(path)}
    digest = hashlib.sha256((json.dumps(files, sort_keys=True, indent=2)+'\n').encode()).hexdigest()
    require(len(files) == PERL_FILES and digest == PERL_TREE, 'exact historical Perl executable and core module tree required')
    perl = identity(kit/PERL_BIN)
    require(all(perl[key] == expected_tools()['perl'][key] for key in ('bytes','sha256')),
            'relocated interpreter must be the exact R5 Perl bytes')
    return {'archive': archive_pin, 'perl': perl, 'version': PERL_VERSION, 'url': PERL_URL,
            'modules': {'files': PERL_FILES-1, 'selected_tree_sha256': PERL_TREE}}


def extract_perl(data, kit):
    """Copy only the one executable and finite regular perl-base modules."""
    kit.mkdir(mode=0o700)
    seen = set()
    total = 0
    with tarfile.open(fileobj=data, mode='r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts, 'Perl archive path traversal refused')
            if member.isdir() or not (path == PERL_BIN or path.is_relative_to(PERL_LIB)):
                continue
            require(member.isfile() and path not in seen and len(seen) < PERL_FILES
                    and 0 <= member.size <= 4*1024**2, 'bounded ordinary historical Perl member required')
            total += member.size
            require(total <= 8*1024**2, 'bounded expanded historical Perl selection required')
            seen.add(path)
            target = kit/path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as sink:
                shutil.copyfileobj(source, sink)
            target.chmod(0o700 if path == PERL_BIN else 0o600)
    require(len(seen) == PERL_FILES, 'complete historical Perl package selection required')


def recover_perl(work):
    from io import BytesIO
    candidate, archive = work/'perl-base.deb.part', work/'perl-base.deb'
    env = {'PATH': TOOL_PATH, 'LC_ALL': 'C', 'HOME': str(work)}
    result = subprocess.run(['/usr/bin/curl', '-q', '--silent', '--show-error', '--fail', '--proto', '=https',
                             '--max-time', '35', '--max-filesize', str(PERL_DEB['bytes']), '--output', str(candidate), PERL_URL],
                            capture_output=True, timeout=40, check=False, env=env)
    require(result.returncode == 0, 'historical Ubuntu Perl acquisition failed')
    deb_identity(candidate)
    candidate.rename(archive)
    raw = subprocess.run(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(archive)], capture_output=True, timeout=30, check=False, env=env)
    require(raw.returncode == 0 and 0 < len(raw.stdout) <= 10*1024**2, 'bounded historical Perl package stream required')
    extract_perl(BytesIO(raw.stdout),work/'perl-base')
    return private_perl(work)


def tool_environment(private=None):
    if private is None:
        return {'PATH': TOOL_PATH}
    kit = Path(private['perl']['path']).parents[2]
    return {'PATH': str(kit/PERL_BIN.parent)+':'+TOOL_PATH, 'PERL5LIB': str(kit/PERL_LIB)}


def tool_inventory(private=None):
    inventory = {}
    path = tool_environment(private)['PATH']
    for role in TOOLS:
        executable = shutil.which(role, path=path)
        try:
            inventory[role] = identity(executable) if executable else None
        except (OSError, ValueError):
            inventory[role] = None
    return inventory


def tool_difference(actual, expected):
    return {name: dict(status='MISSING_OR_UNREADABLE' if row is None else 'IDENTITY_DIFFERS',
                       expected={k:v for k,v in expected[name].items() if k!='path'},
                       observed=None if row is None else {k:v for k,v in row.items() if k!='path'},
                       same_path=row is not None and row['path']==expected[name]['path'])
            for name,row in actual.items() if row != expected[name]}


def config_check(path, boot_diagnostics=False):
    require(boot_diagnostics and Path(path).read_bytes() == expected_config(),
            'generated config must equal the exact reviewed built-in IPv6 config')
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
    return {'page_size': 16384, 'modules': 'DISABLED', 'all_fragment_values_match': True,
            'explicit_fragment_delta': EXPLICIT_DELTA}


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
    report['profile'] = PROFILE
    report['derivation'] = {'base_helper_sha256': 'e94adb4474183feea30ce1e2949b55c03e4969eeb1addb4c36892e8664ba9aaa',
                            'base_fragment_sha256': '6d91180b80138d2d8039efafaaa9ca31349baea22b90430cbb15e07bce02e8f6',
                            'workspace_scan': 'ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',
                            'accepted_profiles_modified': False,
                            'exact_ksm_helper_sha256': '7372ebfece249fae202652f3c3bb419f730bd0e466dc076907270dac1ac873ed',
                            'exact_ksm_fragment_sha256': 'f4a6dc3fbebd5f0e184422cddc490e47e6737d208c55b7df255b678604fe9267',
                            'exact_ksm_config_sha256': BASE_CONFIG_SHA}
    report['boot_diagnostics'] = args.boot_diagnostics
    report['archive'] = identity(args.archive)
    report['fragment'] = identity(HERE / 'kernel.fragment')
    report['helper'] = identity(__file__)
    perl = private_perl(HERE)
    report['private_perl'] = perl
    report['tools'] = tool_inventory(perl)
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
    require(args.boot_diagnostics and os.uname().machine == 'aarch64' and
            report['tools'] == expected_tools(perl),
            'exact native AArch64 R5 tool inventory and diagnostic mode required')
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
        env = {**tool_environment(perl), 'HOME': str(output), 'TMPDIR': str(output), 'LC_ALL': 'C',
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
        report['builtin_drivers'] = ['PL011 console','generic PCI host','virtio-pci','virtio-blk','virtio-console','virtio-input','IPv6 proc network tables','virtio GPU','ext4','UNIX98 PTY','systemd user namespace/cgroup APIs']
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
