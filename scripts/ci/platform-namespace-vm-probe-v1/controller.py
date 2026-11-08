#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Root-bound diskless generic16K probe; default mode is DATA only."""
import argparse
import base64
import importlib.util
import io
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import tarfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C

HERE = Path(__file__).resolve().parent
FIXTURE = 'scripts/virtual/generic16k/fixture.py'
SUPERVISOR = 'scripts/ci/glibc-owned-runtime/runner.py'
KERNEL_CHECK = 'scripts/virtual/generic16k/build_kernel.py'
GUEST_FILES = ('common.py', 'guest.py', 'probe_exec.py', 'inside.py')
REQUIRED = {'busybox', 'usr/bin/python3', 'usr/bin/bwrap'}
RESERVED = ('probe', 'init', 'proc', 'dev', 'tmp', 'home', 'var/lib/pacman')


def source(root):
    dependencies = C.decode(C.read(HERE / 'dependencies.json'))
    C.need(dependencies['minimum_Python'] == '3.12' and dependencies['third_party_Python_dependencies'] == [],
           'standard library only, Python>=3.12')
    for name, row in dependencies['files'].items():
        C.need(name in (FIXTURE, SUPERVISOR, KERNEL_CHECK), 'closed helper dependency paths')
        C.pinned(root / name, row, 1048576)
    C.need(set(dependencies['files']) == {FIXTURE, SUPERVISOR, KERNEL_CHECK}, 'all pinned helper roles')
    defaults = C.decode(C.read(HERE / 'input-policy.json'))
    C.need(defaults == C.defaults(), 'maintained input policy stays unbound/actual selectors NULL')
    return dependencies


def load(root, path, name, dependencies):
    C.pinned(root / path, dependencies['files'][path], 1048576)
    spec = importlib.util.spec_from_file_location(name, root / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(archive, manifest):
    C.need(type(archive) is bytes and len(archive) <= C.BOUNDS['rootfs_bytes'], 'whole uncompressed rootfs tar cap')
    C.need(set(manifest) == {'schema', 'status', 'files'} and type(manifest['schema']) is int and manifest['schema'] == 1 and
           manifest['status'] == 'CLOSED_GENERIC16K_NAMESPACE_ROOTFS_DATA', 'exact closed rootfs DATA manifest')
    rows = manifest['files']
    C.need(type(rows) is dict and REQUIRED <= set(rows) and 1 <= len(rows) <= C.BOUNDS['rootfs_files'],
           'closed finite guest rootfs roots')
    for name, row in rows.items():
        C.relative(name)
        C.need(not any(name == p or name.startswith(p + '/') for p in RESERVED), 'rootfs/harness namespace collision')
        C.need(set(row) == {'bytes', 'sha256', 'mode'} and type(row['mode']) is int and row['mode'] in (0o644, 0o755),
               'ordinary non-setuid rootfs DATA modes')
    C.need(all(rows[n]['mode'] == 0o755 for n in REQUIRED), 'fixed rootfs executables')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        for entry in stream:
            name = C.relative(entry.name)
            C.need(name in rows and name not in files and entry.isfile() and not entry.pax_headers and
                   entry.uid == entry.gid == 0 and entry.mode == rows[name]['mode'], 'exact regular rootfs tar row')
            C.need(type(rows[name]['bytes']) is int and 0 <= entry.size == rows[name]['bytes'] <= 64 * 1024**2,
                   'bounded rootfs member')
            total += entry.size
            C.need(total <= C.BOUNDS['rootfs_bytes'], 'rootfs total cap')
            with stream.extractfile(entry) as member:
                body = member.read(64 * 1024**2 + 1)
            C.need(C.pin(body) == {k: rows[name][k] for k in ('bytes', 'sha256')}, 'whole rootfs member hash')
            files[name] = (stat.S_IFREG | entry.mode, body)
    C.need(set(files) == set(rows), 'complete rootfs manifest/tar bijection')
    return files


def elf_closure(files, generic):
    rows = {}
    for name, (_, body) in files.items():
        if body.startswith(b'\x7fELF'):
            interpreter, needed, segments = generic.elf(body)
            C.need(segments and all(a >= 16384 and (v - o) % 16384 == 0 for v, o, _, a in segments),
                   'guest ELF64 AArch64 16K load alignment')
            C.need(interpreter is None or interpreter.lstrip('/') in files, 'guest interpreter present')
            C.need(all(any(directory + library in files for directory in ('usr/lib/', 'lib/')) for library in needed),
                   'declared guest DT_NEEDED names present')
            rows[name] = dict(interpreter=interpreter, needed=needed)
    C.need(REQUIRED <= set(rows), 'actual AArch64 executable roots')
    return rows


def init(nonce, release):
    C.need(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}', release), 'literal guest boot selectors')
    return f'''#!/busybox sh
export PATH=/usr/bin:/bin HOME=/tmp LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1
fail() {{ printf 'NSVM_BOOT_FAIL_V1 {nonce}\\n'; exec /busybox poweroff -f; }}
/busybox mount -t proc -o nosuid,nodev,noexec proc /proc || fail
/busybox mount -t devtmpfs -o nosuid devtmpfs /dev || fail
/busybox mkdir -p /tmp /home /var/lib/pacman || fail
/usr/bin/python3 -I -B /probe/guest.py '{nonce}' '{release}'
code=$?
printf 'NSVM_END_V1 {nonce} %s\\n' "$code"
exec /busybox poweroff -f
'''.encode()


def assemble(files, dependencies, nonce, release, generic, code_files=None):
    # All paths are in-memory guest DATA; no archive extraction or collected code import.
    result = dict(files)
    for name in GUEST_FILES:
        raw = (C.pinned(HERE / name, {k: code_files['scripts/ci/platform-namespace-vm-probe-v1/' + name][k]
               for k in ('bytes', 'sha256')}, 1048576) if code_files is not None else C.read(HERE / name))
        result['probe/' + name] = (stat.S_IFREG | 0o444, raw)
    root = Path(dependencies['source_root'])
    runner = C.pinned(root / SUPERVISOR, dependencies['files'][SUPERVISOR], 1048576)
    result['probe/runner.py'] = (stat.S_IFREG | 0o444, runner)
    selection = dict(runner=C.pin(runner), bwrap=C.pin(files['usr/bin/bwrap'][1]))
    result['probe/selection.json'] = (stat.S_IFREG | 0o444, C.encoded(selection))
    result['init'] = (stat.S_IFREG | 0o755, init(nonce, release))
    for name, mode in [('proc', 0o555), ('tmp', 0o1777), ('home', 0o755), ('var/lib/pacman', 0o755)]:
        result[name] = (stat.S_IFDIR | mode, b'')
    image = generic.cpio(result)
    C.need(len(image) <= C.BOUNDS['initramfs_bytes'], 'finite diskless initramfs')
    return image


def qemu_argv(binary, work, nonce, firmware_dir=None):
    return [str(binary), *([] if firmware_dir is None else ['-L', str(firmware_dir)]),
            '-nodefaults', '-machine', 'virt', '-accel', 'tcg', '-cpu', 'max',
            '-smp', '1', '-m', str(C.BOUNDS['memory_MiB']), '-kernel', str(work / 'Image'),
            '-initrd', str(work / 'initramfs.cpio'), '-append',
            'console=ttyAMA0 rdinit=/init panic=-1 namespace_vm_probe_v1=' + nonce,
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot']


def observed(raw, actor, failure, nonce, release):
    C.need(failure is None and actor['exit_code'] == 0 and actor['group_absence_verified'] is True,
           'natural QEMU exit and actual process-group retirement required')
    C.need(len(raw) <= C.BOUNDS['UART_bytes'] and b'NSVM_BOOT_FAIL_V1' not in raw and b'Kernel panic' not in raw,
           'bounded complete UART without boot refusal')
    lines = raw.replace(b'\r', b'').splitlines()
    prefix = ('NSVM_REPORT_V1 ' + nonce + ' ').encode()
    reports = [x for x in lines if x.startswith(b'NSVM_REPORT_V1 ')]
    ends = [x for x in lines if x.startswith(b'NSVM_END_V1 ')]
    C.need(len(reports) == len(ends) == 1 and reports[0].startswith(prefix) and
           ends[0] in [('NSVM_END_V1 ' + nonce + ' ' + str(n)).encode() for n in (0, 1)] and
           lines.index(reports[0]) < lines.index(ends[0]), 'one complete nonce report then explicit PID1 poweroff path')
    body = base64.b64decode(reports[0][len(prefix):], validate=True)
    C.need(len(body) <= C.BOUNDS['report_bytes'], 'bounded guest report')
    return C.validate_report(C.decode(body), nonce, release)


def cleanup(work, started, actor):
    if started and (actor is None or actor['group_absence_verified'] is not True):
        return 'UNKNOWN_VM_RETIREMENT_RETAIN_PRIVATE_FILES'
    C.need({p.name for p in work.iterdir()} <= {'Image', 'initramfs.cpio'}, 'unexpected private files; retain workspace')
    for name in ('Image', 'initramfs.cpio'):
        path = work / name
        if path.exists():
            C.need(path.is_file() and not path.is_symlink(), 'only exact owned ordinary work files')
            path.unlink()
    C.need(not any(work.iterdir()), 'owned VM work directory empty')
    work.rmdir()
    return ('VERIFIED_VM_GROUP_AND_SCOPED_PRIVATE_FILES_RETIRED' if started else
            'SCOPED_PRESTART_FILES_RETIRED_VM_NOT_STARTED')


def trial(args, local=None):
    # Validate every external immutable input and helper before creating actor output paths.
    C.need(args.execute, 'explicit future Root execution required')
    selected = C.decode(C.pinned(args.selection, dict(bytes=args.selection.stat().st_size,
                                                   sha256=args.selection_sha256), 1048576))
    if local is None:
        selection = C.bound(selected)  # Original hosted tuple remains strict, including genuine GitHub run.
    else:
        C.need(selected == local['selection'] and selected['actual_run'] is None and
               local['lease_observation']['acquisition'] == 'EXCLUSIVE_NONBLOCKING', 'exact authorized local branch/held lease')
        selection = selected
    dependencies = source(args.source_root)
    kernel = C.pinned(args.kernel, selection['kernel']['Image'], C.BOUNDS['kernel_bytes'])
    config = C.pinned(args.kernel_config, selection['kernel']['config'], 1048576)
    C.pinned(args.kernel_qualification, selection['kernel']['qualification'], 4 * 1048576)
    archive = C.pinned(args.rootfs, selection['rootfs']['archive'], C.BOUNDS['rootfs_bytes'])
    manifest = C.decode(C.pinned(args.rootfs_manifest, selection['rootfs']['manifest'], 4 * 1048576))
    C.pinned(args.rootfs_qualification, selection['rootfs']['qualification'], 4 * 1048576)
    C.pinned(args.qemu, selection['QEMU'], 128 * 1048576)
    C.need(stat.S_IMODE(args.qemu.stat().st_mode) == 0o755, 'exact ordinary executable QEMU mode')
    generic = load(args.source_root, FIXTURE, 'namespace_vm_generic_DATA', dependencies)
    kernel_check = load(args.source_root, KERNEL_CHECK, 'namespace_vm_kernel_DATA', dependencies)
    kernel_check.image_check(args.kernel)
    C.need(b'CONFIG_ARM64_16K_PAGES=y' in config.splitlines(), 'selected 16K kernel config')
    files = payload(archive, manifest)
    elf = elf_closure(files, generic)
    runner = load(args.source_root, SUPERVISOR, 'namespace_vm_owned_runner', dependencies)
    for path in (args.work, args.output):
        C.need(path.is_absolute() and path == path.resolve() and not path.exists() and
               not path.is_relative_to(args.source_root) and not args.source_root.is_relative_to(path),
               'fresh canonical private work/output separate from source')
        parent = path.parent.lstat()
        C.need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
               stat.S_IMODE(parent.st_mode) == 0o700, 'preexisting owned0700 output parent')
    C.need(not args.work.is_relative_to(args.output) and not args.output.is_relative_to(args.work), 'separate owned work/output')
    for source_path in (args.selection, args.kernel, args.kernel_config, args.kernel_qualification,
                        args.rootfs, args.rootfs_manifest, args.rootfs_qualification, args.qemu):
        C.need(not source_path.is_relative_to(args.work) and not source_path.is_relative_to(args.output), 'inputs outside fresh outputs')
    args.output.mkdir(mode=0o700)
    nonce = secrets.token_hex(16) if local is None else selection['nonce']
    report = dict(status='VM_NOT_STARTED', nonce=nonce, selection=selection, ELF=elf,
                  generic_emulated_16K_only=True, hardware='NOT_RUN', namespace_cause='UNKNOWN',
                  performance='NOT_MEASURED', native_acceptance=None, cleanup='NOT_RUN')
    if local is not None:
        report['local_identity'] = dict(local_id=selection['local_id'], actual_run=None,
                                        host=local['authority']['host'], lease=local['lease_observation'],
                                        authority=C.pin(C.read(args.local_authority)))
    started = False
    actor = None
    work_created = False
    try:
        args.work.mkdir(mode=0o700)
        work_created = True
        ramfs = assemble(files, dict(dependencies, source_root=str(args.source_root)), nonce,
                         selection['kernel']['release'], generic, None if local is None else local['files'])
        (args.work / 'Image').write_bytes(kernel)
        (args.work / 'initramfs.cpio').write_bytes(ramfs)
        argv = qemu_argv(args.qemu, args.work, nonce, None if local is None else local['firmware_dir'])
        report.update(argv=argv, kernel=C.pin(kernel), config=C.pin(config), initramfs=C.pin(ramfs),
                      namespace_config={k: next((x.decode() for x in config.splitlines() if x.startswith((k + '=').encode())),
                                                'NOT_DECLARED') for k in ('CONFIG_USER_NS', 'CONFIG_NET_NS', 'CONFIG_NAMESPACES',
                                                                        'CONFIG_UTS_NS', 'CONFIG_IPC_NS', 'CONFIG_PID_NS')})
        (args.output / 'intent.json').write_bytes(C.encoded(report))
        if local is not None:
            import local as local_contract
            local_contract.revalidate(local, args)
        started = True
        environment = C.ENV if local is None else local['environment']
        actor, out, err, failure = runner.run_command(argv, args.work, environment, C.BOUNDS['VM_seconds'], C.BOUNDS['UART_bytes'])
        report.update(actor=actor, QEMU_stderr=C.pin(err))
        (args.output / 'uart.log').write_bytes(out)
        (args.output / 'QEMU.stderr').write_bytes(err)
        report['guest'] = observed(out, actor, failure, nonce, selection['kernel']['release'])
        report['status'] = report['guest']['status']
    except BaseException as error:
        report.update(status='VM_PROBE_FAILED', error_type=type(error).__name__,
                      guard=str(error)[:200] if isinstance(error, ValueError) else None)
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
        try:
            try:
                report['cleanup'] = (cleanup(args.work, started, actor) if work_created else
                                     'NO_OWNED_VM_WORKSPACE_CREATED')
            except BaseException as error:
                report.update(cleanup='REFUSED_SCOPED_PRIVATE_CLEANUP_RETAIN_WORKSPACE',
                              cleanup_error_type=type(error).__name__)
            if started and report['cleanup'] != 'VERIFIED_VM_GROUP_AND_SCOPED_PRIVATE_FILES_RETIRED':
                report['status'] = 'VM_PROBE_FAILED'
            (args.output / 'report.json').write_bytes(C.encoded(report))
        finally:
            signal.alarm(0)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--selection-sha256')
    for name in ('selection', 'kernel', 'kernel-config', 'kernel-qualification', 'rootfs',
                 'rootfs-manifest', 'rootfs-qualification', 'qemu', 'work', 'output'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    C.need(sys.version_info >= (3, 12), 'Python>=3.12 standard library only')
    if not args.execute:
        source(args.source_root)
        print(C.encoded(dict(status='SOURCE_DATA_ONLY_NO_ACTORS', kernel=None, rootfs=None,
                             actual_source=None, actual_run=None, bounds=C.BOUNDS)).decode(), end='')
        return 0
    C.need(all(getattr(args, key) is not None for key in ('selection', 'selection_sha256', 'kernel', 'kernel_config',
           'kernel_qualification', 'rootfs', 'rootfs_manifest', 'rootfs_qualification', 'qemu', 'work', 'output')),
           'all explicit Root input/output operands required')
    def interrupted(*_):
        raise TimeoutError('explicit VM owner interruption or deadline')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(C.BOUNDS['owner_seconds'])
    os.umask(0o077)
    report = trial(args)
    print(C.encoded(dict(status=report['status'], cleanup=report['cleanup'], native_acceptance=None)).decode(), end='')
    return int(report['status'] != 'OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS')


if __name__ == '__main__':
    raise SystemExit(main())
