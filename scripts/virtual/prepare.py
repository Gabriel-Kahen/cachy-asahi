#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare one raw generic guest disk only inside the contracted fixture container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import signal
import stat
import shlex
import struct
import re
from image_decode_report import (ASSET_PATH, ASSET_SHA256, HEADER_ROOTS, PC_NAMES, PKG_ARGV,
    COMPILE_PREFIX, C_SHA256, core_sha256, inventory_sha256, canonical_sha256, validate_elf, validate_build)
from common import GIB, IMAGE_SHA, KERNEL, Refused, check_runtime, contract, digest, free_bytes, guard, require, save, allocated, bounded, barrier_contract, BARRIER_FILES, pinned

ASSETS = ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c',
          'image_decode_probe.c', 'image_decode_report.py')
UNIT = '''[Unit]
Description=Bounded generic ARM software guest proof
Requires=basic.target systemd-udevd.service systemd-udev-trigger.service
After=basic.target systemd-udev-trigger.service
[Service]
Type=oneshot
Environment=CACHY_ASAHI_VIRTUAL_GUEST=1
ExecStart=/usr/bin/python /usr/local/share/virtual-proof/guest.py boot
TimeoutStartSec=650
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyAMA0
[Install]
WantedBy=virtual-proof.target
'''
TARGET = '''[Unit]
Description=Disposable generic ARM software proof only
Requires=virtual-proof.service
After=virtual-proof.service
AllowIsolate=yes
'''


def changed(root, name, data, report, mode=0o644):
    path = root / name
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'fixture change would follow symlink')
    previous = digest(path) if path.is_file() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    report['fixture_changes'].append({'path': name, 'before_sha256': previous, 'after_sha256': digest(path), 'mode': oct(mode)})


def prepare_mime_database(root, command, report):
    """Generate only the staged guest's metadata omitted by masked hooks."""
    mime = root / 'usr/share/mime'
    require(all(not path.is_symlink() for path in (mime, *mime.parents)) and
            (mime / 'packages').is_dir() and not (mime / 'packages').is_symlink(),
            'staged MIME package directory required')
    command(['/usr/bin/update-mime-database', str(mime)], timeout=30)
    cache = mime / 'mime.cache'
    require(cache.is_file() and not cache.is_symlink() and 0 < cache.stat().st_size <= 16 * 1024**2,
            'generated staged MIME cache missing or invalid')
    report['fixture_changes'].append({'path': 'usr/share/mime',
        'reason': 'guest-only MIME metadata generation; package hooks remain masked',
        'mime_cache_sha256': digest(cache)})


def stage_barrier(root, c, proof_path, proof_sha256, report):
    if not barrier_contract(c):
        return
    require(digest(proof_path) == proof_sha256, 'selected proof changed')
    shared = 'usr/local/share/virtual-proof/'
    changed(root, shared + 'virtual-contract.json', proof_path.read_bytes(), report)
    for name, row in BARRIER_FILES.items():
        source = pinned('/inputs', name, row['sha256'])
        require(source.stat().st_size == row['bytes'], 'selected fixture size differs')
        target = shared + 'barrier-source/' + name
        changed(root, target, source.read_bytes(), report)
        require(digest(root / target) == row['sha256'], 'staged barrier source differs')


def stage_size(paths):
    # du does not follow source symlinks; all inputs are immutable container paths.
    result = subprocess.check_output(['/usr/bin/du', '-s', '-B1', '--', *paths], text=True, timeout=60)
    return sum(int(line.split()[0]) for line in result.splitlines())


def decode_build_budget(start, timeout):
    remaining = 1200 - (time.monotonic() - start)
    require(remaining > 5, 'original preparation budget exhausted before decode build')
    return min(timeout, remaining - 5)


def file_identity(path):
    """Read bytes from the current immutable image; packaged hardlinks are valid."""
    path = Path(path)
    resolved = path.resolve(strict=True)
    require(str(path).startswith('/usr/') and str(resolved).startswith('/usr/'), 'build input outside image /usr')
    before = resolved.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 16 * 1024**2,
            'bounded regular build input required')
    sha = digest(resolved)
    after = resolved.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'build input changed during capture')
    return {'path': str(path), 'resolved_path': str(resolved), 'sha256': sha,
            'bytes': before.st_size, 'mode': stat.S_IMODE(before.st_mode)}


def elf_facts(path):
    size = path.stat().st_size
    require(64 <= size <= 16 * 1024**2, 'bounded ELF helper required')
    raw = path.read_bytes()
    require(len(raw) == size and raw[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little endian v1 required')
    kind, machine, version, entry, phoff, _, _, ehsize, phsize, phcount = struct.unpack_from('<HHIQQQIHHH', raw, 16)
    require(kind in (2, 3) and machine == 183 and version == 1 and ehsize == 64 and
            phsize == 56 and 1 <= phcount <= 128 and phoff >= 64 and phoff + phsize * phcount <= size,
            'bounded AArch64 ELF header required')
    segments = []
    for offset in range(phoff, phoff + phsize * phcount, phsize):
        ptype, _, file_offset, address, _, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', raw, offset)
        if ptype == 1:
            segments.append({'offset': file_offset, 'virtual_address': address,
                'file_size': filesz, 'memory_size': memsz, 'alignment': alignment})
    compatible = bool(segments) and all(row['alignment'] >= 16384 and
        row['offset'] % 16384 == row['virtual_address'] % 16384 for row in segments)
    row = {'class': 64, 'encoding': 'little-endian', 'machine': machine,
           'type': {2: 'EXEC', 3: 'DYN'}[kind], 'entry': entry,
           'load_segments': segments, 'compatible_16k': compatible}
    validate_elf(row, size)
    return row


def build_image_decode(root, c, runtime, proof_sha256, command, report):
    # Refuse missing authority before invoking either new build command.
    core_sha256(c['runner_sha256'])
    require(c['runner_sha256']['image_decode_probe.c'] == C_SHA256 and
            re.fullmatch(r'[0-9a-f]{64}', proof_sha256) and
            type(c.get('image_id')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', c['image_id']) and
            type(c.get('baseline_image_id')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', c['baseline_image_id']),
            'selected source/proof/immutable image authority required')
    require(all(type(c.get(key)) is str and re.fullmatch(r'[0-9]{1,' + str(maximum) + '}', c[key])
                for key, maximum in (('run_id', 20), ('run_attempt', 10))),
            'authenticated workflow identity required before build')
    provenance = {'baseline_image_id': c['baseline_image_id'],
        'tooling_lock_sha256': c['tooling_lock_sha256'], 'tooling_audit_sha256': c['tooling_audit_sha256'],
        'compiler': file_identity('/usr/bin/cc'), 'pkg_config': file_identity('/usr/bin/pkg-config'),
        'headers': [], 'pc_files': [], 'pkg_config_argv': list(PKG_ARGV)}
    for directory in HEADER_ROOTS:
        headers = sorted(Path(directory).rglob('*.h'))
        require(headers and len(provenance['headers']) + len(headers) <= 4096, 'same-image headers required')
        provenance['headers'].extend(file_identity(path) for path in headers)
    provenance['headers'].sort(key=lambda row: row['path'])
    provenance['pc_files'] = sorted((file_identity('/usr/lib/pkgconfig/' + name + '.pc')
                                   for name in PC_NAMES), key=lambda row: row['path'])
    result = command(list(PKG_ARGV), timeout=15, limit=16384, decode_build=True)
    require(result['stdout'].isascii(), 'pkg-config stdout must be ASCII')
    stdout = result['stdout'].encode('ascii')
    flags = shlex.split(result['stdout'])
    require(flags and len(flags) <= 128 and all(0 < len(flag) <= 1024 and flag.isascii() and
            all(32 < ord(char) < 127 for char in flag) and flag.startswith(('-I', '-L', '-l', '-D', '-pthread'))
            for flag in flags), 'finite pkg-config flags required')
    provenance.update(pkg_config_stdout_sha256=hashlib.sha256(stdout).hexdigest(), flags=flags,
                      compile_argv=list(COMPILE_PREFIX) + flags)
    require(root == Path('/out/prepared/root'), 'fixed image decode output root')
    command(provenance['compile_argv'], timeout=60, decode_build=True)
    provenance['compile_log_sha256'] = report['commands'][-1]['log_sha256']
    helper = root / 'usr/local/bin/image-decode-probe'
    require(not helper.is_symlink() and helper.is_file() and helper.stat().st_nlink == 1,
            'new regular image decode helper required')
    helper.chmod(0o755)
    identity = {'bytes': helper.stat().st_size, 'sha256': digest(helper), 'mode': stat.S_IMODE(helper.stat().st_mode)}
    elf = elf_facts(helper)
    runners = c['runner_sha256']
    guest = {'schema_version': 1, 'scope': 'fixed-adwaita-svg-guest-contract', 'nonce': c['nonce'], 'attempt': 1,
        'source_sha256': runners['image_decode_probe.c'], 'parser_sha256': runners['image_decode_report.py'],
        'helper_sha256': identity['sha256'], 'guest_sha256': runners['guest.py'],
        'runtime_sha256': runners['common.py'], 'core_sha256': core_sha256(runners),
        'tooling_sha256': c['image_id'].removeprefix('sha256:'),
        'package_inventory_sha256': inventory_sha256(runtime), 'asset_sha256': ASSET_SHA256}
    asset = root / ASSET_PATH.lstrip('/')
    require(asset.is_file() and all(not part.is_symlink() for part in (asset, *asset.parents)) and
            digest(asset) == ASSET_SHA256, 'independently selected staged SVG asset differs')
    receipt = {'status': 'BUILT', 'guest_contract': guest, 'guest_contract_sha256': canonical_sha256(guest),
        'source_commit': c['source_commit'], 'proof_contract_sha256': proof_sha256,
        'run_id': c['run_id'], 'run_attempt': c['run_attempt'], 'helper': identity,
        'elf': elf, 'provenance': provenance}
    validate_build(receipt, c, proof_sha256, runtime)
    shared = 'usr/local/share/virtual-proof/'
    changed(root, shared + 'image_decode_report.py', Path('/runner/virtual/image_decode_report.py').read_bytes(), report)
    changed(root, shared + 'image-decode-contract.json',
            (json.dumps(guest, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii'), report)
    report['fixture_changes'].append({'path': 'usr/local/bin/image-decode-probe',
        'after_sha256': identity['sha256'], 'mode': oct(identity['mode']),
        'source_sha256': runners['image_decode_probe.c']})
    report['image_decode_build'] = receipt


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--contract', type=Path, default=Path('/inputs/virtual-contract.json'))
    ap.add_argument('--contract-sha256', required=True)
    args = ap.parse_args()
    facts = guard(preparation=True)
    c = contract(args.contract, args.contract_sha256, facts)
    output = Path('/out/prepared')
    require(not output.exists(), 'fresh fixed prepared output required')
    output.mkdir(mode=0o755)
    report = {'status': 'FAILED', 'execution': 'qemu-tcg-generic-aarch64', 'native_guest_boot': 'NOT RUN',
              'compositor_session': 'NOT RUN', 'hardware_validation': 'NOT RUN',
              'contract_sha256': args.contract_sha256, 'image_id': c['image_id'], 'nonce': c['nonce'],
              'fixture_changes': [], 'commands': [], 'resources': {},
              'copied_package_trees': ['/usr', '/etc', '/var', '/boot'],
              'extended_attributes': 'NOT PRESERVED - software fixture only'}
    start = time.monotonic()
    def interrupt(*_):
        raise Refused('preparation interrupted/deadline')
    previous = signal.signal(signal.SIGTERM, interrupt)
    old_alarm = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 1200)
    root = output / 'root'
    def command(argv, timeout=180, *, limit=None, decode_build=False):
        require(time.monotonic() - start < 1200, '20-minute preparation deadline')
        log = output / ('command-%03d.log' % len(report['commands']))
        record = {'argv': argv, 'log': log.name, 'returncode': None}
        report['commands'].append(record)
        remaining = 1200 - (time.monotonic() - start)
        if decode_build:
            result = bounded(argv, log=log, timeout=decode_build_budget(start, timeout),
                             **({'limit': limit} if limit is not None else {}))
        else:
            result = bounded(argv, log=log, timeout=min(timeout, max(1, remaining)))
        record['returncode'] = result['returncode']
        record['error'] = result['error']
        record['log_sha256'] = digest(log)
        require(result['error'] is None and result['returncode'] == 0, 'preparation command failed/overflowed: ' + argv[0])
        if decode_build:
            require(time.monotonic() - start < 1200, 'decode build exceeded original preparation deadline')
        return result
    try:
        runtime = check_runtime(c)
        require(set(c.get('runner_sha256', {})) == set(ASSETS), 'complete reviewed runner asset map required')
        for name in ASSETS:
            require(digest(Path('/runner/virtual') / name) == c['runner_sha256'][name], 'runner source differs: ' + name)
        sources = ['/usr', '/etc', '/var', '/boot']
        size = stage_size(sources)
        available = free_bytes(output)
        report['resources'] = {'source_allocated_bytes': size, 'free_before_bytes': available,
                               'minimum_free_bytes': 2 * size + GIB, 'guest_disk_virtual_bytes': 8 * GIB}
        require(size < 6 * GIB and available >= 2 * size + GIB, 'disk preflight fails; no dependency trimming')
        root.mkdir(mode=0o755)
        command(['/usr/bin/cp', '-a', '--no-preserve=xattr', '--reflink=never', '--', *sources, str(root)], timeout=300)
        prepare_mime_database(root, command, report)
        report['special_modes'] = {}
        for source_root in sources:
            for source in Path(source_root).rglob('*'):
                before = source.lstat()
                if stat.S_ISREG(before.st_mode) and before.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    target = root / source.relative_to('/')
                    after = target.lstat()
                    require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) ==
                            (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                            'special file ownership/mode not preserved: ' + str(source))
                    report['special_modes'][str(source.relative_to('/'))] = {
                        'uid': after.st_uid, 'gid': after.st_gid, 'mode': oct(stat.S_IMODE(after.st_mode))}
        for name in ('bin', 'sbin', 'lib', 'lib64'):
            source = Path('/') / name
            if source.exists():
                require(source.is_symlink(), 'unexpected root filesystem link layout')
                (root / name).symlink_to(os.readlink(source))
        for name in ('dev', 'proc', 'sys', 'run', 'tmp', 'home', 'root', 'mnt', 'srv', 'opt'):
            (root / name).mkdir(mode=0o1777 if name == 'tmp' else 0o755)
        passwd = (root / 'etc/passwd').read_text()
        group = (root / 'etc/group').read_text()
        require('virtual-proof:' not in passwd + group and not any(line.split(':')[2] == '23001' for line in (passwd + group).splitlines()), 'guest fixture account collision')
        changed(root, 'etc/passwd', (passwd + 'virtual-proof:x:23001:23001:Generic virtual proof:/home/virtual-proof:/bin/bash\n').encode(), report)
        changed(root, 'etc/group', (group + 'virtual-proof:x:23001:\n').encode(), report)
        shadow = (root / 'etc/shadow').read_bytes()
        changed(root, 'etc/shadow', shadow + b'virtual-proof:!:20000:0:99999:7:::\n', report, 0o600)
        changed(root, 'etc/fstab', b'# Disposable QEMU raw ext4 root; no board-specific mounts.\n/dev/vda / ext4 defaults 0 0\n', report)
        changed(root, 'etc/hostname', b'cachy-generic-virtual-proof\n', report)
        changed(root, 'etc/hosts', b'127.0.0.1 localhost\n::1 localhost\n', report)
        changed(root, 'etc/machine-id', b'', report)
        changed(root, 'etc/systemd/system/virtual-proof.service', UNIT.encode(), report)
        changed(root, 'etc/systemd/system/virtual-proof.target', TARGET.encode(), report)
        shared = 'usr/local/share/virtual-proof/'
        changed(root, shared + 'common.py', Path('/runner/virtual/common.py').read_bytes(), report)
        changed(root, shared + 'guest.py', Path('/runner/virtual/guest.py').read_bytes(), report)
        changed(root, shared + 'minimal.lua',
                b'hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })\n'
                b'hl.config({ debug = { disable_logs = false, enable_stdout_logs = true } })\n', report)
        guest_contract = {'nonce': c['nonce'], 'baseline': c['baseline']}
        if barrier_contract(c):
            guest_contract.update(purpose=c['purpose'], proof_contract_sha256=args.contract_sha256)
        changed(root, shared + 'contract.json', (json.dumps(guest_contract, sort_keys=True) + '\n').encode(), report)
        stage_barrier(root, c, args.contract, args.contract_sha256, report)
        changed(root, shared + 'runtime.lock', ''.join(k + ' ' + v + '\n' for k, v in sorted(runtime.items())).encode(), report)
        flags = subprocess.check_output(['/usr/bin/pkg-config', '--cflags', '--libs', 'egl', 'gbm', 'glesv2', 'libdrm'], text=True, timeout=15).split()
        (root / 'usr/local/bin').mkdir(parents=True, exist_ok=True)
        command(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '/runner/virtual/gbm_probe.c', '-o', str(root / 'usr/local/bin/gbm-probe'), *flags])
        report['fixture_changes'].append({'path': 'usr/local/bin/gbm-probe', 'after_sha256': digest(root / 'usr/local/bin/gbm-probe'), 'source_sha256': c['runner_sha256']['gbm_probe.c']})
        build_image_decode(root, c, runtime, args.contract_sha256, command, report)
        command(['/usr/bin/depmod', '-b', str(root), KERNEL])
        for path in (root / 'usr/lib/modules' / KERNEL).glob('modules.*'):
            report['fixture_changes'].append({'path': str(path.relative_to(root)), 'after_sha256': digest(path), 'reason': 'guest-only depmod metadata'})
        # The systemd unit is selected by the guest cmdline; no enable/host systemctl.
        shutil.copyfile('/boot/Image', output / 'Image')
        require(digest(output / 'Image') == IMAGE_SHA, 'kernel copied incorrectly')
        actual = allocated(root)
        report['resources']['staged_allocated_bytes'] = actual
        report['resources']['free_before_mkfs_bytes'] = free_bytes(output)
        require(actual <= 6 * GIB and free_bytes(output) >= actual + GIB, 'image population would exceed disk budget')
        image = output / 'guest.raw'
        with image.open('xb') as stream:
            stream.truncate(8 * GIB)
        command(['/usr/bin/mkfs.ext4', '-F', '-m', '0', '-L', 'CACHY_VIRTUAL_PROOF', '-d', str(root), str(image)], timeout=300)
        report['guest_image_sha256'] = digest(image)
        report['kernel_sha256'] = digest(output / 'Image')
        report['resources']['disk_allocated_bytes'] = image.stat().st_blocks * 512
        require(free_bytes(output) >= GIB, 'less than 1 GiB disk margin after population')
        # Verify complete original overlay payloads in the staged tree before deleting it.
        for row in c['baseline']:
            for name, value in row['payload_sha256'].items():
                require(digest(root / name) == value, 'staged original payload differs')
        report['package_inventory'] = runtime
        shutil.rmtree(root)
        report['resources']['free_after_staging_cleanup_bytes'] = free_bytes(output)
        report['status'] = 'PREPARED'
    except Exception as exc:
        report['status'] = 'FAILED'
        report['error'] = str(exc)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGTERM, previous)
        signal.signal(signal.SIGALRM, old_alarm)
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        # Private images/logs stay in the controller-owned disposable output directory.
        try:
            for path in [output, *output.rglob('*')]:
                if not path.is_symlink():
                    os.chown(path, c['output_uid'], c['output_gid'])
        except Exception as exc:
            report['status'] = 'FAILED'
            report['ownership_error'] = str(exc)
            raise
        finally:
            save(output / 'prepare.json', report)
            os.chown(output / 'prepare.json', c['output_uid'], c['output_gid'])


if __name__ == '__main__':
    main()
