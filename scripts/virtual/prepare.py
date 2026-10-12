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
from common import GIB, IMAGE_SHA, KERNEL, Refused, check_runtime, contract, digest, free_bytes, guard, require, save, allocated, bounded

ASSETS = ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c')
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


def stage_size(paths):
    # du does not follow source symlinks; all inputs are immutable container paths.
    result = subprocess.check_output(['/usr/bin/du', '-s', '-B1', '--', *paths], text=True, timeout=60)
    return sum(int(line.split()[0]) for line in result.splitlines())


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
    def command(argv, timeout=180):
        require(time.monotonic() - start < 1200, '20-minute preparation deadline')
        log = output / ('command-%03d.log' % len(report['commands']))
        record = {'argv': argv, 'log': log.name, 'returncode': None}
        report['commands'].append(record)
        result = bounded(argv, log=log, timeout=min(timeout, max(1, 1200 - (time.monotonic() - start))))
        record['returncode'] = result['returncode']
        record['error'] = result['error']
        record['log_sha256'] = digest(log)
        require(result['error'] is None and result['returncode'] == 0, 'preparation command failed/overflowed: ' + argv[0])
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
        changed(root, shared + 'minimal.lua', b'hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })\n', report)
        changed(root, shared + 'contract.json', (json.dumps({'nonce': c['nonce'], 'baseline': c['baseline']}, sort_keys=True) + '\n').encode(), report)
        changed(root, shared + 'runtime.lock', ''.join(k + ' ' + v + '\n' for k, v in sorted(runtime.items())).encode(), report)
        flags = subprocess.check_output(['/usr/bin/pkg-config', '--cflags', '--libs', 'egl', 'gbm', 'glesv2', 'libdrm'], text=True, timeout=15).split()
        (root / 'usr/local/bin').mkdir(parents=True, exist_ok=True)
        command(['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '/runner/virtual/gbm_probe.c', '-o', str(root / 'usr/local/bin/gbm-probe'), *flags])
        report['fixture_changes'].append({'path': 'usr/local/bin/gbm-probe', 'after_sha256': digest(root / 'usr/local/bin/gbm-probe'), 'source_sha256': c['runner_sha256']['gbm_probe.c']})
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
