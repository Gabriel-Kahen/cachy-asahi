#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Root-authorized software VM owner; no operation or tool launch on import."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import socket
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('llvm23_actor_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(ok, message):
    if not ok:
        raise ValueError(message)


def domain(status, interfaces, uid_map, host_uid, kvm=False):
    need(all(int(status[n].strip(), 16) == 0 for n in
             ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'))
         and status['NoNewPrivs'].strip() == '1' and interfaces == {'lo'} and not kvm,
         'actual cap0/NNP/no-NIC/no-KVM software-only domain required')
    rows = [line.split() for line in uid_map.splitlines()]
    need(0 < len(rows) <= 64 and all(len(row) == 3 and all(x.isascii() and x.isdigit() for x in row)
         for row in rows), 'bounded numeric kernel UID mapping required')
    maps = [tuple(map(int, row)) for row in rows]
    need(all(length > 0 and inside + length <= 2**32 and outside + length <= 2**32
         for inside, outside, length in maps) and
         [row for row in maps if row[0] == 0] == [(0, host_uid, 1)],
         'rootless container UID0 must map only actual host owner')
    for i, (inside, outside, length) in enumerate(maps):
        for other_inside, other_outside, other_length in maps[i + 1:]:
            need((inside + length <= other_inside or other_inside + other_length <= inside) and
                 (outside + length <= other_outside or other_outside + other_length <= outside),
                 'kernel UID mapping ranges must not overlap')


def qemu_argv(prepared, epoch, limits):
    need(type(limits['cpus']) is int and limits['cpus'] > 0 and
         type(limits['guest_memory_bytes']) is int and limits['guest_memory_bytes'] > 0
         and limits['guest_memory_bytes'] % 1024**2 == 0, 'exact positive Root CPU/MiB guest limits')
    return ['/usr/bin/qemu-system-aarch64', '-machine', 'virt', '-accel', 'tcg,thread=multi',
            '-rtc', 'base=utc,clock=host', '-cpu', 'max', '-smp', str(limits['cpus']),
            '-m', str(limits['guest_memory_bytes'] // 1024**2), '-nodefaults', '-no-user-config',
            '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-kernel', '/inputs/Image', '-append',
            'root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait '
            'init=/usr/lib/systemd/systemd systemd.unit=multi-user.target '
            'arm16k_systemd_nonce=' + prepared['baseline_nonce'] +
            ' arm16k_llvm23_vm_nonce=' + prepared['nonce'] +
            ' arm16k_rtc_host_epoch=' + str(epoch),
            '-drive', 'if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2',
            '-device', 'virtio-blk-device,drive=refdisk',
            '-serial', 'unix:/work/serial.sock,server=on,wait=off',
            '-qmp', 'unix:/work/qmp.sock,server=on,wait=off',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


def run(ctx, prepared, epoch, work, ops):
    K, R, B, O, D = ops.modules()
    limits = ctx['limits']
    deadline = epoch['deadline_monotonic']
    need(epoch['nonce'] == prepared['nonce'] and ctx['nonce'] == prepared['nonce'] and
         type(epoch['utc_ns']) is int and
         0 <= time.time_ns() - epoch['utc_ns'] <= limits['boot_seconds'] * 10**9
         and time.monotonic() < deadline <= ctx['deadline'], 'actual finite Root host boot epoch')
    ctx['active_deadline'] = deadline
    ops.END = deadline
    guard = ops.guard(ctx, work)
    guard()
    need(not (work / 'attempt.json').exists() and not (work / 'attempt.json').is_symlink()
         and not (work / 'overlay.qcow2').exists() and not (work / 'overlay.qcow2').is_symlink(),
         'one fresh owned VM attempt only')
    with (work / 'attempt.json').open('x') as stream:
        stream.write(K.canonical(dict(operation=K.OP, nonce=prepared['nonce'],
                                     source_lock=ctx['source_lock'])).decode())
    budget = (work, sum(limits[n] for n in
              ('overlay_cap_bytes', 'readback_allocated_cap_bytes', 'logs_cap_bytes')), limits['reserve_bytes'])
    paths = ((work / 'overlay.qcow2', limits['overlay_cap_bytes']),
             (work / 'verification.raw', limits['readback_allocated_cap_bytes']))

    def command(label, argv, **options):
        guard()
        row = R.command(argv, work, label, seconds=deadline - time.monotonic(), deadline=deadline,
                        watched_tree=budget, watched_paths=paths, **options)
        guard()
        return row

    command('overlay-create', ['qemu-img', 'create', '-f', 'qcow2', '-F', 'raw',
                              '-b', '/inputs/guest.raw', '/work/overlay.qcow2'])
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    argv = qemu_argv(prepared, epoch['utc_ns'] // 10**9, limits)
    (work / 'qemu-argv.json').write_text(json.dumps(argv, indent=2) + '\n')
    failed = False
    retirement = {}
    try:
        command('qemu', argv, child_file_size_cap=limits['overlay_cap_bytes'])
    except BaseException:
        failed = True
    finally:
        receipt = work / 'qemu.json'
        if receipt.is_file():
            retirement = ops.receipt(receipt)
            retirement['actor_cancelled'] = retirement.get('command_cancelled', [])
            (work / 'qemu-retirement.json').write_bytes(K.canonical(retirement))
    if failed or not R.natural(retirement) or retirement.get('actor_cancelled'):
        return 1
    try:
        guard()
        result = ops.postboot(ctx, work, work / 'overlay.qcow2', guard)
        need(type(result) is dict and result['status'] == 'PASS_COMPLETE_LLVM23_POSTBOOT_PRESERVATION',
             'complete passive postboot preservation receipt required')
        (work / 'postboot-preservation.json').write_bytes(K.canonical(result))
        guard()
    except BaseException as error:
        (work / 'postboot-preservation.json').write_bytes(K.canonical(dict(
            status='HOLD_POSTBOOT_PRESERVATION', nonce=prepared['nonce'],
            failure=dict(category=type(error).__name__, message=str(error)[:1024]))))
        return 1
    return 0


def main():
    ops = load('ops')
    K, R, B, O, D = ops.modules()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and
         os.environ.get('CACHY_LLVM23_VM_BOOT') == '1' and os.geteuid() == 0
         and Path('/.dockerenv').is_file(), 'explicit Root-owned actor entry required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    # Read only the host-authenticated DATA before validating the UID mapping;
    # actor_context revalidates Source/Root/certificate joins before commands.
    manifest = K.load(Path('/inputs/input-manifest.json'))
    domain(status, {name for _, name in socket.if_nameindex()},
           Path('/proc/self/uid_map').read_text(), manifest['ctx']['limits']['host_uid'],
           Path('/dev/kvm').exists())
    ctx = ops.actor_context(Path('/inputs'), Path('/work'), phase='boot')
    prepared = K.load(Path('/inputs/prepared.json'))
    need(manifest['prepared_pin'] == ctx['prepared_pin'] == ctx['authority']['prepared'] ==
         K.pin(Path('/inputs/prepared.json')), 'Root selected complete prepared manifest pin')
    need(prepared['status'] == 'PREPARED_LLVM23_IMAGE_NOT_BOOTED' and prepared['operation'] == K.OP and
         all(prepared[n] == ctx[n] for n in ('source_lock', 'case', 'certs', 'limits', 'kernel', 'tool')) and
         prepared['base_files'] == ctx['base']['files'] and prepared['packet'] == ctx['authority']['packet'] and
         prepared['baseline_nonce'] == ctx['base']['nonce'] and prepared['nonce'] == ctx['nonce'] and
         set(prepared['files']) == {'guest.raw', 'Image', 'kernel.config'}, 'exact actor prepared lineage')
    for name, pin in prepared['files'].items():
        need(K.pin(Path('/inputs') / name, ctx['limits']['prepared_raw_bytes']) == pin,
             'whole readonly actor input changed')
    need(K.pin(Path('/inputs/ownership.json'), 64 * 1024**2) == prepared['ownership'],
         'exact complete baseline ownership before VM')
    need(K.pin(Path('/usr/bin/qemu-system-aarch64')) == ctx['tool']['actual_tool_pin'],
         'exact actual Root-qualified QEMU tool bytes')
    return run(ctx, prepared, K.load(Path('/work/host-epoch.json')), Path('/work'), ops)


if __name__ == '__main__':
    raise SystemExit(main())
