#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One <=20 minute QEMU TCG generic ARM software trial in a disposable container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
from common import GIB, MAX_LOG, IMAGE_SHA, bounded, check_runtime, contract, digest, free_bytes, guard, json_load, pinned, require, save, LoggedProcess


CAPABILITY_LIMIT = 128 * 1024
CAPABILITIES = (
    ('version', ('--version',), 'version 11.1.2'),
    ('tcg', ('-accel', 'help'), 'tcg'),
    ('virt-machine', ('-machine', 'help'), 'virt-11.1'),
    ('virtio-gpu-pci', ('-device', 'help'), 'virtio-gpu-pci'),
)
CAPABILITY_REASONS = {'timeout', 'output-limit', 'process-failed', 'capability-missing',
                      'launch-failed', 'cancelled'}


class ProofInterrupted(ValueError):
    pass


def capability_projection(rows):
    """Exact finite observations; help output and exception text stay private."""
    require(type(rows) is list and len(rows) <= len(CAPABILITIES), 'invalid capability receipt')
    keys = {'check', 'status', 'returncode', 'reason', 'stdout_sha256', 'stdout_bytes',
            'stderr_sha256', 'stderr_bytes'}
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == keys and type(row['check']) is str and
                type(row['status']) is str and
                row['check'] == CAPABILITIES[index][0] and
                row['status'] in ('STARTING', 'PASS', 'FAIL'), 'invalid capability receipt')
        require(index == len(rows) - 1 or row['status'] == 'PASS', 'invalid capability order')
        code = row['returncode']
        require(code is None or type(code) is int and -64 <= code <= 255, 'invalid capability returncode')
        if row['status'] == 'STARTING':
            require(all(row[key] is None for key in keys - {'check', 'status'}), 'invalid starting capability')
            continue
        require(row['reason'] is None if row['status'] == 'PASS' else
                type(row['reason']) is str and row['reason'] in CAPABILITY_REASONS,
                'invalid capability reason')
        require(row['status'] != 'PASS' or code == 0, 'invalid successful capability')
        if code is None and row['reason'] in ('launch-failed', 'cancelled'):
            require(all(row[key] is None for key in ('stdout_sha256', 'stdout_bytes',
                                                   'stderr_sha256', 'stderr_bytes')),
                    'unobserved capability output must remain absent')
            continue
        total = 0
        for stream in ('stdout', 'stderr'):
            sha, size = row[stream + '_sha256'], row[stream + '_bytes']
            require(type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha) and
                    type(size) is int and 0 <= size <= CAPABILITY_LIMIT * 3,
                    'invalid capability output binding')
            total += size
        require(total <= CAPABILITY_LIMIT * 3, 'invalid capability output bound')
    return [dict(row) for row in rows]


def check_capabilities(report, output):
    rows = report['capabilities'] = []
    for name, arguments, expected in CAPABILITIES:
        row = dict.fromkeys(('returncode', 'reason', 'stdout_sha256', 'stdout_bytes',
                             'stderr_sha256', 'stderr_bytes'))
        row.update(check=name, status='STARTING'); rows.append(row)
        save(output / 'capabilities.json', capability_projection(rows))
        try:
            result = bounded(['/usr/bin/qemu-system-aarch64', *arguments],
                             timeout=15, limit=CAPABILITY_LIMIT)
        except BaseException as error:
            row.update(status='FAIL', reason='cancelled' if isinstance(error, (KeyboardInterrupt, ProofInterrupted))
                       else 'launch-failed')
            save(output / 'capabilities.json', capability_projection(rows))
            raise
        row['returncode'] = result['returncode']
        for stream in ('stdout', 'stderr'):
            data = result[stream].encode()
            row.update({stream + '_bytes': len(data), stream + '_sha256': hashlib.sha256(data).hexdigest()})
        reason = {'timeout': 'timeout', 'output overflow': 'output-limit'}.get(result['error'])
        if result['error'] and reason is None: reason = 'launch-failed'
        if reason is None and result['returncode'] != 0: reason = 'process-failed'
        if reason is None and expected not in result['stdout']: reason = 'capability-missing'
        row.update(status='FAIL' if reason else 'PASS', reason=reason)
        save(output / 'capabilities.json', capability_projection(rows))
        require(reason is None, 'pinned QEMU capability missing: ' + name)


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.buffer = b''
        greeting = self.read(time.monotonic() + 10)
        require('QMP' in greeting, 'invalid QMP greeting')
        version = greeting['QMP']['version']['qemu']
        require(version == {'major': 11, 'minor': 1, 'micro': 2}, 'running QEMU revision differs')
        self.number = 0
        self.execute('qmp_capabilities')
        names = {x['name'] for x in self.execute('query-commands')}
        require({'screendump', 'quit', 'query-status'} <= names, 'required QMP capture commands absent')

    def read(self, deadline):
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'absolute QMP command deadline')
            self.socket.settimeout(min(1, remaining))
            try:
                data = self.socket.recv(65536)
            except socket.timeout:
                continue
            require(data, 'QMP connection closed')
            self.buffer += data
            require(len(self.buffer) <= 1024 ** 2, 'oversized QMP response')
        data, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(data)

    def execute(self, command, arguments=None):
        self.number += 1
        request = {'execute': command, 'id': self.number}
        if arguments is not None:
            request['arguments'] = arguments
        deadline = time.monotonic() + 10
        self.socket.settimeout(10)
        self.socket.sendall((json.dumps(request) + '\n').encode())
        for _ in range(100):
            result = self.read(deadline)
            if result.get('id') == self.number:
                require('return' in result, 'QMP command failed: ' + json.dumps(result))
                return result['return']
        raise ValueError('QMP response flood')

    def close(self):
        self.socket.close()


def inspect_ppm(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 * 1024 ** 2, 'missing/oversized captured frame')
    data = path.read_bytes()
    header = re.match(rb'P6\n([0-9]+) ([0-9]+)\n255\n', data)
    require(header is not None, 'unexpected QEMU PPM header')
    width, height = map(int, header.groups())
    pixels = data[header.end():]
    require(0 < width <= 1920 and 0 < height <= 1200 and len(pixels) == width * height * 3, 'invalid frame geometry/payload')
    colors = len({pixels[i:i+3] for i in range(0, len(pixels), 3)})
    require(colors >= 8, 'blank/near-uniform frame cannot establish software desktop capture')
    return {'filename': path.name, 'sha256': digest(path), 'width': width, 'height': height,
            'distinct_rgb_values': colors, 'visual_review': 'NOT RUN'}


def kill(process):
    if process:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--contract', type=Path, default=Path('/inputs/virtual-contract.json'))
    ap.add_argument('--contract-sha256', required=True)
    ap.add_argument('--prepare-receipt', default='prepared/prepare.json')
    ap.add_argument('--prepare-receipt-sha256', required=True)
    args = ap.parse_args()
    f = guard()
    c = contract(args.contract, args.contract_sha256, f)
    require(os.geteuid() == c['output_uid'], 'runner must use controller UID')
    memory = Path('/sys/fs/cgroup/memory.max').read_text().strip()
    require(memory.isdecimal() and int(memory) <= 6 * GIB, 'outer memory ceiling <=6 GiB required')
    quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
    require(quota.isdecimal() and int(quota) <= 4 * int(period), 'outer CPU ceiling <=4 required')
    output = Path('/out/proof')
    require(not output.exists(), 'fresh fixed proof output required')
    output.mkdir(mode=0o755)
    report = {'status': 'FAILED', 'execution': 'qemu-tcg-generic-aarch64',
              'contract_sha256': args.contract_sha256, 'prepare_receipt_sha256': args.prepare_receipt_sha256,
              'image_id': c['image_id'], 'nonce': c['nonce'], 'frames': {}, 'events': [],
              'software_compositor': 'NOT RUN', 'software_session_ipc': 'NOT RUN', 'frame_proof': 'NOT RUN', 'hardware_validation': 'NOT RUN',
              'graphics_acceleration': 'NOT RUN', 'm2_16k_pages': 'NOT RUN', 'performance': 'NOT RUN', 'commands': []}
    process, qmp, uart, collector = None, None, None, None
    start = time.monotonic()
    def interrupt(*_):
        raise ProofInterrupted('proof interrupted/deadline')
    previous = signal.signal(signal.SIGTERM, interrupt)
    old_alarm = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 1200)
    try:
        check_runtime(c)
        require(set(c.get('runner_sha256', {})) == {'common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c'}, 'complete reviewed runner source map required')
        for name, sha in c['runner_sha256'].items():
            require(digest(Path('/runner/virtual') / name) == sha, 'runner source differs')
        prep = json_load(pinned('/inputs', args.prepare_receipt, args.prepare_receipt_sha256))
        require(prep.get('status') == 'PREPARED' and prep.get('image_id') == c['image_id'] and
                prep.get('nonce') == c['nonce'] and prep.get('contract_sha256') == args.contract_sha256, 'prepared image receipt differs')
        disk = pinned('/inputs', 'prepared/guest.raw', prep['guest_image_sha256'])
        image = pinned('/inputs', 'prepared/Image', prep['kernel_sha256'])
        require(prep['kernel_sha256'] == IMAGE_SHA and disk.stat().st_size == 8 * GIB, 'wrong direct kernel/raw disk')
        require(free_bytes(output) >= GIB, 'insufficient snapshot/evidence disk margin')
        report['free_before_bytes'] = free_bytes(output)
        check_capabilities(report, output)
        qmp_path = Path('/tmp') / ('virtual-' + c['nonce'] + '.qmp')
        uart_path = Path('/tmp') / ('virtual-' + c['nonce'] + '.uart')
        require(not qmp_path.exists() and not uart_path.exists(), 'stale QMP/UART endpoint')
        serial = output / 'serial.log'
        argv = ['/usr/bin/qemu-system-aarch64', '-nodefaults', '-machine', 'virt-11.1', '-accel', 'tcg', '-cpu', 'max',
                '-smp', '2', '-m', '4096', '-kernel', str(image), '-append',
                'console=ttyAMA0 root=/dev/vda rw systemd.unit=virtual-proof.target cachy_asahi_virtual_proof=1',
                '-drive', 'if=none,id=root,file=' + str(disk) + ',format=raw,snapshot=on',
                '-device', 'virtio-blk-pci,drive=root', '-device', 'virtio-gpu-pci,id=gpu,xres=1024,yres=768',
                '-nic', 'none', '-display', 'none', '-audiodev', 'none,id=noaudio', '-monitor', 'none',
                '-chardev', 'socket,id=uart,path=' + str(uart_path) + ',server=on,wait=on',
                '-serial', 'chardev:uart', '-qmp', 'unix:' + str(qmp_path) + ',server=on,wait=off']
        report['qemu_argv'] = argv
        env = {'PATH': '/usr/bin', 'HOME': '/tmp', 'TMPDIR': '/out/proof', 'LANG': 'C.UTF-8'}
        with serial.open('xb') as serial_output:
            collector = LoggedProcess(argv, output / 'qemu.log', env=env, limit=1024 ** 2)
            process = collector.process
            boot_deadline = min(start + 1200, time.monotonic() + 600)
            boot, gbm, passed = False, False, set()
            offset, partial = 0, b''
            while True:
                require(time.monotonic() < start + 1200, '20-minute proof deadline')
                require(process.poll() is None, 'QEMU exited before proof completion')
                require(free_bytes(output) >= 128 * 1024 ** 2, 'snapshot/evidence disk margin exhausted')
                require(sum(p.stat().st_size for p in output.glob('*.log')) <= MAX_LOG, 'diagnostic log limit exceeded')
                if uart is None and uart_path.is_socket():
                    uart = socket.socket(socket.AF_UNIX)
                    uart.settimeout(10)
                    uart.connect(str(uart_path))
                    uart.setblocking(False)
                if qmp is None and qmp_path.is_socket():
                    qmp = QMP(qmp_path)
                if uart is not None:
                    try:
                        block = uart.recv(65536)
                    except BlockingIOError:
                        block = b''
                    offset += len(block)
                    require(offset <= MAX_LOG, 'guest UART output overflow')
                    serial_output.write(block)
                    serial_output.flush()
                    partial += block
                    require(len(partial) <= 2 * 1024 ** 2, 'guest serial event limit exceeded')
                    lines = partial.split(b'\n')
                    partial = lines.pop()
                    for line in lines:
                        line = line.rstrip(b'\r')
                        prefix = b'CACHY_ASAHI_EVENT '
                        if not line.startswith(prefix):
                            continue
                        event = json.loads(line[len(prefix):])
                        report['events'].append(event)
                        kind = event.get('event')
                        require(kind != 'guest_failed', 'guest failed: ' + str(event.get('error')))
                        if kind == 'boot':
                            require(not boot and event.get('nonce') == c['nonce'] and event.get('arch') == 'aarch64' and
                                    event.get('page_size') == 4096, 'guest boot identity differs')
                            boot = True
                        elif kind == 'gbm_pass':
                            require(boot and event.get('nonce') == c['nonce'] and event.get('probe', {}).get('status') == 'PASS', 'software GBM event invalid')
                            gbm = True
                        elif kind == 'frame_ready':
                            stage = event.get('stage')
                            require(gbm and qmp and stage in ('minimal', 'overlay') and stage not in report['frames'], 'invalid/duplicate frame phase')
                            frame = output / (stage + '.ppm')
                            qmp.execute('screendump', {'filename': str(frame), 'device': 'gpu', 'head': 0, 'format': 'ppm'})
                            report['frames'][stage] = inspect_ppm(frame)
                        elif kind == 'phase_pass':
                            require(event.get('stage') in report['frames'], 'phase passed without captured frame')
                            passed.add(event['stage'])
                        elif kind == 'guest_pass':
                            require(gbm and passed == {'minimal', 'overlay'} and event.get('nonce') == c['nonce'], 'incomplete guest proof')
                            report['software_session_ipc'] = 'PASS'
                            report['software_compositor'] = 'REVIEW REQUIRED'
                            report['frame_proof'] = 'REVIEW REQUIRED'
                            report['status'] = 'CAPTURED_REQUIRES_VISUAL_REVIEW'
                            break
                    if report['status'] == 'CAPTURED_REQUIRES_VISUAL_REVIEW':
                        break
                require(boot or time.monotonic() < boot_deadline, 'guest boot 10-minute deadline')
                time.sleep(.1)
            qmp.execute('quit')
            process.wait(timeout=15)
            require(process.returncode == 0, 'unclean QEMU shutdown')
        collector.finish()
        report['free_after_bytes'] = free_bytes(output)
    except Exception as exc:
        report['status'] = 'FAILED'
        report['error'] = str(exc)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        kill(process)
        if uart:
            uart.close()
        if qmp:
            qmp.close()
        if collector:
            try:
                collector.finish()
            except Exception as exc:
                report['status'] = 'FAILED'
                report['logging_error'] = str(exc)
        signal.signal(signal.SIGTERM, previous)
        signal.signal(signal.SIGALRM, old_alarm)
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        report['logs'] = {p.name: {'size': p.stat().st_size, 'sha256': digest(p)} for p in output.glob('*.log')}
        save(output / 'result.json', report)


if __name__ == '__main__':
    main()
