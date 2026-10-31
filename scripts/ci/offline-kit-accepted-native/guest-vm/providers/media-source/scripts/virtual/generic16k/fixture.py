#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in, diskless generic ARM64 16K page smoke. No package or host actors."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import time

LIMIT = 64 << 20
TOTAL = 256 << 20
HERE = Path(__file__).resolve().parent


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()


def clean(name):
    if name.startswith('/') or '\x00' in name:
        raise ValueError('unsafe archive path')
    parts = []
    for p in name.split('/'):
        if p in ('', '.'): continue
        if p == '..':
            if not parts: raise ValueError('archive path escape')
            parts.pop()
        else: parts.append(p)
    return '/'.join(parts)


class Archive:
    """Read selected regular bytes, flattening guest links without extraction."""
    def __init__(self, path):
        self.tar = tarfile.open(path, 'r:*')
        self.nodes = {}
        self.total = 0
        try:
            for m in self.tar:
                name = clean(m.name)
                if not name: continue
                if name in self.nodes: raise ValueError('duplicate archive path: ' + name)
                self.nodes[name] = m
                if len(self.nodes) > 200000: raise ValueError('archive node budget')
        except BaseException:
            self.tar.close(); raise

    def resolve(self, name):
        name = clean(name)
        seen = set()
        for _ in range(40):
            if name in seen: raise ValueError('link loop')
            seen.add(name)
            parts = name.split('/')
            for i in range(len(parts)):
                key = '/'.join(parts[:i+1]); m = self.nodes.get(key)
                if m is None: raise ValueError('missing guest path: ' + key)
                if m.issym() or m.islnk():
                    target = m.linkname
                    if m.issym() and not target.startswith('/'):
                        target = '/'.join(parts[:i] + [target])
                    name = clean(target.lstrip('/') + '/' + '/'.join(parts[i+1:]))
                    break
                if i < len(parts)-1 and not m.isdir(): raise ValueError('non-directory ancestor')
            else:
                if not m.isfile() or m.size > LIMIT: raise ValueError('guest file type/size')
                return name, m
        raise ValueError('link depth')

    def read(self, name):
        target, m = self.resolve(name)
        self.total += m.size
        if self.total > TOTAL: raise ValueError('guest byte budget')
        with self.tar.extractfile(m) as f: data = f.read(LIMIT + 1)
        if len(data) != m.size: raise ValueError('guest short read')
        return target, data, m.mode


def elf(data):
    """Bounded ELF64 LE AArch64 interpreter and DT_NEEDED reader."""
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('not ELF64 little endian AArch64')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    ents, count = struct.unpack_from('<HH', data, 54)
    if ents != 56 or count > 128 or phoff + count*ents > len(data): raise ValueError('ELF headers')
    loads, dynamic, interp = [], None, None
    def zstr(b):
        if b'\0' not in b: raise ValueError('unterminated ELF string')
        return b.split(b'\0', 1)[0].decode('ascii')
    for i in range(count):
        typ, flags, off, va, pa, size, mem, align = struct.unpack_from('<IIQQQQQQ', data, phoff+i*56)
        if off+size > len(data): raise ValueError('ELF segment bounds')
        if typ == 1: loads.append((va, off, size, align))
        if typ == 2: dynamic = data[off:off+size]
        if typ == 3: interp = zstr(data[off:off+size])
    needed, strings = [], None
    if dynamic is not None:
        if len(dynamic) % 16: raise ValueError('ELF dynamic size')
        for off in range(0, len(dynamic), 16):
            tag, value = struct.unpack_from('<QQ', dynamic, off)
            if tag == 0: break
            if tag == 1: needed.append(value)
            if tag == 5: strings = value
        if needed:
            for va, off, size, _ in loads:
                if strings is not None and va <= strings < va+size:
                    table = data[off+strings-va:off+size]; break
            else: raise ValueError('ELF string table')
            needed = [zstr(table[n:]) for n in needed]
            if any(not re.fullmatch(r'[A-Za-z0-9_.+-]+', n) for n in needed): raise ValueError('ELF library name')
    return interp, needed, loads


def closure(archive):
    files, provenance = {}, {}
    pending = ['usr/bin/bash', 'usr/bin/uname', 'usr/bin/getconf']
    while pending:
        name = pending.pop()
        if name in files: continue
        if len(files) >= 64: raise ValueError('guest closure count')
        target, data, mode = archive.read(name)
        interp, needed, _ = elf(data)
        files[name] = (stat.S_IFREG | (mode & 0o755), data)
        provenance[name] = {'source_path': target, 'sha256': hashlib.sha256(data).hexdigest()}
        if interp:
            if not interp.startswith('/'): raise ValueError('relative interpreter')
            pending.append(clean(interp[1:]))
        for lib in needed:
            for folder in ('usr/lib', 'lib'):
                candidate = folder + '/' + lib
                try: archive.resolve(candidate)
                except ValueError: continue
                pending.append(candidate); break
            else: raise ValueError('missing ELF library: ' + lib)
    return files, provenance


def cpio(files):
    """Deterministic newc archive with only generated directories and fixed nodes."""
    nodes = dict(files)
    for name in list(files):
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.': nodes.setdefault(str(parent), (stat.S_IFDIR | 0o755, b''))
    nodes['dev'] = (stat.S_IFDIR | 0o755, b'')
    nodes['dev/console'] = (stat.S_IFCHR | 0o600, b'')
    nodes['dev/null'] = (stat.S_IFCHR | 0o666, b'')
    out = bytearray()
    for ino, (name, (mode, data)) in enumerate(sorted(nodes.items()) + [('TRAILER!!!', (0, b''))], 1):
        encoded = name.encode() + b'\0'
        fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 5 if name == 'dev/console' else 1 if name == 'dev/null' else 0,
                  1 if name == 'dev/console' else 3 if name == 'dev/null' else 0, len(encoded), 0)
        out += b'070701' + ''.join('%08x' % x for x in fields).encode() + encoded
        out += b'\0' * (-len(out) % 4); out += data; out += b'\0' * (-len(out) % 4)
    return bytes(out)


def init_script(nonce, release):
    if not re.fullmatch(r'[a-f0-9]{32}', nonce) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', release):
        raise ValueError('unsafe guest identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin LC_ALL=C
fail() {{ printf 'FIXTURE16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
release=$(/usr/bin/uname -r) || fail
machine=$(/usr/bin/uname -m) || fail
page=$(/usr/bin/getconf PAGESIZE) || fail
printf 'UNAME16K %s %s\\nGETCONF16K %s\\n' "$machine" "$release" "$page"
[[ "$release" == '{release}' && "$machine" == aarch64 && "$page" == 16384 ]] || fail
/smoke || fail
printf 'FIXTURE16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def validate_output(output, returncode, nonce, release):
    lines = output.replace(b'\r', b'').splitlines()
    expected = [f'UNAME16K aarch64 {release}'.encode(), b'GETCONF16K 16384',
                b'SMOKE16K: mmap,mprotect,file-offset PASS', f'FIXTURE16K PASS {nonce}'.encode()]
    if returncode != 0 or any(lines.count(s) != 1 for s in expected) or b'FIXTURE16K FAIL' in output:
        raise ValueError('guest evidence or natural QEMU exit missing')
    if [lines.index(s) for s in expected] != sorted(lines.index(s) for s in expected):
        raise ValueError('guest evidence order')


def supervise(command, log, timeout=180, output_limit=1 << 20):
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
    data = bytearray(); poll = selectors.DefaultSelector(); poll.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while poll.get_map():
            if time.monotonic() >= deadline: raise TimeoutError('QEMU time budget')
            for key, _ in poll.select(min(.2, max(0, deadline-time.monotonic()))):
                b = os.read(key.fileobj.fileno(), 65536)
                if not b: poll.unregister(key.fileobj); continue
                data.extend(b)
                if len(data) > output_limit: raise ValueError('QEMU output budget')
        code = child.wait(timeout=max(.01, deadline-time.monotonic()))
        return code, bytes(data)
    finally:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=5); child.stdout.close(); poll.close()
        log.write_bytes(data[:output_limit])


def boot_arguments(diagnostics=False):
    base = 'console=ttyAMA0 rdinit=/init panic=-1'
    return base + (' initcall_debug ignore_loglevel printk.time=1' if diagnostics else '')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for opt in ('kernel', 'kernel-receipt', 'kernel-config', 'kernel-release', 'rootfs-tar', 'rootfs-sha256', 'out'):
        p.add_argument('--'+opt, required=True)
    p.add_argument('--execute-in-owned-fixture', action='store_true')
    p.add_argument('--boot-diagnostics', action='store_true')
    p.add_argument('--qemu', default='qemu-system-aarch64')
    a = p.parse_args()
    kernel = Path(a.kernel).resolve(); config = Path(a.kernel_config).resolve()
    receipt = json.loads(Path(a.kernel_receipt).read_text())
    if (receipt.get('status') != 'BUILT_ONLY' or receipt.get('kernel_build') != 'PASS'
            or receipt.get('image', {}).get('sha256') != digest(kernel)
            or receipt.get('config', {}).get('sha256') != digest(config)
            or receipt.get('image_check', {}).get('header_page_size') != 16384
            or receipt.get('module_policy', {}).get('CONFIG_MODULES') != 'n'
            or receipt.get('kernel_release') != a.kernel_release):
        raise ValueError('kernel receipt join')
    settings = set(config.read_text().splitlines())
    for setting in ('CONFIG_ARM64_16K_PAGES=y', 'CONFIG_BLK_DEV_INITRD=y', 'CONFIG_BINFMT_ELF=y', 'CONFIG_BINFMT_SCRIPT=y'):
        if setting not in settings: raise ValueError('missing kernel setting: '+setting)
    if 'CONFIG_MODULES=y' in settings: raise ValueError('this fixture requires the built-in-only kernel')
    if a.boot_diagnostics and (receipt.get('boot_diagnostics') is not True or
            not {'CONFIG_KALLSYMS=y', 'CONFIG_PRINTK_TIME=y'} <= settings):
        raise ValueError('matching named boot diagnostic kernel required')
    if digest(a.rootfs_tar) != a.rootfs_sha256: raise ValueError('rootfs hash')
    out = Path(a.out).absolute(); out.mkdir(mode=0o700)
    nonce = secrets.token_hex(16)
    result = {'status': 'PREPARED_NOT_RUN', 'page_size': 16384, 'kernel_release': a.kernel_release,
              'kernel_sha256': digest(kernel), 'rootfs_sha256': a.rootfs_sha256, 'nonce': nonce,
              'boot_diagnostics': a.boot_diagnostics,
              'scope': 'generic ARM64 page/ELF smoke; no Asahi/M2/platform/performance acceptance'}
    try:
        if kernel.stat().st_size > 256 << 20: raise ValueError('kernel Image byte budget')
        owned_kernel = out/'Image'; shutil.copyfile(kernel, owned_kernel)
        if digest(owned_kernel) != result['kernel_sha256']: raise ValueError('kernel changed during preparation')
        (out/'kernel.config').write_bytes(config.read_bytes())
        if digest(out/'kernel.config') != receipt['config']['sha256']: raise ValueError('config changed during preparation')
        (out/'kernel-build-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        arc = Archive(a.rootfs_tar)
        try: files, sources = closure(arc)
        finally: arc.tar.close()
        smoke = out/'smoke'
        compiler = shutil.which('clang'); linker = shutil.which('ld.lld')
        if not compiler or not linker: raise ValueError('clang/lld unavailable')
        result['tools'] = {name: {'path': str(Path(path).resolve()), 'sha256': digest(path)}
                           for name, path in (('clang', compiler), ('ld.lld', linker))}
        command = [compiler, '--target=aarch64-linux-gnu', '-nostdlib', '-static', '-fuse-ld='+linker,
                   '-fno-stack-protector', '-fno-builtin', '-O2', '-Wl,-z,max-page-size=16384',
                   '-Wl,-e,_start', str(HERE/'smoke.c'), '-o', str(smoke)]
        code, _ = supervise(command, out/'compile.log', timeout=60)
        if code != 0: raise ValueError('smoke compiler failed: see compile.log')
        binary = smoke.read_bytes(); interp, needed, loads = elf(binary)
        if interp or needed or not loads or any(align < 16384 or (va-off) % 16384 for va, off, _, align in loads):
            raise ValueError('static smoke ELF16K alignment')
        files.update({'init': (stat.S_IFREG|0o755, init_script(nonce, a.kernel_release)),
                      'smoke': (stat.S_IFREG|0o755, binary),
                      'page-data': (stat.S_IFREG|0o444, b'A'*16384+b'B'*16384)})
        image = out/'initramfs.cpio'; image.write_bytes(cpio(files))
        result.update({'initramfs_sha256': digest(image), 'selected_sources': sources, 'smoke_build': command,
                       'smoke_source_sha256': digest(HERE/'smoke.c'), 'smoke_sha256': digest(smoke)})
        if a.execute_in_owned_fixture:
            qemu = shutil.which(a.qemu)
            if not qemu: raise ValueError('QEMU executable unavailable')
            result['tools']['qemu'] = {'path': str(Path(qemu).resolve()), 'sha256': digest(qemu)}
            command = [qemu, '-nodefaults', '-machine', 'virt', '-accel', 'tcg', '-cpu', 'max', '-smp', '1',
                       '-m', '512', '-kernel', str(owned_kernel), '-initrd', str(image), '-append',
                       boot_arguments(a.boot_diagnostics), '-nic', 'none', '-display', 'none',
                       '-monitor', 'none', '-serial', 'stdio', '-no-reboot']
            result['qemu_command'] = command
            code, output = supervise(command, out/'uart.log')
            validate_output(output, code, nonce, a.kernel_release)
            result.update(status='PASS', qemu_exit=code, natural_exit=True)
    except BaseException as e:
        result.update(status='FAIL', error=type(e).__name__+': '+str(e)); raise
    finally:
        (out/'fixture-result.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    def terminate(signum, frame): raise KeyboardInterrupt('termination signal')
    signal.signal(signal.SIGTERM, terminate)
    main()
