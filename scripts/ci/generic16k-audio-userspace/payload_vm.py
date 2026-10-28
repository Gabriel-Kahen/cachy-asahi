#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Diskless 16KiB audio userspace fixture; source-defined offline correctness only."""
import io
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import tarfile
import deps as d

LIMIT = 1024**2


def payload_files(archive, receipt, generic):
    d.need(receipt['status'] == 'NATIVE_PAYLOAD_CAPTURED' and receipt['schema'] == 1 and
           receipt['inventory_count'] == 574 and receipt['inventory_before'] == receipt['inventory_after'] ==
           d.POLICY['inventory_sha256'] and receipt['August_rootfs_used'] is False, 'native574 receipt required')
    source_pin = d.POLICY['dependencies']['scripts/ci/asahi-rust-lv2-offline/host.c']['sha256']
    d.need(receipt['host_source_sha256'] == source_pin and receipt['system_pins_observed'] ==
           d.POLICY['runtime_system_pins'], 'native source/system library pins differ')
    d.need(receipt['files']['usr/bin/lv2-host']['sha256'] == receipt['host_sha256'], 'new host identity differs')
    d.need(archive.stat().st_size == receipt['payload_tar']['bytes'] <= 64 * 1024**2 and
           d.sha(archive.read_bytes()) == receipt['payload_tar']['sha256'], 'payload archive differs')
    files = {}
    with tarfile.open(archive, 'r:') as stream:
        for entry in stream:
            name = entry.name; parts = PurePosixPath(name)
            d.need(name == str(parts) and not parts.is_absolute() and '..' not in parts.parts and
                   name not in files and entry.isfile() and entry.size <= 16 * 1024**2 and
                   entry.uid == entry.gid == 0, 'payload member refused')
            row = receipt['files'].get(name)
            d.need(row is not None and len(files) < 96 and entry.size == row['bytes'] and
                   entry.mode == row['mode'], 'payload member identity differs')
            data = stream.extractfile(entry).read()
            d.need(d.sha(data) == row['sha256'], 'payload bytes differ')
            if data.startswith(b'\x7fELF'):
                d.closed_elf(data, generic)
            files[name] = (stat.S_IFREG | entry.mode, data)
    d.need(set(files) == set(receipt['files']) and 'usr/bin/lv2-host' in files, 'closed payload required')
    for name, (mode, data) in files.items():
        if not data.startswith(b'\x7fELF'):
            continue
        interpreter, libraries = d.closed_elf(data, generic)
        if interpreter:
            d.need(interpreter.lstrip('/') in files, 'payload interpreter missing')
        for library in libraries:
            d.need(any(folder + library in files for folder in ('usr/lib/', 'lib/')),
                   'payload library missing: ' + library)
    return files


def script(nonce, release):
    d.need(re.fullmatch('[0-9a-f]{32}', nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}', release), 'guest identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C LV2_PATH=/tmp/empty
fail() {{ printf 'AUDIO16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
machine=$(/usr/bin/uname -m) || fail
release=$(/usr/bin/uname -r) || fail
page=$(/usr/bin/getconf PAGESIZE) || fail
printf 'UNAME16K %s %s\\nGETCONF16K %s\\n' "$machine" "$release" "$page"
[[ "$machine" == aarch64 && "$release" == '{release}' && "$page" == 16384 ]] || fail
/smoke || fail
/usr/bin/lv2-host --loader /candidate/bankstown.lv2/bankstown.so --uri https://chadmed.au/bankstown > /tmp/bankstown.json || fail
printf 'AUDIO16K_REPORT bankstown %s\\n' "$(< /tmp/bankstown.json)"
/usr/bin/lv2-host --loader /candidate/triforce.lv2/triforce.so --uri https://chadmed.au/triforce > /tmp/triforce.json || fail
printf 'AUDIO16K_REPORT triforce-lv2 %s\\n' "$(< /tmp/triforce.json)"
/usr/bin/lv2-host --bundle /candidate > /tmp/processing.json || fail
printf 'AUDIO16K_REPORT processing %s\\n' "$(< /tmp/processing.json)"
printf 'AUDIO16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def reports(output, code, nonce, release, receipt, root):
    d.need(code == 0 and len(output) <= LIMIT, 'natural bounded QEMU exit0 required')
    lines = output.replace(b'\r', b'').splitlines()
    required = [f'UNAME16K aarch64 {release}'.encode(), b'GETCONF16K 16384',
                b'SMOKE16K: mmap,mprotect,file-offset PASS', f'AUDIO16K PASS {nonce}'.encode()]
    d.need(all(lines.count(x) == 1 for x in required) and b'AUDIO16K FAIL' not in output, 'guest markers missing')
    positions = [lines.index(x) for x in required]
    d.need(positions == sorted(positions), 'guest marker order')
    raw_reports, locations = {}, []
    for index, line in enumerate(lines):
        if not line.startswith(b'AUDIO16K_REPORT '):
            continue
        _, tag, raw = line.split(b' ', 2)
        name = tag.decode('ascii')
        d.need(name in ('bankstown', 'triforce-lv2', 'processing') and name not in raw_reports and
               len(raw) <= 128 * 1024, 'audio report set/budget')
        raw_reports[name] = raw; locations.append((index, name))
    d.need([x[1] for x in locations] == ['bankstown', 'triforce-lv2', 'processing'] and
           positions[2] < locations[0][0] < locations[-1][0] < positions[3], 'audio call ordering')
    rust = d.load(root, 'scripts/ci/asahi-rust-lv2-offline/container.py')
    common = d.load(root, 'scripts/ci/asahi-lsp-offline/container.py')
    rust.common = lambda: common  # Private import namespace; unchanged strict numerical projection.
    processing = rust.project_processing(raw_reports['processing'])
    loaders = {}
    for name, uri, path in (('bankstown', 'https://chadmed.au/bankstown', 'candidate/bankstown.lv2/bankstown.so'),
                            ('triforce-lv2', 'https://chadmed.au/triforce', 'candidate/triforce.lv2/triforce.so')):
        row = rust.document(raw_reports[name], 'loader')
        rust.exact(row, ('schema_version', 'mode', 'status', 'selected_uris', 'descriptor_count', 'loaded_basenames',
                         'loaded_paths', 'failure_class', 'audio_devices', 'hardware', 'optimization_acceptance'))
        d.need(row['selected_uris'] == [uri] and type(row['descriptor_count']) is int and row['descriptor_count'] == 1 and
               row['audio_devices'] == 'NOT USED' and row['hardware'] == row['optimization_acceptance'] == 'NOT RUN',
               'loader contract differs')
        names, paths = row['loaded_basenames'], row['loaded_paths']
        d.need(type(names) is list and type(paths) is list and 1 <= len(names) == len(paths) <= 128 and
               len(set(names)) == len(names), 'loader list differs')
        observed = []
        for basename, actual in zip(names, paths):
            if basename == 'linux-vdso.so.1':
                d.need(actual is None, 'vDSO path differs')
                continue
            d.need(type(actual) is str and actual.startswith('/') and
                   PurePosixPath(actual).name == basename and actual.lstrip('/') in receipt['files'],
                   'loader used a file outside the captured ELF closure')
            observed.append({'path': actual, 'sha256': receipt['files'][actual.lstrip('/')]['sha256']})
        d.need('/' + path in [x['path'] for x in observed], 'selected candidate absent from loader')
        loaders[name] = {'status': 'PASS', 'selected_uris': [uri], 'libraries': observed}
    return {'processing': processing, 'loader': loaders,
            'guest': {'machine': 'aarch64', 'kernel_release': release, 'page_size': 16384,
                      'exact_markers_once_in_order': [line.decode() for line in required]},
            'uart': {'bytes': len(output), 'sha256': d.sha(output)}}


def run(root, archive, receipt, kernel_receipt, output):
    generic = d.load(root, 'scripts/virtual/generic16k/fixture.py')
    d.need(kernel_receipt['status'] == 'BUILT_ONLY' and kernel_receipt['kernel_build'] == 'PASS' and
           kernel_receipt['boot_diagnostics'] is True and
           kernel_receipt['image_check']['header_page_size'] == 16384 and
           kernel_receipt['module_policy']['CONFIG_MODULES'] == 'n', 'successful diagnostic kernel receipt required')
    d.need(kernel_receipt['archive']['sha256'] == '874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad' and
           kernel_receipt['source_commit'] == '94fb23346d522edf53722357c426a3e58030beea' and
           kernel_receipt['helper']['sha256'] == d.POLICY['dependencies']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
           'held generic kernel source/build helper required')
    image = Path(kernel_receipt['image']['path']); config = Path(kernel_receipt['config']['path'])
    d.need(image.stat().st_size == kernel_receipt['image']['bytes'] <= 256*1024**2, 'kernel Image bound')
    d.need(d.sha(image.read_bytes()) == kernel_receipt['image']['sha256'] and
           d.sha(config.read_bytes()) == kernel_receipt['config']['sha256'], 'kernel input differs')
    settings = set(config.read_text().splitlines())
    d.need({'CONFIG_ARM64_16K_PAGES=y', 'CONFIG_KALLSYMS=y', 'CONFIG_PRINTK_TIME=y'} <= settings and
           'CONFIG_MODULES=y' not in settings, 'diagnostic kernel configuration differs')
    output.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'scope': 'generic ARM64 16KiB existing Rust LV2 software properties',
              'native_host_sha256': receipt['host_sha256'], 'payload_tar_sha256': receipt['payload_tar']['sha256'],
              'kernel_sha256': kernel_receipt['image']['sha256'], 'hardware': 'NOT RUN',
              'audio_devices': 'NOT USED', 'performance': 'NOT RUN'}
    try:
        files = payload_files(archive, receipt, generic)
        owned_image = output/'Image'; shutil.copyfile(image, owned_image)
        d.need(d.sha(owned_image.read_bytes()) == result['kernel_sha256'], 'copied Image differs')
        nonce = secrets.token_hex(16); release = kernel_receipt['kernel_release']
        smoke = output/'smoke'; compiler = shutil.which('clang'); linker = shutil.which('ld.lld')
        d.need(compiler and linker, 'clang/lld required for unchanged page probe')
        source = d.source(root, 'scripts/virtual/generic16k/smoke.c')
        command = [compiler, '--target=aarch64-linux-gnu', '-nostdlib', '-static', '-fuse-ld=' + linker,
                   '-O2', '-fno-stack-protector', '-fno-builtin', '-Wl,-z,max-page-size=16384',
                   '-Wl,-e,_start', str(source), '-o', str(smoke)]
        code, _ = generic.supervise(command, output/'compile.log', 60)
        d.need(code == 0, 'page probe build failed')
        binary = smoke.read_bytes(); d.closed_elf(binary, generic)
        files.update({'init': (stat.S_IFREG|0o755, script(nonce, release)),
                      'smoke': (stat.S_IFREG|0o755, binary),
                      'page-data': (stat.S_IFREG|0o444, b'A'*16384+b'B'*16384),
                      'tmp/empty': (stat.S_IFDIR|0o755, b'')})
        initramfs = output/'initramfs.cpio'; initramfs.write_bytes(generic.cpio(files))
        qemu = shutil.which('qemu-system-aarch64'); d.need(qemu, 'QEMU unavailable')
        command = [qemu, '-nodefaults', '-machine', 'virt', '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512',
                   '-kernel', str(owned_image), '-initrd', str(initramfs), '-append', generic.boot_arguments(True),
                   '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot']
        result.update(nonce=nonce, kernel_release=release, qemu_argv=command,
                      initramfs_sha256=d.sha(initramfs.read_bytes()), page_probe_source_sha256=d.sha(source.read_bytes()),
                      tools={name: d.sha(Path(path).read_bytes()) for name, path in
                             (('clang', compiler), ('ld.lld', linker), ('qemu', qemu))},
                      QEMU_seconds=600, UART_byte_limit=LIMIT)
        code, uart = generic.supervise(command, output/'uart.log', 600, LIMIT)
        result.update(reports(uart, code, nonce, release, receipt, root),
                      status='PASS_GENERIC_16K_AUDIO_SOFTWARE_ONLY', QEMU_exit=code, natural_exit=True)
    finally:
        (output/'vm.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result
