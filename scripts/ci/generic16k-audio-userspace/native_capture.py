#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile the existing host once and capture same-image ELF bytes, build-only."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deps as d


def compile_host(root, common):
    source = d.source(root, 'scripts/ci/asahi-rust-lv2-offline/host.c')
    headers = {}
    for name, (path, expected) in common.HEADERS.items():
        actual = common.digest(path)
        d.need(actual == expected, 'native header differs')
        headers[name] = actual
    flags = common.pkg_flags(common.command(['/usr/bin/pkg-config', '--cflags', '--libs', 'lilv-0'],
                                           'pkg-config', 10))
    host = Path('/tmp/offline/host')
    argv = ['/usr/bin/gcc', *common.FLAGS, str(source), '-o', str(host), *flags, '-ldl', '-lm']
    common.command(argv, 'compile', 60)
    return source, host, argv, headers


def capture(root, image):
    common = d.load(root, 'scripts/ci/asahi-lsp-offline/container.py')
    generic = d.load(root, 'scripts/virtual/generic16k/fixture.py')
    checks = d.load(root, 'scripts/checks/package_checks.py')
    common.assert_isolation()
    common.require(common.mount_readonly('/repo', Path('/proc/self/mountinfo').read_text()), 'isolation')
    before = common.inventory('inventory-before')
    d.need(before == d.POLICY['inventory_sha256'], '574 inventory differs')
    pins = json.loads(d.source(root, 'scripts/ci/asahi-rust-lv2-offline/inputs.json').read_text())
    source, host, argv, headers = compile_host(root, common)
    files, rows, observations = {}, {}, {}
    def add(name, data, mode, origin):
        d.need(name not in files and len(files) < 96 and len(data) <= 16 * 1024**2, 'payload file budget')
        d.need(sum(len(v[1]) for v in files.values()) + len(data) <= 64 * 1024**2, 'payload total budget')
        files[name] = (stat.S_IFREG | mode, data)
        rows[name] = {'bytes': len(data), 'mode': mode, 'sha256': d.sha(data), 'origin': origin}
    pending = [('usr/bin/lv2-host', host, True),
               *[(name, Path('/') / name, False) for name in ('usr/bin/bash', 'usr/bin/uname', 'usr/bin/getconf')]]
    for package in pins['packages']:
        bundle = Path('/candidate') / Path(package['elf_paths'][0]).parent.name
        for member in package['payload']:
            relative = member['path'].removeprefix('/usr/lib/lv2/')
            if member['path'].startswith('/usr/lib/lv2/'):
                src = bundle / Path(relative).name
                data = src.read_bytes()
                d.need(d.sha(data) == member['sha256'], 'accepted bundle differs')
                target = 'candidate/' + relative
                if src.suffix == '.so':
                    pending.append((target, src, True))
                else:
                    add(target, data, member['mode'], 'accepted ' + package['filename'])
        # Notices are read from the exact accepted archive, without package installation.
        archive = Path('/accepted-archives') / package['filename']
        d.need(archive.stat().st_size == package['size'] and d.sha(archive.read_bytes()) == package['sha256'],
               'accepted archive differs')
        wanted = {x['path'].lstrip('/'): x for x in package['payload'] if '/share/licenses/' in x['path']}
        with tarfile.open(archive, 'r:xz') as stream:
            copied = set()
            for member in stream:
                name = member.name.removeprefix('./')
                if name not in wanted:
                    continue
                d.need(member.isfile() and name not in copied and member.size <= 1024**2, 'notice member differs')
                data = stream.extractfile(member).read()
                d.need(d.sha(data) == wanted[name]['sha256'], 'notice hash differs')
                add(name, data, wanted[name]['mode'], 'accepted ' + package['filename'])
                copied.add(name)
        d.need(copied == set(wanted), 'notice set incomplete')
    system_pins_observed = {}
    while pending:
        name, path, audio = pending.pop()
        if name in files:
            origin = rows[name]['origin']
            if audio and origin.startswith('/usr/lib/'):
                key = origin.removeprefix('/usr/lib/')
                d.need(d.POLICY['runtime_system_pins'].get(key) == rows[name]['sha256'], '574 audio library pin differs')
                system_pins_observed[key] = rows[name]['sha256']
            continue
        resolved = path.resolve(strict=True)
        data = common.bounded_bytes(resolved, 16 * 1024**2)
        interpreter, needed = d.closed_elf(data, generic)
        observation = common.elf_observation(resolved, 'payload-' + str(len(files)), checks.elf_check)
        d.need(sorted(needed) == observation['needed'], 'ELF dependency views differ')
        if audio and str(resolved).startswith('/usr/lib/'):
            key = str(resolved).removeprefix('/usr/lib/')
            d.need(d.POLICY['runtime_system_pins'].get(key) == d.sha(data), '574 audio library pin differs')
            system_pins_observed[key] = d.sha(data)
        add(name, data, stat.S_IMODE(path.stat().st_mode) & 0o755, str(resolved))
        observations[name] = observation
        if interpreter:
            pending.append((interpreter.lstrip('/'), Path(interpreter), audio))
        for library in needed:
            d.need(re.fullmatch('[A-Za-z0-9_.+-]+', library), 'ELF library name')
            source_path = next((Path(folder) / library for folder in ('/usr/lib', '/lib')
                                if (Path(folder) / library).is_file()), None)
            d.need(source_path is not None, 'ELF dependency absent in native574 image')
            pending.append((str(source_path).lstrip('/'), source_path, audio))
    d.need(set(system_pins_observed) == set(d.POLICY['runtime_system_pins']), 'complete audio574 library set required')
    add('usr/share/licenses/lv2-host/host.c', source.read_bytes(), 0o644, 'unchanged project C source/MIT')
    after = common.inventory('inventory-after')
    d.need(after == before, 'native inventory changed')
    receipt = {'schema': 1, 'status': 'NATIVE_PAYLOAD_CAPTURED', 'image_id': image,
               'inventory_before': before, 'inventory_after': after, 'inventory_count': 574,
               'host_source_sha256': d.sha(source.read_bytes()), 'host_sha256': rows['usr/bin/lv2-host']['sha256'],
               'host_identity': 'NEW same-job build; historical hash is not a reproduction requirement',
               'compile_argv': argv, 'headers': headers,
               'tools': {n: common.digest('/usr/bin/' + n) for n in ('gcc', 'pkg-config', 'readelf')},
               'files': rows, 'elf': observations, 'system_pins_observed': system_pins_observed,
               'package_archives': [{k: p[k] for k in ('name', 'filename', 'size', 'sha256', 'origin')}
                                    for p in pins['packages']],
               'signature_policy': 'existing retained TEST-signed-native-output identities; no invented detached signature',
               'August_rootfs_used': False, 'DSP_processing': 'NOT RUN', 'hardware': 'NOT RUN'}
    archive = Path('/out/payload.tar')
    with tarfile.open(archive, 'w') as target:
        for name, (mode, data) in sorted(files.items()):
            member = tarfile.TarInfo(name); member.size = len(data); member.mode = stat.S_IMODE(mode)
            member.uid = member.gid = member.mtime = 0
            target.addfile(member, io.BytesIO(data))
    receipt['payload_tar'] = {'bytes': archive.stat().st_size, 'sha256': d.sha(archive.read_bytes())}
    Path('/out/native.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path('/repo'))
    parser.add_argument('--image-id', required=True)
    args = parser.parse_args()
    d.need(re.fullmatch('sha256:[0-9a-f]{64}', args.image_id), 'immutable image ID required')
    capture(args.source_root, args.image_id)
