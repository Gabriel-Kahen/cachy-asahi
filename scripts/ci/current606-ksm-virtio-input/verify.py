# SPDX-License-Identifier: MIT
"""Check the source-only plan or emit a kernel profile from a complete job-owned build."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct

HERE = Path(__file__).resolve().parent
SOURCE = '94fb23346d522edf53722357c426a3e58030beea'
ARCHIVE = {'bytes': 262965559, 'sha256': '874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'}
PARENT = '5a643db838759d7cf574e596efbcd45b1df96984'
PARENT_TREE = 'f678cbc8338c0e0a29c09be08de8f5c6830e6741'
PROFILE = 'KSM_ADVICE_VIRTIO_INPUT_GENERIC16K_DIAGNOSTIC_V1'
RELEASE = '7.1.13-generic16k-managed-gui'
DELTA = {'CONFIG_VIRTIO_INPUT': {'before': 'n', 'after': 'y'}}
FRAGMENT_ADD = b'CONFIG_VIRTIO_INPUT=y\n'
DIAGNOSTICS = b'CONFIG_KALLSYMS=y\nCONFIG_PRINTK_TIME=y\n'
PINS = {
    'base.config': '5f1f5e507586734c0955607960ceecfe822b5c908bfc1da9d29fe80ac627a8e9',
    'base-build-receipt.json': 'fdd538c9e3c73f906da0c82f0b381b0385306a52d0dc1539ab13ceaa69938398',
    'build_kernel.py': 'ee3bc29634588e5c32d9521c95d8f98a6d350963ad8fe41060ad61eff99427c2',
    'kernel.fragment': '5658e06608f2a6bb7b2f89d38003a0b1327347e4aecf189c25f02f7d17de96c9',
    'diagnostic.fragment': '1e87785cc2f8ba1127b0f24c135191cfbf59496911b3c11efdf195b8328f5121',
}
EXPECTED_CONFIG = {'bytes': 63782, 'sha256': '89823436abe3b5e4d1abd6fd28cfc8dd81e1601e5ce44b6b09c2b486b66b1607'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path, cap):
    need(path.is_absolute() and path.resolve() == path and not any(p.is_symlink() for p in path.parents),
         'ordinary absolute path required')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
         'bounded single-link regular operand required')
    body = path.read_bytes()
    after = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(body) == before.st_size and identity(before) == identity(after), 'operand changed during read')
    return body


def source(root):
    raw = {name: read(root/name, 256 << 10) for name in PINS if name != 'diagnostic.fragment'}
    need(all(pin(body)['sha256'] == PINS[name] for name, body in raw.items()), 'exact combined kernel source pins')
    fragment = raw['kernel.fragment']
    need(fragment.endswith(FRAGMENT_ADD) and pin(fragment.removesuffix(FRAGMENT_ADD))['sha256'] ==
         'f4a6dc3fbebd5f0e184422cddc490e47e6737d208c55b7df255b678604fe9267', 'single appended input option')
    diagnostic = fragment + DIAGNOSTICS
    need(pin(diagnostic)['sha256'] == PINS['diagnostic.fragment'], 'exact combined diagnostic fragment')
    base = raw['base.config']
    held = ('CONFIG_KSM=y', 'CONFIG_ADVISE_SYSCALLS=y', 'CONFIG_XXHASH=y', 'CONFIG_VIRTIO=y',
            'CONFIG_VIRTIO_PCI=y', 'CONFIG_VIRTIO_MMIO=y', 'CONFIG_INPUT=y', 'CONFIG_INPUT_EVDEV=y',
            '# CONFIG_MODULES is not set', 'CONFIG_ARM64_16K_PAGES=y', '# CONFIG_VIRTIO_INPUT is not set')
    need(all(key.encode() in base.splitlines() for key in held), 'exact KSM, input dependencies, both buses and 16KiB baseline')
    combined = base.replace(b'# CONFIG_VIRTIO_INPUT is not set\n', FRAGMENT_ADD, 1)
    need(pin(combined) == EXPECTED_CONFIG, 'single exact generated-config delta')
    return {name: pin(body) for name, body in raw.items()}, combined, diagnostic, json.loads(raw['base-build-receipt.json'])


def file_join(path, row, cap):
    body = read(path, cap)
    need(row == dict(path=str(path), **pin(body)), 'receipt does not join exact owned ' + path.name)
    return body


def complete(out):
    need(out.is_absolute() and out.resolve() == out and out.name == 'built' and out.is_dir() and not out.is_symlink(),
         'exact job-owned helper/built directory required')
    pins, expected, diagnostic, base = source(out.parent)
    receipt = json.loads(read(out/'build-receipt.json', 128 << 10))
    need(receipt['status'] == 'BUILT_ONLY' and receipt['kernel_build'] == 'PASS'
         and receipt['guest_boot'] == receipt['hardware'] == receipt['performance'] == 'NOT RUN'
         and receipt['profile'] == PROFILE and receipt['kernel_release'] == RELEASE
         and receipt['source_commit'] == SOURCE and receipt['boot_diagnostics'] is True
         and receipt['tools'] == base['tools'] and receipt['build_environment']['host_uname'][-1] == 'aarch64'
         and all(receipt['build_environment'][key] == base['build_environment'][key]
                 for key in ('jobs', 'build_seconds', 'workspace_limit_bytes', 'per_file_limit_bytes')),
         'complete original native build with exact source, tools and bounded settings')
    need({key: receipt['archive'][key] for key in ARCHIVE} == ARCHIVE
         and receipt['module_policy'] == {'CONFIG_MODULES': 'n', 'external_modules_allowed': False}
         and receipt['config_check'] == {'page_size': 16384, 'modules': 'DISABLED', 'all_fragment_values_match': True,
                                         'exact_sole_delta': DELTA}, 'exact archive and built-in config receipt')
    for role, name in (('helper', 'build_kernel.py'), ('fragment', 'kernel.fragment')):
        need(receipt[role] == dict(path=str(out.parent/name), **pins[name]), 'receipt source role differs: '+role)
    need(file_join(out/'diagnostic.fragment', receipt['diagnostic_fragment'], 4096) == diagnostic,
         'combined diagnostic fragment differs')
    commands = receipt['commands']
    need(type(commands) is list and len(commands) == 2, 'exact configure and compile command roles')
    prefix = ['/usr/bin/make', '-C', str(out/'linux-asahi-7.1.13-3'), 'O='+str(out/'build'), 'ARCH=arm64', 'LLVM=1']
    for row, target, name in zip(commands, (['allnoconfig'], ['-j2', 'Image']), ('configure.log', 'build.log'), strict=True):
        path = out/name
        body = read(path, 16 << 20)
        need(row == {'argv': prefix+target, 'log': str(path), 'returncode': 0,
                     'log_sha256': pin(body)['sha256'], 'log_bytes': len(body)}, 'exact successful command and log join')
    cfg = file_join(out/'build/.config', receipt['config'], 256 << 10)
    need(cfg == expected, 'generated output changed outside the sole virtio-input option')
    image = file_join(out/'build/arch/arm64/boot/Image', receipt['image'], 256 << 20)
    need(len(image) >= 64 and image[56:60] == b'ARM\x64', 'AArch64 Image header required')
    flags = struct.unpack_from('<Q', image, 24)[0]
    need(flags & 1 == 0 and (flags >> 1) & 3 == 2 and receipt['image_check'] ==
         {'header_page_size': 16384, 'flags': flags, 'boot': 'NOT RUN'}, 'little-endian 16KiB Image header required')
    symbols = file_join(out/'build/System.map', receipt['system_map'], 32 << 20)
    need(re.search(rb'^[\da-fA-F]+ [tT] virtinput_probe$', symbols, re.M) is not None and
         re.search(rb'^[\da-fA-F]+ [dD] virtio_input_driver$', symbols, re.M) is not None,
         'linked virtio-input driver and probe required in System.map')
    return {'schema_version': 1, 'profile': PROFILE, 'release': RELEASE, 'architecture': 'aarch64',
            'page_size': 16384, 'source_revision': SOURCE, 'archive_sha256': ARCHIVE['sha256'],
            'helper_sha256': PINS['build_kernel.py'], 'fragment_sha256': PINS['kernel.fragment'],
            'diagnostic_fragment_sha256': PINS['diagnostic.fragment'], 'Image': pin(image), 'config': pin(cfg),
            'modules': 'DISABLED'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='completed absolute job-owned helper/built directory')
    args = parser.parse_args()
    if args.output is not None:
        report = complete(args.output)
    else:
        pins, cfg, diagnostic, _ = source(HERE)
        report = {'status': 'SOURCE_ONLY_PLAN', 'profile': PROFILE, 'release': RELEASE, 'source_revision': SOURCE,
                  'parent': {'source': PARENT, 'tree': PARENT_TREE}, 'archive': ARCHIVE, 'source_files': pins,
                  'expected_config': pin(cfg), 'diagnostic_fragment': pin(diagnostic), 'sole_delta': DELTA,
                  'build': 'NOT RUN', 'boot': 'NOT RUN', 'hardware': 'NOT RUN', 'authority': None}
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
