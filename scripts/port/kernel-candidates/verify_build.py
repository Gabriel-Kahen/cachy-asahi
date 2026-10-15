#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only future native-build checks; never install or certify hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import stat
import zlib

import harness


def config_bytes(raw):
    harness.need(len(raw) <= LIMIT_CONFIG, 'bounded config bytes required')
    text = raw.decode('utf-8')
    settings = {}
    for line in text.splitlines():
        match = re.fullmatch(r'(CONFIG_[A-Za-z0-9_]+)=(.*)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set', line)
        if match or disabled:
            name = (match or disabled)[1]
            harness.need(name not in settings, 'duplicate config setting')
            settings[name] = match[2] if match else 'n'
        else:
            harness.need(not line or line.startswith('#'), 'malformed generated config line')
    harness.need(set(harness.GUARDS) <= set(text.splitlines()), 'Apple/16K config guards differ')
    return settings


def config(path):
    harness.regular(path, LIMIT_CONFIG)
    return config_bytes(path.read_bytes())


def verify_config(expected, actual):
    harness.regular(expected, LIMIT_CONFIG); harness.regular(actual, LIMIT_CONFIG)
    before_raw, after_raw = expected.read_bytes(), actual.read_bytes()
    before, after = config_bytes(before_raw), config_bytes(after_raw)
    delta = {key: [before.get(key), after.get(key)] for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
    harness.need(not delta, 'generated configuration differs: ' + json.dumps(delta, sort_keys=True))
    return {'status': 'CONFIG_IDENTICAL', 'expected_sha256': hashlib.sha256(before_raw).hexdigest(),
            'generated_sha256': hashlib.sha256(after_raw).hexdigest(), 'setting_count': len(before)}


# Selected unmodified files in the independently checked 94fb source archive.
SOURCE_COMMIT = '94fb23346d522edf53722357c426a3e58030beea'
SOURCE_PINS = {
    'arch/arm64/boot/dts/apple/t8112-j413.dts': '753dc7bb3fe2d3b87222b106f6982a6da5b78fdc1519eb6e2b00de520c81c6e6',
    'arch/arm64/boot/dts/apple/t8112-j415.dts': '925e48ab78bae91c07610b29169c05444e2379fef78fdd686623b10f5a35f912',
    'arch/arm64/include/asm/image.h': '44566a36d241a88d10681e4b54c1241ddde696afa74417516b49a3e98c8c827d',
    'arch/arm64/kernel/image.h': '38250b439a9f562a38c590755237d4557768cabc8b803d186d9c618feeebebfa',
    'arch/arm64/kernel/efi-header.S': 'aa9b5a1f28bd01da995ff4d2298181a49932a6bfb33c5148e294b4385f42278a',
    'arch/arm64/kernel/head.S': 'db56887baf6cb87c24974609ffdb76ed5765a3756739c50a44384e384925977d',
    'arch/arm64/Makefile': '5a9d21434edc1e6220dbd8054610eb25aef675d1a25fbe54d7299eec375ae293',
    'arch/arm64/boot/Makefile': '4f40f40d639364121150113999a06d3a9d7441c6f7c607992560fc0655488b10',
    'include/linux/export.h': '4ad93a3c87f955bad3fde700801cc787b9d50b30137e6db5aff45001fe678b9d',
    'include/linux/kvm_types.h': 'be96e612d8c61f46357615b104ab89f6b9f1810e91f05606fc11310ff3731a36',
    'mm/filemap.c': 'f903eff6e896c52fe04a0eb7601d23da9e891ebbe6b615ab3d6b22ebec2a7d66',
    'include/linux/vermagic.h': '0556c28fe7711d0383dbd5e91667560c1b96a9a914d4d15e2fdd85dea3671aea',
    'arch/arm64/include/asm/vermagic.h': 'c1d4fcab34100e6d5a58bae03b59a99de671bf1afce7c099047793d28aa7dd0b',
    'kernel/configs.c': 'c355fb8c6968035fe662aa6105d4cbfb68ff39528b2b1a6b8178c13d5b38bd8a',
    'kernel/Makefile': '18ab5bdeb31f60dd99554e807be2042b2733451d3bd10b74c1e7ea8603c5eeda',
    'scripts/Makefile.modfinal': '30cdc5efb0dcf93bb58a5960192798b681519c53989748897c08e2f6b9d69e25',
    'scripts/mod/modpost.c': '5e628987885cfe158ec063cdb756dc74f31d8a919ddb4c82c238b63066d603e8',
    'sound/soc/apple/Makefile': '1c6a295fbee056d082a9d87d55c1b07f70494e5f65535bd4598fad4da8a3f869',
    'Makefile': '8565c2fa8574b1cb2f4ae32acdcfcef4b946397df990fa50d26a75617fe6388d',
}
APPLE_MODULES = {'CONFIG_SND_SOC_APPLE_MCA': 'sound/soc/apple/snd-soc-apple-mca.ko',
                 'CONFIG_SND_SOC_APPLE_MACAUDIO': 'sound/soc/apple/snd-soc-macaudio.ko',
                 'CONFIG_SND_SOC_APPLE_AOP_AUDIO': 'sound/soc/apple/snd-soc-aop.ko'}
LIMIT_CONFIG = 1024**2


def source_evidence(source):
    snapshots = {name: pinned_bytes(source / name, pin) for name, pin in SOURCE_PINS.items()}
    identities = {}
    for board in ('j413', 'j415'):
        text = snapshots['arch/arm64/boot/dts/apple/t8112-' + board + '.dts'].decode('utf-8')
        root = re.search(r'/ \{\s*compatible = ([^;]+);\s*model = "([^"\n]+)";', text)
        harness.need(root, 'pinned DTS root identity required')
        compatible = re.findall(r'"([^"\n]+)"', root[1])
        identities['t8112-' + board + '.dtb'] = {
            'compatible': b''.join(x.encode('ascii') + b'\0' for x in compatible),
            'model': root[2].encode('ascii') + b'\0'}
    return identities


def cstring(data, offset, limit=4096):
    harness.need(0 <= offset < len(data), 'string offset outside table')
    end = data.find(b'\0', offset, min(len(data), offset + limit))
    harness.need(end >= 0, 'bounded terminated string required')
    return data[offset:end]


def verify_dtb(path, expected):
    harness.regular(path, 4 * 1024**2)
    data = path.read_bytes()
    harness.need(len(data) >= 40, 'full FDT header required')
    magic, total, start, strings, reserve, version, compat, _, nstrings, nstruct = struct.unpack_from('>10I', data)
    harness.need(magic == 0xd00dfeed and total == len(data) and version >= 17 and 16 <= compat <= 17 and compat <= version,
                 'complete backwards-compatible FDT17 header required')
    harness.need(reserve >= 40 and reserve % 8 == 0 and start % 4 == 0 and nstruct % 4 == 0 and
                 reserve < start < strings and nstruct >= 16 and nstrings > 0 and
                 start + nstruct <= strings and strings + nstrings <= total, 'FDT block bounds/alignment/order required')
    regions, pos = [], reserve
    while pos + 16 <= start:
        addr, size = struct.unpack_from('>QQ', data, pos); pos += 16
        if addr == size == 0:
            break
        harness.need(size > 0 and addr + size <= 2**64 and len(regions) < 4096, 'bounded valid FDT reservation required')
        regions.append((addr, addr + size))
    else:
        raise ValueError('FDT reservation terminator absent')
    regions.sort()
    harness.need(all(a[1] <= b[0] for a, b in zip(regions, regions[1:])), 'overlapping FDT reservations')
    table = data[strings:strings + nstrings]
    harness.need(table.endswith(b'\0'), 'FDT strings table must end in NUL')
    # Name offsets may legally refer to shared suffixes inside another string.
    stack, seen, root_properties, tokens = [], set(), {}, 0
    pos, end, root_closed = start, start + nstruct, False
    while pos < end:
        harness.need(pos + 4 <= end, 'truncated FDT token')
        token = struct.unpack_from('>I', data, pos)[0]; pos += 4; tokens += 1
        harness.need(tokens <= 262144, 'FDT token budget exceeded')
        if token == 1:
            harness.need(not root_closed and len(stack) < 128, 'FDT root/depth invalid')
            name = cstring(data, pos, 256)
            harness.need((not stack and not seen and name == b'') or (stack and name and re.fullmatch(rb'[A-Za-z0-9,._+@-]+', name)), 'invalid FDT node name/root')
            padded = (pos + len(name) + 1 + 3) & ~3
            harness.need(padded <= end and not any(data[pos + len(name) + 1:padded]), 'FDT node padding invalid')
            pos = padded
            nodepath = (stack[-1]['path'] + (name,)) if stack else ()
            harness.need(nodepath not in seen, 'duplicate FDT node')
            seen.add(nodepath)
            if stack:
                stack[-1]['children'] = True
            stack.append({'path': nodepath, 'properties': set(), 'children': False})
        elif token == 2:
            harness.need(stack, 'unmatched FDT end-node')
            stack.pop()
            if not stack:
                root_closed = True
        elif token == 3:
            harness.need(stack and not stack[-1]['children'] and pos + 8 <= end, 'FDT property placement/truncation')
            length, nameoff = struct.unpack_from('>II', data, pos); pos += 8
            name = cstring(table, nameoff, 256)
            harness.need(name and all(33 <= b <= 126 for b in name) and name not in stack[-1]['properties'], 'FDT property name/duplicate invalid')
            stack[-1]['properties'].add(name)
            padded = (pos + length + 3) & ~3
            harness.need(padded <= end and not any(data[pos + length:padded]), 'FDT property bounds/padding invalid')
            if len(stack) == 1 and name in (b'model', b'compatible'):
                root_properties[name.decode('ascii')] = data[pos:pos + length]
            pos = padded
        elif token == 4:
            continue
        elif token == 9:
            harness.need(root_closed and not stack and pos == end, 'FDT final END/root required')
            break
        else:
            raise ValueError('unknown FDT token')
    else:
        raise ValueError('FDT final END absent')
    harness.need(root_properties == expected, 'Apple DTB identity differs from pinned J413/J415 DTS')
    return {'sha256': harness.digest(path), 'nodes': len(seen), 'reservations': len(regions),
            'version': version, 'model': expected['model'][:-1].decode('ascii'),
            'compatible': expected['compatible'][:-1].decode('ascii').split('\0')}


class ELF:
    """Bounded ELF64 reader; never execute tools or map a multi-GiB ELF into RAM."""
    def __init__(self, path, kind, cap, *, artifact_role='elf'):
        harness.regular(path, cap)
        self.path, self.size = path, path.stat().st_size
        self.stream = path.open('rb')
        try:
            self.parse(kind, artifact_role=artifact_role)
        except BaseException:
            self.stream.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.stream.close()

    def read(self, offset, size, cap=128 * 1024**2):
        harness.need(0 <= offset <= self.size and 0 <= size <= cap and offset + size <= self.size, 'bounded ELF range required')
        self.stream.seek(offset)
        data = self.stream.read(size)
        harness.need(len(data) == size, 'ELF short read')
        return data

    def parse(self, kind, *, artifact_role='elf'):
        # Only the Source-bound Image projection caller selects this artifact role.
        harness.need(type(artifact_role) is str and artifact_role in ('elf', 'arm64-image-reference') and
                     (artifact_role == 'elf' or kind in (2, 3)),
                     'valid config-selected AArch64 ELF type/version/header required')
        kernel_image = artifact_role == 'arm64-image-reference'
        header = self.read(0, 64)
        ident = header[:16]
        harness.need(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and ident[8] == 0 and not any(ident[9:]),
                     'ELF64 little-endian current-version identity required')
        typ, machine, version, self.entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstrings = struct.unpack_from('<HHIQQQIHHHHHH', header, 16)
        harness.need(typ == kind and machine == 183 and version == 1 and flags == 0 and ehsize == 64,
                     'valid config-selected AArch64 ELF type/version/header required')
        harness.need(shsize == 64 and 1 < shnum <= 8192 and 0 < shstrings < shnum and shoff >= 64 and shoff % 8 == 0,
                     'bounded ELF section headers required')
        shdata = self.read(shoff, shsize * shnum)
        self.sections = [dict(zip(('nameoff', 'type', 'flags', 'addr', 'offset', 'size', 'link', 'info', 'align', 'entsize'),
                                  struct.unpack_from('<IIQQQQIIQQ', shdata, i * 64))) for i in range(shnum)]
        harness.need(not any(self.sections[0].values()), 'ELF section zero invalid')
        names = self.sections[shstrings]
        harness.need(names['type'] == 3 and names['size'] > 0, 'ELF section-name string table required')
        strings = self.read(names['offset'], names['size'])
        self.by_name, ranges = {}, [(0, 64), (shoff, shoff + len(shdata))]
        for index, row in enumerate(self.sections):
            name = cstring(strings, row['nameoff']).decode('ascii')
            row['name'], row['index'] = name, index
            if index:
                harness.need(name and name not in self.by_name and row['link'] < shnum and
                             (row['align'] in (0, 1) or row['align'] & (row['align'] - 1) == 0), 'ELF section name/link/alignment invalid')
                self.by_name[name] = row
                if row['type'] != 8 and row['size']:
                    harness.need(row['offset'] >= 64 and row['offset'] + row['size'] <= self.size and
                                 row['offset'] % max(1, row['align']) == 0, 'ELF section file geometry invalid')
                    ranges.append((row['offset'], row['offset'] + row['size']))
                harness.need(not (row['flags'] & 1 and row['flags'] & 4), 'ELF writable executable section refused')
        self.loads = []
        if kind == 1:
            harness.need(phnum == phoff == self.entry == 0 and phsize in (0, 56), 'relocatable module must not have entry/program headers')
        else:
            harness.need(phsize == 56 and 0 < phnum <= 64 and phoff >= 64 and phoff % 8 == 0, 'bounded ELF program headers required')
            rows = self.read(phoff, phsize * phnum)
            ranges.append((phoff, phoff + len(rows)))
            for index in range(phnum):
                ptype, perm, off, va, pa, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', rows, index * 56)
                harness.need(off + filesz <= self.size and filesz <= memsz and va + memsz <= 2**64 and pa + memsz <= 2**64,
                             'ELF segment range invalid')
                if ptype == 1:
                    harness.need(align >= 4096, '16K ELF load geometry/permissions required; WX refused [ALIGN_MIN]')
                    harness.need(align & (align - 1) == 0, '16K ELF load geometry/permissions required; WX refused [ALIGN_POWER_TWO]')
                    harness.need(va % align == off % align, '16K ELF load geometry/permissions required; WX refused [VA_ALIGN]')
                    harness.need(pa % align == off % align, '16K ELF load geometry/permissions required; WX refused [PA_ALIGN]')
                    harness.need(va % 16384 == off % 16384, '16K ELF load geometry/permissions required; WX refused [VA_16K]')
                    harness.need(pa % 16384 == off % 16384, '16K ELF load geometry/permissions required; WX refused [PA_16K]')
                    harness.need(perm in ((4, 5, 6, 7) if kernel_image else (4, 5, 6)),
                                 '16K ELF load geometry/permissions required; WX refused [PERMISSIONS_RWX]' if perm == 7 else
                                 '16K ELF load geometry/permissions required; WX refused [PERMISSIONS_OTHER]')
                    harness.need(memsz > 0, '16K ELF load geometry/permissions required; WX refused [MEMORY_SIZE]')
                    self.loads.append({'offset': off, 'addr': va, 'paddr': pa, 'filesz': filesz, 'memsz': memsz, 'alignment': align, 'flags': perm})
                elif ptype == 0x6474e551:
                    harness.need(not perm & 1, 'executable ELF stack refused')
            harness.need(self.loads and any(p['flags'] in ((5, 7) if kernel_image else (5,)) and p['addr'] <= self.entry < p['addr'] + p['filesz'] for p in self.loads),
                         'ELF entry must be in file-backed executable load')
            loads = sorted(self.loads, key=lambda p: p['addr'])
            harness.need(all(a['addr'] + a['memsz'] <= b['addr'] for a, b in zip(loads, loads[1:])), 'overlapping ELF load memory ranges')
            for row in self.sections[1:]:
                if row['flags'] & 2 and row['size']:
                    harness.need(any(p['addr'] <= row['addr'] and row['addr'] + row['size'] <= p['addr'] + p['memsz'] and
                                     (row['type'] == 8 or (p['offset'] <= row['offset'] and row['offset'] + row['size'] <= p['offset'] + p['filesz'] and
                                                          row['addr'] - p['addr'] == row['offset'] - p['offset'])) for p in self.loads),
                                 'allocated ELF section outside consistent load segment')
        # Sections/ELF metadata are independent file ranges (segments may contain them).
        ranges.sort()
        harness.need(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'overlapping ELF section/header file ranges')
        sym = self.by_name.get('.symtab')
        harness.need(sym and sym['type'] == 2 and sym['entsize'] == 24 and sym['size'] % 24 == 0 and
                     0 < sym['size'] // 24 <= 2000000 and self.sections[sym['link']]['type'] == 3,
                     'bounded actual ELF symbol table required')
        self.symbols = sym
        for row in self.sections:
            if row['type'] in (4, 9):
                relocation_role = 'IMAGE_REFERENCE' if artifact_role == 'arm64-image-reference' else 'RELOCATABLE' if kind == 1 else 'ELF'
                harness.need(row['type'] == 4, 'AArch64 ELF RELA metadata invalid [' + relocation_role + '_TYPE_RELA]')
                harness.need(row['entsize'] == 24, 'AArch64 ELF RELA metadata invalid [' + relocation_role + '_ENTRY_SIZE]')
                harness.need(row['size'] % 24 == 0, 'AArch64 ELF RELA metadata invalid [' + relocation_role + '_SIZE_MULTIPLE]')
                harness.need(self.sections[row['link']]['type'] in (2, 11) or
                             (artifact_role == 'arm64-image-reference' and kind in (2, 3) and
                              row['link'] == 0 and row['info'] == 0 and row['flags'] & 2),
                             'AArch64 ELF RELA metadata invalid [' + relocation_role + '_SYMBOL_TABLE_TYPE]')
                harness.need(row['info'] < shnum, 'AArch64 ELF RELA metadata invalid [' + relocation_role + '_TARGET_INDEX]')
                harness.need(kind != 1 or row['info'] > 0, 'AArch64 ELF RELA metadata invalid [' + relocation_role + '_MODULE_TARGET]')
                relative = row['link'] == 0
                linked = self.sections[row['link']]
                if not relative:
                    harness.need(linked['entsize'] == 24 and linked['size'] % 24 == 0, 'relocation symbol table invalid')
                target = self.sections[row['info']]
                for pos in range(0, row['size'], 24 * 4096):
                    raw = self.read(row['offset'] + pos, min(24 * 4096, row['size'] - pos))
                    for offset, info, _ in struct.iter_unpack('<QQq', raw):
                        if relative:
                            # Linux arm64 keeps allocated RELA after discarding .dynsym.
                            # Its self-relocator applies only R_AARCH64_RELATIVE (1027).
                            harness.need(info == 1027 and any(s['flags'] & 2 and s['addr'] <= offset and
                                         offset + 8 <= s['addr'] + s['size'] for s in self.sections) and
                                         any(p['addr'] <= offset and offset + 8 <= p['addr'] + p['memsz'] for p in self.loads),
                                         'ELF relocation index/offset invalid')
                        else:
                            harness.need(info >> 32 < linked['size'] // 24 and (kind != 1 or offset < target['size']), 'ELF relocation index/offset invalid')

    def section_bytes(self, name, cap=128 * 1024**2):
        row = self.by_name.get(name)
        harness.need(row and row['type'] != 8, 'ELF file-backed section required: ' + name)
        return self.read(row['offset'], row['size'], cap)

    def definitions(self, wanted):
        row = self.symbols
        strings = self.sections[row['link']]
        names = self.read(strings['offset'], strings['size'])
        harness.need(names and names[0] == names[-1] == 0, 'ELF symbol strings invalid')
        found = {}
        for pos in range(0, row['size'], 24 * 4096):
            raw = self.read(row['offset'] + pos, min(24 * 4096, row['size'] - pos))
            for nameoff, info, other, section, value, size in struct.iter_unpack('<IBBHQQ', raw):
                name = cstring(names, nameoff).decode('ascii')
                harness.need(other & ~3 == 0 and (section < len(self.sections) or section in (0xfff1, 0xfff2)), 'ELF symbol section/visibility invalid')
                if name in wanted and section and info >> 4 in (1, 2):
                    harness.need(section != 0xfff2 and name not in found, 'ambiguous/common defined export')
                    if section != 0xfff1:
                        sec = self.sections[section]
                        harness.need(sec['flags'] & 2 and size <= sec['size'] and
                                     ((value <= sec['size'] and value + size <= sec['size']) if self.entry == 0 else
                                      (sec['addr'] <= value and value + size <= sec['addr'] + sec['size'])), 'defined symbol outside allocated section')
                    found[name] = {'value': value, 'size': size, 'section': section, 'type': info & 15}
        harness.need(set(found) == set(wanted), 'export/kernel symbol missing from actual ELF: ' + ','.join(sorted(set(wanted) - set(found))[:10]))
        return found


def embedded_config(path, expected):
    # Uncompressed Image/vmlinux only; streaming search with bounded gzip decoding.
    start, finish = b'IKCFG_ST', b'IKCFG_ED'
    count, decoded, tail = 0, None, b''
    with path.open('rb') as stream:
        while True:
            block = stream.read(1024**2)
            if not block:
                break
            raw = tail + block
            at = 0
            while True:
                index = raw.find(start, at)
                if index < 0:
                    break
                count += 1
                harness.need(count == 1, 'duplicate embedded IKCONFIG marker')
                # Re-read bounded gzip member from absolute marker offset.
                absolute = stream.tell() - len(raw) + index + len(start)
                here = stream.tell(); stream.seek(absolute)
                compressed = stream.read(2 * LIMIT_CONFIG); stream.seek(here)
                dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
                try:
                    value = dec.decompress(compressed, LIMIT_CONFIG + 1)
                except zlib.error as error:
                    raise ValueError('invalid embedded config gzip') from error
                harness.need(dec.eof and len(value) <= LIMIT_CONFIG and dec.unused_data.startswith(finish) and value == expected,
                             'complete embedded IKCONFIG differs from generated .config')
                decoded = hashlib.sha256(value).hexdigest()
                at = index + len(start)
            tail = raw[-(len(start) - 1):]
    harness.need(count == 1, 'embedded IKCONFIG absent')
    return decoded


def walk_error(error):
    raise error


def module_inventory(build):
    path = build / 'modules.order'; harness.regular(path, LIMIT_CONFIG)
    raw = path.read_text()
    harness.need(raw.endswith('\n'), 'terminated modules.order required')
    order = raw.splitlines()
    harness.need(0 < len(order) <= 4096 and len(set(order)) == len(order), 'nonempty bounded unique module order required')
    for name in order:
        harness.safe_name(name)
        harness.need(name.endswith('.o') and re.fullmatch(r'[A-Za-z0-9_./+-]+', name), 'pinned Kbuild .o module order format required')
    expected = {name[:-2] + '.ko' for name in order}
    actual, count, total = set(), 0, 0
    for root, dirs, files in os.walk(build, followlinks=False, onerror=walk_error):
        # Kbuild O= emits a source link; it is not an output subtree.
        for name in dirs[:]:
            entry = Path(root) / name
            if entry.is_symlink():
                harness.need(entry == build / 'source', 'module inventory symlink directory refused')
                dirs.remove(name)
        count += len(dirs) + len(files)
        harness.need(count <= 250000, 'build inventory entry budget exceeded')
        for name in files:
            if name.endswith(('.ko', '.ko.xz', '.ko.zst', '.ko.gz')):
                entry = Path(root) / name
                harness.regular(entry, 1024**3)
                harness.need(name.endswith('.ko'), 'compressed modules unexpected in native build output')
                actual.add(entry.relative_to(build).as_posix())
                total += entry.stat().st_size
                harness.need(len(actual) <= 4096 and total <= 12 * 1024**3, 'module inventory storage budget exceeded')
    harness.need(actual == expected, 'modules.order differs from actual .ko inventory')
    return order, total


def namespace_valid(namespace):
    if len(namespace) > 512:
        return False
    if not namespace.startswith('module:'):
        return namespace == '' or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', namespace) is not None
    # 94fb modpost.c supports comma-separated module names with tail-globs only.
    patterns = namespace[len('module:'):].split(',')
    return (0 < len(patterns) <= 64 and len(patterns) == len(set(patterns)) and
            all(re.fullmatch(r'(?:[A-Za-z0-9_+-]+\*?|\*)', pattern) for pattern in patterns))


def symvers(build, owners, settings):
    path = build / 'Module.symvers'; harness.regular(path, 32 * 1024**2)
    raw = path.read_text(); rows, seen = [], set()
    harness.need(raw and raw.endswith('\n'), 'nonempty terminated Module.symvers required')
    for line in raw.splitlines():
        fields = line.split('\t')
        harness.need(len(fields) == 5, 'Module.symvers requires five tab-separated fields')
        crc, symbol, owner, export, namespace = fields
        harness.need(re.fullmatch(r'0x[0-9a-f]{8}', crc) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', symbol) and
                     owner in owners and export in ('EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL') and
                     namespace_valid(namespace) and symbol not in seen, 'invalid/duplicate Module.symvers export')
        harness.need(settings.get('CONFIG_MODVERSIONS') == 'y' or crc == '0x00000000', 'unexpected CRC with MODVERSIONS disabled')
        seen.add(symbol); rows.append((symbol, owner))
        harness.need(len(rows) <= 250000, 'symbol inventory budget exceeded')
    harness.need(any(owner == 'vmlinux' for _, owner in rows), 'vmlinux exports absent')
    return rows


def vermagic(release, settings):
    harness.need(settings.get('CONFIG_RANDSTRUCT_NONE') == 'y', 'unreviewed RANDSTRUCT vermagic refused')
    value = release + ' '
    for key, word in (('CONFIG_SMP', 'SMP'), ('CONFIG_MODULE_UNLOAD', 'mod_unload'), ('CONFIG_MODVERSIONS', 'modversions')):
        if key == 'CONFIG_MODULE_UNLOAD':
            value += 'preempt_rt ' if settings.get('CONFIG_PREEMPT_RT') == 'y' else 'preempt ' if settings.get('CONFIG_PREEMPT_BUILD') == 'y' else ''
        if settings.get(key) == 'y':
            value += word + ' '
    return value + 'aarch64'


def image_relation(reader, image, text):
    """Match all bytes of the pinned arm64 objcopy binary projection, streaming."""
    removed = {'.note', '.note.gnu.build-id', '.comment'}
    copied, excluded = [], []
    for row in reader.sections[1:]:
        if not row['size'] or not row['flags'] & 2 or row['type'] == 8:
            continue
        if row['name'] in removed:
            excluded.append(row['name'])
            continue
        harness.need(not row['flags'] & (0x800 | 0x80000000), 'unreviewed compressed/excluded allocated Image section')
        loads = [p for p in reader.loads if p['addr'] <= row['addr'] and row['addr'] + row['size'] <= p['addr'] + p['filesz'] and
                 p['offset'] <= row['offset'] and row['offset'] + row['size'] <= p['offset'] + p['filesz'] and
                 row['addr'] - p['addr'] == row['offset'] - p['offset']]
        harness.need(len(loads) == 1, 'unique file-backed Image section load mapping required')
        load = loads[0]
        lma = load['paddr'] + row['addr'] - load['addr']
        copied.append((lma, row['size'], row['offset'], row['name']))
    harness.need(copied, 'Image requires copied allocated ELF sections')
    copied.sort()
    base = copied[0][0]
    head = [p for p in reader.loads if p['addr'] <= text < p['addr'] + p['filesz']]
    harness.need(len(head) == 1 and base == head[0]['paddr'] + text - head[0]['addr'],
                 'lowest copied Image LMA must correspond to vmlinux _text')
    harness.need(all(a[0] + a[1] <= b[0] for a, b in zip(copied, copied[1:])), 'overlapping copied Image LMA ranges')
    length = copied[-1][0] + copied[-1][1] - base
    harness.regular(image, 256 * 1024**2)
    harness.need(length == image.stat().st_size and length <= 256 * 1024**2, 'Image length differs from complete ELF binary projection')
    digest, position, gaps = hashlib.sha256(), 0, 0
    with image.open('rb') as stream:
        for lma, size, offset, name in copied:
            start = lma - base
            gap = start - position
            if gap:
                gaps += gap
                while gap:
                    block = stream.read(min(gap, 1024**2))
                    harness.need(block and not any(block), 'Image ELF inter-section gap must contain only zero bytes')
                    gap -= len(block); digest.update(block)
            for pos in range(0, size, 1024**2):
                count = min(1024**2, size - pos)
                expected = reader.read(offset + pos, count)
                actual = stream.read(count)
                harness.need(actual == expected, 'Image body differs from vmlinux allocated section: ' + name)
                digest.update(actual)
            position = start + size
        harness.need(not stream.read(1), 'unexpected bytes after final copied Image section')
    return {'status': 'IMAGE_ELF_BYTES_VERIFIED', 'recipe': '-O binary -R .note -R .note.gnu.build-id -R .comment -S',
            'load_address': base, 'bytes': length, 'sha256': digest.hexdigest(), 'zero_gap_bytes': gaps,
            'copied_sections': [{'name': name, 'image_offset': lma - base, 'bytes': size} for lma, size, _, name in copied],
            'removed_allocated_sections': excluded}


def image_efi_header(path, header, settings, effective_size):
    pe = struct.unpack_from('<I', header, 60)[0]
    if settings.get('CONFIG_EFI') != 'y':
        harness.need(pe == 0 and struct.unpack_from('<I', header)[0] == 0xd503201f,
                     'non-EFI Image must have source NOP and zero PE offset')
        return
    harness.need(header[:2] == b'MZ' and 64 <= pe <= path.stat().st_size - 24, 'EFI Image MZ/PE offset required')
    with path.open('rb') as stream:
        stream.seek(pe); data = stream.read(24)
        harness.need(data[:4] == b'PE\0\0', 'EFI PE signature required')
        machine, count, timestamp, symptr, nsymbols, optsize, characteristics = struct.unpack_from('<HHIIIHH', data, 4)
        harness.need(machine == 0xaa64 and count == 2 and timestamp == symptr == nsymbols == 0 and
                     112 <= optsize <= 4096 and characteristics == 0x206 and
                     pe + 24 + optsize + count * 40 <= path.stat().st_size, 'source ARM64 EFI COFF header required')
        opt = stream.read(optsize); sections = stream.read(count * 40)
    section_align, file_align = struct.unpack_from('<II', opt, 32)
    image_size, headers_size = struct.unpack_from('<II', opt, 56)
    entry = struct.unpack_from('<I', opt, 16)[0]
    directories = struct.unpack_from('<I', opt, 108)[0]
    harness.need(struct.unpack_from('<H', opt)[0] == 0x20b and struct.unpack_from('<Q', opt, 24)[0] == 0 and
                 section_align >= 16384 and section_align & (section_align - 1) == 0 and file_align == 512 and
                 image_size == effective_size and pe + 24 + optsize + 80 <= headers_size <= path.stat().st_size and
                 headers_size % section_align == 0 and struct.unpack_from('<H', opt, 68)[0] == 10 and
                 optsize == 112 + directories * 8, 'source EFI PE32+ sizes/alignment/subsystem required')
    ranges, executable = [], False
    for index in range(2):
        name, vsize, va, rawsize, off, reloc, lines, nreloc, nlines, flags = struct.unpack_from('<8sIIIIIIHHI', sections, index * 40)
        harness.need(name == (b'.text\0\0\0' if index == 0 else b'.data\0\0\0') and
                     flags == (0x60000020 if index == 0 else 0xc0000040) and reloc == lines == nreloc == nlines == 0 and
                     headers_size <= off and off == va and off % file_align == rawsize % file_align == 0 and
                     0 < rawsize <= vsize and off + rawsize <= path.stat().st_size and va + vsize <= effective_size,
                     'source EFI PE section geometry/permissions required')
        ranges.append((va, va + vsize))
        executable |= index == 0 and va <= entry < va + rawsize
    harness.need(ranges[0][1] <= ranges[1][0] and executable, 'EFI section overlap/entry invalid')


def verify_outputs(build, source, expected_config=None):
    source_link_check = source_links(source)
    identities = source_evidence(source)
    harness.regular(build / '.config', LIMIT_CONFIG)
    cfg = (build / '.config').read_bytes()
    settings = config_bytes(cfg)
    harness.need(settings.get('CONFIG_MODULES') == settings.get('CONFIG_IKCONFIG') == 'y' and settings.get('CONFIG_CPU_BIG_ENDIAN', 'n') == 'n',
                 'built-in IKCONFIG and little-endian module-enabled kernel required')
    comparison = verify_config(expected_config, build / '.config') if expected_config is not None else None
    release_path = build / 'include/config/kernel.release'; harness.regular(release_path, 256)
    release_raw = release_path.read_text()
    harness.need(re.fullmatch(r'7\.1\.13[-A-Za-z0-9._+]*\n', release_raw), 'bounded source-version kernel.release required')
    release = release_raw[:-1]
    uts = build / 'include/generated/utsrelease.h'; harness.regular(uts, 512)
    harness.need(uts.read_text() == '#define UTS_RELEASE "' + release + '"\n', 'UTS_RELEASE differs from kernel.release')
    image, elf = build / 'arch/arm64/boot/Image', build / 'vmlinux'
    harness.regular(image, 256 * 1024**2)
    with image.open('rb') as stream:
        header = stream.read(64)
    harness.need(len(header) == 64 and header[56:60] == b'ARM\x64', 'ARM64 Image header required')
    offset, size, flags, r2, r3, r4 = struct.unpack_from('<6Q', header, 8)
    harness.need(offset == r2 == r3 == r4 == 0 and flags == 12 and 64 < image.stat().st_size <= size <= 512 * 1024**2,
                 'source-bound little-endian16K Image size/offset/reserved/placement flags required')
    harness.need(struct.unpack_from('<I', header, 4)[0] & 0xfc000000 == 0x14000000, 'Image entry branch required')
    image_efi_header(image, header, settings, size)
    image_config = embedded_config(image, cfg)
    order, module_bytes = module_inventory(build)
    required = {path for key, path in APPLE_MODULES.items() if settings.get(key) == 'm'}
    harness.need(required <= {name[:-2] + '.ko' for name in order}, 'configured Apple audio modules missing')
    owners = {'vmlinux'} | {name[:-2] for name in order}
    exports = symvers(build, owners, settings)
    by_owner = {owner: set() for owner in owners}
    for symbol, owner in exports:
        by_owner[owner].add(symbol)
    with ELF(elf, 3 if settings.get('CONFIG_RELOCATABLE') == 'y' else 2, 4 * 1024**3,
             artifact_role='arm64-image-reference') as reader:
        definitions = reader.definitions(by_owner['vmlinux'] | {'_text', '_end'})
        text, end = definitions['_text']['value'], definitions['_end']['value']
        harness.need(reader.entry == text and text >= 0xffff000000000000 and end - text == size, 'Image size/entry differ from vmlinux _text/_end')
        head_load = next(p for p in reader.loads if p['addr'] <= text < p['addr'] + p['filesz'])
        harness.need(reader.read(head_load['offset'] + text - head_load['addr'], 64) == header, 'Image header differs from vmlinux bytes')
        relation = image_relation(reader, image, text)
        loads = reader.loads
    elf_config = embedded_config(elf, cfg)
    modules, expected_magic = {}, vermagic(release, settings)
    modnames = {Path(name).stem.replace('-', '_') for name in order}
    harness.need(len(modnames) == len(order), 'ambiguous module names')
    for name in order:
        path = build / (name[:-2] + '.ko')
        with ELF(path, 1, 1024**3) as reader:
            definitions = reader.definitions(by_owner[name[:-2]] | {'__this_module'})
            harness.need(reader.by_name.get('.text', {}).get('flags', 0) & 4 and
                         reader.by_name.get('.gnu.linkonce.this_module', {}).get('flags', 0) & 3 == 3 and
                         definitions['__this_module']['section'] == reader.by_name['.gnu.linkonce.this_module']['index'], 'actual module code/descriptor required')
            raw = reader.section_bytes('.modinfo', LIMIT_CONFIG)
            harness.need(raw and raw[-1] == 0, 'terminated module metadata required')
            info = {}
            for row in raw.split(b'\0'):
                if not row:
                    continue
                harness.need(b'=' in row, 'module metadata key/value required')
                key, value = row.decode('ascii').split('=', 1)
                harness.need(re.fullmatch(r'[A-Za-z0-9_]+', key) and all(32 <= ord(c) < 127 for c in value), 'module metadata text invalid')
                info.setdefault(key, []).append(value)
            expected_name = Path(name).stem.replace('-', '_')
            harness.need(info.get('vermagic') == [expected_magic] and info.get('name') == [expected_name] and
                         info.get('license') and len(info.get('depends', [])) == 1, 'module vermagic/name/license/dependency metadata invalid')
            depends = info['depends'][0].split(',') if info['depends'][0] else []
            harness.need(len(set(depends)) == len(depends) and set(depends) <= modnames - {expected_name}, 'module dependencies outside actual inventory')
        modules[name[:-2] + '.ko'] = {'sha256': harness.digest(path), 'bytes': path.stat().st_size, 'name': expected_name, 'vermagic': expected_magic}
    dtbs = {name: verify_dtb(build / 'arch/arm64/boot/dts/apple' / name, identity) for name, identity in identities.items()}
    return {'status': 'BUILD_OUTPUT_STRUCTURE_VERIFIED', 'source_commit': SOURCE_COMMIT, 'source_evidence_sha256': SOURCE_PINS, 'source_links': source_link_check,
            'image_sha256': relation['sha256'], 'image_effective_bytes': size, 'image_flags': flags, 'image_elf_relation': relation,
            'vmlinux_sha256': harness.digest(elf), 'elf_loads': loads, 'apple_dtbs': dtbs,
            'generated_config_sha256': hashlib.sha256(cfg).hexdigest(), 'config_comparison': comparison,
            'embedded_config_sha256': {'Image': image_config, 'vmlinux': elf_config}, 'kernelrelease': release,
            'module_symvers_sha256': harness.digest(build / 'Module.symvers'), 'export_count': len(exports),
            'modules_order_sha256': harness.digest(build / 'modules.order'), 'modules': modules, 'module_bytes': module_bytes,
            'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED', 'runtime_correctness': 'NOT RUN'}


def pinned_bytes(path, pin):
    """Authenticate one bounded descriptor snapshot before consuming its fields."""
    harness.need(harness.PIN.fullmatch(pin or ''), 'receipt SHA-256 required')
    harness.regular(path, LIMIT_CONFIG)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        harness.need(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= LIMIT_CONFIG, 'bounded receipt descriptor required')
        raw = stream.read(LIMIT_CONFIG + 1)
    harness.need(len(raw) <= LIMIT_CONFIG and hashlib.sha256(raw).hexdigest() == pin, 'receipt byte-snapshot pin differs')
    return raw


def pinned_json(path, pin):
    raw = pinned_bytes(path, pin)
    def unique(rows):
        result = {}
        for key, value in rows:
            harness.need(key not in result, 'duplicate receipt JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def source_links(source):
    """Reject dangling/cyclic chains before any kernel build is permitted."""
    harness.need(source.is_dir() and not any(p.is_symlink() for p in (source, *source.parents)), 'real source root required')
    count, links = 0, 0
    for root, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        count += len(dirs) + len(files)
        harness.need(count <= 110000, 'source entry budget exceeded')
        for name in dirs + files:
            path = Path(root) / name
            if path.is_symlink():
                links += 1
                harness.need(links <= 256, 'source symlink budget exceeded')
                try:
                    resolved = path.resolve(strict=True)
                except (OSError, RuntimeError) as error:
                    raise ValueError('source symlink has cyclic/dangling resolution') from error
                harness.need(resolved.is_relative_to(source.resolve(strict=True)), 'resolved source link outside verified root')
    return {'status': 'SOURCE_LINKS_VERIFIED', 'entries': count, 'symlinks': links}


def preflight(args):
    harness.need(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() == os.geteuid() != 0,
                 'nonroot native aarch64 Linux builder required')
    # Whole native builder/image/package/tool provenance is an execution gate.
    builder = pinned_json(args.builder, args.builder_sha256)
    harness.need(builder['status'] == 'REVIEWED_NATIVE_KERNEL_BUILDER' and
                 re.fullmatch(r'sha256:[0-9a-f]{64}', builder['image_id']), 'reviewed immutable builder receipt required')
    packages = Path(builder['packages_path']); harness.regular(packages, 1024**2)
    harness.need(harness.digest(packages) == builder['packages_sha256'], 'native builder package inventory differs')
    tools = builder['tools']
    harness.need(set(tools) == {'gcc', 'ld', 'as', 'make', 'rustc', 'bindgen', 'pahole', 'dtc', 'python3'}, 'complete tool executable pins required')
    for name, row in tools.items():
        path = Path(row['path'])
        resolved = shutil.which(name, path='/usr/bin:/bin')
        harness.need(resolved and Path(resolved).resolve() == path and path.is_absolute(), 'tool command resolution differs: ' + name)
        harness.regular(path, 256 * 1024**2)
        harness.need(harness.digest(path) == row['sha256'], 'tool executable differs: ' + name)
    harness.need(builder.get('output_quota_enforced') is True and
                 0 < builder.get('output_quota_bytes', 0) <= 24 * 1024**3,
                 'reviewed enforced24GiB writable-output quota required')
    lock, _, _ = harness.validate(args.lock, args.lock_sha256, args.archive, args.config, args.patch)
    source = args.source
    harness.need(source.is_absolute() and source == source.resolve() and source.is_relative_to(harness.ROOT / 'artifacts/kernel-candidates') and
                 source.is_dir() and not any(p.is_symlink() for p in (source, *source.parents)), 'owned canonical source required')
    source_links(source)
    result = harness.verify_full_tree(args.archive, source, lock, patched=args.variant == 'candidate')
    harness.private_output(args.build)
    return {'status': 'NATIVE_BUILD_INPUTS_VERIFIED', 'variant': args.variant, 'source': str(source), 'verification': result,
            'builder_sha256': args.builder_sha256, 'kernel_build': 'NOT RUN', 'hardware_validation': 'NOT RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    cfg = sub.add_parser('config')
    cfg.add_argument('--expected', type=Path, required=True); cfg.add_argument('--actual', type=Path, required=True)
    outputs = sub.add_parser('outputs')
    outputs.add_argument('--build', type=Path, required=True)
    outputs.add_argument('--source', type=Path, required=True)
    outputs.add_argument('--expected-config', type=Path)
    pre = sub.add_parser('preflight')
    for name in ('builder', 'lock', 'archive', 'config', 'patch', 'source', 'build'):
        pre.add_argument('--' + name, type=Path, required=True)
    for name in ('builder-sha256', 'lock-sha256'):
        pre.add_argument('--' + name, required=True)
    pre.add_argument('--variant', choices=('baseline', 'candidate'), required=True)
    args = parser.parse_args()
    try:
        value = verify_config(args.expected, args.actual) if args.mode == 'config' else verify_outputs(args.build, args.source, args.expected_config) if args.mode == 'outputs' else preflight(args)
        print(json.dumps(value, sort_keys=True)); return 0
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        print('Native build verification refused; no installation or hardware acceptance.'); return 1


if __name__ == '__main__':
    raise SystemExit(main())
