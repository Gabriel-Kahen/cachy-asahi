#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stream tar payloads as DATA; inspect ELF program/dynamic metadata without execution."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import resource
import signal
import struct
import tarfile
import time

HERE = Path(__file__).resolve().parent
PREFIX_LIMIT = 32 * 1024**2


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            h.update(block)
    return h.hexdigest()


def safe_name(name, root):
    if not name or name.startswith('/') or '\\' in name or any(ord(c) < 32 for c in name):
        raise ValueError('unsafe archive name')
    p = PurePosixPath(name)
    if '..' in p.parts or p.parts[0] != root:
        raise ValueError('archive namespace escaped pinned root')
    return p.as_posix()


def elf_headers(prefix, size):
    if prefix[:4] != b'\x7fELF':
        return None
    if prefix[4:6] != b'\x02\x01' or len(prefix) < 64:
        raise ValueError('unsupported ELF class/encoding')
    values = struct.unpack_from('<HHIQQQIHHHHHH', prefix, 16)
    kind, machine, _, entry, phoff, _, _, _, phsize, phnum, *_ = values
    if (phnum and phsize != 56) or phsize not in [0, 56] or phoff + phsize * phnum > len(prefix):
        raise ValueError('ELF program headers exceed bounded prefix')
    headers = []
    for i in range(phnum):
        ptype, flags, offset, vaddr, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', prefix, phoff + i * phsize)
        if offset + filesz > size:
            raise ValueError('ELF segment exceeds member size')
        headers.append(dict(type=ptype, flags=flags, offset=offset, vaddr=vaddr, filesz=filesz, memsz=memsz, align=align))
    return {'elf_class': 64, 'endianness': 'little', 'type': kind, 'machine': machine, 'entry': entry, 'program_headers': headers}


def alignment_16k(elf):
    loads = [p for p in elf['program_headers'] if p['type'] == 1]
    return bool(loads) and all(p['align'] >= 16384 and p['offset'] % 16384 == p['vaddr'] % 16384 for p in loads)


def overlap(chunk, start, lo, hi):
    return chunk[max(lo - start, 0):max(min(hi - start, len(chunk)), 0)] if start < hi and start + len(chunk) > lo else b''


def dynamic_metadata(elf, captures, prefix):
    dynamic = [p for p in elf['program_headers'] if p['type'] == 2]
    interp = [p for p in elf['program_headers'] if p['type'] == 3]
    elf['interpreter'] = captures.get('interp', b'').rstrip(b'\0').decode() if interp else None
    elf['load_segments_16k_congruence_and_alignment'] = alignment_16k(elf)
    if not dynamic:
        elf.update(needed=[], rpath=[], runpath=[], soname=None)
        return None
    values = {}
    payload = captures['dynamic']
    for offset in range(0, len(payload) - 15, 16):
        tag, value = struct.unpack_from('<qQ', payload, offset)
        if tag == 0:
            break
        values.setdefault(tag, []).append(value)
    address, size = values[5][0], values[10][0]
    if size > 64 * 1024**2:
        raise ValueError('dynamic string table exceeds 64 MiB bound')
    loads = [p for p in elf['program_headers'] if p['type'] == 1 and p['vaddr'] <= address < p['vaddr'] + p['filesz']]
    if len(loads) != 1:
        raise ValueError('dynamic string table has no unique file mapping')
    p = loads[0]
    lo = p['offset'] + address - p['vaddr']
    if lo + size > p['offset'] + p['filesz']:
        raise ValueError('dynamic string table exceeds mapped segment')
    request = {'offset': lo, 'bytes': size, 'values': values}
    if lo + size <= len(prefix):
        finish_dynamic(elf, request, prefix[lo:lo+size])
        return None
    return request


def finish_dynamic(elf, request, strings):
    if len(strings) != request['bytes']:
        raise ValueError('incomplete dynamic string table')
    def string(offset):
        end = strings.find(b'\0', offset)
        if offset >= len(strings) or end < 0:
            raise ValueError('invalid dynamic string offset')
        return strings[offset:end].decode()
    values = request['values']
    elf['needed'] = [string(i) for i in values.get(1, [])]
    elf['rpath'] = [string(i) for i in values.get(15, [])]
    elf['runpath'] = [string(i) for i in values.get(29, [])]
    elf['soname'] = string(values[14][0]) if 14 in values else None


def manifest_audit(records, texts, root, component):
    base = root + '/' + component + '/'
    actual = {r['path'][len(base):]: r for r in records if r['path'].startswith(base)}
    manifest = texts[base + 'manifest.in'].decode()
    entries = []
    missing = []
    for line in manifest.splitlines():
        kind, sep, name = line.partition(':')
        if not sep or kind not in ['file', 'dir'] or name.startswith('/') or '..' in PurePosixPath(name).parts:
            raise ValueError('invalid installer manifest entry')
        entries.append((kind, name))
        if name not in actual or (kind == 'dir' and actual[name]['kind'] != 'dir') or (kind == 'file' and actual[name]['kind'] not in ['file', 'symlink', 'hardlink']):
            missing.append(line)
    uncovered = [name for name, r in actual.items() if r['kind'] != 'dir' and name != 'manifest.in' and not any(name == p or (kind == 'dir' and name.startswith(p + '/')) for kind, p in entries)]
    return {'component': component, 'manifest_entries': len(entries), 'missing_or_wrong_kind': missing, 'uncovered_payload_members': uncovered, 'layout_observed': bool(actual), 'installer_executed': False}


def audit_archive(path, pin, output):
    if sha(path) != pin['sha256']:
        raise ValueError('archive whole checksum differs')
    root = pin['archive_root']
    records, texts, elfs, second = [], {}, {}, {}
    seen = set()
    logical = 0
    with tarfile.open(path, 'r|xz') as archive:
        for member in archive:
            name = safe_name(member.name, root)
            if name in seen:
                raise ValueError('duplicate normalized archive path')
            seen.add(name)
            if len(seen) > 100000:
                raise ValueError('member count bound exceeded')
            logical += member.size
            if logical > 8 * 1024**3:
                raise ValueError('declared logical payload bound exceeded')
            kind = 'file' if member.isfile() else 'dir' if member.isdir() else 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'special'
            record = dict(path=name, kind=kind, mode=member.mode, bytes=member.size)
            if kind == 'special':
                raise ValueError('special archive entry refused')
            if kind in ['symlink', 'hardlink']:
                target = member.linkname if kind == 'hardlink' else posixpath.join(posixpath.dirname(name), member.linkname)
                safe_name(posixpath.normpath(target), root)
                record['link_target'] = member.linkname
            if member.isfile():
                stream = archive.extractfile(member)
                first = stream.read(min(member.size, 65536))
                elf = elf_headers(first, member.size)
                wanted = {}
                if elf:
                    for p in elf['program_headers']:
                        if p['type'] in [2, 3]:
                            key = 'dynamic' if p['type'] == 2 else 'interp'
                            if p['filesz'] > 1024**2:
                                raise ValueError('oversized ELF metadata segment')
                            wanted[key] = (p['offset'], p['offset'] + p['filesz'])
                basename = PurePosixPath(name).name.lower()
                notice = basename.startswith(('license', 'copying')) or basename in ['copyright', 'notice', 'notice.txt']
                metadata = basename in ['manifest.in', 'components', 'rust-installer-version', 'version', 'git-commit-hash']
                retain = notice or metadata
                if retain and member.size > 1024**2:
                    raise ValueError('notice/manifest retention bound exceeded')
                prefix = bytearray()
                captures = {k: bytearray() for k in wanted}
                full = bytearray()
                h = hashlib.sha256()
                position = 0
                chunk = first
                while chunk:
                    h.update(chunk)
                    if elf and position < PREFIX_LIMIT:
                        prefix.extend(chunk[:PREFIX_LIMIT-position])
                    if retain:
                        full.extend(chunk)
                    for key, (lo, hi) in wanted.items():
                        captures[key].extend(overlap(chunk, position, lo, hi))
                    position += len(chunk)
                    chunk = stream.read(1024**2)
                if position != member.size:
                    raise ValueError('member truncated')
                record['sha256'] = h.hexdigest()
                if first.startswith(b'!<arch>\n'):
                    record['nested_ar_payload_audit'] = 'NOT_PERFORMED; no nested ELF/object or symbol qualification inferred'
                if retain:
                    texts[name] = bytes(full)
                    target = output / ('notices' if notice else 'metadata') / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(full)
                    record['retained_data_path'] = str(target.relative_to(HERE))
                if elf:
                    request = dynamic_metadata(elf, {k: bytes(v) for k, v in captures.items()}, prefix)
                    elfs[name] = elf
                    if request:
                        second[name] = request
            records.append(record)
            archive.members.clear()  # streaming inventory, no growing TarInfo cache
    if second:
        with tarfile.open(path, 'r|xz') as archive:
            for member in archive:
                if member.name in second:
                    request = second[member.name]
                    stream = archive.extractfile(member)
                    position, data = 0, bytearray()
                    for chunk in iter(lambda: stream.read(1024**2), b''):
                        data.extend(overlap(chunk, position, request['offset'], request['offset'] + request['bytes']))
                        position += len(chunk)
                    finish_dynamic(elfs[member.name], request, data)
                archive.members.clear()
    manifest = manifest_audit(records, texts, root, pin['component'])
    if manifest['missing_or_wrong_kind'] or manifest['uncovered_payload_members']:
        manifest['status'] = 'GAPS_OBSERVED'
    else:
        manifest['status'] = 'ALL_INSTALL_MANIFEST_PATHS_AND_COMPONENT_PAYLOAD_JOINED'
    (output / (path.name + '.inventory.json')).write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
    (output / (path.name + '.elf.json')).write_text(json.dumps(elfs, indent=2, sort_keys=True) + '\n')
    return {'bytes': path.stat().st_size, 'sha256': pin['sha256'], 'archive_root': root, 'member_count': len(records), 'declared_payload_bytes': logical, 'namespace': 'PASS_PINNED_ROOT_UNIQUE_NAMES_NO_SPECIAL_OR_ESCAPING_LINKS', 'install_manifest': manifest, 'top_level_components': texts.get(root + '/components', b'').decode().splitlines(), 'installer_version': texts.get(root + '/rust-installer-version', b'').decode().strip(), 'ELF_regular_files': len(elfs), 'ELF_all_AArch64': all(e['machine'] == 183 for e in elfs.values()), 'ELF_load_alignment_16k_data': {k: v['load_segments_16k_congruence_and_alignment'] for k, v in elfs.items()}, 'needed_union': sorted({x for e in elfs.values() for x in e['needed']}), 'notice_files_retained': [r['retained_data_path'] for r in records if r.get('retained_data_path', '').startswith('records/notices/')], 'nested_ar_files_not_audited': sum('nested_ar_payload_audit' in r for r in records), 'ELF_string_table_second_pass_files': len(second), 'records': records, 'elf': elfs}


def main():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    def timeout(_signum, _frame):
        raise TimeoutError('1200-second audit deadline')
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(1200)
    started = time.monotonic()
    acquisition = json.loads((HERE / 'acquisition.json').read_bytes())
    pins = json.loads((HERE.parent / 'inputs.json').read_bytes())
    output = HERE / 'records'
    output.mkdir(exist_ok=True)
    result = {'schema': 1, 'status': 'ACTUAL_STAGE0_ARCHIVE_DATA_AUDIT_RUNTIME_UNQUALIFIED', 'candidate_inputs_sha256': sha(HERE.parent / 'inputs.json'), 'acquisition_sha256': sha(HERE / 'acquisition.json'), 'archives': {}, 'holds_preserved': pins['holds'], 'publisher_execution': 0, 'installer_execution': 0, 'extracted_binary_payload_files': 0, 'static_16k_scope': 'Top-level regular ELF PT_LOAD alignment >=16384 and offset/vaddr congruence modulo16384 only; not loader/runtime/16K qualification. Nested ar/rlib objects not parsed.', 'signature_authentication': 'NOT_PERFORMED; TLS and exact retained stage0-declaration hashes only', 'compatibility': 'UNQUALIFIED', 'environment_image': 'NOT_SUPPLIED_OR_QUALIFIED'}
    for name, artifact in acquisition['artifacts'].items():
        report = audit_archive(Path(artifact['path']), pins['archives'][name], output)
        report.pop('records')
        report.pop('elf')
        result['archives'][name] = report
        print(name + ': DATA audit complete', flush=True)
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    result['process_VmHWM'] = next(line.strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmHWM:'))
    (HERE / 'data-admission.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
