# SPDX-License-Identifier: MIT
# Exact maintained project ELF parser; bytes only, no loader.
import struct
from source import need

def elf_info(body, machine=183):
    """Bounded ELF64 byte parser; no loader, readelf, or external providers."""
    need(len(body) >= 64 and body[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little-endian required')
    kind, actual, version = struct.unpack_from('<HHI', body, 16)
    need(machine == actual == 183 and kind in (2, 3) and version == 1, 'ELF AArch64 architecture/type/version mismatch')
    phoff = struct.unpack_from('<Q', body, 32)[0]
    ehsize, phentsize, phnum = struct.unpack_from('<HHH', body, 52)
    need(ehsize == 64 and phentsize == 56 and 0 < phnum < 1024
         and phoff >= 64 and phoff + phentsize * phnum <= len(body), 'ELF program headers malformed')
    segments = [struct.unpack_from('<IIQQQQQQ', body, phoff + n * phentsize) for n in range(phnum)]
    interpreters = [s for s in segments if s[0] == 3]
    need(len(interpreters) <= 1, 'ELF duplicate interpreter segment')
    interpreter = None
    if interpreters:
        segment = interpreters[0]
        need(1 < segment[5] <= 4096 and segment[2] + segment[5] <= len(body),
             'ELF bounded interpreter segment required')
        raw = body[segment[2]:segment[2] + segment[5]]
        need(raw[-1:] == b'\0' and b'\0' not in raw[:-1]
             and all(32 < c < 127 for c in raw[:-1]), 'ELF interpreter string malformed')
        interpreter = raw[:-1].decode('ascii')
    loads = [s for s in segments if s[0] == 1]
    need(loads, 'ELF load segments required')
    for segment in segments:
        need(segment[2] + segment[5] <= len(body), 'ELF segment outside file')
    for s in loads:
        need(s[5] <= s[6] and s[3] + s[6] < 2**64
             and s[7] >= 16384 and not s[7] & (s[7] - 1)
             and s[2] % s[7] == s[3] % s[7], 'ELF 16K load geometry required')

    def offset(address, size):
        matches = [s for s in loads if s[3] <= address and address + size <= s[3] + s[5]]
        need(size > 0 and len(matches) == 1, 'ELF metadata outside unique file-backed load segment')
        return matches[0][2] + address - matches[0][3]

    dynamic = [s for s in segments if s[0] == 2]
    need(len(dynamic) <= 1, 'ELF duplicate dynamic segment')
    tags, needed_offsets = {}, []
    if dynamic:
        segment = dynamic[0]
        need(segment[5] and segment[5] % 16 == 0 and segment[5] // 16 <= 65536,
             'ELF dynamic segment malformed')
        need(offset(segment[3], segment[5]) == segment[2], 'ELF dynamic segment load mapping mismatch')
        terminated = False
        for start in range(segment[2], segment[2] + segment[5], 16):
            tag, value = struct.unpack_from('<qQ', body, start)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed_offsets.append(value)
            else:
                if tag in (5, 10, 14, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff):
                    need(tag not in tags, 'ELF duplicate dynamic metadata tag')
                tags[tag] = value
        need(terminated, 'ELF dynamic segment unterminated')
    uses_strings = needed_offsets or any(t in tags for t in (14, 0x6ffffffc, 0x6ffffffe))
    table, table_bytes = 0, 0
    if uses_strings:
        need(5 in tags and 10 in tags and 0 < tags[10] <= len(body), 'ELF dynamic string table missing')
        table_bytes = tags[10]
        table = offset(tags[5], table_bytes)

    def text(index):
        need(0 <= index < table_bytes, 'ELF dynamic string outside table')
        end = body.find(b'\0', table + index, table + table_bytes)
        need(end > table + index, 'ELF dynamic string unterminated/empty')
        raw = body[table + index:end]
        need(all(32 < c < 127 for c in raw) and b'/' not in raw, 'ELF metadata string must be printable basename')
        return raw.decode('ascii')

    def versions(address_tag, count_tag, definitions):
        need((address_tag in tags) == (count_tag in tags), 'ELF GNU version table/count pair required')
        if address_tag not in tags:
            return None
        count = tags[count_tag]
        need(0 < count <= 4096, 'ELF GNU version count bound')
        address, result, visited, total_aux = tags[address_tag], [], set(), 0
        for number in range(count):
            need(address not in visited, 'ELF GNU version chain cycle')
            visited.add(address)
            start = offset(address, 20 if definitions else 16)
            if definitions:
                version, flags, index, aux_count, digest, aux, next_entry = struct.unpack_from('<HHHHIII', body, start)
                row = dict(flags=flags, index=index, hash=digest, names=[])
            else:
                version, aux_count, filename, aux, next_entry = struct.unpack_from('<HHIII', body, start)
                row = dict(file=text(filename), versions=[])
            need(version == 1 and 0 < aux_count <= 4096 and aux > 0, 'ELF GNU version record malformed')
            total_aux += aux_count
            need(total_aux <= 65536, 'ELF GNU total auxiliary bound')
            aux_address, aux_seen = address + aux, set()
            for auxiliary in range(aux_count):
                need(aux_address not in aux_seen, 'ELF GNU version auxiliary cycle')
                aux_seen.add(aux_address)
                start = offset(aux_address, 8 if definitions else 16)
                if definitions:
                    name, next_aux = struct.unpack_from('<II', body, start)
                    row['names'].append(text(name))
                else:
                    digest, flags, other, name, next_aux = struct.unpack_from('<IHHII', body, start)
                    row['versions'].append(dict(name=text(name), hash=digest, flags=flags, other=other))
                need(bool(next_aux) == (auxiliary + 1 < aux_count), 'ELF GNU auxiliary chain count mismatch')
                aux_address += next_aux
            result.append(row)
            need(bool(next_entry) == (number + 1 < count), 'ELF GNU version chain count mismatch')
            address += next_entry
        return result

    return dict(type=kind, machine=actual, interpreter=interpreter, soname=text(tags[14]) if 14 in tags else None,
        needed=[text(index) for index in needed_offsets],
        version_needs=versions(0x6ffffffe, 0x6fffffff, False),
        version_definitions=versions(0x6ffffffc, 0x6ffffffd, True),
        load_segments=[dict(offset=s[2], virtual_address=s[3], file_bytes=s[5], memory_bytes=s[6], alignment=s[7]) for s in loads],
        geometry_16k=True, metadata_scope='ELF_BYTES_ONLY_NO_NATIVE_OR_PROVIDER_ACCEPTANCE')
