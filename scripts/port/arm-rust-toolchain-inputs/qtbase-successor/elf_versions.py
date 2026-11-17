"""Read GNU ELF version-name contracts as data, without loading a payload."""
import struct


def require(ok, message):
    if not ok:
        raise ValueError(message)


def parse(data):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'unsupported ELF version input')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, count = struct.unpack_from('<HH', data, 54)
    require(count < 4096 and (not count or phsize == 56), 'invalid version program headers')
    require(phoff + phsize * count <= len(data), 'truncated version program headers')
    loads, tags = [], {}
    for i in range(count):
        typ, flags, off, va, pa, size, mem, align = struct.unpack_from('<IIQQQQQQ', data, phoff + phsize * i)
        require(off + size <= len(data), 'truncated version segment')
        if typ == 1:
            loads.append((va, off, size))
        elif typ == 2:
            require(size % 16 == 0, 'invalid version dynamic table')
            for at in range(off, off + size, 16):
                tag, value = struct.unpack_from('<qQ', data, at)
                if tag == 0:
                    break
                if tag in (5, 10, 0x6ffffffe, 0x6fffffff, 0x6ffffffc, 0x6ffffffd):
                    require(tag not in tags, 'duplicate version dynamic tag')
                    tags[tag] = value
    result = {'needs': {}, 'defines': []}
    if not any(t in tags for t in (0x6ffffffe, 0x6ffffffc)):
        return result

    def offset(addr, length):
        found = [off + addr - va for va, off, size in loads if va <= addr and addr + length <= va + size]
        require(len(found) == 1, 'unmapped/ambiguous ELF version address')
        return found[0]

    require(5 in tags and 10 in tags, 'version string table missing')
    start = offset(tags[5], tags[10])
    strings = data[start:start + tags[10]]

    def string(at):
        require(at < len(strings) and b'\0' in strings[at:], 'invalid version string')
        return strings[at:strings.index(b'\0', at)].decode('utf-8')

    for tag, numtag, kind in [(0x6ffffffe, 0x6fffffff, 'needs'), (0x6ffffffc, 0x6ffffffd, 'defines')]:
        if tag not in tags:
            continue
        require(0 < tags.get(numtag, 0) < 65536, 'invalid version record count')
        addr, seen = tags[tag], set()
        for i in range(tags[numtag]):
            require(addr not in seen, 'version record cycle')
            seen.add(addr)
            if kind == 'needs':
                version, total, file, aux, nxt = struct.unpack_from('<HHIII', data, offset(addr, 16))
                require(version == 1 and 0 < total < 65536, 'invalid version need header')
                library, names, at = string(file), [], addr + aux
                for j in range(total):
                    hashval, flags, other, name, following = struct.unpack_from('<IHHII', data, offset(at, 16))
                    names.append(string(name))
                    require((following > 0) == (j + 1 < total), 'invalid version auxiliary chain')
                    at += following
                require(library not in result['needs'], 'duplicate version library')
                result['needs'][library] = sorted(set(names))
            else:
                version, flags, index, total, hashval, aux, nxt = struct.unpack_from('<HHHHIII', data, offset(addr, 20))
                require(version == 1 and 0 < total < 65536, 'invalid version definition')
                at = addr + aux
                for j in range(total):
                    name, following = struct.unpack_from('<II', data, offset(at, 8))
                    if j == 0:
                        result['defines'].append(string(name))
                    require((following > 0) == (j + 1 < total), 'invalid version definition auxiliary chain')
                    at += following
            require((nxt > 0) == (i + 1 < tags[numtag]), 'invalid version record chain')
            addr += nxt
    result['defines'] = sorted(set(result['defines']))
    return result


def join(entries, elf_joins):
    providers = {(j['consumer'], j['needed']): j['provider'] for j in elf_joins}
    found, missing = [], []
    for path, record in sorted(entries.items()):
        for library, names in record.get('gnu_versions', {}).get('needs', {}).items():
            provider = providers.get((path, library))
            definitions = set(entries.get(provider, {}).get('gnu_versions', {}).get('defines', []))
            for name in names:
                row = {'consumer': path, 'library': library, 'version': name, 'provider': provider}
                (found if provider is not None and name in definitions else missing).append(row)
    return found, missing
