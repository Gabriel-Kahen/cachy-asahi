# SPDX-License-Identifier: MIT
"""Bounded static AArch64 ELF dependency audit; no file I/O, loader or execution.

File-backed PT_DYNAMIC/DT_STRTAB checks follow scripts/platform/elf_audit.py.
Unlike its global filename-candidate inventory, this module resolves an explicit
closed regular-file rootfs. Symbol/version ABI and actual loading are not proved.
"""
import hashlib
import posixpath
import re
import struct

MAX_ROWS, MAX_TOTAL, MAX_FILE = 8192, 256*1024**2, 128*1024**2
MAX_PH, MAX_DYNAMIC, MAX_STRING = 256, 4096, 4096
MAX_SECTIONS = 8192
DEFAULT_DIRS = ('usr/lib', 'lib')
RESERVED = ('probe', 'init', 'proc', 'dev', 'tmp', 'home', 'var/lib/pacman')
UNSUPPORTED_TAGS = {0x6ffffefa, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(path):
    need(type(path) is str and 0 < len(path) <= MAX_STRING and not path.startswith('/')
         and '\\' not in path and not re.search(r'[\x00-\x20\x7f]', path)
         and all(part not in ('', '.', '..') for part in path.split('/')), 'noncanonical rootfs path')
    need(not any(path == prefix or path.startswith(prefix+'/') for prefix in RESERVED), 'reserved rootfs path')
    return path


def library_name(value):
    need(type(value) is str and len(value) <= 255 and re.fullmatch(r'[A-Za-z0-9_+.-]+', value)
         and value not in ('.', '..'), 'unsupported library name or dynamic token')
    return value


def parse_elf(raw):
    """Return bounded loader metadata, None for ordinary non-ELF DATA."""
    need(type(raw) is bytes and len(raw) <= MAX_FILE, 'bounded immutable file bytes')
    if raw[:4] != b'\x7fELF':
        return None
    need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
         and raw[7] in (0, 3) and raw[8] == 0, 'ELF64 little-endian SystemV/Linux required')
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phent, phnum, shent, shnum, shstr = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    need(machine == 183 and kind in (1, 2, 3) and version == 1 and flags == 0 and ehsize == 64,
         'loadable AArch64 ELF type/version/flags required')
    if kind == 1:
        # Python's complete stdlib includes config-*/python.o. It is retained
        # as inert build DATA, never as a loader, dependency or entrypoint.
        need(entry == phoff == phent == phnum == 0 and shent == 64
             and 1 < shnum <= MAX_SECTIONS and shoff >= 64
             and shoff+shnum*shent <= len(raw) and 0 < shstr < shnum,
             'bounded nonloadable ET_REL headers required')
        sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff+i*shent) for i in range(shnum)]
        need(not any(sections[0]), 'ordinary ET_REL null section required')
        names = sections[shstr]
        need(names[1] == 3 and names[5] <= MAX_FILE and names[4]+names[5] <= len(raw),
             'ET_REL section-name string table required')
        name_bytes = raw[names[4]:names[4]+names[5]]
        need(name_bytes[:1] == b'\0', 'ET_REL section names start with NULL')
        for name, typ, section_flags, addr, off, size, link, info, align, entsize in sections[1:]:
            need(typ != 6 and addr == 0 and off <= len(raw) and size <= MAX_TOTAL
                 and (typ == 8 or size <= len(raw)-off) and link < shnum
                 and (align in (0, 1) or align & (align-1) == 0)
                 and (not entsize or size % entsize == 0), 'ET_REL section structure')
            need(name < len(name_bytes) and name_bytes.find(b'\0', name) >= 0,
                 'ET_REL section-name termination')
            if typ in (4, 9):
                need(info < shnum and entsize == (24 if typ == 4 else 16), 'ET_REL relocation section')
            if typ in (2, 11):
                need(entsize == 24 and sections[link][1] == 3 and info <= size//24,
                     'ET_REL symbol section')
        return dict(type=1, machine='AArch64', classification='NONLOADABLE_ET_REL_DATA', sections=shnum)
    need(0 < phnum <= MAX_PH and phnum != 65535 and phent == 56 and phoff >= 64
         and phoff + phnum*phent <= len(raw), 'bounded ordinary program-header table required')
    loads, dynamics, interpreter = [], [], None

    def ranged(offset, size):
        need(0 <= offset <= len(raw) and 0 <= size <= len(raw)-offset, 'ELF file range')
        return offset

    for index in range(phnum):
        typ, pflags, off, va, pa, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', raw, phoff+index*phent)
        if typ == 0:
            continue
        ranged(off, filesz)
        if typ == 1:
            need(filesz <= memsz and va+memsz <= 2**64 and pflags <= 7
                 and (align in (0, 1) or align & (align-1) == 0)
                 and (align <= 1 or off % align == va % align), 'ELF LOAD layout')
            need(not loads or va >= loads[-1]['vaddr'], 'ELF LOAD order')
            loads.append(dict(offset=off, vaddr=va, filesz=filesz, memsz=memsz, flags=pflags, alignment=align))
        elif typ == 3:
            need(interpreter is None and not loads and 1 < filesz <= MAX_STRING, 'ELF INTERP layout')
            data = raw[off:off+filesz]
            need(data[-1:] == b'\0' and b'\0' not in data[:-1], 'ELF INTERP termination')
            interpreter = data[:-1].decode('ascii')
            need(interpreter.startswith('/'), 'absolute ELF interpreter required')
            canonical(interpreter[1:])
        elif typ == 2:
            need(not dynamics, 'duplicate PT_DYNAMIC')
            dynamics.append((off, va, filesz, memsz))
    need(loads and max(row['vaddr']+row['memsz'] for row in loads)-loads[0]['vaddr'] <= MAX_TOTAL,
         'bounded loadable ELF memory span')
    if kind == 2 or interpreter is not None:
        need(any(row['vaddr'] <= entry < row['vaddr']+row['memsz'] and row['flags'] & 1 for row in loads),
             'ELF entry must map an executable LOAD')

    def mapped(address, size):
        need(address+size <= 2**64, 'ELF virtual range overflow')
        matches = [row['offset']+address-row['vaddr'] for row in loads
                   if row['vaddr'] <= address and size <= row['filesz']-(address-row['vaddr'])]
        need(len(matches) == 1, 'ELF address must have one complete file-backed LOAD mapping')
        return ranged(matches[0], size)

    tags = {}; ignored_records = ignored_nonzero_records = 0
    if dynamics:
        off, va, size, memory = dynamics[0]
        need(size >= 16 and size % 16 == 0 and size//16 <= MAX_DYNAMIC and memory == size
             and mapped(va, memory) == off, 'bounded file-backed dynamic table required')
        terminated = False
        for index in range(size//16):
            tag, value = struct.unpack_from('<qQ', raw, off+index*16)
            if tag == 0:
                terminated = True
                # DT_NULL terminates the loader's table. Its value and later
                # records are DATA, never needed/provider evidence. In the
                # retained bwrap, one later DT_NULL has an unused value1321.
                ignored_records = size//16-index-1
                ignored_nonzero_records = sum(any(struct.unpack_from('<qQ',raw,off+n*16))
                    for n in range(index+1,size//16))
                break
            tags.setdefault(tag, []).append(value)
        need(terminated, 'unterminated dynamic table')
        need(not UNSUPPORTED_TAGS.intersection(tags), 'audit/filter/auxiliary/config loader tags unsupported')
        for tag in (5, 10, 14, 15, 29, 0x6ffffffb):
            need(len(tags.get(tag, [])) <= 1, 'duplicate singleton dynamic tag')
        need(not tags.get(0x6ffffffb, [0])[0] & 0x800, 'DF_1_NODEFLIB unsupported')
    values = dict(needed=[], soname=None, rpath=None, runpath=None)
    if any(tag in tags for tag in (1, 5, 10, 14, 15, 29)):
        need(5 in tags and 10 in tags and 0 < tags[10][0] <= 4*1024**2, 'bounded DT_STRTAB/DT_STRSZ pair required')
        start, size = mapped(tags[5][0], tags[10][0]), tags[10][0]
        need(raw[start] == raw[start+size-1] == 0, 'dynamic string table boundaries')
        def string(offset):
            need(offset < size, 'dynamic string offset')
            end = raw.find(b'\0', start+offset, min(start+size, start+offset+MAX_STRING+1))
            need(end >= 0, 'dynamic string termination')
            value = raw[start+offset:end].decode('ascii')
            need(not re.search(r'[\x00-\x1f\x7f]', value), 'dynamic string controls')
            return value
        values['needed'] = [string(offset) for offset in tags.get(1, [])]
        need(len(values['needed']) == len(set(values['needed'])), 'duplicate DT_NEEDED unsupported')
        for tag, name in ((14, 'soname'), (15, 'rpath'), (29, 'runpath')):
            if tag in tags:
                values[name] = string(tags[tag][0])
    if values['soname'] is not None:
        library_name(values['soname'])
    return dict(type=kind, machine='AArch64', interpreter=interpreter, dynamic=bool(dynamics),
                flags_1=tags.get(0x6ffffffb, [0])[0], loads=loads,
                ignored_dynamic_records=ignored_records, ignored_nonzero_dynamic_records=ignored_nonzero_records, **values)


def search_directories(path, metadata):
    """No environment/cache search. RUNPATH applies only to this object's deps."""
    need(metadata['rpath'] is None or metadata['runpath'] is not None,
         'legacy transitive DT_RPATH unsupported; explicit classification required')
    result = []
    if metadata['runpath'] is not None:
        parts = metadata['runpath'].split(':')
        need(0 < len(parts) <= 16 and all(parts), 'empty/cwd or excessive RUNPATH entries unsupported')
        for part in parts:
            origin = next((token for token in ('$ORIGIN', '${ORIGIN}') if part == token or part.startswith(token+'/')), None)
            if origin:
                text = posixpath.dirname(path) + part[len(origin):]
                components = []
                for component in text.split('/'):
                    if component in ('', '.'):
                        continue
                    if component == '..':
                        need(components, 'RUNPATH escapes rootfs')
                        components.pop()
                    else:
                        components.append(component)
                text = '/'.join(components)
            else:
                need(part.startswith('/'), 'relative RUNPATH or unsupported token')
                text = part[1:]
            need('$' not in text, 'unsupported dynamic RUNPATH token')
            canonical(text)
            if text not in result:
                result.append(text)
    return result + [name for name in DEFAULT_DIRS if name not in result]


def audit_closure(files, roots=None):
    """Audit every selected ELF; roots additionally require named ELF entrypoints.

    files maps canonical relative paths to exactly {'raw': bytes, 'mode': int}.
    Aliases must already be materialized regular files by the assembler.
    """
    need(type(files) is dict and 0 < len(files) <= MAX_ROWS, 'rootfs row count')
    total, parsed, pins, nonloadable = 0, {}, {}, {}
    for path, row in files.items():
        canonical(path)
        need(type(row) is dict and set(row) == {'raw', 'mode'} and type(row['raw']) is bytes
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'ordinary readable file mode/bytes required')
        total += len(row['raw']); need(total <= MAX_TOTAL, 'rootfs aggregate byte cap')
        need(path not in ('etc/ld.so.cache', 'etc/ld.so.preload') and 'glibc-hwcaps' not in path.split('/'),
             'loader cache/preload/hwcaps data unsupported')
        pins[path] = dict(bytes=len(row['raw']), sha256=hashlib.sha256(row['raw']).hexdigest(), mode=row['mode'])
        elf = parse_elf(row['raw'])
        if elf is not None:
            if elf['type'] == 1:
                need(row['mode'] == 0o644, 'nonloadable ET_REL must remain nonexecutable DATA')
                nonloadable[path] = elf
            else:
                parsed[path] = elf
    need(parsed, 'no selected ELF files')
    for path in files:
        need(not any(parent in files for parent in _parents(path)), 'file/directory collision')
    required = sorted(parsed) if roots is None else roots
    need(type(required) in (list, tuple) and len(required) <= MAX_ROWS and len(required) == len(set(required)), 'finite unique required roots')
    need(all(canonical(path) in parsed for path in required), 'required root is not a selected AArch64 ELF')
    # Arch's /lib alias is materialized, not imagined. Conflicting duplicates
    # cannot support an order-independent canonical-/usr/lib closure.
    for path in files:
        if path.startswith('lib/') and 'usr/'+path in files:
            need(files[path] == files['usr/'+path], 'conflicting materialized /lib alias')
    special_dirs = set()
    for name in files:
        parts = name.split('/')
        for index, part in enumerate(parts):
            if part in ('tls', 'aarch64', 'glibc-hwcaps'):
                special_dirs.add('/'.join(parts[:index]))
    providers, edges = {}, []
    for path, elf in sorted(parsed.items()):
        if elf['soname'] is not None:
            previous = providers.setdefault(elf['soname'], pins[path]['sha256'])
            need(previous == pins[path]['sha256'], 'conflicting selected SONAME providers')
        if elf['interpreter'] is not None:
            target = canonical(elf['interpreter'][1:])
            need(target in parsed and parsed[target]['type'] == 3 and parsed[target]['interpreter'] is None
                 and files[target]['mode'] == 0o755, 'missing or invalid literal PT_INTERP provider')
            edges.append(dict(requester=path, kind='PT_INTERP', requested=elf['interpreter'], provider=target, sha256=pins[target]['sha256']))
        directories = search_directories(path, elf)
        for directory in directories:
            need(directory not in special_dirs, 'loader hardware-capability search subtree unsupported')
        for wanted in elf['needed']:
            if '/' in wanted:
                need(wanted.startswith('/') and '$' not in wanted, 'relative/token DT_NEEDED path unsupported')
                candidates = [canonical(wanted[1:])]
            else:
                library_name(wanted)
                candidates = [directory+'/'+wanted for directory in directories]
            target = next((name for name in candidates if name in files), None)
            need(target is not None and target in parsed and parsed[target]['type'] == 3
                 and not parsed[target]['flags_1'] & 0x08000000
                 and (parsed[target]['interpreter'] is None or parsed[target]['soname'] is not None),
                 'missing or non-DSO DT_NEEDED provider: '+path+' -> '+wanted)
            provider = parsed[target]
            need(provider['soname'] is None or provider['soname'] == posixpath.basename(wanted),
                 'DT_NEEDED provider SONAME mismatch: '+wanted)
            # Canonical Arch library storage must not be replaced by a lone
            # /lib file when only alias flattening made it appear searchable.
            if target.startswith('lib/') and target in candidates and wanted[0] != '/' and target.startswith(tuple(directory+'/' for directory in DEFAULT_DIRS)):
                need('usr/'+target in files and files['usr/'+target] == files[target], 'default /lib provider lacks canonical /usr/lib copy')
            edges.append(dict(requester=path, kind='DT_NEEDED', requested=wanted, provider=target,
                              sha256=pins[target]['sha256'], search=directories))
    return dict(status='PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE', files=len(files), bytes=total,
        required_roots=list(required), elf_files=sorted(parsed), metadata=parsed, edges=edges,
        nonloadable_DATA=nonloadable,
        audited_all_selected_ELFs=True, rootfs_pins=pins, runtime_execution='NOT_RUN',
        symbol_version_ABI='NOT_AUDITED', page_size='NOT_QUALIFIED', hardware='NOT_RUN',
        loader_assumptions=dict(environment_overrides='ABSENT', cache='ABSENT', preload='ABSENT',
            hwcaps_subtrees='ABSENT', default_directories=list(DEFAULT_DIRS), aliases='MATERIALIZED_REGULAR_FILES'))


def _parents(path):
    parts = path.split('/')
    return ['/'.join(parts[:index]) for index in range(1, len(parts))]
