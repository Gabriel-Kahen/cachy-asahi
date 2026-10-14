# SPDX-License-Identifier: MIT
"""Pure bounded inspection of held compile outputs; no runtime admission.

ELF layout and emitted UAPI values cannot prove compiled control flow, kernel
handlers, loader behavior, selected signer APIs or any M2 compatibility.
"""
import hashlib
import struct

MAX_ELF = 4 * 1024 * 1024
MAX_TOOL_TEXT = 8 * 1024 * 1024
PAGE = 65536
U64 = 2**64
ABI_MAGIC = 0x3149424154495757  # little endian: WWITABI1


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def span(offset, size, bound, reason):
    need(type(offset) is int and type(size) is int and 0 <= offset <= bound
         and 0 <= size <= bound - offset, reason)


def digest(raw):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def elf(raw, kind):
    need(type(raw) is bytes and 64 <= len(raw) <= MAX_ELF, 'elf-size')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    ident, typ, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names = h
    need(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3)
         and ident[8:] == bytes(8), 'elf-ident')
    need(typ == kind and machine == 183 and version == 1 and flags == 0 and ehsize == 64, 'elf-header')
    need(phnum <= 32 and 0 < shnum <= 256 and 0 < names < shnum, 'elf-tables-count')
    need(shsize == 64 and shoff >= 64 and shoff % 8 == 0, 'section-table-shape')
    span(shoff, shnum * 64, len(raw), 'section-table-bound')
    if phnum:
        need(phsize == 56 and phoff >= 64 and phoff % 8 == 0, 'program-table-shape')
        span(phoff, phnum * 56, len(raw), 'program-table-bound')
        need(phoff + phnum * 56 <= shoff or shoff + shnum * 64 <= phoff, 'table-overlap')
    else:
        need(phoff == 0 and phsize == 0, 'absent-program-table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * 64) for i in range(shnum)]
    need(sections[0] == (0,) * 10, 'null-section')
    ns = sections[names]
    need(ns[1] == 3 and 0 < ns[5] <= 65536, 'section-name-table')
    span(ns[4], ns[5], len(raw), 'section-name-bound')
    table = raw[ns[4]:ns[4] + ns[5]]
    need(table[:1] == b'\0' and table[-1:] == b'\0', 'section-name-termination')
    named = []
    for s in sections:
        name, stype, sflags, address, offset, size, link, info, align, entsize = s
        need(name < len(table), 'section-name-offset')
        end = table.find(b'\0', name)
        need(end >= name and end - name <= 255, 'section-name-length')
        try:
            label = table[name:end].decode('ascii')
        except UnicodeDecodeError as error:
            raise Refused('section-name-ascii') from error
        need(align == 0 or align & (align - 1) == 0, 'section-align')
        need(address < U64 and size < U64 - address, 'section-address-overflow')
        if stype != 8:  # SHT_NOBITS has no file extent
            span(offset, size, len(raw), 'section-file-bound')
        need(link < shnum, 'section-link-bound')
        named.append((label, s))
    return h, named


def inspect_shim(raw):
    h, sections = elf(raw, 2)  # ET_EXEC, not PIE/shared object
    entry, phoff, phnum = h[4], h[5], h[10]
    need(0 < phnum <= 32, 'shim-program-table')
    loads, stacks = [], []
    for i in range(phnum):
        ptype, flags, offset, virtual, physical, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', raw, phoff + i * 56)
        need(ptype not in (2, 3), 'dynamic-or-interpreter')
        need(ptype in (0, 1, 4, 6, 0x6474e550, 0x6474e551, 0x6474e552), 'unsupported-program-type')
        need(flags & ~7 == 0 and flags & 3 != 3, 'program-writable-executable')
        span(offset, filesz, len(raw), 'program-file-bound')
        need(filesz <= memsz and memsz < U64 - virtual, 'program-memory-bound')
        if ptype == 1:
            need(memsz > 0 and align >= PAGE and align & (align - 1) == 0
                 and offset % align == virtual % align, 'load-page-layout')
            loads.append((virtual, virtual + memsz, offset, offset + filesz, flags))
        elif ptype == 0x6474e551:
            need(flags == 6 and filesz == memsz == 0, 'stack-must-be-nonexecuting')
            stacks.append(i)
    need(0 < len(loads) <= 8 and len(stacks) == 1, 'load-stack-count')
    for i, a in enumerate(loads):
        for b in loads[i + 1:]:
            need((a[1] + PAGE - 1) // PAGE * PAGE <= b[0] // PAGE * PAGE
                 or (b[1] + PAGE - 1) // PAGE * PAGE <= a[0] // PAGE * PAGE, 'rounded-load-overlap')
            need(a[3] <= b[2] or b[3] <= a[2] or a[2] == a[3] or b[2] == b[3], 'load-file-overlap')
    need(entry % 4 == 0 and any(flags & 1 and start <= entry < start + endoff - offset
                              for start, end, offset, endoff, flags in loads), 'entry-file-backed-executable')
    for label, s in sections:
        need(not s[2] & (0x400 | 0x800), 'shim-tls-compressed-section')
        need(s[2] & 5 != 5, 'section-writable-executable')
        need(s[1] not in (6, 11), 'dynamic-section')
        if s[2] & 2 and s[5]:
            need(any(start <= s[3] and s[5] <= end - s[3]
                     and (not s[2] & 1 or flags & 2) and (not s[2] & 4 or flags & 1)
                     and (s[1] == 8 or (s[4] - offset == s[3] - start
                          and s[5] <= endoff - s[4]))
                     for start, end, offset, endoff, flags in loads), 'allocated-section-load-custody')
    return dict(status='STATIC_SHIM_ELF_STRUCTURE_ONLY', artifact=digest(raw),
                entry=entry, page_separation=PAGE, load_count=len(loads),
                compiled_instruction_review=False, kernel_loader_api_admission=False)


ABI_FIELDS = (
    ('sizeof.seccomp_data', 64),
    ('offsetof.seccomp_data.nr', 0),
    ('offsetof.seccomp_data.arch', 4),
    ('offsetof.seccomp_data.instruction_pointer', 8),
    ('offsetof.seccomp_data.args', 16),
    ('sizeof.seccomp_notif', 80),
    ('offsetof.seccomp_notif.id', 0),
    ('offsetof.seccomp_notif.pid', 8),
    ('offsetof.seccomp_notif.flags', 12),
    ('offsetof.seccomp_notif.data', 16),
    ('sizeof.seccomp_notif_resp', 24),
    ('offsetof.seccomp_notif_resp.id', 0),
    ('offsetof.seccomp_notif_resp.val', 8),
    ('offsetof.seccomp_notif_resp.error', 16),
    ('offsetof.seccomp_notif_resp.flags', 20),
    ('sizeof.seccomp_notif_sizes', 6),
    ('offsetof.seccomp_notif_sizes.seccomp_notif', 0),
    ('offsetof.seccomp_notif_sizes.seccomp_notif_resp', 2),
    ('offsetof.seccomp_notif_sizes.seccomp_data', 4),
    ('sizeof.sock_filter', 8),
    ('offsetof.sock_filter.code', 0),
    ('offsetof.sock_filter.jt', 2),
    ('offsetof.sock_filter.jf', 3),
    ('offsetof.sock_filter.k', 4),
    ('sizeof.sock_fprog', 16),
    ('offsetof.sock_fprog.len', 0),
    ('offsetof.sock_fprog.filter', 8),
    ('sizeof.pollfd', 8),
    ('offsetof.pollfd.fd', 0),
    ('offsetof.pollfd.events', 4),
    ('offsetof.pollfd.revents', 6),
    ('shim_wire.sizeof.vector', 16),
    ('shim_wire.offsetof.vector.base', 0),
    ('shim_wire.offsetof.vector.size', 8),
    ('shim_wire.sizeof.message', 56),
    ('shim_wire.offsetof.message.name', 0),
    ('shim_wire.offsetof.message.name_size', 8),
    ('shim_wire.offsetof.message.vectors', 16),
    ('shim_wire.offsetof.message.count', 24),
    ('shim_wire.offsetof.message.control', 32),
    ('shim_wire.offsetof.message.control_size', 40),
    ('shim_wire.offsetof.message.flags', 48),
    ('shim_wire.sizeof.rights', 24),
    ('shim_wire.offsetof.rights.size', 0),
    ('shim_wire.offsetof.rights.level', 8),
    ('shim_wire.offsetof.rights.kind', 12),
    ('shim_wire.offsetof.rights.fd', 16),
    ('shim_wire.offsetof.rights.padding', 20),
    ('sizeof.long', 8),
    ('sizeof.void_pointer', 8),
    ('sizeof.unsigned_int', 4),
    ('sizeof.unsigned_short', 2),
    ('sizeof.unsigned_long_long', 8),
    ('SECCOMP_IOCTL_NOTIF_RECV', 3226476800),
    ('SECCOMP_IOCTL_NOTIF_SEND', 3222806785),
    ('SECCOMP_IOCTL_NOTIF_ID_VALID', 1074274562),
    ('SECCOMP_USER_NOTIF_FLAG_CONTINUE', 1),
    ('SECCOMP_FILTER_FLAG_NEW_LISTENER', 8),
    ('SECCOMP_SET_MODE_FILTER', 1),
    ('SECCOMP_GET_ACTION_AVAIL', 2),
    ('SECCOMP_GET_NOTIF_SIZES', 3),
    ('SECCOMP_RET_USER_NOTIF', 2143289344),
    ('SECCOMP_RET_ALLOW', 2147418112),
    ('SECCOMP_RET_ERRNO', 327680),
    ('SECCOMP_RET_KILL_PROCESS', 2147483648),
    ('AUDIT_ARCH_AARCH64', 3221225655),
    ('PR_SET_NO_NEW_PRIVS', 38),
    ('PR_SET_SECCOMP', 22),
    ('PR_SET_MM', 35),
    ('PR_SET_PTRACER', 1499557217),
    ('PR_SET_DUMPABLE', 4),
    ('AT_EMPTY_PATH', 4096),
    ('FD_CLOEXEC', 1),
    ('F_SETFD', 2),
    ('O_RDONLY', 0),
    ('O_NONBLOCK', 2048),
    ('O_NOFOLLOW', 131072),
    ('O_CLOEXEC', 524288),
    ('POLLIN', 1),
    ('POLLERR', 8),
    ('POLLHUP', 16),
    ('POLLNVAL', 32),
    ('CLONE_VM', 256),
    ('CLONE_FS', 512),
    ('CLONE_FILES', 1024),
    ('CLONE_SIGHAND', 2048),
    ('CLONE_THREAD', 65536),
    ('CLONE_SYSVSEM', 262144),
    ('CLONE_SETTLS', 524288),
    ('CLONE_PARENT_SETTID', 1048576),
    ('CLONE_CHILD_CLEARTID', 2097152),
    ('__NR_execveat', 281),
    ('__NR_brk', 214),
    ('__NR_clone', 220),
    ('__NR_clone3', 435),
    ('__NR_execve', 221),
    ('__NR_seccomp', 277),
    ('__NR_prctl', 167),
    ('__NR_sendmsg', 211),
    ('__NR_close', 57),
    ('__NR_dup3', 24),
    ('__NR_fcntl', 25),
    ('__NR_getpid', 172),
    ('__NR_exit_group', 94),
    ('__NR_pidfd_open', 434),
    ('__NR_pidfd_send_signal', 424),
    ('__NR_ptrace', 117),
    ('__NR_process_vm_writev', 271),
    ('__NR_pidfd_getfd', 438),
    ('__NR_unshare', 97),
    ('__NR_setns', 268),
    ('__NR_io_uring_setup', 425),
    ('BPF_LD_W_ABS', 32),
    ('BPF_JMP_JEQ_K', 21),
    ('BPF_RET_K', 6),
    ('thread_clone_mask', 4001536),
)


def inspect_abi_object(raw):
    h, sections = elf(raw, 1)  # ET_REL; this helper is NEVER run
    need(h[4] == 0 and h[10] == 0, 'abi-object-nonexecutable')
    need(all(not (s[5] and s[2] & (1 | 4 | 0x400 | 0x800)) for _, s in sections),
         'abi-object-writable-executable-tls-compressed')
    need(all(not (s[5] and s[2] & 2) or label == '.witness_abi' for label, s in sections),
         'abi-object-other-allocated-data')
    candidates = [(i, s) for i, (label, s) in enumerate(sections) if label == '.witness_abi']
    need(len(candidates) == 1, 'abi-section-count')
    index, s = candidates[0]
    need(s[1] == 1 and s[2] in (0, 2) and s[3] == 0 and s[8] == 8
         and s[9] == 0 and s[6] == s[7] == 0, 'abi-section-readonly-data')
    need(s[5] == (3 + len(ABI_FIELDS)) * 8, 'abi-section-size')
    need(all(not (item[1] in (4, 9) and item[7] == index) for _, item in sections), 'abi-section-relocation')
    values = struct.unpack_from('<' + 'Q' * (3 + len(ABI_FIELDS)), raw, s[4])
    need(values[:3] == (ABI_MAGIC, 1, len(ABI_FIELDS)), 'abi-section-schema')
    need(values[3:] == tuple(value for name, value in ABI_FIELDS), 'abi-selected-layout-mismatch')
    return dict(status='COMPILED_HEADER_LAYOUT_ONLY', artifact=digest(raw),
                section=digest(raw[s[4]:s[4] + s[5]]), schema=1,
                values=dict(ABI_FIELDS), helper_executed=False,
                kernel_loader_api_admission=False)


def inspect_outputs(shim, abi_object, *, shim_disassembly, shim_readelf, abi_disassembly, abi_readelf):
    records = {}
    for name, raw in (('shim_disassembly', shim_disassembly), ('shim_readelf', shim_readelf),
                      ('abi_disassembly', abi_disassembly), ('abi_readelf', abi_readelf)):
        need(type(raw) is bytes and 0 < len(raw) <= MAX_TOOL_TEXT, 'tool-output-bound')
        records[name] = digest(raw)
    return dict(shim=inspect_shim(shim), abi=inspect_abi_object(abi_object), tool_outputs=records,
                compiled_instruction_review=False, actual_header_provenance_review=False,
                kernel_loader_api_admission=False, hardware_admission=False)
