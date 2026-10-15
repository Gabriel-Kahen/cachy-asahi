# SPDX-License-Identifier: MIT
"""Pure bytes/observations gate. No file/proc/actor/native authority is acquired.

Only the trusted native owner may supply observations and an opaque adoption
capability. A JSON receipt is never a replacement for either. Tests use inert
synthetic capabilities. Passing means conditional consistency, not native proof.
"""
from dataclasses import dataclass
import hashlib
import stat
import struct


class Refusal(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def digest(data):
    need(type(data) is bytes and 0 < len(data) <= 8 * 1024 * 1024, 'byte bound')
    return hashlib.sha256(data).hexdigest()


def shim_elf(data):
    """Conservative ELF64 LE AArch64 ET_EXEC structural gate, not code audit."""
    digest(data)
    need(len(data) >= 64, 'ELF header')
    ident = data[:16]
    need(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7:9] == b'\0\0'
         and ident[9:] == bytes(7), 'ELF ABI')
    fields = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, entry, phoff, shoff, flags, eh, pe, pn, se, sn, si = fields
    need((kind, machine, version, flags, eh, pe) == (2, 183, 1, 0, 64, 56), 'ELF target')
    need(1 <= pn <= 32 and phoff >= 64 and phoff + pn * pe <= len(data), 'PH table')
    need(not sn or (se == 64 and 0 < sn <= 4096 and shoff >= 64
                    and shoff + sn * se <= len(data) and si < sn), 'SH table')
    need(sn or (shoff == se == si == 0), 'extended sections unsupported')
    loads = []
    for i in range(pn):
        t, f, off, va, pa, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, phoff+i*56)
        need(t in (1, 4, 6, 0x6474e551), 'unreviewed PH type (interp/dynamic refused)')
        need(f & ~7 == 0 and f & 3 != 3, 'writable executable segment')
        need(off <= len(data) and fs <= len(data)-off and ms >= fs, 'segment bounds')
        need(va + ms < 2**64 and ms <= 16 * 1024 * 1024, 'segment memory bound')
        if t == 0x6474e551:
            need(not (f & 1), 'executable stack')
        if t != 1:
            continue
        need(fs > 0 and ms > 0 and align >= 65536 and align <= 2**21
             and align & (align-1) == 0 and off % align == va % align, 'LOAD alignment')
        # Reject overlap even after 64KiB page rounding. Supports smaller pages too.
        lo, hi = va & ~65535, (va + ms + 65535) & ~65535
        need(all(hi <= a or lo >= b for a, b, *_ in loads), 'LOAD page alias')
        loads.append((lo, hi, f, va, fs))
    need(loads and any(f & 1 and va <= entry < va+fs for _, _, f, va, fs in loads), 'entry not file-backed executable')
    need(any(f & 1 for _, _, f, _, _ in loads), 'no executable LOAD')
    return {'sha256': digest(data), 'bytes': len(data), 'machine': 183, 'type': 2,
            'load_segments': len(loads), 'code_paths': 'REQUIRES_ROOT_COMPILED_CODE_REVIEW'}


@dataclass(frozen=True)
class Snapshot:
    dev: int
    inode: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int


def snap(s):
    need(type(s) is Snapshot and all(type(v) is int and v >= 0 for v in s.__dict__.values()), 'typed stat observation')
    need(s.inode > 0 and s.nlink == 1, 'inode/hardlink')


@dataclass(frozen=True)
class HeldFile:
    # Native owner holds object tokens until last guard; never substitute fd numbers.
    token: object
    fd_before: Snapshot
    fd_after: Snapshot
    named_before: Snapshot
    named_after: Snapshot
    bytes_read: bytes


@dataclass(frozen=True)
class Context:
    source: str
    policy_sha256: str
    profile: str
    job_uid: int
    job_gid: int
    nonce: str
    generation: int
    job_inode: tuple
    keyhome_inode: tuple
    socket_inode: tuple


def context(c):
    need(type(c) is Context and c.profile in ('fish', 'topmem'), 'profile')
    need(type(c.source) is str and len(c.source) == 40 and all(v in '0123456789abcdef' for v in c.source), 'Source')
    hexhash(c.policy_sha256)
    need(type(c.job_uid) is int and c.job_uid > 0 and type(c.job_gid) is int and c.job_gid > 0, 'job credentials')
    need(type(c.nonce) is str and len(c.nonce) == 32 and all(v in '0123456789abcdef' for v in c.nonce), 'nonce')
    need(type(c.generation) is int and c.generation > 0, 'generation')
    for row in (c.job_inode, c.keyhome_inode, c.socket_inode):
        need(type(row) is tuple and len(row) == 2 and all(type(v) is int and v > 0 for v in row), 'scope inode')
    need(len({c.job_inode, c.keyhome_inode, c.socket_inode}) == 3, 'scope aliases')


def hexhash(s):
    need(type(s) is str and len(s) == 64 and all(c in '0123456789abcdef' for c in s), 'digest syntax')


@dataclass(frozen=True)
class BuildBinding:
    source_sha256: str
    compiler_sha256: str
    headers_sha256: str
    filter_sha256: str
    command_sha256: str
    binary_sha256: str
    code_review_sha256: str


def held(f, token, sha, owner, mode):
    need(type(f) is HeldFile and f.token is token and token is not None, 'held object custody')
    for s in (f.fd_before, f.fd_after, f.named_before, f.named_after):
        snap(s)
    s = f.fd_before
    need(f.fd_after == f.named_before == f.named_after == s, 'fd/named race')
    need(stat.S_ISREG(s.mode) and stat.S_IMODE(s.mode) == mode and (s.uid, s.gid) == owner, 'role ownership/mode')
    need(s.size == len(f.bytes_read) and digest(f.bytes_read) == sha, 'held bytes')
    return s.dev, s.inode


class Adoption:
    """Opaque Root reviewed custody, not serializable receipt authority.

    The parent must retain a private identity token minted only after actual
    compiled-byte review and hosted-kernel/binfmt proof. Same trusted Python
    scope can forge an instance: no claim to constrain that trusted owner.
    """
    def __init__(self, root_token, ctx, build, shim_token, agent_token, kernel_sha,
                 handler_review_sha, agent_sha, interpreter_closure_sha):
        need(root_token is not None and type(root_token) is object, 'Root private token')
        context(ctx)
        need(type(build) is BuildBinding, 'build binding')
        for s in build.__dict__.values():
            hexhash(s)
        for s in (kernel_sha, handler_review_sha, agent_sha, interpreter_closure_sha):
            hexhash(s)
        need(type(shim_token) is object and type(agent_token) is object and shim_token is not agent_token, 'distinct held tokens')
        self.root_token, self.ctx, self.build = root_token, ctx, build
        self.shim_token, self.agent_token = shim_token, agent_token
        self.kernel_sha, self.handler_review_sha = kernel_sha, handler_review_sha
        self.agent_sha, self.interpreter_closure_sha = agent_sha, interpreter_closure_sha


@dataclass(frozen=True)
class HandlerObservation:
    # Supplied by Root's actual bounded acquisition. No collection code here.
    kernel_sha256: str
    handler_review_sha256: str
    interpreter_closure_sha256: str
    binfmt_misc_before: bytes
    binfmt_misc_after: bytes
    complete_entries_before: tuple
    complete_entries_after: tuple
    scope_before: Context
    scope_after: Context


def admit(root_token, grant, ctx, shim, agent, handler, observed_artifacts):
    """Pure conditional validation. Returns no native/current-image capability.

    observed_artifacts is a BuildBinding of actual byte hashes, not filenames.
    Root grant review must also establish immutable-until-exec provenance,
    ancestor custody and complete hosted-kernel native ELF handler selection.
    """
    need(type(grant) is Adoption and root_token is grant.root_token, 'opaque Root adoption')
    context(ctx)
    need(ctx == grant.ctx and observed_artifacts == grant.build, 'Source/build/context')
    # Root's kernel review must bind handler registration ordering, no competing
    # built-in/module handlers, and runtime mount/namespace snapshot completeness.
    need(type(handler) is HandlerObservation and handler.scope_before == handler.scope_after == ctx, 'handler scope race')
    need((handler.kernel_sha256, handler.handler_review_sha256, handler.interpreter_closure_sha256)
         == (grant.kernel_sha, grant.handler_review_sha, grant.interpreter_closure_sha), 'kernel/handler/interpreter proof')
    need(handler.binfmt_misc_before == handler.binfmt_misc_after == b'disabled\n', 'binfmt_misc disabled observation required')
    # Complete enumeration required even globally disabled: malformed/partial
    # enumeration and enabled entries remain a narrow native stage refusal.
    need(handler.complete_entries_before == handler.complete_entries_after == (), 'nonempty/unknown binfmt registry')
    si = held(shim, grant.shim_token, grant.build.binary_sha256, (ctx.job_uid, ctx.job_gid), 0o500)
    ai = held(agent, grant.agent_token, grant.agent_sha, (0, 0), 0o755)
    need(si != ai, 'shim/agent inode alias')
    shim_elf(shim.bytes_read)
    need(len(agent.bytes_read) >= 64 and agent.bytes_read[:7] == b'\x7fELF\x02\x01\x01', 'agent ELF magic/ABI')
    et, em, ev = struct.unpack_from('<HHI', agent.bytes_read, 16)
    need(et in (2, 3) and em == 183 and ev == 1, 'agent ELF target')
    return {'status': 'CONDITIONAL_INPUTS_CONSISTENT_NO_NATIVE_PROOF',
            'shim_inode': si, 'agent_inode': ai, 'native_execution': False,
            'current_image_proof': False, 'historical_absence': False}
