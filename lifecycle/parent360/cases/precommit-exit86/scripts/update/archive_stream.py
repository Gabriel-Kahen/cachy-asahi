#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded single-frame package inspection; no extraction or external actors."""
from dataclasses import dataclass
import hashlib
import lzma
import math
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time
import zlib

try:
    from compression import zstd
except ImportError:
    zstd = None

DECODER_ERRORS = (tarfile.TarError, zlib.error, lzma.LZMAError, EOFError, RecursionError)
if zstd is not None:
    DECODER_ERRORS += (zstd.ZstdError,)

CHUNK = 64 * 1024
AUXILIARIES = {'usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'}
CONTROLS = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL', '.CHANGELOG'}


class Invalid(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Invalid(reason)


@dataclass(frozen=True)
class Limits:
    compressed_bytes: int
    total_compressed_bytes: int
    decoded_bytes: int
    members: int
    file_bytes: int
    window_bytes: int
    deadline: float

    def __post_init__(self):
        for name in ('compressed_bytes', 'total_compressed_bytes', 'decoded_bytes', 'members',
                     'file_bytes', 'window_bytes'):
            need(type(getattr(self, name)) is int and 0 < getattr(self, name) <= 2**63 - 1,
                 'positive finite integer limit required: ' + name)
        need(self.window_bytes >= 32768, 'decoder window budget below gzip minimum')
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline) and self.deadline > 0,
             'finite absolute monotonic deadline required')


def tick(limits):
    need(time.monotonic() < limits.deadline, 'archive deadline exhausted')


def relative(name):
    need(type(name) is str and name and '\0' not in name and not name.startswith('/')
         and '..' not in name.split('/') and PurePosixPath(name).as_posix() == name,
         'noncanonical payload path')
    return name


def resolve(rows, name, limits, seen=()):
    parts = []
    for part in name.split('/'):
        tick(limits)
        if part in ('', '.'):
            continue
        if part == '..':
            need(parts, 'escaping payload link')
            parts.pop()
            continue
        parts.append(part)
        current = '/'.join(parts)
        if rows.get(current, {}).get('type') == 'symlink':
            need(current not in seen and len(seen) < 40, 'cyclic payload link')
            target = rows[current]['target']
            need(not target.startswith('/'), 'absolute payload link')
            parts = resolve(rows, '/'.join(parts[:-1] + [target]), limits, (*seen, current)).split('/')
    return '/'.join(parts)


class Decoded:
    """At most one compressed input block and one bounded output read in memory."""
    def __init__(self, source, limits, decoded_before):
        self.source, self.limits, self.before = source, limits, decoded_before
        self.pending = source.read(CHUNK)
        self.total, self.done, self.drain = 0, False, False
        if self.pending.startswith(b'\x1f\x8b'):
            self.kind, self.decoder = 'gzip', zlib.decompressobj(31)
        elif self.pending.startswith(b'\xfd7zXZ\x00'):
            self.kind, self.decoder = 'xz', lzma.LZMADecompressor(memlimit=limits.window_bytes)
        else:
            need(self.pending.startswith(b'\x28\xb5\x2f\xfd'), 'only gzip/xz/zstd archives supported')
            need(zstd is not None, 'Python compression.zstd is unavailable')
            window = min(limits.window_bytes.bit_length() - 1,
                         zstd.DecompressionParameter.window_log_max.bounds()[1])
            self.kind = 'zstd'
            self.decoder = zstd.ZstdDecompressor(options={zstd.DecompressionParameter.window_log_max: window})

    def read(self, size):
        need(type(size) is int and 0 <= size <= CHUNK, 'bounded decoder read required')
        result = bytearray()
        while len(result) < size and not self.done:
            tick(self.limits)
            if self.decoder.eof:
                need(not self.decoder.unused_data and not self.source.read(1),
                     'trailing or concatenated compressed frame refused')
                self.done = True
                break
            if self.pending:
                data, self.pending = self.pending, b''
            elif self.kind == 'gzip' and self.drain or self.kind != 'gzip' and not self.decoder.needs_input:
                data = b''
            else:
                data = self.source.read(CHUNK)
                need(data, 'truncated compressed frame')
            maximum = min(size - len(result), self.limits.decoded_bytes - self.before - self.total + 1)
            if self.kind == 'gzip':
                output = self.decoder.decompress(data, maximum)
                self.pending = self.decoder.unconsumed_tail
                self.drain = len(output) == maximum
            else:
                output = self.decoder.decompress(data, max_length=maximum)
            self.total += len(output)
            need(self.before + self.total <= self.limits.decoded_bytes, 'aggregate decoded byte limit exceeded')
            result.extend(output)
            tick(self.limits)
        return bytes(result)


def archive_payload(path, limits, accounting=None):
    """Return installer-compatible nodes and update aggregate counters on success.

    accounting retains the tiny caller's bytes/nodes names (decoded tar bytes and
    raw tar headers), adding compressed_bytes. Failed inspection changes none.
    Caller must separately authenticate the archive and protect cross-package/root
    overlaps; no archive-derived value can increase these externally supplied caps.
    """
    need(isinstance(limits, Limits), 'explicit archive limits required')
    tick(limits)
    need(accounting is None or type(accounting) is dict
         and set(accounting) <= {'bytes', 'nodes', 'compressed_bytes'}, 'invalid aggregate accounting')
    counters = {key: (accounting or {}).get(key, 0) for key in ('bytes', 'nodes', 'compressed_bytes')}
    need(all(type(value) is int and value >= 0 for value in counters.values()), 'invalid aggregate counter')
    need(counters['bytes'] <= limits.decoded_bytes and counters['nodes'] <= limits.members
         and counters['compressed_bytes'] <= limits.total_compressed_bytes, 'aggregate accounting exceeds limits')
    rows, seen, headers, end_seen = {}, set(), 0, False

    class BoundedTarInfo(tarfile.TarInfo):
        # Bound extension bodies before tarfile materializes them, including
        # recursive PAX/GNU headers which are absent from normal member iteration.
        @classmethod
        def _fromtarfile(cls, archive, *, dircheck=True):
            nonlocal headers, end_seen
            tick(limits)
            raw = archive.fileobj.read(tarfile.BLOCKSIZE)
            if raw == b'\0' * tarfile.BLOCKSIZE:
                end_seen = True
            else:
                headers += 1
                need(counters['nodes'] + headers <= limits.members, 'aggregate member limit exceeded')
            item = cls._frombuf(raw, archive.encoding, archive.errors, dircheck=dircheck)
            item.offset = archive.fileobj.tell() - tarfile.BLOCKSIZE
            return item._proc_member(archive)

        def _proc_pax(self, archive):
            need(0 <= self.size <= min(CHUNK, limits.file_bytes), 'extended header byte limit exceeded')
            return super()._proc_pax(archive)

        def _proc_gnulong(self, archive):
            need(0 <= self.size <= min(CHUNK, limits.file_bytes), 'extended header byte limit exceeded')
            return super()._proc_gnulong(archive)

        def _proc_sparse(self, *args):
            raise Invalid('sparse archive member refused')

        _proc_gnusparse_00 = _proc_sparse
        _proc_gnusparse_01 = _proc_sparse
        _proc_gnusparse_10 = _proc_sparse

    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= limits.compressed_bytes, 'compressed archive size/type limit exceeded')
        need(counters['compressed_bytes'] + before.st_size <= limits.total_compressed_bytes,
             'aggregate compressed byte limit exceeded')
        decoded = Decoded(source, limits, counters['bytes'])
        try:
            with tarfile.open(fileobj=decoded, mode='r|', bufsize=CHUNK, tarinfo=BoundedTarInfo, stream=True) as archive:
                for member in archive:
                    tick(limits)
                    need(not member.sparse and not any(key.startswith('GNU.sparse') for key in member.pax_headers),
                         'sparse archive member refused')
                    name = relative(member.name.removeprefix('./').rstrip('/'))
                    need(name not in seen and member.uid == member.gid == 0, 'duplicate/nonroot archive member')
                    seen.add(name)
                    need(0 <= member.size <= limits.file_bytes, 'member file byte limit exceeded')
                    if name.startswith('.'):
                        need(name in CONTROLS and member.isfile(), 'unexpected control member')
                        continue
                    node = {'mode': member.mode & 0o7777, 'uid': 0, 'gid': 0}
                    if member.isdir():
                        node['type'] = 'directory'
                    elif member.isfile():
                        digest, size = hashlib.sha256(), 0
                        stream = archive.extractfile(member)
                        while block := stream.read(CHUNK):
                            tick(limits)
                            size += len(block)
                            need(size <= member.size, 'payload exceeds declared file size')
                            digest.update(block)
                        need(size == member.size, 'truncated member payload')
                        node.update(type='file', sha256=digest.hexdigest(), bytes=size)
                    elif member.issym():
                        need(not member.linkname.startswith('/') and '\0' not in member.linkname,
                             'absolute archive link refused')
                        node.update(type='symlink', target=member.linkname)
                    else:
                        raise Invalid('archive special/hardlink member refused')
                    need(name not in AUXILIARIES, 'unaudited auxiliary ldconfig refused')
                    rows[name] = node
                need(end_seen, 'missing complete tar end marker')
                tail = 0
                while block := archive.fileobj.read(CHUNK):
                    tick(limits)
                    need(not any(block), 'trailing or concatenated tar data refused')
                    tail += len(block)
                need(tail >= tarfile.BLOCKSIZE and decoded.total % tarfile.BLOCKSIZE == 0,
                     'incomplete tar zero padding')
        except DECODER_ERRORS as error:
            raise Invalid('invalid bounded compressed tar archive: ' + type(error).__name__) from error
        tick(limits)
        need(decoded.done and identity(os.fstat(source.fileno())) == identity(before)
             and identity(path.stat(follow_symlinks=False)) == identity(before), 'archive input changed during inspection')
    for name in rows:
        target = resolve(rows, name, limits)
        need(target not in AUXILIARIES, 'unaudited auxiliary ldconfig alias refused')
    if accounting is not None:
        accounting.update(bytes=counters['bytes'] + decoded.total, nodes=counters['nodes'] + headers,
                          compressed_bytes=counters['compressed_bytes'] + before.st_size)
    return rows
