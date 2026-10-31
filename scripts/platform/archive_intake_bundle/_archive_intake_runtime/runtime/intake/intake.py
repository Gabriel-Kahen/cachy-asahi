#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixture-only inert XZ/tar package intake. Actual CLI admission remains closed."""
import hashlib
from contextlib import contextmanager
import json
import lzma
import os
import re
import stat
import sys
import tarfile
import zlib

PRIMARY = '68B3537F39A313B3E574D06777193F152BDBE6A6'
SCOPE = 'MODELED_NOT_CRYPTOGRAPHIC'
CHUNK, CONTROL_LIMIT, MTREE_LIMIT = 65536, 1048576, 16 * 1048576
CONTROLS = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL'}
META = {'name', 'version', 'arch', 'depends', 'provides', 'conflicts', 'replaces', 'license'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _priority(primary, later):
    if primary is None or (isinstance(primary, Exception) and not isinstance(later, Exception)):
        return later
    return primary


@contextmanager
def _archive_source(core, fd, budget):
    owned = source = None
    try:
        budget.check()
        owned = os.dup(fd)
        # Keep explicit FD ownership through stream construction and closure.
        source = os.fdopen(owned, 'rb', closefd=False)
        yield source
    finally:
        original = primary = sys.exc_info()[1]
        for cleanup in ((lambda: source.close()) if source is not None else (lambda: None),
                        lambda: core.close_owned((owned,))):
            try:
                cleanup()
            except BaseException as later:
                primary = _priority(primary, later)
                primary.add_note('archive-stream-cleanup-failure: ' + type(later).__name__)
        if primary is not original:
            raise primary from original


def normalized_metadata(core, value):
    core.need(type(value) is dict and set(value) == META, 'signed-metadata-schema')
    core.package_identity({k: value[k] for k in ('name', 'version', 'arch')})
    result = {k: value[k] for k in ('name', 'version', 'arch')}
    for key in sorted(META - set(result)):
        values = value[key]
        core.need(type(values) is list and len(values) <= 10000 and all(
            type(v) is str and 0 < len(v) <= 4096 and not re.search(r'[\x00-\x1f\x7f]', v)
            for v in values), 'signed-metadata-values')
        result[key] = sorted(values)  # Preserve multiplicity; never silently deduplicate.
    return result


def _bindings(core, row, budget):
    core.need(type(row) is dict and set(row) == {
        'identity', 'archive', 'signature', 'authentication', 'source_admission'}, 'intake-row')
    core.package_identity(row['identity'])
    for key, limit in [('archive', core.ARCHIVE), ('signature', CHUNK),
                       ('authentication', CONTROL_LIMIT), ('source_admission', CONTROL_LIMIT)]:
        core.reference(row[key], limit)
    # Caller pins all four references independently. JSON assertions are not crypto.
    admission = core.decode(core.read_reference(row['source_admission'], CONTROL_LIMIT, budget))
    auth = core.decode(core.read_reference(row['authentication'], CONTROL_LIMIT, budget))
    source_keys = {'schema_version', 'scope', 'identity', 'archive_sha256', 'signature_sha256',
                   'expected_primary', 'signed_metadata', 'signed_metadata_sha256'}
    auth_keys = source_keys - {'signed_metadata'} | {'source_admission_sha256'}
    core.need(type(admission) is dict and set(admission) == source_keys and
              type(auth) is dict and set(auth) == auth_keys, 'intake-admission-schema')
    for document in (admission, auth):
        core.need(type(document['schema_version']) is int and document['schema_version'] == 1
                  and document['scope'] == SCOPE and document['identity'] == row['identity']
                  and document['expected_primary'] == PRIMARY
                  and document['archive_sha256'] == row['archive']['sha256']
                  and document['signature_sha256'] == row['signature']['sha256'],
                  'intake-model-binding')
    metadata = normalized_metadata(core, admission['signed_metadata'])
    core.need({k: metadata[k] for k in ('name', 'version', 'arch')} == row['identity']
              and admission['signed_metadata_sha256'] == digest(metadata)
              and auth['signed_metadata_sha256'] == digest(metadata)
              and auth['source_admission_sha256'] == row['source_admission']['sha256'],
              'intake-metadata-binding')
    core.read_reference(row['signature'], CHUNK, budget)
    return metadata


class _Inflated:
    """One explicit compressed stream, bounded output quanta, no ignored remainder."""
    def __init__(self, core, source, size, budget, kind):
        self.core, self.source, self.size, self.budget = core, source, size, budget
        self.codec = (lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * core.MIB)
                      if kind == 'xz' else zlib.decompressobj(31))
        self.kind, self.count, self.pending, self.finished = kind, 0, b'', False

    def read(self, n):
        c = self.core
        c.need(c.integer(n, c.MIB), 'inflate-read-bound')
        if not n or self.finished:
            return b''
        while True:
            self.budget.check()
            if self.kind == 'xz':
                incoming = self.source.read(CHUNK) if self.codec.needs_input else b''
            else:
                incoming = self.pending or self.source.read(CHUNK)
                self.pending = b''
            if incoming:
                # zlib unconsumed_tail was already charged on its initial read.
                if self.kind == 'xz' or not getattr(self, '_from_pending', False):
                    self.count += len(incoming)
                    c.need(self.count <= self.size, 'compressed-size')
            elif (self.kind == 'gzip' or self.codec.needs_input) and not self.codec.eof:
                raise EOFError('compressed-truncated')
            out = self.codec.decompress(incoming, max_length=n)
            self.budget.check()
            if self.kind == 'gzip':
                self.pending = self.codec.unconsumed_tail
                self._from_pending = bool(self.pending)
            if self.codec.eof:
                c.need(not self.codec.unused_data and not self.pending, 'compressed-remainder')
                self.budget.check()
                c.need(not self.source.read(1) and self.count == self.size, 'compressed-remainder')
                self.budget.check()
                self.finished = True
            if out or self.finished:
                return out


def _exact(core, stream, size, budget):
    core.need(core.integer(size, core.MIB), 'read-quantum')
    result = bytearray()
    while len(result) < size:
        budget.check()
        data = stream.read(size - len(result))
        core.need(type(data) is bytes and len(data) <= size - len(result), 'stream-framing')
        if not data:
            raise EOFError('tar-truncated')
        result.extend(data)
    return bytes(result)


class _Body:
    def __init__(self, core, stream, size, budget):
        self.core, self.stream, self.remaining, self.budget = core, stream, size, budget
        self.hash = hashlib.sha256()

    def read(self, n):
        self.core.need(self.core.integer(n, CHUNK), 'body-read-bound')
        if not n or not self.remaining:
            return b''
        data = _exact(self.core, self.stream, min(n, self.remaining), self.budget)
        self.remaining -= len(data)
        self.hash.update(data)
        return data


def _spool_ref(core, ref, maximum):
    core.need(type(ref) is dict and set(ref) == {'name', 'size', 'sha256', 'identity'}
              and type(ref['name']) is str and re.fullmatch(r'body-[0-9]{8}', ref['name'])
              and core.integer(ref['size'], maximum) and type(ref['sha256']) is str
              and core.HEX.fullmatch(ref['sha256']) and type(ref['identity']) is list
              and len(ref['identity']) == len(core.FIELDS)
              and all(core.integer(v, 2**64-1) for v in ref['identity'])
              and ref['identity'][6] == ref['size'] and stat.S_ISREG(ref['identity'][2])
              and ref['identity'][3] == 1, 'spool-reference')


def _spooled(core, store, ref, maximum, budget):
    _spool_ref(core, ref, maximum)
    data = bytearray()
    with store.lookup(ref) as stream:
        while True:
            budget.check()
            part = stream.read(min(CHUNK, maximum - len(data) + 1))
            core.need(type(part) is bytes, 'spool-bytes')
            if not part:
                break
            data.extend(part)
            core.need(len(data) <= ref['size'] and len(data) <= maximum, 'spool-byte-bound')
    core.need(len(data) == ref['size'] and hashlib.sha256(data).hexdigest() == ref['sha256'],
              'spool-digest')
    return bytes(data)


def _fields(core, raw, budget, scalars=()):
    text = raw.decode('utf-8', 'strict')
    core.need(not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text), 'control-text')
    fields = {}
    lines = text.splitlines()
    core.need(len(lines) <= 10000, 'control-lines')
    for line in lines:
        budget.check()
        if not line or line.startswith('#'):
            continue
        core.need(' = ' in line, 'control-field')
        key, value = line.split(' = ', 1)
        core.need(re.fullmatch(r'[a-z][a-z0-9_]*', key) and 0 < len(value) <= 4096
                  and not re.search(r'[\x00-\x1f\x7f]', value), 'control-field')
        core.need(key not in scalars or key not in fields, 'duplicate-control-scalar')
        fields.setdefault(key, []).append(value)
    return fields


def _mtree(core, store, ref, budget):
    # Raw gzip bytes remain in the store; internal decode is bounded and charged.
    raw = _spooled(core, store, ref, CONTROL_LIMIT, budget)
    import io
    stream = _Inflated(core, io.BytesIO(raw), len(raw), budget, 'gzip')
    data = bytearray()
    while True:
        budget.check()
        part = stream.read(CHUNK)
        if not part:
            break
        data.extend(part)
        budget.decoded += len(part)
        core.need(len(data) <= MTREE_LIMIT and budget.decoded + budget.tree_bytes <= core.TOTAL_DECODED,
                  'mtree-decoded-bound')
    text = data.decode('utf-8', 'strict')
    core.need(text.startswith('#mtree\n') and not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text),
              'mtree-text')
    lines = text.splitlines()
    core.need(len(lines) <= core.ARCHIVE_NODES + 8 and all(len(x) <= 8192 for x in lines),
              'mtree-lines')
    # Retain finite token data, do not pretend it closes xattrs or file correspondence.
    rows = []
    for line in lines:
        budget.check()
        if not line or line.startswith('#'):
            continue
        core.need(not line.endswith('\\'), 'mtree-continuation-unsupported')
        rows.append(line.split())
    return {'status': 'PARSED-INERT-TOKENS-CORRESPONDENCE-UNACCEPTED', 'rows': rows,
            'decoded_bytes': len(data), 'xattrs_accepted': False, 'payload_correspondence_accepted': False}


def inspect_archive(core, row, store, budget):
    """Return a closed prepared package for one modeled, pinned inert archive."""
    core.need(type(row) is dict and set(row) == {
        'identity', 'archive', 'signature', 'authentication', 'source_admission'}, 'intake-row')
    core.package_identity(row['identity'])
    for key, limit in [('archive', core.ARCHIVE), ('signature', CHUNK),
                       ('authentication', CONTROL_LIMIT), ('source_admission', CONTROL_LIMIT)]:
        core.reference(row[key], limit)
    # Freeze already validated primitive values; never retain caller-owned dictionaries.
    row = {'identity': dict(row['identity']), **{
        key: {field: list(value) if field == 'identity' else value for field, value in row[key].items()}
        for key in ('archive', 'signature', 'authentication', 'source_admission')}}
    expected = _bindings(core, row, budget)
    previous = getattr(budget, 'intake_compressed', 0)
    core.need(core.integer(previous, core.COMPRESSED), 'compressed-ledger')
    # Reserve the actual two hash reads and one compressed decode read.
    budget.intake_compressed = previous + 3 * row['archive']['size']
    core.need(budget.intake_compressed <= core.COMPRESSED, 'compressed-bound')
    nodes, bodies, metadata, created, seen = {}, {}, {}, [], set()
    members = 0
    try:
        ref = row['archive']
        with core.opened(ref['path'], budget, ref['identity']) as (fd, before):
            core.need(core.hashed(fd, ref['size'], budget) == ref['sha256'], 'archive-digest')
            os.lseek(fd, 0, os.SEEK_SET)
            with _archive_source(core, fd, budget) as source:
                counted = core.Counted(_Inflated(core, source, ref['size'], budget, 'xz'), budget)
                while True:
                    block = _exact(core, counted, 512, budget)
                    if block == bytes(512):
                        core.need(_exact(core, counted, 512, budget) == bytes(512), 'tar-end-blocks')
                        while True:
                            tail = counted.read(CHUNK)
                            if not tail:
                                break
                            core.need(not any(tail), 'tar-remainder')
                        core.need(counted.count % 512 == 0, 'tar-remainder-alignment')
                        break
                    budget.node()
                    members += 1
                    core.need(members <= core.ARCHIVE_NODES, 'archive-node-bound')
                    member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
                    # No tar extension header is consumed implicitly or hidden from node accounting.
                    core.need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                                              tarfile.SYMTYPE, tarfile.LNKTYPE)
                              and member.sparse is None and not member.pax_headers,
                              'archive-extension-or-type-unsupported')
                    name = core.path(member.name.removeprefix('./').removesuffix('/'))
                    core.need(name not in seen, 'duplicate-normalized-member')
                    seen.add(name)
                    core.need(core.integer(member.uid, 2**32-1) and core.integer(member.gid, 2**32-1)
                              and core.integer(member.mode, 0o7777)
                              and core.integer(member.size, core.FILE), 'archive-member')
                    kind = ('file' if member.isfile() else 'directory' if member.isdir()
                            else 'symlink' if member.issym() else 'hardlink')
                    node = dict(type=kind, mode=member.mode, uid=member.uid, gid=member.gid)
                    if name in CONTROLS:
                        core.need(kind == 'file' and member.size <= CONTROL_LIMIT, 'control-member')
                    if kind == 'file':
                        body = _Body(core, counted, member.size, budget)
                        closed = store.put(body, member.size)
                        created.append(closed)
                        _spool_ref(core, closed, core.FILE)
                        core.need(body.remaining == 0 and closed['size'] == member.size
                                  and closed['sha256'] == body.hash.hexdigest(), 'spool-put-binding')
                        core.need(sum(x['name'] == closed['name'] for x in created) == 1,
                                  'duplicate-spool-reference')
                        node.update(bytes=member.size, sha256=body.hash.hexdigest())
                        core.need(not any(_exact(core, counted, (-member.size) % 512, budget)), 'tar-padding')
                        if name in CONTROLS:
                            metadata[name] = {'ref': closed, 'parsed': None}
                        else:
                            bodies[name] = closed
                    elif kind in ('symlink', 'hardlink'):
                        core.need(member.size == 0, 'link-body')
                        node['target'] = (core.path(member.linkname.removeprefix('./').removesuffix('/'))
                                          if kind == 'hardlink' else member.linkname)
                    else:
                        core.need(member.size == 0, 'directory-body')
                    core.node_shape(node)
                    if name not in CONTROLS:
                        nodes[name] = node
            core.need(core.identity(before) == core.identity(os.fstat(fd)), 'archive-drift')
            os.lseek(fd, 0, os.SEEK_SET)
            core.need(core.hashed(fd, ref['size'], budget) == ref['sha256'], 'archive-final-digest')
        core.need('.PKGINFO' in metadata, 'pkginfo-missing')
        raw = _spooled(core, store, metadata['.PKGINFO']['ref'], CONTROL_LIMIT, budget)
        fields = _fields(core, raw, budget, ('pkgname', 'pkgver', 'arch', 'pkgbase', 'pkgdesc',
                                           'url', 'builddate', 'packager', 'size'))
        core.need(all(fields.get(k) == [row['identity'][v]] for k, v in
                      [('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch')]), 'archive-tuple')
        actual = dict(row['identity'])
        for key, rawkey in [('depends', 'depend'), ('provides', 'provides'), ('conflicts', 'conflict'),
                            ('replaces', 'replaces'), ('license', 'license')]:
            actual[key] = fields.get(rawkey, [])
        core.need(normalized_metadata(core, actual) == expected, 'archive-signed-metadata')
        metadata['.PKGINFO']['parsed'] = {'status': 'MODELED-METADATA-BOUND-NOT-CRYPTO', 'fields': fields}
        if '.BUILDINFO' in metadata:
            raw = _spooled(core, store, metadata['.BUILDINFO']['ref'], CONTROL_LIMIT, budget)
            metadata['.BUILDINFO']['parsed'] = {'status': 'PARSED-INERT-SOURCE-CORRESPONDENCE-UNACCEPTED',
                'fields': _fields(core, raw, budget, ('format', 'pkgbase', 'pkgver', 'pkgarch',
                                                    'pkgbuild_sha256sum', 'packager', 'builddate', 'builddir'))}
        before_mtree = budget.decoded
        if '.MTREE' in metadata:
            metadata['.MTREE']['parsed'] = _mtree(core, store, metadata['.MTREE']['ref'], budget)
        core.need(counted.count + budget.decoded - before_mtree <= core.DECODED, 'archive-decoded-bound')
        if '.INSTALL' in metadata:
            _spooled(core, store, metadata['.INSTALL']['ref'], CONTROL_LIMIT, budget)
            metadata['.INSTALL']['parsed'] = {'status': 'RETAINED-INERT-HOOK-UNCLOSED',
                                              'executed': False, 'hook_closure_accepted': False}
        for name, node in nodes.items():
            budget.check()
            if node['type'] == 'hardlink':
                target, chain = node['target'], {name}
                while target in nodes and nodes[target]['type'] == 'hardlink':
                    budget.check()
                    core.need(target not in chain, 'hardlink-cycle')
                    chain.add(target)
                    target = nodes[target]['target']
                core.need(target in nodes and nodes[target]['type'] == 'file', 'hardlink-same-package-file')
                node['target'] = target
        for key in ('archive', 'signature', 'authentication', 'source_admission'):
            if key == 'archive':
                with core.opened(row[key]['path'], budget, row[key]['identity']):
                    pass
            else:
                core.read_reference(row[key], row[key]['size'], budget)
        budget.check()
        result = {'identity': dict(row['identity']), 'archive_sha256': row['archive']['sha256'],
                  'source_sha256': row['source_admission']['sha256'], 'nodes': nodes, 'bodies': bodies,
                  'metadata': metadata, 'intake': {'scope': SCOPE, 'status': 'PASS-INERT-MODELED-INTAKE',
                    'archive_format': 'single-XZ/512-byte-tar-no-extension-headers',
                    'signature_sha256': row['signature']['sha256'],
                    'authentication_sha256': row['authentication']['sha256'],
                    'source_admission_sha256': row['source_admission']['sha256'],
                    'decoded_bytes': counted.count + budget.decoded - before_mtree, 'members': members,
                    'missing_controls': sorted(CONTROLS - set(metadata)), 'tar_pax_xattrs_policy': 'REJECTED',
                    'hardlink_policy': 'same-package-regular-root-canonicalized',
                    'mtree_semantics_accepted': False, 'complete261_compatibility_accepted': False,
                    'signature_verified_by_intake': False, 'source_custody_accepted': False,
                    'hook_closure_accepted': False, 'installation_accepted': False,
                    'hardware_accepted': False, 'system_mutation': False}}
        core.need(len(json.dumps(result, allow_nan=False).encode()) <= core.REPORT, 'intake-report-bound')
        return result
    except BaseException as failure:
        primary = failure
        for ref in reversed(created):
            try:
                store.discard(ref)
            except BaseException as cleanup:
                primary = _priority(primary, cleanup)
                primary.add_note('spool-discard-failure: ' + type(cleanup).__name__)
        if primary is not failure:
            raise primary from failure
        raise


def main():
    print(json.dumps({'status': 'REFUSED', 'reason': 'actual-archive-CLI-not-admitted',
                      'archive_read': False, 'signature_verified': False, 'installation_accepted': False}))
    return 20


if __name__ == '__main__':
    raise SystemExit(main())
