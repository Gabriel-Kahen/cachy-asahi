#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Flat owned regular-body spool. Package paths never become host paths."""
from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path
import re
import stat

CHUNK = 65536
FILE_CAP = 512*1024**2
TOTAL_CAP = 8*1024**3
IO_CAP = 4*TOTAL_CAP


def need(value, reason):
    if not value:
        raise ValueError(reason)


def priority(original, later):
    if original is None:
        return later
    if isinstance(original, Exception) and not isinstance(later, Exception):
        return later
    original.add_note('owned spool cleanup: '+type(later).__name__)
    return original


class Reader:
    def __init__(self, stream, store, expected):
        self.stream, self.store, self.expected = stream, store, expected
        self.bytes = 0
        self.digest = hashlib.sha256()

    def read(self, count):
        need(type(count) is int and 0 <= count <= CHUNK, 'spool-bounded-read')
        self.store.budget.check()
        self.store.charge('stream_read_bytes', count, reserve=True)
        raw = self.stream.read(count)
        need(type(raw) is bytes and len(raw) <= count, 'spool-read-result')
        self.bytes += len(raw)
        need(self.bytes <= self.expected['size'], 'spool-stream-size')
        self.digest.update(raw)
        self.store.charge('stream_read_bytes', len(raw))
        self.store.stats['max_read_request'] = max(self.store.stats['max_read_request'], count)
        self.store.budget.check()
        return raw


class Store:
    def __init__(self, root, core, budget):
        self.root, self.core, self.budget = Path(root), core, budget
        need(self.root.is_absolute() and '..' not in self.root.parts and
             re.fullmatch(r'[a-zA-Z0-9._-]{1,64}', self.root.name), 'spool-root-path')
        self.uid, self.gid = os.getuid(), os.getgid()
        self.parent_fd = self.fd = None
        self.root_info = None
        self.refs = {}
        self.next_name = 0
        self.cleanup_errors = []
        self.stats = dict(written_bytes=0, hash_read_bytes=0, stream_read_bytes=0,
                          max_read_request=0, max_write_chunk=0)

    def charge(self, field, count, reserve=False):
        need(type(count) is int and count >= 0, 'spool-counter')
        total = sum(self.stats[key] for key in ('written_bytes', 'hash_read_bytes', 'stream_read_bytes'))
        need(total + count <= IO_CAP, 'spool-total-io-cap')
        if field == 'written_bytes':
            need(self.stats[field] + count <= TOTAL_CAP, 'spool-storage-cap')
        if not reserve:
            self.stats[field] += count
        self.budget.check()

    def root_check(self, cleanup=False):
        if not cleanup:
            self.budget.check()
        named = os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False)
        held = os.fstat(self.fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        need(all(getattr(named, key) == getattr(held, key) == getattr(self.root_info, key)
                 for key in fields), 'spool-root-drift')
        need(stat.S_ISDIR(held.st_mode) and stat.S_IMODE(held.st_mode) == 0o700 and
             held.st_uid == self.uid and held.st_gid == self.gid and held.st_nlink >= 1,
             'spool-root-ownership')

    def __enter__(self):
        # Reuse the no-follow ancestor reader before mutation; its full directory
        # timestamps cannot be held invariant while creating our own children.
        try:
            with self.core.opened(self.root.parent, self.budget, directory=True) as (parent, _):
                self.parent_fd = os.dup(parent)
            os.mkdir(self.root.name, 0o700, dir_fd=self.parent_fd)
            self.root_info = os.stat(self.root.name, dir_fd=self.parent_fd, follow_symlinks=False)
            self.fd = os.open(self.root.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                              dir_fd=self.parent_fd)
            self.root_check()
            return self
        except BaseException:
            self.core.close_owned((self.fd, self.parent_fd))
            self.fd = self.parent_fd = None
            raise

    def body_check(self, info):
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == self.uid and info.st_gid == self.gid,
             'spool-body-ownership')

    def reference_check(self, ref, cleanup=False):
        need(type(ref) is dict and set(ref) == {'name', 'size', 'sha256', 'identity'} and
             type(ref['name']) is str and re.fullmatch(r'body-[0-9]{8}', ref['name']) and
             self.refs.get(ref['name']) == ref, 'closed-spool-reference')
        need(type(ref['size']) is int and 0 <= ref['size'] <= FILE_CAP and
             type(ref['sha256']) is str and self.core.HEX.fullmatch(ref['sha256']), 'spool-reference-values')
        need(type(ref['identity']) is list and len(ref['identity']) == len(self.core.FIELDS) and
             all(self.core.integer(value, 2**64-1) for value in ref['identity']), 'spool-reference-identity')
        self.root_check(cleanup=cleanup)
        info = os.stat(ref['name'], dir_fd=self.fd, follow_symlinks=False)
        self.body_check(info)
        need(self.core.identity(info) == ref['identity'], 'spool-body-drift')

    def put(self, stream, expected_bytes):
        need(type(expected_bytes) is int and 0 <= expected_bytes <= FILE_CAP, 'spool-file-cap')
        self.charge('written_bytes', expected_bytes, reserve=True)
        self.root_check()
        self.next_name += 1
        need(self.next_name <= 500000, 'spool-node-cap')
        name = 'body-' + str(self.next_name).zfill(8)
        fd = os.open(name, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        accepted = False
        before = None
        try:
            before = os.fstat(fd)
            self.body_check(before)
            need(self.core.identity(before) == self.core.identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)),
                 'spool-created-binding')
            accepted = True
            digest, size = hashlib.sha256(), 0
            while True:
                self.budget.check()
                count = min(CHUNK, expected_bytes-size+1)
                raw = stream.read(count)
                need(type(raw) is bytes and len(raw) <= count, 'spool-input-chunk')
                if not raw:
                    break
                need(size + len(raw) <= expected_bytes, 'spool-input-overrun')
                self.charge('written_bytes', len(raw), reserve=True)
                view = memoryview(raw)
                while view:
                    self.budget.check()
                    written = os.write(fd, view)
                    need(type(written) is int and 0 < written <= len(view), 'spool-write-result')
                    self.charge('written_bytes', written)
                    view = view[written:]
                size += len(raw)
                digest.update(raw)
                self.stats['max_write_chunk'] = max(self.stats['max_write_chunk'], len(raw))
            need(size == expected_bytes, 'spool-input-truncated')
            info = os.fstat(fd)
            self.body_check(info)
            need(self.core.identity(info) == self.core.identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)),
                 'spool-written-binding')
            ref = dict(name=name, size=size, sha256=digest.hexdigest(), identity=self.core.identity(info))
            self.refs[name] = copy.deepcopy(ref)
            return ref
        except BaseException as original:
            failure = original
            if accepted:
                try:
                    now = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    held = os.fstat(fd)
                    if (now.st_dev, now.st_ino) == (held.st_dev, held.st_ino) == (before.st_dev, before.st_ino):
                        os.unlink(name, dir_fd=self.fd)
                except BaseException as error:
                    self.cleanup_errors.append(type(error).__name__)
                    failure = priority(failure, error)
            if failure is not original:
                raise failure from original
            raise
        finally:
            self.core.close_owned((fd,))

    @contextmanager
    def lookup(self, ref):
        self.reference_check(ref)
        with self.core.readable_at(self.fd, ref['name'], self.budget, ref['identity']) as (fd, _):
            # Verification and subsequent serialization are separate charged passes.
            digest, count = hashlib.sha256(), 0
            while True:
                self.charge('hash_read_bytes', CHUNK, reserve=True)
                raw = os.read(fd, min(CHUNK, ref['size']-count+1))
                if not raw:
                    break
                count += len(raw)
                need(count <= ref['size'], 'spool-verify-overrun')
                self.charge('hash_read_bytes', len(raw))
                digest.update(raw)
            need(count == ref['size'] and digest.hexdigest() == ref['sha256'], 'spool-content-digest')
            os.lseek(fd, 0, os.SEEK_SET)
            with os.fdopen(os.dup(fd), 'rb') as stream:
                reader = Reader(stream, self, ref)
                yield reader
                need(reader.bytes == ref['size'] and reader.digest.hexdigest() == ref['sha256'], 'spool-consumed-content')
            self.reference_check(ref)

    def discard(self, ref):
        self.reference_check(ref, cleanup=True)
        os.unlink(ref['name'], dir_fd=self.fd)
        del self.refs[ref['name']]

    def __exit__(self, kind, original, traceback):
        failure = original
        try:
            for ref in list(self.refs.values()):
                try:
                    self.discard(ref)
                except BaseException as error:
                    self.cleanup_errors.append(type(error).__name__)
                    failure = priority(failure, error)
            try:
                self.root_check(cleanup=True)
                os.rmdir(self.root.name, dir_fd=self.parent_fd)
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__)
                failure = priority(failure, error)
        finally:
            try:
                self.core.close_owned((self.fd, self.parent_fd))
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__)
                failure = priority(failure, error)
            self.fd = self.parent_fd = None
        if failure is not None and failure is not original:
            raise failure from original
        return False
