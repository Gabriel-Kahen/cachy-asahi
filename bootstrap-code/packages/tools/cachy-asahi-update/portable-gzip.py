#!/usr/bin/env python3
"""Canonical gzip encoding using RFC 1951 stored blocks, never a compressor.

Writes use a zero-time RFC 1952 header (XFL=0, OS=255), 65535-byte blocks,
CRC32 and ISIZE. Flush never changes block boundaries. Output is deliberately
uncompressed. Import before temporarily replacing gzip.GzipFile; read modes
delegate to the original captured stdlib class without recursive patching.
"""
import binascii
import gzip
import io
import struct

ORIGINAL_GZIP_FILE = gzip.GzipFile
BLOCK_SIZE = 65535
MAX_INPUT_BYTES = 512 * 1024**2
HEADER = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff'


class StoredGzipWriter(io.BufferedIOBase):
    def __init__(self, fileobj, *, owns_file=False, max_bytes=MAX_INPUT_BYTES):
        self._failed, self._closing, self._owns_file = True, False, False
        if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_INPUT_BYTES:
            raise ValueError('bounded gzip input limit required')
        self._output, self._owns_file, self._limit = fileobj, owns_file, max_bytes
        self._buffer = bytearray()
        self._size = self._crc = 0
        self._failed = self._closing = False
        try:
            self._emit(HEADER)
        except BaseException:
            self._failed = True
            self.close()
            raise

    def _check(self):
        if self.closed:
            raise ValueError('I/O operation on closed gzip writer')
        if self._failed:
            raise OSError('gzip writer failed; partial output must be discarded')

    def _emit(self, data):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = self._output.write(view[offset:])
            if type(written) is not int or not 0 < written <= len(view) - offset:
                raise OSError('invalid/blocked underlying gzip write')
            offset += written

    def _block(self, final):
        size = len(self._buffer)
        self._emit(struct.pack('<BHH', int(final), size, size ^ 0xffff))
        self._emit(self._buffer)
        self._buffer.clear()

    def write(self, data):
        self._check()
        view = memoryview(data).cast('B')
        size = len(view)
        if self._size + size > self._limit:
            self._failed = True
            raise ValueError('gzip input byte limit exceeded; discard partial output')
        try:
            offset = 0
            while offset < size:
                # Hold a full block until another input byte proves it non-final.
                if len(self._buffer) == BLOCK_SIZE:
                    self._block(False)
                take = min(size - offset, BLOCK_SIZE - len(self._buffer))
                self._buffer.extend(view[offset:offset + take])
                offset += take
            self._crc = binascii.crc32(view, self._crc) & 0xffffffff
            self._size += size
        except BaseException:
            self._failed = True
            raise
        return size

    def flush(self):
        if self.closed:
            self._check()
        if self._closing:
            return
        self._check()
        try:
            self._output.flush()
        except BaseException:
            self._failed = True
            raise

    def tell(self):
        self._check()
        return self._size

    def writable(self):
        self._check()
        return True

    def readable(self):
        self._check()
        return False

    def seekable(self):
        self._check()
        return False

    def close(self):
        if self.closed:
            return
        self._closing = True
        try:
            if not self._failed:
                try:
                    self._block(True)
                    self._emit(struct.pack('<II', self._crc, self._size & 0xffffffff))
                    self._output.flush()
                except BaseException:
                    self._failed = True
                    raise
        finally:
            try:
                super().close()
            finally:
                if self._owns_file:
                    self._output.close()


def GzipFile(filename=None, mode=None, compresslevel=9, fileobj=None, mtime=None,
             *, max_bytes=MAX_INPUT_BYTES):
    """Factory for the generators' binary gzip API; reading uses stdlib gzip."""
    mode = mode or getattr(fileobj, 'mode', 'rb')
    if mode in ('r', 'rb'):
        return ORIGINAL_GZIP_FILE(filename=filename, mode=mode, compresslevel=compresslevel,
                                  fileobj=fileobj, mtime=mtime)
    if mode not in ('w', 'wb'):
        raise ValueError('portable gzip supports binary read/write; no append/text mode')
    if mtime not in (None, 0) or type(compresslevel) is not int or not 0 <= compresslevel <= 9:
        raise ValueError('portable gzip requires zero mtime and compression level 0..9')
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_INPUT_BYTES:
        raise ValueError('bounded gzip input limit required')
    owns_file = fileobj is None
    if owns_file:
        if not filename:
            raise ValueError('gzip output file object or filename required')
        fileobj = open(filename, 'wb')
    return StoredGzipWriter(fileobj, owns_file=owns_file, max_bytes=max_bytes)
