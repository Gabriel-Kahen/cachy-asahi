# SPDX-License-Identifier: MIT
"""Finite primary-layout adversarial DATA; never an actual Root observation."""
import struct

MAGIC = b'glibc-ld.so.auxcache-2.0'


def model(entries, *, padding=b'\0' * 4, string_order=None):
    names = [i for i, entry in enumerate(entries) if entry.get('name') is not None]
    order = names if string_order is None else string_order
    strings = bytearray(b'\0'); offsets = {}
    for i in order:
        offsets[i] = len(strings); strings.extend(entries[i]['name'] + b'\0')
    rows = [struct.pack('<QQQQiII4s', e['inode'], e.get('ctime', 1700000000), e.get('size', 65536),
                        e.get('device', 254), e.get('flags', 0xa03), offsets.get(i, 0), e.get('isa', 0), padding)
            for i, e in enumerate(entries)]
    return struct.pack('<24sII', MAGIC, len(rows), len(strings)) + b''.join(rows) + strings


def unsigned_entries():
    values = [0, 1, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 63) - 1, 1 << 63,
              (1 << 63) + 1, 0x9999999999999998, 0x9999999999999999, (1 << 64) - 1]
    rows = [dict(inode=value, ctime=(1 << 64) - 1 - i, size=(1 << 53) + i,
                 device=(1 << 63) + i, isa=1023, name=b'libU.so.' + str(i).encode())
            for i, value in enumerate(values)]
    rows += [dict(inode=7, ctime=c, size=s, device=d, name=b'tie-' + str(i).encode())
             for i, (c, s, d) in enumerate(((0, 0, 0), (0, 0, (1 << 64) - 1),
                                           (0, (1 << 64) - 1, 0), ((1 << 64) - 1, 0, 0)))]
    return rows


def named_entries():
    return [dict(inode=1, name=None), dict(inode=2, name=b''), dict(inode=3, name=b'libX.so.09'),
            dict(inode=4, name=b'libX.so.9'), dict(inode=5, name=b'\xff\x80\x01lib/\n\tfull.so.01')]


def mutation(blob, offset, fmt, value):
    result = bytearray(blob); struct.pack_into(fmt, result, offset, value); return bytes(result)


def refusals(cap):
    good = model([dict(inode=1, name=b'libA.so.1'), dict(inode=2, name=b'libB.so.2')])
    yield 'empty-input', b''
    yield 'short-header', good[:31]
    yield 'wrong-version', struct.pack('<24s', b'glibc-ld.so.auxcache-1.0') + good[24:]
    yield 'count-over-cap', mutation(good, 24, '<I', 4097)
    yield 'zero-string-extent', mutation(good, 28, '<I', 0)
    yield 'huge-string-extent', mutation(good, 28, '<I', 0xffffffff)
    yield 'truncated', good[:-1]
    yield 'trailing', good + b'\0'
    yield 'byte-cap', b'x' * (cap + 1)
    yield 'big-endian-header', struct.pack('>24sII', MAGIC, 2, len(good) - 128) + good[32:]
    yield 'wrong-flags', mutation(good, 64, '<i', 0x303)
    yield 'negative-flags', mutation(good, 64, '<i', -1)
    yield 'unsupported-isa', mutation(good, 72, '<I', 1024)
    yield 'duplicate-identity', model([dict(inode=1, name=b'a'), dict(inode=1, name=b'b')])
    yield 'interior-name', mutation(good, 68, '<I', 2)
    yield 'outside-name', mutation(good, 68, '<I', 0xffffffff)
    yield 'reused-name', mutation(good, 116, '<I', 1)
    yield 'unreferenced-name', mutation(good, 68, '<I', 0)
    yield 'missing-nul', good[:-1] + b'x'
    yield 'name-over-cap', model([dict(inode=1, name=b'x' * 4097)])
