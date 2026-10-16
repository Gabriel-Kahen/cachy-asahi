"""Accept only raw equality or one bounded, exact glibc load/save serialization.

No cache access or writes. The supported AArch64 tail padding is classified,
not compared as semantic data; every source-initialized byte remains checked.
The source/binary correspondence and actual helper exit remain unobserved.
"""
import hashlib
import struct

HELPER_SHA256 = '8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98'
SOURCE_REVISION = '8362e8ce10b24068bacc19552c128dd10e082fd9'
SOURCE_SHA256 = '4d8950977fbba59b0ccd479027811c6b82a31c3700d4478d04e8a4147c87bca8'
MAGIC = b'glibc-ld.so.auxcache-2.0'
LIMIT = 256 * 1024
MAX_ENTRIES = 4096
MAX_STRINGS = 128 * 1024
MAX_NAME = 4096
# The source selects from this table; this is not mathematical next-prime.
PRIMES = (1021, 2039, 4093, 8191)
ENTRY = struct.Struct('<QQQQiII')


class Refused(ValueError): pass


def need(ok, reason):
    if not ok: raise Refused('aux-order-' + reason)


def parse(data):
    """Only the observed little-endian header32/record48 layout is supported."""
    need(type(data) is bytes and 32 <= len(data) <= LIMIT, 'size')
    need(data[:24] == MAGIC, 'magic')
    count, string_size = struct.unpack_from('<II', data, 24)
    need(0 < count <= MAX_ENTRIES and 0 < string_size <= MAX_STRINGS, 'counts')
    start = 32 + count * 48
    need(start + string_size == len(data), 'layout')
    strings = data[start:]
    need(strings[0] == 0, 'initial-string')
    records, keys, cursor = [], set(), 1
    for number in range(count):
        fields = ENTRY.unpack_from(data, 32 + number * 48)
        key = fields[:4]
        flags, offset, isa = fields[4:]
        need(key not in keys, 'duplicate-key')
        keys.add(key)
        name = None
        if offset:
            need(offset == cursor < string_size, 'string-offset')
            end = strings.find(b'\0', cursor, min(string_size, cursor + MAX_NAME + 1))
            need(end >= cursor, 'string-termination')
            name = strings[cursor:end]
            cursor = end + 1
        records.append((key, (flags, name, isa)))
    need(cursor == string_size, 'string-coverage')
    return records


def bucket(key, size):
    ino, ctime, length, dev = key
    value = (((ino * 11 + ctime) * 11 + length) * 11 + dev) & ((1 << 64) - 1)
    return ((value ^ (value >> 32)) & ((1 << 32) - 1)) % size


def compare(before, after):
    """Check expected bytes in place; never reconstruct a cache output."""
    need(type(before) is bytes and type(after) is bytes
         and 0 < len(before) <= LIMIT and 0 < len(after) <= LIMIT, 'size')
    if before == after: return {'kind': 'RAW_EQUAL'}
    old, new = parse(before), parse(after)
    need(dict(old) == dict(new), 'named-map')
    need(before[:32] == after[:32], 'header')
    size = next(prime for prime in PRIMES if prime >= len(old))
    buckets = {}
    for row in old: buckets.setdefault(bucket(row[0], size), []).append(row)
    expected = [row for index in sorted(buckets) for row in reversed(buckets[index])]
    string_start, cursor = 32 + len(old) * 48, 1
    for number, (key, (flags, name, isa)) in enumerate(expected):
        position = 32 + number * 48
        offset = 0 if name is None else cursor
        need(after[position:position + 44] == ENTRY.pack(*key, flags, offset, isa), 'expected-record')
        if name is not None:
            chunk = name + b'\0'
            need(after[string_start + cursor:string_start + cursor + len(chunk)] == chunk, 'expected-string')
            cursor += len(chunk)
    need(string_start + cursor == len(after), 'expected-length')
    # cache.c assigns only44 named bytes; AArch64 rounds each record to48.
    # load_aux_cache consumes named fields/strings, never these padding contents.
    tails = [b''.join(data[32 + i * 48 + 44:32 + i * 48 + 48] for i in range(len(old)))
             for data in (before, after)]
    padding = {'classification': 'PINNED_SOURCE_AARCH64_TAIL_PADDING', 'bytes_per_record': 4,
               'slots_compared': len(old),
               'slots_changed': sum(tails[0][i:i + 4] != tails[1][i:i + 4] for i in range(0, len(tails[0]), 4)),
               'bytes_changed': sum(a != b for a, b in zip(*tails)),
               'before_sha256': hashlib.sha256(tails[0]).hexdigest(),
               'after_sha256': hashlib.sha256(tails[1]).hexdigest()}
    return {'kind': 'EXACT_LOAD_SAVE_ORDER', 'entries': len(old), 'hash_buckets': size,
            'source_sha256': SOURCE_SHA256, 'padding': padding}
