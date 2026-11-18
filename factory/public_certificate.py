# SPDX-License-Identifier: MIT
"""Bounded PUBLIC certificate structure only. GPG must independently verify math."""
import base64
import hashlib
import re

CAP = 65536

def need(ok, why):
    if not ok:
        raise ValueError(why)

def length(raw, at):
    need(at < len(raw), 'truncated packet length')
    first = raw[at]; at += 1
    if first < 192:
        return first, at
    if first < 224:
        need(at < len(raw), 'truncated two-byte length')
        return ((first - 192) << 8) + raw[at] + 192, at + 1
    need(first == 255 and at + 4 <= len(raw), 'partial/indeterminate length refused')
    return int.from_bytes(raw[at:at+4], 'big'), at + 4

def packets(raw):
    at = 0; rows = []
    while at < len(raw):
        header = raw[at]; at += 1
        need(header & 128, 'invalid packet header')
        if header & 64:
            tag = header & 63; size, at = length(raw, at)
        else:
            tag, kind = (header >> 2) & 15, header & 3
            need(kind != 3, 'indeterminate old packet refused')
            count = (1, 2, 4)[kind]
            need(at + count <= len(raw), 'truncated old length')
            size = int.from_bytes(raw[at:at+count], 'big'); at += count
        need(0 < size <= CAP and at + size <= len(raw) and len(rows) < 64, 'finite complete packets')
        rows.append((tag, raw[at:at+size])); at += size
    return rows

def subpackets(raw):
    at = 0; rows = []
    while at < len(raw):
        size, at = length(raw, at)
        need(size >= 1 and at + size <= len(raw) and len(rows) < 64, 'bounded signature subpackets')
        rows.append((raw[at] & 127, raw[at+1:at+size])); at += size
    return rows

def mpi(raw, at):
    need(at + 2 <= len(raw), 'truncated MPI')
    bits = int.from_bytes(raw[at:at+2], 'big'); at += 2
    size = (bits + 7) // 8
    need(0 < bits <= 2048 and at + size <= len(raw), 'bounded MPI')
    value = int.from_bytes(raw[at:at+size], 'big')
    need(value.bit_length() == bits, 'canonical MPI')
    return bits, value, at + size

def unarmor(raw):
    need(type(raw) is bytes and 0 < len(raw) <= CAP and b'PRIVATE KEY' not in raw, 'bounded public-only armor')
    lines = raw.decode('ascii').splitlines()
    need(lines[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----' and
         lines[-1] == '-----END PGP PUBLIC KEY BLOCK-----' and
         raw.count(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') == 1, 'one public armor block')
    at = 1
    while at < len(lines) and lines[at]:
        need(':' in lines[at] and len(lines[at]) <= 256, 'bounded armor headers')
        at += 1
    need(at < len(lines) - 2, 'armor separator')
    body = lines[at+1:-1]
    need(body and body[-1].startswith('=') and len(body[-1]) == 5, 'armor CRC required')
    data = base64.b64decode(''.join(body[:-1]), validate=True)
    checksum = base64.b64decode(body[-1][1:], validate=True)
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    need(checksum == (crc & 0xffffff).to_bytes(3, 'big'), 'public armor CRC')
    return data

def parse_public_certificate(raw):
    rows = packets(unarmor(raw))
    need(len(rows) >= 3 and rows[0][0] == 6 and rows[1][0] == 13 and
         all(tag == 2 for tag, _ in rows[2:]), 'one primary key/UID and self-certifications only')
    key, uid_raw = rows[0][1], rows[1][1]
    need(len(key) >= 8 and key[0] == 4 and key[5] == 1, 'version4 RSA public key')
    bits, _, at = mpi(key, 6); _, exponent, at = mpi(key, at)
    need(bits == 2048 and exponent == 65537 and at == len(key), 'exact RSA2048 primary')
    created = int.from_bytes(key[1:5], 'big')
    fp = hashlib.sha1(b'\x99' + len(key).to_bytes(2, 'big') + key).hexdigest().upper()
    uid = uid_raw.decode('ascii')
    need(re.fullmatch(r'CACHY-ASAHI TEST ONLY [a-f0-9]{32} <test-only@invalid\.example>', uid), 'exact TEST-only nonce UID')
    candidates = []
    for _, sig in rows[2:]:
        need(len(sig) >= 12 and sig[0] == 4 and sig[1] in (0x10, 0x11, 0x12, 0x13)
             and sig[2] == 1 and sig[3] in (8, 9, 10, 11), 'bounded RSA self-certification; revocation refused')
        n = int.from_bytes(sig[4:6], 'big'); end = 6 + n
        need(end + 2 <= len(sig), 'complete hashed signature area')
        hashed = subpackets(sig[6:end]); u = int.from_bytes(sig[end:end+2], 'big'); tail = end + 2 + u
        need(tail + 2 < len(sig), 'complete unhashed signature area')
        subpackets(sig[end+2:tail]); _, _, finish = mpi(sig, tail + 2)
        need(finish == len(sig), 'complete signature MPI')
        one = {}
        for kind, value in hashed:
            if kind in (2, 9, 33):
                need(kind not in one, 'duplicate critical self-certification field')
                one[kind] = value
        need(set(one) == {2, 9, 33} and len(one[2]) == len(one[9]) == 4 and
             one[33] == b'\x04' + bytes.fromhex(fp), 'actual hashed selfsig time/expiry/issuer fingerprint')
        certified = int.from_bytes(one[2], 'big'); duration = int.from_bytes(one[9], 'big')
        need(created <= certified and duration > 0, 'positive certificate lifetime')
        candidates.append((certified, created + duration))
    latest = max(t for t, _ in candidates)
    expires = {e for t, e in candidates if t == latest}
    need(len(expires) == 1, 'unambiguous latest certificate expiry')
    return dict(fingerprint=fp, uid=uid, key_created=created,
                certificate_selfsig_created=latest, validity_anchor=latest, expires=expires.pop())
