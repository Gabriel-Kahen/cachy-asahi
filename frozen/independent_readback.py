#!/usr/bin/env python3
"""Finite raw ext4 inventory. Read-only, independent of e2fsprogs output.

Supports 4K extent filesystems, ordinary files/directories/symlinks and inline
or block xattrs. Structural validation is not filesystem integrity acceptance;
e2fsck is still required for allocation, checksums and filesystem consistency.
"""
import base64
import hashlib
import json
import os
import stat
import struct
import sys
import uuid


class ReadbackError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise ReadbackError(message)


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


class Ext4Reader:
    def __init__(self, path, max_nodes=100000, max_file_bytes=64 * 1024 * 1024):
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.max_nodes, self.max_file_bytes = max_nodes, max_file_bytes
        self.read_budget = 2 * 1024 ** 3
        try:
            s = os.fstat(self.fd)
            need(stat.S_ISREG(s.st_mode) and 4096 <= s.st_size <= 4 * 1024 ** 3,
                 'input must be a bounded ordinary image file')
            self.size = s.st_size
            sb = self.read(1024, 1024)
            need(u16(sb, 56) == 0xef53, 'missing ext4 magic')
            need(u32(sb, 24) == 2, 'only 4096-byte block profile supported')
            self.blocksize = 4096
            self.incompat, self.rocompat = u32(sb, 96), u32(sb, 100)
            need(not self.incompat & ~(2 | 4 | 0x40 | 0x80 | 0x200 | 0x2000 | 0x4000),
                 'unsupported incompat filesystem feature')
            need(self.incompat & 0x40, 'extent filesystem required')
            need(not self.rocompat & (0x200 | 0x8000 | 0x10000),
                 'bigalloc, verity and orphan-file profile unsupported')
            self.blocks = u32(sb, 4) | (u32(sb, 336) << 32 if self.incompat & 0x80 else 0)
            need(self.blocks * 4096 == self.size, 'filesystem/image size mismatch')
            self.inodes = u32(sb, 0)
            self.ipg, self.bpg = u32(sb, 40), u32(sb, 32)
            need(self.ipg > 0 and self.bpg > 0 and 1 <= self.inodes <= 1000000,
                 'invalid/excessive group or inode count')
            self.inode_size = u16(sb, 88)
            need(self.inode_size in (128, 256, 512), 'unsupported inode size')
            self.desc_size = u16(sb, 254) if self.incompat & 0x80 else 32
            need(self.desc_size in (32, 64), 'unsupported group descriptor size')
            self.uuid = str(uuid.UUID(bytes=sb[104:120]))
            self.hash_seed = str(uuid.UUID(bytes=sb[236:252]))
            self.created = u32(sb, 264)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def read(self, offset, length):
        need(type(offset) is int and type(length) is int and
             0 <= offset <= self.size and 0 <= length <= self.size - offset,
             'read outside image')
        self.read_budget -= length
        need(self.read_budget >= 0, 'read budget exhausted')
        data = os.pread(self.fd, length, offset)
        need(len(data) == length, 'short image read')
        return data

    def block(self, block):
        need(0 <= block < self.blocks, 'invalid block number')
        return self.read(block * 4096, 4096)

    def inode(self, number):
        need(1 <= number <= self.inodes, 'invalid inode number')
        group, index = divmod(number - 1, self.ipg)
        desc = self.read(4096 + group * self.desc_size, self.desc_size)
        table = u32(desc, 8) | (u32(desc, 40) << 32 if self.desc_size == 64 else 0)
        need(table > 0, 'missing inode table')
        raw = self.read(table * 4096 + index * self.inode_size, self.inode_size)
        mode = u16(raw, 0)
        kind = {stat.S_IFREG: 'file', stat.S_IFDIR: 'directory', stat.S_IFLNK: 'symlink'}.get(stat.S_IFMT(mode))
        need(kind is not None, 'unsupported special or unused inode')
        size = u32(raw, 4) | (u32(raw, 108) << 32)
        need(size <= self.max_file_bytes, 'node exceeds content bound')
        need(not u32(raw, 32) & (0x10000000 | 0x800), 'inline-data or encrypted inode unsupported')
        fields = {'inode': number, 'type': kind, 'mode': stat.S_IMODE(mode),
                  'uid': u16(raw, 2) | (u16(raw, 120) << 16),
                  'gid': u16(raw, 24) | (u16(raw, 122) << 16),
                  'size': size, 'links': u16(raw, 26)}
        extra = u16(raw, 128) if len(raw) >= 132 else 0
        need(extra <= self.inode_size - 128, 'invalid inode extra size')
        for name, offset, eoffset in [('atime', 8, 140), ('ctime', 12, 132),
                                       ('mtime', 16, 136), ('crtime', 144, 148)]:
            if offset + 4 > len(raw) or (name == 'crtime' and extra < 24):
                fields[name] = None
                fields[name + '_ns'] = None
                continue
            ex = u32(raw, eoffset) if eoffset + 4 <= 128 + extra else 0
            fields[name] = struct.unpack_from('<i', raw, offset)[0] + ((ex & 3) << 32)
            fields[name + '_ns'] = ex >> 2
        fields['xattrs'] = self.xattrs(raw, extra)
        return fields, raw

    def xattrs(self, raw, extra):
        result = {}

        def entries(data, start, base):
            at, count = start, 0
            while True:
                need(at + 4 <= len(data), 'truncated xattr entry')
                if data[at:at + 4] == b'\0' * 4:
                    break
                need(at + 16 <= len(data), 'truncated xattr header')
                nlen, index, voff, vinum, vsize, _ = struct.unpack_from('<BBHIII', data, at)
                need(vinum == 0, 'external xattr value inode unsupported')
                need(at + 16 + nlen <= len(data), 'truncated xattr name')
                name = data[at + 16:at + 16 + nlen]
                prefixes = {1: b'user.', 2: b'system.posix_acl_access', 3: b'system.posix_acl_default',
                            4: b'trusted.', 6: b'security.', 7: b'system.'}
                need(index in prefixes, 'unsupported xattr namespace')
                try:
                    full = (prefixes[index] + name).decode('utf-8', 'strict')
                except UnicodeError as exc:
                    raise ReadbackError('non-UTF8 xattr name unsupported') from exc
                need(full not in result, 'duplicate xattr')
                need(0 <= base + voff <= len(data) and vsize <= len(data) - base - voff,
                     'xattr value outside area')
                result[full] = base64.b64encode(data[base + voff:base + voff + vsize]).decode('ascii')
                at += (16 + nlen + 3) & ~3
                count += 1
                need(count <= 1024, 'excessive xattr count')

        begin = 128 + extra
        if begin + 4 <= len(raw) and u32(raw, begin) == 0xea020000:
            entries(raw, begin + 4, begin + 4)
        external = u32(raw, 104) | (u16(raw, 118) << 32)
        if external:
            block = self.block(external)
            need(u32(block, 0) == 0xea020000 and u32(block, 8) == 1,
                 'unsupported external xattr block')
            entries(block, 32, 0)
        return dict(sorted(result.items()))

    def extents(self, data, depth=None, seen=None):
        seen = set() if seen is None else seen
        need(len(data) >= 12 and u16(data, 0) == 0xf30a, 'extent header required')
        count, maximum, actual_depth = u16(data, 2), u16(data, 4), u16(data, 6)
        need(actual_depth <= 3 and (depth is None or depth == actual_depth), 'invalid extent depth')
        need(count <= maximum and 12 + count * 12 <= len(data), 'invalid extent count')
        output = []
        for i in range(count):
            p = 12 + i * 12
            logical = u32(data, p)
            if actual_depth:
                physical = u32(data, p + 4) | (u16(data, p + 8) << 32)
                need(physical not in seen and len(seen) < 16384, 'cyclic/excessive extent tree')
                seen.add(physical)
                child = self.extents(self.block(physical), actual_depth - 1, seen)
                need(child and child[0][0] == logical, 'extent index mismatch')
                output.extend(child)
            else:
                length = u16(data, p + 4)
                need(length != 0, 'zero extent length')
                unwritten = length > 32768
                length = length - 32768 if unwritten else length
                physical = u16(data, p + 6) << 32 | u32(data, p + 8)
                need(physical > 0 and physical + length <= self.blocks, 'extent outside image')
                output.append((logical, length, physical, unwritten))
        for a, b in zip(output, output[1:]):
            need(a[0] + a[1] <= b[0], 'overlapping or unordered extents')
        return output

    def chunks(self, fields, raw):
        remaining, next_logical = fields['size'], 0
        if fields['type'] == 'symlink' and not u32(raw, 32) & 0x80000 and remaining <= 60:
            yield raw[40:40 + remaining]
            return
        if remaining == 0:
            return
        need(u32(raw, 32) & 0x80000, 'non-extent data inode unsupported')
        for logical, length, physical, unwritten in self.extents(raw[40:100]):
            while next_logical < logical and remaining:
                n = min(4096, remaining)
                yield bytes(n)
                remaining -= n
                next_logical += 1
            for offset in range(length):
                if not remaining:
                    break
                n = min(4096, remaining)
                yield bytes(n) if unwritten else self.block(physical + offset)[:n]
                remaining -= n
                next_logical += 1
        while remaining:
            n = min(4096, remaining)
            yield bytes(n)
            remaining -= n

    def inventory(self):
        result, visited_dirs, refs, children = {}, set(), {}, {}
        pending = [('.', 2, 2, 2)]
        while pending:
            path, number, parent, entry_type = pending.pop()
            need(len(result) < self.max_nodes and len(path) <= 4096, 'inventory bound exceeded')
            need(path not in result, 'duplicate directory path')
            node, raw = self.inode(number)
            need(entry_type == {'file': 1, 'directory': 2, 'symlink': 7}[node['type']],
                 'directory type differs from inode')
            result[path] = node
            refs[number] = refs.get(number, 0) + 1
            if node['type'] == 'directory':
                need(number not in visited_dirs, 'directory hardlink/cycle')
                visited_dirs.add(number)
                need(node['size'] <= 16 * 1024 * 1024, 'directory exceeds bound')
                data = b''.join(self.chunks(node, raw))
                found, pos = {}, 0
                children[number] = 0
                while pos < len(data):
                    need(pos + 8 <= len(data), 'truncated directory entry')
                    ino, reclen, namelen, ftype = struct.unpack_from('<IHBB', data, pos)
                    need(reclen >= 8 and reclen % 4 == 0 and pos + reclen <= len(data) and
                         pos % 4096 + reclen <= 4096 and namelen <= reclen - 8,
                         'invalid directory entry bounds')
                    if ino:
                        name = data[pos + 8:pos + 8 + namelen]
                        need(name and b'/' not in name and b'\0' not in name and name not in found,
                             'invalid/duplicate directory entry name')
                        found[name] = ino
                        if name not in (b'.', b'..'):
                            try:
                                name = name.decode('utf-8', 'strict')
                            except UnicodeError as exc:
                                raise ReadbackError('non-UTF8 path unsupported') from exc
                            next_path = name if path == '.' else path + '/' + name
                            pending.append((next_path, ino, number, ftype))
                            if ftype == 2:
                                children[number] += 1
                    pos += reclen
                need(found.get(b'.') == number and found.get(b'..') == parent,
                     'directory dot/parent mismatch')
            elif node['type'] == 'file':
                h = hashlib.sha256()
                for part in self.chunks(node, raw):
                    h.update(part)
                node['sha256'] = h.hexdigest()
            else:
                link = b''.join(self.chunks(node, raw))
                need(b'\0' not in link, 'symlink contains NUL')
                node['target_b64'] = base64.b64encode(link).decode('ascii')
        for node in result.values():
            expected = children[node['inode']] + 2 if node['type'] == 'directory' else refs[node['inode']]
            need(node['links'] == expected, 'inode link-count mismatch')
        return {'schema_version': 1, 'reader': 'independent-raw-ext4-finite-v1',
                'image_bytes': self.size, 'uuid': self.uuid, 'hash_seed': self.hash_seed,
                'created': self.created, 'incompat': self.incompat, 'rocompat': self.rocompat,
                'nodes': dict(sorted(result.items()))}


def read_inventory(path, **kwargs):
    with Ext4Reader(path, **kwargs) as reader:
        return reader.inventory()


if __name__ == '__main__':
    try:
        print(json.dumps(read_inventory(sys.argv[1]), sort_keys=True, indent=2))
    except (ReadbackError, OSError, IndexError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
