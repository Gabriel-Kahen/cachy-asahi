#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Read-only PNG content validation; capture provenance is established separately."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import zlib

from PIL import Image

MAX_BYTES = 8 * 1024 * 1024
MAX_PIXELS = 1024 * 1024
MAX_CHUNKS = 4096
SIGNATURE = b'\x89PNG\r\n\x1a\n'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def identity(node):
    return (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid,
            node.st_nlink, node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def canonical(value):
    raw = os.fspath(value)
    require(type(raw) is str and 0 < len(raw) <= 4096, 'invalid path')
    path = Path(raw)
    require(path.is_absolute() and '..' not in path.parts and raw == str(path),
            'absolute canonical path required')
    return path


def directory_node(root):
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), 'symlink or non-directory component')
    node = root.lstat()
    require(stat.S_ISDIR(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o700
            and node.st_uid == os.geteuid(), 'owned 0700 output root required')
    return node


def chunks(raw, width, height):
    require(raw.startswith(SIGNATURE), 'PNG signature required')
    offset, count = 8, 0
    header = palette = data = closed_data = False
    color_type = None
    while offset < len(raw):
        count += 1
        require(count <= MAX_CHUNKS and offset + 12 <= len(raw), 'truncated or excessive PNG chunks')
        size = struct.unpack_from('>I', raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + size
        require(end <= len(raw), 'truncated PNG chunk')
        require(all(65 <= c <= 90 or 97 <= c <= 122 for c in kind) and not kind[2] & 32,
                'invalid PNG chunk type')
        payload = raw[offset + 8:end - 4]
        expected_crc = struct.unpack_from('>I', raw, end - 4)[0]
        require(zlib.crc32(kind + payload) & 0xffffffff == expected_crc, 'PNG CRC mismatch')
        require(header or kind == b'IHDR', 'IHDR must be first')
        if not kind[0] & 32:
            require(kind in (b'IHDR', b'PLTE', b'IDAT', b'IEND'), 'unknown critical PNG chunk')
        if kind == b'IHDR':
            require(not header and count == 1 and size == 13, 'one first IHDR required')
            w, h, bits, color_type, compression, filtering, interlace = struct.unpack('>IIBBBBB', payload)
            require((w, h) == (width, height), 'PNG dimensions differ')
            require(bits == 8 and color_type in (2, 6) and compression == filtering == 0
                    and interlace in (0, 1), '8-bit RGB or RGBA PNG required')
            header = True
        elif kind == b'PLTE':
            require(not palette and not data and 0 < size <= 768 and size % 3 == 0,
                    'invalid PLTE order or size')
            palette = True
        elif kind == b'IDAT':
            require(not closed_data, 'IDAT chunks must be consecutive')
            data = True
        elif kind == b'IEND':
            require(data and size == 0 and end == len(raw), 'one final empty IEND required')
            return 'RGB' if color_type == 2 else 'RGBA'
        elif data:
            closed_data = True
        offset = end
    raise ValueError('IEND required')


def validate_png(path, output_root, *, width=320, height=240, rgb=(17, 34, 51)):
    """Validate a stable private direct child without changing its image bytes."""
    require(type(width) is type(height) is int and 0 < width <= 4096 and 0 < height <= 4096
            and width * height <= MAX_PIXELS, 'bounded positive dimensions required')
    require(type(rgb) in (tuple, list) and len(rgb) == 3
            and all(type(c) is int and 0 <= c <= 255 for c in rgb), 'three RGB bytes required')
    path, root = canonical(path), canonical(output_root)
    require(path.parent == root and path.name not in ('', '.', '..'), 'direct child of output root required')
    root_before = directory_node(root)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(identity(os.fstat(root_fd)) == identity(root_before), 'output root changed')
        before = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_uid == os.geteuid(), 'owned regular 0600 PNG required')
        require(0 < before.st_size <= MAX_BYTES, 'PNG size exceeds bound or is empty')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=root_fd)
        try:
            require(identity(os.fstat(fd)) == identity(before), 'PNG changed before read')
            raw = bytearray()
            while len(raw) <= before.st_size:
                piece = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
                if not piece:
                    break
                raw.extend(piece)
            require(len(raw) == before.st_size, 'PNG size changed during read')
            require(identity(os.fstat(fd)) == identity(before), 'PNG changed during read')
            raw = bytes(raw)
            mode = chunks(raw, width, height)
            with Image.open(io.BytesIO(raw)) as image:
                require(image.format == 'PNG', 'PNG decoder format differs')
                image.verify()
            with Image.open(io.BytesIO(raw)) as image:
                require(image.mode == mode and image.size == (width, height)
                        and getattr(image, 'n_frames', 1) == 1, 'decoded PNG shape differs')
                image.load()
                pixels = image.convert('RGBA').tobytes()
                require(pixels == (bytes(rgb) + b'\xff') * (width * height),
                        'PNG pixels or alpha differ')
            require(identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)) == identity(before),
                    'PNG changed during validation')
            require(identity(os.fstat(root_fd)) == identity(root_before)
                    and identity(directory_node(root)) == identity(root_before), 'output root changed during validation')
            return {'schema': 1, 'status': 'PASS_PNG_CONTENT_ONLY',
                    'capture_provenance': 'NOT_ESTABLISHED_BY_VALIDATOR',
                    'path': str(path), 'output_root': str(root), 'bytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(), 'width': width, 'height': height,
                    'storage_mode': mode, 'pixels': width * height,
                    'colors': [{'rgb': list(rgb), 'alpha': 255, 'pixels': width * height}],
                    'file': {'device': before.st_dev, 'inode': before.st_ino,
                             'mode': oct(stat.S_IMODE(before.st_mode)), 'uid': before.st_uid, 'gid': before.st_gid},
                    'root': {'device': root_before.st_dev, 'inode': root_before.st_ino,
                             'mode': oct(stat.S_IMODE(root_before.st_mode)), 'uid': root_before.st_uid}}
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--root', required=True)
    parser.add_argument('--width', type=int, default=320)
    parser.add_argument('--height', type=int, default=240)
    parser.add_argument('--rgb', type=int, nargs=3, default=(17, 34, 51))
    args = parser.parse_args(argv)
    try:
        result = validate_png(args.image, args.root, width=args.width, height=args.height, rgb=args.rgb)
    except Exception as error:
        print(json.dumps({'status': 'FAIL_PNG_CONTENT_ONLY', 'error': type(error).__name__,
                          'reason': str(error)[:200]}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
