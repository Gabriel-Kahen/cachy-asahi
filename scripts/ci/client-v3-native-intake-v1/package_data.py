# SPDX-License-Identifier: MIT
"""Independent in-memory XZ package DATA inspection for the exact two Python leaves."""
import hashlib
import io
import lzma
import re
import tarfile
from pathlib import PurePosixPath
from client_v3_common import need, name, pin

META = {'.PKGINFO', '.BUILDINFO', '.MTREE'}

def metadata(raw):
    value = {}
    for line in raw.decode('utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        found = re.fullmatch(r'\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*', line)
        need(found is not None, 'literal metadata DATA required')
        key, text = found.groups()
        value.setdefault(key, []).append(text)
    return value

def package(raw, filename, recipe, expected_payload, source_bytes):
    need(filename.endswith('.pkg.tar.xz') and 0 < len(raw) <= 8 * 1024**2,
         'exact component XZ package required; no subprocess/format fallback')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
    tar = decoder.decompress(raw, max_length=32 * 1024**2 + 1)
    need(decoder.eof and not decoder.unused_data and len(tar) <= 32 * 1024**2, 'complete bounded single XZ stream required')
    need(len(tar) % 512 == 0 and tar.endswith(b'\0' * 1024), 'complete padded TAR termination required')
    members, info, total, end = {}, {}, 0, 0
    with tarfile.open(fileobj=io.BytesIO(tar), mode='r:') as archive:
        for member in archive:
            end = max(end, member.offset_data + ((member.size + 511) // 512) * 512)
            n = member.name.removeprefix('./').rstrip('/') if member.isdir() else member.name.removeprefix('./')
            if n == '.':
                continue
            name(n)
            need(n not in members and len(members) < 128 and not member.pax_headers and
                 (member.isfile() or member.isdir()) and member.uid == member.gid == 0 and not member.mode & 0o7000,
                 'duplicate/PAX/link/special/nonroot package member refused')
            total += member.size
            need(0 <= member.size <= 4 * 1024**2 and total <= 32 * 1024**2, 'package expanded member caps')
            value = archive.extractfile(member).read() if member.isfile() else b''
            need(not member.isfile() or len(value) == member.size, 'whole package member required')
            members[n] = dict(type='0' if member.isfile() else '5', mode=member.mode, uid=member.uid, gid=member.gid,
                              size=member.size, mtime=member.mtime, link=member.linkname,
                              sha256=hashlib.sha256(value).hexdigest() if member.isfile() else None)
            need(not value.startswith(b'\x7fELF'), 'exact arch-any Python/data leaves, no ELF')
            if n in ('.PKGINFO', '.BUILDINFO'):
                info[n] = metadata(value)
    need(not any(tar[end:]), 'unbound trailing TAR data refused')
    actual = {n: row for n, row in members.items() if row['type'] != '5' and n not in META}
    need(set(actual) == set(expected_payload) and META <= set(members) and
         all(members[n]['type'] == '0' for n in META), 'exact bound package payload and three metadata files required')
    parents = {str(p) for n in expected_payload for p in PurePosixPath(n).parents if str(p) != '.'}
    need({n for n, row in members.items() if row['type'] == '5'} <= parents, 'unexpected package directory')
    for n, (original, mode) in expected_payload.items():
        need(actual[n]['mode'] == mode and actual[n]['sha256'] == pin(source_bytes(original))['sha256'], 'actual package payload differs from bound Source DATA')
    pkg, build = info['.PKGINFO'], info['.BUILDINFO']
    version = recipe['pkgver'][0] + '-' + recipe['pkgrel'][0]
    need(pkg.get('pkgname') == recipe['pkgname'] and pkg.get('pkgver') == [version] and pkg.get('arch') == ['any'] and
         pkg.get('license') == ['MIT'] and pkg.get('depend', []) == recipe.get('depends', []), 'actual package identity/dependency differs')
    need(build.get('format') == ['2'] and build.get('pkgname') == pkg['pkgname'] and build.get('pkgver') == pkg['pkgver'] and
         build.get('pkgarch') == ['any'] and build.get('pkgbuild_sha256sum') == [pin(source_bytes('PKGBUILD'))['sha256']],
         'actual BUILDINFO/recipe binding differs')
    return dict(sha256=pin(raw)['sha256'], members=members, metadata=info, payload=actual)
