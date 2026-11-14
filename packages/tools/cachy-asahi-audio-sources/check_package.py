#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Verify finite original recipe sources, frozen closure and actual package data."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

NAME = 'cachy-asahi-audio-sources'
RUNTIME = 'usr/lib/cachy-asahi/audio-sources/'
DOC = 'usr/share/doc/' + NAME + '/'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def desc(raw, mode=0o644):
    return dict(bytes=len(raw), sha256=sha(raw), mode=mode)


def members(raw, maximum=128):
    found, directories = {}, set(); expanded = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
        seen = set()
        for node in archive:
            name = node.name.rstrip('/') if node.isdir() else node.name
            path = PurePosixPath(name)
            need(name and path.as_posix() == name and not path.is_absolute() and '..' not in path.parts
                 and '\\' not in name and name not in seen, 'UNSAFE_OR_DUPLICATE_ARCHIVE_MEMBER')
            seen.add(name)
            need(len(seen) <= maximum and node.sparse is None and not node.pax_headers
                 and node.uid == node.gid == 0 and (node.isfile() or node.isdir()), 'UNSAFE_ARCHIVE_NODE')
            if node.isdir():
                need(node.mode == 0o755 and node.size == 0, 'ARCHIVE_DIRECTORY_MODE')
                directories.add(name)
                continue
            expanded += node.size
            need(0 <= node.size <= 1024**2 and expanded <= 4 * 1024**2, 'ARCHIVE_BYTE_LIMIT')
            with archive.extractfile(node) as stream:
                body = stream.read(1024**2 + 1)
            need(len(body) == node.size, 'TRUNCATED_ARCHIVE_MEMBER')
            found[name] = (body, node.mode)
    need(not any(str(p) in found for n in found for p in PurePosixPath(n).parents), 'ARCHIVE_FILE_AS_PARENT')
    return found, directories


def payload(root):
    mapping = json.loads((root / 'payload-map.json').read_bytes())['files']
    mapping[DOC + 'payload-map.json'] = desc((root / 'payload-map.json').read_bytes())
    return mapping


def audit(root, stage=None):
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    packed = (root / 'runtime-source.tar.gz').read_bytes()
    need(sha(packed) == provenance['archive']['sha256'] and len(packed) == provenance['archive']['bytes'], 'RUNTIME_ARCHIVE_PIN')
    files, directories = members(packed)
    pins = provenance['files']
    need(not directories and len(pins) == 10 and set(files) == {'runtime/' + name for name in pins}, 'FROZEN_CLOSURE_NAMESPACE')
    mapping = json.loads((root / 'runtime-map.json').read_bytes())['files']
    need(set(mapping) == set(pins), 'RUNTIME_MAP_NAMESPACE')
    for name, pin in pins.items():
        raw, mode = files['runtime/' + name]
        need(desc(raw, mode) == {k: pin[k] for k in ('bytes', 'sha256', 'mode')} == mapping[name], 'FROZEN_SOURCE_PIN')
    info = (root / '.SRCINFO').read_text()
    sources = re.findall(r'^\s+source = (.+)$', info, re.M)
    sums = re.findall(r'^\s+sha256sums = (.+)$', info, re.M)
    need(len(sources) == len(sums) and len(sources) == len(set(sources)) == 11, 'RECIPE_SOURCE_NAMESPACE')
    for name, pin in zip(sources, sums):
        need(Path(name).name == name and sha((root / name).read_bytes()) == pin, 'RECIPE_SOURCE_PIN')
    if stage is not None:
        found, directories = {}, set()
        for path in stage.rglob('*'):
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1), 'PAYLOAD_LINK_OR_SPECIAL')
            if stat.S_ISREG(info.st_mode):
                found[path.relative_to(stage).as_posix()] = desc(path.read_bytes(), stat.S_IMODE(info.st_mode))
            else:
                need(stat.S_IMODE(info.st_mode) == 0o755, 'PAYLOAD_DIRECTORY_MODE')
                directories.add(path.relative_to(stage).as_posix())
        need(found == payload(root), 'PAYLOAD_MAP_DIFFERS')
        need(directories == {str(p) for name in found for p in PurePosixPath(name).parents if str(p) != '.'}, 'PAYLOAD_DIRECTORY_NAMESPACE')
    return dict(status='PASS_ORIGINAL_AUDIO_TOOL_PACKAGE_DATA', runtime_files=10,
                payload_files=len(payload(root)), source_execution=False, installation=False)


def metadata(raw):
    result = {}
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.split(' = ', 1)
        result.setdefault(key, []).append(value)
    return result


def archive(root, source, output):
    need(not output.exists(), 'EXTRACTION_OUTPUT_EXISTS')
    files, directories = members(source.read_bytes())
    need(directories == {str(p) for name in files for p in PurePosixPath(name).parents if str(p) != '.'}, 'ARCHIVE_DIRECTORY_NAMESPACE')
    meta = {}
    for name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
        raw, mode = files.pop(name)
        need(mode == 0o644, 'ARCHIVE_METADATA_MODE')
        meta[name] = raw
    need({name: desc(raw, mode) for name, (raw, mode) in files.items()} == payload(root), 'ARCHIVE_PAYLOAD_DIFFERS')
    info, build = metadata(meta['.PKGINFO']), metadata(meta['.BUILDINFO'])
    need(set(info) == {'pkgname', 'pkgbase', 'xdata', 'pkgver', 'pkgdesc', 'url', 'builddate',
                      'packager', 'size', 'arch', 'license', 'depend', 'checkdepend'}
         and info['pkgbase'] == [NAME] and info['xdata'] == ['pkgtype=pkg']
         and info['checkdepend'] == ['bubblewrap'], 'ARCHIVE_INSTALLATION_METADATA')
    need(info['pkgname'] == build['pkgname'] == [NAME] and info['pkgver'] == build['pkgver'] == ['0.1.0-1']
         and info['arch'] == build['pkgarch'] == ['any'] and info['license'] == ['MIT']
         and set(info['depend']) == {'python>=3.12', 'xz'}, 'ARCHIVE_PACKAGE_IDENTITY')
    need(build['pkgbuild_sha256sum'] == [sha((root / 'PKGBUILD').read_bytes())], 'ARCHIVE_RECIPE_BINDING')
    output.mkdir(mode=0o700)
    for name in sorted(directories, key=lambda n: (len(PurePosixPath(n).parts), n)):
        path = output / name; path.mkdir(mode=0o755); path.chmod(0o755)
    for name, (raw, mode) in files.items():
        path = output / name
        path.write_bytes(raw); path.chmod(mode)
    audit(root, output)
    return dict(status='PASS_ACTUAL_ARCHIVE_PAYLOAD_AND_METADATA', payload_files=len(files),
                archive_sha256=sha(source.read_bytes()), installation=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.recipe_root, args.stage), sort_keys=True))
