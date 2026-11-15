# SPDX-License-Identifier: MIT
"""Materialize only the Source-pinned protected capsule, never fetch or sign inputs."""
import hashlib
import json
from pathlib import Path,PurePosixPath
import tarfile


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def materialize(root,work):
    contract=json.loads((root/'contract.json').read_bytes());pin=contract['capsule'];source=root/'lifecycle-capsule.tar'
    if source.stat().st_size!=pin['bytes'] or digest(source)!=pin['sha256']:raise ValueError('exact Source-reviewed lifecycle capsule bytes required')
    destination=work/'lifecycle-inputs'
    if destination.exists():raise ValueError('fresh lifecycle inputs required')
    destination.mkdir(mode=0o700);seen=set();total=0
    with tarfile.open(source,'r|') as archive:
        for item in archive:
            p=PurePosixPath(item.name)
            if not item.isfile() or item.sparse or '..' in p.parts or not p.parts or p.parts[0]!='capsule':raise ValueError('capsule regular contained DATA only')
            name=p.relative_to('capsule').as_posix()
            if name not in pin['members'] or name in seen:raise ValueError('capsule member map differs')
            expected=pin['members'][name];total+=item.size
            if total>48*1024**2 or item.size!=expected['bytes'] or item.mode!=expected['mode']:raise ValueError('capsule size/exact admitted mode differs')
            target=destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);h=hashlib.sha256()
            with target.open('xb') as output:
                stream=archive.extractfile(item)
                while block:=stream.read(65536):output.write(block);h.update(block)
            if h.hexdigest()!=expected['sha256']:raise ValueError('capsule payload checksum differs')
            target.chmod(expected['mode']);seen.add(name);archive.members.clear()
    if seen!=set(pin['members']):raise ValueError('capsule incomplete')
    if digest(destination/'source-map.json')!=pin['source_map_sha256']:raise ValueError('inner Source map differs')
    return destination
