#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Passive XS Original DATA reader; Root authentication and acceptance stay external."""
import sys
if __name__ == '__main__' and (not sys.flags.isolated or sys.flags.optimize or not sys.dont_write_bytecode):
    raise SystemExit('isolated unoptimized Python with -B required')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xs_independent_data', HERE / 'data.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
SOURCE = '0885f89ab7a4301bbdf9c4b180620fb447d9a41a'
REF = 'refs/heads/codex/native-arm-perl5423-xs-v1-20261115'
MAP = '674cc3d18e954dd1f3f351b357f746e3b9ab1b7580370666061fcb9deeb15efc'
TREE = '6a1c29b7aa1655943b54de71a89f3900ff1671c9'
HELD_MAP = '4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96'
HELD_TREE = '43dfa9d6370abd1424bd5586c5524a6f4b4e1556'
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'reader', 'authority', 'approval', 'artifact', 'image'))


def binding(value):
    d.need(type(value) is dict and set(value) == {'schema', 'binding', 'artifact'} and
           type(value['schema']) is int and value['schema'] == 1, 'external Root Reader input envelope required')
    b, a = value['binding'], value['artifact']
    d.need(type(b) is dict and set(b) == {'source', 'ref', 'run', 'job', 'approval', 'source_map_sha256', 'operation'}
           and b['source'] == SOURCE and b['ref'] == REF and b['source_map_sha256'] == MAP and
           b['operation'] == 'perl5423-native-xs-v1' and d.sha(b['approval']) and
           all(type(b[k]) is str and re.fullmatch('[1-9][0-9]{0,19}', b[k]) for k in ('run', 'job')),
           'actual exact published XS Source/ref/run/job/approval/map binding required')
    d.need(type(a) is dict and set(a) == {'id', 'bytes', 'sha256', 'metadata_sha256'} and
           type(a['id']) is str and re.fullmatch('[1-9][0-9]{0,19}', a['id']) and
           type(a['bytes']) is int and 0 < a['bytes'] <= 512*d.MIB and
           d.sha(a['sha256']) and d.sha(a['metadata_sha256']), 'actual Original artifact/metadata pins required')
    return b, a


def git_tree(rows):
    nodes = {}
    for name, (body, mode) in rows.items():
        node = nodes
        parts = d.relative(name).split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            d.need(type(node) is dict, 'Git tree path collision')
        d.need(parts[-1] not in node, 'duplicate Git tree leaf')
        node[parts[-1]] = (body, mode)
    def oid(kind, body):
        return hashlib.sha1(kind + b' ' + str(len(body)).encode() + b'\0' + body).digest()
    def tree(node):
        body = bytearray()
        for name, item in sorted(node.items(), key=lambda row: row[0].encode() + (b'/' if type(row[1]) is dict else b'')):
            d.tick()
            if type(item) is dict:
                mode, digest = b'40000', tree(item)
            else:
                raw, permissions = item
                mode, digest = (b'100755' if permissions == 0o755 else b'100644'), oid(b'blob', raw)
            body.extend(mode + b' ' + name.encode() + b'\0' + digest)
        return oid(b'tree', bytes(body))
    return tree(nodes).hex()


def source(root, b):
    raw = d.read(root, 'source-map.json', d.MIB)
    d.need(d.pin(raw) == dict(bytes=58348, sha256=b['source_map_sha256']), 'complete published Source map differs')
    m = d.decode(raw)
    d.need(m['schema'] == 1 and m['actual'] == ACTUAL and len(m['files']) == 296,
           '297-file Source with null operational declarations required')
    names = d.inventory(root, 297, 96*d.MIB, ignore_git=True)
    d.need(names == set(m['files']) | {'source-map.json'}, 'complete published Source namespace differs')
    leaves = {}
    for name in sorted(names):
        body = d.read(root, name, 64*d.MIB)
        mode = stat.S_IMODE((Path(root) / name).stat().st_mode)
        d.need(mode in (0o644, 0o755), 'ordinary Source Git mode')
        if name != 'source-map.json':
            d.need(dict(**d.pin(body), mode=mode) == m['files'][name], 'Source leaf bytes/mode differs: ' + name)
        leaves[name] = (body, mode)
    d.need(sum(len(body) for body, _ in leaves.values()) == 87006934 and git_tree(leaves) == TREE,
           'complete published Source byte count/Git tree differs')
    held = {name[5:]: row for name, row in leaves.items() if name.startswith('held/')}
    d.need(len(held) == 272 and d.pin(held['source-map.json'][0])['sha256'] == HELD_MAP
           and git_tree(held) == HELD_TREE, 'complete immutable held272 tree differs')
    hm = d.decode(held['source-map.json'][0])
    d.need(hm['actual'] == ACTUAL and hm['files'] ==
           {name: dict(**d.pin(raw), mode=mode) for name, (raw, mode) in held.items() if name != 'source-map.json'},
           'held map namespace/bytes/modes differs')
    aliases = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-perl5423-xs-v1.yml')
    d.need(leaves[aliases[0]] == leaves[aliases[1]], 'exact dedicated workflow aliases differ')
    return m


def original(zip_path, evidence, artifact, metadata_raw, b):
    d.need(d.pin(metadata_raw)['sha256'] == artifact['metadata_sha256'], 'Root-pinned artifact metadata differs')
    metadata = d.decode(metadata_raw)
    run = metadata['workflow_run']
    d.need(type(metadata['id']) is int and str(metadata['id']) == artifact['id']
           and metadata['size_in_bytes'] == artifact['bytes'] and metadata['expired'] is False
           and run['id'] == int(b['run']) and run['head_sha'] == b['source']
           and run['head_branch'] == b['ref'].removeprefix('refs/heads/')
           and metadata['name'] == 'perl5423-native-xs-v1-' + b['run'] + '-1',
           'actual original artifact metadata Source/run/name/size joins differ')
    zip_path = d.absolute(zip_path)
    # Stream the opaque original hash; never materialize or extract archive members.
    fd = os.open(zip_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        d.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == artifact['bytes'],
               'actual bounded ordinary Original ZIP required')
        digest = hashlib.sha256()
        while block := stream.read(65536):
            d.tick()
            digest.update(block)
        d.need(digest.hexdigest() == artifact['sha256'], 'whole Original artifact digest differs')
        stream.seek(0)
        names, seen, directories, total = set(), set(), set(), 0
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            d.need(1 <= len(members) <= 4000 and not archive.comment, 'finite original ZIP member/comment policy')
            for member in members:
                d.tick()
                name = member.filename.removesuffix('/') if member.is_dir() else member.filename
                d.relative(name)
                d.need(name not in seen and not member.flag_bits & 1 and not member.comment
                       and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                       'unique unencrypted ordinary ZIP member required')
                seen.add(name)
                # Only bounded ZIP64 sizes and non-authoritative UTC timestamps.
                extra, tags = member.extra, set()
                d.need(len(extra) <= 128, 'bounded ZIP extra fields')
                while extra:
                    d.need(len(extra) >= 4, 'complete ZIP extra header')
                    tag, size = struct.unpack_from('<HH', extra)
                    field, extra = extra[4:4+size], extra[4+size:]
                    d.need(len(field) == size and tag not in tags and
                           ((tag == 1 and size in (8, 16, 24, 28)) or
                            (tag == 0x5455 and size in (1, 5, 9, 13) and field[0] <= 7)),
                           'unsupported ZIP extra field')
                    tags.add(tag)
                mode = member.external_attr >> 16
                kind, permissions = stat.S_IFMT(mode), stat.S_IMODE(mode)
                if member.is_dir():
                    d.need(kind in (0, stat.S_IFDIR) and permissions in (0, 0o700, 0o755)
                           and member.file_size == 0 and 0 <= member.compress_size <= 8,
                           'safe empty ZIP directory')
                    with archive.open(member) as directory:
                        d.need(directory.read(1) == b'', 'empty bounded ZIP directory content')
                    directories.add(name)
                    continue
                d.need(kind in (0, stat.S_IFREG) and permissions in (0, 0o600, 0o644)
                       and 0 <= member.file_size <= 256*d.MIB, 'bounded nonexecutable regular Original member')
                total += member.file_size
                d.need(total <= 1024*d.MIB, 'Original decoded byte budget')
                expected = d.read(evidence, name, 256*d.MIB)
                d.need(stat.S_IMODE((Path(evidence) / name).lstat().st_mode) in (0o400, 0o444, 0o600, 0o644),
                       'retained evidence must remain ordinary nonexecutable protected DATA')
                size = 0
                check = hashlib.sha256()
                with archive.open(member) as body:
                    while block := body.read(65536):
                        d.tick()
                        size += len(block)
                        d.need(size <= member.file_size, 'ZIP member decoded overrun')
                        check.update(block)
                d.need(size == len(expected) == member.file_size and check.hexdigest() == d.pin(expected)['sha256'],
                       'retained evidence differs from complete Original member')
                names.add(name)
        parents = {str(parent) for name in names for parent in Path(name).parents if str(parent) != '.'}
        d.need(not names & parents and directories <= parents, 'ZIP file/directory collision or empty unreferenced directory')
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        d.need(key(before) == key(os.fstat(stream.fileno())) == key(zip_path.lstat()), 'Original artifact changed during read')
    observed = d.inventory(evidence, 3000, 1024*d.MIB)
    d.need(names == observed, 'complete Original/retained evidence namespace differs')
    d.set_names(names)
    return dict(id=artifact['id'], original={k: artifact[k] for k in ('bytes', 'sha256')},
                files=len(names), decoded_bytes=total, metadata_sha256=artifact['metadata_sha256'])


def validate(args):
    d.start()
    d.need(sys.flags.isolated and not sys.flags.optimize and sys.dont_write_bytecode and sys.version_info >= (3, 14),
           'isolated unoptimized Python3.14+ passive zstd Reader with -B required')
    path = d.absolute(args.binding)
    raw = d.read(path.parent, path.name, 2*d.MIB)
    d.need(d.sha(args.binding_sha256) and d.pin(raw)['sha256'] == args.binding_sha256, 'external Root whole binding pin required')
    b, artifact = binding(d.decode(raw))
    source_root, evidence = d.absolute(args.source_root), d.absolute(args.evidence)
    m = source(source_root, b)
    metadata_path = d.absolute(args.artifact_metadata)
    origin = original(args.original_artifact, evidence, artifact,
                      d.read(metadata_path.parent, metadata_path.name, 2*d.MIB), b)
    def get(name, cap=16*d.MIB):
        d.need(name in d._evidence_names, 'missing Original evidence leaf: ' + name)
        return d.read(evidence, name, cap)
    modules = {}
    for name in ('bootstrap', 'consumer'):
        spec = importlib.util.spec_from_file_location('xs_independent_' + name, HERE / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[name] = module
    context = modules['bootstrap'].validate(get, source_root, b, m, d)
    result = modules['consumer'].validate(get, source_root, b, context, d)
    d.tick()
    return dict(schema=1, status='PASS_SCOPED_XS_ORIGINAL_DATA_CHECKS', binding=b, original=origin,
                source_files=297, held_files=272, bootstrap=context.get('summary'), consumer=result,
                Root_authentication=False, Root_acceptance=None, native_acceptance=False, XS_acceptance=False,
                qualification='NOT_GRANTED', install_lifecycle='NOT_QUALIFIED', native16K='NOT_QUALIFIED',
                M2='NOT_QUALIFIED', performance='NOT_MEASURED', release='NOT_QUALIFIED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binding', 'binding-sha256', 'source-root', 'original-artifact', 'artifact-metadata', 'evidence'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args), sort_keys=True, indent=2, allow_nan=False))
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, RuntimeError) as error:
        print(json.dumps(dict(schema=1, status='REFUSED_XS_DATA', reason=type(error).__name__ + ': ' + str(error),
                              Root_authentication=False, Root_acceptance=None, native_acceptance=False, XS_acceptance=False)))
        sys.exit(2)
