#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Derive one capability-spelling Source as DATA; no payload or actor execution."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import sys
import tarfile

HERE = Path(__file__).resolve().parent
FS_SHA = '7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
PARENT_SOURCE = '71246ca38e58f9f410d1f3eea15f5ddf174bb1bf'
PARENT_TREE = '119da3d2e86d305ba517a7f567c98333aeb9f872'
PARENT_MAP = dict(bytes=45788, sha256='951e947e2d717f5b97e159bf8640adcd69d8884f982a4d22377fbeadf04e0c58')
PARENT_BYTES = 80960040
INPUT_REVIEW = '31aeecaa5ef5bdae8c001940587641cd2a32acb7ed5c5c93ed0609e8eb0acc1e'
OLD_PRODUCER = dict(bytes=14274, sha256='9d4c681100328f2db7abefdc0ff894a569d3670667cf369613dd3d8ffb222b87')
OLD_CAPSULE = dict(bytes=40355840, sha256='7add94a8a16e885d70a2a2c5fc015192f1ecc4fbdea8689f2a07d54c4abd237b')
REPLACEMENTS = {
    'lifecycle-code/producer.py': 'previous-v1/lifecycle-code-producer.py',
    'lifecycle-code-map.json': 'previous-v1/lifecycle-code-map.json',
    'hosted/common.py': 'previous-v1/hosted-common.py',
    '.github/workflows/native-arm-build.yml': 'previous-v1/workflow.yml',
    '.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml': 'previous-v1/workflow.yml',
    'contract.json': 'previous-v1/contract.json',
    'inverse.json': 'previous-v1/inverse.json',
    'source-map.json': 'previous-v1/source-map.json',
}


def module(name, path, raw=None):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(path.read_bytes() if raw is None else raw, str(path), 'exec'), value.__dict__)
    return value


def filesystem():
    path = Path(os.environ.get('CACHY_PERL_INSTALLED_V2_FILESYSTEM', HERE.parent/'filesystem.py'))
    if not path.is_absolute() or path != path.resolve() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('ordinary absolute passive filesystem helper required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FS_SHA:
        raise ValueError('exact existing passive filesystem helper required')
    return module('perl_installed_v2_passive_filesystem', path, raw)


fs = filesystem()
edit = module('perl_installed_v2_capability_edit', HERE/'capabilities.py')


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def unpack(raw, expected):
    fs.need(fs.pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')}, 'whole capsule identity')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            fs.need(member.isfile() and member.name.startswith('capsule/') and not member.sparse,
                    'only ordinary capsule DATA members')
            name = member.name[8:]
            fs.relative(name)
            fs.need(name not in result and name in expected['members'] and member.uid == member.gid == 0
                    and member.mtime == 1791748800 and member.mode == 0o444 and 0 < member.size <= 32*1024**2,
                    'exact protected capsule member metadata')
            with archive.extractfile(member) as stream:
                body = stream.read(member.size+1)
            fs.need(len(body) == member.size and dict(**fs.pin(body), mode=member.mode) == expected['members'][name],
                    'complete exact capsule member')
            result[name] = (body, member.mode)
    fs.need(set(result) == set(expected['members']) and len(result) == 20, 'complete finite capsule')
    manifest = json.loads(result['source-map.json'][0])
    fs.need(manifest['files'] == {n: fs.pin(b) for n, (b, _m) in result.items() if n != 'source-map.json'},
            'complete inner capsule manifest')
    return result


def pack(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:', format=tarfile.PAX_FORMAT) as archive:
        for name, (body, mode) in sorted(files.items()):
            fs.relative(name)
            item = tarfile.TarInfo('capsule/'+name)
            item.uid = item.gid = 0
            item.mtime, item.mode, item.size = 1791748800, mode, len(body)
            archive.addfile(item, io.BytesIO(body))
    return output.getvalue()


def parent(root):
    fs.MAX_FILES = 320
    files = fs.snapshot(root)
    fs.need(len(files) == 232 and sum(len(b) for b, _m in files.values()) == PARENT_BYTES
            and fs.pin(files['source-map.json'][0]) == PARENT_MAP and fs.tree(files) == PARENT_TREE,
            'complete exact parent232 Source required')
    manifest = json.loads(files['source-map.json'][0])
    fs.need(manifest['files'] == fs.descriptors({n: v for n, v in files.items() if n != 'source-map.json'})
            and all(v is None for v in manifest['actual'].values()), 'parent closed map and NULL selectors')
    return files


def restore(files):
    """Rebuild every parent leaf, including capsule, without an archived40MiB copy."""
    record = json.loads(files['v2-inverse.json'][0])
    expected = record['parent_files']
    result = {n: files[REPLACEMENTS.get(n, n)] for n in expected if n != 'lifecycle-capsule.tar'}
    current_contract = json.loads(files['contract.json'][0])
    contents = unpack(files['lifecycle-capsule.tar'][0], current_contract['capsule'])
    contents['producer.py'] = (files['previous-v1/lifecycle-code-producer.py'][0], 0o444)
    contents['source-map.json'] = (files['previous-v1/capsule-source-map.json'][0], 0o444)
    result['lifecycle-capsule.tar'] = (pack(contents), expected['lifecycle-capsule.tar']['mode'])
    fs.need(fs.descriptors(result) == expected and fs.tree(result) == PARENT_TREE,
            'full parent232 inverse bytes/modes/tree')
    return result


def render(before):
    fs.need(len(before) == 232 and fs.tree(before) == PARENT_TREE, 'exact232 input tree')
    old_contract = json.loads(before['contract.json'][0])
    old_map = json.loads(before['source-map.json'][0])
    actual = old_map['actual']
    fs.need(all(v is None for v in actual.values()) and old_contract['input_review_sha256'] == INPUT_REVIEW,
            'unchanged reviewed prerequisites; no runtime grant')
    producer = before['lifecycle-code/producer.py'][0]
    fs.need(fs.pin(producer) == OLD_PRODUCER and fs.pin(before['lifecycle-capsule.tar'][0]) == OLD_CAPSULE,
            'exact old producer and capsule')
    updated = edit.patch(producer)
    fs.need(edit.inverse(updated) == producer, 'only declared producer edit')
    files = dict(before)
    for old, archived in REPLACEMENTS.items():
        fs.need(archived not in before, 'fresh explicit inverse records')
        if archived in files:
            fs.need(files[archived] == before[old], 'identical workflow archive')
        files[archived] = before[old]
    contents = unpack(before['lifecycle-capsule.tar'][0], old_contract['capsule'])
    fs.need(contents['producer.py'][0] == producer, 'both producer bodies were identical')
    files['previous-v1/capsule-source-map.json'] = (contents['source-map.json'][0], 0o644)
    contents['producer.py'] = (updated, 0o444)
    inner = json.loads(contents['source-map.json'][0])
    inner['files']['producer.py'] = fs.pin(updated)
    contents['source-map.json'] = (encode(inner), 0o444)
    files['lifecycle-code/producer.py'] = (updated, 0o644)
    code = json.loads(before['lifecycle-code-map.json'][0])
    code['files']['producer.py'] = dict(**fs.pin(updated), mode=0o644)
    files['lifecycle-code-map.json'] = (encode(code), 0o644)
    old_component = fs.pin(before['lifecycle-code-map.json'][0])['sha256']
    new_component = fs.pin(files['lifecycle-code-map.json'][0])['sha256']
    common = before['hosted/common.py'][0]
    fs.need(common.count(old_component.encode()) == 1, 'one exact component-map binding')
    files['hosted/common.py'] = (common.replace(old_component.encode(), new_component.encode()), 0o644)
    old_common = fs.pin(common)['sha256'].encode()
    new_common = fs.pin(files['hosted/common.py'][0])['sha256'].encode()
    for name in ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml'):
        body = before[name][0]
        fs.need(body.count(old_common) == 1, 'one exact workflow common pin')
        files[name] = (body.replace(old_common, new_common), 0o644)
    capsule = pack(contents)
    files['lifecycle-capsule.tar'] = (capsule, 0o644)
    contract = json.loads(encode(old_contract))
    contract['capsule'] = dict(**fs.pin(capsule), members=fs.descriptors(contents),
                               source_map_sha256=fs.pin(contents['source-map.json'][0])['sha256'])
    contract['adapter_revision'] = dict(kind='PERL_INSTALLED_DOCKER_CAPABILITY_NAMES_V2',
        parent_source=PARENT_SOURCE, parent_tree=PARENT_TREE, unchanged_old_core_files=11,
        revised_core_files=['producer.py'], old_producer=OLD_PRODUCER, new_producer=fs.pin(updated),
        old_core_commit=old_contract['held_code_commit'], old_core_claim='HISTORICAL_PARENT_NOT_ALL12_UNCHANGED',
        kernel_actor='EXACT_UNCHANGED_PARENT_BYTES', raw_inspect='PRESERVED_WITHOUT_NORMALIZATION',
        runtime_grant=False)
    files['contract.json'] = (encode(contract), 0o644)
    original_inverse = json.loads(before['inverse.json'][0])
    original_inverse['additions'] = sorted(set(files)-set(original_inverse['held']) | {'v2-inverse.json', 'source-map.json'})
    files['inverse.json'] = (encode(original_inverse), 0o644)
    inverse = dict(schema=1, operation='RESTORE_EXACT_PARENT232_WITH_DETERMINISTIC_CAPSULE_INVERSE',
        parent_source=PARENT_SOURCE, parent_tree=PARENT_TREE, parent_files=fs.descriptors(before),
        replacements=REPLACEMENTS, capsule_restore='REPACK_CURRENT_MEMBERS_WITH_ARCHIVED_OLD_PRODUCER_AND_INNER_MAP',
        actual=actual)
    files['v2-inverse.json'] = (encode(inverse), 0o644)
    files['source-map.json'] = (encode(dict(old_map, files=fs.descriptors({n: v for n, v in files.items() if n != 'source-map.json'}))), 0o644)
    fs.need(restore(files) == before, 'complete inverse to232 parent')
    fs.need(files['input-review.json'] == before['input-review.json'] and
            files['lifecycle-code/actor.py'] == before['lifecycle-code/actor.py'] and
            files['lifecycle-code/domain.json'] == before['lifecycle-code/domain.json'] and
            files['policy.json'] == before['policy.json'], 'no actor/resource/input-policy changes')
    fs.need(len(files) <= 256 and sum(len(b) for b, _m in files.values()) <= 96*1024**2,
            'finite successor Source')
    return files


def facts(files):
    return dict(status='SOURCE_DATA_ONLY_NO_ACTOR_OR_RUNTIME_ACCEPTANCE', files=len(files),
        bytes=sum(len(b) for b, _m in files.values()), tree=fs.tree(files),
        source_map=fs.pin(files['source-map.json'][0]), producer=fs.pin(files['lifecycle-code/producer.py'][0]),
        capsule=fs.pin(files['lifecycle-capsule.tar'][0]), actual=json.loads(files['source-map.json'][0])['actual'])


def main():
    resource.setrlimit(resource.RLIMIT_AS, (512*1024**2, 512*1024**2))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-source', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    files = render(parent(args.previous_source))
    if args.output is not None:
        fs.need(not args.output.is_relative_to(args.previous_source) and
                not args.previous_source.is_relative_to(args.output) and
                not args.output.is_relative_to(HERE), 'disjoint Source output')
        fs.publish(files, args.output)
    print(json.dumps(facts(files), sort_keys=True))


if __name__ == '__main__':
    main()
