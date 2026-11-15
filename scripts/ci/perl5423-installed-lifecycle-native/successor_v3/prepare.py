#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""One finite241-parent retained-result Source successor, as DATA only."""
import argparse
import importlib.util
import json
from pathlib import Path
import resource
import sys

HERE = Path(__file__).resolve().parent
BASE_SHA = '932bf8a61aaa54b20967913746625bcb3dc351dd443bbe93d6d2b27b24ccfb7a'
PARENT_SOURCE = 'b4079a8a478afb0df8e634b555b3d2955a97bb9b'
PARENT_TREE = '2267627b5dd03ac09e71ce8819e76bce160faf65'
PARENT_MAP = dict(bytes=47304, sha256='34d0b92316fd3c3aac69fb947b3b31ef14474d0128d10f7a0b1684495cc14175')
PARENT_BYTES = 81151225
REPLACEMENTS = {
    'lifecycle-code/actor.py': 'previous-v2/lifecycle-code-actor.py',
    'lifecycle-code/producer.py': 'previous-v2/lifecycle-code-producer.py',
    'lifecycle-code-map.json': 'previous-v2/lifecycle-code-map.json',
    'hosted/common.py': 'previous-v2/hosted-common.py',
    '.github/workflows/native-arm-build.yml': 'previous-v2/workflow.yml',
    '.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml': 'previous-v2/workflow.yml',
    'contract.json': 'previous-v2/contract.json',
    'inverse.json': 'previous-v2/inverse.json',
    'source-map.json': 'previous-v2/source-map.json',
}
RETENTION = dict(schema=1, kind='OWNED_CONTAINER_LAYER_RESULT_V3',
    parent='/cachy-asahi-perl-lifecycle', path='/cachy-asahi-perl-lifecycle/result',
    report_field='retained_output', parent_absent_before_entry=True, parent_mode=0o700, result_mode=0o700, uid=0, gid=0,
    storage='EXISTING_OWNED_WRITABLE_CONTAINER_LAYER_NOT_TMPFS_OR_HOST_BIND',
    scratch='/work', scratch_tmpfs_unchanged=True, export_after_natural_exit=True,
    tar_basename='result', export_bytes=64*1024**2, report_bytes=16*1024**2,
    max_result_members_exclusive=160, host_mounts_added=0, capabilities_added=0,
    retirement='REMOVED_ONLY_WITH_EXACT_OWNED_CONTAINER',
    scope='DECLARED_SOURCE_DOMAIN_NOT_RUNTIME_QUALIFICATION')


def module(name, path, expected=None):
    raw = path.read_bytes()
    if expected is not None:
        import hashlib
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('held passive successor helper changed')
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


base = module('held_v2_lifecycle_DATA_constructor', HERE.parent/'successor_v2/prepare.py', BASE_SHA)
fs, encode = base.fs, base.encode
edit = module('installed_retention_v3_edits', HERE/'edits.py')


def parent(root):
    fs.MAX_FILES = 320
    files = fs.snapshot(root)
    fs.need(len(files) == 241 and sum(len(b) for b, _m in files.values()) == PARENT_BYTES
            and fs.pin(files['source-map.json'][0]) == PARENT_MAP and fs.tree(files) == PARENT_TREE,
            'complete exact closed241 parent Source required')
    fs.need(base.restore(files) and json.loads(files['source-map.json'][0])['files'] ==
            fs.descriptors({n: v for n, v in files.items() if n != 'source-map.json'}), 'parent241 closed map and232 inverse')
    return files


def restore(files):
    record = json.loads(files['v3-inverse.json'][0])
    expected = record['parent_files']
    result = {n: files[REPLACEMENTS.get(n, n)] for n in expected if n != 'lifecycle-capsule.tar'}
    current = base.unpack(files['lifecycle-capsule.tar'][0], json.loads(files['contract.json'][0])['capsule'])
    for name in ('actor.py','producer.py'):
        current[name] = (files['previous-v2/lifecycle-code-'+name][0], 0o444)
    current['source-map.json'] = (files['previous-v2/capsule-source-map.json'][0], 0o444)
    result['lifecycle-capsule.tar'] = (base.pack(current), expected['lifecycle-capsule.tar']['mode'])
    fs.need(fs.descriptors(result) == expected and fs.tree(result) == PARENT_TREE,
            'complete241 inverse bytes/modes/tree with reconstructed capsule')
    return result


def render(before):
    fs.need(len(before) == 241 and fs.tree(before) == PARENT_TREE, 'exact241 source input')
    old_contract = json.loads(before['contract.json'][0])
    manifest = json.loads(before['source-map.json'][0])
    actual = manifest['actual']
    fs.need(all(v is None for v in actual.values()), 'Source selectors remain NULL')
    actors = {name: before['lifecycle-code/'+name][0] for name in ('actor.py','producer.py')}
    updated = dict(actor=edit.actor(actors['actor.py']), producer=edit.producer(actors['producer.py']))
    fs.need(edit.actor_inverse(updated['actor']) == actors['actor.py'] and
            edit.producer_inverse(updated['producer']) == actors['producer.py'], 'only two declared output edits')
    files = dict(before)
    for name, archived in REPLACEMENTS.items():
        fs.need(archived not in before, 'fresh v3 inverse namespace')
        if archived in files:
            fs.need(files[archived] == before[name], 'identical workflow archive')
        files[archived] = before[name]
    contents = base.unpack(before['lifecycle-capsule.tar'][0], old_contract['capsule'])
    files['previous-v2/capsule-source-map.json'] = (contents['source-map.json'][0], 0o644)
    inner = json.loads(contents['source-map.json'][0])
    code = json.loads(before['lifecycle-code-map.json'][0])
    for name in ('actor.py','producer.py'):
        fs.need(contents[name][0] == actors[name], 'identical parent core/capsule body')
        body = updated[name.removesuffix('.py')]
        contents[name] = (body, 0o444)
        inner['files'][name] = fs.pin(body)
        files['lifecycle-code/'+name] = (body, 0o644)
        code['files'][name] = dict(**fs.pin(body), mode=0o644)
    contents['source-map.json'] = (encode(inner), 0o444)
    files['lifecycle-code-map.json'] = (encode(code), 0o644)
    common = before['hosted/common.py'][0]
    old_code_pin = fs.pin(before['lifecycle-code-map.json'][0])['sha256'].encode()
    fs.need(common.count(old_code_pin) == 1, 'one component map binding')
    files['hosted/common.py'] = (common.replace(old_code_pin, fs.pin(files['lifecycle-code-map.json'][0])['sha256'].encode()), 0o644)
    old_common = fs.pin(common)['sha256'].encode()
    new_common = fs.pin(files['hosted/common.py'][0])['sha256'].encode()
    for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml'):
        fs.need(before[name][0].count(old_common) == 1, 'one common workflow binding')
        files[name] = (before[name][0].replace(old_common,new_common), 0o644)
    capsule = base.pack(contents)
    files['lifecycle-capsule.tar'] = (capsule, 0o644)
    contract = json.loads(encode(old_contract))
    contract['prior_adapter_revision_v2'] = contract.pop('adapter_revision')
    contract['adapter_revision'] = dict(kind='PERL_INSTALLED_RETAINED_RESULT_LAYER_V3',
        parent_source=PARENT_SOURCE, parent_tree=PARENT_TREE, unchanged_parent_core_files=10,
        revised_core_files=['actor.py','producer.py'],
        old_bodies={name:fs.pin(body) for name,body in actors.items()},
        new_bodies={name+'.py':fs.pin(body) for name,body in updated.items()},
        transaction_hooks_trust_resources='EXACT_UNCHANGED_PARENT_POLICY',
        retention=RETENTION, runtime_grant=False)
    contract['capsule'] = dict(**fs.pin(capsule), members=fs.descriptors(contents),
        source_map_sha256=fs.pin(contents['source-map.json'][0])['sha256'])
    files['contract.json'] = (encode(contract), 0o644)
    files['result-retention-v3.json'] = (encode(RETENTION), 0o644)
    original = json.loads(before['inverse.json'][0])
    original['additions'] = sorted(set(files)-set(original['held']) | {'v3-inverse.json','source-map.json'})
    files['inverse.json'] = (encode(original), 0o644)
    files['v3-inverse.json'] = (encode(dict(schema=1, operation='RESTORE_EXACT241_FROM_RETAINED_RESULT_V3',
        parent_source=PARENT_SOURCE, parent_tree=PARENT_TREE, parent_files=fs.descriptors(before),
        replacements=REPLACEMENTS, capsule_inverse='OLD_ACTOR_PRODUCER_INNER_MAP_DETERMINISTIC_REPACK', actual=actual)), 0o644)
    files['source-map.json'] = (encode(dict(manifest,files=fs.descriptors({n:v for n,v in files.items() if n!='source-map.json'}))), 0o644)
    fs.need(restore(files) == before, 'full241 inverse')
    for name in ('policy.json','input-review.json','lifecycle-code/domain.json','lifecycle-code/common.py','lifecycle-code/probe.pl'):
        fs.need(files[name] == before[name], 'unchanged transaction/trust/resources/domain: '+name)
    fs.need(len(files) <= 320 and sum(len(b) for b,_m in files.values()) <= 96*1024**2, 'bounded finite successor')
    return files


def facts(files):
    return dict(status='SOURCE_DATA_ONLY_NO_INSTALLED_ACCEPTANCE',files=len(files),
        bytes=sum(len(b) for b,_m in files.values()),source_map=fs.pin(files['source-map.json'][0]),
        tree=fs.tree(files),capsule=fs.pin(files['lifecycle-capsule.tar'][0]),
        bodies={name:fs.pin(files['lifecycle-code/'+name][0]) for name in ('actor.py','producer.py')},
        retention=RETENTION,actual=json.loads(files['source-map.json'][0])['actual'])


def main():
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-source',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(facts(render(parent(args.previous_source))),sort_keys=True))


if __name__ == '__main__':
    main()
