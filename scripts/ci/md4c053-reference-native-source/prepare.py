#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Construct a bounded md4c provider Source; never publish or start an actor."""
import argparse
import ast
import base64
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
FIXED = json.loads((HERE/'inputs.json').read_bytes())
s = importlib.util.spec_from_file_location('md4c_source_data', HERE/'source_data.py')
P = importlib.util.module_from_spec(s); s.loader.exec_module(P)
pin = P.pin
PREFIX = 'scripts/ci/llhttp-reference-native-source/owner/'
BASE = 'held-source/scripts/ci/llhttp-reference-native-source/base/'
MARKER = P.MARKER
OLD_WF = '.github/workflows/native-arm-llhttp-pinned-input-source.yml'
NEW_WF = '.github/workflows/native-arm-md4c053-reference-source.yml'
CHANGED = (MARKER, 'source-map.json', OLD_WF, *(PREFIX+n for n in
    ('payload.py', 'hosted_owner.py', 'public_evidence.py', 'policy.json', 'owner-program.json')))
RECIPE_FILES = ('PKGBUILD', '.SRCINFO', 'smoke.sh', 'smoke.c')

# Keep the historical finisher byte-identical and change only the V2 dependency table.
LEGACY_ELFS = b"""ELFS = {
    'usr/lib/libmd4c.so.0.5.3': ('libmd4c.so.0', {'libc.so.6'}),
    'usr/lib/libmd4c-html.so.0.5.3': ('libmd4c-html.so.0', {'libmd4c.so.0', 'libc.so.6'}),
    'usr/bin/md2html': (None, {'libmd4c-html.so.0', 'libmd4c.so.0', 'libc.so.6'}),
}"""
CORRECTED_ELFS = b"""# AArch64 stack protection resolves __stack_chk_guard in the glibc loader.
GLIBC_NEEDED = frozenset(('libc.so.6', 'ld-linux-aarch64.so.1'))
# The CLI reaches the core through the HTML library's direct dependency.
ELFS = {
    'usr/lib/libmd4c.so.0.5.3': ('libmd4c.so.0', GLIBC_NEEDED),
    'usr/lib/libmd4c-html.so.0.5.3': ('libmd4c-html.so.0', GLIBC_NEEDED | {'libmd4c.so.0'}),
    'usr/bin/md2html': (None, GLIBC_NEEDED | {'libmd4c-html.so.0'}),
}"""

FINISHER_PINS = {
    1: 'b8e1a9f257dcbf3ceb75bad9ceb78fcd6d212cff71caab2a939860054870bff7',
    2: '4c17efdce5aa6d32b86f95de519347abf0da1243217d5d79ec3bac8cc2c9f80a',
}
FACTORY_V2 = dict(kind='MD4C053_NATIVE_SOURCE_FACTORY_V2', entry='prepare.py', source=dict(
    FIXED['factory']['source'], bytes=2035698, tree='2572f523ae0cffbcc29b14c0995ff7abea800d87',
    map=dict(bytes=20201, sha256='5dc52d541e9787164dba097142ac536adc88bc542fb91391f4fb818ad8d8ba26'),
    program=dict(bytes=9674, sha256='ef3c6a3ae253c8eb61845ad4aeaa4920ef6af84eb261850e21b5f1021543b917')))


def finisher_for(version):
    P.need(version in FINISHER_PINS, 'explicit md4c factory version required')
    held = P.read(HERE/'finish_pair.py')
    P.need(pin(held)['sha256'] == FINISHER_PINS[1], 'exact historical V1 finisher')
    if version == 1:
        return held
    P.need(held.count(LEGACY_ELFS) == 1, 'one exact V1 dependency-table preimage')
    corrected = held.replace(LEGACY_ELFS, CORRECTED_ELFS, 1)
    P.need(pin(corrected)['sha256'] == FINISHER_PINS[version], 'exact corrected V2 finisher')
    return corrected


def factory_for(version):
    P.need(version in FINISHER_PINS, 'explicit md4c factory version required')
    return FIXED['factory'] if version == 1 else FACTORY_V2


def row(raw):
    return dict(pin(raw), mode=0o644, body_base64=base64.b64encode(raw).decode())


def unpack(value):
    P.need(type(value) is dict and set(value) == {'bytes', 'sha256', 'mode', 'body_base64'}
           and type(value['bytes']) is int and 0 < value['bytes'] <= 2*1024**2
           and value['mode'] == 0o644 and type(value['body_base64']) is str
           and len(value['body_base64']) <= 3*1024**2, 'bounded complete encoded source member')
    raw = base64.b64decode(value['body_base64'], validate=True)
    P.need(pin(raw) == {k:value[k] for k in ('bytes', 'sha256')}, 'whole encoded member')
    return raw


def validate_parent(old):
    P.validate(old, {k: FIXED['parent'][k] for k in ('files', 'bytes', 'tree', 'map')})
    P.need(pin(old[BASE+'runtime/scripts/ci/inputs.lock.json']) == FIXED['all501']
           and pin(old[BASE+'expected349.lock']) == FIXED['expected349'], 'exact all501 and349 locks')
    P.restore(old, FIXED['predecessors'])


def license_body(archive):
    total = 0; found = {}; names = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r|gz') as stream:
        for member in stream:
            name = Path(member.name)
            P.need(not name.is_absolute() and '..' not in name.parts and str(name) not in names
                   and len(names) < 512 and (member.isfile() or member.isdir())
                   and 0 <= member.size <= 8*1024**2, 'finite ordinary pinned source archive')
            names.add(str(name)); total += member.size
            P.need(total <= 16*1024**2, 'finite complete source expansion')
            if str(name) == 'md4c-'+FIXED['archive']['commit']+'/LICENSE.md':
                with stream.extractfile(member) as f: found['license'] = f.read(member.size+1)
                P.need(len(found['license']) == member.size, 'whole original MIT license')
    P.need(set(found) == {'license'}, 'original upstream license required')
    return found['license']


def bundle_for(old, recipe, archive, *, factory_version=1):
    recipe = P.ordinary(recipe)
    found = {p.name for p in recipe.iterdir() if p.is_file()}
    P.need(found == set(FIXED['recipe_files']) and all(not p.is_symlink() and p.is_file()
           for p in recipe.iterdir()), 'complete frozen source295 recipe snapshot')
    for name, expected in FIXED['recipe_files'].items():
        P.need(pin(P.read(recipe/name)) == expected, 'frozen recipe295 body: '+name)
    raw = P.read(archive)
    P.need(pin(raw) == {k:FIXED['archive'][k] for k in ('bytes', 'sha256')}, 'whole pinned md4c source archive')
    bodies = {'recipe/'+n:P.read(recipe/n) for n in RECIPE_FILES}
    bodies['recipe/'+FIXED['archive']['filename']] = raw
    bodies.update({'finish_pair.py':finisher_for(factory_version),
                   'expected349.lock':old[BASE+'expected349.lock']})
    bodies['reviewed-inputs.json'] = P.encode({n[7:]:pin(b)['sha256'] for n,b in sorted(bodies.items()) if n.startswith('recipe/')})
    bodies['recipe-pin.json'] = recipe_record(raw)
    return {n:row(b) for n,b in sorted(bodies.items())}


def recipe_record(archive):
    return P.encode(dict(recipe_commit=FIXED['recipe_commit'], upstream=FIXED['archive'],
        origin='PROJECT_SOURCE_PROVIDER_NOT_OFFICIAL_ALARM_BINARY',
        license=dict(path='usr/share/licenses/md4c/LICENSE.md', **pin(license_body(archive))),
        package=dict(name='md4c', version='0.5.3-1', arch='aarch64', depends=['glibc']),
        native_build=None, signature=None, Root_acceptance=None))


def validate_bundle(bundle, old, *, factory_version=1):
    runtime = {}; exec(compile(P.read(HERE/'runtime.py'), str(HERE/'runtime.py'), 'exec'), runtime)
    bodies = runtime['decode_bundle'](bundle)
    for name in RECIPE_FILES:
        P.need(pin(bodies['recipe/'+name]) == FIXED['recipe_files'][name], 'fixed recipe bundle body')
    archive = bodies['recipe/'+FIXED['archive']['filename']]
    P.need(pin(archive) == {k:FIXED['archive'][k] for k in ('bytes', 'sha256')}, 'fixed source bundle archive')
    P.need(bodies['expected349.lock'] == old[BASE+'expected349.lock']
           and bodies['finish_pair.py'] == finisher_for(factory_version), 'exact native lock and versioned finisher code')
    reviewed = {n[7:]:pin(b)['sha256'] for n,b in bodies.items() if n.startswith('recipe/')}
    P.need(bodies['reviewed-inputs.json'] == P.encode(reviewed), 'complete reviewed build recipe')
    P.need(bodies['recipe-pin.json'] == recipe_record(archive), 'complete exact project provider provenance')
    return bodies


def assemble(old, bundle, *, factory_version=1):
    validate_parent(old); validate_bundle(bundle, old, factory_version=factory_version)
    new = dict(old)
    payload = new[PREFIX+'payload.py'].decode()
    before = "    exec(compile(N.project_entry(D.projected_entry(D.read(entry_path))),str(entry_path),'exec'),namespace)"
    after = '''    provider = D.decode(D.read(root/'inner-public-retention-v6.json'))
    D.need(provider['kind'] == 'MD4C053_NATIVE_SOURCE_CASE_V1', 'explicit md4c provider case')
    import base64, types, hashlib
    code = base64.b64decode(provider['runtime']['body_base64'], validate=True)
    D.need(D.pin(code) == {k:provider['runtime'][k] for k in ('bytes','sha256')}, 'whole source-bound provider hook')
    hook = types.ModuleType('md4c053_source_provider')
    exec(compile(code,'<source-bound-md4c-provider>','exec'),hook.__dict__)
    entry = N.project_entry(D.projected_entry(D.read(entry_path)).encode())
    D.need(entry.count(b'PASS_CURRENT_LLHTTP_REFERENCE') == 4, 'exact inherited result-label seams')
    entry = entry.replace(b'PASS_CURRENT_LLHTTP_REFERENCE',b'PASS_CURRENT_MD4C053_REFERENCE')
    exec(compile(entry,str(entry_path),'exec'),namespace)'''
    P.need(payload.count(before) == 1, 'one exact admitted held-entry seam')
    payload = payload.replace(before, after)
    before = "    X.phase('inner-pair')"
    P.need(payload.count(before) == 1, 'one post-admission provider installation seam')
    payload = payload.replace(before, "    hook.install(namespace,root,provider['bundle'])\n"+before)
    # Change only the payload return literal; keep the projector's before-label intact.
    payload = payload.replace("report['status'] == 'PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY'", "report['status'] == 'PASS_CURRENT_MD4C053_REFERENCE_NATIVE_PAIR_ONLY'")
    new[PREFIX+'payload.py'] = payload.encode()
    for name in ('hosted_owner.py', 'public_evidence.py'):
        new[PREFIX+name] = old[PREFIX+name].replace(b'PASS_CURRENT_LLHTTP_REFERENCE', b'PASS_CURRENT_MD4C053_REFERENCE')
    new[PREFIX+'public_evidence.py'] = new[PREFIX+'public_evidence.py'].replace(
        b"PACKAGE = 'cachy-asahi-llhttp-reference-9.3.1-1-aarch64'", b"PACKAGE = 'md4c-0.5.3-1-aarch64'")
    workflow = P.read(HERE/'workflow.yml.in')
    P.need(workflow == old[OLD_WF].replace(b'name: native-arm-llhttp-pinned-input-source', b'name: native-arm-md4c053-reference-source').replace(b'Admitted existing-host XZ-only llhttp reference pair', b'Admitted existing-host XZ-only md4c 0.5.3 provider pair'), 'only explicit md4c workflow/step names change')
    new.pop(OLD_WF); new[NEW_WF] = workflow
    exporter = {}; exec(compile(new[PREFIX+'public_evidence.py'], '<md4c-public-catalog>', 'exec'), exporter)
    policy = json.loads(old[PREFIX+'policy.json'])
    policy['inner_public_retention'] = exporter['DECLARATION']
    policy['md4c_provider_case'] = dict(package='md4c-0.5.3-1-aarch64.pkg.tar.xz',
        recipe_commit=FIXED['recipe_commit'], source=FIXED['archive'],
        baseline349_unchanged=True, official_binary='HOLD', global_installation=False,
        signing=None, Root_project_provider_admission=None, native_acceptance=None)
    new[PREFIX+'policy.json'] = P.encode(policy)
    before = P.encode({n:row(old[n]) for n in CHANGED})
    new[MARKER] = P.encode(dict(kind='MD4C053_NATIVE_SOURCE_CASE_V1', parent=FIXED['parent'],
        before=dict(pin(before), compression='xz', body_base64=base64.b64encode(lzma.compress(before, preset=6)).decode()),
        runtime=row(P.read(HERE/'runtime.py')), bundle=bundle, actual=None, Root_authority=None,
        native_pair='NOT RUN', signing='NOT RUN'))
    for name in ('payload.py','hosted_owner.py','public_evidence.py'): ast.parse(new[PREFIX+name])
    new.pop('source-map.json'); new.pop(PREFIX+'owner-program.json')
    new[PREFIX+'owner-program.json'] = P.encode(dict(schema=1,
        base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],
        files={n:dict(pin(b), mode=0o644) for n,b in sorted(new.items()) if not n.startswith('held-source/')}))
    new['source-map.json'] = P.encode(dict(json.loads(old['source-map.json']),
        files={n:dict(pin(b), mode=0o644) for n,b in sorted(new.items())}))
    P.need(len(new) == 95 and sum(map(len,new.values())) < 2*1024**2, 'unchanged95leaf/2MiB source ceiling')
    return new


def inverse(new, *, factory_version=1):
    v = json.loads(new[MARKER]); packed = v['before']
    P.need(v['kind'] == 'MD4C053_NATIVE_SOURCE_CASE_V1' and v['parent'] == FIXED['parent']
           and packed['compression'] == 'xz' and 0 < packed['bytes'] <= 2*1024**2
           and len(packed['body_base64']) < 2*1024**2, 'whole bounded inverse frame')
    decoder = lzma.LZMADecompressor(memlimit=128*1024**2)
    raw = decoder.decompress(base64.b64decode(packed['body_base64'],validate=True), max_length=2*1024**2+1)
    P.need(decoder.eof and not decoder.unused_data and pin(raw) == {k:packed[k] for k in ('bytes','sha256')}, 'complete finite inverse bytes')
    before = json.loads(raw); P.need(set(before) == set(CHANGED), 'all changed before bodies')
    old = dict(new); old.pop(NEW_WF)
    for n,r in before.items(): old[n] = unpack(r)
    validate_parent(old)
    P.need(new == assemble(old, v['bundle'], factory_version=factory_version), 'whole exact md4c source projection/inverse')
    return old


def verify_source(root, *, factory_version=1):
    bodies = P.physical(root)
    factory = factory_for(factory_version)
    binding = factory['source']
    P.validate(bodies, {k: binding[k] for k in ('files', 'bytes', 'tree', 'map')})
    for path, key in ((PREFIX+'policy.json', 'policy'), (PREFIX+'owner-program.json', 'program'),
                      (NEW_WF, 'workflow')):
        P.need(pin(bodies[path]) == binding[key], 'exact factory output: '+path)
    P.need(binding['workflow_path'] == NEW_WF, 'exact factory workflow path')
    inverse(bodies, factory_version=factory_version)
    factory_pin = pin(P.read(HERE/'inputs.json')) if factory_version == 1 else pin(P.encode(factory))
    return dict(status='MD4C053_NATIVE_BUILD_SOURCE_READY_UNISSUED',
        files=binding['files'], bytes=binding['bytes'], tree=binding['tree'],
        source_map=binding['map'], policy=binding['policy'], program=binding['program'],
        workflow_path=NEW_WF, workflow=binding['workflow'], full_fixed241_and_predecessor_inverse=True,
        factory=dict(kind=factory['kind'], entry=factory['entry'], binding=factory_pin),
        all501=FIXED['all501'], expected349=FIXED['expected349'],
        actual=json.loads(bodies['source-map.json'])['actual'], Root_authority=None, Root_registration=None,
        native_pair=None, signing=None, Root_acceptance=None)


def construct(parent, recipe, archive, output, *, factory_version=1):
    parent, recipe, archive, output = map(P.ordinary, (parent, recipe, archive, output))
    P.need(not output.exists() and all(not output.is_relative_to(path) and not path.is_relative_to(output)
           for path in (parent, recipe, archive)), 'new disjoint provider source')
    old = P.physical(parent)
    bundle = bundle_for(old, recipe, archive, factory_version=factory_version)
    new = assemble(old, bundle, factory_version=factory_version)
    binding = factory_for(factory_version)['source']
    P.validate(new, {k: binding[k] for k in ('files', 'bytes', 'tree', 'map')})
    output.mkdir(mode=0o700)
    for n,raw in new.items():
        p = output/n
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as stream:
            stream.write(raw)
        p.chmod(0o644)
    return verify_source(output, factory_version=factory_version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-source', type=Path)
    parser.add_argument('--factory-version', type=int, choices=(1, 2), default=1)
    for name in ('parent','recipe','archive','output'):
        parser.add_argument('--'+name, type=Path)
    args = parser.parse_args()
    operands = (args.parent, args.recipe, args.archive, args.output)
    if args.verify_source is not None and not any(operands):
        result = verify_source(args.verify_source, factory_version=args.factory_version)
    elif args.verify_source is None and all(operands):
        result = construct(*operands, factory_version=args.factory_version)
    else:
        parser.error('supply --verify-source or all four construction operands')
    print(json.dumps(result, sort_keys=True, indent=2))
