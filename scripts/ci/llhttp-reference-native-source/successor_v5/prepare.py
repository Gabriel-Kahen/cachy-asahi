#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure DATA successor: exact Source85 plus explicit read-only Source namespaces."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PINS = {
    'successor_v2/prepare.py': dict(bytes=8931, sha256='9da8a325c0ca13dd1325e5e5903652f046d31678294c826c83276d1a84b2c39f'),
    'successor_v3/prepare.py': dict(bytes=10724, sha256='0d6ac04a67aaa750ff6d696c30a729433b8398c64bb7c130d4f1ef49f46c418c'),
    'successor_v4/prepare.py': dict(bytes=9536, sha256='22c6605e2dbdc17425395d10174260ea70501694c0fcd6beed179c0078fe51bb'),
}
for name, expected in MODULE_PINS.items():
    raw = (HERE.parent/name).read_bytes()
    if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != expected:
        raise ValueError('whole pinned predecessor constructor: '+name)
spec = importlib.util.spec_from_file_location('llhttp_v5_previous_data', HERE.parent/'successor_v4/prepare.py')
P4 = importlib.util.module_from_spec(spec); spec.loader.exec_module(P4)
P = P4.P
PREFIX = P.PREFIX
PARENT_MAP = dict(bytes=18199, sha256='9a4b43eedecd09e5e1edc68677620ccd17a38a1bed8218fdb429b65b04715645')
PARENT_TREE = '0a5bae34a6339354116933cad916d60cc78adda4'
PARENT_SOURCE = 'd7eb16cb611c655bc2cca65501dd30c8bdfbe03f'
CHANGED = tuple(PREFIX+n for n in ('hosted_owner.py', 'policy.json', 'owner-program.json'))
HELPER = 'source_readonly.py'
MARKER = 'source-readonly-namespace-v5.json'
HELPER_PIN = dict(bytes=3052, sha256='55c58b6e15a73339f0c901a6d379f468e39e90e81a6602651942f35162a8e9d8')
EVIDENCE_PIN = dict(bytes=13021, sha256='f99426d52dfb546cd2f1d9e2d7432d0fb62340335a04211ed1873f083cf75591')
README_PIN = dict(bytes=4120, sha256='3f47783809b7cc4a8c241e4e2603211dfdc91749b3e440915e51960ae35e834b')
REVIEW_INPUTS = ('README.md', 'evidence.DATA.json')


def parent_bodies(parent):
    parent = P.ordinary(parent)
    raw = P.read(parent/'source-map.json')
    P.need(P.pin(raw) == PARENT_MAP, 'whole exact public Source85 map')
    P.need((parent/'source-map.json').stat().st_mode & 0o777 == 0o644, 'exact public Source85 map mode')
    value = json.loads(raw)
    found = {str(n.relative_to(parent)) for n in parent.rglob('*') if n.is_file() or n.is_symlink()}
    P.need(found == set(value['files']) | {'source-map.json'} and len(found) == 85,
           'complete ordinary Source85 namespace')
    bodies = {n: P.read(parent/n) for n in sorted(found)}
    P.need(all(dict(P.pin(bodies[n]), mode=(parent/n).stat().st_mode & 0o777) == row
               and row['mode'] == 0o644 for n, row in value['files'].items()), 'whole Source85 pinned bytes and modes')
    validate_parent(bodies)
    return bodies, value


def validate_parent(bodies):
    P.need(P.pin(bodies['source-map.json']) == PARENT_MAP, 'complete retained Source85 map')
    value = json.loads(bodies['source-map.json'])
    P.need(set(bodies) == set(value['files']) | {'source-map.json'} and len(bodies) == 85
           and sum(map(len, bodies.values())) == 1120826 and P.tree(bodies) == PARENT_TREE,
           'complete Source85 inverse namespace, bytes and physical Git tree')
    P.need(all(dict(P.pin(bodies[n]), mode=0o644) == row for n, row in value['files'].items())
           and all(v is None for v in value['actual'].values()), 'whole Source85 inverse modes and NULL selectors')
    previous76 = P4.inverse(bodies)
    previous68 = P4.P3.inverse(previous76)
    P.need(len(previous76) == 76 and len(previous68) == 68 and len(P.inverse(previous68)) == 62,
           'whole predecessor85/76/68/62 inverse chain')


def projections(old):
    name = PREFIX+'hosted_owner.py'
    text = old[name].decode(); seams = {name: []}
    def replace(before, after):
        nonlocal text
        P.need(text.count(before) == 1 and after not in text, 'one exact namespace seam')
        text = text.replace(before, after)
        seams[name].append(dict(before=before, after=after))
    anchor = "s=importlib.util.spec_from_file_location('llhttp_failed_retirement_v3',HERE/'failed_retirement.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)"
    replace(anchor, anchor+"\ns=importlib.util.spec_from_file_location('llhttp_source_readonly_v5',HERE/'source_readonly.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)")
    anchor = "        argv.insert(3,'--description=cachy-llhttp-reference-owned-'+self.nonce+'-'+kind)"
    replace(anchor, anchor+"\n        argv=Q.project_service(argv,self.root,self.out,self.nonce,kind)")
    reverse = text
    for seam in reversed(seams[name]):
        P.need(reverse.count(seam['after']) == 1, 'one exact namespace inverse seam')
        reverse = reverse.replace(seam['after'], seam['before'])
    P.need(reverse.encode() == old[name], 'whole controller projection inverse')
    return {name: text.encode()}, seams


def assemble(old):
    code, seams = projections(old)
    helper = P.read(HERE/HELPER)
    P.need(P.pin(helper) == HELPER_PIN, 'whole pinned source-namespace helper custody')
    Q = P4.P3.load(HERE/HELPER, 'llhttp_v5_source_namespace_data')
    bodies = dict(old); bodies.update(code)
    policy = json.loads(old[PREFIX+'policy.json'])
    P.need('source_readonly_namespace' not in policy, 'no previous Source namespace declaration')
    policy['source_readonly_namespace'] = Q.DECLARATION
    bodies[PREFIX+'policy.json'] = P.encode(policy)
    bodies[PREFIX+HELPER] = helper
    for name in REVIEW_INPUTS:
        bodies[PREFIX+'successor-v5-'+name] = P.read(HERE/name)
    P.need(P.pin(bodies[PREFIX+'successor-v5-evidence.DATA.json']) == EVIDENCE_PIN,
           'whole pinned retained public Source85/native92 evidence DATA')
    P.need(P.pin(bodies[PREFIX+'successor-v5-README.md']) == README_PIN, 'whole pinned Source review notes')
    for name in (*CHANGED, 'source-map.json'):
        bodies['previous-v4/'+name] = old[name]
    bodies[MARKER] = P.encode(dict(
        kind='LLHTTP_SOURCE_READONLY_NAMESPACE_V5', parent_source=PARENT_SOURCE,
        parent_map=PARENT_MAP, parent_tree=PARENT_TREE, parent_files=85,
        parent_bytes=1120826, actual=None, native_pair='NOT RUN',
        effect='NOT RUN; requires next actual native attempt', Root_closure_review='PENDING',
        actual92_status='HOLD', actual92_native_pair='NOT RUN',
        actual92_cleanup_verified=True, actual92_payload_success=False,
        retroactive_acceptance=False, seams=seams, helper=HELPER_PIN,
        review_inputs={n: P.pin(bodies[PREFIX+'successor-v5-'+n]) for n in REVIEW_INPUTS}))
    bodies.pop('source-map.json'); bodies.pop(PREFIX+'owner-program.json')
    program = P.encode(dict(schema=1,
        base_source_map_sha256=json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256'],
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items()) if not n.startswith('held-source/')}))
    bodies[PREFIX+'owner-program.json'] = program
    bodies['source-map.json'] = P.encode(dict(json.loads(old['source-map.json']),
        files={n: dict(P.pin(raw), mode=0o644) for n, raw in sorted(bodies.items())}))
    return bodies


def inverse(bodies):
    additions = {MARKER, PREFIX+HELPER, *(PREFIX+'successor-v5-'+n for n in REVIEW_INPUTS)}
    old = {n: raw for n, raw in bodies.items() if n not in additions and n != 'source-map.json' and not n.startswith('previous-v4/')}
    for name in (*CHANGED, 'source-map.json'):
        old[name] = bodies['previous-v4/'+name]
    validate_parent(old)
    P.need(bodies == assemble(old), 'whole canonical successor namespace, projections, policy, helper, program and source-map')
    P.need(all(bodies[n] == raw for n, raw in old.items() if n not in (*CHANGED, 'source-map.json')),
           'all other predecessor bytes unchanged including payload, DATA, resources, retirement, workflow and held-source')
    return old


def construct(parent, output):
    parent, output = map(P.ordinary, (parent, output))
    P.need(not output.exists() and not output.is_relative_to(parent) and not parent.is_relative_to(output),
           'fresh successor output disjoint in both directions')
    old, prior = parent_bodies(parent)
    bodies = assemble(old)
    inverse(bodies)
    P.need(len(bodies) == 93 and len(bodies) < 96 and sum(map(len, bodies.values())) < 2*1024**2,
           'finite metadata namespace expansion within unchanged 96-file and 2MiB limits')
    output.mkdir(mode=0o700)
    for name, raw in bodies.items():
        path = output/name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o644)
    D = P4.P3.load(output/PREFIX/'data.py', 'llhttp_v5_closed_source_data')
    D.source(output, P.pin(bodies['source-map.json'])['sha256'])
    return dict(status='SOURCE_DATA_ONLY', files=len(bodies), bytes=sum(map(len, bodies.values())),
        tree=P.tree(bodies), source_map=P.pin(bodies['source-map.json']),
        policy=P.pin(bodies[PREFIX+'policy.json']), program=P.pin(bodies[PREFIX+'owner-program.json']),
        actual=prior['actual'], native_pair='NOT RUN', effect='NOT RUN', Root_closure_review='PENDING')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.output), indent=2, sort_keys=True))
