#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure Source93 canonical caller DATA; no Root issuance or operational entry."""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
PREFIX = 'scripts/ci/llhttp-reference-native-source/owner/'
OPERATOR = 'packet/operator-DRAFT/llhttp_once.py'
PRIMITIVE = 'packet/operator-DRAFT/llhttp_dispatch_once.py'
PARENT_SEAL = dict(bytes=4773, sha256='9c6c4b27dde8fca07a99fb1d49e61e6a9072a2d7b4229ca082a75521bbd873ea')
SOURCE_TUPLE = dict(tree='424259eb3868b802b9aa2ae4dbeceff169fce7fd', source_files=93, source_bytes=1204391,
    source_map=dict(bytes=19821, sha256='4abcbcd541e3bf3ad652ff09cd2a813ce5a276bc58fade63cc2801a248c349c7'),
    owner_program=dict(bytes=9294, sha256='2d32d984e81c5ba94e60c4071f331e5d0a0ecb6869b95a6ce4067cdfcf6db4f7'),
    policy=dict(bytes=3788, sha256='1e8939236b0db99d5ca9b9f1e1b2c9e9d28231186dd26f3fe2e7a678ab0a3132'),
    workflow_body=dict(bytes=6201, sha256='2ba05dea048406382cf0285c1a73f56b8671c8a322ffd2636ae41ddc64d82c99'))
CANDIDATE_SOURCE = '8f6370a35215496c0e6c10922929028f5146644b'
CANDIDATE_REF = 'codex/llhttp-reference-native-source-20261117-r5'
METADATA_PATH = Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/Root-llhttp93-publication-r1/Root-publication.ACTUAL.json')
METADATA_PIN = dict(bytes=1532, sha256='dfab228173747346422a809872ae41885918099de17e9ecf114d9ca519d6afef')
CONSUMED_SOURCES = ('b36a1a6dba7dd42d55646582f3d1fa2002d78d5f', '4c3de228552a910ea9b0762e71bf81d14c630bd2',
                    '28dae2796f6f50f42da19be89618c5fda0549d2c', 'd7eb16cb611c655bc2cca65501dd30c8bdfbe03f')
CONSUMED_REFS = tuple('codex/llhttp-reference-native-source-20261117-r'+str(n) for n in range(1, 5))
ANCESTORS = (
    ('previous-v4/', 85, 1120826, '0a5bae34a6339354116933cad916d60cc78adda4', 18199, '9a4b43eedecd09e5e1edc68677620ccd17a38a1bed8218fdb429b65b04715645'),
    ('previous-v3/', 76, 1053728, 'ff131da635fc160b557c58ce0f716a997a918551', 16377, '8e6290fb7c916ba52d094d2a324b7ba77e8813c910a6e454a8f78f0aeda92d57'),
    ('previous-v2/', 68, 980464, 'ff40c38eb5062ace3b46cb2f2c4c8c32fc010a00', 14771, '00a7b3ced2bbf21303734d32cf9dde10e7db5e724b0c1b4857f7ab7e5a685998'),
    ('previous-v1/', 62, 928551, 'd09f9b9870f6b7b9c9eba9c6418178c775a54d43', 13601, 'd6240a8a32bd363e75542e3e5896356e24d28e010f99e24edfff380b67afa050'))


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+'\n').encode()


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute DATA path')
    return path


def read(path):
    path = ordinary(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022 and 0 < before.st_size <= 2*1024**2, 'bounded ordinary DATA file')
    raw = path.read_bytes()
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(key(before) == key(path.lstat()) and len(raw) == before.st_size, 'stable complete DATA file')
    return raw


def tree(bodies):
    def oid(kind, raw):
        return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
    def walk(prefix):
        names = {n[len(prefix):].split('/')[0] for n in bodies if n.startswith(prefix)}
        rows = []
        for name in names:
            path = prefix+name
            leaf = path in bodies
            rows.append(((name if leaf else name+'/').encode(), (b'100644' if leaf else b'40000')+b' '+name.encode()+b'\0'+(oid('blob', bodies[path]) if leaf else walk(path+'/'))))
        return oid('tree', b''.join(row for _, row in sorted(rows)))
    return walk('').hex()


def physical(root, mode):
    root = ordinary(root)
    names = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    bodies = {n: read(root/n) for n in sorted(names)}
    need(all(stat.S_IMODE((root/n).stat().st_mode) == mode for n in names), 'whole physical file modes')
    return bodies


def validate_parent(bodies):
    need(len(bodies) == 26 and sum(map(len, bodies.values())) == 630325 and pin(bodies['packet-seal.DATA.json']) == PARENT_SEAL, 'whole immutable Source85 caller')
    rows = json.loads(bodies['packet-seal.DATA.json'])['files']
    need(set(bodies) == set(rows) | {'packet-seal.DATA.json'} and all(dict(pin(bodies[n]), mode=0o600) == row for n, row in rows.items()), 'complete26 original caller bodies/modes')
    return bodies


def parent_bodies(parent):
    return validate_parent(physical(parent, 0o600))


def closure(bodies, count, size, oid, map_pin):
    need(pin(bodies['source-map.json']) == map_pin, 'whole immutable source map')
    value = json.loads(bodies['source-map.json'])
    rows = value['files']
    need(set(bodies) == set(rows) | {'source-map.json'} and len(bodies) == count and sum(map(len, bodies.values())) == size and tree(bodies) == oid, 'whole Source namespace/bytes/tree')
    need(all(dict(pin(bodies[n]), mode=0o644) == row for n, row in rows.items()) and all(v is None for v in value['actual'].values()), 'whole source bodies/modes and NULL actuals')


def source_inverse(bodies):
    old = bodies
    counts = []
    for prefix, count, size, oid, map_size, digest in ANCESTORS:
        raw = old[prefix+'source-map.json']
        need(pin(raw) == dict(bytes=map_size, sha256=digest), 'whole retained ancestor map')
        rows = json.loads(raw)['files']
        old = {n: old[prefix+n] if prefix+n in old else old[n] for n in rows}
        old['source-map.json'] = raw
        closure(old, count, size, oid, dict(bytes=map_size, sha256=digest))
        counts.append(count)
    return counts


def source_binding(source):
    source = ordinary(source)
    bodies = physical(source, 0o644)
    closure(bodies, SOURCE_TUPLE['source_files'], SOURCE_TUPLE['source_bytes'], SOURCE_TUPLE['tree'], SOURCE_TUPLE['source_map'])
    for name, key in ((PREFIX+'owner-program.json', 'owner_program'), (PREFIX+'policy.json', 'policy'), ('.github/workflows/native-arm-llhttp-reference-source.yml', 'workflow_body')):
        need(pin(bodies[name]) == SOURCE_TUPLE[key], 'whole Source93 '+key)
    raw=read(METADATA_PATH)
    need(pin(raw)==METADATA_PIN, 'whole Root-adopted actual Source93 publication')
    value=json.loads(raw)
    need(value['issuer']=='Root' and value['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY' and value['source']==CANDIDATE_SOURCE and value['ref']=='refs/heads/'+CANDIDATE_REF and value['tree']==SOURCE_TUPLE['tree'] and value['source_map']==SOURCE_TUPLE['source_map'] and value['program']==SOURCE_TUPLE['owner_program'] and value['policy']==SOURCE_TUPLE['policy'] and value['files']==93 and value['bytes']==1204391 and value['public_clone_complete'] is True and value['public_API_blob_join'] is True and value['Root_native_authority'] is None, 'exact actual metadata only; no native authority')
    return dict(SOURCE_TUPLE, source_root=str(source), source_CID=CANDIDATE_SOURCE, source_ref='refs/heads/'+CANDIDATE_REF,
                delegated_metadata_result=dict(path=str(METADATA_PATH), **METADATA_PIN), source_inverse_counts=source_inverse(bodies), runtime54_profile=None, Root_authority=None, Root_entry='NOT RUN', native_pair='NOT RUN')



def replace(text, before, after):
    need(before in text and before != after, 'exact finite metadata seam')
    return text.replace(before, after)


def render(original, binding, script, test, policy):
    new = dict(original)
    old = json.loads(original['binding.DATA.json'])
    need(pin(policy) == SOURCE_TUPLE['policy'], 'whole Source93 policy')
    for name in (OPERATOR, PRIMITIVE):
        text = original[name].decode()
        for before, after in ((old['source_map']['sha256'], binding['source_map']['sha256']), (old['tree'], binding['tree']),
                              (repr(old['policy']), repr(binding['policy'])), (repr(old['owner_program']), repr(binding['owner_program']))):
            text = replace(text, before, after)
        text = replace(text, "CANDIDATE_SOURCE='d7eb16cb611c655bc2cca65501dd30c8bdfbe03f';CANDIDATE_REF='codex/llhttp-reference-native-source-20261117-r4'", 'CANDIDATE_SOURCE='+repr(CANDIDATE_SOURCE)+';CANDIDATE_REF='+repr(CANDIDATE_REF))
        declarations = '\nCONSUMED_SOURCES='+repr(CONSUMED_SOURCES)+';CONSUMED_REFS='+repr(CONSUMED_REFS)+'\n'
        text = replace(text, "PREFIX='" if name == OPERATOR else "MAP='", declarations+("PREFIX='" if name == OPERATOR else "MAP='"))
        if name == OPERATOR:
            for before, after in (("PROPOSED_REF='codex/llhttp-reference-native-source-20261117-r4'", 'PROPOSED_REF='+repr(CANDIDATE_REF)),
                ('selected==CANDIDATE_SOURCE', 'selected==CANDIDATE_SOURCE and selected not in CONSUMED_SOURCES'),
                ("ref==CANDIDATE_REF", "ref==CANDIDATE_REF and ref not in CONSUMED_REFS"),
                ("public['source_map_sha256']==MAP", "public['source_map']==dict(bytes=19821,sha256=MAP)"),
                ('source_files=85,source_bytes=1120826', 'source_files=93,source_bytes=1204391'),
                ("public['files']==85 and public['bytes']==1120826", "public['files']==93 and public['bytes']==1204391"),
                ('dict(bytes=18199,sha256=MAP)', 'dict(bytes=19821,sha256=MAP)'), ('len(rows)==84', 'len(rows)==92'),
                ("==1120826 and all(r['mode']", "==1204391 and all(r['mode']"),
                ("OP='llhttp-reference-mount-class-diagnostics-v4'", "OP='llhttp-reference-source-readonly-v5'")):
                text = replace(text, before, after)
        else:
            text = replace(text, 'source==CANDIDATE_SOURCE and ref==CANDIDATE_REF', "source==CANDIDATE_SOURCE and source not in CONSUMED_SOURCES and ref==CANDIDATE_REF and ref not in CONSUMED_REFS")
        new[name] = text.encode()
    new[OPERATOR] = replace(new[OPERATOR].decode(), 'PRIMITIVE_SHA='+repr(pin(original[PRIMITIVE])['sha256']), 'PRIMITIVE_SHA='+repr(pin(new[PRIMITIVE])['sha256'])).encode()
    name = 'issue_root_packet.DRAFT.py'
    text = original[name].decode()
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in n.targets))
    new[name] = replace(text, ast.get_source_segment(text, node), 'SOURCE=Path('+repr(binding['source_root'])+')').encode()
    new['packet/operator-DRAFT/policy.json'] = policy
    new['binding.DATA.json'] = encode(dict(binding, opbindings={n: pin(new[n]) for n in (OPERATOR, PRIMITIVE, name, 'packet/make_root_config.DRAFT.py')}))
    inputs = {n: None for n in json.loads(original['ROOT-INPUTS.UNISSUED.json'])}
    inputs.update(status='SOURCE93_ACTUAL_METADATA_BOUND_ALL_NATIVE_OPERANDS_UNISSUED', Root_entry='NOT RUN', source_CID=CANDIDATE_SOURCE, source_ref='refs/heads/'+CANDIDATE_REF, delegated_metadata_result=dict(path=str(METADATA_PATH),**METADATA_PIN))
    new['ROOT-INPUTS.UNISSUED.json'] = encode(inputs)
    new['HANDOFF.md'] = b'''# Source93 complete canonical ONCE DRAFT

Source93 map/tree/program/policy and full85/76/68/62 source inverse are pinned.
Every26 immutable Source85 caller body/mode is retained in the full-files inverse.
CID/ref bind the actual Root publication. Native authority/registration/Main/
runtime54/Root context/nonce/time/role/output remain unissued. Root must refresh active
workflow420972285 registration and supply all fresh operational operands.
configure() accepts only actual Root-selected8f6370a3/r5 with the pinned93 tuple;
all four consumed predecessor CIDs/refs are refused. No destination is invented.

The exact five-input/onePOST/noRetry, global two-sweep EMPTY/Main CAS, runtime54,
same FD/PIDFD/NB custody, CLOSE_ONLY and deadlines/resources remain preserved.
Source93 proposes exact Source BindReadOnlyPaths for owner and daemon. Its kernel
effect and native pair remain NOT RUN. Native92 remains failed/HOLD; retirement
is separate from payload success. No actor/lease/Root issuance/publication occurs.
The worker registration plan is DATA only: fresh Root readback and adoption remain
required. Historical files inside the predecessor inverse are historical only.
'''
    new['prepare-carrier.py'] = script
    new['test_canonical_cli.DATA.py'] = test
    new['registration-plan.DATA.json'] = encode(dict(issuer='workerDATA', Root_adoption=None, registration=None,
        repository='Gabriel-Kahen/cachy-asahi', Main=None, workflow_id=420972285,
        workflow_path='.github/workflows/native-arm-llhttp-reference-source.yml', workflow_body=SOURCE_TUPLE['workflow_body'],
        initial_final_Main_CAS=None, source_CID=CANDIDATE_SOURCE, source_ref='refs/heads/'+CANDIDATE_REF, required_secret_name_count=22,
        secret_name_catalog=None, secret_values_read=False, Root_authority=None))
    return new


def inverse(value):
    bodies = physical(value, 0o600) if isinstance(value, (str, Path)) else value
    seal = json.loads(bodies['packet-seal.DATA.json'])
    need(set(bodies) == set(seal['files']) | {'packet-seal.DATA.json'} and all(dict(pin(bodies[n]), mode=0o600) == r for n, r in seal['files'].items()), 'whole sealed caller namespace/bodies/modes')
    need(seal['Root_authority'] is None and seal['role_label'] is None and seal['actual_POSTs'] == 0 and seal['actual_source_metadata']==CANDIDATE_SOURCE and seal['source_ref']=='refs/heads/'+CANDIDATE_REF and seal['runtime54_profile'] is None, 'unissued caller seal')
    proof = json.loads(bodies['full-files-inverse.DATA.json'])
    need(proof['parent_seal'] == PARENT_SEAL and len(proof['files']) == 26, 'complete26 Source85 caller inverse')
    old = {}
    for name, row in proof['files'].items():
        raw = base64.b64decode(row['body_base64'], validate=True)
        need(pin(raw) == row['pin'] and row['mode'] == 0o600, 'whole original inverse body/mode')
        old[name] = raw
    validate_parent(old)
    binding = json.loads(bodies['binding.DATA.json'])
    need(all(binding[k] == v for k, v in SOURCE_TUPLE.items()) and all(binding[k] is None for k in ('Root_authority', 'runtime54_profile')), 'exact93 tuple; all native authority unissued')
    need(binding['source_CID']==CANDIDATE_SOURCE and binding['source_ref']=='refs/heads/'+CANDIDATE_REF and binding['delegated_metadata_result']==dict(path=str(METADATA_PATH),**METADATA_PIN),'actual Root Source93 metadata binding')
    expected = render(old, binding, bodies['prepare-carrier.py'], bodies['test_canonical_cli.DATA.py'], bodies['packet/operator-DRAFT/policy.json'])
    for name, raw in expected.items():
        if name not in ('full-files-inverse.DATA.json', 'packet-seal.DATA.json'):
            need(bodies[name] == raw, 'whole finite caller projection: '+name)
    need(set(expected) == set(bodies), 'whole successor carrier namespace')
    return old


def construct(parent, source, output):
    parent, source, output = map(ordinary, (parent, source, output))
    need(not output.exists() and all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in (parent, source)), 'fresh disjoint caller output in both directions')
    original = parent_bodies(parent)
    binding = source_binding(source)
    test = HERE/'test_data.py'
    if not test.exists():
        test = HERE/'test_canonical_cli.DATA.py'
    new = render(original, binding, read(Path(__file__).resolve()), read(test), read(source/PREFIX/'policy.json'))
    new['full-files-inverse.DATA.json'] = encode(dict(status='COMPLETE_SOURCE85_26_LEAF_CALLER_INVERSE_DATA_ONLY', parent_files=26, parent_seal=PARENT_SEAL,
        files={n: dict(pin=pin(raw), mode=0o600, body_base64=base64.b64encode(raw).decode()) for n, raw in sorted(original.items())}, Root_authority=None))
    new['packet-seal.DATA.json'] = encode(dict(status='SOURCE93_FULL_CANONICAL_ONCE_DRAFT_ALL_ROOT_INPUTS_UNBOUND',
        files={n: dict(pin(raw), mode=0o600) for n, raw in sorted(new.items()) if n != 'packet-seal.DATA.json'},
        Root_authority=None, role_label=None, runtime54_profile=None, actual_source_metadata=CANDIDATE_SOURCE, source_ref='refs/heads/'+CANDIDATE_REF, actual_POSTs=0))
    inverse(new)
    need(len(new) < 40 and sum(map(len, new.values())) < 2*1024**2, 'finite complete caller DATA')
    output.mkdir(mode=0o700)
    for name, raw in new.items():
        path = output/name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o600)
    for path in output.rglob('*.py'):
        ast.parse(read(path), filename=str(path))
    return dict(status='SOURCE93_DRAFT_ONLY', files=len(new), bytes=sum(map(len, new.values())), binding=json.loads(new['binding.DATA.json']),
        operator=pin(new[OPERATOR]), primitive=pin(new[PRIMITIVE]), issuer=pin(new['issue_root_packet.DRAFT.py']),
        joiner=pin(new['packet/make_root_config.DRAFT.py']), seal=pin(new['packet-seal.DATA.json']), Root_authority=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'source', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.source, args.output), indent=2, sort_keys=True))
