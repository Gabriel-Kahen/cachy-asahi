#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure Source95 canonical caller DATA; no Root issuance or operational entry."""
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
PARENT_SEAL = dict(bytes=4941, sha256='ec350f7dd719b1adebf91c2c945057b8d1fe4b20c3d04b49e11552452c52a0ab')
SOURCE_TUPLE = dict(tree='b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f', source_files=95, source_bytes=1318237,
    source_map=dict(bytes=20200, sha256='ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce'),
    owner_program=dict(bytes=9673, sha256='b9197a46a6161d6d5fa9c3cf3c8edfe030ba7010b48c0dcb4fbaf68886245d4f'),
    policy=dict(bytes=21404, sha256='b12d2d4789ea5dbae9170e3a64300adc127568b6ecd40ec009a54532779d471e'),
    workflow_body=dict(bytes=6201, sha256='2ba05dea048406382cf0285c1a73f56b8671c8a322ffd2636ae41ddc64d82c99'))
CANDIDATE_SOURCE = None
CANDIDATE_REF = None
METADATA_PATH = None
METADATA_PIN = None
PUBLIC_RETENTION_PIN = dict(bytes=10144, sha256='9b3c103dc6b309568ff5215f2b282b27bb349b4a44f55b777dcf55bda3157a42')
CONSUMED_SOURCES = ('b36a1a6dba7dd42d55646582f3d1fa2002d78d5f', '4c3de228552a910ea9b0762e71bf81d14c630bd2',
                    '28dae2796f6f50f42da19be89618c5fda0549d2c', 'd7eb16cb611c655bc2cca65501dd30c8bdfbe03f', '8f6370a35215496c0e6c10922929028f5146644b')
CONSUMED_REFS = tuple('codex/llhttp-reference-native-source-20261117-r'+str(n) for n in range(1, 6))
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
    need(len(bodies) == 27 and sum(map(len, bodies.values())) == 1062651 and pin(bodies['packet-seal.DATA.json']) == PARENT_SEAL, 'whole immutable Source93 caller')
    rows = json.loads(bodies['packet-seal.DATA.json'])['files']
    need(set(bodies) == set(rows) | {'packet-seal.DATA.json'} and all(dict(pin(bodies[n]), mode=0o600) == row for n, row in rows.items()), 'complete27 original caller bodies/modes')
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
    marker=json.loads(bodies['inner-public-retention-v6.json'])
    changed={PREFIX+n for n in ('hosted_owner.py','policy.json','owner-program.json')}|{'source-map.json'}
    need(set(marker['before'])==changed,'whole compact93 ledger')
    old={n:raw for n,raw in bodies.items()if n not in ('inner-public-retention-v6.json',PREFIX+'public_evidence.py')}
    for name,row in marker['before'].items():
        raw=base64.b64decode(row['body_base64'],validate=True)
        need(pin(raw)==row['pin'] and row['mode']==0o644,'whole compact93 inverse body')
        old[name]=raw
    closure(old,93,1204391,'424259eb3868b802b9aa2ae4dbeceff169fce7fd',dict(bytes=19821,sha256='4abcbcd541e3bf3ad652ff09cd2a813ce5a276bc58fade63cc2801a248c349c7'))
    counts = [93]
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
        need(pin(bodies[name]) == SOURCE_TUPLE[key], 'whole Source95 '+key)
    need(pin(bodies[PREFIX+'public_evidence.py'])==PUBLIC_RETENTION_PIN,'whole strict public report exporter')
    metadata=None
    if CANDIDATE_SOURCE is not None:
        raw=read(METADATA_PATH)
        need(pin(raw)==METADATA_PIN,'whole Root-adopted actual Source95 publication')
        value=json.loads(raw)
        need(value['issuer']=='Root' and value['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY' and value['source']==CANDIDATE_SOURCE and value['ref']=='refs/heads/'+CANDIDATE_REF and value['tree']==SOURCE_TUPLE['tree'] and value['source_map']==SOURCE_TUPLE['source_map'] and value['program']==SOURCE_TUPLE['owner_program'] and value['policy']==SOURCE_TUPLE['policy'] and value['files']==95 and value['bytes']==1318237 and value['public_clone_complete'] is True and value['public_API_blob_join'] is True and value['Root_native_authority'] is None,'exact actual metadata only; no native authority')
        metadata=dict(path=str(METADATA_PATH),**METADATA_PIN)
    else:
        need(CANDIDATE_REF is METADATA_PATH is METADATA_PIN is None,'all unpublished selectors NULL')
    return dict(SOURCE_TUPLE,public_retention=PUBLIC_RETENTION_PIN,source_root=str(source),source_CID=CANDIDATE_SOURCE,
                source_ref=None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF,delegated_metadata_result=metadata,
                source_inverse_counts=source_inverse(bodies),runtime54_profile=None,Root_authority=None,Root_entry='NOT RUN',native_pair='NOT RUN')



def replace(text, before, after):
    need(before in text and before != after, 'exact finite metadata seam')
    return text.replace(before, after)


def render(original, binding, script, test, policy):
    new=dict(original);old=json.loads(original['binding.DATA.json'])
    need(pin(policy)==SOURCE_TUPLE['policy'],'whole Source95 policy')
    parent_sources=CONSUMED_SOURCES[:-1];parent_refs=CONSUMED_REFS[:-1]
    for name in (OPERATOR,PRIMITIVE):
        text=original[name].decode()
        for before,after in ((old['source_map']['sha256'],binding['source_map']['sha256']),(old['tree'],binding['tree']),
                             (repr(old['policy']),repr(binding['policy'])),(repr(old['owner_program']),repr(binding['owner_program'])),
                             (repr(parent_sources),repr(CONSUMED_SOURCES)),(repr(parent_refs),repr(CONSUMED_REFS))):
            text=replace(text,before,after)
        text=replace(text,"CANDIDATE_SOURCE='8f6370a35215496c0e6c10922929028f5146644b';CANDIDATE_REF='codex/llhttp-reference-native-source-20261117-r5'",
                     'CANDIDATE_SOURCE='+repr(CANDIDATE_SOURCE)+';CANDIDATE_REF='+repr(CANDIDATE_REF))
        if name==OPERATOR:
            for before,after in (("PROPOSED_REF='codex/llhttp-reference-native-source-20261117-r5'",'PROPOSED_REF='+repr(CANDIDATE_REF)),
                ('source_files=93,source_bytes=1204391','source_files=95,source_bytes=1318237'),
                ("public['files']==93 and public['bytes']==1204391","public['files']==95 and public['bytes']==1318237"),
                ('dict(bytes=19821,sha256=MAP)','dict(bytes=20200,sha256=MAP)'),('len(rows)==92','len(rows)==94'),
                ("==1204391 and all(r['mode']","==1318237 and all(r['mode']"),
                ("OP='llhttp-reference-source-readonly-v5'","OP='llhttp-reference-inner-public-retention-v6'")):
                text=replace(text,before,after)
            text=replace(text,"POLICY_SHA=POLICY_PIN['sha256']","POLICY_SHA=POLICY_PIN['sha256']\nPUBLIC_RETENTION_PIN="+repr(PUBLIC_RETENTION_PIN))
            anchor=" program_raw=read(root/prefix/'owner-program.json')"
            text=replace(text,anchor," need(pin(read(root/prefix/'public_evidence.py'))==PUBLIC_RETENTION_PIN,'exact strict public report exporter')\n"+anchor)
        new[name]=text.encode()
    new[OPERATOR]=replace(new[OPERATOR].decode(),'PRIMITIVE_SHA='+repr(pin(original[PRIMITIVE])['sha256']),'PRIMITIVE_SHA='+repr(pin(new[PRIMITIVE])['sha256'])).encode()
    name='issue_root_packet.DRAFT.py';text=original[name].decode()
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='SOURCE'for t in n.targets))
    new[name]=replace(text,ast.get_source_segment(text,node),'SOURCE=Path('+repr(binding['source_root'])+')').encode()
    new['packet/operator-DRAFT/policy.json']=policy
    new['binding.DATA.json']=encode(dict(binding,opbindings={n:pin(new[n])for n in(OPERATOR,PRIMITIVE,name,'packet/make_root_config.DRAFT.py')}))
    inputs={n:None for n in json.loads(original['ROOT-INPUTS.UNISSUED.json'])}
    inputs.update(status='SOURCE95_NATIVE_OPERANDS_UNISSUED',Root_entry='NOT RUN',source_CID=binding['source_CID'],source_ref=binding['source_ref'],delegated_metadata_result=binding['delegated_metadata_result'])
    new['ROOT-INPUTS.UNISSUED.json']=encode(inputs)
    new['HANDOFF.md']=b"Source95 complete canonical ONCE DRAFT. Full27-leaf frozen Source93 caller inverse and complete95/93/85/76/68/62 source chain. New21404-byte policy fits existing2MiB constructor and8MiB policy/authority reads. Unchanged16KiB admission/runtime documents carry pins only. Strict526-leaf inner public export is nonaccepting and preserves HOLD; actual inner cause remains unproven. All Root native roles, runtime54, authority/admission/context, registration/Main/nonce/time/output/lease are unissued. Root supplies actual publication before exact CID/ref configuration, fresh registration and all native grants. No Root actor or publication is performed here.\n"
    new['prepare-carrier.py']=script;new['test_canonical_cli.DATA.py']=test
    new['registration-plan.DATA.json']=encode(dict(issuer='workerDATA',Root_adoption=None,registration=None,Main=None,
        repository='Gabriel-Kahen/cachy-asahi',workflow_id=420972285,workflow_path='.github/workflows/native-arm-llhttp-reference-source.yml',
        workflow_body=SOURCE_TUPLE['workflow_body'],initial_final_Main_CAS=None,source_CID=binding['source_CID'],source_ref=binding['source_ref'],
        required_secret_name_count=22,secret_name_catalog=None,secret_values_read=False,Root_authority=None))
    return new


def inverse(value):
    bodies = physical(value, 0o600) if isinstance(value, (str, Path)) else value
    seal = json.loads(bodies['packet-seal.DATA.json'])
    need(set(bodies) == set(seal['files']) | {'packet-seal.DATA.json'} and all(dict(pin(bodies[n]), mode=0o600) == r for n, r in seal['files'].items()), 'whole sealed caller namespace/bodies/modes')
    need(seal['Root_authority'] is None and seal['role_label'] is None and seal['actual_POSTs'] == 0 and seal['actual_source_metadata']==CANDIDATE_SOURCE and seal['source_ref']==(None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF) and seal['runtime54_profile'] is None, 'unissued caller seal')
    proof = json.loads(bodies['full-files-inverse.DATA.json'])
    need(proof['parent_seal'] == PARENT_SEAL and len(proof['files']) == 27, 'complete27 Source93 caller inverse')
    old = {}
    for name, row in proof['files'].items():
        raw = base64.b64decode(row['body_base64'], validate=True)
        need(pin(raw) == row['pin'] and row['mode'] == 0o600, 'whole original inverse body/mode')
        old[name] = raw
    validate_parent(old)
    binding = json.loads(bodies['binding.DATA.json'])
    need(all(binding[k] == v for k, v in SOURCE_TUPLE.items()) and all(binding[k] is None for k in ('Root_authority', 'runtime54_profile')), 'exact95 tuple; all native authority unissued')
    need(binding['source_CID']==CANDIDATE_SOURCE and binding['source_ref']==(None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF) and binding['delegated_metadata_result']==(None if METADATA_PATH is None else dict(path=str(METADATA_PATH),**METADATA_PIN)) and binding['public_retention']==PUBLIC_RETENTION_PIN,'exact Source95 metadata binding')
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
    new['full-files-inverse.DATA.json'] = encode(dict(status='COMPLETE_SOURCE93_27_LEAF_CALLER_INVERSE_DATA_ONLY', parent_files=27, parent_seal=PARENT_SEAL,
        files={n: dict(pin=pin(raw), mode=0o600, body_base64=base64.b64encode(raw).decode()) for n, raw in sorted(original.items())}, Root_authority=None))
    new['packet-seal.DATA.json'] = encode(dict(status='SOURCE95_FULL_CANONICAL_ONCE_DRAFT_ALL_ROOT_INPUTS_UNBOUND',
        files={n: dict(pin(raw), mode=0o600) for n, raw in sorted(new.items()) if n != 'packet-seal.DATA.json'},
        Root_authority=None, role_label=None, runtime54_profile=None, actual_source_metadata=CANDIDATE_SOURCE, source_ref=None if CANDIDATE_REF is None else 'refs/heads/'+CANDIDATE_REF, actual_POSTs=0))
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
    return dict(status='SOURCE95_DRAFT_ONLY', files=len(new), bytes=sum(map(len, new.values())), binding=json.loads(new['binding.DATA.json']),
        operator=pin(new[OPERATOR]), primitive=pin(new[PRIMITIVE]), issuer=pin(new['issue_root_packet.DRAFT.py']),
        joiner=pin(new['packet/make_root_config.DRAFT.py']), seal=pin(new['packet-seal.DATA.json']), Root_authority=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('parent', 'source', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent, args.source, args.output), indent=2, sort_keys=True))
