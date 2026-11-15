#!/usr/bin/env python3
"""Join pinned UI172 DATA into an unissued manifest; no material reads or actors."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import stat
import time

HERE = Path(__file__).resolve().parent
FIELDS = ('type','mode','uid','gid','bytes','sha256','link')
BASE_LEAVES = {'etc/pam.d/login':'util-linux','etc/pam.d/system-auth':'pambase',
    'etc/pam.d/system-login':'pambase','etc/pam.d/system-local-login':'pambase',
    'usr/lib/udev/rules.d/71-seat.rules':'systemd',
    'usr/lib/girepository-1.0/GLib-2.0.typelib':'glib2','usr/lib/girepository-1.0/Gio-2.0.typelib':'glib2'}
TEMPLATES = {'fish':'21f4ca0ab90c66b131673f2cb2c6caf85b72e2872777481d8118d9264b3d0c02',
             'zsh':'0e88f366d93de023007a290678e38c37dda64d2c10036f763e4ee0c4de4cc9c0'}


class Refused(ValueError): pass


def need(value, message):
    if not value: raise Refused(message)


def digest(body): return {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}


def pairs(rows):
    result={}
    for key,value in rows:
        need(key not in result,'duplicate JSON key');result[key]=value
    return result


def parse(body):
    return json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite JSON')))


def read_pinned(ref, budget, maximum):
    path=Path(ref['path'])
    need(path.is_absolute() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents),'ordinary absolute DATA input')
    need(type(ref['bytes']) is int and 0<ref['bytes']<=maximum and budget['remaining']>=ref['bytes'],'DATA input byte cap')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_size==ref['bytes'],'DATA input size/type')
        budget['remaining']-=ref['bytes'];body=stream.read(ref['bytes']+1);after=os.fstat(stream.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(identity(before)==identity(after) and digest(body)=={k:ref[k] for k in ('bytes','sha256')},'DATA input full pin/identity')
    return body


def reference(row, maximum):
    need(set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=maximum
         and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),'finite byte/SHA256 reference')


def relative(path):
    need(isinstance(path,str) and path and not path.startswith('/') and '\\' not in path and '\0' not in path
         and '..' not in path.split('/') and PurePosixPath(path).as_posix()==path,'canonical relative guest path')


def payload(row):
    need(set(row)==set(FIELDS),'exact seven payload fields')
    need(row['type'] in ('0','1','2') and all(type(row[k]) is int and row[k]>=0 for k in ('mode','uid','gid','bytes')),'payload type/numeric fields')
    need(row['mode']<=0o7777 and isinstance(row['link'],str) and '\0' not in row['link'],'payload mode/link')
    if row['type']=='0':
        need(row['link']=='' and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256']),'regular payload hash/link')
    else: need(row['sha256'] is None and row['link']!='','link payload declaration')


def association(rows):
    normalized={n:{'version':v['version'],'directory':v['directory'],'provides':sorted(v['provides']),'files':sorted(v['files'])} for n,v in rows.items()}
    return digest(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode())


def _build(data, refs, keyring_sources):
    """Pure DATA function. It never opens an archive, signature, key or rootfs."""
    ledger,base,proposal,lower,schema=(data[n] for n in ('ledger','baseline','proposal','lower155','contract'))
    constants=schema['constants'];project=constants['PROJECT'];required=constants['REQUIRED']
    need(ledger['kind']=='ARM16K_FIRST_LOGIN_UI_AUTHENTICATED_LEDGER_V1' and ledger['known_incompatibilities']==[] and ledger['ELF_holds']==[],'accepted ledger DATA/no known incompatibility')
    need((proposal['baseline'],proposal['additions'],proposal['final'])==(111,172,283),'exact111+172 composition')
    materials={r['name']:r for r in proposal['materials']};rows=ledger['archives'];bm=base['baseline_metadata']
    need(len(materials)==len(rows)==172 and set(rows)==set(materials) and len(bm)==111 and not set(rows)&set(bm),'exact unique172/111 namespaces')
    need(len(project)==3 and set(project)<=set(rows),'all three fixed project additions')
    need(base['status']=='PASS_ARM111_BASELINE_METADATA_NAMESPACE_DATA_ONLY','actual baseline namespace DATA')
    need(association(bm)=={'sha256':schema['baseline_metadata_association']['sha256'],
                          'bytes':schema['baseline_metadata_association']['normalized_bytes']},'actual111 association')
    need(lower['kind']=='ARM16K_VIRTIO_SEAT_ADDITIONS_V1' and len(lower['archives'])==44,'lower44 manifest DATA')
    for key in ('baseline_metadata','baseline_metadata_provenance','original_file_pins'):
        need(lower[key]==base[key],'lower155/baseline exact '+key)
    prepared=lower['baseline_prepared'];reference(prepared,1024**2)
    need(prepared=={k:base['baseline_metadata_provenance']['prepared'][k] for k in ('bytes','sha256')},'exact baseline prepared reference')
    proof=proposal['metadata_prepare'];p=proof['prepare']
    need(ledger['metadata_prepare']==proof and proof['status']=='PASS_EXPLICIT_FINITE_METADATA_PREPARE'
         and proof['baseline_preserved']==111 and proof['final_count']==283 and proof['conflicts']==[],'unchanged actual ALPM preparation')
    need(p['libalpm_version']=='16.0.1' and p['prepare_exit']==p['prepare_errno']==0
         and all(p[k]==[] for k in ('errors','callback_errors','questions','remove')),'actual ALPM success/no removals')
    need(len(p['add'])==172 and {r['name']:r['version'] for r in p['add']}=={n:r['version'] for n,r in rows.items()},'actual ALPM exact172 versions')
    joined=ledger['actual_dependency_joins'];edges=proof['dependencies']
    need(len(edges)==len(joined)==1319 and [{k:r[k] for k in ('package','provider','relation')} for r in joined]==edges
         and all(r['status']=='PASS_METADATA_ONLY' for r in joined),'actual1319 selected edge witnesses')
    archives={};plan=[];compressed=0
    for name,row in sorted(rows.items()):
        material=materials[name];meta=row['metadata'];role='project' if name in project else 'official'
        need(re.fullmatch(r'[A-Za-z0-9@._+:-]+\.pkg\.tar\.(xz|zst)',row['filename']) is not None,'flat original archive filename')
        reference(row['archive'],64*1024**2);reference(row['signature'],65536);compressed+=row['archive']['bytes']
        need(row['version']==material['version'] and row['filename']==material['archive']['filename'] and
             row['archive']=={k:material['archive'][k] for k in ('bytes','sha256')} and
             row['signature']=={'bytes':material['archive']['signature_bytes'],'sha256':material['archive']['signature_sha256']},'exact proposal archive/signature pins')
        need(all(isinstance(k,str) and isinstance(v,list) and all(isinstance(s,str) for s in v) for k,v in meta.items()),'full PKGINFO multimap')
        need(meta.get('pkgname')==[name] and meta.get('pkgver')==[row['version']] and meta.get('arch')==[material['arch']]
             and meta['arch'] in (['aarch64'],['any']) and meta.get('depend',[])==material['depends'],'actual PKGINFO identity/dependency order')
        need(row['signer_role']==role and row['official_repository'] is (role=='official'),'separate official/project roles')
        need(row['expected_signer']==ledger['trust']['keyrings'][role]['primary'],'expected signer/keyring role')
        if role=='project':need(meta['arch']==['any'] and row['archive']['sha256']==project[name],'fixed3 project archive identities')
        else:need(row['expected_signer']==constants['OFFICIAL'],'exact official primary')
        if name in lower['archives']:
            need(all(row[k]==lower['archives'][name][k] for k in ('filename','version','archive','signature','metadata','expected_signer')),'unchanged lower44 additions')
        for expression in meta.get('depend',[]):
            selected=[e for e in edges if e['package']==name and e['relation']==expression]
            need(len(selected)==1 and selected[0]['provider'] in set(rows)|set(bm),'unique selected dependency provider')
        archives[name]={k:copy.deepcopy(row[k]) for k in ('filename','version','archive','signature','metadata','signer_role','expected_signer','official_repository')}
        archives[name]['source_provenance']={'authenticated_ledger':refs['ledger'],'package':name}
        source=row['source_provenance']
        plan.extend([{'filename':row['filename'],'source_path':source['archive_path'],'pin':row['archive']},
                     {'filename':row['filename']+'.sig','source_path':source['signature_path'],'pin':row['signature']}])
    need(compressed==proposal['declared_archive_bytes']==schema['composition']['archive_bytes'] and compressed<=256*1024**2,'exact finite archive byte sum')
    need(sum(r['signer_role']=='official' for r in archives.values())==169 and sum(r['signer_role']=='project' for r in archives.values())==3,'exact169 official/three TEST roles')
    need(rows['xorg-server-xvfb']['version']=='21.1.26-1' and rows['xorg-server-xvfb']['archive']['sha256']==schema['composition']['root_change']['archive']['sha256'],'fixed current Xvfb')
    need(set(ledger['required_namespace'])==set(required),'all12 required addition leaves')
    namespace=copy.deepcopy(ledger['required_namespace'])
    for path,owner in required.items():
        relative(path);row=namespace[path];need(row['owner']==owner and owner in rows,'exact addition owner');payload(row['payload'])
        if path.startswith('usr/bin/') and row['payload']['type']=='0':
            need(row['payload']['mode']&0o111 and row['payload']['uid']==row['payload']['gid']==0,'root-owned executable leaf')
    policy=namespace['usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy']['payload']
    need(policy['sha256']==constants['POLICY'] and policy==schema['fixed_NM_policy']==ledger['NM_policy']['payload'],'actual original NM policy payload')
    fixed=base['required_namespace'];need(set(fixed)==set(BASE_LEAVES) and len(base['original_file_pins'])==7,'exact seven baseline fixed leaves')
    need(fixed==schema['fixed_baseline_namespace'],'fixed baseline ownership/payload/pin: exact PAM/seat/typelib numeric metadata')
    for path,owner in BASE_LEAVES.items():
        row=fixed[path];payload(row['payload'])
        need(row['owner']==owner and row['payload']['type']=='0' and row['payload']['uid']==row['payload']['gid']==0
             and path in bm[owner]['files'] and base['original_file_pins'].get('/'+path)==row['payload']['sha256'],'fixed baseline ownership/payload/pin')
        if path.endswith('.typelib'): namespace[path]=copy.deepcopy(row)
    need(set(ledger['templates'])==set(TEMPLATES),'fish/zsh template DATA')
    templates={}
    for name,row in ledger['templates'].items():
        reference(row['pin'],1024**2);need(row['pin']['sha256']==TEMPLATES[name],'fixed shell template pin')
        need(Path(row['filename']).name==row['filename'],'flat template filename')
        templates[name]={k:copy.deepcopy(row[k]) for k in ('filename','pin')}
        plan.append({'filename':row['filename'],'source_path':row['source_path'],'pin':row['pin']})
    rings=copy.deepcopy(ledger['trust']['keyrings']);need(set(rings)=={'official','project'},'two distinct public signing roles')
    need(rings['official']['primary']!=rings['project']['primary'],'distinct TEST/official primary')
    for role,row in rings.items():
        reference(row['pin'],65536);need(row['filename']==role+'-public.gpg' and re.fullmatch('[0-9A-F]{40}',row['primary']),'public role ring shape')
        source=keyring_sources[role+'_binary_keyring'];need(row['pin']=={k:source[k] for k in ('bytes','sha256')},'retained public keyring pin association')
        plan.append({'filename':row['filename'],'source_path':source['path'],'pin':row['pin']})
    need(len(ledger['project_regular_usr_payloads'])==24 and all(r['owner'] in project and r['type']=='file' for r in ledger['project_regular_usr_payloads'].values()),'24 actual project regular payload records')
    need(len({r['filename'] for r in plan})==len(plan)==348,'distinct172 pairs+two templates+two public rings')
    manifest={'kind':'ARM16K_FIRST_LOGIN_UI_ADDITIONS_V1','status':'HOLD_ROOT_UI_ISSUANCE_CURRENT_TEST_TRUST_AND_RUNTIME_QUALIFICATION',
        'issued_by':None,'issued_at':None,'Root_review':None,'baseline_prepared':copy.deepcopy(prepared),
        'archives':archives,'metadata_prepare':copy.deepcopy(proof),'baseline_metadata':copy.deepcopy(bm),
        'baseline_metadata_provenance':copy.deepcopy(base['baseline_metadata_provenance']),
        'original_file_pins':copy.deepcopy(base['original_file_pins']),'required_namespace':namespace,
        'fixed_baseline_namespace':copy.deepcopy(fixed),'known_incompatibilities':[], 'templates':templates,
        'trust':{'keyrings':rings,'valid_until_utc':None,'issued_by':None,'Root_TEST_trust_issuance':None,
                 'certificate_observation':copy.deepcopy(ledger['trust'].get('project_certificate_observation'))},
        'actual_runtime_qualification':None,'runtime_authority':None,'source_DATA':copy.deepcopy(refs),
        'deferred_checks':['Root current trust/issuance and runtime authority','independent full archive/ownership/link-target namespace validation',
                           'complete symbol/transitive ABI and actual runtime/seat','native builds/M2/legal/release']}
    return manifest,{'kind':'UI172_RETAINED_MATERIALS_PLAN_DATA_ONLY','copy_or_archive_reads_performed':False,'files':plan}


def build(data, refs, keyring_sources):
    try:return _build(data,refs,keyring_sources)
    except (KeyError,TypeError,IndexError) as error:
        raise Refused('missing or malformed exact DATA input: '+str(error)) from None


def refuse_unissued(manifest):
    """Prove the missing-Root refusal; this is not a runtime trust verifier."""
    need(manifest['issued_by']=='Root' and manifest['status']=='ROOT_REVIEWED_COMPLETE_UI283_CLOSURE'
         and manifest['trust']['Root_TEST_trust_issuance'] is not None and manifest['trust']['valid_until_utc'] is not None
         and manifest['actual_runtime_qualification'] is not None and manifest['runtime_authority'] is not None,
         'unissued DATA template: external Root trust/issuance/runtime qualification required before any actor')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    config=parse((HERE/'inputs.json').read_bytes());limits=config['limits'];resource.setrlimit(resource.RLIMIT_AS,(limits['address_space_bytes'],limits['address_space_bytes']));signal.alarm(limits['wall_seconds']);started=time.monotonic()
    budget={'remaining':limits['total_input_bytes']};refs=config['documents'];data={n:parse(read_pinned(r,budget,limits['file_input_bytes'])) for n,r in refs.items()}
    read_pinned(data['contract']['consumer_source'],budget,limits['file_input_bytes'])
    manifest,plan=build(data,refs,config['keyring_sources'])
    try:refuse_unissued(manifest)
    except Refused:pass
    else:raise Refused('unexpected admitted output')
    output=args.output.resolve();need(output.is_relative_to(Path('/tmp')) and not args.output.is_symlink() and not any(p.is_symlink() for p in output.parents),'new ordinary private /tmp output')
    output.mkdir(mode=0o700,exist_ok=False)
    receipt={'status':'PASS_PURE_DATA_JOIN_ROOT_ADMISSION_HELD','inputs':refs,'package_archive_signature_keyring_rootfs_reads':0,
        'metadata_bytes_read':limits['total_input_bytes']-budget['remaining'],'archives':172,'baseline':111,'namespace':14,'fixed_baseline_leaves':7,
        'official':169,'project_TEST':3,'metadata_edges':1319,'runtime_admission':'REFUSED_NULL_ROOT_FIELDS','seconds':round(time.monotonic()-started,3),
        'producer':digest(Path(__file__).read_bytes()),'limits':limits}
    for name,value in [('additions-manifest.UNISSUED.json',manifest),('materials-plan.DATA.json',plan),('receipt.json',receipt)]:
        body=json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n';need(len(body.encode())<=limits['output_bytes'],'DATA output cap')
        (output/name).write_text(body)
    print(json.dumps(receipt))


if __name__=='__main__':main()
