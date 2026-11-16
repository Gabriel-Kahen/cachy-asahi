# SPDX-License-Identifier: MIT
"""Closed Source/public cache DATA assembly; no actor, acquisition or authority."""
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import time

API='CURRENT_ONBOARDING_INPUTS_V3'
OP='first-login-enrollment-ui-current-v2'
FAMILY='scripts/ci/first-login-enrollment-native-source'
PROFILE=FAMILY+'/successor_v2/profile.json'
PROFILE_PIN=dict(bytes=21679,sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171')
BASE_SHA='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
BASE_BYTES=328101
FACTORY=FAMILY+'/profile.json'
FACTORY_PIN=dict(bytes=62259,sha256='ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa')
BOOTSTRAP_PIN=dict(bytes=168201,sha256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c')
SUPPLEMENT={'cmake','cppdap','jsoncpp','libuv','meson','ninja','python-tqdm','rhash'}
KEYRINGS={'archlinuxarm.gpg','archlinuxarm-trusted','archlinuxarm-revoked'}
STAGING_TABLE='inputs/material-staging-materials-v4.json'
REGISTRY=FAMILY+'/successor_v4_source/program.json'
STAGING_MATERIALS={
    'retained_carrier_profile':('bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json','4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'),
    'retained_prefill_profile':('bootstrap/scripts/ci/setup6-retained-helpers/legacy-prefill-profile.json','9cc82d4e0947415ecad9d40094a4c0a2709d01be54513e78af8c739fd76fb696'),
    'public14_profile':(FAMILY+'/inputs/public14-profile.json','5fe4761bc96d21ec388322ead3b97c735d2f689c38061c560afc90a2143de346'),
    'staging_base_lock':('bootstrap/scripts/ci/inputs.lock.json',BASE_SHA),
    'staging_bootstrap_profile':('native/input-profile.json',BOOTSTRAP_PIN['sha256'])}
BASELINE_SHA='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
COUNTS=dict(backend=350,lifecycle=372,ui=374)
OFFICIAL=('fuse-common','fuse3','gobject-introspection-runtime','graphene','gssdp','gst-plugins-bad-libs','gst-plugins-base-libs',
 'gstreamer','gtk4','gupnp','gupnp-igd','libgirepository','libnice','liburing','libva','libxv','numactl','orc','python-gobject',
 'vmaf','vulkan-icd-loader','xdg-desktop-portal','xdg-desktop-portal-gtk')
ALIASES={'official/'+name+'/'+kind:'official_'+name.replace('-','_')+'_'+kind for name in OFFICIAL for kind in ('archive','signature')}
ALIASES.update({'Setup8/archive':'setup8_archive','Setup8/current_signature':'setup8_current_signature',
 'Setup8/current_public_key':'setup8_current_public_key','Setup8/current_verification':'setup8_current_verification',
 'Setup8/current_decision':'setup8_current_decision','expected/backend':'expected_backend','expected/ui':'expected_ui',
 'expected/lifecycle':'expected_lifecycle','official/exact_closure':'official_exact_closure',
 'official/archive_signature_inputs':'official_archive_signature_inputs','prospective/inputs':'prospective_inputs',
 'expected/stage_vectors':'expected_stage_vectors','prospective/signed_lifecycle':'prospective_signed_lifecycle'})
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
PRODUCT_KEYS={'archives','signature','Root_decision','Root_verification','producer_delegation','producer_context','pair','test'}
SELECTED_KIND='ROOT_SELECTED_PRODUCT_INPUT_REFS_V4'
SELECTED_KEYS={'kind','selection_role','archives','signatures','producer_delegation','producer_context','completion','pair','root_component','root_test'}

class MissingInput(ValueError):
    def __init__(self,role): self.role=role;super().__init__('missing actual input: '+role)

def need(ok,why):
    if not ok: raise ValueError(why)

def required(value,role):
    if value is None: raise MissingInput(role)
    return value

def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def decoded(raw):
    def pairs(rows):
        result={}
        for key,value in rows: need(key not in result,'duplicate JSON key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
    encoded(value);need(type(value)is dict,'JSON object required');return value

def number(value,low=1,high=2**63-1):
    need(type(value)is int and low<=value<=high,'bounded integer');return value

def absolute(path):
    need(type(path)in(str,Path)or isinstance(path,Path),'explicit path')
    path=Path(path);need(path.is_absolute()and str(path)==os.path.normpath(str(path))and
        not any(p.is_symlink()for p in(path,*path.parents)),'absolute ordinary nonaliased operand')
    return path

def whole(row,cap=1024**3,body=False,verify=True):
    need(type(row)is dict and set(row)=={'path','bytes','sha256'},'exact whole reference')
    number(row['bytes'],0,cap);need(type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'whole SHA256')
    if not verify:
        need(not body,'body reads always verified');return absolute(row['path'])
    path=absolute(row['path']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==row['bytes']and not before.st_mode&0o022,'bounded ordinary single-link whole file')
        size=0;h=hashlib.sha256();parts=[]
        while block:=os.read(fd,1024**2):
            size+=len(block);need(size<=row['bytes'],'whole file grew');h.update(block)
            if body:parts.append(block)
        stable=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        need(size==row['bytes']and h.hexdigest()==row['sha256']and stable(before)==stable(os.fstat(fd))==stable(path.lstat()),'whole file hash/stability')
    finally:os.close(fd)
    return b''.join(parts)if body else path

def load(row,cap=2*1024**2): return decoded(whole(row,cap,True))
def same_pin(a,b): return {k:a[k]for k in('bytes','sha256')}==b

def template():
    return dict(schema=3,kind='CURRENT_ONBOARDING_INPUT_REQUEST_V3',stage=None,source_date_epoch=None,
        base_lock=None,bootstrap_profile=None,base_materials=None,supplemental_materials=None,keyring_materials=None,
        official_trust=None,test_trust=None,products=None,retention=None)

def base349_inputs(*,source_root,source_rows,request,verify_archives=True):
    """Join the original signed341 and fixed8 without rewriting the held lock."""
    root=absolute(source_root);factory_ref=dict(path=str(root/FACTORY),**FACTORY_PIN)
    need({k:source_rows[FACTORY][k]for k in('bytes','sha256')}==FACTORY_PIN,'factory joins whole verified Source')
    factory=load(factory_ref)
    base_ref=required(request['base_lock'],'base_lock');need(same_pin(base_ref,dict(bytes=BASE_BYTES,sha256=BASE_SHA)),'fixed original248 lock')
    bootstrap_ref=required(request['bootstrap_profile'],'bootstrap_profile');need(same_pin(bootstrap_ref,BOOTSTRAP_PIN),'fixed original signed341 plus fixed8 bootstrap profile')
    base=load(base_ref);bootstrap=load(bootstrap_ref)
    member='inputs/stages/baseline349.expected.lock';baseline_ref=dict(path=str(root/member),**{k:source_rows[member][k]for k in('bytes','sha256')})
    baseline_raw=whole(baseline_ref,1024**2,True);need(pin(baseline_raw)['sha256']==BASELINE_SHA,'held349 version vector')
    for name,wanted in(('bootstrap/scripts/ci/inputs.lock.json',dict(bytes=BASE_BYTES,sha256=BASE_SHA)),('native/input-profile.json',BOOTSTRAP_PIN),('native/expected349.lock',pin(baseline_raw))):
        need(factory['parent_files'][name]==dict(wanted,mode=0o644),'original parent descriptor: '+name)
    baseline=inventory(baseline_raw,349)
    need(len(base['rootfs_packages'])==165 and len(base['packages'])==248 and len({r['name']for r in base['packages']})==248,'complete original165/248 input records')
    versions={}
    for row in base['rootfs_packages']:
        need(all(type(row[k])is list and len(row[k])==1 for k in('name','version','arch'))and row['name'][0]not in versions and row['arch'][0]in('any','aarch64'),'unique typed rootfs identities')
        versions[row['name'][0]]=row['version'][0]
    for row in base['packages']:
        need(row['arch']in('any','aarch64'),'exact base architecture');versions[row['name']]=row['version']
    need(len(versions)==341 and bootstrap['original341']['package_count']==341 and bootstrap['original341']['packages']==versions,'authentic original341 union')
    supplement=bootstrap['additions'];rows=supplement['rows']
    need(len(rows)==8 and {r['name']for r in rows}==SUPPLEMENT and supplement['count']==8
        and supplement['expected_augmented_package_count']==349 and not supplement['unresolved'],'exact fixed8 supplement')
    for row in rows:
        need(row['name']not in versions and row['arch']in('any','aarch64'),'supplements never replace original341');versions[row['name']]=row['version']
    need(versions==baseline,'exact signed341 plus fixed8 final349 versions')
    need(len(base['keyring_files'])==3 and {r['filename']for r in base['keyring_files']}==KEYRINGS,'original public keyring closure')
    groups={};paths=[]
    for key,records,count,signed in(('base_materials',[base['rootfs'],*base['packages']],498,True),
        ('supplemental_materials',rows,16,True),('keyring_materials',base['keyring_files'],3,False)):
        materials=required(request[key],key);wanted={r['filename']+suffix for r in records for suffix in(('', '.sig')if signed else('',))}
        need(type(materials)is dict and len(wanted)==count,'exact fixed material group')
        extra=set(materials)-wanted;need(not extra,'unknown selected '+key+' operands')
        missing=wanted-set(materials)
        if missing:raise MissingInput(key+'/'+sorted(missing)[0])
        for row in records:
            for suffix in(('', '.sig')if signed else('',)):
                value=materials[row['filename']+suffix];size=row['signature_size']if suffix else row['size'];sha=row['signature_sha256']if suffix else row['sha256']
                need(same_pin(value,dict(bytes=size,sha256=sha)),'fixed whole material pin: '+key+'/'+row['filename']+suffix)
                whole(value,1024**2 if suffix or not signed else 1024**3,verify=verify_archives);paths.append(value['path'])
        groups[key]=materials
    need(len(paths)==len(set(paths))==517,'distinct complete517 selected material paths')
    return dict(base_lock=base_ref,bootstrap_profile=bootstrap_ref,baseline_inventory=baseline_ref,**groups),base,baseline

def inventory(raw,count):
    rows={}
    for line in raw.decode('ascii').splitlines():
        need(re.fullmatch(r'[a-z0-9][a-z0-9@._+-]* [^\s]+',line),'typed package inventory')
        name,version=line.split(' ');need(name not in rows,'duplicate inventory package');rows[name]=version
    need(len(rows)==count and raw==''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode(),'whole sorted inventory')
    return rows

def _context(delegation_raw,delegation_sha256,c,source,H):
    need(pin(delegation_raw)['sha256']==delegation_sha256,'external Root-selected delegation SHA before program load')
    d=decoded(delegation_raw);root=absolute(source)
    if H is None:
        row=d['programs']['context'];member=row['member'];need(not Path(member).is_absolute()and'..'not in Path(member).parts,'closed context program')
        body=whole(dict(path=str(root/member),**{k:row[k]for k in('bytes','sha256')}),128*1024,True)
        spec=importlib.util.spec_from_file_location('current_inputs_context',root/member);H=importlib.util.module_from_spec(spec)
        exec(compile(body,str(root/member),'exec'),H.__dict__)
    d=H.validate_delegation(delegation_raw,delegation_sha256)
    need(H.OPERATION==OP and H.DELEGATION in('ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3','ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4')
        and d['kind']==H.DELEGATION and d['schema']==(4 if H.DELEGATION.endswith('_V4')else 3),'exact selected Source context API/version, no identity projection')
    if c is not None:H.validate_context(d,c)
    verified,rows=H.source(d,root);need(verified==root and d['stage']in COUNTS and
        (c is None or(c['source_root']==str(root)and c['stage']==d['stage'])),'same whole closed Source/context/stage')
    own=d['programs']['inputs_assembler'];need(own['member']in rows and H.descriptor(own)==pin(Path(__file__).read_bytes()),'executing exact reviewed inputs_assembler role')
    return d,root,H,rows

def source_inputs(root,d,H,source_rows):
    def selected_ref(selected):
        need(type(selected)is dict and set(selected)=={'member','bytes','sha256'},'exact Source material descriptor')
        member=selected['member'];need(type(member)is str and not Path(member).is_absolute()and '..'not in Path(member).parts,'ordinary Source-relative material member')
        need(member in source_rows and {k:source_rows[member][k]for k in('bytes','sha256')}==H.descriptor(selected),'material joins complete verified Source')
        row=dict(path=str(root/member),**H.descriptor(selected))
        whole(row,16*1024**2);return row
    # Resolve the closure once above; every selected material also retains its exact whole pin.
    member='inputs/delegated-materials-v4.json';raw=whole(dict(path=str(root/member),**{k:source_rows[member][k]for k in('bytes','sha256')}),1024**2,True);table=decoded(raw)
    need(set(table)=={'schema','kind','aliases','materials'}and type(table['schema'])is int and table['schema']==4
         and table['kind']=='DELEGATED_SOURCE_RELATIVE_MATERIALS_V4'and table['aliases']==ALIASES
         and type(table['materials'])is dict and set(table['materials'])==set(ALIASES.values()),'exact original59 roles and fixed aliases')
    need(len({row['member']for row in table['materials'].values()})==59,'distinct carrier material members')
    original=table['materials'];need(type(d['materials'])is dict and all(d['materials'].get(k)==v for k,v in original.items()),'all original59 Root selections unchanged')
    registry=load(dict(path=str(root/REGISTRY),**{k:source_rows[REGISTRY][k]for k in('bytes','sha256')}))if REGISTRY in source_rows else None
    staging=STAGING_TABLE in source_rows or set(d['materials'])!=set(original)or(registry is not None and 'staging_materials'in registry)
    if staging:
        need(STAGING_TABLE in source_rows and registry is not None,'explicit supplemental Source table and registry required')
        for name in(STAGING_TABLE,REGISTRY):need(source_rows[name]['mode']==0o644,'ordinary supplemental table/registry Source mode')
        supplemental=load(dict(path=str(root/STAGING_TABLE),**{k:source_rows[STAGING_TABLE][k]for k in('bytes','sha256')}))
        need(set(supplemental)=={'schema','kind','materials'}and type(supplemental['schema'])is int and supplemental['schema']==4
            and supplemental['kind']=='DELEGATED_MATERIAL_STAGING_SOURCE_MATERIALS_V4'and type(supplemental['materials'])is dict
            and set(supplemental['materials'])==set(STAGING_MATERIALS),'exact optional supplemental5 table')
        extra=supplemental['materials']
        need(type(registry['schema'])is int and registry['schema']==4 and registry['kind']=='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4'
            and registry['operation']==OP and registry['staging_materials']==extra,'whole Source registry selects exact same supplemental5')
        need(set(d['materials'])==set(original)|set(extra)and all(d['materials'][k]==v for k,v in extra.items()),'exact Root-selected original59 plus supplemental5')
        need(all(type(v)is dict and set(v)=={'member','bytes','sha256'}for v in extra.values()),'typed supplemental descriptors')
        need(len({v['member']for v in d['materials'].values()})==64,'no supplemental/original/cross-role member aliases')
        for role,(member,sha)in STAGING_MATERIALS.items():
            row=extra[role];need(row['member']==member and row['sha256']==sha,'fixed supplemental role/member/pin: '+role)
            need(member in source_rows and source_rows[member]['mode']==0o644,'fixed supplemental Source member mode');selected_ref(row)
            if role=='staging_base_lock':need(row['bytes']==BASE_BYTES,'fixed staging lock size')
            if role=='staging_bootstrap_profile':need(row['bytes']==BOOTSTRAP_PIN['bytes'],'fixed staging bootstrap size')
    else:need(d['materials']==original,'exact default59 materials')
    refs={name:selected_ref(d['materials'][alias])for name,alias in ALIASES.items()}
    profile_raw=whole(dict(path=str(root/PROFILE),**PROFILE_PIN),1024**2,True)
    profile=decoded(profile_raw);need(profile['operation']==OP and all(v is None for v in profile['actual'].values()),'unissued exact recipe profile')
    return refs,profile

def trust(row,kind,fingerprint,now):
    required(row,kind+'_trust');need(type(row)is dict and set(row)=={'public_key','fingerprint','Root_admission'},'explicit current trust input')
    need(row['fingerprint']==fingerprint and re.fullmatch('[0-9A-F]{40}',fingerprint),'exact current primary fingerprint')
    public=whole(row['public_key'],65536,True);need(b'PRIVATE KEY'not in public,'public certificate only')
    a=load(row['Root_admission']);need(a['issuer']=='Root'and a['approved']is True and a['scope']=='CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY'
        and a['public_key']==row['public_key']and a['fingerprint']==fingerprint and type(a['issued_epoch'])is type(a['expires_epoch'])is int
        and a['issued_epoch']<=now<a['expires_epoch'],'actual current separately Root-issued public trust DATA')
    return row

def project_proof(row,key,name,version):
    decision,proof=load(row['Root_decision']),load(row['Root_verification']);ar={k:row['archive'][k]for k in('bytes','sha256')};sig={k:row['signature'][k]for k in('bytes','sha256')}
    public=dict({k:key['public_key'][k]for k in('bytes','sha256')},fingerprint=key['fingerprint'],trust_scope='TEST_ONLY')
    expected='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY'if name=='cachy-asahi-setup'else'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'
    need(decision['schema']==1 and decision['issuer']=='Root'and decision['accepted']is decision['holds_preserved']is True
        and decision['status']==expected and decision['trust_scope']=='TEST_ONLY'and decision['archive']==dict(ar,package=name,version=version,arch='any')
        and decision['signature']==sig and decision['public_test_key']==public and decision['verification_proof_sha256']==row['Root_verification']['sha256'],'exact historical Root project decision joins')
    need(proof['schema']==1 and proof['Root_issuer']=='Root'and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE'and proof['verified']is True
        and proof['trust_scope']=='TEST_ONLY'and proof['archive']==ar and proof['signature']==sig and proof['public_test_key']==public,'exact Root public TEST verification joins')

def product(kind,row,profile,d,c,H,key,verify_archives=True):
    if d['capability'].get('allow_selected_pair_adoption')is True:
        return selected_product(kind,row,profile,d,H,key,verify_archives)
    need(d['schema']==3 and H.DELEGATION=='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3','unchanged strict v3 product route')
    required(row,'products.'+kind);need(type(row)is dict and set(row)==PRODUCT_KEYS,'exact actual product references')
    need(type(row['archives'])is list and len(row['archives'])==2,'two actual native product bodies')
    for ar in row['archives']:whole(ar,16*1024**2,verify=verify_archives)
    ar=row['archives'][0];need(same_pin(row['archives'][1],{k:ar[k]for k in('bytes','sha256')}),'complete compressed product pair equality')
    whole(row['signature'],65536,verify=verify_archives)
    for name in PRODUCT_KEYS-{'archives','signature'}:whole(row[name],2*1024**2)
    producer_raw=whole(row['producer_delegation'],2*1024**2,True);producer=H.validate_delegation(producer_raw,row['producer_delegation']['sha256'])
    observed=load(row['producer_context']);H.validate_context(producer,observed)
    stage='ui'if kind=='ui'else'backend';need(producer['stage']==stage and d['capability']['allow_pair_adoption']is True
        and same_pin(row['producer_delegation'],d['private_stage_producers'][stage]),'Root-selected actual product producer')
    target=d['binding']if c is None else c['binding']
    need(all(observed['binding'][k]==target[k]for k in('source','ref','attempt','source_lock'))and
        (c is None or observed['binding']['run']==target['run'])and all(type(observed['binding'][k])is str and re.fullmatch('[1-9][0-9]*',observed['binding'][k])for k in('run','job')),'same actual Source and observed product run/job')
    recipe=profile['packages'][kind];pair=load(row['pair']);proof=load(row['test'])
    for value,expected in((pair,'DELEGATED_CURRENT_ONBOARDING_PAIR_V3'),(proof,'DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3')):
        need(value['schema']==3 and value['kind']==expected and value['issuer']=='DELEGATED_CURRENT_OWNER_V3'
            and value['binding']==observed['binding']and value['nonce']==producer['nonce']and value['program_pin']==H.descriptor(producer['programs']['owner'])
            and value['policy_pin']==H.descriptor(producer['policy'])and all(value.get(k)==v and type(value.get(k))is type(v)for k,v in FINAL.items()),'actual delegated product proof binding, no final authority')
    archive_pin={k:ar[k]for k in('bytes','sha256')};signature_pin={k:row['signature'][k]for k in('bytes','sha256')}
    need(pair['matching_pair']is True and pair['package']==recipe['name']and pair['version']==recipe['version']and pair['archives']==[archive_pin]*2,'current package/version and complete pair')
    need(proof['pair_pin']=={k:row['pair'][k]for k in('bytes','sha256')}and proof['public_test_key_pin']=={k:key['public_key'][k]for k in('bytes','sha256')}
        and proof['fingerprint']==key['fingerprint']and proof['trust_scope']=='TEST_ONLY'and len(proof['verifications'])==2,'same pair and public TEST proof')
    forbidden={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    for verification in proof['verifications']:
        natural=verification['supervision'];need(verification['archive']==archive_pin and verification['signature']==signature_pin and natural['reaped']is True
            and natural['ownership']=='REAPED'and natural['group_census']=='EMPTY_TWICE'and natural['output_complete']is True and natural['timeout']is False
            and natural['signals']==[]and natural['error']is None and type(natural['exit'])is int and natural['exit']==0,'natural retained TEST verification')
        status=verification['status'];need(type(status)is str and len(status)<=65536,'bounded retained public status')
        lines=[line.split()[1:]for line in status.splitlines()if line.startswith('[GNUPG:] ')]
        valid=[r for r in lines if r and r[0]=='VALIDSIG'];need(not any(r and r[0]in forbidden for r in lines)and len(valid)==1 and len(valid[0])==11
            and valid[0][1]==valid[0][-1]==key['fingerprint']and any(r and r[0]=='TRUST_ULTIMATE'for r in lines),'strict retained primary TEST verification DATA')
    effective=dict(name=recipe['name'],version=recipe['version'],arch='any',archive=ar,signature=row['signature'],
        Root_decision=row['Root_decision'],Root_verification=row['Root_verification'],payload_files=recipe['payload_files'])
    project_proof(effective,key,recipe['name'],recipe['version']);return effective

def selected_product(kind,row,profile,d,H,key,verify_archives=True):
    """Preflight selected bodies without inventing a poststart consumer context."""
    need(d['schema']==4 and H.DELEGATION=='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4'
        and d['kind']==H.DELEGATION and d['capability']['allow_pair_adoption']is False,'distinct whole-pinned context-v4 selected capability')
    need(type(row)is dict and set(row)==SELECTED_KEYS and row['kind']==SELECTED_KIND,'explicit v4 selected product shape, no v3 relabelling')
    role=row['selection_role']
    if 'pair_selections'in d:
        need(type(role)is str and role in d['pair_selections']and'pair_selection'not in d,'explicit exact selected component role');s=d['pair_selections'][role]
    else:need(role is None and'pair_selection'in d,'explicit single selection with no invented role');s=d['pair_selection']
    recipe=profile['packages'][kind];component=dict(name=recipe['name'],version=recipe['version'],architecture='any')
    need(s['component']==component and s['test_fingerprint']==key['fingerprint']and s['public_test_key_pin']=={k:key['public_key'][k]for k in('bytes','sha256')},'selected exact current component/key identity')
    for group in('archives','signatures'):
        need(type(row[group])is list and len(row[group])==2 and type(s[group])is list and len(s[group])==2,'both selected archive/signature refs and pins')
        for value,wanted in zip(row[group],s[group]):
            need(same_pin(value,wanted),'exact Root-selected body pin');whole(value,16*1024**2 if group=='archives'else 65536,verify=verify_archives)
    fields={'producer_delegation':'producer_delegation_pin','producer_context':'producer_context_pin','completion':'completion_pin','pair':'pair_pin',
        'root_component':'root_component_decision_pin','root_test':'root_test_decision_pin'}
    bodies={}
    for field,selected_pin in fields.items():
        need(same_pin(row[field],s[selected_pin]),'exact selected proof/delegation operand');bodies[field]=whole(row[field],2*1024**2,True)
    producer,observed=decoded(bodies['producer_delegation']),decoded(bodies['producer_context'])
    need(bodies['producer_delegation']==encoded(producer)and bodies['producer_context']==encoded(observed),'unchanged canonical historical producer bytes')
    need(observed['binding']==s['producer_binding']and all(producer['binding'][k]==d['binding'][k]==s['producer_binding'][k]for k in('source','ref','source_lock')),'selected original actual producer tuple and same Source/ref/map')
    completion=decoded(bodies['completion']);need(type(completion['schema'])is int and completion['schema']==1 and completion['kind']=='CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4'
        and completion['producer_binding']==s['producer_binding']and completion['producer_delegation_pin']==s['producer_delegation_pin']
        and completion['producer_context_pin']==s['producer_context_pin']and type(completion['observed_epoch'])is int
        and 0<=d['issued_epoch']-completion['observed_epoch']<=s['max_producer_age_seconds'],'actual selected completion precedes consumer issuance')
    pair=decoded(bodies['pair']);version=producer['schema']
    need(type(version)is int and version in(3,4)and pair['schema']==version and pair['kind']=='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(version)
        and pair['issuer']=='DELEGATED_CURRENT_OWNER_V'+str(version)and pair['binding']==s['producer_binding']and pair['component']==component
        and pair['archives']==s['archives']and pair['matching_pair']is True and pair['nonce']==producer['nonce']
        and pair['program_pin']==H.descriptor(producer['programs']['owner'])and pair['policy_pin']==H.descriptor(producer['policy'])
        and all(pair.get(k)==v and type(pair.get(k))is type(v)for k,v in FINAL.items()),'original selected pair identity without upgraded acceptance')
    for field,expected in(('root_component','ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4'),('root_test','ROOT_SELECTED_CURRENT_ONBOARDING_TEST_V4')):
        decision=decoded(bodies[field]);need(decision['schema']==4 and decision['issuer']=='Root'and decision['approved']is True and decision['kind']==expected
            and decision['operation']==OP and decision['scope']=='CURRENT_PRIVATE_COMPONENT_ONLY'and decision['Root_final_acceptance']is None
            and decision['hardware_acceptance']is decision['release_acceptance']is False,'separate authentic selected Root decision shape')
        for name in('producer_binding','producer_delegation_pin','producer_context_pin','completion_pin','component','pair_pin','archives'):
            need(decision[name]==s[name],'exact selected Root decision join')
        need(type(decision['issued_epoch'])is type(decision['expires_epoch'])is int and completion['observed_epoch']<=decision['issued_epoch']<=d['issued_epoch']
            and decision['issued_epoch']<=time.time()<decision['expires_epoch']and 0<decision['expires_epoch']-decision['issued_epoch']<=d['context_limits']['max_delegation_seconds'],'current selected Root decision; historical producer never renewed')
        if field=='root_test':need(decision['signatures']==s['signatures']and decision['public_test_key_pin']==s['public_test_key_pin']
            and decision['test_fingerprint']==s['test_fingerprint']and decision['trust_scope']=='TEST_ONLY','selected Root TEST signature/key join')
    return dict(name=recipe['name'],version=recipe['version'],arch='any',archive=row['archives'][0],signature=row['signatures'][0],
        Root_decision=row['root_component'],Root_verification=row['root_test'],payload_files=recipe['payload_files'],pair_adoption=copy.deepcopy(row))

def _assembly(*,delegation_raw,delegation_sha256,context,source_root,request,output,context_program=None,now=None,verify_archives=True,check_only=False):
    now=time.time()if now is None else now;need(type(now)in(int,float)and math.isfinite(now),'finite observed time')
    d,root,H,source_rows=_context(delegation_raw,delegation_sha256,context,source_root,context_program)
    need(type(request)is dict and set(request)==set(template())and request['schema']==3 and request['kind']==template()['kind'],'exact input request schema')
    stage=required(request['stage'],'stage');need(stage==d['stage'],'same requested current stage')
    epoch=number(required(request['source_date_epoch'],'source_date_epoch'),0)
    retention=request['retention']
    if stage=='lifecycle':
        if retention is None:raise MissingInput('retention.prior_backend')
        need(type(retention)is dict,'explicit lifecycle capsule references')
        for name in('prior_backend','prior_ui'):required(retention.get(name),'retention.'+name)
        need(set(retention)=={'prior_backend','prior_ui'},'exact lifecycle prior capsule roles')
        for value in retention.values():
            need(not absolute(value['path']).is_relative_to(root),'explicit external selected prior capsule, never a discovered Source/private path')
            whole(value,64*1024**2,verify=verify_archives)
    else:need(retention is None or(type(retention)is dict and not retention),'backend/UI retention absent or empty only')
    refs,profile=source_inputs(root,d,H,source_rows)
    base_fields,base,baseline=base349_inputs(source_root=root,source_rows=source_rows,request=request,verify_archives=verify_archives)
    official_trust=trust(request['official_trust'],'official',base['signer_fingerprint'],now)
    setup_proof=load(refs['Setup8/current_verification']);test_trust=trust(request['test_trust'],'test',setup_proof['public_test_key']['fingerprint'],now)
    need(same_pin(test_trust['public_key'],{k:refs['Setup8/current_public_key'][k]for k in('bytes','sha256')}),'same retained Setup8 public TEST certificate')
    policy=d['policy'];selected_test=load(dict(path=str(root/policy['member']),**H.descriptor(policy)))['private_stage']['test']
    need(selected_test==dict(fingerprint=test_trust['fingerprint'],public_key_role=ALIASES['Setup8/current_public_key']),
        'same exact Source policy TEST fingerprint and original public key role')
    setup=dict(name='cachy-asahi-setup',version='0.3.0-1',arch='any',archive=refs['Setup8/archive'],signature=refs['Setup8/current_signature'],
        Root_decision=refs['Setup8/current_decision'],Root_verification=refs['Setup8/current_verification'],payload_files=profile['setup8']['payload_files'])
    need(same_pin(setup['archive'],profile['setup8']['archive_pin']),'genuine qualified Setup8 dependency')
    project_proof(setup,test_trust,setup['name'],setup['version'])
    catalog=load(refs['official/exact_closure']);table_doc=load(refs['official/archive_signature_inputs']);table=table_doc['packages'];selected=catalog['selected'];operational={}
    need(set(selected)==set(table)==set(OFFICIAL)and catalog['addition_count']==23 and catalog['expected_final_official_count']==372
        and catalog['Root_acceptance']is catalog['Root_current_official_signature_admission']is None
        and table_doc['Root_current_official_trust']is table_doc['Root_current_verification']is None
        and all(not catalog[k]for k in('unresolved','ambiguous','conflicts','ordering_comparisons_pending','conflict_ordering_pending')),'exact transitive23 official package closure; historical trust unchanged')
    for name,row in selected.items():
        item=table[name];need(name not in baseline and item['name']==name and(row['version'],row['arch'],row['filename'])==(item['version'],item['arch'],item['filename'])and row['arch']in('any','aarch64'),'same official identity/epoch/arch/filename')
        body=dict(name=name,version=row['version'],arch=row['arch'],filename=row['filename'])
        for kind in('archive','signature'):
            value=refs['official/'+name+'/'+kind];need(same_pin(value,row[kind])and same_pin(item[kind],row[kind]),'same official whole body/signature')
            body[kind]=value
        operational[name]=body
    expected=dict(baseline)
    if stage in('lifecycle','ui'):expected.update({n:r['version']for n,r in selected.items()})
    if stage in('backend','ui'):expected['cachy-asahi-setup']='0.3.0-1'
    if stage=='ui':expected['cachy-asahi-first-login']='0.1.0-3'
    need(inventory(whole(refs['expected/'+stage],1024**2,True),COUNTS[stage])==expected,'complete exact stage inventory')
    products=required(request['products'],'products');wanted_products=set()if stage=='backend'else{'first-login'}if stage=='ui'else{'enrollment','first-login','ui'}
    need(type(products)is dict and set(products)==wanted_products,'exact currently required product set; no future product placeholders')
    effective={k:product(k,row,profile,d,context,H,test_trust,verify_archives)for k,row in products.items()}
    image=dict(base_fields,official_catalog=refs['official/exact_closure'],official_trust=official_trust,test_trust=test_trust)
    if stage in('backend','ui'):image.update(setup8=setup)
    if stage=='ui':
        row=products['first-login'];image['cli03']=effective['first-login']if row.get('kind')==SELECTED_KIND else dict(effective['first-login'],pair_adoption={k:row[k]for k in('producer_delegation','producer_context','pair','test')})
    owner=dict(schema=3,kind='DELEGATED_CURRENT_PRIVATE_INPUTS_V3',source_date_epoch=epoch,
        setup8={key+'_role':ALIASES[role]for key,role in(('archive','Setup8/archive'),('signature','Setup8/current_signature'),('decision','Setup8/current_decision'),('verification','Setup8/current_verification'))},products=copy.deepcopy(products))
    if retention is not None:owner['retention']=copy.deepcopy(retention)
    out=absolute(output);need(out.parent.is_dir()and not out.is_relative_to(root)and not root.is_relative_to(out),'disjoint operational input output')
    table_raw=encoded(dict(packages=operational));table_path=out/'official-materials.json'
    if not check_only:
        need(not out.exists(),'fresh operational output');out.mkdir(mode=0o700)
        table_path.write_bytes(table_raw);table_path.chmod(0o600)
    image['official_materials']=dict(path=str(table_path),**pin(table_raw))
    result=dict(image_inputs=image,stage_inputs=owner)
    raw=encoded(result);need(len(raw)<=2*1024**2,'bounded complete operational JSON')
    if not check_only:
        (out/'owner-inputs.json').write_bytes(raw);(out/'owner-inputs.json').chmod(0o600)
        report=dict(schema=3,kind='ASSEMBLED_CURRENT_ONBOARDING_INPUTS_DATA_V3',api=API,stage=stage,binding=d['binding'],owner_inputs_pin=pin(raw),
            provenance=dict(original_roles=refs,source_map=d['binding']['source_lock'],delegation=pin(delegation_raw),material_aliases=ALIASES),
            inputs_complete=True,authority_issued=False,**FINAL)
        (out/'assembly.DATA.json').write_bytes(encoded(report));(out/'assembly.DATA.json').chmod(0o600)
    return result

def references(value):
    rows={}
    def visit(item):
        if type(item)is dict:
            if set(item)=={'path','bytes','sha256'}:
                whole(item,verify=False);path=item['path']
                need(path not in rows or rows[path]==item,'conflicting duplicate input reference');rows[path]=item
            else:
                for child in item.values():visit(child)
        elif type(item)is list:
            for child in item:visit(child)
    visit(value);need(len(rows)<=1024,'finite declared whole references');return [rows[k]for k in sorted(rows)]

def assemble_inputs(*,delegation_raw,delegation_sha256,source_root,request,output,context=None,context_program=None,now=None):
    """Write canonical staged wrapper after whole verification; issue no authority."""
    owner=_assembly(delegation_raw=delegation_raw,delegation_sha256=delegation_sha256,context=context,source_root=source_root,
        request=request,output=output,context_program=context_program,now=now)
    root=absolute(source_root);external=[row for row in references(owner)if not Path(row['path']).is_relative_to(root)]
    value=dict(schema=3,kind='ROOT_STAGED_CURRENT_INPUTS_V3',owner_inputs=owner,staged_refs=external)
    path=Path(output)/'inputs.json';path.write_bytes(encoded(value));path.chmod(0o600);return value

def owner_shape(inputs):
    need(type(inputs)is dict and set(inputs)=={'image_inputs','stage_inputs'}and all(type(value)is dict for value in inputs.values()),'exact canonical inner image_inputs/stage_inputs object')
    stage=inputs['stage_inputs']
    need(set(stage)in({'schema','kind','source_date_epoch','setup8','products'},{'schema','kind','source_date_epoch','setup8','products','retention'})and type(stage['schema'])is int and stage['schema']==3
        and stage['kind']=='DELEGATED_CURRENT_PRIVATE_INPUTS_V3','exact explicit private stage inputs')
    number(stage['source_date_epoch'],0);need(type(stage['setup8'])is dict and type(stage['products'])is dict,'typed private stage operands')
    return inputs['image_inputs'],stage

def validate_owner_inputs_v3(*,inputs,delegation,source_root):
    """One read-only semantic implementation for the exact inner owner object.

    No external archive streaming, mutation, actor or authority. The launcher
    streams returned required_refs before sudo; runtime consumers recheck them.
    """
    image,stage=owner_shape(inputs);table=image['official_materials'];out=absolute(table['path']).parent
    request=dict(schema=3,kind=template()['kind'],stage=delegation['stage'],source_date_epoch=stage['source_date_epoch'],
        **{k:image[k]for k in('base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials')},
        official_trust=image['official_trust'],test_trust=image['test_trust'],products=stage['products'],retention=stage.get('retention'))
    raw=encoded(delegation)
    expected=_assembly(delegation_raw=raw,delegation_sha256=pin(raw)['sha256'],context=None,source_root=source_root,
        request=request,output=out,verify_archives=False,check_only=True)
    need(inputs==expected,'complete semantically reproduced image/owner inputs; no stale or unknown fields')
    whole(table,2*1024**2)
    root=absolute(source_root);required_refs=[row for row in references(expected)if not Path(row['path']).is_relative_to(root)]
    return dict(valid=True,required_refs=required_refs)

def validate_hosted_inputs_v3(*,inputs,delegation,source_root):
    """Validate only the outer envelope, then delegate all owner semantics once."""
    need(type(inputs)is dict and set(inputs)=={'schema','kind','owner_inputs','staged_refs'}and type(inputs['schema'])is int
        and inputs['schema']==3 and inputs['kind']=='ROOT_STAGED_CURRENT_INPUTS_V3','exact canonical staged wrapper')
    result=validate_owner_inputs_v3(inputs=inputs['owner_inputs'],delegation=delegation,source_root=source_root)
    need(type(inputs['staged_refs'])is list and inputs['staged_refs']==result['required_refs'],'exact complete staged ref closure, no omissions or extras')
    return result

def stage_inputs(document):
    """Hydrate only already pinned product references at the owner call boundary."""
    _,stage=owner_shape(document)
    result=copy.deepcopy(stage);products={};total=0;declared_total=0
    for kind,row in result['products'].items():
        groups=('archives','signatures')if row.get('kind')==SELECTED_KIND else('archives',)
        for group in groups:need(type(row[group])is list and len(row[group])==2,'exact two bodies before hydration')
        refs=[value for group in groups for value in row[group]]
        refs += [value for key,value in row.items()if key not in set(groups)|{'kind','selection_role'}]
        declared_total+=sum(number(value['bytes'],high=16*1024**2)for value in refs)
        need(declared_total<=128*1024**2,'whole product hydration budget before reads')
        if row.get('kind')==SELECTED_KIND:
            need(set(row)==SELECTED_KEYS,'exact selected serialized product input')
            product=dict(kind=SELECTED_KIND,selection_role=row['selection_role'])
            for group in('archives','signatures'):product[group]=[whole(value,16*1024**2 if group=='archives'else 65536,True)for value in row[group]]
            for field in SELECTED_KEYS-{'kind','selection_role','archives','signatures'}:product[field+'_raw']=whole(row[field],2*1024**2,True)
            product['producer_context']=decoded(product.pop('producer_context_raw'));total+=sum(len(body)for group in('archives','signatures')for body in product[group])
            total+=sum(len(body)for body in product.values()if type(body)is bytes);need(total<=128*1024**2,'bounded selected product bodies')
            products[kind]=product;continue
        need(set(row)==PRODUCT_KEYS,'exact serialized product input')
        bodies={key:whole(row[key],65536 if key=='signature'else 2*1024**2,True)for key in PRODUCT_KEYS-{'archives'}}
        archives=[whole(ref,16*1024**2,True)for ref in row['archives']];total+=sum(map(len,archives))+sum(map(len,bodies.values()))
        need(total<=128*1024**2 and len(archives)==2 and archives[0]==archives[1],'bounded whole genuine product bodies')
        products[kind]=dict(archives=archives,signature=bodies['signature'],producer_delegation_raw=bodies['producer_delegation'],
            producer_context=decoded(bodies['producer_context']),pair_raw=bodies['pair'],test_raw=bodies['test'],
            Root_decision_raw=bodies['Root_decision'],Root_verification_raw=bodies['Root_verification'])
    result['products']=products;return result

def adopt_selected_inputs(*,document,delegation_raw,delegation_sha256,context,source_root):
    """Full v4 historical/completion replay only after real consumer capture."""
    required(context,'actual_poststart_consumer_context');need(type(context)is dict,'actual poststart consumer context object')
    d,root,H,_=_context(delegation_raw,delegation_sha256,context,source_root,None)
    need(d['schema']==4 and H.DELEGATION=='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4'
        and d['capability'].get('allow_selected_pair_adoption')is True and callable(getattr(H,'adopt_selected_pair',None)),
        'whole-pinned explicit v4 selected-adoption API; no v3 fallback')
    expected=validate_owner_inputs_v3(inputs=document,delegation=d,source_root=root)
    need(expected['valid']is True,'same semantically validated staged inputs')
    policy=load(dict(path=str(root/d['policy']['member']),**H.descriptor(d['policy'])))['private_stage']['test']
    key=whole(document['image_inputs']['test_trust']['public_key'],65536,True);products=stage_inputs(document)['products'];receipts={}
    for kind,row in products.items():
        need(row.get('kind')==SELECTED_KIND,'no mixed v3/v4 selected products')
        receipt=H.adopt_selected_pair(d,context,producer_delegation_raw=row['producer_delegation_raw'],producer_context=row['producer_context'],
            completion_raw=row['completion_raw'],pair_raw=row['pair_raw'],root_component_raw=row['root_component_raw'],root_test_raw=row['root_test_raw'],
            archive_bodies=row['archives'],signature_bodies=row['signatures'],public_test_key_raw=key,selection_role=row['selection_role'])
        need(receipt['kind']=='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4'and receipt['binding']==context['binding']
            and receipt['test_fingerprint']==policy['fingerprint']and receipt['current_stage_gpg_required']is True
            and all(receipt.get(k)==v and type(receipt.get(k))is type(v)for k,v in FINAL.items()),'actual selected context replay, never GPG or final acceptance')
        receipts[kind]=receipt
    return receipts

if __name__=='__main__':raise SystemExit('Offline DATA callbacks only; no standalone authority or actor entry')
