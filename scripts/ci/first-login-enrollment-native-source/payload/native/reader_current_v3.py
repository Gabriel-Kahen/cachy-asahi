# SPDX-License-Identifier: MIT
"""Independent public-retention Reader: bytes only, no producer imports or actors."""
import ast
import base64
import datetime
import hashlib
import inspect
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import tarfile
import zlib

OP='first-login-enrollment-ui-current-v2'
KINDS=('enrollment','first-login','ui')
STAGES=('backend','ui','lifecycle')
VERSIONS={'enrollment':('cachy-asahi-repository-enrollment','0.4.0-1'),
          'first-login':('cachy-asahi-first-login','0.1.0-3'),
          'ui':('cachy-asahi-first-login-ui','0.2.0-2')}
COUNTS={'backend':350,'ui':374,'lifecycle':372}
MAX_FILE=16*1024**2
MAX_COMPRESSED=8*1024**2
MAX_LOGICAL=16*1024**2
MAX_MEMBERS=512
MAX_SOURCE=96*1024**2
HELPER_COMMIT='1da96c5ed81a81c5d941161a2f7d0b5900d82d9d'
HELPER_SOURCE_SHA256='52f1453fa0c09e566a41a6d33ed94529353bddc1f0c9b468c64b6a71e33f3d24'
HELPER_PINS={'need': '88a702e4c7c7629f4c6a212862aaf78ae29573333a7044a20260f0039f1cb1ac', 'encoded': '18af7a3e841df4bf3c6fd3eeadbf31ad0f9dbf676c45118eda6d3821d653eebb', 'pin': '327cecfeba0345fbc09b3255daed14a41ea8b97ce2a7232e1abe98bcee1c44b0', 'decode': '74452604500e8254f1f56630515bc42296c75cec780a852c85cc083600dd20e8', 'relative': 'f8d96fa3c4bc217fe817854a163825c22202491f71751ea196c26925a227c3e0', 'metadata': '112732fd44e0fa38ae6f07b3c91651b8bad46f4d34d28a1cdcb7e24167f44cdc', 'inventory': '929e45cd158d9c22deca1da620581eadddc096474967be43dc9e5b849ee71139', 'inventory_bytes': '5fac63946070606e430bc119b1e020c141a4a1a5fc8a6b4aaecdb3f3dd164bce', 'check_log': '270c56094d1bee04aa097880ffea3c75ef55fafff106bee52dc4e65bba6b9d10', 'strict_signature': 'fd1cf54165adc10a6a213137fd15861177cbe9d21684f10a60a45fe4d1ff297f', 'archive_tar': '0f12411bde7e3fd117f073b06459e2bc489145d5002c25727242f76bab65767d', 'package': 'e213e38adf0a25c4d078ab30f2d8e40caeed397b50901d97de840497e6637cc3'}

def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(value):
    need(type(value) is str and 0<len(value.encode())<=4096 and not value.startswith('/') and
         not any(ord(c)<32 or ord(c)==127 or c=='\\' for c in value) and
         all(p not in ('','.','..') for p in value.split('/')),'literal relative DATA path')
    return value


def metadata(raw):
    need(type(raw) is bytes and len(raw)<=256*1024,'metadata cap')
    result={}
    for line in raw.decode('utf-8').split('\n'):
        if not line or line.startswith('#'):continue
        key,sep,value=line.partition(' = ')
        need(sep and re.fullmatch('[a-z][a-z0-9_]*',key) and len(value)<=8192 and '\r' not in value,'canonical package metadata')
        result.setdefault(key,[]).append(value)
    return result


def inventory(raw):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.endswith(b'\n'),'complete inventory bytes')
    result={}
    for line in raw.decode('ascii').split('\n')[:-1]:
        name,sep,version=line.partition(' ')
        need(sep and re.fullmatch('[a-z0-9@._+-]+',name) and re.fullmatch(r'[A-Za-z0-9.+_:~\-]+',version) and name not in result,'unique literal inventory row')
        result[name]=version
    return result


def inventory_bytes(rows):return ''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()


def check_log(raw,kind,profile):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.count(b'Starting check()')==1,'one bounded recipe check invocation')
    text=raw.decode('utf-8');need(not re.search(r'FAILED|ERROR:|\bskipped\b|expected failure',text,re.I),'failed/skipped checks refused')
    if kind=='enrollment':
        values=[]
        for line in text.split('\n'):
            if line.startswith('{'):
                try:values.append(decode(line.encode()))
                except ValueError:pass
        need(values==[profile['enrollment_check_report']],'exact current Enrollment04 check report')
    else:
        wanted=profile['packages'][kind]['check_counts']
        need(wanted==([14,6] if kind=='first-login' else [38,6]),'current check suite counts')
        need(re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$',text,re.M)==list(map(str,wanted)) and
             text.splitlines().count('OK')==2,'complete ordered native check suites')


def strict_signature(raw,fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    rows=[line.split()[1:] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in bad for row in rows),'bad TEST signature/key state')
    valid=[r for r in rows if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint and
         any(r and r[0]=='TRUST_ULTIMATE' for r in rows),'one exact trusted TEST primary')


def archive_tar(raw,recipe,packages,epoch=None):
    need(type(raw) is bytes and 0<len(raw)<=MAX_FILE and len(raw)%512==0,'bounded decoded package DATA')
    expected=recipe['payload_files'];parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
    seen=set();dirs=set();payload={};meta={};cursor=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for item in archive:
            name=item.name[:-1] if item.name.endswith('/') else item.name;relative(name)
            need(name not in seen and item.offset==cursor and item.offset_data==cursor+512 and not item.pax_headers and
                 item.uid==item.gid==0 and item.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),'closed single-header package framing')
            seen.add(name);end=item.offset_data+item.size;cursor=item.offset_data+(item.size+511)//512*512
            need(0<=item.size<=1024**2 and cursor<=len(raw) and not any(raw[end:cursor]),'package member/padding bound')
            if item.isdir():
                need(name in parents and item.mode==0o755 and item.size==0,'package directory namespace/mode');dirs.add(name);continue
            body=raw[item.offset_data:end]
            if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                need(item.mode==0o644,'package metadata mode');meta[name]=body
            else:
                need(name in expected and dict(mode=item.mode,**pin(body))==expected[name],'source-bound package payload')
                payload[name]=expected[name]
    need(dirs==parents and set(payload)==set(expected) and set(meta)=={'.PKGINFO','.BUILDINFO','.MTREE'} and
         len(raw)-cursor>=1024 and not any(raw[cursor:]),'complete package payload/metadata/trailer')
    pkg,build=metadata(meta['.PKGINFO']),metadata(meta['.BUILDINFO'])
    for key,value in (('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('arch','any')):
        need(pkg.get(key)==[value],'exact current PKGINFO identity')
    for key,field in (('depend','depends'),('makedepend','makedepends'),('checkdepend','checkdepends'),('optdepend','optdepends')):
        need(sorted(pkg.get(key,[]))==sorted(recipe.get(field,[])),'exact source dependency metadata')
    need(pkg.get('license')==['MIT'] and not any(k in pkg for k in ('provides','replaces','conflict','install','backup')),'private package metadata policy')
    for key,value in (('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact source BUILDINFO identity/recipe')
    need('check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'BUILDINFO checks enabled')
    labels={n+'-'+v:n for n,v in packages.items()};need(len(labels)==len(packages),'unambiguous installed labels')
    installed=build.get('installed',[]);need(len(installed)==len(set(installed))==len(packages),'complete builder installed inventory')
    names=set()
    for value in installed:
        label,sep,arch=value.rpartition('-');need(sep and arch in ('aarch64','any') and label in labels,'exact installed name/version; architecture syntax')
        names.add(labels[label])
    need(names==set(packages),'exact installed package membership')
    if epoch is not None:need(pkg.get('builddate')==build.get('builddate')==[str(epoch)],'stable source epoch metadata')
    return {'payload':payload,'metadata':meta}


def package(raw,recipe,packages,epoch=None):
    need(0<len(raw)<=MAX_FILE,'compressed package cap')
    if raw.startswith(b'\xfd7zXZ\0'):
        import lzma
        stream=lzma.LZMADecompressor(memlimit=64*1024**2);body=stream.decompress(raw,max_length=MAX_FILE+1)
        need(stream.eof and not stream.unused_data,'complete one XZ package frame')
    else:
        need(raw.startswith(b'\x28\xb5\x2f\xfd'),'exact zstd/XZ package framing')
        try:from compression import zstd
        except ImportError:raise ValueError('Python3.14 stdlib zstd required; no external decoder')
        with zstd.ZstdFile(io.BytesIO(raw),'rb') as stream:
            body=stream.read(MAX_FILE+1);need(stream.read(1)==b'','decoded package cap')
    return archive_tar(body,recipe,packages,epoch)


DOMAIN_POLICY=dict(endpoint='unix:///var/run/docker.sock',native_architecture='aarch64',rootful=True,cgroup='v2',
    network='none',no_new_privileges=True,cap_drop_all=True,
    mount_policy=dict(source_readonly=True,inputs_readonly=True,output_only_writable=True,no_daemon_socket=True),
    builder=dict(user='NONROOT',readonly_root=True,cpus=4,memory_bytes=4*1024**3,swap_bytes=0,pids=512),
    lifecycle=dict(user='0:0',python_parent='BASH_PID1',readonly_root=False,
                   capabilities=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID']))
PUBLIC={'context','domain','inventory','public_test_key','image_qualification','runtime','admission'}
BUILD_FILES={'build.log','validation.json','expected-packages.lock','artifacts/packages.lock',
             'artifacts/generated.SRCINFO','artifacts/environment.txt','artifacts/config.sha256',
             'artifacts/makepkg.conf','artifacts/pacman.conf'}
EXPECTED_KEYS={'schema','kind','stage','binding','capsule_pin','reader_pin','source_lock_pin','source',
               'public_pins','test_pins','support_pins','image','fingerprint','resources','observed_at','prior'}
OFFICIAL=('fuse-common','fuse3','gobject-introspection-runtime','graphene','gssdp','gst-plugins-bad-libs',
    'gst-plugins-base-libs','gstreamer','gtk4','gupnp','gupnp-igd','libgirepository','libnice','liburing','libva',
    'libxv','numactl','orc','python-gobject','vmaf','vulkan-icd-loader','xdg-desktop-portal','xdg-desktop-portal-gtk')
MATERIAL_ALIASES={'official/'+name+'/'+kind:'official_'+name.replace('-','_')+'_'+kind
    for name in OFFICIAL for kind in ('archive','signature')}
MATERIAL_ALIASES.update({'Setup8/archive':'setup8_archive','Setup8/current_signature':'setup8_current_signature',
    'Setup8/current_public_key':'setup8_current_public_key','Setup8/current_verification':'setup8_current_verification',
    'Setup8/current_decision':'setup8_current_decision','expected/backend':'expected_backend','expected/ui':'expected_ui',
    'expected/lifecycle':'expected_lifecycle','official/exact_closure':'official_exact_closure',
    'official/archive_signature_inputs':'official_archive_signature_inputs','prospective/inputs':'prospective_inputs',
    'expected/stage_vectors':'expected_stage_vectors','prospective/signed_lifecycle':'prospective_signed_lifecycle'})
HISTORICAL_ROLES={'v3_basis_owner','v3_basis_route','context','image','image_executor','delegated_owner','route',
    'retention','public_reader','policy','workflow','encoder'}
CURRENT_ROLES=HISTORICAL_ROLES|{'owned_process','hosted_launcher','inputs_assembler'}
HISTORICAL_CONSTRUCTOR_PIN=dict(bytes=15456,sha256='742308ab13be797192b805034b8c6404475e76a2c608ac91b7f0bc66e2274ea7')
CURRENT_CONSTRUCTOR_PIN=dict(bytes=16211,sha256='24bf8c841fe9eb9608a183e101de8f3a6ce1f72f974d003eb88cbcd65fcb318d')
HISTORICAL_FULL_POLICY_PIN=dict(bytes=5314,sha256='4d3452ba28366f5cebc0217158c014f9944fa4a417e867014815f4d15aef15ee')
FULL_POLICY_PIN=dict(bytes=5478,sha256='075f517e04cee255650897c5b71545fbe394928699d73502184ebe95b7b39d1a')
PREREQUISITE_FILES={
    'host_prerequisites':('scripts/ci/first-login-enrollment-native-source/payload/native/host_prerequisites_current_v3.py',13750,
        '521163f6f9504edaa573fa079751d7714065bea2ceef69428e8bc7585e361daa'),
    'host_prerequisite_plan':('scripts/ci/fish-config02-native-source/successor_v2/host_prerequisites.py',13845,
        '4bef653f0e999876e8dd1e74e7d61b808182f7528f4f50ce6444e14f6ff33d64'),
    'host_prerequisite_tools':('scripts/ci/fish-config02-native-source/successor_v2/host_tools.py',5273,
        '5f980d2df87cebdf264167e7be7220485a6fcc555667782d31316da0d08aef72'),
    'host_prerequisite_runner_basis':('scripts/ci/fish-config02-native-source/successor_v2/hosted_owner.py',31464,
        '7f4d2a68f13a2439a4363cfb154553dc9e721a88dc985080dd290d44583ad634')}
PREREQUISITE_ROLES=CURRENT_ROLES|set(PREREQUISITE_FILES)
PREREQUISITE_POLICY=dict(kind='CURRENT_ONBOARDING_HOST_PREREQUISITES_V3',scope_seconds=495,work_seconds=450,
    observation_seconds=15,cleanup_seconds=30,controller_AS_bytes=536870912,controller_CPU_seconds=500,core_bytes=0,
    scope_limits={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'},
    output_bytes=16777216,output_nodes=64,minimum_free_bytes=822083584,minimum_free_nodes=4288,
    prerequisite_plan_sha256=PREREQUISITE_FILES['host_prerequisite_plan'][2],Root_acceptance=None)
PREREQUISITE_TIMING=dict(kind='CURRENT_HOSTED_SHARED_7560_PREREQUISITE_TIMING_V3',whole_budget_seconds=7560,
    charge_preflight_and_prerequisites=True,allow_clipped_stage_window=True,metadata_queries=2,
    controller_retirement_reserve_seconds=15,Root_acceptance=None)
PREREQUISITE_CALLBACKS={'prerequisite_selected','prerequisite_program','make_timing','validate_timing',
    'controller_seconds','available_stage_seconds','prerequisite_controller'}
PREREQUISITE_SUPPORT={'prerequisite_timing','prerequisite_report','prerequisite_initial_context',
    'prerequisite_launcher','prerequisite_controller','prerequisite_qualification'}
HOSTED_LAUNCHER_LIMITS=dict(request_bytes=49152,preflight_seconds=180,launcher_seconds=7740,
    address_space_bytes=536870912,cpu_seconds=7740,preflight_cpu_seconds=180,control_bytes=33554432,
    control_nodes=128,reference_files=1024,reference_bytes=34359738368,reference_file_bytes=8589934592,
    scope_stop_seconds=10)
PREREQUISITE_TOOLS={'systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4','mount',
    'umount','python3','gpg','gpgconf','gpg-connect-agent','bsdtar','zstd','env'}
MATERIAL_PROGRAM_ROLES={'materials_stager','material_domain_executor','base_inputs','private_seed',
    'material_transport','retained_transport_core','retained_prepare','retained_prefill'}
MATERIAL_STAGING_ROLES=PREREQUISITE_ROLES|MATERIAL_PROGRAM_ROLES
MATERIAL_STAGING_MATERIAL_ROLES={'retained_carrier_profile','retained_prefill_profile','public14_profile',
    'staging_base_lock','staging_bootstrap_profile'}
MATERIAL_STAGING_POLICY=dict(kind='CURRENT_COMPLETE517_MATERIAL_STAGING_V3',whole_budget_seconds=7560,
    staging_seconds=3600,cleanup_seconds=30,controller_AS_bytes=2147483648,controller_CPU_seconds=3600,
    context_age_seconds=7560,initial_metadata_queries=1,scope_limits=PREREQUISITE_POLICY['scope_limits'],
    storage_bytes=8*1024**3,storage_nodes=20000,storage_minimum_free_bytes=6*1024**3,command_rows=27,
    python_spawn_ceiling=2400,child_output_bytes=131072,file_bytes=2*1024**3+128*1024**2,
    download_requests=63,download_redirects=42,download_seconds=90,
    transport_policy=dict(fetch_seconds=400,transport_seconds=480,outer_seconds=500,
        reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee'),Root_acceptance=None)
SELECTED_TEST_FINGERPRINT='D9D7A9FC25B9914CF6F2CE55952AEDD8A209B4C0'
SELECTED_TEST_KEY_PIN=dict(bytes=437,sha256='01ffe16c6215c2030914d0cfc7f27f14ae15cb58da1e4723ac1651c423c1e289')


def helper_inverse():
    for name,sha in HELPER_PINS.items():
        need(hashlib.sha256(inspect.getsource(globals()[name]).encode()).hexdigest()==sha,
             'HOLD_READER_HELPER_INVERSE:'+name)


def whole(row):
    need(type(row) is dict and {'bytes','sha256'}<=set(row) and type(row['bytes']) is int
         and 0<=row['bytes']<=MAX_SOURCE and type(row['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}',row['sha256']),'HOLD_WHOLE_PIN')
    return {k:row[k] for k in ('bytes','sha256')}


def same(a,b):return encoded(a)==encoded(b)


def prerequisite_policy(raw):
    """Exact optional proposal composed with the independently pinned base policy."""
    policy=receipt(raw);base=dict(policy)
    need(same(base.pop('host_prerequisites_current_v3',None),PREREQUISITE_POLICY)
         and same(base.pop('host_prerequisite_timing_v3',None),PREREQUISITE_TIMING)
         and pin(encoded(base))==FULL_POLICY_PIN and raw==encoded(policy),
         'HOLD_EXACT_PREREQUISITE_POLICY_COMPOSITION')
    return policy


def material_staging_policy(raw):
    """Parse the committed stager's unissued proposal as DATA, never a grant."""
    policy=receipt(raw);base=dict(policy)
    need(same(base.pop('material_staging_current_v3',None),MATERIAL_STAGING_POLICY)
         and raw==encoded(policy),'HOLD_MATERIAL_STAGING_EXACT_POLICY_COMPOSITION')
    prerequisite_policy(encoded(base));return policy


def material_registry_shape(program,closure):
    """Exact corrected27+5 metadata shape; not whole-body Source qualification."""
    actual={'source','ref','run','job','Root_delegation','Root_trust','Root_resources','Root_runtime','actual_images','publication'}
    registry_keys={'schema','kind','operation','api','owner','route','owner_callbacks','route_callback','roles',
        'entrypoints','closure_commit','v3_registry_scope','actual','delegation_programs','retention_callback','staging_materials'}
    need(type(program) is dict and set(program)==registry_keys and type(program['schema']) is int
         and program['schema']==4 and program['kind']=='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4'
         and program['operation']==OP and program['api']=='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'
         and program['owner_callbacks']==dict(build='open_delegated_session',lifecycle='launch_delegated_lifecycle')
         and program['route_callback']=='run_registered' and program['retention_callback']=='retain_delegated_stage'
         and program['v3_registry_scope']=='PRESERVED_DATA_ONLY_NEVER_DELEGATED_EXECUTION',
         'HOLD_MATERIAL_STAGING_REGISTRY_SCHEMA')
    need(type(closure) is dict and set(closure)=={'schema','kind','operation','commit','roles','files','entrypoints','actual','staging_materials'}
         and type(closure['schema']) is int and closure['schema']==4
         and closure['kind']=='COMMITTED_DELEGATED_CURRENT_PIPELINE_CLOSURE_V4' and closure['operation']==OP
         and type(program['closure_commit']) is str and re.fullmatch('[0-9a-f]{40}',program['closure_commit'])
         and closure['commit']==program['closure_commit'],'HOLD_MATERIAL_STAGING_CLOSURE_SCHEMA')
    for value in (program,closure):
        need(type(value['actual']) is dict and set(value['actual'])==actual
             and all(x is None for x in value['actual'].values()),'HOLD_MATERIAL_STAGING_UNISSUED_SELECTORS')
    roles=program['roles'];materials=program['staging_materials']
    need(type(roles) is dict and set(roles)==MATERIAL_STAGING_ROLES,
         'HOLD_MATERIAL_STAGING_EXACT_PROGRAM_ROLES')
    need(type(materials) is dict and set(materials)==MATERIAL_STAGING_MATERIAL_ROLES,
         'HOLD_MATERIAL_STAGING_EXACT_FIVE_MATERIALS')
    members=set()
    for role,row in {**roles,**materials}.items():
        need(type(row) is dict and set(row)=={'member','bytes','sha256'},'HOLD_MATERIAL_STAGING_DESCRIPTOR')
        relative(row['member']);need(row['member'] not in members and 0<whole(row)['bytes']<=16*1024**2,
             'HOLD_MATERIAL_STAGING_DESCRIPTOR_COLLISION')
        members.add(row['member'])
    need(closure['roles']=={role:row['member'] for role,row in roles.items()}
         and closure['staging_materials']=={role:row['member'] for role,row in materials.items()}
         and program['owner']==roles['delegated_owner'] and program['route']==roles['route'],
         'HOLD_MATERIAL_STAGING_ROLE_MATERIAL_JOIN')
    entries=program['entrypoints']
    need(type(entries) is dict and set(entries)=={'image_executor','public_reader','hosted_launcher','inputs_assembler'}
         and closure['entrypoints']==entries and all(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}',name)
             for name in entries.values()) and entries['public_reader']=='read_delegated_stage',
         'HOLD_MATERIAL_STAGING_ENTRYPOINTS')
    rows=closure['files'];need(type(rows) is dict and members<=set(rows) and len(members)<=len(rows)<=96,
         'HOLD_MATERIAL_STAGING_CLOSED_FILES')
    for name,row in rows.items():
        relative(name);need(not name.startswith(('carrier/','inputs/','provenance/',
             'scripts/ci/first-login-enrollment-native-source/successor_v3/',
             'scripts/ci/first-login-enrollment-native-source/successor_v4_source/'))
             and name not in ('source-map.json','source.lock.json')
             and type(row) is dict and set(row)=={'bytes','sha256','mode'}
             and type(row['mode']) is int and row['mode'] in (0o644,0o755),
             'HOLD_MATERIAL_STAGING_CLOSED_FILES')
        whole(row)
    for role,row in {**roles,**materials}.items():
        need(whole(row)==whole(rows[row['member']]) and (role not in MATERIAL_PROGRAM_ROLES|MATERIAL_STAGING_MATERIAL_ROLES
             or rows[row['member']]['mode']==0o644),'HOLD_MATERIAL_STAGING_DESCRIPTOR_JOIN')
    selected={name:roles[role] for name,role in dict(context='context',owner='delegated_owner',image='image',
        image_executor='image_executor',route='route',retention='retention',public_reader='public_reader',owned_process='owned_process',
        hosted_launcher='hosted_launcher',inputs_assembler='inputs_assembler',encoder='encoder',local_callbacks='v3_basis_owner').items()}
    selected.update({role:roles[role] for role in set(PREREQUISITE_FILES)|MATERIAL_PROGRAM_ROLES})
    selected['build_validator']=dict(member='scripts/ci/first-login-enrollment-native-source/successor_v4/validate_build.py',bytes=7798,
        sha256='dd2fd5a390b7764b753817044e60b8ea088cb6b704e80503f53d4b6335559d84')
    validator=selected['build_validator']
    need(validator['member'] in rows and rows[validator['member']]==dict(mode=0o644,**whole(validator)),
         'HOLD_MATERIAL_STAGING_BUILD_VALIDATOR')
    need(same(program['delegation_programs'],selected),'HOLD_MATERIAL_STAGING_CANONICAL_PROGRAM_MAPPING')
    return dict(status='MATERIAL_STAGING_REGISTRY_SHAPE_DATA_ONLY_V4',program_roles=27,staging_material_roles=5,
        Root_authentication=False,Source_qualification='HOLD_PENDING_COMMITTED_CONSTRUCTOR_AND_DOMAIN')


def material_projection_data(original_raw,supplemental_raw,program):
    """Keep original59 DATA byte-canonical and supplemental5 in a separate table."""
    original=receipt(original_raw);extra=receipt(supplemental_raw)
    need(set(original)=={'schema','kind','aliases','materials'} and type(original['schema']) is int
         and original['schema']==4 and original['kind']=='DELEGATED_SOURCE_RELATIVE_MATERIALS_V4'
         and original['aliases']==MATERIAL_ALIASES and set(original['materials'])==set(MATERIAL_ALIASES.values())
         and original_raw==encoded(original),'HOLD_MATERIAL_STAGING_ORIGINAL59_PROJECTION')
    need(set(extra)=={'schema','kind','materials'} and type(extra['schema']) is int and extra['schema']==4
         and extra['kind']=='DELEGATED_MATERIAL_STAGING_SOURCE_MATERIALS_V4'
         and type(extra['materials']) is dict and set(extra['materials'])==MATERIAL_STAGING_MATERIAL_ROLES
         and same(extra['materials'],program['staging_materials']) and supplemental_raw==encoded(extra),
         'HOLD_MATERIAL_STAGING_SUPPLEMENTAL5_PROJECTION')
    selected={**original['materials'],**extra['materials']};members=set()
    for role,row in selected.items():
        need(type(row) is dict and set(row)=={'member','bytes','sha256'},'HOLD_MATERIAL_STAGING_DESCRIPTOR')
        relative(row['member']);need(row['member'] not in members and 0<whole(row)['bytes']<=16*1024**2,
             'HOLD_MATERIAL_STAGING_DESCRIPTOR_COLLISION')
        if role in original['materials']:need(row['member'].startswith('carrier/'),'HOLD_MATERIAL_STAGING_ORIGINAL59_PROJECTION')
        members.add(row['member'])
    return dict(status='MATERIAL_STAGING_MATERIAL_PROJECTION_DATA_ONLY_V4',materials=selected,
        original_material_roles=59,staging_material_roles=5,Root_authentication=False)


def literal_timing(tree):
    """Read one literal dict declaration; never invoke a Source predicate."""
    rows=[node.value for node in tree.body if isinstance(node,ast.Assign)
          and any(isinstance(target,ast.Name) and target.id=='TIMING' for target in node.targets)]
    need(len(rows)==1,'HOLD_PREREQUISITE_LITERAL_TIMING')
    node=rows[0]
    if isinstance(node,ast.Call):
        need(isinstance(node.func,ast.Name) and node.func.id=='dict' and not node.args
             and all(item.arg is not None for item in node.keywords)
             and len({item.arg for item in node.keywords})==len(node.keywords),'HOLD_PREREQUISITE_LITERAL_TIMING')
        return {item.arg:ast.literal_eval(item.value) for item in node.keywords}
    return ast.literal_eval(node)


def receipt(raw):
    value=decode(raw);need(type(value) is dict,'HOLD_RECEIPT_SCHEMA')
    def inspect_public(item):
        if isinstance(item,dict):
            for key,child in item.items():
                name=re.sub('[^a-z0-9]','',key.casefold())
                need(name not in ('authorization','proxyauthorization','apikey','xapikey','awsaccesskeyid')
                     and not name.endswith(('token','password','passwd','secret','privatekey','secretkey'))
                     and not any(part in name for part in ('credential','password','privatekey','secretaccesskey')),
                     'HOLD_PRIVATE_RECEIPT_FIELD')
                inspect_public(child)
        elif isinstance(item,list):
            for child in item:inspect_public(child)
    inspect_public(value);return value


def capsule_files(raw,expected_pin,stage):
    need(type(raw) is bytes and 0<len(raw)<=MAX_COMPRESSED and pin(raw)==whole(expected_pin),'HOLD_CAPSULE_PIN')
    stream=zlib.decompressobj(31);tar=stream.decompress(raw,18*1024**2+1)
    need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and len(tar)<=18*1024**2,
         'HOLD_CAPSULE_GZIP_BOUND')
    prefix='current-'+stage+'-public-v3/';files={};total=0;cursor=0
    with tarfile.open(fileobj=io.BytesIO(tar),mode='r:') as archive:
        for item in archive:
            need(len(files)<MAX_MEMBERS and item.isfile() and not item.issym() and not item.islnk()
                 and item.name.startswith(prefix) and item.mode==0o444 and 0<=item.size<=8*1024**2
                 and set(item.pax_headers)<={'mtime','atime','ctime'},'HOLD_CAPSULE_MEMBER')
            name=item.name[len(prefix):];relative(name)
            need(name not in files and not any(part in ('home','trust','cache','gpg','.gnupg','credentials')
                 for part in name.split('/')) and Path(name).name not in ('inside.json','proxy.json','signature-config.txt'),
                 'HOLD_CAPSULE_NAMESPACE')
            with archive.extractfile(item) as body:files[name]=body.read(item.size+1)
            need(len(files[name])==item.size,'HOLD_CAPSULE_MEMBER_SIZE')
            cursor=max(cursor,item.offset_data+(item.size+511)//512*512)
            total+=item.size;need(total<=MAX_LOGICAL,'HOLD_CAPSULE_LOGICAL_CAP')
    need(len(tar)-cursor>=1024 and not any(tar[cursor:]),'HOLD_CAPSULE_TAR_TRAILER')
    need('retention-manifest.json' in files,'HOLD_RETENTION_MANIFEST_MISSING')
    manifest=receipt(files['retention-manifest.json'])
    need(set(manifest['files'])==set(files)-{'retention-manifest.json'},'HOLD_RETENTION_MEMBERSHIP')
    for name,row in manifest['files'].items():need(pin(files[name])==whole(row),'HOLD_RETAINED_BODY:'+name)
    return files,manifest


def source_data(expected,files,*,delegated=False):
    need(type(files) is dict and all(type(n) is str and type(v) is bytes for n,v in files.items()),'HOLD_SOURCE_BODIES')
    need(sum(map(len,files.values()))<=MAX_SOURCE and len(files)<=512,'HOLD_SOURCE_CAP')
    raw=files['source.lock.json'];lock=receipt(raw)
    need(pin(raw)==whole(expected['source_lock_pin'])==expected['binding']['source_lock']
         and files['source-map.json']==raw and lock['schema']==1 and lock['operation']==OP
         and lock['kind']=='CURRENT_ONBOARDING_CLOSED_SOURCE_V3'
         and set(lock['actual'])=={'source','ref','run','job','artifact','Root_trust','Root_resources','Root_runtime',
             'Root_signing','actual_images','dispatch_grant','publication'}
         and all(v is None for v in lock['actual'].values()),
         'HOLD_SOURCE_QUALIFICATION')
    need(set(files)==set(lock['files'])|{'source.lock.json','source-map.json'},'HOLD_SOURCE_CLOSED_NAMESPACE')
    for name,row in lock['files'].items():
        relative(name);need(row['mode'] in (0o644,0o755) and pin(files[name])==whole(row),'HOLD_SOURCE_LEAF:'+name)
    need(set(expected['source'])=={'profile','program','policy','retention','encoder'},'HOLD_SOURCE_ROLE_SET')
    values={}
    for role,row in expected['source'].items():
        relative(row['path']);need(pin(files[row['path']])==whole(row),'HOLD_SOURCE_ROLE:'+role)
        values[role]=files[row['path']]
    p=receipt(values['profile']);program=receipt(values['program']);policy=receipt(values['policy'])
    need(p['operation']==OP and set(p['packages'])==set(KINDS),'HOLD_CURRENT_PROFILE')
    for kind,count in zip(KINDS,(16,6,8)):
        recipe=p['packages'][kind]
        need((recipe['name'],recipe['version'])==VERSIONS[kind] and len(recipe['payload_files'])==count,
             'HOLD_CURRENT_PACKAGE_SCOPE')
        for name,row in recipe['files'].items():
            relative(name);need(pin(files[recipe['path']+'/'+name])==whole(row),'HOLD_RECIPE_SOURCE_BODY')
    if program.get('schema')==4:
        actual={'source','ref','run','job','Root_delegation','Root_trust','Root_resources','Root_runtime','actual_images','publication'}
        prefix='scripts/ci/first-login-enrollment-native-source/successor_v4_source/'
        roles=set(program['roles'])
        if roles==MATERIAL_STAGING_ROLES:
            material_registry_shape(program,receipt(files['provenance/v4/delegated-closure.json']))
            material_projection_data(files['inputs/delegated-materials-v4.json'],
                files['inputs/material-staging-materials-v4.json'],program)
            need(False,'HOLD_MATERIAL_STAGING_FINAL_CONSTRUCTOR_REQUIRED')
        prerequisites=roles==PREREQUISITE_ROLES
        current=roles in (CURRENT_ROLES,PREREQUISITE_ROLES)
        need(current or roles==HISTORICAL_ROLES,'HOLD_DELEGATED_EXACT_REGISTRY_VERSION')
        need(not prerequisites or delegated and whole(expected['source']['retention'])==BASE_RETENTION_PIN,
             'HOLD_PREREQUISITE_EXACT_SOURCE_VERSION')
        entries={'image_executor','public_reader'}|({'hosted_launcher','inputs_assembler'} if current else set())
        if delegated:
            need(current and whole(expected['source']['retention']) in DELEGATED_RETENTION_VERSIONS,
                 'HOLD_DELEGATED_SOURCE_SELECTOR')
            constructor_pin=BASE_CONSTRUCTOR_PIN if whole(expected['source']['retention'])==BASE_RETENTION_PIN else DELEGATED_CONSTRUCTOR_PIN
            need(pin(files[prefix+'prepare.py'])==constructor_pin,'HOLD_DELEGATED_EXACT_CONSTRUCTOR_BODY')
            tree=ast.parse(files[prefix+'prepare.py']);declarations={}
            for node in tree.body:
                if isinstance(node,ast.Assign) and isinstance(node.value,(ast.Tuple,ast.List)):
                    for target in node.targets:
                        if isinstance(target,ast.Name) and target.id in ('ROLES','ENTRYPOINTS'):
                            declarations[target.id]=set(ast.literal_eval(node.value))
            wanted=[]
            for node in ast.walk(tree):
                if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='wanted' for target in node.targets):
                    need(isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name)
                         and node.value.func.id=='dict','HOLD_DELEGATED_CONSTRUCTOR_CALLBACK_DECLARATION')
                    wanted=[keyword for keyword in node.value.keywords if keyword.arg=='retention']
            need(declarations==dict(ROLES=CURRENT_ROLES,ENTRYPOINTS=entries) and len(wanted)==1
                 and ast.literal_eval(wanted[0].value)=={'retain_delegated_stage'}
                 and lock['files'][prefix+'prepare.py']['mode']==0o644,
                 'HOLD_DELEGATED_CONSTRUCTOR_CALLBACK_DECLARATION')
            legacy='scripts/ci/first-login-enrollment-native-source/payload/native/retention_current_v3.py'
            need(pin(files[legacy])['sha256']=='738360745901f1938be1e6a893ce45131c3f1f825421991522cfee3c66ed8c6a'
                 and lock['files'][legacy]['mode']==0o644,'HOLD_DELEGATED_PURE_DEPENDENCY')
        else:
            need(pin(files[prefix+'prepare.py'])==(CURRENT_CONSTRUCTOR_PIN if current else HISTORICAL_CONSTRUCTOR_PIN)
                 and lock['files'][prefix+'prepare.py']['mode']==0o644,'HOLD_EXACT_VERSIONED_CONSTRUCTOR_BODY')
        program_keys={'schema','kind','operation','api','owner','route','owner_callbacks','route_callback','roles',
                 'entrypoints','closure_commit','v3_registry_scope','actual'}
        if delegated:program_keys|={'delegation_programs','retention_callback'}
        need(set(program)==program_keys
             and program['kind']=='DELEGATED_CURRENT_PROGRAM_REGISTRY_V4' and program['operation']==OP
             and program['api']=='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'
             and program['owner_callbacks']==dict(build='open_delegated_session',lifecycle='launch_delegated_lifecycle')
             and program['route_callback']=='run_registered'
             and program['v3_registry_scope']=='PRESERVED_DATA_ONLY_NEVER_DELEGATED_EXECUTION'
             and set(program['actual'])==actual and re.fullmatch('[0-9a-f]{40}',program['closure_commit'])
             and all(value is None for value in program['actual'].values()),'HOLD_DELEGATED_PROGRAM')
        closure=receipt(files['provenance/v4/delegated-closure.json'])
        need(set(closure)=={'schema','kind','operation','commit','roles','files','entrypoints','actual'}
             and closure['schema']==4 and closure['kind']=='COMMITTED_DELEGATED_CURRENT_PIPELINE_CLOSURE_V4'
             and closure['operation']==OP and closure['commit']==program['closure_commit']
             and closure['roles']=={role:row['member'] for role,row in program['roles'].items()}
             and len(set(closure['roles'].values()))==len(roles)
             and set(closure['roles'].values())<=set(closure['files']) and len(roles)<=len(closure['files'])<=96
             and set(closure['actual'])==actual
             and all(value is None for value in closure['actual'].values()),'HOLD_DELEGATED_COMMITTED_CLOSURE')
        for name,row in closure['files'].items():
            relative(name);need(set(row)=={'bytes','sha256','mode'} and pin(files[name])==whole(row)
                and row==lock['files'][name] and name not in ('source-map.json','source.lock.json')
                and not name.startswith((prefix,'scripts/ci/first-login-enrollment-native-source/successor_v3/',
                    'carrier/','inputs/','provenance/')),'HOLD_DELEGATED_CODE_BODY')
        for role,row in program['roles'].items():
            relative(row['member']);need(set(row)=={'member','bytes','sha256'}
                and pin(files[row['member']])==whole(row)
                and whole(row)==whole(closure['files'][row['member']]),'HOLD_DELEGATED_ROLE_BODY')
        basis={'v3_basis_owner':('scripts/ci/first-login-enrollment-native-source/payload/native/owner_current_v2.py',46298,
                    'f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d'),
               'v3_basis_route':('scripts/ci/first-login-enrollment-native-source/successor_v2/owned_route.py',26320,
                    '43db41de72822cb8f4d875b6c1d17ffd5062770616ed303f63e299c13478dd86')}
        for role,(name,size,sha) in basis.items():
            need(program['roles'][role]==dict(member=name,bytes=size,sha256=sha)
                 and closure['files'][name]['mode']==0o644,'HOLD_IMMUTABLE_V3_CALLBACK_BASIS')
        if current:
            name='scripts/virtual/owned_process.py'
            need(program['roles']['owned_process']==dict(member=name,bytes=25140,
                 sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')
                 and closure['files'][name]['mode']==0o755,'HOLD_CURRENT_OWNED_SUPERVISOR')
        if prerequisites:
            for role,(name,size,sha) in PREREQUISITE_FILES.items():
                need(program['roles'][role]==dict(member=name,bytes=size,sha256=sha)
                     and closure['files'][name]['mode']==0o644,'HOLD_PREREQUISITE_EXACT_SOURCE_DEPENDENCY')
        need(program['owner']==program['roles']['delegated_owner'] and program['route']==program['roles']['route'],
             'HOLD_DELEGATED_CALLBACK_ROLES')
        for role in ('retention','encoder','policy'):
            need(program['roles'][role]==dict(member=expected['source'][role]['path'],**whole(expected['source'][role])),
                 'HOLD_DELEGATED_SELECTED_ROLE')
        need(whole(program['roles']['public_reader'])==whole(expected['reader_pin'])
             and set(program['entrypoints'])==entries
             and program['entrypoints']==closure['entrypoints'],'HOLD_DELEGATED_READER_ENTRY')
        trees={role:ast.parse(files[row['member']]) for role,row in program['roles'].items() if role not in ('policy','workflow')}
        functions=lambda role:{node.name for node in trees[role].body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
        for role,entry in program['entrypoints'].items():
            need(type(entry) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}',entry)
                 and entry in functions(role),'HOLD_DELEGATED_ACTUAL_ENTRYPOINT')
        if current:
            entry=next((node for node in trees['public_reader'].body
                        if isinstance(node,ast.FunctionDef) and node.name==program['entrypoints']['public_reader']),None)
            need(entry is not None and entry.name==('read_delegated_stage' if delegated else 'read_stage') and not entry.decorator_list
                 and [arg.arg for arg in entry.args.args]==['capsule'] and not entry.args.posonlyargs
                 and not entry.args.vararg and not entry.args.kwarg
                 and [arg.arg for arg in entry.args.kwonlyargs]==['expected','source_files','support_files','now'],
                 'HOLD_CURRENT_PURE_READER_DECLARATION')
        callbacks=dict(context={'validate_delegation','validate_context','capture_context','adopt_pair'},image={'build_stage'},
            delegated_owner={'open_delegated_session','launch_delegated_lifecycle'},route={'run_registered'},
            retention={'retain_stage','emit'},encoder={'bundle'})
        if delegated:callbacks['retention']={'retain_delegated_stage'}
        if delegated:
            callbacks['context'].add('adopt_selected_pair')
            callbacks['delegated_owner'].add('run_owned_current_v3')
            callbacks.update(inputs_assembler={'validate_owner_inputs_v3','validate_hosted_inputs_v3','stage_inputs'},
                image_executor={'context_contract','owner_main','controller_main'},hosted_launcher={'checked_inputs','preflight'})
            need(program['retention_callback']=='retain_delegated_stage','HOLD_DELEGATED_CALLBACK_SELECTION')
        if prerequisites:
            callbacks['host_prerequisites']={'prepare_host_prerequisites'}
            callbacks['hosted_launcher']|=PREREQUISITE_CALLBACKS
            need(same(literal_timing(trees['hosted_launcher']),PREREQUISITE_TIMING),
                 'HOLD_PREREQUISITE_LITERAL_TIMING')
        need(all(entries<=functions(role) for role,entries in callbacks.items()),'HOLD_DELEGATED_ROLE_CALLBACKS')
        if delegated:
            selected={name:program['roles'][role] for name,role in dict(context='context',owner='delegated_owner',image='image',
                image_executor='image_executor',route='route',retention='retention',public_reader='public_reader',owned_process='owned_process',
                hosted_launcher='hosted_launcher',inputs_assembler='inputs_assembler',encoder='encoder',local_callbacks='v3_basis_owner').items()}
            name='scripts/ci/first-login-enrollment-native-source/successor_v4/validate_build.py'
            validator=dict(bytes=7798,sha256='dd2fd5a390b7764b753817044e60b8ea088cb6b704e80503f53d4b6335559d84')
            need(pin(files[name])==validator and lock['files'][name]['mode']==0o644 and name in closure['files'],
                 'HOLD_DELEGATED_BUILD_VALIDATOR_BODY')
            selected['build_validator']=dict(member=name,**validator)
            if prerequisites:selected.update({role:program['roles'][role] for role in PREREQUISITE_FILES})
            need(program['delegation_programs']==selected,'HOLD_DELEGATED_EXACT_PROGRAM_MAPPING')
            need(program['roles']['encoder']['member']=='scripts/ci/log_evidence.py'
                 and whole(program['roles']['encoder'])==dict(bytes=1708,sha256='a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5'),
                 'HOLD_DELEGATED_IMMUTABLE_ENCODER')
        need(any(isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='API' for target in node.targets)
             and isinstance(node.value,ast.Constant) and node.value.value=='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'
             for node in trees['delegated_owner'].body),'HOLD_DELEGATED_LITERAL_API')
        workflow=program['roles']['workflow']['member']
        need(workflow.startswith('.github/workflows/') and workflow.endswith('.yml')
             and b'workflow_dispatch:' in files[workflow],'HOLD_DELEGATED_WORKFLOW_DECLARATION')
        inverse=receipt(files[prefix+'inverse.json'])
        original=files['provenance/v4/v3-source-map.json'];old=receipt(original)
        need(set(inverse)=={'schema','kind','original_map','original_files','original_bytes','remove','actual_acceptance'}
             and inverse['schema']==4 and inverse['kind']=='DELEGATED_SOURCE_V4_TO_V3_INVERSE_DATA_ONLY'
             and inverse['actual_acceptance'] is None and inverse['original_map']==pin(original)
             and {k:v for k,v in old.items() if k!='files'}=={k:v for k,v in lock.items() if k!='files'}
             and inverse['remove']==sorted(['provenance/v4/v3-source-map.json','provenance/v4/delegated-closure.json',
                 'inputs/delegated-materials-v4.json',*(prefix+name for name in ('program.json','prepare.py','README.md','inverse.json'))]),
             'HOLD_DELEGATED_INVERSE')
        restored={name:raw for name,raw in files.items() if name not in inverse['remove'] and name not in ('source.lock.json','source-map.json')}
        need(set(restored)==set(old['files']) and all(pin(raw)==whole(old['files'][name])
             and lock['files'][name]['mode']==old['files'][name]['mode'] for name,raw in restored.items())
             and len(restored)+2==inverse['original_files'] and sum(map(len,restored.values()))+2*len(original)==inverse['original_bytes'],
             'HOLD_WHOLE_V3_BASIS_INVERSE')
        materials=receipt(files['scripts/ci/first-login-enrollment-native-source/successor_v3/owner-program.json'])['materials']
        need(set(materials)==set(MATERIAL_ALIASES),'HOLD_DELEGATED_ORIGINAL_MATERIALS')
        projected={};members=set()
        for original,alias in MATERIAL_ALIASES.items():
            row=materials[original];relative(row['path'])
            need(set(row)=={'path','bytes','sha256'} and row['path'].startswith('carrier/')
                 and lock['files'][row['path']]['mode']==0o644 and pin(files[row['path']])==whole(row),
                 'HOLD_DELEGATED_MATERIAL_BODY')
            if current:
                need(row['path'] not in members and type(row['bytes']) is int and 0<row['bytes']<=16*1024**2
                     and len(row['path'].split('/'))<=16 and all(re.fullmatch('[A-Za-z0-9._+-]+',part)
                         for part in row['path'].split('/')),'HOLD_CURRENT_UNIQUE_MATERIAL_BODY')
                members.add(row['path'])
            projected[alias]=dict(member=row['path'],**whole(row))
        need(receipt(files['inputs/delegated-materials-v4.json'])==dict(schema=4,
             kind='DELEGATED_SOURCE_RELATIVE_MATERIALS_V4',aliases=MATERIAL_ALIASES,materials=projected),
             'HOLD_DELEGATED_MATERIAL_PROJECTION')
    else:
        need(program['schema']==1 and program['kind']=='CURRENT_ONBOARDING_COMMITTED_OWNER_PROGRAM_V3'
             and program['operation']==OP and program['api']=='CURRENT_ONBOARDING_PUBLIC_CALLBACKS_V3'
             and program['entrypoint']=='execute_public_stage' and program['closure'] and
             all(value is None for value in program['actual'].values()),'HOLD_OWNER_PROGRAM')
        for name,row in program['closure'].items():
            relative(name);need(pin(files[name])==whole(row),'HOLD_PROGRAM_CLOSURE_BODY')
    if program.get('schema')==4 and set(program['roles']) in (CURRENT_ROLES,PREREQUISITE_ROLES):
        optional=set(program['roles'])==PREREQUISITE_ROLES
        if optional:prerequisite_policy(values['policy'])
        elif delegated:need(pin(values['policy'])==FULL_POLICY_PIN,'HOLD_DELEGATED_SELECTED_FULL_POLICY')
        need((optional or pin(values['policy']) in (HISTORICAL_FULL_POLICY_PIN,FULL_POLICY_PIN)) and policy['schema']==3
             and policy['kind']=='CURRENT_ONBOARDING_FULL_POLICY_PROPOSAL_V3'
             and policy['review_state']=='PROPOSED_REQUIRES_SEPARATE_ROOT_DELEGATION'
             and all(policy[name] is None for name in ('Root_issuance','Root_final_acceptance','actual_binding',
                 'actual_images','runtime','independent_component_acceptance','hardware_acceptance','release_acceptance'))
             and lock['files'][expected['source']['policy']['path']]['mode']==0o644
             and expected['resources']==frozen_resources(policy)
             and all(lock['files'][name]['mode']==0o644 for name in inverse['remove']),
             'HOLD_UNISSUED_FULL_SOURCE_POLICY')
        if optional or pin(values['policy'])==FULL_POLICY_PIN:
            test=policy['private_stage']['test']
            need(test==dict(fingerprint=SELECTED_TEST_FINGERPRINT,public_key_role='setup8_current_public_key')
                 and expected['fingerprint']==test['fingerprint'],'HOLD_SOURCE_TEST_KEY_SELECTION')
            key=receipt(files['inputs/delegated-materials-v4.json'])['materials'][test['public_key_role']]
            need(whole(key)==SELECTED_TEST_KEY_PIN and pin(files[key['member']])==SELECTED_TEST_KEY_PIN,
                 'HOLD_SOURCE_TEST_CERTIFICATE_BODY')
    else:
        need(policy['schema']==3 and policy['kind']=='CURRENT_PUBLIC_DOMAIN_POLICY_V3' and policy['operation']==OP
             and same(policy['resources'],expected['resources']) and same(policy['domain_policy'],DOMAIN_POLICY),
             'HOLD_SOURCE_POLICY')
    return p,program,policy


def frozen_resources(policy):
    limits=policy['frozen_stage_limits']
    return {name:limits['admission_total_seconds'] if name=='total_seconds' else limits[name] for name in
        ('build_seconds','builder_cpus','builder_memory_bytes','builder_pids','total_seconds','command_rows')}


def natural(row):
    need(type(row) is dict and type(row.get('exit')) is int and row['exit']==0 and
         all(row.get(k)==v for k,v in dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',
             output_complete=True,timeout=False,signals=[],error=None).items()) and
         row.get('passed') is True and type(row.get('seconds')) in (int,float)
         and math.isfinite(row['seconds']) and row['seconds']>=0 and not any(row.get(k) for k in
             ('forced_cleanup','ownership_lost','emergency_retirement')),'HOLD_UNCERTAIN_SUPERVISION')


def current_signature(raw,fingerprint,observed_at):
    strict_signature(raw,fingerprint)
    fields=next(line.split()[1:] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG '))
    need(all(re.fullmatch('[0-9]+',fields[i]) for i in (3,4,5,6,7,8))
         and re.fullmatch('[0-9A-Fa-f]{2}',fields[9]),'HOLD_CURRENT_SIGNATURE_VALIDITY_FIELDS')
    created,expires=int(fields[3]),int(fields[4])
    date=datetime.date.fromisoformat(fields[2])
    need(datetime.datetime.fromtimestamp(created,datetime.timezone.utc).date()==date and created<=observed_at
         and (expires==0 or observed_at<=expires),'HOLD_CURRENT_SIGNATURE_VALIDITY_WINDOW')


def index(files,label,resources):
    rows=decode(files['streams/'+label+'/commands.public.json'])
    need(type(rows) is list and 0<len(rows)<=resources['command_rows']<=512,'HOLD_COMMAND_INDEX')
    result={};elapsed=0
    for i,row in enumerate(rows):
        step=row['step'];need(type(step) is str and re.fullmatch('[A-Za-z0-9._+-]{1,96}',step)
             and step not in result and row['log']=='%03d-%s.log'%(i,step) and row['success'] is True
             and type(row['expected']) is int and row['expected']==0
             and row['channels']=='stdout+stderr combined in pipe order' and not row.get('launch_error'),
             'HOLD_COMMAND_RESULT')
        natural(row['supervision']);seconds=row['supervision']['seconds']
        need(type(seconds) in (int,float) and math.isfinite(seconds) and 0<=seconds<=resources['build_seconds'],
             'HOLD_COMMAND_BUDGET')
        elapsed+=seconds
        excluded=any(word in step for word in ('inspect','create','start-attached','native-daemon'))
        if excluded:
            need(row.get('private_launch_body_excluded') is True,'HOLD_PRIVATE_LAUNCH_SELECTION')
            raw=None
        else:
            raw=files['streams/'+label+'/'+row['log']]
            need(pin(raw)==whole(row['log_pin']),'HOLD_COMMAND_LOG_BODY')
        result[step]=(i,row,raw)
    need(elapsed<=resources['total_seconds'],'HOLD_AGGREGATE_COMMAND_TIME')
    return result


def owned_domain_policy(q,runtime,policy,expected):
    """Require externally selected actual observations, never promote Source proposals."""
    need(type(q.get('owned_domains')) is dict,'HOLD_OWNED_DOMAIN_QUALIFICATION')
    observed=q['owned_domains'];nonce=observed['nonce'];executor=policy['executor_current_v3']
    need(set(observed)=={'nonce','controller','owner','daemon','storage','host','seconds','frozen_seconds',
         'image_seconds','image_alpm_capabilities','normal_ALPM','signature_policy'}
         and type(nonce) is str and re.fullmatch('[0-9a-f]{64}',nonce) and runtime['nonce']==nonce,
         'HOLD_OWNED_DOMAIN_QUALIFICATION')
    need(observed['controller']==dict(kernel=executor['controller'],address_space_bytes=executor['controller_AS_bytes'])
         and observed['owner']==dict(kernel=policy['image_domains']['owner'],address_space_bytes=executor['owner_AS_bytes']),
         'HOLD_ACTUAL_CONTROLLER_OWNER_LIMITS')
    endpoint=policy['image_endpoint_template'].replace('{nonce}',nonce)
    need(observed['daemon']==dict(kernel=policy['image_domains']['daemon'],endpoint=endpoint,shared_daemon=False,
         native_architecture='aarch64',rootful=True,cgroup='v2'),'HOLD_ACTUAL_PRIVATE_DAEMON_LIMITS')
    need(observed['storage']==dict(capacity_bytes=policy['image_storage_bytes'],private=True,retired=True),
         'HOLD_ACTUAL_PRIVATE_STORAGE')
    host=observed['host'];need(set(host)=={'available_bytes','disk_free_bytes','reserve_bytes'}
         and all(type(value) is int for value in host.values())
         and host['available_bytes']>=executor['minimum_available_bytes']
         and host['disk_free_bytes']>=executor['minimum_disk_bytes']
         and host['reserve_bytes']>=executor['host_reserve_bytes'],'HOLD_ACTUAL_HOST_CAPACITY')
    scopes=(('seconds',{name:executor[name] for name in ('controller_seconds','setup_seconds','service_seconds','cleanup_seconds','stage_seconds')}),
            ('frozen_seconds',{name:policy['frozen_stage_limits'][name] for name in
                ('build_seconds','admission_total_seconds','owned_session_seconds','retirement_reserve_seconds')}),
            ('image_seconds',policy['image_steps']))
    for role,limits in scopes:
        actual=observed[role]
        need(set(actual)==set(limits) and all(type(value) in (int,float) and math.isfinite(value)
             and 0<value<=limits[name] for name,value in actual.items()),'HOLD_ACTUAL_SCOPED_TIME_BUDGET:'+role)
    need(runtime['finished_at']-runtime['started_at']<=observed['seconds']['stage_seconds']
         <=observed['seconds']['service_seconds']
         and sum(observed['seconds'][name] for name in ('setup_seconds','service_seconds','cleanup_seconds'))
             <=observed['seconds']['controller_seconds'],'HOLD_ACTUAL_DOMAIN_TIME_ORDER')
    need(observed['image_alpm_capabilities']==policy['image_alpm_capabilities']
         and observed['normal_ALPM']==policy['normal_ALPM']
         and observed['signature_policy']=={k:v for k,v in policy['signature_policy'].items() if k!='Root_trust_admission'},
         'HOLD_ACTUAL_ALPM_SIGNATURE_POLICY')
    domain=dict(DOMAIN_POLICY,endpoint=endpoint)
    domain['builder']=dict(DOMAIN_POLICY['builder'],tmpfs_bytes=policy['frozen_stage_limits']['builder_tmpfs_bytes'])
    return domain


def qualified(files,expected,support,policy):
    stage=expected['stage'];binding=expected['binding'];caps=expected['resources']
    full=policy['kind']=='CURRENT_ONBOARDING_FULL_POLICY_PROPOSAL_V3'
    if full:
        need(same(caps,frozen_resources(policy)) and all(type(v) is int for v in caps.values()),
             'HOLD_CURRENT_RESOURCE_POLICY')
    else:
        need(set(caps)=={'build_seconds','builder_cpus','builder_memory_bytes','builder_pids','total_seconds','command_rows'}
             and all(type(v) is int for v in caps.values()) and 2<=caps['build_seconds']<=180
             and (caps['builder_cpus'],caps['builder_memory_bytes'],caps['builder_pids'])==(4,4*1024**3,512)
             and 2<=caps['total_seconds']<=1800 and 1<=caps['command_rows']<=512,'HOLD_RESOURCE_POLICY')
    public={role:files['public/'+role+'.data'] for role in expected['public_pins']}
    context=receipt(public['context']);domain=receipt(public['domain']);runtime=receipt(public['runtime'])
    ad=receipt(public['admission']);image=receipt(public['image_qualification']);packages=inventory(public['inventory'])
    need(len(packages)==COUNTS[stage] and pin(public['inventory'])==whole(expected['public_pins']['inventory']['projection']),
         'HOLD_TYPED_STAGE_INVENTORY')
    for role,value in (('context',context),('domain',domain)):
        need(value['schema']==1 and value['kind']=='CURRENT_ONBOARDING_PUBLIC_'+role.upper()+'_V3'
             and value['operation']==OP and value['stage']==stage and value['binding']==binding,'HOLD_CONTEXT_BINDING')
    facts=context['facts'];need(facts['architecture']=='aarch64' and type(facts['page_size']) is int
         and facts['page_size'] in (4096,16384) and facts['image']==expected['image'],'HOLD_NATIVE_CONTEXT')
    timing=expected['observed_at'];need(set(timing)=={'started_at','finished_at'} and all(type(v) in (int,float)
         and math.isfinite(v) for v in timing.values()),'HOLD_EVENT_TIME_QUALIFICATION')
    need(runtime['schema']==3 and runtime['kind']=='CURRENT_PUBLIC_RUNTIME_QUALIFICATION_V3'
         and runtime['status']=='QUALIFIED_CURRENT_PUBLIC_RUNTIME' and runtime['qualified'] is True
         and runtime['provisional'] is False and runtime['operation']==OP and runtime['stage']==stage
         and runtime['binding']==binding and runtime['source_lock']==binding['source_lock']
         and runtime['program']==expected['source']['program'] and runtime['policy']==expected['source']['policy']
         and runtime['context_pin']==pin(public['context']) and runtime['domain_pin']==pin(public['domain'])
         and runtime['image']==expected['image'] and all(runtime[k]==v for k,v in timing.items()),
         'HOLD_RUNTIME_QUALIFICATION')
    if full:
        need(runtime.get('capability')==policy['stage_capabilities'][stage]
             and all(type(value) is int for value in runtime['capability'].values()),
             'HOLD_INDEPENDENT_OUTER_RUNTIME_CAPABILITY')
    need(ad['schema']==1 and ad['issuer']=='Root' and ad['approved'] is True and ad['operation']==OP
         and ad['stage']==stage and ad['binding']==binding and same(ad['resources'],caps)
         and ad['profile_pin']==whole(expected['source']['profile']) and ad['inputs_pin']==pin(support['inputs']),
         'HOLD_SELECTED_ADMISSION')
    start,end=ad['issued_at_unix'],ad['expires_at_unix']
    need(all(type(v) in (int,float) and math.isfinite(v) for v in (start,end))
         and start<=timing['started_at']<=end<=start+300
         and timing['started_at']<=timing['finished_at']<=timing['started_at']+caps['total_seconds'],
         'HOLD_STALE_ADMISSION_OR_EVENT')
    need(image['issuer']=='Root' and image['status']=='ROOT_REVIEWED_CURRENT_ONBOARDING_IMAGE_V2'
         and image['operation']==OP and image['stage']==stage and image['binding']==binding
         and image['image']==expected['image'] and whole(image['inventory_pin'])==pin(public['inventory'])
         and image['observed_architecture']=='aarch64' and image['owned_runner'] is True
         and image['image_build_policy_admitted'] is True and image['runtime_pin']==pin(public['runtime']),
         'HOLD_IMAGE_QUALIFICATION')
    selected=ad['images'][stage]
    need(selected['id']==expected['image'] and selected['packages']==packages
         and whole(selected['inventory_pin'])==pin(public['inventory']),'HOLD_SELECTED_IMAGE_INVENTORY')
    projects={'cachy-asahi-setup':'0.3.0-1',**dict(VERSIONS.values())}
    wanted={'cachy-asahi-setup'} if stage=='backend' else {'cachy-asahi-setup','cachy-asahi-first-login'} if stage=='ui' else set()
    need(set(packages)&set(projects)==wanted and all(packages[k]==projects[k] for k in wanted),'HOLD_STAGE_PROJECT_SCOPE')
    q=receipt(support['domain_qualification'])
    domain_policy=owned_domain_policy(q,runtime,policy,expected) if full else DOMAIN_POLICY
    need(q['schema']==3 and q['kind']=='ROOT_QUALIFIED_PUBLIC_DOMAIN_V3' and q['issuer']=='Root'
         and q['status']=='ROOT_REVIEWED_CURRENT_PUBLIC_DOMAIN' and q['operation']==OP and q['stage']==stage
         and q['binding']==binding and q['image']==expected['image'] and q['domain_pin']==pin(public['domain'])
         and q['runtime_pin']==pin(public['runtime']) and q['policy_pin']==whole(expected['source']['policy'])
         and same(q['policy'],domain_policy) and q['observed_at']==timing,'HOLD_DOMAIN_QUALIFICATION')
    need(domain['facts']['execution_domain']==('OWNED_SIGNED_IMAGE_LOCAL' if stage=='lifecycle' else 'OWNED_NATIVE_BUILD_PROXY'),
         'HOLD_PUBLIC_EXECUTION_DOMAIN')
    if stage=='lifecycle':
        signature_policy=domain['facts']['signature_policy'];route=receipt(files['route.public.json'])
        need(signature_policy==dict(architecture='aarch64',SigLevel='Required',LocalFileSigLevel='Required',
             offline_verifier=True,public_TEST_only=True,private_home_retired=True,
             signature_config_pin=route['signature_config_pin']) and q['signature_policy']==signature_policy,
             'HOLD_REQUIRED_SIGNATURE_DOMAIN_POLICY')
    containers={};retired=set()
    for observation in domain['facts']['observations']:
        body=observation['body'];whole(observation['source_pin'])
        if observation['kind']=='container':
            cid=body['cid'];need(cid not in containers and re.fullmatch('[0-9a-f]{64}',cid)
                and body['image']==expected['image'] and body['state']['Running'] is False
                and type(body['state']['ExitCode']) is int and body['state']['ExitCode']==0
                and body['state'].get('OOMKilled',False) is False,'HOLD_DOMAIN_TERMINAL')
            containers[cid]=body
        elif observation['kind']=='retirement':
            need(body['status'] in ('REMOVED_AND_ABSENT','ABSENT') and body['absence_verified'] is True,'HOLD_DOMAIN_ABSENCE')
            retired.add(body['cid'])
    need(containers and set(containers)==retired==set(q['containers']),'HOLD_DOMAIN_CID_SET')
    for cid,body in containers.items():
        observed=q['containers'][cid];created=observed['created'];terminal=observed['terminal'];gone=observed['retirement']
        need(created==dict(cid=cid,name=body['name'],image=expected['image'],policy=domain_policy)
             and terminal==dict(cid=cid,Running=False,ExitCode=0,OOMKilled=False)
             and gone==dict(cid=cid,status='REMOVED_AND_ABSENT',absence_verified=True),'HOLD_NATURAL_CID_RETIREMENT')
        natural(observed['supervision'])
    inp=receipt(support['inputs']);need(inp['source']==binding and inp['Root_capacity']==caps
         and inp['source_date_epoch']==ad['source_date_epoch'],'HOLD_INPUTS_BINDING')
    if stage in ('ui','lifecycle'):
        official=receipt(support['official_verification'])
        need(official['issuer']=='Root' and official['status']=='ROOT_REVIEWED_OFFICIAL_ONBOARDING_CLOSURE_V2'
             and official['catalog']==pin(support['official_catalog'])
             and official['archive_signature_inputs']==pin(support['official_archive_signature_inputs'])
             and (official['base_packages'],official['selected_packages'],official['qualified_packages'])==(349,23,372)
             and {'gtk4','python-gobject'}<=set(packages),'HOLD_OFFICIAL_UI_CLOSURE')
    return ad,inp,packages,containers


def test_signatures(files,expected,ad,inputs):
    stage=expected['stage'];keys=('setup8','first_login_backend') if stage=='ui' else ('setup8',)
    need(set(expected['test_pins'])==set(keys),'HOLD_TEST_PROOF_SELECTION')
    key_raw=files['public/public_test_key.data'];fingerprint=expected['fingerprint']
    need(re.fullmatch('[0-9A-F]{40}',fingerprint) and key_raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----')
         and b'PRIVATE KEY' not in key_raw,'HOLD_PUBLIC_TEST_KEY')
    route=receipt(files['route.public.json']);verification=route['stage_signature_verification']
    need(verification['status']=='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION' and verification['operation']==OP
         and verification['stage']==stage and verification['binding']==expected['binding']
         and verification['scope']=='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION'
         and set(verification['verified'])==set(keys),'HOLD_ACTUAL_STAGE_VERIFICATION')
    admin=index(files,'administrative' if stage=='lifecycle' else 'admission',expected['resources'])
    wanted=['import-root-test-public','current-primary','trust-current-test-primary']
    if stage=='lifecycle':wanted+=['baseline-inventory','before-e','before-d']
    wanted+=['owner-current-signature-'+key for key in keys]
    if stage=='lifecycle':wanted+=['restored-inventory','after-e','after-d']
    wanted+=['retire-private-0','no-agent-private-0','retire-private-1','no-agent-private-1']
    if stage!='lifecycle':wanted=['fresh-owner-label','native-daemon']+wanted
    need(list(admin)==wanted,'HOLD_COMPLETE_CURRENT_TRUST_STREAM')
    fingerprints=[line.split(':')[9] for line in admin['current-primary'][2].decode().splitlines() if line.startswith('fpr:')]
    need(fingerprints==[fingerprint],'HOLD_ACTUAL_CURRENT_TEST_PRIMARY')
    for key in keys:
        archive=files['public/'+key+'.archive'];signature=files['public/'+key+'.signature']
        decision_raw=files['public/'+key+'.Root_decision.json'];proof_raw=files['public/'+key+'.Root_verification.json']
        need(pin(decision_raw)==whole(expected['test_pins'][key]['decision'])
             and pin(proof_raw)==whole(expected['test_pins'][key]['verification']),'HOLD_AUTHENTIC_ROOT_TEST_PIN')
        decision=receipt(decision_raw);proof=receipt(proof_raw);package_name='cachy-asahi-setup' if key=='setup8' else VERSIONS['first-login'][0]
        version='0.3.0-1' if key=='setup8' else '0.1.0-3'
        key_pin=dict(**pin(key_raw),fingerprint=fingerprint,trust_scope='TEST_ONLY')
        selected=inputs[key]
        need(whole(selected['archive'])==pin(archive) and whole(selected['signature'])==pin(signature)
             and whole(selected['current_TEST_signature_verification']['Root_decision'])==pin(decision_raw)
             and whole(selected['current_TEST_signature_verification']['Root_verification'])==pin(proof_raw),
             'HOLD_ORIGINAL_SELECTED_TEST_INPUTS')
        need(decision['schema']==1 and decision['issuer']=='Root' and decision['accepted'] is True
             and decision['holds_preserved'] is True and decision['trust_scope']=='TEST_ONLY'
             and decision['status']==('ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' if key=='setup8' else 'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY')
             and decision['archive']==dict(package=package_name,version=version,arch='any',**pin(archive))
             and decision['signature']==pin(signature) and decision['signature_file']==inputs[key]['signature']['path']
             and decision['verification_proof_sha256']==pin(proof_raw)['sha256'] and decision['public_test_key']==key_pin
             and decision['public_test_key_file']==ad['owner']['test_public_key']['path'],
             'HOLD_ROOT_TEST_DECISION')
        need(proof['schema']==1 and proof['Root_issuer']=='Root' and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE'
             and proof['verified'] is True and proof['trust_scope']=='TEST_ONLY' and proof['archive']==pin(archive)
             and proof['signature']==pin(signature) and proof['public_test_key']==key_pin,'HOLD_ROOT_TEST_VERIFICATION')
        verified=datetime.datetime.fromisoformat(proof['actual_verified_utc']);issued=datetime.datetime.fromisoformat(decision['issued_at'])
        need(verified.tzinfo is not None and issued.tzinfo is not None and
             verified.timestamp()<=issued.timestamp()<=ad['issued_at_unix'],'HOLD_TEST_PROOF_CHRONOLOGY')
        row=verification['verified'][key];step='owner-current-signature-'+key;_,command,raw=admin[step]
        need(row['archive']==pin(archive) and row['signature']==pin(signature) and row['public_test_key']==pin(key_raw)
             and row['fingerprint']==fingerprint and row['status_text'].encode()==raw
             and files['public/'+key+'.gpg-status.txt']==raw and whole(command['log_pin'])==pin(raw),
             'HOLD_CURRENT_GPG_BODY_JOIN')
        current_signature(raw,fingerprint,expected['observed_at']['finished_at'])
    need(ad['owner']['test_fingerprint']==fingerprint and whole(ad['owner']['test_public_key'])==pin(key_raw),
         'HOLD_SELECTED_TEST_POLICY')
    for i in (0,1):
        _,_,raw=admin['no-agent-private-'+str(i)]
        need(raw==b'gpg-connect-agent: no gpg-agent running in this session\n','HOLD_PRIVATE_AGENT_RETIREMENT')
    if stage=='lifecycle':
        need(admin['baseline-inventory'][2]==admin['restored-inventory'][2]==files['public/inventory.data']
             and admin['before-e'][2]==admin['after-e'][2] and admin['before-d'][2]==admin['after-d'][2],
             'HOLD_LOCAL_STATE_OR_INSTALLATION_REASONS')
    return admin


def builds(files,expected,source,p,inp,packages,containers,commands):
    stage=expected['stage'];kinds=('ui',) if stage=='ui' else ('enrollment','first-login')
    route=receipt(files['route.public.json']);result={};clean=set()
    need(list(commands)==['current-'+kind+'-'+suffix for kind in kinds for suffix in ('a','b','compare')],
         'HOLD_EXACT_BUILD_COMMAND_ROLES')
    for kind in kinds:
        recipe=p['packages'][kind];archives=[];parsed=[];provenances=[]
        for label in ('a','b'):
            root='builds/'+kind+'-'+label;provenance=receipt(files[root+'/provenance.public.json']);provenances.append(provenance)
            need(provenance['status']=='built-package-static-pass' and provenance['mode']=='native' and provenance['network']=='none'
                 and provenance['image']==provenance['image_id']==expected['image'] and provenance['builder_host_arch'] in ('aarch64','arm64')
                 and provenance['source_date_epoch']==inp['source_date_epoch'] and provenance['exit_code']==0
                 and provenance['expected_packages_sha256']==pin(files['public/inventory.data'])['sha256'],'HOLD_BUILD_PROVENANCE')
            identity=provenance['clean_environment_id'];need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',identity) and identity not in clean,'HOLD_DISTINCT_CLEAN_BUILDS');clean.add(identity)
            need(provenance['recipe_inputs']=={name:row['sha256'] for name,row in recipe['files'].items()},'HOLD_BUILD_RECIPE_MAP')
            for name,row in recipe['files'].items():
                need(pin(files[root+'/inputs/'+name])==whole(row) and files[root+'/inputs/'+name]==source[recipe['path']+'/'+name],
                     'HOLD_CLEAN_RECIPE_SOURCE_BYTES')
            need(BUILD_FILES<=set(provenance['files'])<=BUILD_FILES|{'artifacts/'+recipe['archive']},'HOLD_COMPLETE_PROVENANCE_OUTPUTS')
            for name,sha in provenance['files'].items():relative(name);need(pin(files[root+'/'+name])['sha256']==sha,'HOLD_PROVENANCE_BODY')
            need(files[root+'/expected-packages.lock']==files[root+'/artifacts/packages.lock']==files['public/inventory.data'],'HOLD_BUILD_TYPED_INVENTORY')
            check_log(files[root+'/build.log'],kind,p);need(receipt(files[root+'/validation.json'])['errors']==[],'HOLD_BUILD_VALIDATION')
            need(provenance['entry_script_sha256']==pin(source['scripts/build/container-entry.sh'])['sha256'],'HOLD_PINNED_BUILDER_ENTRY')
            raw=files[root+'/artifacts/'+recipe['archive']]
            need(provenance['artifacts']=={recipe['archive']:pin(raw)['sha256']} and route['artifacts'][kind][label]==pin(raw),'HOLD_ACTUAL_ARCHIVE_BODY')
            archives.append(raw);parsed.append(package(raw,recipe,packages,inp['source_date_epoch']))
        _,_,raw=commands['current-'+kind+'-compare'];comparison=receipt(raw)
        observed={recipe['archive']:dict(installed_contents_equal=parsed[0]['payload']==parsed[1]['payload'],
            pkginfo_equal=parsed[0]['metadata']['.PKGINFO']==parsed[1]['metadata']['.PKGINFO'],bytes_equal=archives[0]==archives[1],
            buildinfo_equal=parsed[0]['metadata']['.BUILDINFO']==parsed[1]['metadata']['.BUILDINFO'])}
        need(all(observed[recipe['archive']].values()) and comparison==route['builds']['pairs'][kind]
             and comparison['status']=='contents-reproduced' and comparison['errors']==[] and comparison['packages']==observed,
             'HOLD_RECOMPUTED_COMPARATOR')
        for key in ('image','image_id','mode','source_date_epoch','recipe_inputs','recipe_metadata','expected_packages_sha256','entry_script_sha256'):
            need(provenances[0][key]==provenances[1][key],'HOLD_PAIR_INPUT_MISMATCH')
        result[kind]=dict(archive=pin(archives[0]),payload_files=len(recipe['payload_files']))
    need(clean=={body['name'] for body in containers.values()},'HOLD_BUILD_DOMAIN_IDENTITIES')
    by_name={body['name']:cid for cid,body in containers.items()}
    for name in clean:
        intent=receipt(files['owner-state/intents/'+name+'.json.public.json'])
        outcome=receipt(files['owner-state/intents/'+name+'.result.public.json'])
        need(intent==dict(name=name,image=expected['image'],readonly=True) and outcome['status']=='PASS_OWNED_GENERIC_BUILD_PROXY'
             and outcome['name']==name and not outcome.get('failure') and not outcome.get('retirement_error')
             and outcome['retirement']['status']=='REMOVED_AND_ABSENT' and outcome['retirement']['cid']==by_name[name],
             'HOLD_PROXY_RETIREMENT_BODY')
    cleanup=receipt(files['owner-cleanup.json'])
    need(cleanup['stage']==stage and cleanup['binding']==expected['binding'] and cleanup['failures']==[]
         and cleanup['retired']==[dict(status='ABSENT',name=name) for name in sorted(clean)],'HOLD_FINAL_BUILD_CLEANUP_BODY')
    retired=index(files,'retirement',expected['resources'])
    need(list(retired)==['retire-'+str(i)+'-query' for i in range(len(clean))]+['final-owner-label']
         and all(row[2]==b'' for row in retired.values()),'HOLD_ACTUAL_FINAL_ABSENCE_LOGS')
    labels={name.split('/')[1] for name in files if name.startswith('streams/proxy-')}
    need(labels=={'proxy-'+str(i) for i in range(3*len(clean))},'HOLD_COMPLETE_PROXY_STREAMS')
    inspections=architectures=0;removed=set()
    for label in sorted(labels):
        stream=index(files,label,expected['resources'])
        if list(stream)==['image-inspect']:inspections+=1
        elif list(stream)==['native-architecture']:
            need(stream['native-architecture'][2].strip() in (b'arm64',b'aarch64'),'HOLD_ACTUAL_NATIVE_DAEMON_BODY');architectures+=1
        else:
            need(list(stream)==['fresh-name','create','inspect-created','start-attached','inspect-terminal',
                 'proxy-final-query','proxy-final-inspect','proxy-final-remove','proxy-final-after']
                 and stream['fresh-name'][2]==stream['proxy-final-after'][2]==b'','HOLD_EXACT_PROXY_COMMAND_STREAM')
            cid=stream['proxy-final-remove'][2].decode().strip()
            need(cid in containers and cid not in removed,'HOLD_ACTUAL_CID_REMOVAL_LOG');removed.add(cid)
    need(inspections==architectures==len(clean) and removed==set(containers),'HOLD_COMPLETE_PROXY_RETIREMENTS')
    return result


def lifecycle(files,expected,source,p,inputs,ad,packages,commands,support,depth):
    route=receipt(files['route.public.json']);prior=expected['prior'];need(type(prior) is dict and set(prior)=={'backend','ui'},'HOLD_PRIOR_STAGE_BINDINGS')
    prior_data={};prior_views={}
    for stage in ('backend','ui'):
        raw=files['public/prior_'+stage+'.data'];other=prior[stage]
        need(other['stage']==stage and other['binding']==expected['binding'],'HOLD_PRIOR_STAGE_TUPLE')
        need(other['observed_at']['finished_at']<=expected['observed_at']['started_at'],'HOLD_PRIOR_STAGE_CHRONOLOGY')
        result=_check(raw,other,source,support,depth+1)
        need(result['status']=='PASS_PUBLIC_CURRENT_STAGE_DATA_ONLY','HOLD_PRIOR_STAGE_READER')
        prior_data.update(result['packages']);prior_views[stage]=capsule_files(raw,other['capsule_pin'],stage)[0]
    signed={};epoch=inputs['source_date_epoch'];steps=list(commands);required={'current-baseline'}
    for kind in ('setup8',*KINDS):
        raw=files['signed/'+kind+'.archive'];sig=files['signed/'+kind+'.signature'];signed[kind]=raw
        selected=ad['signed'][kind];recipe=p['setup8'] if kind=='setup8' else p['packages'][kind]
        need(selected['name']==recipe['name'] and selected['version']==recipe['version']
             and selected['archive_pin']==pin(raw) and selected['signature_pin']==pin(sig)
             and selected['payload_files']==recipe['payload_files'],'HOLD_ROOT_SELECTED_SIGNED_INPUTS')
        _,_,status=commands['current-signature-'+kind]
        current_signature(status,expected['fingerprint'],expected['observed_at']['finished_at'])
        info=metadata(commands['current-pkginfo-'+kind][2])
        need(info.get('pkgname')==[recipe['name']] and info.get('pkgver')==[recipe['version']]
             and info.get('arch')==['any'] and steps.index('current-baseline')<steps.index('current-signature-'+kind)
             <steps.index('current-pkginfo-'+kind)<steps.index('current-install-setup8'),'HOLD_SIGNATURE_PKGINFO_INSTALL_ORDER')
        required.update(('current-signature-'+kind,'current-pkginfo-'+kind))
        if kind=='setup8':need(raw==files['public/setup8.archive'] and sig==files['public/setup8.signature'] and pin(raw)==p['setup8']['archive_pin'],'HOLD_SETUP8_ACCEPTED_BODY')
        else:
            recipe=p['packages'][kind];stage='ui' if kind=='ui' else 'backend'
            actual=prior_views[stage]['builds/'+kind+'-a/artifacts/'+recipe['archive']]
            need(raw==actual and pin(raw)==prior_data[kind]['archive'],'HOLD_SIGNED_PRIOR_PAIR_BODY')
            parsed=package(raw,recipe,inventory(prior_views[stage]['public/inventory.data']),epoch)
            need(commands['current-pkginfo-'+kind][2]==parsed['metadata']['.PKGINFO'],'HOLD_ACTUAL_SIGNED_PKGINFO_BODY')
    versions={recipe['name']:recipe['version'] for recipe in p['packages'].values()};setup={p['setup8']['name']:p['setup8']['version']}
    inventory_steps=['current-baseline','current-dependency-inventory','current-install-inventory','current-after-remove-install',
                     'current-reinstall-inventory','current-after-remove-reinstall','current-final-inventory']
    wanted=[packages,packages|setup,packages|setup|versions,packages|setup,packages|setup|versions,packages|setup,packages]
    required.update(inventory_steps);required.add('current-install-setup8')
    need([commands[step][0] for step in inventory_steps]==sorted(commands[step][0] for step in inventory_steps),
         'HOLD_LIFECYCLE_TRANSITION_ORDER')
    for step,selected in zip(inventory_steps,wanted):
        _,_,raw=commands[step];need(raw==inventory_bytes(selected),'HOLD_LIFECYCLE_INVENTORY_BODY')
        if step!='current-baseline':need(route['lifecycle']['inventories'][step]==pin(raw),'HOLD_LIFECYCLE_INVENTORY_PIN')
    def payload(kind,label,after,before):
        recipe=p['setup8'] if kind=='setup8' else p['packages'][kind];record=route['lifecycle']['payloads']['setup8'] if kind=='setup8' else route['lifecycle']['payloads'][label.split('-')[1]][kind]
        need(record==dict(verified=True,files=recipe['payload_files']),'HOLD_PAYLOAD_SOURCE_RECEIPT')
        position,_,raw=commands[label+'-file-list']
        required.add(label+'-file-list')
        need(position>steps.index(after) and {n.lstrip('/') for n in raw.decode().splitlines() if not n.endswith('/')}==set(recipe['payload_files']),
             'HOLD_ALPM_FILE_LIST')
        for i,(name,row) in enumerate(sorted(recipe['payload_files'].items())):
            required.update(label+'-'+field+'-'+str(i) for field in ('owner','stat','sha256'))
            owner=commands[label+'-owner-'+str(i)];observed=commands[label+'-stat-'+str(i)];digest=commands[label+'-sha256-'+str(i)]
            need(min(owner[0],observed[0],digest[0])>steps.index(after) and max(owner[0],observed[0],digest[0])<steps.index(before)
                 and owner[2].decode().strip()==recipe['name']
                 and observed[2]==('0:0:%o:%d:1:regular file\n'%(row['mode'],row['bytes'])).encode()
                 and digest[2]==(row['sha256']+'  /'+name+'\n').encode(),'HOLD_ACTUAL_PAYLOAD_OWNER_STAT_HASH')
    payload('setup8','current-setup8','current-dependency-inventory','current-install')
    need(steps.index('current-install-setup8')<steps.index('current-dependency-inventory'),'HOLD_SETUP_INSTALL_ORDER')
    for cycle in ('install','reinstall'):
        required.update(('current-'+cycle,'current-remove-'+cycle))
        need(steps.index('current-'+cycle)<steps.index('current-'+cycle+'-inventory'),'HOLD_PROJECT_INSTALL_ORDER')
        for kind in KINDS:
            required.add('current-'+cycle+'-help-'+kind)
            payload(kind,'current-'+cycle+'-'+kind,'current-'+cycle+'-inventory','current-remove-'+cycle)
            need(steps.index('current-'+cycle+'-inventory')<commands['current-'+cycle+'-help-'+kind][0]<steps.index('current-remove-'+cycle),'HOLD_HELP_ORDER')
        need(steps.index('current-remove-'+cycle)<steps.index('current-after-remove-'+cycle),'HOLD_REMOVE_INVENTORY_ORDER')
        names=sorted({name for recipe in p['packages'].values() for name in recipe['payload_files']})
        for i,_ in enumerate(names):
            for flag in ('-e','-L'):
                required.add('current-absent-'+cycle+'-'+str(i)+flag)
                position,_,raw=commands['current-absent-'+cycle+'-'+str(i)+flag]
                need(position>steps.index('current-after-remove-'+cycle) and raw==b'','HOLD_REMOVED_PAYLOAD_ABSENCE')
    required.add('current-remove-setup8')
    first_absent=max(commands['current-absent-install-'+str(i)+flag][0] for i in range(len(names)) for flag in ('-e','-L'))
    last_absent=max(commands['current-absent-reinstall-'+str(i)+flag][0] for i in range(len(names)) for flag in ('-e','-L'))
    need(first_absent<steps.index('current-reinstall') and last_absent<steps.index('current-remove-setup8')
         <steps.index('current-final-inventory'),'HOLD_REINSTALL_AND_FINAL_REMOVAL_ORDER')
    for i,_ in enumerate(sorted(p['setup8']['payload_files'])):
        for flag in ('-e','-L'):
            required.add('current-absent-setup8-'+str(i)+flag)
            position,_,raw=commands['current-absent-setup8-'+str(i)+flag]
            need(position>steps.index('current-final-inventory') and raw==b'','HOLD_SETUP8_REMOVAL_ABSENCE')
    need(set(commands)==required,'HOLD_EXACT_LIFECYCLE_ROLE_SET')
    need(route['protected_before']==route['protected_after'] and set(route['protected_before'])==
        {'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'},'HOLD_PROTECTED_STATE_PRESERVATION')
    local=receipt(files['owner-local.public.json']);outer=receipt(files['outer-retirement.public.json'])
    need(all(row['operation']==OP and row['stage']=='lifecycle' and row['binding']==expected['binding']
         for row in (local,outer)),'HOLD_LIFECYCLE_RETIREMENT_TUPLE')
    need(local['status']=='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT' and local['body_success'] is True
         and local['protected_state_unchanged'] is True and all(local['private_retirement'].get(k) is True for k in
             ('homes_retired','no_sockets','private_directory_absent')) and outer['status']=='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT',
         'HOLD_OWNED_LIFECYCLE_RETIREMENT')
    outer_commands=index(files,'outer',expected['resources'])
    need(list(outer_commands)==['fresh-owner-label','native-daemon','fresh-name','create','inspect-created','start-attached',
         'inspect-terminal','retire-query','retire-inspect','retire-remove','retire-after']
         and outer_commands['retire-after'][2]==b'','HOLD_OUTER_NATURAL_RETIREMENT_STREAM')
    return {kind:dict(archive=pin(raw),payload_files=len((p['setup8'] if kind=='setup8' else p['packages'][kind])['payload_files'])) for kind,raw in signed.items()}


def _check(capsule,expected,source_files,support_files,depth=0):
    need(depth<=1 and type(expected) is dict and set(expected)==EXPECTED_KEYS and expected['schema']==3
         and expected['kind']=='ROOT_BOUND_PUBLIC_CURRENT_READER_V3' and expected['stage'] in STAGES,'HOLD_EXTERNAL_READER_BINDING')
    helper_inverse();need(pin(Path(__file__).read_bytes())==whole(expected['reader_pin']),'HOLD_EXACT_READER_PROGRAM')
    binding=expected['binding'];stage=expected['stage']
    need(set(binding)=={'source','ref','run','job','attempt','source_lock'} and re.fullmatch('[0-9a-f]{40}',binding['source'])
         and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',binding['ref'])
         and all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]*',binding[k]) for k in ('run','job'))
         and type(binding['attempt']) is int and binding['attempt']==1,'HOLD_ACTUAL_TUPLE')
    files,manifest=capsule_files(capsule,expected['capsule_pin'],stage)
    need(manifest['schema']==3 and manifest['kind']=={'backend':'CURRENT_BACKEND_RETENTION_V3','ui':'CURRENT_UI_RETENTION_V3','lifecycle':'CURRENT_LIFECYCLE_RETENTION_V3'}[stage]
         and manifest['operation']==OP and manifest['stage']==stage and manifest['binding']==binding
         and manifest['evidence_state']=='COMPLETE' and manifest['holds']==[]
         and all(manifest[k] is None for k in ('Root_acceptance','component_acceptance','hardware_acceptance','release_acceptance')),
         'HOLD_INCOMPLETE_OR_UNCERTAIN_RETENTION')
    roles=PUBLIC|({'prior_backend','prior_ui'} if stage=='lifecycle' else set())
    need(set(expected['public_pins'])==roles,'HOLD_PUBLIC_ROLE_BINDING')
    for role,row in expected['public_pins'].items():
        need(set(row)=={'original','projection'},'HOLD_PUBLIC_PROJECTION_PIN_SCHEMA')
        name='public/'+role+'.data'
        need(pin(files[name])==whole(row['projection']) and whole(manifest['sources'][name])==whole(row['original']),
             'HOLD_ORIGINAL_VS_PUBLIC_PROJECTION:'+role)
    required={'inputs','domain_qualification'}|({'official_catalog','official_archive_signature_inputs','official_verification'} if stage in ('ui','lifecycle') else set())|({'ui_backend_pair'} if stage=='ui' else set())
    need(set(expected['support_pins'])==required and type(support_files) is dict,'HOLD_PUBLIC_SUPPORT_SELECTION')
    # A lifecycle caller supplies a stage-keyed support map for recursively bound prior capsules.
    support=support_files.get(stage,support_files)
    need(set(support)==required,'HOLD_PUBLIC_SUPPORT_BODIES')
    for role,row in expected['support_pins'].items():need(type(support[role]) is bytes and pin(support[role])==whole(row),'HOLD_PUBLIC_SUPPORT_PIN:'+role)
    p,program,policy=source_data(expected,source_files)
    if whole(expected['source']['policy'])==FULL_POLICY_PIN:
        need(pin(files['public/public_test_key.data'])==SELECTED_TEST_KEY_PIN,'HOLD_RETAINED_SOURCE_TEST_CERTIFICATE')
    ad,inputs,packages,containers=qualified(files,expected,support,policy)
    route=receipt(files['route.public.json'])
    need(route['operation']==OP and route['stage']==stage and route['binding']==binding
         and route['status']=='PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY' and route['Root_acceptance'] is None
         and route['profile_pin']==whole(expected['source']['profile']) and route['inputs_pin']==pin(support['inputs'])
         and route['source_lock']==binding['source_lock'],'HOLD_ROUTE_SOURCE_BINDING')
    cleanup=route['owner_cleanup'];need(cleanup['status']=='PASS_OWNED_CURRENT_STAGE_RETIREMENT'
         and cleanup['binding']==binding and cleanup['stage']==stage and all(cleanup[k] is True for k in
         ('natural_retirement','owned_container_absence_verified','protected_state_unchanged')),'HOLD_OWNER_CLEANUP')
    test_signatures(files,expected,ad,inputs);commands=index(files,'stage',expected['resources'])
    if policy['kind']=='CURRENT_ONBOARDING_FULL_POLICY_PROPOSAL_V3':
        observed=receipt(support['domain_qualification'])['owned_domains']['frozen_seconds']
        need(max(row[1]['supervision']['seconds'] for row in commands.values())<=observed['build_seconds'],
             'HOLD_ACTUAL_FROZEN_COMMAND_DURATION')
    if stage=='ui':
        pair=receipt(support['ui_backend_pair'])
        need(pair['issuer']=='Root' and pair['status']=='ROOT_REVIEWED_CURRENT_FIRST_LOGIN_PAIR_V2' and pair['binding']==binding
             and pair['name']=='cachy-asahi-first-login' and pair['version']=='0.1.0-3'
             and pair['archive']==pin(files['public/first_login_backend.archive']),'HOLD_REVIEWED_CURRENT_BACKEND_PAIR')
    result=(lifecycle(files,expected,source_files,p,inputs,ad,packages,commands,support_files,depth) if stage=='lifecycle'
            else builds(files,expected,source_files,p,inputs,packages,containers,commands))
    return dict(status='PASS_PUBLIC_CURRENT_STAGE_DATA_ONLY',stage=stage,binding=binding,packages=result,
                source_program=whole(expected['source']['program']),Root_authentication=False,Root_acceptance=None,
                component_acceptance=None,hardware_acceptance=None,release_acceptance=None,
                native16K='UNQUALIFIED',M2='NOT_RUN',performance='NOT_MEASURED')


def read_stage(capsule,*,expected,source_files,support_files,now):
    """Passive independent replay; all absent/provisional/uncertain evidence is HOLD."""
    try:
        need(type(now) in (int,float) and math.isfinite(now) and expected['observed_at']['finished_at']<=now,'HOLD_EVENT_TIME')
        return _check(capsule,expected,source_files,support_files)
    except Exception as error:
        reason=str(error) if isinstance(error,ValueError) and str(error).startswith('HOLD_') else 'HOLD_MISSING_OR_MALFORMED_PUBLIC_EVIDENCE'
        if isinstance(error,ValueError) and 'Python3.14 stdlib zstd required' in str(error):reason='HOLD_ZSTD_DECODER_REQUIRES_PYTHON314'
        return dict(status='HOLD',stage=expected.get('stage') if isinstance(expected,dict) else None,
                    reasons=[reason],Root_authentication=False,Root_acceptance=None,component_acceptance=None,
                    hardware_acceptance=None,release_acceptance=None)


DELEGATED_RETENTION_PIN=dict(bytes=41461,sha256='cccaf8c96e774e06f81045e52ca5328ca5d8528f0492ca98b790618e7f95da10')
CANONICAL_RETENTION_PIN=dict(bytes=41534,sha256='ac6536c1375de1ff63e0757201caf3202039bd25ed0b4c45208e4abedfdef438')
SELECTED_RETENTION_PIN=dict(bytes=43990,sha256='677bd9c6c34e63352da017f4191e64d60a3e53f7cec25de3d6d861388265ba3a')
TIMED_RETENTION_PIN=dict(bytes=47183,sha256='8af738f176a76751a70e794e1b665d5c01a89bc2959a0dfb17b7de746c045bfd')
INVOCATION_RETENTION_PIN=dict(bytes=52552,sha256='6ca157194b944614de3eb8cda0b99702b4f6e95d5a0654dce878e17b5a877fe3')
BASE_RETENTION_PIN=dict(bytes=56142,sha256='0aed986194a009fd1dcce5b244b1c6ccb1e0c11667a9674bdf12c657cc1c9fe7')
INVOCATION_RETENTION_VERSIONS=(INVOCATION_RETENTION_PIN,BASE_RETENTION_PIN)
DELEGATED_RETENTION_VERSIONS=(DELEGATED_RETENTION_PIN,CANONICAL_RETENTION_PIN,SELECTED_RETENTION_PIN,TIMED_RETENTION_PIN,*INVOCATION_RETENTION_VERSIONS)
TIMED_RETENTION_VERSIONS=(TIMED_RETENTION_PIN,*INVOCATION_RETENTION_VERSIONS)
ADOPTION_RETENTION_VERSIONS=(SELECTED_RETENTION_PIN,*TIMED_RETENTION_VERSIONS)
DELEGATED_CONSTRUCTOR_PIN=dict(bytes=20198,sha256='02660706d2195b03212c0368636de67f43f08ecab1f7ede8bcd6c745ae9e5119')
BASE_CONSTRUCTOR_PIN=dict(bytes=24988,sha256='d97e9914f4d99f85cc245e591fa9c18c9aeb743ea58348b6ca5c9978c6317586')
DELEGATED_OWNER_BASIS=dict(commit='e8034dabf4eb757ab8261ebecfc00a45c5c8092b',
    owner=dict(bytes=63490,sha256='43c8ec1b0c857b7e27f6243dba50c824d47ba6323df6dd6d64ad9eabae39f825'),
    route=dict(bytes=16200,sha256='86894e3e8696308c50ad248c5ba4cd786f299e8316c0c57571334880c2f19fcf'))
CANONICAL_OWNER_BASIS=dict(commit='81d66ae53849e3924eab25d3d48aaf037e631cdd',
    owner=dict(bytes=61778,sha256='4b24c48594253e9fee5df134b130f329e94f32574369cc748e82d74393c3f581'),
    route=dict(bytes=16196,sha256='78be10c869556ecc0cd07e7ddc0b94016c3fae0cc02b1470420861808289cdee'))
INVOCATION_OWNER_BASIS=dict(commit='9fa3201a28d3981fd05013d4244fbb406739cbc5',
    owner=dict(bytes=68320,sha256='4196aa414d7711a5e56c0a73f63282db712fffdfccdd9206e5b4e69f9605c7ad'),
    route=CANONICAL_OWNER_BASIS['route'])
DELEGATED_EXPECTED_KEYS={'schema','kind','stage','binding','nonce','capsule_pin','reader_pin','source_lock_pin',
    'source','delegation_pin','context_pin','image_report_pin','stage_report_pin','origin_pins',
    'support_pins','test_pins','observed_at','prior'}
DELEGATED_FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,
    hardware_acceptance=False,release_acceptance=False)
DELEGATED_SAFE=r'(?:verify-[0-9]+|pkginfo-[0-9]+|start-(?:base|backend|ui|lifecycle|probe)|build-(?:enrollment|first-login|ui)-[ab]-attach|validate-(?:enrollment|first-login|ui)-[ab]|current-[A-Za-z0-9_.-]+|private-signature-[A-Za-z0-9_.-]+|adopted-pkginfo-[A-Za-z0-9_.-]+|(?:no-agent-private|private-no-agent)-[0-9]+)'


def delegated_final(value):
    need(all(key in value and type(value[key]) is type(wanted) and value[key]==wanted
         for key,wanted in DELEGATED_FINAL.items()),'HOLD_DELEGATED_FINAL_AUTHORITY')


def delegated_public_body(raw):
    need(not re.search(br'-----BEGIN (?:PGP PRIVATE KEY BLOCK|[A-Z0-9 ]*PRIVATE KEY)-----|(?im:^)(?:Authorization:|AWS_SECRET_ACCESS_KEY=|GITHUB_TOKEN=)',raw),
         'HOLD_DELEGATED_PRIVATE_MATERIAL')
    if raw.lstrip().startswith((b'{',b'[')):
        try:value=decode(raw)
        except (ValueError,UnicodeError):
            # Normal literal status lines such as [GNUPG:] are not JSON receipts.
            need(not raw.lstrip().startswith(b'{'),'HOLD_MALFORMED_PUBLIC_RECEIPT')
            return
        receipt(encoded(dict(value=value)))


def delegated_capsule_files(raw,expected):
    stage=expected['stage']
    selector=whole(expected['source']['retention'])
    need(selector in DELEGATED_RETENTION_VERSIONS,'HOLD_DELEGATED_SELECTOR_VERSION')
    basis=DELEGATED_OWNER_BASIS if selector==DELEGATED_RETENTION_PIN else INVOCATION_OWNER_BASIS if selector in INVOCATION_RETENTION_VERSIONS else CANONICAL_OWNER_BASIS
    need(type(raw) is bytes and 0<len(raw)<=MAX_COMPRESSED and pin(raw)==whole(expected['capsule_pin']),
         'HOLD_DELEGATED_CAPSULE_PIN')
    stream=zlib.decompressobj(31);tar=stream.decompress(raw,18*1024**2+1)
    need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and len(tar)<=18*1024**2,
         'HOLD_DELEGATED_GZIP_BOUND')
    prefix='delegated-'+stage+'-public-v4/';files={};total=0;cursor=0
    with tarfile.open(fileobj=io.BytesIO(tar),mode='r:') as archive:
        for item in archive:
            need(len(files)<MAX_MEMBERS and item.isfile() and item.name.startswith(prefix) and item.mode==0o444
                 and 0<=item.size<=8*1024**2 and set(item.pax_headers)<={'mtime','atime','ctime'},
                 'HOLD_DELEGATED_CAPSULE_MEMBER')
            name=item.name[len(prefix):];relative(name)
            need(name not in files and Path(name).name not in ('inside.json','proxy.json','signature-config.txt','ownertrust','pacman.log')
                 and not set(name.split('/'))&{'home','trust','cache','gpg','gnupg','keyring','keyrings','storage','mounted-storage',
                     '.git','.gnupg','.ssh','.aws','.cache','.config','.local','.docker','.kube','.password-store','.netrc',
                     'private-keys-v1.d','openpgp-revocs.d','credentials'},'HOLD_DELEGATED_NAMESPACE')
            with archive.extractfile(item) as body:raw_body=body.read(item.size+1)
            need(len(raw_body)==item.size,'HOLD_DELEGATED_MEMBER_SIZE');delegated_public_body(raw_body)
            files[name]=raw_body;total+=item.size
            need(total<=MAX_LOGICAL,'HOLD_DELEGATED_LOGICAL_CAP')
            cursor=max(cursor,item.offset_data+(item.size+511)//512*512)
    need(len(tar)-cursor>=1024 and not any(tar[cursor:]),'HOLD_DELEGATED_TAR_TRAILER')
    manifest=receipt(files['retention-manifest.json'])
    need(set(manifest)=={'schema','kind','issuer','operation','stage','binding','nonce','delegation_pin','context_pin',
         'stage_report_pin','image_report_pin','selector_basis','evidence_state','holds','files','origins',
         'legacy_private_launch_replay','provisional_observations_only',*DELEGATED_FINAL}
         and manifest['schema']==4 and manifest['kind']=='DELEGATED_CURRENT_STAGE_RETENTION_V4'
         and manifest['issuer']=='DELEGATED_RETENTION_PROGRAM_V4' and manifest['operation']==OP
         and manifest['stage']==stage and manifest['binding']==expected['binding'] and manifest['nonce']==expected['nonce']
         and manifest['selector_basis']==basis and manifest['evidence_state']=='COMPLETE'
         and manifest['holds']==[] and manifest['legacy_private_launch_replay'] is False
         and manifest['provisional_observations_only'] is True,'HOLD_DELEGATED_MANIFEST')
    delegated_final(manifest)
    need(set(manifest['files'])==set(files)-{'retention-manifest.json'},'HOLD_DELEGATED_CLOSED_MEMBERSHIP')
    for name,row in manifest['files'].items():need(pin(files[name])==whole(row),'HOLD_DELEGATED_FILE_PIN:'+name)
    need(set(expected['origin_pins'])==set(manifest['origins']),'HOLD_DELEGATED_ORIGIN_SELECTION')
    for name,row in manifest['origins'].items():
        selected=expected['origin_pins'][name]
        need(name in files and set(selected)=={'original','projection'}
             and set(row) in ({'pin'},{'pin','member'},{'pin','projection'})
             and whole(row['pin'])==whole(selected['original']) and pin(files[name])==whole(selected['projection']),
             'HOLD_DELEGATED_ORIGINAL_PROJECTION_PIN:'+name)
        if 'member' in row:relative(row['member'])
        if 'projection' in row:need(row['projection'] is True,'HOLD_DELEGATED_PROJECTION_KIND')
        else:need(pin(files[name])==whole(row['pin']),'HOLD_DELEGATED_ORIGINAL_BODY:'+name)
    for name in ('delegation','context'):
        need(manifest[name+'_pin']==whole(expected[name+'_pin'])==pin(files[name+'.json']),
             'HOLD_DELEGATED_ORIGINAL_'+name.upper())
        need(encoded(receipt(files[name+'.json']))==files[name+'.json'],'HOLD_DELEGATED_CANONICAL_ORIGINAL')
    for role,name in (('image','image.public.json'),('stage','route.public.json')):
        need(manifest[role+'_report_pin']==whole(expected[role+'_report_pin'])
             ==whole(manifest['origins'][name]['pin']) and manifest['origins'][name].get('projection') is True,
             'HOLD_DELEGATED_REPORT_ORIGINAL_PIN')
    if selector==BASE_RETENTION_PIN:
        name='image/base-inputs.public.json'
        need(name in files and name in manifest['origins'] and manifest['origins'][name].get('projection') is True,
             'HOLD_BASE_PROVENANCE_BODY_REQUIRED')
    return files,manifest


def delegated_index(files,label,stage,selected_streams=False,timed=False,index_selection=None,image_report_pin=None,invocations=False):
    wrapped=receipt(files['streams/'+label+'/commands.public.json'])
    need(set(wrapped)==({'schema','kind','source','count','rows'} if timed else {'rows'})
         and type(wrapped['rows']) is list and 0<len(wrapped['rows'])<=512,
         'HOLD_DELEGATED_COMMAND_INDEX')
    if timed:
        origin=wrapped['source']
        need(wrapped['schema']==4 and wrapped['kind']=='DELEGATED_PUBLIC_COMMAND_INDEX_V4'
             and type(wrapped['count']) is int and wrapped['count']==len(wrapped['rows'])
             and type(index_selection) is dict and set(index_selection)=={'original','projection'}
             and index_selection['original']==origin
             and whole(index_selection['projection'])==pin(files['streams/'+label+'/commands.public.json']),
             'HOLD_DELEGATED_INDEX_ORIGINAL_PROJECTION')
        whole(origin['canonical_rows_pin'])
        if label=='image':need(set(origin)=={'kind','report_pin','field','canonical_rows_pin'}
             and origin['kind']=='ORIGINAL_IMAGE_REPORT_FIELD' and origin['field']=='commands'
             and origin['report_pin']==image_report_pin,'HOLD_DELEGATED_IMAGE_INDEX_ORIGIN')
        else:need(set(origin)=={'kind','pin','canonical_rows_pin'} and origin['kind']=='ORIGINAL_COMMAND_INDEX_BODY'
             and whole(origin['pin'])==origin['pin'],'HOLD_DELEGATED_LOCAL_INDEX_ORIGIN')
    result={};used_frames={};used_invocations={};style='image' if label=='image' else 'local' if label=='administrative' or label=='stage' and stage=='lifecycle' else 'owner'
    for i,row in enumerate(wrapped['rows']):
        step=row['step'];need(type(step) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',step)
             and step not in result,'HOLD_DELEGATED_COMMAND_STEP')
        required={'step','expected','output_pin','supervision','original_receipt_pin'}|({'ordinal','timeout_seconds','supervision_cap_seconds'} if timed else {'exit'})
        optional={'stderr_pin','body_frame','private_body_excluded_before_open'}|({'exit','success','expected_policy','channels','original_executor_receipt_pin','body_members'} if timed else set())
        if invocations:optional|={'retirement_seconds','grace_seconds','max_output_bytes','local_invocation_v1','invocation_frame'}
        need(required<=set(row)<=required|optional,
             'HOLD_DELEGATED_COMMAND_FIELDS')
        whole(row['original_receipt_pin']);whole(row['output_pin'])
        expected=row['expected'];need(type(expected) is int and expected in (0,2)
             and (expected==0 or step.startswith('no-agent-private-')),'HOLD_DELEGATED_COMMAND_EXIT')
        if 'exit' in row:need(type(row['exit']) is int and row['exit']==expected,'HOLD_DELEGATED_COMMAND_EXIT')
        supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
            timeout=False,signals=[],error=None,exit=expected)
        wanted_supervision=set(supervision)|({'seconds','passed'} if timed else set())
        flags={'forced_cleanup','ownership_lost','emergency_retirement'} if timed else set()
        need(wanted_supervision<=set(row['supervision'])<=wanted_supervision|flags and all(type(row['supervision'][key]) is type(value)
             and row['supervision'][key]==value for key,value in supervision.items()),'HOLD_DELEGATED_NATURAL_RETIREMENT')
        if timed:
            sup=row['supervision'];elapsed=sup['seconds'];cap=row['supervision_cap_seconds'];timeout=row['timeout_seconds']
            need(type(row['ordinal']) is int and row['ordinal']==i and type(sup['passed']) is bool
                 and sup['passed'] is (expected==0) and all(type(value) in (int,float) and math.isfinite(value) for value in (elapsed,cap,timeout))
                 and 0<=elapsed<cap<=timeout and cap>1 and all(sup[key] is False for key in flags&set(sup)),
                 'HOLD_DELEGATED_ACTUAL_RETAINED_COMMAND_BOUND')
            if 'success' in row:need(row['success'] is True,'HOLD_DELEGATED_ACTUAL_COMMAND_SUCCESS')
            if 'expected_policy' in row:need(row['expected_policy']=='OBSERVE_STATUS_ONLY','HOLD_DELEGATED_EXPECTED_POLICY')
            if 'channels' in row:need(row['channels'] in ('stdout with separately pinned stderr','stdout+stderr combined in pipe order'),
                 'HOLD_DELEGATED_ACTUAL_CHANNEL_CONTRACT')
            if 'original_executor_receipt_pin' in row:whole(row['original_executor_receipt_pin'])
            if style=='owner':need('original_executor_receipt_pin' in row,'HOLD_DELEGATED_ORIGINAL_EXECUTOR_ASSOCIATION')
            if invocations and any(key in row for key in ('retirement_seconds','grace_seconds','max_output_bytes')):
                need({'retirement_seconds','grace_seconds','max_output_bytes'}<=set(row)
                     and all(type(row[key]) in (int,float) and math.isfinite(row[key]) for key in ('retirement_seconds','grace_seconds'))
                     and 0<=row['grace_seconds']<row['retirement_seconds']<cap and type(row['max_output_bytes']) is int
                     and 0<=row['max_output_bytes']<=1024**2,'HOLD_DELEGATED_ACTUAL_RETIREMENT_BOUND')
        if invocations and style=='local':
            proof=row['local_invocation_v1'];request=proof['request'];chosen=proof['supervision_request']
            need(set(proof)=={'schema','kind','request','request_pin','supervision_request','supervision_request_pin','held_receipt_pin','supervision_result_pin'}
                 and type(proof['schema']) is int and proof['schema']==1 and proof['kind']=='DELEGATED_LOCAL_COMMAND_INVOCATION_V1'
                 and set(request)=={'schema','kind','step','argv_pin','timeout_seconds','deadline_monotonic','max_output_bytes'}
                 and type(request['schema']) is int and request['schema']==1 and request['kind']=='DELEGATED_LOCAL_COMMAND_INVOCATION_REQUEST_V1'
                 and request['step']==step and type(request['deadline_monotonic']) in (int,float)
                 and math.isfinite(request['deadline_monotonic']) and request['deadline_monotonic']>0,
                 'HOLD_DELEGATED_LOCAL_REQUEST')
            need(all(whole(value)['bytes']>0 for value in (request['argv_pin'],proof['held_receipt_pin'],proof['supervision_result_pin'])),
                 'HOLD_DELEGATED_LOCAL_ORIGINAL_WHOLE_PINS')
            need(2<=request['timeout_seconds']<=600 and row['supervision_cap_seconds']>1.1
                 and row['retirement_seconds']==1 and row['grace_seconds']==.2
                 and proof['supervision_result_pin']==pin(encoded(row['supervision'])),
                 'HOLD_DELEGATED_HELD_LOCAL_INVOCATION')
            need(set(chosen)=={'schema','kind','step','request_pin','cap_seconds','retirement_seconds','grace_seconds','max_output_bytes'}
                 and type(chosen['schema']) is int and chosen['schema']==1 and chosen['kind']=='DELEGATED_LOCAL_SUPERVISION_REQUEST_V1' and chosen['step']==step
                 and chosen['request_pin']==proof['request_pin']==pin(encoded(request))
                 and proof['supervision_request_pin']==pin(encoded(chosen))
                 and request['timeout_seconds']==row['timeout_seconds'] and type(request['timeout_seconds']) is type(row['timeout_seconds'])
                 and type(request['max_output_bytes']) is int
                 and request['max_output_bytes']==chosen['max_output_bytes']==row['max_output_bytes']
                 and all(chosen[key]==row[target] and type(chosen[key]) is type(row[target]) for key,target in
                     (('cap_seconds','supervision_cap_seconds'),('retirement_seconds','retirement_seconds'),('grace_seconds','grace_seconds'),('max_output_bytes','max_output_bytes'))),
                 'HOLD_DELEGATED_LOCAL_SUPERVISION_REQUEST')
            name=row['invocation_frame'];need(re.fullmatch('streams/'+label+'/invocations-[0-9]{3}\\.json',name),
                 'HOLD_DELEGATED_INVOCATION_FRAME_REFERENCE')
            if name not in used_invocations:
                frame=receipt(files[name]);need(set(frame)=={'schema','kind','rows'} and frame['schema']==1
                     and frame['kind']=='EXACT_LOCAL_INVOCATION_BODIES_V1' and type(frame['rows']) is list and frame['rows'],
                     'HOLD_DELEGATED_INVOCATION_FRAME_SCHEMA')
                used_invocations[name]=[frame['rows'],set()]
            matches=[value for value in used_invocations[name][0] if value['step']==step]
            need(len(matches)==1 and step not in used_invocations[name][1] and set(matches[0])=={'step','request','supervision_request'},
                 'HOLD_DELEGATED_INVOCATION_FRAME_STEP')
            for role,value in (('request',request),('supervision_request',chosen)):
                part=matches[0][role];need(set(part)=={'pin','base64'} and type(part['base64']) is str
                     and len(part['base64'])<=22000,'HOLD_DELEGATED_INVOCATION_BASE64_BOUND')
                raw=base64.b64decode(part['base64'],validate=True)
                need(len(raw)<=16384 and raw==encoded(value) and base64.b64encode(raw).decode()==part['base64']
                     and pin(raw)==whole(part['pin'])==whole(proof[role+'_pin']),
                     'HOLD_DELEGATED_INVOCATION_FRAME_BODY')
                delegated_public_body(raw)
            used_invocations[name][1].add(step)
        else:need('local_invocation_v1' not in row and 'invocation_frame' not in row,'HOLD_DELEGATED_UNEXPECTED_LOCAL_INVOCATION')
        safe=re.fullmatch(DELEGATED_SAFE,step) is not None or selected_streams and re.fullmatch('verify-selected-[0-9]+-1',step) is not None
        stdout=stderr=None
        if safe:
            need('private_body_excluded_before_open' not in row,'HOLD_DELEGATED_SAFE_BODY_EXCLUDED')
            if style=='image' or invocations and style=='local':
                need('body_members' not in row,'HOLD_DELEGATED_IMAGE_BODY_ASSOCIATION')
                name=row['body_frame'];need(re.fullmatch('streams/'+label+'/bodies-[0-9]{3}\\.json',name),
                     'HOLD_DELEGATED_FRAME_REFERENCE')
                if name not in used_frames:
                    frame=receipt(files[name]);need(set(frame)=={'schema','kind','streams'} and frame['schema']==4
                         and frame['kind']=='EXACT_PUBLIC_COMMAND_STREAMS_V4' and type(frame['streams']) is list
                         and frame['streams'],'HOLD_DELEGATED_FRAME_SCHEMA')
                    used_frames[name]=[frame['streams'],set()]
                matches=[value for value in used_frames[name][0] if value['step']==step]
                need(len(matches)==1 and step not in used_frames[name][1],'HOLD_DELEGATED_FRAME_STEP')
                channels=('stdout','stderr') if style=='image' else ('combined',)
                frame=matches[0];need(set(frame)=={'step',*channels},'HOLD_DELEGATED_FRAME_CHANNELS')
                decoded=[]
                for channel in channels:
                    part=frame[channel];need(set(part)=={'pin','base64'} and type(part['base64']) is str
                         and len(part['base64'])<=1400000,'HOLD_DELEGATED_FRAME_BASE64_BOUND')
                    raw=base64.b64decode(part['base64'],validate=True)
                    need(len(raw)<=1024**2 and base64.b64encode(raw).decode()==part['base64']
                         and pin(raw)==whole(part['pin']),'HOLD_DELEGATED_FRAME_BODY_PIN')
                    delegated_public_body(raw);decoded.append(raw)
                stdout=decoded[0];stderr=decoded[1] if style=='image' else None;used_frames[name][1].add(step)
            else:
                need('body_frame' not in row,'HOLD_DELEGATED_ORDINARY_BODY_ASSOCIATION')
                name=step+'.stdout' if style=='owner' else '%03d-%s.log'%(i,step)
                if timed:
                    association={'stdout':'streams/'+label+'/'+name,'stderr':'streams/'+label+'/'+step+'.stderr'} if style=='owner' else {'combined':'streams/'+label+'/'+name}
                    need(row['body_members']==association,'HOLD_DELEGATED_BODY_MEMBER_ASSOCIATION')
                stdout=files['streams/'+label+'/'+name]
                if style=='owner':stderr=files['streams/'+label+'/'+step+'.stderr']
            need(pin(stdout)==whole(row['output_pin']),'HOLD_DELEGATED_STDOUT_PIN')
            if style in ('owner','image'):
                need('stderr_pin' in row and pin(stderr)==whole(row['stderr_pin']),'HOLD_DELEGATED_STDERR_PIN')
            else:need('stderr_pin' not in row,'HOLD_DELEGATED_LOCAL_CHANNEL_CONTRACT')
        else:
            need(row.get('private_body_excluded_before_open') is True and 'body_frame' not in row and 'body_members' not in row,
                 'HOLD_DELEGATED_PRIVATE_LAUNCH_BODY')
        result[step]=(i,row,stdout,stderr)
    if style=='image' or invocations and style=='local':
        present={name for name in files if re.fullmatch('streams/'+label+'/bodies-[0-9]{3}\\.json',name)}
        need(present==set(used_frames) and present=={'streams/'+label+'/bodies-%03d.json'%i for i in range(len(present))},
             'HOLD_DELEGATED_FRAME_MEMBERSHIP')
        for values,seen in used_frames.values():
            need(len(values)==len(seen) and {value['step'] for value in values}==seen,'HOLD_DELEGATED_FRAME_ORPHAN')
    present={name for name in files if re.fullmatch('streams/'+label+'/invocations-[0-9]{3}\\.json',name)}
    need(present==set(used_invocations) and present=={'streams/'+label+'/invocations-%03d.json'%i for i in range(len(present))},
         'HOLD_DELEGATED_INVOCATION_FRAME_MEMBERSHIP')
    for values,seen in used_invocations.values():
        need(len(values)==len(seen) and {value['step'] for value in values}==seen,'HOLD_DELEGATED_INVOCATION_FRAME_ORPHAN')
    return result


def delegated_payload(capsule,expected):
    """Recompute bounded public transport; this result carries no qualification."""
    files,manifest=delegated_capsule_files(capsule,expected)
    labels={'image','stage'}|({'administrative','outer'} if expected['stage']=='lifecycle' else set())
    need({name.split('/')[1] for name in files if name.endswith('/commands.public.json')}==labels,
         'HOLD_DELEGATED_STREAM_LABEL_SET')
    selector=whole(expected['source']['retention']);timed=selector in TIMED_RETENTION_VERSIONS
    if timed:need(type(expected.get('index_pins')) is dict and set(expected['index_pins'])==labels,'HOLD_DELEGATED_INDEX_SELECTION_SET')
    commands={label:delegated_index(files,label,expected['stage'],selector in ADOPTION_RETENTION_VERSIONS,timed,
        expected['index_pins'][label] if timed else None,expected['image_report_pin'],selector in INVOCATION_RETENTION_VERSIONS) for label in labels}
    return files,manifest,commands


BASE_METADATA_PINS={
    'base_lock':dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),
    'bootstrap_profile':dict(bytes=168201,sha256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c'),
    'baseline_inventory':dict(bytes=6800,sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')}
BASE_FACTORY_PIN=dict(bytes=62259,sha256='ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa')
BASE_SUPPLEMENTS={'cmake','cppdap','jsoncpp','libuv','meson','ninja','python-tqdm','rhash'}


def base_operand_pin(value):
    """Opaque original operands can exceed capsule caps; no operand is opened."""
    need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int
         and 0<=value['bytes']<=2*1024**3 and type(value['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}',value['sha256']),'HOLD_BASE_OPERAND_PIN')
    return value


def pinned_base_metadata(raw,wanted):
    """Exact public package/sysconfig metadata; names are not credential fields."""
    need(wanted in (*BASE_METADATA_PINS.values(),BASE_FACTORY_PIN) and type(raw) is bytes and pin(raw)==wanted,
         'HOLD_BASE_EXACT_PUBLIC_METADATA')
    value=decode(raw);need(type(value) is dict,'HOLD_BASE_METADATA_OBJECT');encoded(value)
    return value


def delegated_base_provenance(files,expected,source_files,inputs,support):
    """Join original341/fixed8 metadata; never infer archive presence or trust."""
    name='image/base-inputs.public.json';public=receipt(files[name]);image_inputs=inputs['image_inputs']
    need(set(public)=={'base_lock','bootstrap_profile','baseline_inventory','factory_profile_pin',
         'original_package_count','supplemental_package_count','final_package_count','materials'},'HOLD_BASE_PROVENANCE_FIELDS')
    need(type(expected.get('origin_pins')) is dict and name in expected['origin_pins']
         and set(expected['origin_pins'][name])=={'original','projection'}
         and pin(files[name])==whole(expected['origin_pins'][name]['projection']),'HOLD_BASE_PUBLIC_PROJECTION_SELECTION')
    for key,value in (('original_package_count',341),('supplemental_package_count',8),('final_package_count',349)):
        need(type(public[key]) is int and public[key]==value,'HOLD_BASE_EXACT_PACKAGE_COUNTS')
    def ref(value):
        need(type(value) is dict and set(value)=={'path','bytes','sha256'} and type(value['path']) is str
             and 0<len(value['path'])<=4096 and Path(value['path']).is_absolute()
             and str(Path(value['path']))==value['path'] and '..' not in Path(value['path']).parts
             and not any(ord(char)<32 or ord(char)==127 for char in value['path']),
             'HOLD_BASE_ORIGINAL_REFERENCE_LABEL')
        return base_operand_pin({key:value[key] for key in ('bytes','sha256')})
    for role,wanted in BASE_METADATA_PINS.items():
        need(type(support.get(role)) is bytes and pin(support[role])==wanted
             and whole(expected['support_pins'][role])==wanted and public[role]==wanted
             and ref(image_inputs[role])==wanted,'HOLD_BASE_ORIGINAL_METADATA_BODY:'+role)
    factory_name='scripts/ci/first-login-enrollment-native-source/profile.json'
    factory_raw=source_files[factory_name]
    need(pin(factory_raw)==public['factory_profile_pin']==BASE_FACTORY_PIN,'HOLD_BASE_SOURCE_FACTORY_PROFILE')
    factory=pinned_base_metadata(factory_raw,BASE_FACTORY_PIN)
    for role,member in (('base_lock','bootstrap/scripts/ci/inputs.lock.json'),('bootstrap_profile','native/input-profile.json'),
                        ('baseline_inventory','native/expected349.lock')):
        need(factory['parent_files'][member]==dict(**BASE_METADATA_PINS[role],mode=0o644),
             'HOLD_BASE_FACTORY_PARENT_DESCRIPTOR')
    need(source_files['inputs/stages/baseline349.expected.lock']==support['baseline_inventory'],
         'HOLD_BASE_SOURCE_BASELINE_BODY')
    lock=pinned_base_metadata(support['base_lock'],BASE_METADATA_PINS['base_lock'])
    profile=pinned_base_metadata(support['bootstrap_profile'],BASE_METADATA_PINS['bootstrap_profile'])
    baseline=inventory(support['baseline_inventory'])
    need(len(lock['rootfs_packages'])==165 and len(lock['packages'])==248 and len(baseline)==349,
         'HOLD_BASE_COMPLETE_ORIGINAL_COUNTS')
    original={}
    for row in lock['rootfs_packages']:
        need(all(type(row[key]) is list and len(row[key])==1 for key in ('name','version','arch'))
             and row['arch'][0] in ('any','aarch64') and row['name'][0] not in original,'HOLD_BASE_ROOTFS_IDENTITIES')
        original[row['name'][0]]=row['version'][0]
    need(len({row['name'] for row in lock['packages']})==248,'HOLD_BASE_UNIQUE_ORIGINAL_ARCHIVES')
    for row in lock['packages']:
        need(row['arch'] in ('any','aarch64'),'HOLD_BASE_ORIGINAL_ARCHITECTURE');original[row['name']]=row['version']
    need(len(original)==341 and profile['original341']['package_count']==341 and profile['original341']['packages']==original,
         'HOLD_BASE_ORIGINAL341_VERSION_VECTOR')
    extra=profile['additions'];supplements=extra['rows']
    need(type(supplements) is list and len(supplements)==8 and {row['name'] for row in supplements}==BASE_SUPPLEMENTS
         and type(extra['count']) is int and extra['count']==8 and extra['expected_augmented_package_count']==349
         and extra['unresolved']==[],'HOLD_BASE_FIXED8_CLOSURE')
    augmented=dict(original)
    for row in supplements:
        need(row['name'] not in augmented and row['arch'] in ('any','aarch64'),'HOLD_BASE_DISJOINT_SUPPLEMENT')
        augmented[row['name']]=row['version']
    need(augmented==baseline,'HOLD_BASE_AUGMENTED349_VERSION_VECTOR')
    projected=[];original_rows=[];filenames=set();paths=set()
    for group,rows in (('base_materials',[lock['rootfs'],*lock['packages']]),('supplemental_materials',supplements)):
        material=image_inputs[group];wanted={row['filename']+suffix for row in rows for suffix in ('','.sig')}
        need(type(material) is dict and set(material)==wanted and len(wanted)==(498 if group=='base_materials' else 16),
             'HOLD_BASE_EXACT_OPERAND_ROSTER')
        for row in rows:
            filename=row['filename'];need(type(filename) is str and re.fullmatch('[A-Za-z0-9._+@:-]+',filename)
                 and filename not in filenames,'HOLD_BASE_UNIQUE_MATERIAL_FILENAME');filenames.add(filename)
            archive,signature=material[filename],material[filename+'.sig']
            need(ref(archive)==dict(bytes=row['size'],sha256=row['sha256'])
                 and ref(signature)==dict(bytes=row['signature_size'],sha256=row['signature_sha256']),
                 'HOLD_BASE_ARCHIVE_SIGNATURE_METADATA_JOIN')
            for operand in (archive,signature):
                need(operand['path'] not in paths,'HOLD_BASE_DISTINCT_ORIGINAL_OPERANDS');paths.add(operand['path'])
            identity={key:row.get(key) for key in ('name','version','arch')}
            metadata_pin=pin(encoded(row));common=dict(**identity,filename=filename,source_group=group,metadata_pin=metadata_pin)
            projected.append(dict(**common,archive=ref(archive),signature=ref(signature)))
            original_rows.append(dict(**common,archive=archive,signature=signature))
    need(len(projected)==257 and len(paths)==514,'HOLD_BASE_ALL_ORIGINAL_OPERANDS')
    common=dict(factory_profile_pin=BASE_FACTORY_PIN,original_package_count=341,supplemental_package_count=8,final_package_count=349)
    calculated=dict(**common,**BASE_METADATA_PINS,materials=projected)
    need(public==calculated and files[name]==encoded(calculated),'HOLD_BASE_RECOMPUTED_PUBLIC_PROVENANCE')
    # References below are already externally supplied DATA labels, never paths
    # followed by this Reader or restored into its sanitized public namespace.
    original=dict(**common,**{role:image_inputs[role] for role in BASE_METADATA_PINS},materials=original_rows)
    need(pin(encoded(original))==whole(expected['origin_pins'][name]['original']),
         'HOLD_BASE_ORIGINAL_PROVENANCE_SELECTION')
    return dict(original_packages=341,supplemental_packages=8,baseline_packages=baseline,materials=projected,
        material_count=257,operand_count=514,signer_fingerprint=lock['signer_fingerprint'],
        archive_bodies_replayed=False,signature_math_replayed=False)


def delegated_context(d_raw,c_raw,expected,source,event_epoch):
    """Replay original provider/context bytes; never open the historical workspace."""
    d,c=receipt(d_raw),receipt(c_raw);version=d['schema']
    need(type(version) is int and version in (3,4) and d_raw==encoded(d) and c_raw==encoded(c),
         'HOLD_DELEGATED_CONTEXT_VERSION')
    need(d['kind']=='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V'+str(version)
         and d['issuer']=='Root' and d['approved'] is True and d['scope']=='CURRENT_PRIVATE_STAGE_ONLY',
         'HOLD_DELEGATED_CONTEXT_AUTHORITY_SELECTION')
    delegated_final(d);delegated_final(c)
    b=d['binding'];binding=expected['binding'];nonce=expected['nonce'];stage=expected['stage']
    need(set(b)=={'source','ref','run','job','attempt','source_lock'} and b['run'] is b['job'] is None
         and type(b['attempt']) is int and b['attempt']==1
         and all(b[key]==binding[key] for key in ('source','ref','attempt','source_lock'))
         and d['stage']==stage and d['nonce']==nonce and re.fullmatch('[0-9a-f]{64}',nonce)
         and d['image_ids']==dict(backend=None,ui=None,lifecycle=None),'HOLD_DELEGATED_PREDISPATCH_IDENTITIES')
    need(all(type(d[key]) is int for key in ('issued_epoch','expires_epoch'))
         and 0<=d['issued_epoch']<=event_epoch<=d['expires_epoch'],'HOLD_DELEGATED_USE_WINDOW')
    limits=d['context_limits'];policy=receipt(source[d['policy']['member']])
    need(limits==policy['context'] and set(limits)=={'metadata_query_seconds','metadata_max_bytes',
         'max_context_age_seconds','max_delegation_seconds'} and all(type(value) is int and value>0 for value in limits.values())
         and limits['metadata_query_seconds']<=30 and limits['metadata_max_bytes']<=1024**2
         and 0<d['expires_epoch']-d['issued_epoch']<=limits['max_delegation_seconds']
         and limits['max_context_age_seconds']<=limits['max_delegation_seconds'],'HOLD_DELEGATED_CONTEXT_LIMITS')
    cap=d['capability'];numeric=policy['stage_capabilities'][stage]
    need(cap['operation']==OP and cap['stage']==stage and cap['allow_provisional_context'] is True
         and cap['allow_provisional_image_checks'] is True and type(cap['allow_pair_adoption']) is bool
         and all(type(cap[key]) is int and 0<cap[key]<=value for key,value in numeric.items())
         and (cap['builder_cpus'],cap['builder_memory_bytes'],cap['builder_pids'])==(4,4*1024**3,512)
         and 2<=cap['max_command_seconds']<=min(180,cap['total_seconds']),
         'HOLD_DELEGATED_CAPABILITY_SCOPE')
    selected=cap.get('allow_selected_pair_adoption',False)
    need(type(selected) is bool and (not selected or version==4 and not cap['allow_pair_adoption']),
         'HOLD_DELEGATED_ADOPTION_SCOPE')
    material_selected=cap.get('allow_material_staging',False)
    need(type(material_selected) is bool,'HOLD_MATERIAL_STAGING_EXPLICIT_CAPABILITY')
    need(not material_selected,'HOLD_MATERIAL_STAGING_RUNTIME_QUALIFICATION_UNAVAILABLE')
    prerequisites=cap.get('allow_host_prerequisites',False)
    need(type(prerequisites) is bool,'HOLD_PREREQUISITE_EXPLICIT_CAPABILITY')
    if prerequisites:
        need(version==4 and set(PREREQUISITE_FILES)<=set(d['programs'])
             and whole(d['programs']['retention'])==BASE_RETENTION_PIN,
             'HOLD_PREREQUISITE_EXACT_SOURCE_VERSION')
        prerequisite_policy(source[d['policy']['member']])
    if selected:
        # The exact committed context currently supports backend producers only.
        selections=d.get('pair_selections',{'single':d.get('pair_selection')})
        need(('pair_selection' in d)!=('pair_selections' in d) and type(selections) is dict
             and 0<len(selections)<=8 and all(type(value) is dict for value in selections.values()),
             'HOLD_DELEGATED_SELECTED_PAIR_CONTRACT')
    else:need('pair_selection' not in d and 'pair_selections' not in d,'HOLD_DELEGATED_UNSELECTED_PAIR_CONTRACT')
    for group in ('programs','materials'):
        need(type(d[group]) is dict and 0<len(d[group])<=256,'HOLD_DELEGATED_DESCRIPTOR_ROLES')
        for role,row in d[group].items():
            need(type(role) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}',role)
                 and set(row)=={'member','bytes','sha256'},'HOLD_DELEGATED_SOURCE_DESCRIPTOR')
            relative(row['member']);need(pin(source[row['member']])==whole(row),'HOLD_DELEGATED_DESCRIPTOR_BODY')
    need(set(d['policy'])=={'member','bytes','sha256'} and pin(source[d['policy']['member']])==whole(d['policy']),
         'HOLD_DELEGATED_POLICY_DESCRIPTOR')
    program=d['programs']['context'];known={3:dict(bytes=21460,sha256='efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b'),
        4:dict(bytes=42498,sha256='7dc4af2ea5db1f36db62e9df0c00cd728edfa16114b7218a9ee494965f638566')}
    need(whole(program)==known[version],'HOLD_DELEGATED_CONTEXT_PROGRAM_PIN')
    h=d['hosted'];need(set(h)=={'repository','workflow_ref','workflow_sha','job_key','job_name','runner_environment','runner_os','runner_arch'}
         and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',h['repository'])
         and h['workflow_ref'].startswith(h['repository']+'/.github/workflows/')
         and re.fullmatch('[0-9a-f]{40}',h['workflow_sha']) and re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,99}',h['job_key'])
         and type(h['job_name']) is str and 0<len(h['job_name'])<=200
         and (h['runner_environment'],h['runner_os'],h['runner_arch'])==('github-hosted','Linux','ARM64'),
         'HOLD_DELEGATED_HOSTED_SELECTION')
    observed=c['observed_epoch'];need(type(observed) is int and d['issued_epoch']<=observed<=event_epoch
         and event_epoch-observed<=limits['max_context_age_seconds'],'HOLD_DELEGATED_CONTEXT_AGE')
    root=c['source_root'];need(type(root) is str and Path(root).is_absolute() and str(Path(root))==root
         and '..' not in Path(root).parts,'HOLD_DELEGATED_HISTORICAL_WORKSPACE')
    env=c['hosted'];want=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=h['repository'],GITHUB_SHA=b['source'],GITHUB_REF=b['ref'],
        GITHUB_RUN_ATTEMPT='1',GITHUB_JOB=h['job_key'],GITHUB_WORKFLOW_REF=h['workflow_ref'],GITHUB_WORKFLOW_SHA=h['workflow_sha'],
        GITHUB_WORKSPACE=root,RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='Linux',RUNNER_ARCH='ARM64')
    need(set(env)==set(want)|{'GITHUB_RUN_ID','RUNNER_NAME'} and all(env[key]==value for key,value in want.items())
         and type(env['GITHUB_RUN_ID']) is str and re.fullmatch('[1-9][0-9]{0,19}',env['GITHUB_RUN_ID'])
         and type(env['RUNNER_NAME']) is str and 0<len(env['RUNNER_NAME'])<=200 and '\n' not in env['RUNNER_NAME'],
         'HOLD_DELEGATED_HOSTED_OBSERVATION')
    response=c['jobs_response'];run=env['GITHUB_RUN_ID'];base='https://api.github.com/repos/'+h['repository']+'/actions/runs/'+run
    need(set(response)=={'url','status','body','received_epoch','elapsed_ms'} and response['url']==base+'/jobs?filter=latest&per_page=100'
         and type(response['status']) is int and response['status']==200 and type(response['body']) is str,
         'HOLD_DELEGATED_PROVIDER_RESPONSE')
    need(type(response['received_epoch']) is int and 0<=observed-response['received_epoch']<=limits['metadata_query_seconds']
         and type(response['elapsed_ms']) is int and 0<=response['elapsed_ms']<=1000*limits['metadata_query_seconds'],
         'HOLD_DELEGATED_PROVIDER_TIME')
    body=response['body'].encode();need(len(body)<=limits['metadata_max_bytes'],'HOLD_DELEGATED_PROVIDER_CAP')
    jobs=receipt(body);need(type(jobs['jobs']) is list and type(jobs['total_count']) is int
         and 1<=jobs['total_count']<=100 and len(jobs['jobs'])==jobs['total_count'],'HOLD_DELEGATED_PROVIDER_PAGE')
    matches=[row for row in jobs['jobs'] if type(row) is dict and row.get('name')==h['job_name'] and row.get('runner_name')==env['RUNNER_NAME']]
    need(len(matches)==1,'HOLD_DELEGATED_PROVIDER_JOB');row=matches[0]
    need(type(row['id']) is int and row['id']>0 and type(row['run_id']) is int and str(row['run_id'])==run
         and type(row['run_attempt']) is int and row['run_attempt']==1 and row['head_sha']==b['source']
         and row['status']=='in_progress' and row['conclusion'] is None and row['run_url']==base
         and row['url']=='https://api.github.com/repos/'+h['repository']+'/actions/jobs/'+str(row['id'])
         and row['html_url']=='https://github.com/'+h['repository']+'/actions/runs/'+run+'/job/'+str(row['id']),
         'HOLD_DELEGATED_ACTUAL_PROVIDER_TUPLE')
    actual=dict(source=b['source'],ref=b['ref'],run=run,job=str(row['id']),attempt=1,source_lock=b['source_lock'])
    replay=dict(schema=version,kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V'+str(version),issuer='DELEGATED_CONTEXT_PROGRAM_V'+str(version),
        operation=OP,stage=stage,nonce=nonce,delegation_pin=pin(d_raw),program_pin=whole(program),policy_pin=whole(d['policy']),
        source_root=root,binding=actual,hosted=env,jobs_response=response,jobs_response_pin=pin(body),observed_epoch=observed,**DELEGATED_FINAL)
    need(c==replay and actual==binding,'HOLD_DELEGATED_EXACT_CONTEXT_REPLAY')
    return d,c,policy


def prerequisite_scope(value,nonce,role):
    """Parse retained kernel/property DATA independently of the executor."""
    domain=value['domain'];props=value['properties'];group='/system.slice/cachy-current-'+role+'-'+nonce+'.scope'
    need(set(domain)=={'pid','starttime','cgroup','limits'} and type(domain['pid']) is int and domain['pid']>0
         and type(domain['starttime']) is int and domain['starttime']>0 and domain['cgroup']==group
         and same(domain['limits'],PREREQUISITE_POLICY['scope_limits'])
         and set(props)=={'RuntimeMaxUSec','ActiveEnterTimestampMonotonic','ControlGroup'}
         and props['ControlGroup']==group and type(props['ActiveEnterTimestampMonotonic']) is str
         and props['ActiveEnterTimestampMonotonic'].isdecimal()
         and int(props['ActiveEnterTimestampMonotonic'])>0,'HOLD_PREREQUISITE_ACTUAL_KERNEL_SCOPE')
    span=props['RuntimeMaxUSec'];need(type(span) is str and 0<len(span)<=100,'HOLD_PREREQUISITE_RUNTIME_PROPERTY')
    units={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000,'d':86400000000}
    parts=re.findall(r'([0-9]+)(min|us|ms|s|h|d)',span)
    need(span.isdecimal() or parts and ''.join(a+b for a,b in parts)==re.sub(r'\s+','',span),
         'HOLD_PREREQUISITE_RUNTIME_PROPERTY')
    runtime=int(span) if span.isdecimal() else sum(int(a)*units[b] for a,b in parts)
    need(runtime>0,'HOLD_PREREQUISITE_RUNTIME_PROPERTY')
    return int(props['ActiveEnterTimestampMonotonic'])/1000000,runtime/1000000


def prerequisite_tools(value):
    need(type(value) is dict and value['missing_or_invalid']==[] and set(value['tools'])==PREREQUISITE_TOOLS,
         'HOLD_PREREQUISITE_COMPLETE_TOOL_OBSERVATIONS')
    result={}
    for name,row in value['tools'].items():
        selected=row['selected'];need(type(selected) is dict and type(selected['path']) is str,
             'HOLD_PREREQUISITE_COMPLETE_TOOL_OBSERVATIONS')
        target=Path(selected['path']);aliases={name}|({'mke2fs'} if name=='mkfs.ext4' else set())
        need(selected['candidate'] in ('/usr/bin/'+name,'/usr/sbin/'+name) and str(target)==selected['path']
             and str(target.parent) in ('/usr/bin','/usr/sbin') and (target.name in aliases
                 or name=='python3' and re.fullmatch(r'python3\.[0-9]{1,2}',target.name))
             and type(selected['bytes']) is int and 0<selected['bytes']<=256*1024**2
             and type(selected['sha256']) is str and re.fullmatch('[0-9a-f]{64}',selected['sha256']),
             'HOLD_PREREQUISITE_COMPLETE_TOOL_OBSERVATIONS')
        result[name]={key:selected[key] for key in ('path','bytes','sha256')}
    return result


def delegated_prerequisites(files,expected,source,support,policy,d,c,runtime,q):
    """Replay public launch facts and separately selected Root observations.

    Missing APT output bodies are not reconstructed or claimed replayed. Root
    supplies their authentic supervision and the private launch/clock bridge.
    """
    selected=d['capability'].get('allow_host_prerequisites',False)
    need(type(selected) is bool,'HOLD_PREREQUISITE_EXPLICIT_CAPABILITY')
    if not selected:
        need(not PREREQUISITE_SUPPORT&set(support) and 'host_prerequisite_qualification_pin' not in runtime,
             'HOLD_PREREQUISITE_UNSELECTED_RUNTIME')
        return None
    need(PREREQUISITE_SUPPORT<=set(support),'HOLD_PREREQUISITE_ROOT_OBSERVATIONS')
    prerequisite_policy(source[expected['source']['policy']['path']])
    raw={role:support[role] for role in PREREQUISITE_SUPPORT};v={role:receipt(body) for role,body in raw.items()}
    root=v['prerequisite_qualification'];timing=v['prerequisite_timing'];report=v['prerequisite_report']
    launcher=v['prerequisite_launcher'];controller=v['prerequisite_controller'];nonce=expected['nonce']
    public={role:pin(body) for role,body in raw.items() if role!='prerequisite_qualification'}
    keys={'schema','kind','issuer','status','binding','nonce','delegation_pin','policy_pin','request_pin','launcher',
          'trusted_main_commit','launch_selection','public_pins','boot_pin','same_boot','clock','actual_limits','commands'}
    need(set(root)==keys and type(root['schema']) is int and root['schema']==4
         and root['kind']=='ROOT_QUALIFIED_HOST_PREREQUISITES_SHARED_7560_V4' and root['issuer']=='Root'
         and root['status']=='ROOT_REVIEWED_HOST_PREREQUISITES_SHARED_7560' and root['binding']==expected['binding']
         and root['nonce']==nonce and root['delegation_pin']==expected['delegation_pin']
         and root['policy_pin']==whole(expected['source']['policy']) and root['launcher']==d['programs']['hosted_launcher']
         and type(root['trusted_main_commit']) is str and re.fullmatch('[0-9a-f]{40}',root['trusted_main_commit'])
         and root['public_pins']==public and root['same_boot'] is True,
         'HOLD_PREREQUISITE_ROOT_SELECTION')
    need(0<whole(root['request_pin'])['bytes']<=HOSTED_LAUNCHER_LIMITS['request_bytes']
         and whole(root['boot_pin'])['bytes']==37
         and same(root['launch_selection'],dict(jobs_metadata=True,privileged_controller=True,
             launcher_limits=HOSTED_LAUNCHER_LIMITS,host_prerequisites=True,whole_timing=PREREQUISITE_TIMING))
         and runtime['host_prerequisite_qualification_pin']==pin(raw['prerequisite_qualification'])
         and q['host_prerequisite_qualification_pin']==pin(raw['prerequisite_qualification']),
         'HOLD_PREREQUISITE_ROOT_LAUNCH_AUTHORIZATION')
    need(set(timing)=={'schema','kind','request_pin','delegation_pin','binding','policy_pin','boot_pin',
         'started_monotonic','deadline_monotonic','expires_epoch','whole_budget_seconds',*DELEGATED_FINAL}
         and type(timing['schema']) is int and timing['schema']==3 and timing['kind']==PREREQUISITE_TIMING['kind']
         and type(timing['whole_budget_seconds']) is int and timing['whole_budget_seconds']==7560
         and timing['request_pin']==root['request_pin'] and timing['delegation_pin']==expected['delegation_pin']
         and timing['binding']==expected['binding'] and timing['policy_pin']==root['policy_pin']
         and timing['boot_pin']==root['boot_pin'] and timing['expires_epoch']==d['expires_epoch']
         and raw['prerequisite_timing']==encoded(timing),'HOLD_PREREQUISITE_SHARED_TIMING')
    delegated_final(timing)
    start,end=timing['started_monotonic'],timing['deadline_monotonic']
    need(all(type(x) in (int,float) and math.isfinite(x) for x in (start,end)) and 0<start<end<=start+7560,
         'HOLD_PREREQUISITE_SHARED_TIMING')
    order=('launch_started','preflight_finished','prerequisite_started','prerequisite_retired','controller_selected',
           'controller_started','stage_started','stage_finished','controller_retired','launch_finished')
    clock=root['clock'];need(set(clock)==set(order),'HOLD_PREREQUISITE_CLOCK_OBSERVATIONS')
    for point in clock.values():
        need(set(point)=={'monotonic','epoch'} and all(type(x) in (int,float) and math.isfinite(x) for x in point.values())
             and start<=point['monotonic']<end and d['issued_epoch']<=point['epoch']<d['expires_epoch'],
             'HOLD_PREREQUISITE_CLOCK_OBSERVATIONS')
    need(clock['launch_started']['monotonic']==start and all(
         clock[a]['monotonic']<=clock[b]['monotonic'] and clock[a]['epoch']<=clock[b]['epoch'] for a,b in zip(order,order[1:]))
         and all(abs((point['epoch']-clock['launch_started']['epoch'])-(point['monotonic']-start))<=1 for point in clock.values())
         and clock['preflight_finished']['monotonic']-start<=180
         and end<=clock['preflight_finished']['monotonic']+d['expires_epoch']-clock['preflight_finished']['epoch']+.1
         and end-clock['prerequisite_started']['monotonic']>=510
         and clock['prerequisite_retired']['monotonic']-clock['prerequisite_started']['monotonic']<=510
         and runtime['started_at']==clock['stage_started']['epoch'] and runtime['finished_at']==clock['stage_finished']['epoch'],
         'HOLD_PREREQUISITE_WHOLE_TIME_ORDER')
    initial_d,initial,_=delegated_context(files['delegation.json'],raw['prerequisite_initial_context'],expected,source,
        clock['preflight_finished']['epoch'])
    need(initial_d==d and initial['binding']==c['binding'] and initial['observed_epoch']<=clock['preflight_finished']['epoch']
         and clock['prerequisite_retired']['epoch']<c['observed_epoch']+1
         and c['observed_epoch']<=clock['controller_selected']['epoch']
         and c['observed_epoch']>=initial['observed_epoch'],'HOLD_PREREQUISITE_TWO_CONTEXT_OBSERVATIONS')
    need(controller['kind']=='CURRENT_HOSTED_CONTROLLER_OBSERVATION_V3' and controller['binding']==expected['binding']
         and controller['policy_pin']==root['policy_pin'],'HOLD_PREREQUISITE_CONTROLLER_BINDING')
    delegated_final(controller)
    entered,ceiling=prerequisite_scope(controller,nonce,'controller')
    chosen=clock['controller_selected'];left=min(end-chosen['monotonic'],d['expires_epoch']-chosen['epoch'])
    stage_ceiling=min(7200,ceiling-361)
    need(ceiling==math.floor(left)-15 and 361<ceiling<=7560
         and clock['controller_selected']['monotonic']<=entered<=clock['controller_started']['monotonic']
         and entered+ceiling<=end and clock['controller_retired']['monotonic']<=entered+ceiling
         and clock['controller_retired']['monotonic']-entered<=q['owned_domains']['seconds']['controller_seconds']
         and runtime['finished_at']-runtime['started_at']<=stage_ceiling
         and clock['stage_finished']['monotonic']-clock['stage_started']['monotonic']
             <=q['owned_domains']['seconds']['stage_seconds']
         and clock['stage_started']['monotonic']-clock['controller_started']['monotonic']
             <=q['owned_domains']['seconds']['setup_seconds']
         and clock['controller_retired']['monotonic']-clock['stage_finished']['monotonic']
             <=q['owned_domains']['seconds']['cleanup_seconds']
         and q['owned_domains']['seconds']['controller_seconds']<=ceiling
         and q['owned_domains']['seconds']['stage_seconds']<=stage_ceiling,
         'HOLD_PREREQUISITE_CLIPPED_MAIN_BUDGET')
    limits=root['actual_limits'];need(set(limits)=={'rlimits','capacity','output','seconds'},'HOLD_PREREQUISITE_ACTUAL_LIMITS')
    need(same(limits['rlimits'],dict(address_space_bytes=536870912,cpu_seconds=500,core_bytes=0))
         and set(limits['capacity'])=={'free_bytes','free_nodes'}
         and all(type(x) is int for x in limits['capacity'].values())
         and limits['capacity']['free_bytes']>=822083584 and limits['capacity']['free_nodes']>=4288
         and set(limits['output'])=={'bytes','nodes'}
         and all(type(x) is int and 0<=x<=PREREQUISITE_POLICY['output_'+key] for key,x in limits['output'].items())
         and set(limits['seconds'])=={'observation','work','cleanup'}
         and all(type(x) in (int,float) and math.isfinite(x) and 0<=x<=PREREQUISITE_POLICY[key+'_seconds']
             for key,x in limits['seconds'].items()) and sum(limits['seconds'].values())<=495,
         'HOLD_PREREQUISITE_ACTUAL_LIMITS')
    need(report['api']=='CURRENT_ONBOARDING_HOST_PREREQUISITES_V3'
         and report['kind']=='UBUNTU24_ARM64_LIBARCHIVE_TOOLS_CI_PREREQUISITE_V1'
         and report['status']=='PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY' and report['package']=='libarchive-tools'
         and report['binding']==expected['binding'] and report['delegation_pin']==expected['delegation_pin']
         and type(report['tool_count']) is int and report['tool_count']==16 and report['cache_absent'] is True
         and report['Root_acceptance'] is None,'HOLD_PREREQUISITE_PUBLIC_OUTCOME')
    delegated_final(report)
    entered,seconds=prerequisite_scope(report['scope_observation'],nonce,'prerequisites')
    need(seconds==495 and clock['prerequisite_started']['monotonic']<=entered
         <=clock['prerequisite_retired']['monotonic']<=entered+495 and entered+495<=end,
         'HOLD_PREREQUISITE_SCOPE_TIME')
    host=report['context'];env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',
        GITHUB_REPOSITORY=c['hosted']['GITHUB_REPOSITORY'],GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',
        GITHUB_RUN_ID=expected['binding']['run'],GITHUB_SHA=expected['binding']['source'],GITHUB_REF=expected['binding']['ref'],
        GITHUB_JOB=c['hosted']['GITHUB_JOB'])
    need(host['kind']=='CURRENT_ONBOARDING_PUBLIC_HOST_CONTEXT_V3' and host['machine'] in ('aarch64','arm64')
         and host['os_release']==dict(ID='ubuntu',VERSION_ID='24.04') and host['environment']==env
         and same(host['checks'],dict(root=True,machine=True,ubuntu24=True,public_identity=True))
         and host['reason_codes']==[] and host['Root_acceptance'] is None,'HOLD_PREREQUISITE_HOST_CONTEXT')
    delegated_final(host)
    tools=prerequisite_tools(report['tools_after']);before=report['tools_before']
    need(set(before['tools'])==PREREQUISITE_TOOLS and type(before['missing_or_invalid']) is list
         and set(before['missing_or_invalid'])<={'bsdtar'} and report['repository_key_trust_before']==report['repository_key_trust_after']
         and type(report['repository_key_trust_before']) is dict and report['repository_key_trust_before'],
         'HOLD_PREREQUISITE_TOOL_TRUST_PRESERVATION')
    trust=report['repository_key_trust_before'];total=0
    roots=('etc/apt/sources.list','etc/apt/sources.list.d','etc/apt/trusted.gpg','etc/apt/trusted.gpg.d',
           'etc/apt/keyrings','etc/apt/apt.conf','etc/apt/apt.conf.d','usr/share/keyrings')
    need(len(trust)<=1024 and any(name.startswith('etc/apt/sources.list') for name in trust)
         and any(name.startswith(('usr/share/keyrings/','etc/apt/keyrings/','etc/apt/trusted.gpg')) for name in trust),
         'HOLD_PREREQUISITE_TOOL_TRUST_PRESERVATION')
    for name,row in trust.items():
        relative(name);need(any(name==prefix or name.startswith(prefix+'/') for prefix in roots)
             and set(row)=={'bytes','sha256'} and whole(row)['bytes']<=2*1024**2,
             'HOLD_PREREQUISITE_TOOL_TRUST_PRESERVATION')
        total+=row['bytes']
    need(total<=16*1024**2,'HOLD_PREREQUISITE_TOOL_TRUST_PRESERVATION')
    for name,row in before['tools'].items():
        if name!='bsdtar':need(row['selected'] is not None and tools[name]=={key:row['selected'][key] for key in ('path','bytes','sha256')},
             'HOLD_PREREQUISITE_TOOL_TRUST_PRESERVATION')
    need(report['installed']==dict(package='libarchive-tools',state='install ok installed',version=report['selected_version'],architecture='arm64')
         and type(report['selected_version']) is str and re.fullmatch('[A-Za-z0-9.+:~_-]{1,160}',report['selected_version']),
         'HOLD_PREREQUISITE_INSTALLED_IDENTITY')
    rows=report['commands'];observations=root['commands'];caps=(15,15,120,15,30,90,120,15,15)
    need(type(rows) is list and len(rows)==9 and type(observations) is list and len(observations)==9
         and [row['name'] for row in rows]==['dpkg','dpkg-query','apt-get','apt-cache','apt-get','apt-get','apt-get','dpkg-query','bsdtar'],
         'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
    fixed=['-o','Acquire::Retries=0','-o','Acquire::http::Timeout=15','-o','Acquire::https::Timeout=15',
        '-o','APT::Update::Error-Mode=any','-o','Acquire::AllowInsecureRepositories=false',
        '-o','Acquire::AllowDowngradeToInsecureRepositories=false','-o','APT::Get::AllowUnauthenticated=false',
        '-o','APT::Get::allow-Downgrades=false','-o','APT::Get::allow-Change-Held-Packages=false',
        '-o','Acquire::Check-Valid-Until=true']
    cache='/var/lib/cachy-current-prerequisites-'+nonce+'/ci-prerequisite-cache'
    opts=['-o','Dir::State::lists='+cache+'/lists','-o','Dir::Cache::archives='+cache+'/archives',
        '-o','Dir::Cache::pkgcache='+cache+'/pkgcache.bin','-o','Dir::Cache::srcpkgcache='+cache+'/srcpkgcache.bin']
    query=['-W','--showformat='+'${binary:Package}\t${Status}\t${Version}\t${Architecture}\n','libarchive-tools']
    install=['--yes','--no-remove','--no-install-recommends','install','libarchive-tools='+report['selected_version']]
    args=[['--print-architecture'],query,[*fixed,*opts,'update'],[*opts,'policy','libarchive-tools'],
          [*fixed,*opts,'--simulate',*install],[*fixed,*opts,'--download-only',*install],
          [*fixed,*opts,'--no-download',*install],query,['--version']]
    for i,(row,actual,cap) in enumerate(zip(rows,observations,caps)):
        need(type(row['exit']) is int and row['exit'] in ((0,1) if i==1 else (0,)) and whole(row['output'])['bytes']<=1024**2
             and set(row)=={'name','argv','exit','output'} and row['argv']==[
                 tools['bsdtar']['path'] if row['name']=='bsdtar' else '/usr/bin/'+row['name'],*args[i]]
             and set(actual)=={'receipt_pin','output_pin','supervision'} and actual['receipt_pin']==pin(encoded(row))
             and actual['output_pin']==whole(row['output']),'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
        sup=dict(actual['supervision'])
        need(type(sup['exit']) is int and sup['exit']==row['exit'] and sup['passed'] is (row['exit']==0)
             and sup['reaped'] is True and sup['output_complete'] is True and sup['timeout'] is False,
             'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
        # The initial query may naturally observe an absent package (exit1).
        sup.update(exit=0,passed=True);natural(sup)
        need(sup['seconds']<=cap,'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
    need(sum(row['supervision']['seconds'] for row in observations)<=limits['seconds']['work'],
         'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
    need(report['dpkg_architecture']==dict(architecture='arm64',output=rows[0]['output'],reason_codes=[])
         and report['initial_package_query']==dict(exit=rows[1]['exit'],output=rows[1]['output'])
         and report['bsdtar_version_output']==rows[-1]['output'],'HOLD_PREREQUISITE_COMMAND_OBSERVATIONS')
    need(launcher['status']=='DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY' and launcher['binding']==expected['binding']
         and launcher['request_pin']==root['request_pin'] and same(launcher['cleanup'],dict(owned_storage_absent=True,error_count=0))
         and same(launcher['prerequisite_scope_absence'],dict(scope='cachy-current-prerequisites-'+nonce+'.scope',absent_twice=True))
         and same(launcher['scope_absence'],dict(scope='cachy-current-controller-'+nonce+'.scope',empty_twice=True))
         and prerequisite_tools(launcher['tools_after_prerequisites'])==tools,'HOLD_PREREQUISITE_LAUNCH_RETIREMENT')
    delegated_final(launcher)
    for role in ('metadata','metadata_after_prerequisites','prerequisite_retirement','controller_retirement'):
        row=launcher[role];need(type(row['exit']) is int and row['exit']==0 and row['reaped'] is True
             and row['group_census']=='EMPTY_TWICE' and row['natural'] is True,
             'HOLD_PREREQUISITE_LAUNCH_RETIREMENT')
        whole(row['stdout_pin']);whole(row['stderr_pin'])
    need(launcher['metadata']['stdout_pin']==initial['jobs_response_pin']
         and launcher['metadata_after_prerequisites']['stdout_pin']==c['jobs_response_pin'],
         'HOLD_PREREQUISITE_TWO_CONTEXT_OBSERVATIONS')
    shared=launcher['shared_timing']
    need(set(shared)=={'whole_budget_seconds','elapsed_seconds','controller_runtime_ceiling_seconds','available_stage_ceiling_seconds'}
         and type(shared['whole_budget_seconds']) is int and shared['whole_budget_seconds']==7560
         and all(type(shared[key]) is int for key in ('controller_runtime_ceiling_seconds','available_stage_ceiling_seconds'))
         and all(type(x) in (int,float) and math.isfinite(x) for x in shared.values())
         and clock['prerequisite_retired']['monotonic']-start<=shared['elapsed_seconds']<=chosen['monotonic']-start
         and ceiling<=shared['controller_runtime_ceiling_seconds']<=math.floor(end-start-shared['elapsed_seconds'])-15
         and stage_ceiling<=shared['available_stage_ceiling_seconds']<=min(7200,shared['controller_runtime_ceiling_seconds']-361),
         'HOLD_PREREQUISITE_LAUNCH_TIMING')
    return dict(whole_budget_seconds=7560,controller_ceiling_seconds=ceiling,stage_ceiling_seconds=stage_ceiling,
        APT_output_bodies_replayed=False,Root_authentication=False)


def delegated_root_inputs(files,expected,support,commands,policy,d,c):
    """Check separately pinned public Root inputs; no producer observation is upgraded."""
    stage=expected['stage'];binding=expected['binding'];nonce=expected['nonce'];times=expected['observed_at']
    runtime=receipt(support['runtime']);image=receipt(support['image_qualification']);q=receipt(support['domain_qualification'])
    image_view=receipt(files['image.public.json']);domain=receipt(files['domain.public.json'])
    inventory_raw=files['image/inventory.lock'];packages=inventory(inventory_raw)
    need(len(packages)==COUNTS[stage] and image_view['packages']==packages,'HOLD_DELEGATED_IMAGE_INVENTORY')
    need(runtime['schema']==3 and runtime['kind']=='CURRENT_PUBLIC_RUNTIME_QUALIFICATION_V3'
         and runtime['status']=='QUALIFIED_CURRENT_PUBLIC_RUNTIME' and runtime['qualified'] is True and runtime['provisional'] is False
         and runtime['operation']==OP and runtime['stage']==stage and runtime['binding']==binding and runtime['nonce']==nonce
         and runtime['source_lock']==binding['source_lock'] and runtime['program']==expected['source']['program']
         and runtime['policy']==expected['source']['policy'] and runtime['context_pin']==pin(files['context.json'])
         and runtime['domain_pin']==pin(files['domain.public.json']) and runtime['image']==image_view['image_id']
         and runtime['capability']==policy['stage_capabilities'][stage]
         and all(runtime[key]==value for key,value in times.items()),'HOLD_DELEGATED_ROOT_RUNTIME_QUALIFICATION')
    need(q['schema']==3 and q['kind']=='ROOT_QUALIFIED_PUBLIC_DOMAIN_V3' and q['issuer']=='Root'
         and q['status']=='ROOT_REVIEWED_CURRENT_PUBLIC_DOMAIN' and q['operation']==OP and q['stage']==stage
         and q['binding']==binding and q['image']==runtime['image'] and q['domain_pin']==pin(files['domain.public.json'])
         and q['runtime_pin']==pin(support['runtime']) and q['policy_pin']==whole(expected['source']['policy'])
         and q['observed_at']==times,'HOLD_DELEGATED_ROOT_DOMAIN_QUALIFICATION')
    domain_policy=owned_domain_policy(q,runtime,policy,expected)
    need(q['policy']==domain_policy,'HOLD_DELEGATED_OBSERVED_DOMAIN_POLICY')
    need(image['issuer']=='Root' and image['status']=='ROOT_REVIEWED_CURRENT_ONBOARDING_IMAGE_V2'
         and image['operation']==OP and image['stage']==stage and image['binding']==binding
         and image['image']==runtime['image'] and whole(image['inventory_pin'])==pin(inventory_raw)
         and image['runtime_pin']==pin(support['runtime']) and image['observed_architecture']=='aarch64'
         and image['owned_runner'] is True and image['image_build_policy_admitted'] is True
         and image['image_report_pin']==expected['image_report_pin'] and image['image_public_pin']==pin(files['image.public.json']),
         'HOLD_DELEGATED_INDEPENDENT_IMAGE_QUALIFICATION')
    need(domain['api']=='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3' and domain['binding']==binding
         and domain['stage']==stage and domain['nonce']==nonce and domain['native_architecture']=='aarch64'
         and domain['code_pin']==whole(d['programs']['image_executor']) and domain['domain_policy_pin']==whole(d['policy'])
         and domain['supervision_program_pin']==whole(d['programs']['owned_process'])
         and all(domain[key] is True for key in ('daemon_pidfd_held','whole_owner_deadline_enforced','daemon_deadline_enforced','exclusive_daemon')),
         'HOLD_DELEGATED_DOMAIN_OBSERVATIONS')
    delegated_final(domain)
    for role,selected in (('owner_domain',policy['image_domains']['owner']),('daemon_domain',policy['image_domains']['daemon'])):
        actual=domain[role]
        need(set(actual)=={'pid','starttime','cgroup','limits'} and type(actual['pid']) is int and actual['pid']>0
             and type(actual['starttime']) is int and actual['starttime']>0 and type(actual['cgroup']) is str
             and actual['cgroup'].startswith('/') and actual['limits']==selected,'HOLD_DELEGATED_OBSERVED_KERNEL_LIMITS')
    need(domain['storage']['kernel_enforced'] is True and domain['storage']['scope']=='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES'
         and type(domain['storage']['quota_bytes']) is int and domain['storage']['quota_bytes']==policy['image_storage_bytes']
         and type(domain['storage']['device']) is int and domain['storage']['device']>0,'HOLD_DELEGATED_OBSERVED_STORAGE')
    observation=receipt(support['command_observations'])
    need(observation['schema']==4 and observation['kind']=='ROOT_SELECTED_PUBLIC_COMMAND_OBSERVATIONS_V4'
         and observation['issuer']=='Root' and observation['operation']==OP and observation['binding']==binding
         and observation['stage']==stage and observation['nonce']==nonce,'HOLD_DELEGATED_COMMAND_OBSERVATIONS')
    wanted={label+'/'+step:(row,stdout,stderr) for label,index in commands.items() for step,(_,row,stdout,stderr) in index.items()}
    need(set(observation['commands'])==set(wanted),'HOLD_DELEGATED_COMPLETE_COMMAND_OBSERVATIONS')
    totals={label:0 for label in commands}
    need(all(len(rows)<=d['capability']['command_rows'] for rows in commands.values()),'HOLD_DELEGATED_ACTUAL_COMMAND_ROW_BUDGET')
    for name,(row,_,_) in wanted.items():
        actual=observation['commands'][name];label,step=name.split('/',1)
        local_proof=row.get('local_invocation_v1')
        selected_fields={'original_receipt_pin','passed','seconds','supervision'}|({'held_receipt_pin','supervision_result_pin'} if local_proof is not None else set())
        need(set(actual)==selected_fields
             and actual['original_receipt_pin']==whole(row['original_receipt_pin'])
             and actual['passed'] is (row['expected']==0)
             and type(actual['seconds']) in (int,float) and math.isfinite(actual['seconds']) and actual['seconds']>=0
             and actual['supervision']==row['supervision'],'HOLD_DELEGATED_ACTUAL_COMMAND_COMPLETION')
        if local_proof is not None:
            need(actual['held_receipt_pin']==whole(local_proof['held_receipt_pin'])
                 and actual['supervision_result_pin']==whole(local_proof['supervision_result_pin']),
                 'HOLD_DELEGATED_AUTHENTIC_ORIGINAL_LOCAL_RESULT')
        limit=d['capability']['max_command_seconds'] if label=='image' else policy['frozen_stage_limits']['build_seconds']
        if label=='image' and step.startswith('verify-'):limit=policy['image_steps']['verification_seconds']
        need(actual['seconds']<=limit,'HOLD_DELEGATED_SCOPED_COMMAND_BUDGET');totals[label]+=actual['seconds']
        if whole(expected['source']['retention']) in TIMED_RETENTION_VERSIONS:
            need(row['supervision']['seconds']==actual['seconds'] and row['supervision']['passed'] is actual['passed']
                 and row['timeout_seconds']<=limit,'HOLD_DELEGATED_ORIGINAL_BOUND_QUALIFICATION_JOIN')
    need(all(total<=(d['capability']['total_seconds'] if label=='image' else policy['frozen_stage_limits']['admission_total_seconds'])
         for label,total in totals.items()),'HOLD_DELEGATED_SCOPED_TOTAL_BUDGET')
    verify={step:row for step,row in commands['image'].items() if step.startswith('verify-')}
    need(verify and set(image['verification_fingerprints'])==set(verify),'HOLD_DELEGATED_IMAGE_TEST_OBSERVATIONS')
    for step,(_,_,stdout,stderr) in verify.items():
        current_signature(stdout+stderr,image['verification_fingerprints'][step],times['finished_at'])
    for key,body in q['containers'].items():
        need(re.fullmatch('[0-9a-f]{64}',key) and body['created']['cid']==key
             and body['created']['image']==runtime['image'] and body['created']['policy']==domain_policy
             and body['terminal']==dict(cid=key,Running=False,ExitCode=0,OOMKilled=False)
             and body['retirement']==dict(cid=key,status='REMOVED_AND_ABSENT',absence_verified=True),
             'HOLD_DELEGATED_QUALIFIED_CID_RETIREMENT')
        natural(body['supervision'])
    return packages,runtime,q


def delegated_test_proof(files,expected,*,label,archive,signature,decision_name,verification_name,recipe,at):
    selected=expected['test_pins'][label];decision_raw=files[decision_name];proof_raw=files[verification_name]
    need(set(selected)=={'decision','verification'} and pin(decision_raw)==whole(selected['decision'])
         and pin(proof_raw)==whole(selected['verification']),'HOLD_DELEGATED_ROOT_TEST_SELECTION')
    decision=receipt(decision_raw);proof=receipt(proof_raw)
    key=dict(**SELECTED_TEST_KEY_PIN,fingerprint=SELECTED_TEST_FINGERPRINT,trust_scope='TEST_ONLY')
    need(pin(files['setup8/public-key.asc'])==SELECTED_TEST_KEY_PIN and decision['schema']==1 and decision['issuer']=='Root'
         and decision['accepted'] is True and decision['holds_preserved'] is True and decision['trust_scope']=='TEST_ONLY'
         and decision['status']==('ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' if label=='setup8' else 'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY')
         and decision['archive']==dict(**pin(archive),package=recipe['name'],version=recipe['version'],arch='any')
         and decision['signature']==pin(signature) and decision['public_test_key']==key
         and decision['verification_proof_sha256']==pin(proof_raw)['sha256'],'HOLD_DELEGATED_ROOT_TEST_DECISION')
    need(proof['schema']==1 and proof['Root_issuer']=='Root' and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE'
         and proof['verified'] is True and proof['trust_scope']=='TEST_ONLY' and proof['archive']==pin(archive)
         and proof['signature']==pin(signature) and proof['public_test_key']==key,'HOLD_DELEGATED_ROOT_TEST_VERIFICATION')
    def epoch(value):return datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    need(epoch(proof['actual_verified_utc'])<=epoch(decision['issued_at'])<=at,'HOLD_DELEGATED_TEST_PROOF_CHRONOLOGY')


def delegated_completion(raw,d,c,binding,finished):
    value=receipt(raw);need(value['schema']==1 and value['kind']=='CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4'
         and value['producer_binding']==binding and value['producer_delegation_pin']==pin(encoded(d))
         and value['producer_context_pin']==pin(encoded(c)),'HOLD_DELEGATED_COMPLETION_SELECTION')
    observed=value['observed_epoch'];response=value['jobs_response'];limits=d['context_limits']
    base='https://api.github.com/repos/'+d['hosted']['repository']+'/actions/runs/'+binding['run']
    need(type(observed) is int and finished<=observed and set(response)=={'url','status','body','received_epoch','elapsed_ms'}
         and response['url']==base+'/jobs?filter=latest&per_page=100' and type(response['status']) is int and response['status']==200
         and type(response['body']) is str and len(response['body'].encode())<=limits['metadata_max_bytes']
         and type(response['received_epoch']) is int and 0<=observed-response['received_epoch']<=limits['metadata_query_seconds']
         and type(response['elapsed_ms']) is int and 0<=response['elapsed_ms']<=1000*limits['metadata_query_seconds'],
         'HOLD_DELEGATED_COMPLETION_PROVIDER')
    jobs=receipt(response['body'].encode());need(type(jobs['jobs']) is list and type(jobs['total_count']) is int
         and 1<=jobs['total_count']<=100 and len(jobs['jobs'])==jobs['total_count'],'HOLD_DELEGATED_COMPLETION_PAGE')
    rows=[row for row in jobs['jobs'] if type(row) is dict and type(row.get('id')) is int and str(row['id'])==binding['job']]
    need(len(rows)==1,'HOLD_DELEGATED_COMPLETED_JOB');row=rows[0];repo=d['hosted']['repository']
    need(type(row['run_id']) is int and str(row['run_id'])==binding['run'] and type(row['run_attempt']) is int and row['run_attempt']==1
         and row['head_sha']==binding['source'] and row['name']==d['hosted']['job_name'] and row['runner_name']==c['hosted']['RUNNER_NAME']
         and row['status']=='completed' and row['conclusion']=='success' and row['run_url']==base
         and row['url']=='https://api.github.com/repos/'+repo+'/actions/jobs/'+binding['job']
         and row['html_url']=='https://github.com/'+repo+'/actions/runs/'+binding['run']+'/job/'+binding['job'],
         'HOLD_DELEGATED_COMPLETED_TUPLE')
    times=[]
    for key in ('started_at','completed_at'):
        need(type(row[key]) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',row[key]),'HOLD_DELEGATED_COMPLETION_UTC')
        times.append(datetime.datetime.fromisoformat(row[key].replace('Z','+00:00')).timestamp())
    need(times[0]<=c['observed_epoch']<=finished<=times[1]<=observed,'HOLD_DELEGATED_COMPLETION_CHRONOLOGY')
    return observed


def delegated_builds(files,commands,p,source,packages,image_id,epoch,expected,support,now):
    stage=expected['stage'];kinds=('ui',) if stage=='ui' else ('enrollment','first-login');route=receipt(files['route.public.json'])
    need(set(route['builds'])=={'pairs','artifacts'} and set(route['builds']['pairs'])==set(kinds)
         and set(route['builds']['artifacts'])==set(kinds),'HOLD_DELEGATED_BUILD_MEMBERSHIP')
    d=receipt(files['delegation.json']);c=receipt(files['context.json'])
    completed=delegated_completion(support['completion'],d,c,expected['binding'],expected['observed_at']['finished_at'])
    results={};clean=set()
    for kind in kinds:
        recipe=p['packages'][kind];archives=[];parsed=[];provenances=[]
        for label in ('a','b'):
            root='builds/'+kind+'-'+label;prov=receipt(files[root+'/provenance.public.json']);provenances.append(prov)
            need(prov['status']=='built-package-static-pass' and prov['mode']=='native' and prov['network']=='none'
                 and prov['image']==prov['image_id']==image_id and prov['builder_host_arch']=='aarch64'
                 and prov['source_date_epoch']==epoch and type(prov['exit_code']) is int and prov['exit_code']==0
                 and prov['expected_packages_sha256']==pin(files['image/inventory.lock'])['sha256'],
                 'HOLD_DELEGATED_BUILD_PROVENANCE')
            identity=prov['clean_environment_id'];need(identity not in clean and re.fullmatch('[A-Za-z0-9_.-]{1,200}',identity),
                 'HOLD_DELEGATED_DISTINCT_BUILD');clean.add(identity)
            need(prov['recipe_inputs']=={name:row['sha256'] for name,row in recipe['files'].items()}
                 and prov['entry_script_sha256']==pin(source['scripts/build/container-entry.sh'])['sha256'],
                 'HOLD_DELEGATED_SOURCE_BUILD_INPUTS')
            required=BUILD_FILES|{'build-log-components.json'}
            need(required<=set(prov['files'])<=required|{'artifacts/'+recipe['archive']},'HOLD_DELEGATED_PROVENANCE_MEMBERSHIP')
            for name,digest in prov['files'].items():relative(name);need(pin(files[root+'/'+name])['sha256']==digest,'HOLD_DELEGATED_PROVENANCE_FILE')
            for name,row in recipe['files'].items():
                need(pin(files[root+'/inputs/'+name])==whole(row) and files[root+'/inputs/'+name]==source[recipe['path']+'/'+name],
                     'HOLD_DELEGATED_RECIPE_BYTES')
            need(files[root+'/expected-packages.lock']==files[root+'/artifacts/packages.lock']==files['image/inventory.lock'],
                 'HOLD_DELEGATED_BUILD_INVENTORY')
            _,_,stdout,stderr=commands['stage']['build-'+kind+'-'+label+'-attach']
            need(stdout+stderr==files[root+'/build.log'] and receipt(files[root+'/build-log-components.json'])==
                 dict(stdout=pin(stdout),stderr=pin(stderr),composition='stdout followed by stderr; no cross-channel ordering claim'),
                 'HOLD_DELEGATED_BUILD_CHANNEL_COMPOSITION')
            check_log(files[root+'/build.log'],kind,p)
            validation=receipt(files[root+'/validation.json']);static=receipt(commands['stage']['validate-'+kind+'-'+label][2])
            raw=files[root+'/artifacts/'+recipe['archive']];sha=pin(raw)['sha256']
            need(validation['errors']==[] and len(validation['artifacts'])==1
                 and validation['artifacts'][0]['artifact']==recipe['archive'] and validation['artifacts'][0]['sha256']==sha
                 and validation['artifacts'][0]['errors']==[] and static['status']=='PASS_DELEGATED_BUILD_STATIC_VALIDATION'
                 and static['validation_pin']==pin(files[root+'/validation.json'])
                 and static['artifacts']==prov['artifacts']=={recipe['archive']:sha}
                 and route['builds']['artifacts'][kind][label]==pin(raw),'HOLD_DELEGATED_STATIC_ARCHIVE_JOIN')
            archives.append(raw);parsed.append(package(raw,recipe,packages,epoch))
        observed={recipe['archive']:dict(bytes_equal=archives[0]==archives[1],installed_contents_equal=parsed[0]['payload']==parsed[1]['payload'],
            pkginfo_equal=parsed[0]['metadata']['.PKGINFO']==parsed[1]['metadata']['.PKGINFO'],buildinfo_equal=parsed[0]['metadata']['.BUILDINFO']==parsed[1]['metadata']['.BUILDINFO'])}
        comparison=receipt(commands['stage']['current-'+kind+'-compare'][2])
        need(all(observed[recipe['archive']].values()) and comparison==route['builds']['pairs'][kind]
             and comparison['status']=='contents-reproduced' and comparison['errors']==[] and comparison['packages']==observed,
             'HOLD_DELEGATED_RECOMPUTED_PAIR')
        for key in ('image','image_id','mode','source_date_epoch','recipe_inputs','recipe_metadata','expected_packages_sha256','entry_script_sha256'):
            need(provenances[0][key]==provenances[1][key],'HOLD_DELEGATED_PAIR_INPUTS')
        pair_name=kind+'-pair.public.json';pair=receipt(files[pair_name]);delegated_final(pair)
        need(type(pair['schema']) is int and pair['schema']==c['schema']
             and pair['kind']=='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(c['schema'])
             and pair['issuer']=='DELEGATED_CURRENT_OWNER_V'+str(c['schema'])
             and pair['program_pin']==whole(d['programs']['owner']) and pair['policy_pin']==whole(d['policy'])
             and pair['binding']==expected['binding'] and pair['nonce']==expected['nonce']
             and pair['archives']==[pin(body) for body in archives] and pair['matching_pair'] is True
             and pair['package']==recipe['name'] and pair['version']==recipe['version'],
             'HOLD_DELEGATED_PAIR_PROJECTION')
        component=receipt(support['component_'+kind])
        need(component['schema']==4 and component['kind']=='ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4'
             and component['issuer']=='Root' and component['approved'] is True and component['operation']==OP
             and component['scope']=='CURRENT_PRIVATE_COMPONENT_ONLY' and component['producer_binding']==expected['binding']
             and component['producer_delegation_pin']==expected['delegation_pin'] and component['producer_context_pin']==expected['context_pin']
             and component['completion_pin']==pin(support['completion'])
             and component['pair_pin']==expected['origin_pins'][pair_name]['original']
             and component['component']==dict(name=recipe['name'],version=recipe['version'],architecture='any')
             and component['archives']==[pin(body) for body in archives] and component['Root_final_acceptance'] is None
             and component['hardware_acceptance'] is False and component['release_acceptance'] is False
             and type(component['issued_epoch']) is int and type(component['expires_epoch']) is int
             and completed<=component['issued_epoch']<=now<=component['expires_epoch']
             and 0<component['expires_epoch']-component['issued_epoch']<=d['context_limits']['max_delegation_seconds'],
             'HOLD_DELEGATED_INDEPENDENT_COMPONENT_DECISION')
        results[kind]=dict(archive=pin(archives[0]),payload_files=len(recipe['payload_files']))
    qualified=receipt(support['domain_qualification'])['containers']
    names={row['created']['name']:cid for cid,row in qualified.items()}
    need(clean<=set(names) and len(names)==len(qualified)==len(clean)+1,'HOLD_DELEGATED_BUILD_DOMAIN_IDENTITIES')
    return results


def delegated_products(files,expected,source,p,d,c,inputs,at):
    stage=expected['stage'];wanted=set() if stage=='backend' else {'first-login'} if stage=='ui' else set(KINDS)
    products=inputs['stage_inputs']['products'];need(set(products)==wanted,'HOLD_DELEGATED_PRODUCT_SET')
    selected=d['capability'].get('allow_selected_pair_adoption',False)
    canonical=whole(expected['source']['retention'])!=DELEGATED_RETENTION_PIN
    names=dict(delegation='producer_delegation' if canonical else 'producer_delegation_raw',pair='pair' if canonical else 'pair_raw',
        completion='completion' if canonical else 'completion_raw',component='root_component' if canonical else 'root_component_raw',
        test='root_test' if canonical else 'root_test_raw',decision='Root_decision' if canonical else 'Root_decision_raw',
        verification='Root_verification' if canonical else 'Root_verification_raw')
    results={}
    for kind in sorted(wanted):
        product=products[kind];base='products/'+kind+'/'
        def body(field):
            suffix=names.get(field,field);name=base+suffix+'.data'
            if field=='producer_context' and name not in files:name=base+suffix+'.json'
            return name,files[name]
        pd_raw=body('delegation')[1];pc_raw=body('producer_context')[1];pd=receipt(pd_raw);pc=receipt(pc_raw)
        producer_stage='ui' if kind=='ui' else 'backend';recipe=p['packages'][kind]
        vector=dict(expected,stage=producer_stage,binding=pc['binding'],nonce=pd['nonce'])
        producer_epoch=pc['observed_epoch'] if selected else at
        delegated_context(pd_raw,pc_raw,vector,source,producer_epoch)
        pair_raw=body('pair')[1];pair=receipt(pair_raw);archives=[files[base+'archives-'+str(i)+'.data'] for i in (0,1)]
        need(pd['stage']==producer_stage and pair['schema']==pc['schema']
             and pair['kind']=='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(pc['schema'])
             and pair['issuer']=='DELEGATED_CURRENT_OWNER_V'+str(pc['schema']) and pair['binding']==pc['binding']
             and pair['nonce']==pd['nonce'] and pair['program_pin']==whole(pd['programs']['owner'])
             and pair['policy_pin']==whole(pd['policy']) and pair['package']==recipe['name'] and pair['version']==recipe['version']
             and archives[0]==archives[1] and pair['archives']==[pin(raw) for raw in archives]
             and pair['matching_pair'] is True,'HOLD_DELEGATED_PRODUCT_PAIR')
        delegated_final(pair)
        if selected:
            need(d['schema']==4 and producer_stage=='backend','HOLD_SELECTED_UI_CONTEXT_PROGRAM_UNSUPPORTED')
            selection=d['pair_selections'][product['selection_role']] if 'pair_selections' in d else d['pair_selection']
            fields={'schema','kind','producer_binding','component','archives','signatures','test_fingerprint','max_producer_age_seconds',
                'producer_delegation_pin','producer_context_pin','completion_pin','pair_pin','root_component_decision_pin',
                'root_test_decision_pin','public_test_key_pin'}
            need(set(selection)==fields and selection['schema']==1 and selection['kind']=='ROOT_EXPLICIT_COMPLETED_COMPONENT_SELECTION_V4'
                 and selection['producer_binding']==pc['binding'] and selection['producer_delegation_pin']==pin(pd_raw)
                 and selection['producer_context_pin']==pin(pc_raw) and selection['pair_pin']==pin(pair_raw)
                 and selection['component']==dict(name=recipe['name'],version=recipe['version'],architecture='any')
                 and selection['archives']==pair['archives'] and selection['test_fingerprint']==SELECTED_TEST_FINGERPRINT
                 and selection['public_test_key_pin']==SELECTED_TEST_KEY_PIN and pc['binding']['run']!=c['binding']['run']
                 and all(pc['binding'][key]==c['binding'][key] for key in ('source','ref','attempt','source_lock')),
                 'HOLD_DELEGATED_EXPLICIT_COMPLETED_SELECTION')
            signatures=[files[base+'signatures-'+str(i)+'.data'] for i in (0,1)]
            need(selection['signatures']==[pin(raw) for raw in signatures],'HOLD_DELEGATED_SELECTED_SIGNATURE_BODIES')
            completed_raw=body('completion')[1]
            need(selection['completion_pin']==pin(completed_raw) and type(selection['max_producer_age_seconds']) is int
                 and 0<selection['max_producer_age_seconds']<=30*86400,'HOLD_DELEGATED_SELECTED_COMPLETION')
            completed=delegated_completion(completed_raw,pd,pc,pc['binding'],pc['observed_epoch'])
            need(completed<=d['issued_epoch'] and d['issued_epoch']-completed<=selection['max_producer_age_seconds'],
                 'HOLD_DELEGATED_SELECTED_PRODUCER_AGE')
            expected_test=expected['test_pins'][kind]
            for role,kind_name,pin_key in (('component','ROOT_SELECTED_CURRENT_ONBOARDING_COMPONENT_V4','root_component_decision_pin'),
                                            ('test','ROOT_SELECTED_CURRENT_ONBOARDING_TEST_V4','root_test_decision_pin')):
                raw=body(role)[1];decision=receipt(raw)
                need(pin(raw)==whole(expected_test[role])==selection[pin_key] and decision['schema']==4 and decision['kind']==kind_name
                     and decision['issuer']=='Root' and decision['approved'] is True and decision['operation']==OP
                     and decision['scope']=='CURRENT_PRIVATE_COMPONENT_ONLY' and all(decision[key]==selection[key] for key in
                         ('producer_binding','producer_delegation_pin','producer_context_pin','completion_pin','component','pair_pin','archives'))
                     and decision['Root_final_acceptance'] is None and decision['hardware_acceptance'] is False and decision['release_acceptance'] is False
                     and type(decision['issued_epoch']) is int and type(decision['expires_epoch']) is int
                     and completed<=decision['issued_epoch']<=d['issued_epoch']<=at<=decision['expires_epoch']
                     and 0<decision['expires_epoch']-decision['issued_epoch']<=d['context_limits']['max_delegation_seconds'],
                     'HOLD_DELEGATED_SELECTED_ROOT_DECISION')
                if role=='test':need(decision['signatures']==selection['signatures']
                     and decision['public_test_key_pin']==SELECTED_TEST_KEY_PIN and decision['test_fingerprint']==SELECTED_TEST_FINGERPRINT
                     and decision['trust_scope']=='TEST_ONLY','HOLD_DELEGATED_SELECTED_ROOT_TEST')
            adoption=dict(schema=4,kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4',issuer='DELEGATED_CONTEXT_PROGRAM_V4',
                binding=c['binding'],producer_binding=pc['binding'],component=selection['component'],nonce=d['nonce'],delegation_pin=pin(encoded(d)),
                selection_pin=pin(encoded(selection)),producer_delegation_pin=pin(pd_raw),producer_context_pin=pin(pc_raw),
                completion_pin=pin(completed_raw),pair_pin=pin(pair_raw),root_component_decision_pin=selection['root_component_decision_pin'],
                root_test_decision_pin=selection['root_test_decision_pin'],archives=selection['archives'],signatures=selection['signatures'],
                public_test_key_pin=SELECTED_TEST_KEY_PIN,test_fingerprint=SELECTED_TEST_FINGERPRINT,trust_scope='TEST_ONLY',
                current_stage_gpg_required=True,**DELEGATED_FINAL)
            if whole(expected['source']['retention']) in ADOPTION_RETENTION_VERSIONS:
                need(receipt(files[base+'adoption.json'])==adoption,'HOLD_DELEGATED_ACTUAL_SELECTED_ADOPTION')
        else:
            need(d['capability']['allow_pair_adoption'] is True and pin(pd_raw)==d['private_stage_producers'][producer_stage]
                 and all(pc['binding'][key]==c['binding'][key] for key in ('source','ref','run','attempt','source_lock')),
                 'HOLD_DELEGATED_SAME_RUN_PRODUCT')
            if producer_stage=='backend':need(pin(pd_raw)==d['pair_policy']['producer_delegation_pin'],'HOLD_DELEGATED_SAME_RUN_BACKEND_SELECTION')
            signatures=[files[base+'signature.data']]
            delegated_test_proof(files,expected,label=kind,archive=archives[0],signature=signatures[0],
                decision_name=body('decision')[0],verification_name=body('verification')[0],recipe=recipe,at=at)
        results[kind]=dict(archives=archives,signatures=signatures,pair=pair,producer_context=pc)
        if selected:results[kind]['adoption']=adoption
    need(set(expected['test_pins'])=={'setup8'}|wanted,'HOLD_DELEGATED_EXACT_ROOT_TEST_ROLES')
    return results


def delegated_lifecycle(files,commands,p,packages,products,expected,source,support,now,depth,q):
    route=receipt(files['route.public.json']);prior=expected['prior']
    need(type(prior) is dict and set(prior)=={'backend','ui'},'HOLD_DELEGATED_PRIOR_BINDINGS')
    prior_results={};prior_files={}
    for stage in ('backend','ui'):
        other=prior[stage];raw=files['prior/prior_'+stage+'.capsule']
        need(other['stage']==stage and other['capsule_pin']==pin(raw)
             and all(other['binding'][key]==products['ui' if stage=='ui' else 'first-login']['producer_context']['binding'][key]
                     for key in ('source','ref','run','job','attempt','source_lock'))
             and other['observed_at']['finished_at']<=expected['observed_at']['started_at'],'HOLD_DELEGATED_PRIOR_PRODUCT_TUPLE')
        prior_results.update(_delegated_check(raw,other,source,support,now,depth+1)['packages'])
        prior_files[stage]=delegated_capsule_files(raw,other)[0]
    steps=commands['stage'];order=list(steps);life=route['lifecycle']
    need(life['status']=='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY'
         and route['protected_before']==route['protected_after'] and set(route['protected_before'])==
             {'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'},
         'HOLD_DELEGATED_LIFECYCLE_PRESERVATION')
    def position(name):return steps[name][0]
    def output(name):return steps[name][2]
    inventory_steps=['current-baseline','current-dependency-inventory','current-install-inventory','current-after-remove-install',
        'current-reinstall-inventory','current-after-remove-reinstall','current-final-inventory']
    setup={p['setup8']['name']:p['setup8']['version']};project={recipe['name']:recipe['version'] for recipe in p['packages'].values()}
    states=[packages,packages|setup,packages|setup|project,packages|setup,packages|setup|project,packages|setup,packages]
    need([position(name) for name in inventory_steps]==sorted(position(name) for name in inventory_steps),
         'HOLD_DELEGATED_LIFECYCLE_ORDER')
    for name,state in zip(inventory_steps,states):
        need(output(name)==inventory_bytes(state),'HOLD_DELEGATED_LIFECYCLE_INVENTORY')
        if name!='current-baseline':need(life['inventories'][name]==pin(output(name)),'HOLD_DELEGATED_LIFECYCLE_INVENTORY_PIN')
    need(position('current-baseline')<position('current-install-setup8')<position('current-dependency-inventory'),
         'HOLD_DELEGATED_SETUP8_INSTALL_ORDER')
    for kind in ('setup8',*KINDS):
        recipe=p['setup8'] if kind=='setup8' else p['packages'][kind]
        archive=files['signed/'+kind+'.archive'];sig=files['signed/'+kind+'.signature']
        need(position('current-baseline')<position('current-signature-'+kind)<position('current-pkginfo-'+kind)
             <position('current-install-setup8'),'HOLD_DELEGATED_SIGNED_METADATA_ORDER')
        current_signature(output('current-signature-'+kind),SELECTED_TEST_FINGERPRINT,expected['observed_at']['finished_at'])
        info=metadata(output('current-pkginfo-'+kind));need(info.get('pkgname')==[recipe['name']]
             and info.get('pkgver')==[recipe['version']] and info.get('arch')==['any'],'HOLD_DELEGATED_SIGNED_PACKAGE_IDENTITY')
        if kind=='setup8':need(archive==files['setup8/archive.data'] and sig==files['setup8/signature.data'],'HOLD_DELEGATED_SETUP8_SIGNED_BODY')
        else:
            stage='ui' if kind=='ui' else 'backend';original=prior_files[stage]['builds/'+kind+'-a/artifacts/'+recipe['archive']]
            need(archive==original==products[kind]['archives'][0] and sig==products[kind]['signatures'][0]
                 and prior_results[kind]['archive']==pin(archive),'HOLD_DELEGATED_SIGNED_PRIOR_ARCHIVE')
            actual=package(archive,recipe,inventory(prior_files[stage]['image/inventory.lock']))
            need(output('current-pkginfo-'+kind)==actual['metadata']['.PKGINFO'],'HOLD_DELEGATED_ACTUAL_SIGNED_METADATA')
    def payload(kind,label,after,before,record):
        recipe=p['setup8'] if kind=='setup8' else p['packages'][kind]
        need(record==dict(verified=True,files=recipe['payload_files']) and position(after)<position(label+'-file-list')<position(before)
             and {name.lstrip('/') for name in output(label+'-file-list').decode().splitlines() if not name.endswith('/')}
                 ==set(recipe['payload_files']),'HOLD_DELEGATED_PAYLOAD_FILE_LIST')
        for i,(name,row) in enumerate(sorted(recipe['payload_files'].items())):
            owner,mode,digest=(label+'-'+field+'-'+str(i) for field in ('owner','stat','sha256'))
            need(all(position(after)<position(step)<position(before) for step in (owner,mode,digest))
                 and output(owner).decode().strip()==recipe['name']
                 and output(mode)==('0:0:%o:%d:1:regular file\n'%(row['mode'],row['bytes'])).encode()
                 and output(digest)==(row['sha256']+'  /'+name+'\n').encode(),'HOLD_DELEGATED_PAYLOAD_OWNER_STAT_HASH')
    payload('setup8','current-setup8','current-dependency-inventory','current-install',life['payloads']['setup8'])
    prior_absence=-1
    for cycle in ('install','reinstall'):
        need(prior_absence<position('current-'+cycle)<position('current-'+cycle+'-inventory')
             <position('current-remove-'+cycle)<position('current-after-remove-'+cycle),'HOLD_DELEGATED_INSTALL_REMOVE_ORDER')
        for kind in KINDS:
            payload(kind,'current-'+cycle+'-'+kind,'current-'+cycle+'-inventory','current-remove-'+cycle,life['payloads'][cycle][kind])
            need(position('current-'+cycle+'-inventory')<position('current-'+cycle+'-help-'+kind)<position('current-remove-'+cycle),
                 'HOLD_DELEGATED_HELP_ORDER')
        names=sorted({name for recipe in p['packages'].values() for name in recipe['payload_files']})
        for i in range(len(names)):
            for flag in ('-e','-L'):
                name='current-absent-'+cycle+'-'+str(i)+flag
                need(position(name)>position('current-after-remove-'+cycle) and output(name)==b'','HOLD_DELEGATED_REMOVED_PAYLOAD_ABSENCE')
                prior_absence=max(prior_absence,position(name))
    need(prior_absence<position('current-remove-setup8')<position('current-final-inventory'),'HOLD_DELEGATED_FINAL_REMOVAL_ORDER')
    for i in range(len(p['setup8']['payload_files'])):
        for flag in ('-e','-L'):
            name='current-absent-setup8-'+str(i)+flag
            need(position(name)>position('current-final-inventory') and output(name)==b'','HOLD_DELEGATED_SETUP8_ABSENCE')
    local=receipt(files['owner-local.public.json']);outer=receipt(files['outer-retirement.public.json'])
    need(local['operation']==OP and local['stage']=='lifecycle' and local['binding']==expected['binding']
         and local['body_success'] is True and local['protected_state_unchanged'] is True
         and outer['status']=='REMOVED_AND_ABSENT' and outer['cid'] in q['containers'],
         'HOLD_DELEGATED_LIFECYCLE_RETIREMENT')
    need(all(q['local_private_retirement'][name] is True for name in ('homes_retired','no_sockets','private_directory_absent')),
         'HOLD_DELEGATED_QUALIFIED_LOCAL_TRUST_RETIREMENT')
    reasons=q['installation_reasons']
    need(set(reasons)=={'before_explicit','after_explicit','before_dependencies','after_dependencies','baseline_inventory','restored_inventory'}
         and all(type(value) is str and len(value.encode())<=1024**2 for value in reasons.values())
         and reasons['before_explicit']==reasons['after_explicit'] and reasons['before_dependencies']==reasons['after_dependencies']
         and reasons['baseline_inventory']==reasons['restored_inventory']
         and reasons['baseline_inventory'].encode()==files['image/inventory.lock'],
         'HOLD_DELEGATED_INSTALLATION_REASON_RESTORATION')
    need(list(commands['outer'])==['private-lifecycle-'+suffix for suffix in ('fresh','create','created','attach','terminal')]+
         ['retire-5-'+suffix for suffix in ('query','inspect','remove','after-0','after-1')],
         'HOLD_DELEGATED_OUTER_COMMAND_ROLES')
    return {kind:dict(archive=pin(files['signed/'+kind+'.archive']),payload_files=len(p['packages'][kind]['payload_files'])) for kind in KINDS}


def _delegated_check(capsule,expected,source_files,support_files,now,depth=0):
    need(type(expected) is dict and type(expected.get('source')) is dict,'HOLD_DELEGATED_EXTERNAL_SELECTION')
    timed=whole(expected['source']['retention']) in TIMED_RETENTION_VERSIONS
    expected_keys=DELEGATED_EXPECTED_KEYS|({'index_pins'} if timed else set())
    need(depth<=1 and set(expected)==expected_keys and expected['schema']==4
         and expected['kind']=='ROOT_BOUND_DELEGATED_PUBLIC_READER_V4' and expected['stage'] in STAGES,
         'HOLD_DELEGATED_EXTERNAL_SELECTION')
    helper_inverse();need(pin(Path(__file__).read_bytes())==whole(expected['reader_pin']),'HOLD_DELEGATED_EXACT_READER')
    binding=expected['binding'];stage=expected['stage'];times=expected['observed_at']
    need(set(binding)=={'source','ref','run','job','attempt','source_lock'} and re.fullmatch('[0-9a-f]{40}',binding['source'])
         and re.fullmatch('refs/heads/[A-Za-z0-9._+/-]+',binding['ref']) and type(binding['attempt']) is int and binding['attempt']==1
         and all(type(binding[key]) is str and re.fullmatch('[1-9][0-9]{0,19}',binding[key]) for key in ('run','job'))
         and binding['source_lock']==whole(expected['source_lock_pin']),'HOLD_DELEGATED_ACTUAL_BINDING')
    need(set(times)=={'started_at','finished_at'} and all(type(value) in (int,float) and math.isfinite(value) for value in times.values())
         and 0<=times['started_at']<=times['finished_at']<=now,'HOLD_DELEGATED_EVENT_TIME')
    files,manifest,commands=delegated_payload(capsule,expected)
    prerequisites=receipt(files['delegation.json'])['capability'].get('allow_host_prerequisites',False)
    need(type(prerequisites) is bool,'HOLD_PREREQUISITE_EXPLICIT_CAPABILITY')
    kinds=() if stage=='lifecycle' else ('ui',) if stage=='ui' else ('enrollment','first-login')
    required={'inputs','runtime','domain_qualification','image_qualification','command_observations'}
    if whole(expected['source']['retention'])==BASE_RETENTION_PIN:required|=set(BASE_METADATA_PINS)
    if prerequisites:required|=PREREQUISITE_SUPPORT
    if kinds:required|={'completion',*('component_'+kind for kind in kinds)}
    need(type(expected['support_pins']) is dict and set(expected['support_pins'])==required
         and type(support_files) is dict,'HOLD_MISSING_DELEGATED_ROOT_QUALIFICATION')
    support=support_files.get(stage,support_files)
    need(type(support) is dict and set(support)==required,'HOLD_MISSING_DELEGATED_ROOT_QUALIFICATION')
    for role,row in expected['support_pins'].items():
        need(type(support[role]) is bytes and pin(support[role])==whole(row),'HOLD_DELEGATED_ROOT_QUALIFICATION_PIN:'+role)
        if whole(expected['source']['retention'])==BASE_RETENTION_PIN and role in ('base_lock','bootstrap_profile'):
            pinned_base_metadata(support[role],BASE_METADATA_PINS[role])
        else:delegated_public_body(support[role])
    # This internal Source predicate compares declarations only; it emits no old
    # admission/image/runtime object from the producer's provisional observations.
    policy=receipt(source_files[expected['source']['policy']['path']])
    source_expected=dict(expected,fingerprint=SELECTED_TEST_FINGERPRINT,resources=frozen_resources(policy))
    p,program,policy=source_data(source_expected,source_files,delegated=True)
    need(pin(source_files[expected['source']['profile']['path']])==dict(bytes=21679,
         sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171'),
         'HOLD_DELEGATED_FROZEN_PROFILE')
    d,c,_=delegated_context(files['delegation.json'],files['context.json'],expected,source_files,times['finished_at'])
    need(d['policy']==dict(member=expected['source']['policy']['path'],**whole(expected['source']['policy']))
         and d['programs']['retention']==dict(member=expected['source']['retention']['path'],**whole(expected['source']['retention']))
         and d['programs']['encoder']==dict(member=expected['source']['encoder']['path'],**whole(expected['source']['encoder'])),
         'HOLD_DELEGATED_SELECTED_SOURCE_ROLES')
    basis=manifest['selector_basis']
    need(whole(d['programs']['owner'])==basis['owner'] and whole(d['programs']['route'])==basis['route'],
         'HOLD_DELEGATED_ACTUAL_OWNER_BASIS')
    if whole(expected['source']['retention'])!=DELEGATED_RETENTION_PIN:
        need(program['delegation_programs']==d['programs'],'HOLD_DELEGATED_CANONICAL_PROGRAM_MAPPING')
    need(d['materials']==receipt(source_files['inputs/delegated-materials-v4.json'])['materials'],
         'HOLD_DELEGATED_CANONICAL_MATERIAL_MAPPING')
    validator=d['programs']['inputs_assembler'];tree=ast.parse(source_files[validator['member']])
    need(any(isinstance(node,ast.FunctionDef) and node.name=='validate_owner_inputs_v3' for node in tree.body),
         'HOLD_DELEGATED_INNER_INPUT_VALIDATOR_API')
    inputs=receipt(support['inputs']);stage_inputs=inputs['stage_inputs']
    need(stage_inputs['schema']==3 and stage_inputs['kind']=='DELEGATED_CURRENT_PRIVATE_INPUTS_V3'
         and type(stage_inputs['source_date_epoch']) is int and stage_inputs['source_date_epoch']>=0,
         'HOLD_DELEGATED_CANONICAL_OWNER_INPUTS')
    need(files['image/inventory.lock']==source_files[d['materials']['expected_'+stage]['member']],
         'HOLD_DELEGATED_SOURCE_SELECTED_IMAGE_INVENTORY')
    base_provenance=None
    if whole(expected['source']['retention'])==BASE_RETENTION_PIN:
        base_provenance=delegated_base_provenance(files,expected,source_files,inputs,support)
    packages,runtime,q=delegated_root_inputs(files,expected,support,commands,policy,d,c)
    prerequisite_facts=delegated_prerequisites(files,expected,source_files,support,policy,d,c,runtime,q)
    need(runtime['inputs_pin']==pin(support['inputs']),'HOLD_DELEGATED_QUALIFIED_INPUT_DECLARATION')
    if base_provenance is not None:
        name='image/base-inputs.public.json';qualification=receipt(support['image_qualification'])
        need(qualification['base_input_provenance_pin']==expected['origin_pins'][name]['original']
             and qualification['base_public_pin']==pin(files[name])
             and qualification['base_metadata_pins']==dict(BASE_METADATA_PINS,factory_profile=BASE_FACTORY_PIN),
             'HOLD_BASE_INDEPENDENT_IMAGE_QUALIFICATION')
        operands={'verify-%03d'%i:dict(archive=row['archive'],signature=row['signature'],metadata_pin=row['metadata_pin'])
                  for i,row in enumerate(base_provenance['materials'])}
        need(qualification['base_verification_operands']==operands
             and all(step in commands['image'] and qualification['verification_fingerprints'][step]==base_provenance['signer_fingerprint']
                     for step in operands),'HOLD_BASE_AUTHENTIC_VERIFICATION_OPERAND_JOIN')
    route=receipt(files['route.public.json']);image=receipt(files['image.public.json'])
    need(route['schema']==4 and route['kind']=='DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4' and route['issuer']=='DELEGATED_CURRENT_OWNER_V3'
         and route['operation']==OP
         and route['status']=='PROVISIONAL_CURRENT_'+stage.upper()+'_DATA_ONLY' and route['binding']==binding and route['nonce']==expected['nonce']
         and route['context_pin']==expected['context_pin'] and route['delegation_pin']==expected['delegation_pin']
         and route['image_pin']==expected['image_report_pin'],'HOLD_DELEGATED_ORIGINAL_ROUTE_IDENTITY')
    delegated_final(route);cleanup=route['owner_cleanup'];delegated_final(cleanup)
    need(cleanup['status']=='PASS_DELEGATED_CURRENT_STAGE_RETIREMENT' and cleanup['binding']==binding and cleanup['stage']==stage
         and cleanup['nonce']==expected['nonce'] and all(cleanup[key] is True for key in
             ('natural_retirement','owned_container_absence_verified','protected_state_unchanged')),'HOLD_DELEGATED_OWNER_CLEANUP')
    route_image=route['image']
    need(set(route_image)=={'id','packages','inventory_pin'} and route_image['id']==image['image_id']==runtime['image']
         and route_image['packages']==packages and whole(route_image['inventory_pin'])==pin(files['image/inventory.lock']),
         'HOLD_DELEGATED_ROUTE_IMAGE_JOIN')
    facts=route['owner_facts'];delegated_final(facts)
    need(facts['operation']==OP and facts['stage']==stage and facts['binding']==binding and facts['nonce']==expected['nonce']
         and facts['delegation_pin']==expected['delegation_pin'] and facts['context_pin']==expected['context_pin']
         and facts['context_program_pin']==whole(d['programs']['context']) and facts['context_issuer']==c['issuer']
         and facts['context_kind']==c['kind'] and facts['image']==runtime['image']
         and facts['architecture']=='aarch64' and type(facts['page_size']) is int
         and facts['page_size'] in (4096,16384),'HOLD_DELEGATED_OWNER_NATIVE_FACTS')
    need(image['status']=='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY' and image['operation']==OP and image['binding']==binding and image['stage']==stage
         and image['delegation_pin']==expected['delegation_pin'] and image['Root_final_acceptance'] is None
         and image['independent_image_qualification'] is None and image['cleanup']['errors']==[]
         and image['protected_before']==image['protected_after'] and set(image['protected_before'])==
             {'/var/lib/pacman','/etc/pacman.conf','/etc/pacman.d/gnupg','/var/cache/pacman'}
         and all(image['private_retirement'][key] is True
             for key in ('homes_retired','no_sockets','private_directory_absent')),'HOLD_DELEGATED_PROVISIONAL_IMAGE_PRESERVATION')
    need(pin(files['setup8/public-key.asc'])==SELECTED_TEST_KEY_PIN and pin(files['setup8/archive.data'])==p['setup8']['archive_pin'],
         'HOLD_DELEGATED_ORIGINAL_SETUP8_MATERIAL')
    for field in ('archive','signature','decision','verification'):
        descriptor=d['materials'][stage_inputs['setup8'][field+'_role']]
        name='setup8/'+field+('.json' if field in ('decision','verification') else '.data')
        need(pin(files[name])==whole(descriptor) and files[name]==source_files[descriptor['member']],
             'HOLD_DELEGATED_SETUP8_SOURCE_BODY')
    delegated_test_proof(files,expected,label='setup8',archive=files['setup8/archive.data'],signature=files['setup8/signature.data'],
        decision_name='setup8/decision.json',verification_name='setup8/verification.json',recipe=p['setup8'],at=d['issued_epoch'])
    products=delegated_products(files,expected,source_files,p,d,c,inputs,times['finished_at'])
    if whole(expected['source']['retention']) in ADOPTION_RETENTION_VERSIONS:
        adoptions=image['selected_pair_adoptions_v4'];selected=d['capability'].get('allow_selected_pair_adoption',False)
        need(type(adoptions) is list and len(adoptions)==(1 if stage=='ui' and selected else 0),
             'HOLD_DELEGATED_IMAGE_ADOPTION_SET')
        if adoptions:
            record=adoptions[0];names=record['current_stage_gpg_steps']
            need(record['adoption']==products['first-login']['adoption'] and type(names) is list and len(names)==2
                 and re.fullmatch('verify-[0-9]+',names[0]) and names[1]=='verify-selected-'+names[0].split('-')[1]+'-1',
                 'HOLD_DELEGATED_IMAGE_ADOPTION_JOIN')
            for name in names:current_signature(commands['image'][name][2]+commands['image'][name][3],SELECTED_TEST_FINGERPRINT,times['finished_at'])
    if stage!='lifecycle':
        clean=receipt(files['owner-cleanup.public.json']);delegated_final(clean)
        need(clean['operation']==OP and clean['stage']==stage and clean['binding']==binding and clean['nonce']==expected['nonce']
             and clean['protected_before']==clean['protected_after'] and set(clean['protected_before'])==
                 {'/var/lib/pacman','/etc/pacman.conf','/etc/pacman.d/gnupg','/var/cache/pacman'},
             'HOLD_DELEGATED_BUILD_PROTECTED_STATE')
        need(all(q['stage_private_retirement'][key] is True for key in ('homes_retired','no_sockets','private_directory_absent')),
             'HOLD_DELEGATED_QUALIFIED_STAGE_TRUST_RETIREMENT')
        for i in (0,1):
            _,_,stdout,stderr=commands['stage']['private-no-agent-'+str(i)]
            need(stdout+stderr==b'gpg-connect-agent: no gpg-agent running in this session\n','HOLD_DELEGATED_STAGE_NO_AGENT_BODY')
        signature_roles={'setup8'}|({'first-login-selected-0','first-login-selected-1'} if d['capability'].get('allow_selected_pair_adoption')
            else {'first-login'}) if stage=='ui' else {'setup8'}
        for role in signature_roles:
            row=receipt(files['signatures/'+role+'.json']);raw=commands['stage']['private-signature-'+role][2]
            current_signature(raw,SELECTED_TEST_FINGERPRINT,times['finished_at'])
            need(row['status'].encode()==raw and row['fingerprint']==SELECTED_TEST_FINGERPRINT and row['trust_scope']=='TEST_ONLY',
                 'HOLD_DELEGATED_CURRENT_TEST_STATUS')
            archive=files['setup8/archive.data'] if role=='setup8' else products['first-login']['archives'][0]
            signature=files['setup8/signature.data'] if role=='setup8' else products['first-login']['signatures'][int(role[-1]) if '-selected-' in role else 0]
            need(row['archive']==pin(archive) and row['signature']==pin(signature),'HOLD_DELEGATED_CURRENT_TEST_INPUTS')
        retired=receipt(files['owner-retirement.public.json'])['rows']
        need(len(retired)==1+2*len(kinds) and len({row['cid'] for row in retired})==len(retired)
             and {row['cid'] for row in retired}==set(q['containers']) and all(row['status']=='REMOVED_AND_ABSENT'
                 and row['name']==q['containers'][row['cid']]['created']['name'] for row in retired),
             'HOLD_DELEGATED_ALL_ACTORS_RETIRED')
        result=delegated_builds(files,commands,p,source_files,packages,runtime['image'],stage_inputs['source_date_epoch'],expected,support,now)
        need(expected['prior'] is None,'HOLD_DELEGATED_BUILD_PRIOR_SCHEMA')
    else:
        refs=stage_inputs['retention'];need(set(refs)=={'prior_backend','prior_ui'},'HOLD_DELEGATED_PRIOR_REFERENCE_SET')
        for role,row in refs.items():need(pin(files['prior/'+role+'.capsule'])==whole(row),'HOLD_DELEGATED_PRIOR_ORIGINAL_REFERENCE')
        result=delegated_lifecycle(files,commands,p,packages,products,expected,source_files,support_files,now,depth,q)
    verdict=dict(status='PASS_DELEGATED_PUBLIC_CURRENT_STAGE_DATA_ONLY',stage=stage,binding=binding,packages=result,
        Root_authentication=False,Root_acceptance=None,component_acceptance=None,hardware_acceptance=None,release_acceptance=None,
        Root_final_acceptance=None,independent_component_acceptance=False,native16K='UNQUALIFIED',M2='NOT_RUN',performance='NOT_MEASURED')
    if base_provenance is not None:
        verdict['base_provenance']={key:base_provenance[key] for key in
            ('original_packages','supplemental_packages','material_count','operand_count','archive_bodies_replayed','signature_math_replayed')}
    if prerequisite_facts is not None:verdict['host_prerequisites']=prerequisite_facts
    return verdict


def read_delegated_stage(capsule,*,expected,source_files,support_files,now):
    """Distinct v4 replay; absent independent Root inputs and unknown schemas HOLD."""
    try:
        need(type(now) in (int,float) and math.isfinite(now),'HOLD_DELEGATED_READER_TIME')
        return _delegated_check(capsule,expected,source_files,support_files,now)
    except Exception as error:
        reason=str(error) if isinstance(error,ValueError) and str(error).startswith('HOLD_') else 'HOLD_MISSING_OR_MALFORMED_DELEGATED_EVIDENCE'
        if isinstance(error,ValueError) and 'Python3.14 stdlib zstd required' in str(error):reason='HOLD_ZSTD_DECODER_REQUIRES_PYTHON314'
        return dict(status='HOLD',stage=expected.get('stage') if isinstance(expected,dict) else None,reasons=[reason],
            Root_authentication=False,Root_acceptance=None,component_acceptance=None,hardware_acceptance=None,release_acceptance=None,
            Root_final_acceptance=None,independent_component_acceptance=False)
