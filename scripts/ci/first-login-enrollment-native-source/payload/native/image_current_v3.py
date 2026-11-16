# SPDX-License-Identifier: MIT
"""Root-delegated current image construction; no actor on import, no qualification.

Every command belongs to an explicitly selected, whole-pinned executor with an
actual bounded owner/daemon domain. This module never creates that authority.
"""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import time

OP='first-login-enrollment-ui-current-v2'
API='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3'
LABEL='org.cachy-asahi.current-image'
COUNTS={'backend':350,'lifecycle':372,'ui':374}
OFFICIAL={'fuse-common','fuse3','gobject-introspection-runtime','graphene','gssdp','gst-plugins-bad-libs','gst-plugins-base-libs','gstreamer','gtk4','gupnp','gupnp-igd','libgirepository','libnice','liburing','libva','libxv','numactl','orc','python-gobject','vmaf','vulkan-icd-loader','xdg-desktop-portal','xdg-desktop-portal-gtk'}
BASE_LOCK_SHA='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
BASE_INVENTORY_SHA='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
FACTORY_PROFILE_PIN=dict(bytes=62259,sha256='ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa')
BOOTSTRAP_PROFILE_PIN=dict(bytes=168201,sha256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c')
SUPPLEMENTAL={'cmake','cppdap','jsoncpp','libuv','meson','ninja','python-tqdm','rhash'}
PROFILE_SHA='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171'
TOOLS_SHA='eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13'
CAPS=['CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETUID','SETGID','SETFCAP','KILL']
FORBIDDEN={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','BADARMOR'}
PROTECTED=('/var/lib/pacman','/etc/pacman.conf','/etc/pacman.d/gnupg','/var/cache/pacman')
# No hook masking, scriptlet suppression, dependency bypass, sync or network.
DRIVER=r'''set -euo pipefail
phase="$1"; uid="$2"; gid="$3"
work=/tmp/current-image-public-trust
mkdir -m700 "$work"
mkdir -p /image-facts
for key in /current-inputs/keys/*.public; do
  gpg --batch --no-options --no-autostart --homedir "$work" --no-auto-key-retrieve --auto-key-locate clear --import "$key"
done
gpg --batch --no-options --no-autostart --homedir "$work" --import-ownertrust /current-inputs/ownertrust.txt
printf '[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n' > /current-inputs/pacman.conf
mapfile -t archives < /current-inputs/archives.list
pacman --config /current-inputs/pacman.conf --gpgdir "$work" --noconfirm -U "${archives[@]}"
mapfile -t packages < /current-inputs/packages.list
pacman -Qkk "${packages[@]}" > /image-facts/package-file-check.log
pacman -Q | LC_ALL=C sort > /builder-packages.lock
cp /builder-packages.lock /image-facts/inventory.lock
: > /image-facts/payload.tsv
while IFS=$'\t' read -r owner path; do
  test -f "/$path"; test ! -L "/$path"
  test "$(pacman -Qqo -- "/$path")" = "$owner"
  printf '%s\t%s\t' "$owner" "$path" >> /image-facts/payload.tsv
  stat -c '%u:%g:%a:%s:%h:%F' -- "/$path" >> /image-facts/payload.tsv
  sha256sum -- "/$path" >> /image-facts/payload.tsv
done < /current-inputs/payload.list
: > /image-facts/package-files.txt
while IFS= read -r owner; do
  printf 'PACKAGE %s\n' "$owner" >> /image-facts/package-files.txt
  pacman -Qlq "$owner" >> /image-facts/package-files.txt
done < /current-inputs/project.list
if test "$phase" = base; then
  groupmod -g "$gid" alarm
  usermod -u "$uid" -g alarm alarm
fi
getent passwd alarm > /image-facts/alarm.passwd
getent group alarm > /image-facts/alarm.group
gpgconf --homedir "$work" --kill all
test ! -S "$work/S.gpg-agent"
rm -rf "$work" /current-inputs
'''


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):return(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()


def decoded(raw):
    def pairs(rows):
        result={}
        for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
        return result
    def number(text):
        value=float(text);need(math.isfinite(value),'finite JSON number');return value
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=number,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
    need(type(value)is dict,'JSON object');return value


def stable_stat(value):
    """Identity and mutation metadata; ordinary reads may update access time."""
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,
            value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def data(path,cap=2*1024**2):
    path=Path(path);need(path.is_absolute() and path==path.resolve(),'ordinary nonaliased DATA path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary DATA')
        raw=b''
        while block:=os.read(fd,min(65536,cap+1-len(raw))):raw+=block;need(len(raw)<=cap,'DATA cap')
        need(len(raw)==before.st_size and stable_stat(before)==stable_stat(os.fstat(fd))==stable_stat(path.lstat()),'stable whole DATA');return raw
    finally:os.close(fd)


def reference(row,cap=2*1024**2):
    need(type(row)is dict and set(row)=={'path','bytes','sha256'},'whole explicit input reference')
    raw=data(row['path'],cap);need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'whole input mismatch');return raw


def whole(row,cap=1024**3):
    """Stream rootfs/packages without holding their full bodies in Python."""
    need(type(row)is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes'])is int and 0<row['bytes']<=cap,'whole archive reference')
    path=Path(row['path']);need(path.is_absolute() and path==path.resolve(),'archive ancestry alias')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],'ordinary exact archive')
        h=hashlib.sha256();size=0
        while block:=os.read(fd,1024**2):h.update(block);size+=len(block);need(size<=row['bytes'],'archive cap')
        need(size==row['bytes'] and h.hexdigest()==row['sha256'] and stable_stat(before)==stable_stat(os.fstat(fd))==stable_stat(path.lstat()),'whole stable archive pin')
    finally:os.close(fd)
    return path


def natural(row,expected=0):
    need(row['reaped']is True and row['ownership']=='REAPED' and row['group_census']=='EMPTY_TWICE' and row['output_complete']is True
         and row['signals']==[] and row['timeout']is False and row['error']is None and type(row['exit'])is int and row['exit']==expected,
         'complete natural owned command retirement')


def signature(status,fingerprint):
    rows=[line.split()[1:]for line in status.decode().splitlines()if line.startswith('[GNUPG:] ')]
    need(not any(row and row[0]in FORBIDDEN for row in rows),'expired/revoked/unknown/bad signature')
    valid=[r for r in rows if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and any(r and r[0]=='GOODSIG'for r in rows) and valid[0][-1]==fingerprint,'exact current public primary signature')


def load_program(root,row,name):
    member=row['member'];need(not Path(member).is_absolute() and '..'not in Path(member).parts,'closed Source program member')
    path=root/member;raw=data(path,128*1024);need(pin(raw)=={k:row[k]for k in ('bytes','sha256')},'whole committed program pin')
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m


def kernel_limits(value,expected,nonce):
    need(type(value)is dict and nonce in value['cgroup'] and value['cgroup'].startswith('/') and '..'not in Path(value['cgroup']).parts
         and type(value['pid'])is int and value['pid']>0 and type(value['starttime'])is int and value['starttime']>0,
         'actual nonce-bound kernel domain identity')
    need(value['limits']==expected,'exact separately admitted owner/daemon domain limits')
    for key in ('memory.max','memory.swap.max','pids.max'):
        text=expected[key];need(type(text)is str and text.isdecimal() and (int(text)>0 or key=='memory.swap.max'),'finite kernel memory/PID/swap limits')
    need(expected['memory.swap.max']=='0' and re.fullmatch('[1-9][0-9]* [1-9][0-9]*',expected['cpu.max']),'finite CPU and zero-swap kernel domain')


def native_identity():
    return dict(system=os.uname().sysname,machine=os.uname().machine,uid=os.getuid(),gid=os.getgid(),pid=os.getpid())


def actual_domain(pid):
    proc=Path('/proc')/str(pid);text=(proc/'stat').read_text();fields=text.rpartition(')')[2].split()
    raw=(proc/'cgroup').read_text().strip();need(raw.startswith('0::/')and'\n'not in raw,'actual unified process cgroup')
    cgroup=raw[3:];root=Path('/sys/fs/cgroup')/cgroup.lstrip('/')
    limits={k:(root/k).read_text().strip()for k in ('memory.max','memory.swap.max','pids.max','cpu.max')}
    need(len(text)<4096 and int(text.split('(',1)[0])==pid,'bounded actual process identity')
    return dict(pid=pid,starttime=int(fields[19]),cgroup=cgroup,limits=limits,executable=(proc/'exe').resolve().name)


CONTEXT_PROGRAM_PINS={
    3:dict(bytes=21460,sha256='efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b'),
    4:dict(bytes=43482,sha256='2d08f9572b3f5f89d3ebac2b32e6d41a00ff4929739c35780c7c96a1d3d3b21d')}
CONTEXT_OPERATION='first-login-enrollment-ui-current-v2'


def context_contract(delegation,context=None,program=None,source_root=None):
    """Select one exact committed program and its schema/kind/issuer together."""
    row=delegation.get('programs',{}).get('context')
    need(type(row)is dict and set(row)=={'member','bytes','sha256'},'whole Source-selected context descriptor')
    descriptor={key:row[key]for key in ('bytes','sha256')}
    selected=[version for version,expected in CONTEXT_PROGRAM_PINS.items()if descriptor==expected]
    need(len(selected)==1,'exact committed context predecessor or v4 program')
    version=selected[0]
    delegation_kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V'+str(version)
    context_kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V'+str(version)
    issuer='DELEGATED_CONTEXT_PROGRAM_V'+str(version)
    need(type(delegation.get('schema'))is int and delegation['schema']==version
         and delegation.get('kind')==delegation_kind and delegation.get('issuer')=='Root','selected context program/delegation schema identity')
    if context is not None:
        need(type(context.get('schema'))is int and context['schema']==version and context.get('kind')==context_kind
             and context.get('issuer')==issuer and context.get('operation')==CONTEXT_OPERATION
             and context.get('program_pin')==descriptor,'selected program/context schema/kind/issuer/whole pin')
    if program is not None:
        need(program.OPERATION==CONTEXT_OPERATION and program.DELEGATION==delegation_kind
             and program.CONTEXT==context_kind and program.ISSUER==issuer,'actual context program API identity')
        member=Path(row['member'])
        need(not member.is_absolute() and '..'not in member.parts,'ordinary context Source member')
        path=Path(source_root)/member
        need(Path(program.__file__)==path and pin(data(path,128*1024))==descriptor,'executing exact Source-selected context body')
    return version


def admit(raw,sha,context,source,executor,context_program=None):
    need(pin(raw)['sha256']==sha,'external Root delegation whole SHA')
    preview=decoded(raw);context_contract(preview)
    H=context_program or load_program(source,preview['programs']['context'],'current_image_context')
    d=H.validate_delegation(raw,sha);context_contract(d,context,H,source)
    c=H.validate_context(d,context)
    for role in ('context','image_executor'):
        row=d['programs'][role];member=Path(row['member']);need(not member.is_absolute()and'..'not in member.parts,'closed pinned executor/context program')
        body=data(source/member,128*1024);need(pin(body)=={k:row[k]for k in ('bytes','sha256')},'actual complete context/executor code pin')
    need(c['source_root']==str(source) and c['stage']in COUNTS and c['binding']['attempt']==1 and d['capability']['allow_provisional_image_checks']is True,'actual poststart current image stage')
    own=data(Path(__file__).resolve(),128*1024);need(pin(own)=={k:d['programs']['image'][k]for k in ('bytes','sha256')},'exact reviewed image program')
    policy_path=source/d['policy']['member'];policy_raw=reference(dict(path=str(policy_path),**{k:d['policy'][k]for k in ('bytes','sha256')}));policy=decoded(policy_raw)
    f=executor.facts;need(f['api']==API and f['binding']==c['binding'] and f['nonce']==c['nonce'] and f['stage']==c['stage']
        and f['code_pin']=={k:d['programs']['image_executor'][k]for k in ('bytes','sha256')}
        and f['domain_policy_pin']==pin(policy_raw) and f['native_architecture']=='aarch64','actual pinned native executor/context/policy')
    kernel_limits(f['owner_domain'],policy['image_domains']['owner'],c['nonce']);kernel_limits(f['daemon_domain'],policy['image_domains']['daemon'],c['nonce'])
    host=native_identity();need(host['system']=='Linux'and host['machine']=='aarch64'and host['uid']>0 and host['uid']==f['uid']and host['gid']==f['gid']and host['pid']==f['owner_domain']['pid'],'genuine ordinary native ARM Python owner')
    for role in ('owner','daemon'):
        observed=actual_domain(f[role+'_domain']['pid']);need(all(observed[k]==f[role+'_domain'][k]for k in ('pid','starttime','cgroup','limits')),'actual kernel owner/daemon observations match receipt')
        if role=='daemon':need(observed['executable']=='dockerd'and f['daemon_pidfd_held']is True,'actual exclusive dockerd identity/custody')
    need(f['whole_owner_deadline_enforced']is True and f['daemon_deadline_enforced']is True,'external hard whole-tree/daemon deadline, not cooperative Python timer')
    need(f['owner_domain']['cgroup']!=f['daemon_domain']['cgroup'] and f['exclusive_daemon']is True
         and f['docker_endpoint']==policy['image_endpoint_template'].format(nonce=c['nonce'])
         and f['docker_endpoint'].startswith('unix:///') and c['nonce']in f['docker_endpoint'],'exclusive bounded named daemon, never inferred global default')
    need(f['storage']['quota_bytes']==policy['image_storage_bytes'] and type(f['storage']['quota_bytes'])is int and f['storage']['quota_bytes']>0
         and f['storage']['kernel_enforced']is True and f['storage']['scope']=='ALL_IMAGE_OWNER_CONTEXT_DAEMON_WRITES','actual whole image storage domain')
    cap=d['capability'];need(cap['builder_cpus']==4 and cap['builder_memory_bytes']==4*1024**3 and cap['builder_pids']==512
                           and 1<=cap['command_rows']<=512,'held normal builder resource/row bounds')
    need(policy['image_steps']==dict(verification_seconds=60,bootstrap_seconds=1800,stage_seconds=180,inspect_seconds=15,cleanup_seconds=90),
         'explicit held audit/bootstrap/stage/control/cleanup caps')
    need(cap['max_command_seconds']>=1800 and cap['total_seconds']>91 and policy['image_alpm_capabilities']==CAPS,'reviewed bootstrap time and finite root ALPM capabilities')
    return d,c,policy,H


def inventory(raw,count):
    rows={}
    for line in raw.decode('ascii').splitlines():
        need(re.fullmatch('[a-z0-9][a-z0-9@._+-]* [^\\s]+',line),'typed inventory row')
        n,v=line.split(' ');need(n not in rows,'duplicate inventory');rows[n]=v
    need(len(rows)==count and raw==lock(rows),'complete sorted inventory');return rows


def lock(rows):return ''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode()


def rootfs_metadata(path):
    rows=[];total=0
    with tarfile.open(path,'r|gz')as archive:
        for member in archive:
            total+=member.size;need(total<=16*1024**3,'bounded expanded signed rootfs')
            name=member.name.removeprefix('./')
            if name.startswith('var/lib/pacman/local/')and name.endswith('/desc'):
                need(member.isfile() and member.size<=1024**2,'bounded rootfs package record');fields={}
                for block in archive.extractfile(member).read().decode().split('\n\n'):
                    parts=block.strip().splitlines()
                    if parts:fields[parts[0].strip('%')]=parts[1:]
                rows.append({k.lower():fields.get(k,[])for k in ('NAME','VERSION','ARCH','LICENSE','DEPENDS','PROVIDES')})
    need(rows,'signed rootfs inventory present');return rows


def package_metadata(path):
    found=[];total=0
    with tarfile.open(path,'r|*')as archive:
        for member in archive:
            total+=member.size;need(total<=2*1024**3,'bounded expanded official package')
            if member.name.removeprefix('./')=='.PKGINFO':
                need(member.isfile()and member.size<=256*1024,'bounded package metadata');fields={}
                for line in archive.extractfile(member).read().decode().splitlines():
                    if ' = 'in line:k,v=line.split(' = ',1);fields.setdefault(k,[]).append(v)
                found.append(fields)
    need(len(found)==1,'one actual PKGINFO');return found[0]


SELECTED_PRODUCT_KIND='ROOT_SELECTED_PRODUCT_INPUT_REFS_V4'
SELECTED_PRODUCT_KEYS={'kind','selection_role','archives','signatures','producer_delegation','producer_context','completion','pair','root_component','root_test'}


def adopt_selected_product(row,key,H,d,c):
    """Replay the explicit assembler v4 operand against the actual consumer."""
    need(context_contract(d,c)==4 and d['capability'].get('allow_selected_pair_adoption')is True
         and d['capability'].get('allow_pair_adoption')is False,'explicit separate v4 selected-pair capability')
    pair=row['pair_adoption']
    need(type(pair)is dict and set(pair)==SELECTED_PRODUCT_KEYS and pair['kind']==SELECTED_PRODUCT_KIND,'exact selected-product v4 reference object')
    for group in ('archives','signatures'):
        need(type(pair[group])is list and len(pair[group])==2,'both selected archive/signature operands')
    need(row['archive']==pair['archives'][0] and row['signature']==pair['signatures'][0]
         and row['Root_decision']==pair['root_component'] and row['Root_verification']==pair['root_test'],'unchanged selected first archive/signature and authentic Root decisions')
    fields=('producer_delegation','producer_context','completion','pair','root_component','root_test')
    bodies={field:reference(pair[field])for field in fields}
    producer_context=decoded(bodies['producer_context'])
    need(encoded(producer_context)==bodies['producer_context'],'unchanged canonical historical context bytes')
    now=time.time()
    for field in ('root_component','root_test'):
        decision=decoded(bodies[field])
        need(type(decision['issued_epoch'])is int and type(decision['expires_epoch'])is int
             and decision['issued_epoch']<=now<decision['expires_epoch'],'current selected Root decision expiry before use')
    archives=[reference(value,64*1024**2)for value in pair['archives']]
    signatures=[reference(value,1024**2)for value in pair['signatures']]
    public=reference(key['public_key'],65536);need(b'PRIVATE KEY'not in public,'public selected TEST certificate only')
    adopted=H.adopt_selected_pair(d,c,producer_delegation_raw=bodies['producer_delegation'],producer_context=producer_context,
        completion_raw=bodies['completion'],pair_raw=bodies['pair'],root_component_raw=bodies['root_component'],root_test_raw=bodies['root_test'],
        archive_bodies=archives,signature_bodies=signatures,public_test_key_raw=public,selection_role=pair['selection_role'])
    need(type(adopted['schema'])is int and adopted['schema']==4 and adopted['kind']=='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4'
         and adopted['issuer']=='DELEGATED_CONTEXT_PROGRAM_V4' and adopted['binding']==c['binding'] and adopted['nonce']==d['nonce']
         and adopted['delegation_pin']==c['delegation_pin'] and adopted['component']==dict(name=row['name'],version=row['version'],architecture=row['arch'])
         and adopted['archives']==list(map(pin,archives)) and adopted['signatures']==list(map(pin,signatures))
         and adopted['public_test_key_pin']==pin(public) and adopted['test_fingerprint']==key['fingerprint']
         and adopted['trust_scope']=='TEST_ONLY' and adopted['current_stage_gpg_required']is True
         and adopted['Root_final_acceptance']is None and adopted['independent_component_acceptance']is False
         and adopted['hardware_acceptance']is False and adopted['release_acceptance']is False,'exact selected adoption receipt; current GPG still mandatory')
    names={'producer_delegation':'producer_delegation_pin','producer_context':'producer_context_pin','completion':'completion_pin',
        'pair':'pair_pin','root_component':'root_component_decision_pin','root_test':'root_test_decision_pin'}
    need(all(adopted[target]==pin(bodies[field])for field,target in names.items()),'unchanged whole selected decision and historical operand pins')
    return adopted


def base_inputs(inputs,source):
    """Join the immutable original341 lock and exact fixed8 into signed349."""
    raw=reference(inputs['base_lock']);need(pin(raw)['sha256']==BASE_LOCK_SHA,'held original341 input lock')
    base=decoded(raw);baseline_raw=reference(inputs['baseline_inventory']);need(pin(baseline_raw)['sha256']==BASE_INVENTORY_SHA,'held349 version vector')
    profile_raw=reference(inputs['bootstrap_profile']);need(pin(profile_raw)==BOOTSTRAP_PROFILE_PIN,'whole fixed supplemental bootstrap profile')
    factory_raw=data(source/'scripts/ci/first-login-enrollment-native-source/profile.json')
    need(pin(factory_raw)==FACTORY_PROFILE_PIN,'whole Source factory provenance for original341 plus fixed8')
    parent=decoded(factory_raw)['parent_files']
    for member,body in (('bootstrap/scripts/ci/inputs.lock.json',raw),('native/input-profile.json',profile_raw),('native/expected349.lock',baseline_raw)):
        need(parent[member]==dict(pin(body),mode=0o644),'exact Source factory parent descriptor: '+member)
    baseline=inventory(baseline_raw,349);profile=decoded(profile_raw);extra=profile['additions'];supplements=extra['rows']
    need(len(base['rootfs_packages'])==165 and len(base['packages'])==248 and len({r['name']for r in base['packages']})==248,'complete original165/248 package records')
    versions={}
    for row in base['rootfs_packages']:
        need(all(type(row[k])is list and len(row[k])==1 for k in ('name','version','arch'))and row['arch'][0]in ('any','aarch64')
             and row['name'][0]not in versions,'unique original rootfs name/version/architecture')
        versions[row['name'][0]]=row['version'][0]
    for row in base['packages']:
        need(row['arch']in ('any','aarch64'),'original signed package architecture');versions[row['name']]=row['version']
    need(len(versions)==341 and profile['original341']['package_count']==341 and profile['original341']['packages']==versions,'same complete original341 version vector')
    need(type(supplements)is list and len(supplements)==8 and {r['name']for r in supplements}==SUPPLEMENTAL
         and extra['count']==8 and extra['expected_augmented_package_count']==349 and extra['unresolved']==[],'complete exact fixed8 dependency closure')
    for row in supplements:
        need(row['name']not in versions and row['arch']in ('any','aarch64'),'supplemental packages never replace original341');versions[row['name']]=row['version']
    need(versions==baseline,'same exact final349 signed original341 plus fixed8 union')
    rows=[]
    for group,values in (('base_materials',[base['rootfs'],*base['packages']]),('supplemental_materials',supplements)):
        wanted={r['filename']+suffix for r in values for suffix in ('','.sig')};materials=inputs[group]
        need(type(materials)is dict and set(materials)==wanted and len(wanted)==(498 if group=='base_materials'else 16),'complete exact '+group+' references')
        for value in values:
            ref=materials[value['filename']];sig=materials[value['filename']+'.sig']
            for operand,expected in ((ref,dict(bytes=value['size'],sha256=value['sha256'])),(sig,dict(bytes=value['signature_size'],sha256=value['signature_sha256']))):
                need(type(operand)is dict and set(operand)=={'path','bytes','sha256'} and {k:operand[k]for k in ('bytes','sha256')}==expected,'whole '+group+' archive/signature lock join')
            rows.append(dict(name=value.get('name'),version=value.get('version'),arch=value.get('arch'),filename=value['filename'],archive=ref,signature=sig,trust='official',
                source_group=group,metadata_pin=pin(encoded(value))))
    paths=[ref['path']for row in rows for ref in (row['archive'],row['signature'])]
    need(len(paths)==len(set(paths))==514,'distinct complete base and supplemental operands')
    return base,rows,baseline


def selected_inputs(inputs,stage,source,H,d,c):
    base,rows,baseline=base_inputs(inputs,source)
    additions=[]
    if stage in ('lifecycle','ui'):
        catalog=decoded(reference(inputs['official_catalog']));table=decoded(reference(inputs['official_materials']))['packages']
        need(set(catalog['selected'])==set(table)==OFFICIAL and not any(catalog[k]for k in ('unresolved','ambiguous','conflicts','ordering_comparisons_pending','conflict_ordering_pending')),'exact transitive23 source closure')
        for name,row in sorted(catalog['selected'].items()):
            item=table[name];need(name not in baseline and (item['version'],item['arch'])==(row['version'],row['arch']),'no base upgrade or guessed official provider')
            need(all({k:item[kind][k]for k in ('bytes','sha256')}==row[kind]for kind in ('archive','signature')),'same official whole archives/signatures')
            additions.append(dict(item,trust='official'))
    profile_raw=data(source/'scripts/ci/first-login-enrollment-native-source/successor_v2/profile.json');need(pin(profile_raw)['sha256']==PROFILE_SHA,'whole current profile and project payloads')
    profile=decoded(profile_raw)
    if stage in ('backend','ui'):
        setup=inputs['setup8'];need((setup['name'],setup['version'],setup['arch'])==('cachy-asahi-setup','0.3.0-1','any')
             and {k:setup['archive'][k]for k in ('bytes','sha256')}==profile['setup8']['archive_pin']
             and setup['payload_files']==profile['setup8']['payload_files'],'exact qualified Setup8 dependency and source payload')
        additions.append(dict(setup,trust='test'))
    if stage=='ui':
        cli=inputs['cli03'];need(cli['name']=='cachy-asahi-first-login'and cli['version']=='0.1.0-3'and cli['arch']=='any'and cli['payload_files']==profile['packages']['first-login']['payload_files'],'only actual source-bound current backend, no CLI02')
        pair=cli['pair_adoption']
        if pair.get('kind')==SELECTED_PRODUCT_KIND:
            adopted=adopt_selected_product(cli,inputs['test_trust'],H,d,c)
            additions.append(dict(cli,trust='test',selected_pair_adoption_v4=adopted))
        else:
            need(d['capability'].get('allow_selected_pair_adoption')is not True,'selected capability cannot fall back to legacy same-run adoption')
            adopted=H.adopt_pair(d,c,producer_delegation_raw=reference(pair['producer_delegation']),producer_context=decoded(reference(pair['producer_context'])),pair_raw=reference(pair['pair']),test_raw=reference(pair['test']))
            version=context_contract(d,c)
            need(adopted['kind']=='DELEGATED_CURRENT_ONBOARDING_PAIR_ADOPTION_V'+str(version) and adopted['binding']==c['binding']
                 and adopted['archives']==[{k:cli['archive'][k]for k in ('bytes','sha256')}]*2
                 and adopted['Root_final_acceptance']is None and adopted['independent_component_acceptance']is False,'genuine delegated same-run pair adoption, never image/component acceptance')
            additions.append(dict(cli,trust='test'))
    expected=dict(baseline)
    for row in additions:need(row['name']not in expected,'no replacement or duplicate addition');expected[row['name']]=row['version']
    need(len(expected)==COUNTS[stage],'exact350/372/374 composition')
    return base,rows,additions,baseline,expected


class Build:
    def __init__(self,executor,d,c,p,out):
        self.e,self.d,self.c,self.p,self.out=executor,d,c,p,out;self.cleanup_end=time.monotonic()+d['capability']['total_seconds'];self.end=self.cleanup_end-90
        self.rows=[];self.stderr={};self.containers=[];self.images=[];self.cleaning=False;self.target=None;self.image_submission=False
    def run_result(self,step,argv,cap,expected=0):
        need(len(self.rows)<self.d['capability']['command_rows'],'finite image command index')
        need(self.cleaning or time.time()<=self.d['expires_epoch'],'Root delegation expired before new work')
        remaining=(self.cleanup_end if self.cleaning else self.end)-time.monotonic();seconds=min(cap,self.d['capability']['max_command_seconds'],remaining)
        need(seconds>1,'whole image deadline before command')
        result=self.e.run(step,argv,seconds,expected=expected)
        need(type(result)is dict and type(result.get('receipt'))is dict,'separate stream executor result')
        raw=result.get('stdout');errors=result.get('stderr');row=result['receipt']
        need(type(raw)is bytes and len(raw)<=1024**2 and type(errors)is bytes and len(errors)<=1024**2
             and row['step']==step and row['argv']==argv and type(row['expected'])is int and row['expected']==expected
             and type(row['exit'])is int and row['output_pin']==pin(raw)
             and row.get('stderr_pin')==pin(errors),'exact complete separate stdout/stderr command association')
        self.rows.append(row);self.stderr[step]=errors
        (self.out/(step+'.log')).write_bytes(raw);(self.out/(step+'.stderr.log')).write_bytes(errors)
        natural(row['supervision'],expected)
        need(row['exit']==expected,'actual executor exit differs from requested exit');return result
    def run(self,step,argv,cap,expected=0):
        return self.run_result(step,argv,cap,expected)['stdout']
    def docker(self,step,args,cap=15,expected=0):
        return self.run(step,['/usr/bin/docker','--host='+self.e.facts['docker_endpoint'],*args],cap,expected)
    def image(self,image,labels):
        value=decoded(b'{"rows":'+self.docker('inspect-image-'+str(len(self.rows)),['image','inspect',image])+b'}')['rows']
        need(len(value)==1 and value[0]['Id']==image and value[0]['Os']=='linux'and value[0]['Architecture']=='arm64'
             and value[0]['Config']['Labels']==labels,'actual exact immutable labelled native image')
        return value[0]
    def inspect(self,cid,name,image,labels,probe=False):
        rows=json.loads(self.docker('inspect-container-'+str(len(self.rows)),['container','inspect',cid]));need(len(rows)==1,'one exact current image container')
        r=rows[0];h=r['HostConfig'];need(r['Id']==cid and r['Name']=='/'+name and r['Image']==image and r['Config']['Labels']==labels,'full CID/name/image/label custody')
        phase=name.rsplit('-',1)[1];uid,gid=self.e.facts['uid'],self.e.facts['gid']
        expected=['-c','pacman -Q | LC_ALL=C sort']if probe else['-c',DRIVER,'--',phase,str(uid),str(gid)]
        need(phase in ('base',self.c['stage'],'probe')and r['Config']['Entrypoint']==['/bin/bash']and r['Config']['Cmd']==expected
             and r['Config']['User']==(f'{uid}:{gid}'if probe else'0:0'),'exact normal ALPM/probe user and static entry')
        need(h['NetworkMode']=='none'and h['Privileged']is False and not h['Devices']and not h.get('DeviceRequests')
             and h['CapDrop']==['ALL']and (h.get('CapAdd')or[])==([]if probe else CAPS)
             and h.get('PidMode','')==''and h.get('UTSMode','')==''and h.get('UsernsMode','')==''and h.get('IpcMode','private')=='private'
             and h['Memory']==h['MemorySwap']==4*1024**3 and h['NanoCpus']==4*10**9 and h['PidsLimit']==512
             and h['ReadonlyRootfs']is probe and h['SecurityOpt']in (['no-new-privileges'],['no-new-privileges=true'])
             and r['Mounts']==[],'normal finite offline image actor, no host mounts or privileged fallback')
        return r
    def actor(self,phase,image,labels,materials,packages,expected,payload):
        name='cachy-current-image-'+self.c['nonce']+'-'+phase;uid,gid=self.e.facts['uid'],self.e.facts['gid']
        probe=phase=='probe';command=['-c','pacman -Q | LC_ALL=C sort']if probe else ['-c',DRIVER,'--',phase,str(uid),str(gid)]
        argv=['container','create','--name',name,'--pull=never','--platform=linux/arm64','--network=none','--user',f'{uid}:{gid}'if probe else'0:0',
              '--env=LC_ALL=C.UTF-8','--env=TZ=UTC','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=4g','--memory-swap=4g','--cpus=4','--pids-limit=512']
        if probe:argv+=['--read-only']
        else:
            for cap in CAPS:argv+=['--cap-add='+cap]
        for k,v in sorted(labels.items()):argv+=['--label',k+'='+v]
        argv+=['--entrypoint=/bin/bash',image,*command]
        need(not self.docker('fresh-name-'+phase,['ps','-aq','--filter','name=^/'+name+'$']).strip(),'fresh actor namespace, no collision deletion')
        state=dict(name=name,cid=None,image=image,labels=labels,probe=probe,submitted=True);self.containers.append(state)
        cid=self.docker('create-'+phase,argv).decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual full CID');state['cid']=cid
        self.inspect(cid,name,image,labels,probe)
        if not probe:self.docker('copy-inputs-'+phase,['cp',str(materials)+'/.',cid+':/current-inputs'],60)
        output=self.docker('start-'+phase,['container','start','--attach',cid],1800 if phase=='base'else 180)
        terminal=self.inspect(cid,name,image,labels,probe);need(terminal['State']['Running']is False and terminal['State']['ExitCode']==0 and terminal['State']['OOMKilled']is False,'natural successful image actor')
        if probe:need(inventory(output,len(expected))==expected,'fresh committed image actual inventory');return state
        need(not any(re.search(br'(?im)(?:^error:|command failed to execute correctly|(?:hook|scriptlet)[^\n]*(?:failed|error)|failed to commit transaction|could not satisfy dependencies)',stream)for stream in (output,self.stderr['start-'+phase])),'normal ALPM hook/scriptlet/transaction failure must remain HOLD')
        facts=self.out/('facts-'+phase);facts.mkdir();self.docker('copy-facts-'+phase,['cp',cid+':/image-facts/.',str(facts)],60)
        observed=inventory(data(facts/'inventory.lock'),len(expected));need(observed==expected,'complete actual normal ALPM inventory')
        check_payload(facts,payload,uid,gid)
        need(data(facts/'package-file-check.log'),'complete actual pacman-Qkk observation')
        return state
    def commit(self,state,phase):
        tag='cachy-current-image-'+self.c['nonce']+':'+phase
        actual=self.docker('commit-'+phase,['container','commit','--change','USER alarm','--change','ENTRYPOINT ["/bin/bash"]','--change','CMD ["-l"]',state['cid'],tag],180).decode().strip()
        need(re.fullmatch('sha256:[0-9a-f]{64}',actual),'actual committed image ID');self.images.append(dict(id=actual,tag=tag,labels=state['labels']))
        self.image(actual,state['labels']);return actual
    def cleanup(self):
        self.cleaning=True;self.cleanup_end=min(self.cleanup_end,time.monotonic()+90);errors=[];retired=[]
        for state in reversed(self.containers):
            try:
                cid=state['cid']
                if cid is None:
                    raw=self.docker('discover-uncertain-'+str(len(self.rows)),['ps','-aq','--no-trunc','--filter','name=^/'+state['name']+'$']).decode().splitlines()
                    need(len(raw)<=1,'uncertain create discovery ambiguous');cid=raw[0]if raw else None
                if cid:
                    row=self.inspect(cid,state['name'],state['image'],state['labels'],state['probe'])
                    if row['State']['Running']is True:
                        self.docker('stop-failed-'+str(len(self.rows)),['container','stop','--time','5',cid])
                        stopped=self.inspect(cid,state['name'],state['image'],state['labels'],state['probe'])
                        need(stopped['State']['Running']is False,'owned failed actor stopped')
                        errors.append(dict(kind='forced-stop',name=state['name'],error='NONNATURAL_RECORDED_HOLD'))
                    self.docker('remove-container-'+str(len(self.rows)),['container','rm',cid])
                for n in range(2):need(not self.docker('absent-'+str(len(self.rows)),['ps','-aq','--no-trunc','--filter','name=^/'+state['name']+'$']).strip(),'exact actor absence twice')
                retired.append(state['name'])
            except BaseException as error:errors.append(dict(kind='container',name=state['name'],error=type(error).__name__))
        if self.image_submission:
            try:
                ids=self.docker('discover-owned-images-'+str(len(self.rows)),['image','ls','-aq','--no-trunc','--filter','label='+LABEL+'.nonce='+self.c['nonce']]).decode().splitlines()
                need(len(ids)<=16 and len(ids)==len(set(ids)),'finite unique nonce image namespace')
                known={row['id']for row in self.images};labels={LABEL+'.nonce':self.c['nonce'],LABEL+'.source':self.c['binding']['source'],LABEL+'.stage':self.c['stage']}
                for image in ids:
                    if image not in known:
                        observed=self.image(image,labels)
                        need(not observed.get('RepoDigests')and all(tag.startswith('cachy-current-image-'+self.c['nonce']+':')for tag in observed.get('RepoTags')or[]),'exclusive owned image tags before cleanup')
                        self.images.append(dict(id=image,tag=None,labels=labels))
            except BaseException as error:errors.append(dict(kind='image-discovery',error=type(error).__name__))
        for image in reversed(self.images):
            if image['id']==self.target:continue
            try:self.image(image['id'],image['labels']);self.docker('remove-image-'+str(len(self.rows)),['image','rm',image['id']])
            except BaseException as error:errors.append(dict(kind='image',id=image['id'],error=type(error).__name__))
        if self.image_submission:
            try:
                for n in range(2):
                    ids=set(self.docker('image-absence-'+str(len(self.rows)),['image','ls','-aq','--no-trunc','--filter','label='+LABEL+'.nonce='+self.c['nonce']]).decode().splitlines())
                    need(ids==({self.target}if self.target else set()),'all temporary nonce images absent twice')
            except BaseException as error:errors.append(dict(kind='image-absence',error=type(error).__name__))
        return dict(errors=errors,retired_containers=retired,retained_target_image_unqualified=self.target)


NO_AGENT_STDERR_V3=b'gpg-connect-agent: no gpg-agent running in this session\n'


def retire_private_separated_v3(held,build,work,homes):
    """Adapt one exact stderr diagnostic to the frozen callback's byte token.

    The callback return is an explicit compatibility projection. Receipt stdout
    remains empty, its actual nonzero exit remains two, and stderr is pinned/logged
    separately. No arbitrary stderr or merged output is accepted as no-agent proof.
    """
    def callback(step,argv):
        if argv and argv[0]=='/usr/bin/gpg-connect-agent':
            need(re.fullmatch('no-agent-private-[0-9]+',step) and len(argv)==5 and argv[1]=='--homedir'
                 and argv[3:]==['--no-autostart','/bye'],'exact held no-agent command adapter')
            result=build.run_result(step,argv,15,expected=2)
            need(result['stdout']==b'' and result['stderr']==NO_AGENT_STDERR_V3,'exact separate no-agent stderr; no stdout substitution')
            result['receipt']['held_tools_adapter_v3']=dict(kind='CURRENT_IMAGE_NO_AGENT_STDERR_V3',
                source_stream='stderr',actual_exit=2,stdout_pin=pin(b''),stderr_pin=pin(result['stderr']),
                held_callback_token_pin=pin(NO_AGENT_STDERR_V3),stdout_relabelled=False)
            return result['stderr']
        return build.run(step,argv,15)
    return held.retire_private(callback,work,homes)


def check_payload(facts,payload,uid,gid):
    lines=data(facts/'payload.tsv').decode().splitlines()if (facts/'payload.tsv').stat().st_size else[];need(len(lines)==2*len(payload),'complete installed payload observations')
    expected=[]
    for path,row in sorted(payload.items()):
        expected.extend([row['owner']+'\t'+path+'\t0:0:%o:%d:1:regular file'%(row['mode'],row['bytes']),row['sha256']+'  /'+path])
    need(lines==expected,'source-bound payload owner/mode/body/size')
    files=data(facts/'package-files.txt').decode().splitlines()if (facts/'package-files.txt').stat().st_size else[];seen={};owner=None
    for line in files:
        if line.startswith('PACKAGE '):owner=line[8:];need(owner not in seen,'unique project ownership list');seen[owner]=set()
        elif not line.endswith('/'):need(owner is not None,'typed owner list');seen[owner].add(line.lstrip('/'))
    need(seen=={name:{p for p,r in payload.items()if r['owner']==name}for name in {r['owner']for r in payload.values()}},'exact ALPM owned project file set')
    user=data(facts/'alarm.passwd').decode().strip().split(':');group=data(facts/'alarm.group').decode().strip().split(':')
    need(user[0]==group[0]=='alarm'and user[2:4]==[str(uid),str(gid)]and group[2]==str(gid),'actual ordinary builder user mapping')


def stage_materials(path,rows,trust,payload):
    path.mkdir();(path/'keys').mkdir();archives=[];names=[]
    for key,value in trust.items():
        target=path/'keys'/(key+'.public');shutil.copyfile(value['public_key']['path'],target)
        whole(dict(path=str(target),**{k:value['public_key'][k]for k in ('bytes','sha256')}),65536)
    (path/'ownertrust.txt').write_text(''.join(row['fingerprint']+':6:\n'for row in trust.values()))
    for i,row in enumerate(rows):
        name='%03d.pkg.tar.xz'%i
        for field,suffix in (('archive',''),('signature','.sig')):
            target=path/(name+suffix);shutil.copyfile(row[field]['path'],target);whole(dict(path=str(target),**{k:row[field][k]for k in ('bytes','sha256')}))
        archives.append('/current-inputs/'+name);names.append(row['name'])
    (path/'archives.list').write_text('\n'.join(archives)+'\n');(path/'packages.list').write_text('\n'.join(names)+'\n')
    (path/'payload.list').write_text(''.join(row['owner']+'\t'+name+'\n'for name,row in sorted(payload.items())))
    (path/'project.list').write_text(''.join(name+'\n'for name in sorted({r['owner']for r in payload.values()})))


def tools(source):
    path=source/'scripts/ci/first-login-enrollment-native-source/payload/native/build_tools_tools_v2.py';body=data(path,65536)
    need(pin(body)['sha256']==TOOLS_SHA,'held normal ALPM/payload/protected-state helper')
    spec=importlib.util.spec_from_file_location('current_image_held_tools',path);m=importlib.util.module_from_spec(spec);exec(compile(body,str(path),'exec'),m.__dict__);return m


def protected_state(T):
    result={}
    for name in PROTECTED:
        if name!='/etc/pacman.d/gnupg':result[name]=T.snapshot_receipt(Path(name));continue
        root=Path(name);rows={}
        if os.path.lexists(root):
            def visit(path,depth=0):
                need(depth<=64 and len(rows)<100000,'bounded protected trust metadata')
                info=path.lstat();need(not path.is_symlink(),'protected trust aliases refuse')
                rows[str(path.relative_to(root))]=dict(device=info.st_dev,inode=info.st_ino,mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,
                    bytes=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
                if stat.S_ISDIR(info.st_mode):
                    for child in sorted(path.iterdir()):visit(child,depth+1)
            visit(root)
        result[name]=dict(scope='METADATA_ONLY_NO_PRIVATE_KEY_CONTENT_READ',entries=len(rows),**pin(encoded(rows)))
    return result


def build_stage(*,delegation_raw,delegation_sha256,context,source_root,inputs,executor,output,context_program=None):
    """Construct one real provisional350/372/374 image through the qualified executor."""
    source=Path(source_root);out=Path(output);d,c,p,H=admit(delegation_raw,delegation_sha256,context,source,executor,context_program)
    need(out.is_absolute()and out==out.resolve()and not out.exists()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022
         and not out.is_relative_to(source)and not source.is_relative_to(out),'fresh disjoint owned image output')
    base,base_rows,additions,baseline,expected=selected_inputs(inputs,c['stage'],source,H,d,c)
    T=tools(source);before=protected_state(T);out.mkdir(mode=0o700)
    b=Build(executor,d,c,p,out);report=dict(status='HOLD',operation=OP,stage=c['stage'],binding=c['binding'],delegation_pin=c['delegation_pin'],
        owner_executor_facts=executor.facts,Root_final_acceptance=None,independent_image_qualification=None,native16K='UNQUALIFIED',M2='NOT_RUN',release='NOT_ADMITTED')
    report['base_input_provenance']=dict(base_lock=inputs['base_lock'],bootstrap_profile=inputs['bootstrap_profile'],baseline_inventory=inputs['baseline_inventory'],
        factory_profile_pin=FACTORY_PROFILE_PIN,original_package_count=341,supplemental_package_count=8,final_package_count=349,
        materials=[{k:row[k]for k in ('name','version','arch','filename','archive','signature','source_group','metadata_pin')}for row in base_rows])
    current_gpg={};report['selected_pair_adoptions_v4']=[]
    trust={};private=Path('/tmp')/('build-tools-test-current-image-'+c['nonce']);homes=[str(private/'official'),str(private/'test')];private_created=False;primary=None
    try:
        need(not private.exists(),'fresh private public-trust work');private.mkdir(mode=0o700);private_created=True
        for name in ('official','test'):(private/name).mkdir(mode=0o700)
        for key in (('official','test')if c['stage']in ('backend','ui')else('official',)):
            home=private/key;row=inputs[key+'_trust']
            admission=decoded(reference(row['Root_admission']));public=reference(row['public_key'],65536);need(b'PRIVATE KEY'not in public,'public certificates only')
            need(admission['issuer']=='Root'and admission['approved']is True and admission['public_key']==row['public_key']and admission['fingerprint']==row['fingerprint']
                 and admission['scope']=='CURRENT_ONBOARDING_IMAGE_INPUT_TRUST_ONLY'and type(admission['issued_epoch'])is int and type(admission['expires_epoch'])is int and admission['issued_epoch']<=time.time()<admission['expires_epoch'],'actual separately Root-admitted current public trust')
            need(re.fullmatch('[0-9A-F]{40}',row['fingerprint'])and (key!='official'or row['fingerprint']==base['signer_fingerprint']),'explicit exact primary trust')
            trust[key]=row
            b.run('import-'+key,['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(home),'--no-auto-key-retrieve','--auto-key-locate','clear','--import',row['public_key']['path']],60)
        for i,row in enumerate([*base_rows,*additions]):
            whole(row['archive']);whole(row['signature'],1024**2)
            key=row['trust'];home=Path(homes[0 if key=='official'else 1])
            status=b.run('verify-%03d'%i,['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(home),'--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',row['signature']['path'],row['archive']['path']],60)
            signature(status,trust[key]['fingerprint'])
            if 'selected_pair_adoption_v4'in row:
                pair=row['pair_adoption'];archive=pair['archives'][1];sig=pair['signatures'][1]
                whole(archive,64*1024**2);whole(sig,1024**2)
                step='verify-selected-%03d-1'%i
                signature(b.run(step,['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(home),'--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify',sig['path'],archive['path']],60),trust[key]['fingerprint'])
                current_gpg[row['name']]=['verify-%03d'%i,step]
            if row['name']is not None:
                head=Path(row['archive']['path']).open('rb')
                try:magic=head.read(4)
                finally:head.close()
                md=T._metadata(b.run('pkginfo-%03d'%i,['/usr/bin/bsdtar','-xOf',row['archive']['path'],'.PKGINFO'],60))if magic==b'\x28\xb5\x2f\xfd'else package_metadata(row['archive']['path'])
                need(md.get('pkgname')==[row['name']]and md.get('pkgver')==[row['version']]and md.get('arch')==[row['arch']],'actual signed package identity/epoch/architecture')
        need(rootfs_metadata(base_rows[0]['archive']['path'])==base['rootfs_packages'],'complete held signed rootfs inventory')
        for row in additions:
            if row['trust']=='test':
                if 'selected_pair_adoption_v4'in row:
                    admission=decoded(reference(trust['test']['Root_admission']))
                    need(admission['issued_epoch']<=time.time()<admission['expires_epoch'],'current TEST trust expiry before selected use')
                    adopted=adopt_selected_product(row,trust['test'],H,d,c)
                    need(adopted==row['selected_pair_adoption_v4'],'unchanged selected adoption after both current-stage GPG checks')
                    report['selected_pair_adoptions_v4'].append(dict(adoption=adopted,current_stage_gpg_steps=current_gpg[row['name']]))
                    continue
                decision=decoded(reference(row['Root_decision']));proof=decoded(reference(row['Root_verification']))
                ar={k:row['archive'][k]for k in ('bytes','sha256')};sig={k:row['signature'][k]for k in ('bytes','sha256')}
                key=dict({k:trust['test']['public_key'][k]for k in ('bytes','sha256')},fingerprint=trust['test']['fingerprint'],trust_scope='TEST_ONLY')
                expected_status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY'if row['name']=='cachy-asahi-setup'else'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'
                need(decision['schema']==1 and decision['issuer']=='Root'and decision['accepted']is decision['holds_preserved']is True
                     and decision['status']==expected_status and decision['trust_scope']=='TEST_ONLY'and decision['archive']==dict(ar,package=row['name'],version=row['version'],arch=row['arch'])
                     and decision['signature']==sig and decision['public_test_key']==key and decision['verification_proof_sha256']==pin(reference(row['Root_verification']))['sha256']
                     and proof['schema']==1 and proof['Root_issuer']=='Root'and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE'and proof['verified']is True
                     and proof['trust_scope']=='TEST_ONLY'and proof['archive']==ar and proof['signature']==sig and proof['public_test_key']==key,'genuine exact current Root project TEST decision/proof')
        seed=out/'seed';seed.mkdir();shutil.copyfile(base_rows[0]['archive']['path'],seed/'rootfs.tar.gz');whole(dict(path=str(seed/'rootfs.tar.gz'),**{k:base_rows[0]['archive'][k]for k in ('bytes','sha256')}))
        (seed/'Dockerfile').write_text('FROM scratch\nADD rootfs.tar.gz /\n')
        labels={LABEL+'.nonce':c['nonce'],LABEL+'.source':c['binding']['source'],LABEL+'.stage':c['stage']}
        info=decoded(b.docker('native-daemon-info',['info','--format','{{json .}}']))
        need(info['OSType']=='linux'and info['Architecture']in ('arm64','aarch64')and info['CgroupVersion']=='2'
             and not any('rootless'in value or'userns'in value for value in info['SecurityOptions'])
             and info['ID']==executor.facts['engine_id']and all(info[k]is True for k in ('MemoryLimit','SwapLimit','CpuCfsQuota','PidsLimit')),'actual bounded native daemon capabilities/identity')
        need(not b.docker('fresh-images',['image','ls','-aq','--no-trunc','--filter','label='+LABEL+'.nonce='+c['nonce']]).strip(),'fresh exclusively owned image namespace')
        tag='cachy-current-image-'+c['nonce']+':seed';iid=out/'seed.iid'
        argv=['/usr/bin/env','DOCKER_BUILDKIT=0','/usr/bin/docker','--host='+executor.facts['docker_endpoint'],'build','--quiet','--no-cache','--network=none','--pull=false','--iidfile',str(iid),'--tag',tag]
        for k,v in sorted(labels.items()):argv+=['--label',k+'='+v]
        b.image_submission=True
        b.run('seed-build',argv+[str(seed)],1800);image=data(iid,128).decode().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image),'actual scratch image IID')
        b.images.append(dict(id=image,tag=tag,labels=labels));b.image(image,labels)
        materials=out/'base-materials';stage_materials(materials,base_rows[1:],trust,{})
        actor=b.actor('base',image,labels,materials,[r['name']for r in base_rows[1:]],baseline,{})
        image=b.commit(actor,'base349')
        payload={}
        for row in additions:
            if row['trust']=='test':
                for name,value in row['payload_files'].items():need(name not in payload,'disjoint project payload');payload[name]=dict(value,owner=row['name'])
        materials=out/'stage-materials';stage_materials(materials,additions,trust,payload)
        actor=b.actor(c['stage'],image,labels,materials,[r['name']for r in additions],expected,payload);target=b.commit(actor,str(COUNTS[c['stage']]))
        b.actor('probe',target,labels,None,[],expected,{})
        b.target=target;report.update(status='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY',image_id=target,packages=expected,
            inventory_pin=dict(path=str(out/('facts-'+c['stage'])/'inventory.lock'),**pin(data(out/('facts-'+c['stage'])/'inventory.lock'))),payload_files=payload)
    except BaseException as error:primary=error;report['failure']=dict(type=type(error).__name__,message=str(error)[:1000])
    finally:
        try:report['cleanup']=b.cleanup()
        except BaseException as error:report['cleanup']=dict(errors=[dict(error=type(error).__name__)])
        if private_created and private.exists():
            try:report['private_retirement']=retire_private_separated_v3(T,b,private,homes)
            except BaseException as error:report['private_retirement']=dict(failures=[type(error).__name__])
        else:report['private_retirement']=dict(homes_retired=not private.exists(),no_sockets=None,private_directory_absent=not private.exists(),failures=[])
        try:after=protected_state(T)
        except BaseException as error:after=None;report['protected_observation_failure']=type(error).__name__
        report['protected_before']=before;report['protected_after']=after
        if report['cleanup']['errors']or report['private_retirement'].get('failures')or before!=after:
            report['status']='HOLD';report['cleanup_or_protected_failure']=True
        if primary is not None:report['status']='HOLD'
        report['commands']=b.rows;(out/'image-provisional.json').write_bytes(encoded(report))
    if report['status']!='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY':raise ValueError('image construction held; inspect retained primary/cleanup DATA')from primary
    return report


if __name__=='__main__':raise SystemExit('Root-delegated image callback only; no standalone authority or actor entry')
