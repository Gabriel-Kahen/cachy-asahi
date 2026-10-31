# SPDX-License-Identifier: MIT
"""Passive, closed native-pair validation. No fetch, signing, build or install.

Welcome2 is deliberately UNBOUND until Root accepts actual pair/CLI evidence.
The binding carrier_source identifies the immutable input-carrier checkout;
source identifies its actual native build run source. Both are independently
required revision operands, with the checkout revision checked by C.bound_inputs.
Its future byte-pinned carrier index has schema_version=1,
kind=ROOT_ACCEPTED_WELCOME2_NATIVE_INPUTS, native_source, candidate_source and
packages containing only cachy-asahi-welcome. That package row retains version,
native_source/native_run, files a/b, source_files, payload, checks a/b,
comparison, raw_lifecycle, root_guard_tap, cleanup, collection and decision.
Every public byte operand is a path/bytes/sha256 reference. Root's decision
joins original comparison and complete raw lifecycle; the original validator
requires 32 ordinary passes plus its single scoped root-only skip, separately
passed actual UID0 guard, and the complete574/577 signed CLI lifecycle.
This accepts native build provenance on574, not604 deployment or GUI/hardware.
"""
from pathlib import Path
import hashlib
import tarfile
import re
import shutil
import stat
import tempfile
import sys
import contract as C

META={'.PKGINFO','.BUILDINFO','.MTREE'}
WELCOME='cachy-asahi-welcome'
SETUP='cachy-asahi-setup'
MANAGEMENT_SOURCE='92e433fa79eb57bfb3e4038feb30e7a7c87c652f'
MANAGEMENT_INDEX=dict(path='index.json',bytes=104659,sha256='b60048aa1312d22b1012a5d2d2e4c5185c8087b3a8f2b6c410ff9ec6a1dddfcf')
SETUP_SOURCE='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44'
SETUP_INDEX=dict(path='index.json',bytes=25005,sha256='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d')


def require_welcome(policy):
    """First gate, including callers passing an explicit policy; touch no inputs."""
    value=policy.get('welcome',{})
    C.need(value.get('status')=='ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE' and
        re.fullmatch('[0-9a-f]{40}',value.get('source') or '') and
        re.fullmatch('[0-9a-f]{40}',value.get('carrier_source') or '') and
        re.fullmatch('[0-9a-f]{40}',value.get('candidate_source') or '') and type(value.get('index')) is dict,
        'Welcome2 native pair and actual CLI/lifecycle acceptance remain UNBOUND')
    return value


def tools(source):
    before=list(sys.path)
    try:
        sys.path[:0]=[str(source/'scripts/checks'),str(source/'scripts/build')]
        checks=C.scoped_load('_604_package_checks',source/'scripts/checks/package_checks.py',{})
        bind=C.scoped_load('_604_build_binding',source/'scripts/build/build.py',{'package_checks':checks})
        return checks,bind
    finally:sys.path[:]=before


def comparison(value):
    C.need(value.get('status')=='contents-reproduced' and value.get('errors')==[] and
        len(value.get('packages',{}))==1 and all(all(row.get(k) is True for k in
        ('bytes_equal','pkginfo_equal','buildinfo_equal','installed_contents_equal')) for row in value['packages'].values()),
        'complete native pair comparison required')


def normalized(name,row,root,report):
    return dict(row,name=name,archive=str(C.checked(root,row['files']['a'],8*1024**2)),
        recipe_metadata=row.get('metadata'),metadata=report['metadata']['.PKGINFO'],payload={n:r for n,r in report['members'].items()
        if r['type']!='5' and n not in META},inspected=report)


def management_pairs(source,root,binding,checks):
    api=C.scoped_load('_604_management_packet',source/'scripts/ci/management-tools-generic16k/contract.py',{})
    expected=api.policy()
    C.need(binding==expected and binding['packet_source']==MANAGEMENT_SOURCE and binding['packet_index']==MANAGEMENT_INDEX,
        'exact accepted four-pair native carrier required')
    packet=api.packet(root);api.package_payload(root,packet,checks)
    result={}
    for name,row in packet['packages'].items():
        for filename,ref in row['source_files'].items():
            original=source/'packages/tools'/name/filename
            C.need(original.read_bytes()==api.checked(root,ref),'retained management source differs from current recipe: '+name+'/'+filename)
        report=checks.package(C.checked(root,row['files']['a'],8*1024**2))
        result[name]=normalized(name,dict(row,sources=row['source_files']),root,report)
    return result


def setup_pair(source,root,binding,checks,bind):
    C.need(binding==dict(source=SETUP_SOURCE,index=SETUP_INDEX),'exact accepted Setup5 carrier required')
    index=C.read(C.checked(root,SETUP_INDEX));C.need(index.get('schema_version')==1 and
        index.get('status')=='ROOT_ACCEPTED_NATIVE_SETUP5_PAIR_AND_LEGACY_LIFECYCLE_INPUTS' and
        index.get('native_run')==38934198468 and index.get('native_source')=='4cf9884dacb2816532b07c8107982d7157656046' and
        index.get('package')==SETUP and index.get('version')=='0.1.0-5' and len(index.get('files',{}))==147,
        'accepted Setup5 index identity differs')
    # The immutable index has empty original observation records: verify every byte,
    # including zero-byte entries, with no extraction or execution of packet code.
    nodes=[]
    for path in root.rglob('*'):
        nodes.append(path);C.need(len(nodes)<256 and not path.is_symlink() and (path.is_file() or path.is_dir()),'bounded ordinary Setup5 carrier required')
    actual={p.relative_to(root).as_posix() for p in nodes if p.is_file()}
    C.need(actual==set(index['files'])|{'index.json','README.md'} and len(actual)==149 and
        sum(p.stat().st_size for p in nodes if p.is_file())==1305823 and (root/'README.md').stat().st_size==345,
        'complete original Setup5 149-file closure required')
    for name,ref in index['files'].items():
        C.need(type(name) is str and not Path(name).is_absolute() and all(n not in ('','.','..') for n in name.split('/')),
            'safe Setup5 carrier path required')
        path=root/name;info=path.stat()
        C.need(info.st_nlink==1 and info.st_size==ref['bytes']<=2*1024**2 and C.sha(path)==ref['sha256'],
            'accepted Setup5 carrier member differs: '+name)
    api=C.scoped_load('_604_setup_native',source/'scripts/ci/setup5-native/contract.py',{})
    recipe=api.recipe(source);sources={}
    for name,sha in recipe['input_sha256'].items():
        filename='source/'+SETUP+'/'+name;ref=dict(path=filename,**index['files'][filename]);path=C.checked(root,ref)
        C.need(C.sha(path)==sha,'accepted Setup5 current recipe/source join differs: '+name);sources[name]=ref
    files={side:dict(path='packages/'+SETUP+'-'+side+'/'+SETUP+'-0.1.0-5-any.pkg.tar.xz',
        bytes=index['archive_bytes'],sha256=index['archive_sha256']) for side in ('a','b')}
    reports=[]
    for side in ('a','b'):
        path=C.checked(root,files[side],8*1024**2);report=checks.package(path)
        C.need(not bind.bind_artifact(recipe['metadata'],report,recipe['input_sha256']['PKGBUILD']),
            'Setup5 native BUILDINFO/PKGINFO differs')
        api.payload(report,source);api.check_log(root/'runtime'/(SETUP+'-'+side)/'build.log');reports.append(report)
    C.need(reports[0]['metadata']==reports[1]['metadata'] and reports[0]['members']==reports[1]['members'],
        'Setup5 native pair metadata/payload differs')
    comparison(C.read(root/'runtime'/ (SETUP+'-comparison.json')))
    life=C.read(root/'runtime/lifecycle.json');api.validate_lifecycle(life)
    cleanup=C.scoped_load('_604_setup_cleanup',source/'scripts/ci/management-tools-generic16k/contract.py',{})
    cleanup.cleanup_proof(C.read(root/'ordered-cleanup.json'))
    decision=C.read(root/'root-verification.json')
    C.need(decision.get('status')=='ROOT_ACCEPTED_NATIVE_SETUP5_PAIR_AND_LEGACY_LIFECYCLE' and
        decision.get('run_id')==index['native_run'] and decision.get('source')==index['native_source'] and
        decision.get('package_sha256')==index['archive_sha256'] and decision.get('ordered_cleanup')=='PASS' and
        decision.get('full574_restored') is True and decision.get('hardware')=='NOT_RUN','Setup5 Root acceptance differs')
    return normalized(SETUP,dict(version=index['version'],native_source=index['native_source'],native_run=index['native_run'],
        qualification=index['status'],files=files,sources=sources,source_files=sources,metadata=recipe['metadata'],
        raw_lifecycle=dict(path='runtime/lifecycle.json',**index['files']['runtime/lifecycle.json']),
        acceptance=dict(path='root-verification.json',**index['files']['root-verification.json']),
        retained_index=SETUP_INDEX),root,reports[0])


def welcome_pair(source,root,binding,checks,bind):
    value=C.read(C.checked(root,binding['index']))
    C.need(value.get('schema_version')==1 and value.get('kind')=='ROOT_ACCEPTED_WELCOME2_NATIVE_INPUTS' and
        value.get('native_source')==binding['source'] and value.get('candidate_source')==binding['candidate_source'] and
        set(value.get('packages',{}))=={WELCOME},'Root-bound Welcome2 native carrier identity required')
    row=value['packages'][WELCOME];C.need(row.get('version')=='0.1.0-2' and row.get('native_source')==binding['source'] and
        re.fullmatch('[1-9][0-9]*',str(row.get('native_run',''))) and set(row.get('files',{}))=={'a','b'} and
        row['files']['a']['sha256']==row['files']['b']['sha256'] and row['files']['a']['bytes']==row['files']['b']['bytes'] and
        row['files']['a']['path']!=row['files']['b']['path'],'Welcome2 two distinct original identical archives required')
    refs={}
    def collect(node):
        if type(node) is dict:
            if set(node)=={'path','bytes','sha256'}:
                previous=refs.setdefault(node['path'],node);C.need(previous==node,'conflicting Welcome2 references');C.checked(root,node)
            else:
                for child in node.values():collect(child)
        elif type(node) is list:
            for child in node:collect(child)
    collect(value);C.need(len(refs)<=256,'finite closed Welcome2 carrier required')
    nodes=[]
    for path in root.rglob('*'):
        nodes.append(path);C.need(len(nodes)<=512 and not path.is_symlink() and (path.is_file() or path.is_dir()),'bounded ordinary Welcome2 carrier required')
    C.need({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==set(refs)|{binding['index']['path']} and
        sum(r['bytes'] for r in refs.values())<=64*1024**2,'Welcome2 original carrier reference closure differs')
    api=C.scoped_load('_604_welcome_native',source/'scripts/ci/welcome-management-native/native_contract.py',{})
    C.need(api.policy()['candidate_source']==binding['candidate_source'],'Welcome2 original product-source provenance differs')
    product=api.product(WELCOME);recipe=api.recipe(source,WELCOME)
    C.need(set(row.get('source_files',{}))==set(product['source_files']),'complete Welcome2 24-file source closure required')
    for name,ref in row['source_files'].items():
        path=C.checked(root,ref);C.need(dict(bytes=path.stat().st_size,sha256=C.sha(path))==product['source_files'][name] and
            C.sha(path)==C.sha(source/'packages/tools'/WELCOME/name),'Welcome2 retained/current product source differs')
    C.need(set(row.get('checks',{}))=={'a','b'} and row['checks']['a']['path']!=row['checks']['b']['path'],'distinct Welcome2 ordinary check logs required')
    reports=[]
    for side in ('a','b'):
        path=C.checked(root,row['files'][side],8*1024**2)
        C.need(path.name==WELCOME+'-0.1.0-2-aarch64.pkg.tar.xz','fixed native Welcome2 archive basename required')
        report=checks.package(path);C.need(not bind.bind_artifact(recipe['metadata'],report,recipe['input_sha256']['PKGBUILD']),
            'Welcome2 native BUILDINFO/PKGINFO/source binding differs')
        C.need(api.payload(report,source,WELCOME)==row.get('payload'),'Welcome2 original payload receipt differs')
        with tarfile.open(path,'r:xz') as archive:
            members=[m for m in archive if checks.clean_name(m.name)=='usr/bin/'+WELCOME]
            C.need(len(members)==1 and members[0].isfile() and members[0].size<=4*1024**2,'one bounded actual Welcome2 ELF required')
            api.elf(archive.extractfile(members[0]).read(),checks)
        api.check_log(C.checked(root,row['checks'][side]),WELCOME);reports.append(report)
    C.need(reports[0]['members']==reports[1]['members'] and reports[0]['metadata']==reports[1]['metadata'],'Welcome2 native pair metadata/payload differs')
    comparison(C.read(C.checked(root,row['comparison'])))
    life=C.read(C.checked(root,row['raw_lifecycle']));api.validate_lifecycle(life)
    api.validate_root_guard(life['root_guard'],C.checked(root,row['root_guard_tap']).read_text())
    cleanup=C.scoped_load('_604_welcome_cleanup',source/'scripts/ci/management-tools-generic16k/contract.py',{})
    cleanup.cleanup_proof(C.read(C.checked(root,row['cleanup'])))
    C.checked(root,row['collection']);decision=C.read(C.checked(root,row['decision']))
    C.need(decision.get('status')=='ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE' and
        decision.get('source_sha')==binding['source'] and str(decision.get('run_id'))==str(row['native_run']) and
        decision.get('version')=='0.1.0-2' and decision.get('archive_bytes')==row['files']['a']['bytes'] and
        decision.get('archive_sha256')==row['files']['a']['sha256'] and decision.get('comparison')==C.read(C.checked(root,row['comparison'])) and
        decision.get('lifecycle')==life and decision.get('cleanup')=='PASS' and decision.get('hardware')=='NOT_RUN',
        'Root accepted Welcome2 actual pair/CLI lifecycle decision differs')
    return normalized(WELCOME,dict(row,sources=row['source_files']),root,reports[0])


def _validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy):
    require_welcome(policy)  # Must precede imports, filesystem reads and every actor.
    source,legacy,eight,seven,management,setup,welcome=map(Path,(source,legacy,eight,seven,management,setup,welcome))
    checks,bind=tools(source)
    accepted=C.scoped_load('_604_accepted600_contract',source/'scripts/ci/expanded600-installer-vm/contract.py',{})
    accepted.load=lambda name,path:C.scoped_load(name,path,{'contract':accepted})
    materializer=C.scoped_load('_604_accepted600_materializer',source/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':accepted})
    pairs=materializer.accepted_pairs(eight,seven,legacy,policy)
    for name,row in pairs.items():row.update(recipe_metadata=row['metadata'],metadata=row['inspected']['metadata']['.PKGINFO'])
    old,reader=materializer.legacy_inputs(legacy)
    combined=reader.combined(legacy,policy)
    C.need(policy.get('combined_materialization_source')==accepted.LEGACY,
        'combined exact-byte materialization provenance differs')
    # The existing readers deliberately reject Git metadata. Stage only their exact
    # byte-pinned public closure in passive scratch, never a recursive checkout copy.
    with tempfile.TemporaryDirectory(prefix='expanded604-input-check-') as temporary:
        temporary=Path(temporary)
        m=stage_packet(management,temporary/'management',policy['management']['packet_index'])
        s=stage_packet(setup,temporary/'setup',policy['setup']['index'],setup_packet=True)
        w=stage_packet(welcome,temporary/'welcome',policy['welcome']['index'])
        result=dict(pairs=pairs,management=management_pairs(source,m,policy['management'],checks),
            setup=setup_pair(source,s,policy['setup'],checks,bind),welcome=welcome_pair(source,w,policy['welcome'],checks,bind),
            summary=dict(status='PASS_ALL_RETAINED_NATIVE_INPUTS',builds='NOT_RUN_REUSED_ACCEPTED_PAIRS',
                management_index=MANAGEMENT_INDEX,setup_index=SETUP_INDEX,welcome_index=policy['welcome']['index'],hardware='NOT_RUN',
                declared_driver_source=combined['source'],materialized_from_legacy=policy['combined_materialization_source']))
        for rows,root in ((result['management'].values(),management),([result['setup']],setup),([result['welcome']],welcome)):
            for row in rows:row['archive']=str(C.checked(root,row['files']['a'],8*1024**2))
    result['retention']=retention(eight,seven,management,setup,welcome,legacy,policy)
    return result



def references(value):
    refs={}
    def collect(node):
        if type(node) is dict:
            if set(node)=={'path','bytes','sha256'}:
                old=refs.setdefault(node['path'],node);C.need(old==node,'conflicting original carrier references')
            else:
                for child in node.values():collect(child)
        elif type(node) is list:
            for child in node:collect(child)
    collect(value);return refs


def packet_refs(root,index_ref,setup_packet=False):
    index=C.read(C.checked(root,index_ref));refs=references(index)
    if setup_packet:
        C.need(type(index.get('files')) is dict and len(index['files'])==147,'original147 Setup5 records required')
        refs={name:dict(path=name,**ref) for name,ref in index['files'].items()}
        readme=root/'README.md';C.need(readme.is_file() and not readme.is_symlink() and readme.stat().st_size==345,
            'original Setup5 outer README required')
        refs['README.md']=dict(path='README.md',bytes=345,sha256=C.sha(readme))
    C.need(index_ref['path'] not in refs,'carrier index self-reference refused');refs[index_ref['path']]=index_ref
    C.need(len(refs)<=256 and sum(ref['bytes'] for ref in refs.values())<=64*1024**2,'finite public carrier closure required')
    return refs


def source_ref(root,ref):
    if ref.get('bytes')!=0:return C.checked(root,ref)
    C.need(set(ref)=={'path','bytes','sha256'} and type(ref['bytes']) is int and type(ref['path']) is str and
        not Path(ref['path']).is_absolute() and all(p not in ('','.','..') for p in ref['path'].split('/')) and
        ref['sha256']==hashlib.sha256(b'').hexdigest(),'exact empty original public record required')
    path=root/ref['path'];C.need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary empty public record path required')
    info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==0,'ordinary empty public record required')
    return path


def stage_packet(root,target,index_ref,setup_packet=False):
    refs=packet_refs(root,index_ref,setup_packet);C.need(not target.exists(),'fresh passive scratch packet required')
    # Validate all original operands before copying any packet data.
    paths={name:source_ref(root,ref) for name,ref in refs.items()};target.mkdir(mode=0o700)
    for name,path in paths.items():
        dest=target/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copyfile(path,dest);dest.chmod(0o600)
        source_ref(target,refs[name])
    return target


def retention(eight,seven,management,setup,welcome,legacy,policy):
    """Retain both native archives and all referenced public source/evidence bytes."""
    rows={};total=0
    def add(role,ref):
        nonlocal total
        key=(role,ref['path'])
        if key in rows:C.need(rows[key]['ref']==ref,'conflicting retention reference');return
        rows[key]=dict(root=role,ref=ref);total+=ref['bytes']
        C.need(len(rows)<=1024 and total<=64*1024**2,'complete public retention exceeds new604 cap')
    for role,root,index_ref,setup_packet in (
        ('eight_source',eight,policy['eight_pair_index'],False),
        ('management_source',management,policy['management']['packet_index'],False),
        ('setup_source',setup,policy['setup']['index'],True),
        ('welcome_source',welcome,policy['welcome']['index'],False)):
        refs=eight_refs(root,policy) if role=='eight_source' else packet_refs(root,index_ref,setup_packet)
        for ref in refs.values():source_ref(root,ref);add(role,ref)
    add('seven_source',policy['retained_seven_index'])
    for ref in policy['combined']['files'].values():add('legacy_source',ref)
    return [rows[key] for key in sorted(rows)]


def eight_refs(root,policy):
    """Original184-file carrier: exact index plus original report's public closure."""
    refs=packet_refs(root,policy['eight_pair_index'])
    row=C.read(C.checked(root,policy['eight_pair_index']))['packages']['cachy-asahi-fish-bang-bang']
    report=C.read(C.checked(root,row['evidence']));prefix='evidence/run38948569244/'
    C.need(row['evidence']['path']==prefix+'report.json' and len(report.get('public_files',{}))==49,
        'original eight-carrier public49 closure differs')
    def add(ref):
        previous=refs.setdefault(ref['path'],ref);C.need(previous==ref,'original eight carrier reference conflict');source_ref(root,ref)
    for name,pin in report['public_files'].items():add(dict(path=prefix+name,**pin))
    for ref in policy['prerequisites'].values():add(ref)
    add(dict(policy['retained_seven_index'],path='evidence/root/retained-seven-index.json'))
    # These two original outer records are not recursively named by index/report.
    # Keep their accepted carrier bytes explicit rather than scanning a checkout.
    for ref in (
        dict(path='evidence/root/input-receipt.json',bytes=1274,sha256='4742e94b6aef7382b27ba57beff3366273535eb89e7eb08d914acc2bcf62661d'),
        dict(path=prefix+'run-metadata.json',bytes=357,sha256='f3f8361a8208f70bd4aef272c7a00db3ba926d3c26ad97e8d823d7be52c81095')):add(ref)
    C.need(len(refs)==184,'original accepted184-file carrier closure differs')
    return refs


def validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy):
    require_welcome(policy)  # First: no source import, scratch directory or actor.
    previous=list(sys.path)
    try:return _validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy)
    finally:sys.path[:]=previous
