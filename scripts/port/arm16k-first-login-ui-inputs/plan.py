#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite ARM111 UI metadata adapter. No network, daemon, install or guest."""
import argparse,ctypes,gc,hashlib,importlib.util,json,os,re,resource,stat,subprocess,sys,tarfile,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];MAX=16*1024**2

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def sha(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def bound(ref):
    p=Path(ref['path']);assert p.is_absolute()and not any(v.is_symlink()for v in [p,*p.parents])
    s=p.stat();assert stat.S_ISREG(s.st_mode)and 0<s.st_size==ref['bytes']<=MAX
    data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==ref['sha256'];return data

def package_metadata(path):
    class Prefix:
        def __init__(self,stream):self.stream=stream;self.count=0
        def read(self,size):
            assert 0<=size<=1024**2;data=self.stream.read(size);self.count+=len(data);assert self.count<=256*1024;return data
    with path.open('rb')as stream:
        counted=Prefix(stream)
        with tarfile.open(fileobj=counted,mode='r|*')as archive:
            decoded=0
            for index,member in enumerate(archive):
                assert index<16;decoded+=member.size;assert decoded<=256*1024
                if member.name.removeprefix('./')=='.PKGINFO':
                    assert member.isfile()and member.size<=128*1024
                    data=archive.extractfile(member).read();result={}
                    for line in data.decode().splitlines():
                        if not line or line.startswith('#'):continue
                        key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
                    return result,{'PKGINFO_sha256':hashlib.sha256(data).hexdigest(),'compressed_prefix_bytes_read':counted.count}
    raise ValueError('bounded PKGINFO absent')

def candidate(ref,parser):
    data=bound(ref['archive']);assert len(data)<=1024**2
    path=Path(ref['archive']['path']);meta,evidence=package_metadata(path);declared,_=parser.srcinfo(bound(ref['srcinfo']))
    fields={'NAME':'pkgname','VERSION':'pkgver','ARCH':'arch','DEPENDS':'depend','PROVIDES':'provides','CONFLICTS':'conflict','REPLACES':'replaces','LICENSE':'license'}
    for key,source in fields.items():assert sorted(declared.get(key,[]))==sorted(meta.get(source,[])), 'SRCINFO/PKGINFO mismatch: '+key
    assert meta['arch']==['any'],'project archive must explicitly declare any'
    signature=bound(ref['signature'])
    row={'name':meta['pkgname'][0],'version':meta['pkgver'][0],'repo':'project','arch':'any','depends':meta.get('depend',[]),'provides':meta.get('provides',[]),'conflicts':meta.get('conflict',[]),'replaces':meta.get('replaces',[]),'files':None,'hooks':None,'review':None,'archive':{'filename':path.name,'bytes':len(data),'sha256':ref['archive']['sha256'],'signature_bytes':len(signature),'signature_sha256':ref['signature']['sha256']},'licenses_declared':meta.get('license',[])}
    if 'retention'in ref:
        retention=json.loads(bound(ref['retention']));assert retention['bytes']==ref['archive']['bytes']and retention['sha256']==ref['archive']['sha256'];evidence['retention_reference']=ref['retention']
    return row,{'name':row['name'],'archive':ref['archive'],'signature':ref['signature'],'srcinfo':ref['srcinfo'],'scope':ref['scope'],'identity_arch_relations_hash_check':'PASS','signature_authentication':'NOT RUN in this metadata planner','source_build_native_acceptance':'HOLD',**evidence}

def anchor_rows(base):
    assert base['schema_version']==1 and len(base['packages'])==111 and len({p['name']for p in base['packages']})==111
    result=[]
    for row in base['packages']:
        d=row['desc'];assert d['NAME']==[row['name']]and d['VERSION']==[row['version']]and d['ARCH']in [['any'],['aarch64']]
        result.append({'name':row['name'],'version':row['version'],'repo':'signed-rootfs111','arch':d['ARCH'][0],'depends':d.get('DEPENDS',[]),'provides':d.get('PROVIDES',[]),'conflicts':d.get('CONFLICTS',[]),'replaces':d.get('REPLACES',[]),'archive':None,'files':None,'hooks':None,'review':None})
    return result

def retained(row,roots,small_limit):
    pin=row['archive'];observations=[]
    for directory in roots:
        path=Path(directory)/pin['filename']
        if not path.exists():continue
        item={'path':str(path),'archive_sha256_catalog_declaration':pin['sha256'],'fresh_full_archive_hash':'NOT RUN; no large archive rescan'};observations.append(item)
        try:
            assert path.is_file()and not path.is_symlink()and path.stat().st_size==pin['bytes'],'retained size mismatch'
            meta,details=package_metadata(path);assert meta['pkgname']==[row['name']]and meta['pkgver']==[row['version']]and meta['arch']==[row['arch']],'retained PKGINFO identity mismatch'
            assert sorted(meta.get('depend',[]))==sorted(row['depends']),'retained dependency declarations differ'
            item.update(details,PKGINFO_identity_and_dependencies='PASS')
            sig=path.with_name(path.name+'.sig')
            item['signature_pin_matches']=sig.is_file()and sig.stat().st_size==pin['signature_bytes']and sha(sig)==pin['signature_sha256']
            if pin['bytes']<=small_limit:
                assert sha(path)==pin['sha256'],'small archive SHA mismatch';item['fresh_full_archive_hash']='PASS small bounded archive'
            item['status']='RETAINED_DECLARED_INPUT_PENDING_AUTHENTICATION'if item['signature_pin_matches']else'HOLD_MISSING_OR_DIFFERENT_SIGNATURE'
        except Exception as error:item.update(status='HOLD_RETAINED_REFUSAL',reason=type(error).__name__)
    return observations

def prepare_proposal(anchors,additions):
    def metadata(row):
        value={'NAME':[row['name']],'VERSION':[row['version']],'ARCH':[row['arch']]}
        for source,key in [('depends','DEPENDS'),('provides','PROVIDES'),('conflicts','CONFLICTS'),('replaces','REPLACES')]:value[key]=row[source]
        if row.get('archive'):
            a=row['archive'];value.update(FILENAME=[a['filename']],CSIZE=[str(a['bytes'])],SHA256SUM=[a['sha256']])
        return value
    catalogs={}
    for row in additions:catalogs.setdefault(row['repo'],{})[row['name']]=metadata(row)
    value={'image':{r['name']:metadata(r)for r in anchors},'catalogs':catalogs,'targets':[{k:r[k]for k in ['name','version','repo']}for r in additions]}
    # The full catalogs are gone before this explicit finite proposal is copied.
    gc.collect();libc=ctypes.CDLL(None);libc.malloc_trim.argtypes=[ctypes.c_size_t];libc.malloc_trim(0)
    size=int(next(line.split()[1]for line in Path('/proc/self/status').read_text().splitlines()if line.startswith('VmSize:')))*1024
    if size>152*1024**2:return {'status':'HOLD_PREPARE_MEMORY_BUDGET','parent_virtual_bytes':size}
    old_limits=resource.getrlimit(resource.RLIMIT_AS);resource.setrlimit(resource.RLIMIT_AS,(160*1024**2,old_limits[1]))
    try:
        with tempfile.TemporaryDirectory(prefix='private-ARM111-UI-metadata-')as directory:
            path=Path(directory)/'proposal.json';path.write_text(json.dumps(value));assert path.stat().st_size<=2*1024**2
            result=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare_metadata.py'),str(path)],capture_output=True,timeout=40)
            assert len(result.stdout)+len(result.stderr)<=1024**2
            if result.returncode:return {'status':'HOLD_PREPARE_REFUSAL','exit':result.returncode,'diagnostic':result.stdout.decode(errors='replace')[:1024],'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()}
            report=json.loads(result.stdout);prepared=report['prepare'];report['status']='PASS_EXPLICIT_FINITE_METADATA_PREPARE'if all(d['provider']is not None for d in report['dependencies'])and prepared['prepare_exit']==0 and not prepared['errors']and not prepared['callback_errors']and not any('unapproved'in q['policy']for q in prepared['questions'])and not report['conflicts']else'HOLD_METADATA_PREPARE'
            return report
    finally:resource.setrlimit(resource.RLIMIT_AS,old_limits)

def run(contract):
    assert contract['schema_version']==1 and contract['memory_limit_bytes']==256*1024**2
    for name,pin in contract['engine_sources'].items():assert name in {'scripts/port/platform-residual-closure/resolve.py','scripts/platform/transaction.py','scripts/port/preview.py','scripts/port/supported-composition/compose.py'}and(ROOT/name).stat().st_size==pin['bytes']and sha(ROOT/name)==pin['sha256'],'existing engine source drift'
    assert len(contract['engine_sources'])==4
    R=load('existing_ARM_UI_resolver',ROOT/'scripts/port/platform-residual-closure/resolve.py');P=load('existing_ARM_UI_srcinfo',ROOT/'scripts/port/supported-composition/compose.py')
    baseline_ref={**contract['baseline'],'path':str((HERE/contract['baseline']['filename']).resolve())};base=json.loads(bound(baseline_ref));anchors=anchor_rows(base);protected={r['name']:r['version']for r in anchors};catalog=[];diagnostics=[];started=time.monotonic()
    prepared=json.loads(bound(contract['reference_prepared']));assert {r['name']:r['version']for r in prepared['base_packages']}==protected,'exact111 reference manifest mismatch'
    selection=json.loads(bound(base['source_selection']));assert {r['name']:r['version']for r in selection['packages']}==protected
    paths=set(selection['paths']);required={'dbus-daemon':'dbus','dbus-run-session':'dbus','loginctl':'systemd','systemctl':'systemd','getopt':'util-linux','mktemp':'coreutils','ldconfig':'glibc','python3':'python','fish':'fish','zsh':'zsh','Xvfb':'xorg-server-xvfb','xvfb-run':'xorg-server-xvfb','xauth':'xorg-xauth','pkttyagent':'polkit'}
    namespace=[{'program':'/usr/bin/'+name,'baseline_selected_path':('usr/bin/'+name)in paths,'expected_provider':provider,'executable_resolution':'not re-audited; future full namespace check required'}for name,provider in required.items()];del selection,paths
    rootfs_provenance=json.loads(bound(contract['rootfs_input_manifest']));assert rootfs_provenance['material_files']['rootfs.tar.gz']['sha256']==base['rootfs_sha256']
    assert [r['repo']for r in contract['catalogs']]==['core','extra']
    for ref in contract['catalogs']:
        grouped,unavailable=R.read_catalog(bound(ref),ref['repo'],time.monotonic()+30);rows=R.catalog_packages(grouped,ref['repo'],ref);catalog.extend(rows);diagnostics.extend({'repo':ref['repo'],'entry':v,'reason':'sparse-unavailable'}for v in unavailable);del grouped,rows;gc.collect()
    projects=[]
    for ref in contract['project']:
        row,evidence=candidate(ref,P);catalog.append(row);projects.append(evidence)
    key_material=[]
    for ref in contract['public_key_material']:
        bound(ref);key_material.append({**ref,'authentication_or_freshness':'NOT RUN; public bytes only, no import/trust change'})
    template_data=[]
    for ref in contract['template_data']:
        bound(ref);meta,evidence=package_metadata(Path(ref['path']));assert meta['arch']==['any']
        template_data.append({**ref,**evidence,'declared_name':meta['pkgname'],'declared_version':meta['pkgver'],'scope':'explicit private template DATA only; not package install roots or ARM runtime acceptance'})
    roots=[]
    for name in contract['root_names']:
        matches=[r for r in catalog if r['name']==name];assert len(matches)==1,'exact root missing/ambiguous: '+name;roots.append(R.identity(matches[0]))
    result=R.resolve(anchors,catalog,roots,protected,limits=R.Limits(max_packages=512,max_seconds=30))
    selected=result['selected'];graph_blockers=[r for r in result['blockers']if r.get('scope')not in ['custody','ownership','hooks','review']]
    additions=[r for r in selected if r['name']not in protected];preserved={r['name']:r['version']for r in selected if r['name']in protected};assert preserved==protected,'baseline drift refused'
    del catalog;gc.collect()
    materials=[]
    for row in additions:
        if row['repo']=='project':observed=[next(p for p in projects if p['name']==row['name'])]
        else:observed=retained(row,contract['cache_directories'],contract['small_archive_rehash_limit'])
        materials.append({'name':row['name'],'version':row['version'],'repo':row['repo'],'arch':row['arch'],'archive':row['archive'],'depends':row['depends'],'licenses_declared':row.get('licenses_declared',[]),'observations':observed,'availability':'MISSING'if not observed else'RETAINED_PENDING_AUTHENTICATION'if row['repo']=='project'or any(o.get('status')=='RETAINED_DECLARED_INPUT_PENDING_AUTHENTICATION'for o in observed)else'HOLD_RETAINED_INPUT','ELF16K_ABI_runtime_source_license':'HOLD; not inferred from arch or metadata'})
    native_prepare=prepare_proposal(anchors,additions)
    config=bound(contract['kernel_config']).decode();capabilities={key:bool(re.search(r'(?m)^'+key+r'=[ym]$',config))for key in ['CONFIG_VT','CONFIG_VT_CONSOLE','CONFIG_INPUT_EVDEV','CONFIG_DRM_VIRTIO_GPU','CONFIG_VIRTIO_INPUT']}
    return {'schema_version':1,'status':'HOLD_METADATA_PLAN_ONLY','scope':contract['scope'],'metadata_graph_status':result['metadata_graph_status'],'explicit_finite_libalpm_prepare':native_prepare,'proposal_dependency_status':native_prepare['status']if all(r['status']=='SELECTED'for r in result['roots'])else'HOLD_REQUIRED_ROOT_PIN','required_namespace_metadata':namespace,'baseline_count':111,'preserved_baseline_count':len(preserved),'addition_candidates':len(additions),'proposed_total':111+len(additions),'roots':roots,'explicit_reference_providers':contract['explicit_reference_providers'],'graph_blockers':graph_blockers,'conservative_graph_note':'existing graph treats inherited named-package/provides overlaps conservatively; finite libalpm result stays separate; excluded catalog rows remain holds','catalog_diagnostics':diagnostics,'edges':result['edges'],'materials':materials,'project_archive_checks':projects,'public_key_material':key_material,'template_data':template_data,'missing_archives':[r['archive']for r in materials if r['availability']=='MISSING'],'declared_addition_archive_bytes':sum(r['archive']['bytes']for r in materials),'rootfs_custody':{'rootfs_sha256':base['rootfs_sha256'],'per_package_archives':'not independently authenticated; installed records inherited from signed whole rootfs'},'kernel_declarations':capabilities,'tool_and_ABI_gaps':['actual archive/signature/ELF16K ABI/runtime acceptance remains pending','current kernel lacks virtio-input declaration; x86 ATkbd/seat0 proof does not transfer']if not capabilities['CONFIG_VIRTIO_INPUT']else['actual ARM seat0/input path NOT RUN'],'holds':['metadata-only plan, not a complete accepted transaction','all111 baseline versions frozen; no coordinated update authorized','full archive/signature checks pending for retained large inputs; no acquisition','every new ELF16K geometry/dynamic ABI/runtime/source/license review remains held','payload ownership/file-conflict/scriptlet/normal-hook inspection NOT RUN by metadata preparation','generic Mesa here is only a TCG reference dependency, not an Asahi/M2 selection','Xvfb GUI/stock DBus/Polkit/session tools require separately admitted actual ARM execution','current production trust/freshness/native16K/M2/release NOT RUN'],'resolver_source_sha256':sha(ROOT/'scripts/port/platform-residual-closure/resolve.py'),'seconds':time.monotonic()-started,'memory_limits':list(resource.getrlimit(resource.RLIMIT_AS)),'memory_budget_phases':{'serial_parent_AS_bytes':256*1024**2,'concurrent_parent_AS_bytes':160*1024**2,'prepare_child_AS_bytes':96*1024**2},'proc_memory':{k:int(v.split()[0])*1024 for k,v in (line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if line.startswith(('VmPeak:','VmHWM:','VmRSS:','VmSize:')))},'network_download_daemon_guest_install':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--contract',type=Path,default=HERE/'inputs.json');parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if not __debug__:parser.error('assertions must remain enabled')
    assert a.contract.is_file()and not a.contract.is_symlink()and a.contract.stat().st_size<=1024**2
    contract=json.loads(a.contract.read_text());a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    try:report=run(contract)
    except Exception as error:report={'status':'HOLD_INPUT_OR_RESOURCE_REFUSAL','category':type(error).__name__,'message':str(error)[:512],'network_download_daemon_guest_install':False}
    report['contract_reference']={'path':str(a.contract.resolve()),'bytes':a.contract.stat().st_size,'sha256':sha(a.contract)}
    (a.output/'plan.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:report.get(k)for k in ['status','metadata_graph_status','baseline_count','addition_candidates','proposed_total','proc_memory','category','message']}));return 2 if report['status']=='HOLD_METADATA_PLAN_ONLY'else 1
if __name__=='__main__':raise SystemExit(main())
