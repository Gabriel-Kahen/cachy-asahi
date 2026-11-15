#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded inert ELF/real frozen-provider audit; no target loader/execution."""
import argparse,hashlib,importlib.util,json,os,posixpath,re,resource,signal,subprocess,tarfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('current_Xvfb_static_intake',HERE/'acquire.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C);P=C.I.P
E=P.load('held_static_ELF',P.ROOT/'scripts/platform/elf_audit.py');A=P.load('held_static_readelf',P.ROOT/'scripts/ci/glibc-gnu-provider/abi.py')
PROVIDERS={'libsystemd.so.0':'systemd-libs','libpixman-1.so.0':'pixman','libXfont2.so.2':'libxfont2','libXdmcp.so.6':'libxdmcp','libunwind.so.8':'libunwind','libm.so.6':'glibc','libnettle.so.9':'nettle','libtirpc.so.3':'libtirpc','libXau.so.6':'libxau','libGL.so.1':'libglvnd','libc.so.6':'glibc','ld-linux-aarch64.so.1':'glibc'}
def symbols(text):
    required=[];exports={}
    for line in text.splitlines():
        f=line.split()
        if len(f)<8 or f[4]not in ['GLOBAL','WEAK']or f[5]not in ['DEFAULT','PROTECTED']:continue
        name=f[7].replace('@@','@');entry={'name':name,'type':f[3],'binding':f[4],'visibility':f[5],'default_export':('@'not in f[7]or'@@'in f[7])}
        if f[6]=='UND':required.append(entry)
        else:exports[name]=entry
    return required,exports

def archive_library(path,soname):
    files={};links={};decoded=0
    with tarfile.open(path,'r|xz')as archive:
        for index,m in enumerate(archive):
            assert index<50000;decoded+=m.size;assert decoded<=128*1024**2
            name=m.name.removeprefix('./');assert not name.startswith('/')and '..'not in Path(name).parts
            if name.startswith('usr/lib/'+soname):
                if m.issym():links[name]=posixpath.normpath(posixpath.join(posixpath.dirname(name),m.linkname))
                elif m.isfile():assert m.size<=16*1024**2;files[name]=archive.extractfile(m).read()
    selected='usr/lib/'+soname
    for _ in range(16):
        if selected in files:return files[selected],selected
        assert selected in links;selected=links[selected]
    raise ValueError('bounded library link resolution refused')

def version_needs(text):
    active=False;current=None;result={}
    for line in text.splitlines():
        if line.startswith("Version needs section"):active=True
        if not active:continue
        file=re.search(r"File: ([^ ]+)",line)
        if file:current=file[1];result[current]=[]
        name=re.search(r"Name: ([^ ]+)",line)
        if name:
            assert current is not None;result[current].append(name[1])
    return result

def run(root,proposal,label):
    started=time.monotonic();out=root/label;out.mkdir(mode=0o700);current=json.loads((root/'acquisition.json').read_text());doc=json.loads(proposal.read_text());assert doc['metadata_prepare']['status']=='PASS_EXPLICIT_FINITE_METADATA_PREPARE';materials={r['name']:r for r in doc['materials']};contract=json.loads((HERE.parent/'inputs.json').read_text());base=json.loads((HERE.parent/'baseline111.json').read_text());baseline={r['name']:r['version']for r in base['packages']}
    prepared=json.loads(P.bound(contract['reference_prepared']));raw=Path(contract['reference_prepared']['path']).parent/'guest.raw';before=raw.stat();indexpath=Path('/tmp/cachy-asahi-arm16k-inputs-20261114/rootfs-index.json');index=json.loads(indexpath.read_text())['nodes'];assert raw.stat().st_size==1610612736
    with tarfile.open(current['objects'][0]['path'],'r|xz')as archive:
        for member in archive:
            if member.name.removeprefix('./')=='usr/bin/Xvfb':assert member.isfile()and member.size<4*1024**2;target=archive.extractfile(member).read();break
        else:raise ValueError('Xvfb absent')
    target_path=out/'Xvfb.inert';target_path.write_bytes(target);target_path.chmod(0o600);elf=E.parse_elf(target);assert elf['machine']==183
    required,_=symbols(A.readelf(target_path,'--dyn-syms'));needed_versions=version_needs(A.readelf(target_path,'--version-info'));all_exports={};providers=[]
    for soname in elf['needed']:
        name=PROVIDERS[soname];path=out/(soname+'.inert');source={}
        if name in baseline:
            selected='usr/lib/'+soname
            for _ in range(16):
                node=index[selected]
                if node['type']=='0':break
                assert node['type']in ['1','2'];link=node['link'];selected=posixpath.normpath(link.lstrip('/')if link.startswith('/')else posixpath.join(posixpath.dirname(selected),link));assert selected.startswith('usr/lib/')
            assert index[selected]['type']=='0'and index[selected]['bytes']<16*1024**2
            r=subprocess.run(['/usr/bin/debugfs','-R','dump /'+selected+' '+str(path),str(raw)],capture_output=True,timeout=5);assert r.returncode==0 and path.is_file()and path.stat().st_size==index[selected]['bytes'];data=path.read_bytes();source={'scope':'actual read-only prepared ARM111 filesystem provider','package':name,'version':baseline[name],'selected_path':selected,'reference_prepared':contract['reference_prepared'],'raw_fresh_full_hash':'NOT RUN; Root-retained descriptor custody, selected file bytes read only','rootfs_index_sha256':P.sha(indexpath)}
        else:
            row=materials[name];a=row['archive'];observed=next(o for o in row['observations']if o.get('PKGINFO_identity_and_dependencies')=='PASS');archive=Path(observed['path']);assert archive.stat().st_size==a['bytes']and P.sha(archive)==a['sha256'];data,selected=archive_library(archive,soname);path.write_bytes(data);source={'scope':'exact proposed archive provider; full SHA checked, new signature authentication not run here','package':name,'version':row['version'],'archive_sha256':a['sha256'],'selected_path':selected}
        path.chmod(0o600);meta=E.parse_elf(data);assert meta['machine']==183;_,exports=symbols(A.readelf(path,'--dyn-syms'));all_exports[soname]=exports;providers.append({'soname':soname,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'source':source,'ELF':meta,'exports':len(exports)})
    available={key for exports in all_exports.values()for key in exports};default_names={key.split('@')[0]for exports in all_exports.values()for key,value in exports.items()if value['default_export']};missing=[];weak=[]
    for symbol in required:
        name=symbol['name'];found=name in available if '@'in name else name in default_names
        if not found:(weak if symbol['binding']=='WEAK'else missing).append(symbol)
    namespace_holds=[]
    for library,versions in needed_versions.items():
        provided={name.split('@',1)[1]for name in all_exports[library]if '@'in name}
        for version in versions:
            if version not in provided:namespace_holds.append({'library':library,'missing_version':version})
    after=raw.stat();fields=['st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'];assert all(getattr(before,k)==getattr(after,k)for k in fields),'original raw changed'
    return {'status':'HOLD_DIRECT_STATIC_SCOPE_ONLY','scope':'actual candidate/direct12NEEDED providers and symbol/version names, no loader/execution','ELF':elf,'candidate_bytes':len(target),'candidate_sha256':hashlib.sha256(target).hexdigest(),'required_dynamic_symbols':len(required),'required_GLIBC_versions':sorted({s['name'].split('@')[1]for s in required if '@GLIBC_'in s['name']}),'missing_strong_symbols':missing,'unresolved_optional_weak_symbols':weak,'providers':providers,'direct_needed_providers':len(providers),'all_direct_symbols_found':not missing,'needed_version_namespaces':needed_versions,'missing_needed_version_namespaces':namespace_holds,'all_direct_16K_shapes':all(not p['ELF']['insufficient_declared_16K_alignment']and p['ELF']['static_16K_observation']=='load-congruence-observed'for p in providers),'original_raw_stable_identity_and_content_times':True,'original_raw_fresh_full_hash':'NOT RUN','transitive_provider_ABI':'HOLD; direct provider dynamic dependencies reported, complete transitive namespace/version/load audit not established','runtime_native_M2_release':'NOT RUN','seconds':time.monotonic()-started,'source_pins':{str(p.relative_to(P.ROOT)):{'bytes':p.stat().st_size,'sha256':P.sha(p)}for p in [P.ROOT/'scripts/platform/elf_audit.py',P.ROOT/'scripts/ci/glibc-gnu-provider/abi.py']}}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--proposal',type=Path,required=True);p.add_argument('--label',default='provider-static-audit-v2');a=p.parse_args();
    if not __debug__:p.error('assertions must remain enabled')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('120s static DATA limit')));signal.alarm(120)
    try:report=run(a.root,a.proposal,a.label)
    except Exception as error:report={'status':'HOLD_STATIC_DATA_REFUSAL','category':type(error).__name__,'reason':str(error)[:512]}
    finally:signal.alarm(0)
    (a.root/(a.label+'.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps({k:report.get(k)for k in ['status','direct_needed_providers','required_dynamic_symbols','all_direct_symbols_found','category','reason']}))
