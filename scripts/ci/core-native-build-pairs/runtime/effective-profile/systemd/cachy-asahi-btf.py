#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One source-bound observed ARM64 BTF input; no host-BTF query or target authority."""
import argparse,base64,hashlib,json,math,os,re,selectors,signal,stat,struct,subprocess,time
from pathlib import Path
POLICY={'bytes': 65768, 'sha256': 'd28d901747a09b3473220a4c1fbe0ccf7dd2f9d777524bba41b08b66bf3ec973'}
RAW=dict(bytes=8430525,sha256='bb0d29de550d1cf6f63cbc8792f4ad75e1b1f9b4df2d480a1015749949e4d5a2');M=1024**2
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def obj(raw):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate JSON');v[k]=x
  return v
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(path,cap):
 p=Path(path).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary whole input');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink input');b=bytearray()
  while part:=os.read(fd,65536):b.extend(part);need(len(b)<=cap,'whole input byte cap')
  need(len(b)==a.st_size and KEY(a)==KEY(os.fstat(fd))==KEY(p.lstat()),'whole stable source bytes excluding atime');return bytes(b)
 finally:os.close(fd)
def file_hash(path,want):
 p=Path(path).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary complete source archive');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==want['bytes'],'whole source archive size');h=hashlib.sha256();n=0
  while part:=os.read(fd,M):n+=len(part);need(n<=want['bytes'],'bounded source archive');h.update(part)
  need(n==want['bytes']and h.hexdigest()==want['sha256']and KEY(a)==KEY(os.fstat(fd))==KEY(p.lstat()),'whole publisher source archive hash/identity');return dict(bytes=n,sha256=h.hexdigest())
 finally:os.close(fd)
def validate(root,source_archives=None):
 root=Path(root).absolute();raw=read(root/'vmlinux-input.json',M);need(pin(raw)==POLICY,'whole fixed BTF/source/license provenance');p=obj(raw);data=read(root/'vmlinux.btf',32*M);need(pin(data)==RAW==p['raw'],'whole original observed BTF input');need(p['status']=='SOURCE_BOUND_PREOBSERVED_RAW_BTF_BUILD_INPUT_ONLY'and p['authority']is False and p['source_bit_correspondence']=='NOT_ESTABLISHED_NO_REBUILD_CLAIM'and p['target_kernel']=='NOT_SELECTED'and p['hardware']=='NOT_RUN'and p['release']=='NOT_ADMITTED','honest source-only scope')
 magic,version,flags,size,off,length,strings,count=struct.unpack_from('<HBBIIIII',data);need(magic==0xeb9f and version==1 and flags==0 and size+off+length<=len(data)and size+strings+count==len(data)and data[size+strings]==data[-1]==0,'whole BTFv1 type/string sections')
 d=p['diagnostic'];r=d['receipt'];run=d['originals']['run.json'];jobs=d['originals']['jobs.json'];artifacts=d['originals']['artifacts.json'];c=d['originals']['collection.json'];pub=d['publication']['Root-committed-publication.json'];auth=d['publication']['source-authorization.json'];git=d['publication']['Root-git-source-authorization.json'];source='d14992a95966feb1bc4e957b3a55be3a01e876da';ref='codex/core-systemd-btf-diagnostic-v1';rid=39584141217
 need((d['source'],d['ref'],d['run'],d['attempt'],d['CI'],d['header'])==(source,ref,rid,1,'failure','ABSENT_NATIVE_HOST_WRAPPER_REFUSED'),'preserved actual capture failure; no invented header/native success');need((pub['source'],pub['ref'],pub['files'],pub['git_joins'],pub['status'],pub['actual'])==(source,ref,6,6,'COMMITTED_EXACT_CLOSED_TRIAL_SOURCE','NOT_RUN')and len(auth)==6 and git==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=source,ref=ref,files=auth),'whole genuine original6 source/Git join')
 need(run['id']==rid and run['head_sha']==source and run['head_branch']==ref and run['run_attempt']==1 and run['status']=='completed'and run['conclusion']=='failure'and run['workflow_id']==381664314 and run['repository']['full_name']=='Gabriel-Kahen/cachy-asahi','genuine exact terminal capture metadata');need(jobs['total_count']==len(jobs['jobs'])==1 and jobs['jobs'][0]['labels']==['ubuntu-24.04-arm']and jobs['jobs'][0]['conclusion']=='failure','whole original native capture job')
 need(artifacts['total_count']==len(artifacts['artifacts'])==1,'whole original one artifact role');a=artifacts['artifacts'][0];need(a['name']=='core-host-btf-input-'+str(rid)+'-1'and a['workflow_run']['id']==rid and a['workflow_run']['head_sha']==source and c['artifact_id']==a['id']and c['artifact']==dict(bytes=a['size_in_bytes'],sha256=a['digest'].removeprefix('sha256:'))and c['source']==source and c['ref']==ref and c['run']==rid and c['attempt']==1,'whole once artifact metadata/hash joins')
 originals={n:base64.b64decode(value,validate=True)for n,value in d['originals_bytes_base64'].items()};need(all(obj(raw)==d['originals'][n]for n,raw in originals.items())and c['metadata']=={n:pin(originals[n])for n in('run.json','jobs.json','artifacts.json')}and obj(base64.b64decode(d['receipt_base64'],validate=True))==r,'all whole original API metadata/receipt bytes')
 need(r['source']==source and r['run']==rid and r['attempt']==1 and r['source_files']==auth and r['status']=='INCOMPLETE_READ_ONLY_HOST_BTF_DIAGNOSTIC'and r['error']==dict(type='ValueError',message='root-owned native AArch64 ELF bpftool required; host wrapper not substituted')and r['BTF']==dict(path='/sys/kernel/btf/vmlinux',**RAW)and r['actual_authority']is False and r['host']['uname'][4]=='aarch64'and r['host']['uname'][2]=='7.0.0-1017-azure','authentic raw input retained before exact host wrapper refusal')
 proc=base64.b64decode(d['proc_version_base64'],validate=True);os_release=base64.b64decode(d['os_release_base64'],validate=True);need(r['files']=={'vmlinux.btf':RAW,'proc-version.txt':pin(proc),'os-release.txt':pin(os_release)}and b'7.0.0-1017-azure'in proc and b'#17~24.04.1-Ubuntu'in proc,'whole original raw/member/proc-version pins')
 u=p['ubuntu'];dsc=base64.b64decode(u['dsc_base64'],validate=True);need(b'Source: linux-azure-7.0\n'in dsc and b'Version: 7.0.0-1017.17~24.04.1\n'in dsc and b'Architecture: all amd64 arm64\n'in dsc and u['retrieval_authentication']=='PUBLISHER_HTTPS_AND_WHOLE_DSC_SHA256_NOT_FRESH_DSC_SIGNATURE_VERIFICATION','exact publisher source/version/architecture; no fresh signature claim');availability={}
 for n,want in u['source_archives'].items():
  need(re.fullmatch('linux-azure-7[.]0_[A-Za-z0-9.~+-]+[.](tar[.]gz|diff[.]gz)',n)and want['url']==u['publisher']+n and (want['sha256']+' '+str(want['bytes'])+' '+n).encode()in dsc and want['retrieved']=='WHOLE_BYTES_HASHED_AGAINST_EXACT_DSC','whole corresponding original source availability pin/URL/DSC join')
  availability[n]=file_hash(Path(source_archives)/n,want)if source_archives is not None else{k:want[k]for k in('bytes','sha256')}
 need(pin(read(root/'BTF-COPYING',65536))==u['copyright']and u['kernel_root_declared_license']=='GPL-2.0 WITH Linux-syscall-note; other source file licenses may also apply','whole original source license notices');return p,availability

def command(argv,deadline,cap):
 started=time.monotonic();p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);selector=selectors.DefaultSelector();data={'stdout':bytearray(),'stderr':bytearray()};code=None;error=None
 try:
  for n,stream in(('stdout',p.stdout),('stderr',p.stderr)):os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,n)
  while selector.get_map():
   need(time.monotonic()<deadline,'original package/90s BTF generation deadline')
   for key,_ in selector.select(.1):
    block=os.read(key.fd,65536)
    if not block:selector.unregister(key.fileobj)
    else:data[key.data].extend(block);need(sum(map(len,data.values()))<=cap,'bounded complete generator streams')
  code=p.wait(timeout=max(.01,deadline-time.monotonic()))
 except Exception as e:error=e
 finally:
  selector.close()
  for stream in(p.stdout,p.stderr):stream.close()
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  p.wait(timeout=5);code=p.returncode if code is None else code
 try:os.killpg(p.pid,0)
 except ProcessLookupError:retired=True
 else:retired=False
 result=dict(argv=argv,returncode=code,elapsed_seconds=time.monotonic()-started,combined_cap=cap,direct_child_reaped=True,group_retired=retired)
 if error:raise error
 need(code==0 and retired,'original pinned bpftool failed/retirement refusal');return {n:bytes(raw)for n,raw in data.items()},result

def generate(root,header,output,tool='/usr/bin/bpftool',source_archives=None):
 started=time.monotonic();deadline=started+90;root=Path(root).absolute();header=Path(header).absolute();output=Path(output).absolute();need(header.parent==root and header.name=='vmlinux.h'and not header.exists()and not output.exists(),'fresh fixed generated header and receipt');p,availability=validate(root,source_archives);tool=Path(tool).resolve();tool_raw=read(tool,32*M);need(tool_raw.startswith(b'\x7fELF')and tool.stat().st_uid==0 and not(tool.stat().st_mode&0o022),'original root-owned builder ELF bpftool');version,vr=command([str(tool),'version'],deadline,65536);need(version['stdout'].startswith(b'bpftool v7.8.0')and not version['stderr'],'existing pinned638 bpftool version');streams,role=command([str(tool),'btf','dump','file',str(root/'vmlinux.btf'),'format','c'],deadline,16*M);raw=streams['stdout'];need(not streams['stderr']and raw.startswith(b'#ifndef __VMLINUX_H__')and raw.rstrip().endswith(b'#endif /* __VMLINUX_H__ */')and b'preserve_access_index'in raw and b'enum lsm_integrity_type'in raw and b'LSM_INT_DMVERITY_SIG_VALID'in raw,'full provided CO-RE header with original LSM feature available');need(pin(read(tool,32*M))==pin(tool_raw)and pin(read(root/'vmlinux.btf',32*M))==RAW,'whole generator/input bytes held');need(time.monotonic()<deadline,'whole BTF generation90s original package sub-bound')
 with header.open('xb')as f:f.write(raw)
 artifact=output.parent/'systemd-vmlinux.h'
 with artifact.open('xb')as f:f.write(raw)
 for n,body in(('systemd-bpftool-version.stdout',version['stdout']),('systemd-bpftool-version.stderr',version['stderr']),('systemd-bpftool-dump.stderr',streams['stderr'])):
  with(output.parent/n).open('xb')as f:f.write(body)
 r=dict(schema=1,status='PASS_FIXED_BTF_FULL_HEADER_BUILD_INPUT_DATA_ONLY',input=RAW,provenance=POLICY,source_archives=availability,source_availability='PRIOR_COMPLETE_PUBLISHER_SOURCE_HASH_PROOF_NOT_REACQUIRED_IN_NATIVE_BUILDER',tool=dict(path=str(tool),**pin(tool_raw)),version=dict(role=vr,stdout=pin(version['stdout']),stderr=pin(version['stderr'])),header=dict(path='systemd-vmlinux.h',**pin(raw)),generator=dict(role=role,stdout=pin(raw),stderr=pin(streams['stderr'])),clock=dict(limit_seconds=90,elapsed_seconds=time.monotonic()-started),original_capture=dict(run=39584141217,source='d14992a95966feb1bc4e957b3a55be3a01e876da',CI='failure',original_header='ABSENT_WRAPPER_REFUSED'),bpf_features='UNCHANGED_ORIGINAL_PROVIDED_MODE_ALL_TESTS_REQUIRED',source_bit_correspondence='NOT_ESTABLISHED_NO_REBUILD_CLAIM',actual_authority=False,target_kernel='NOT_SELECTED',hardware='NOT_RUN',release='NOT_ADMITTED')
 with output.open('xb')as f:f.write(enc(r))
 return r
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--header',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args();need(os.getuid()>0 and os.getuid()==os.geteuid()and os.uname().machine in('aarch64','arm64')and os.environ.get('CORE_RECIPE')=='systemd'and os.environ.get('CACHY_ASAHI_CORE_CONTAINER')=='1','original ordinary native systemd builder only');print(enc(generate(a.root,a.header,a.receipt)).decode(),end='')
