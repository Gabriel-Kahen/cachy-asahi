#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only ARM64 host BTF/header DATA export; never a package or target acceptance."""
import argparse,hashlib,json,os,re,selectors,shutil,signal,stat,struct,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;M=1024**2
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(path,cap):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary no-alias source/input');fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink file');raw=bytearray()
  while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=cap,'whole input byte cap')
  need(len(raw)==a.st_size and KEY(a)==KEY(os.fstat(fd))==KEY(path.lstat()),'stable whole input bytes/identity excluding atime');return bytes(raw)
 finally:os.close(fd)
def save(path,raw):
 with Path(path).open('xb')as f:f.write(raw)
def command(argv,deadline,cap):
 started=time.monotonic();p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C',TZ='UTC'),cwd='/');streams={'stdout':bytearray(),'stderr':bytearray()};selector=selectors.DefaultSelector();group=p.pid
 try:
  for n,s in(('stdout',p.stdout),('stderr',p.stderr)):os.set_blocking(s.fileno(),False);selector.register(s,selectors.EVENT_READ,n)
  while selector.get_map():
   need(time.monotonic()<deadline,'original whole diagnostic deadline')
   for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
    raw=os.read(key.fd,65536)
    if not raw:selector.unregister(key.fileobj)
    else:streams[key.data].extend(raw);need(sum(map(len,streams.values()))<=cap,'combined bounded read-only child streams')
  returncode=p.wait(timeout=max(.01,deadline-time.monotonic()))
 finally:
  selector.close()
  for s in(p.stdout,p.stderr):s.close()
  try:os.killpg(group,signal.SIGKILL)
  except ProcessLookupError:pass
  p.wait(timeout=5)
 try:os.killpg(group,0)
 except ProcessLookupError:retired=True
 else:retired=False
 need(retired,'read-only command process group retired');return {n:bytes(raw)for n,raw in streams.items()},dict(argv=argv,returncode=returncode,direct_child_reaped=True,group_retired=retired,elapsed_seconds=time.monotonic()-started,combined_cap=cap)
def source():
 raw=read(HERE/'source-manifest.json',M);p=json.loads(raw);actual={}
 for q in HERE.rglob('*'):
  if q.relative_to(HERE).parts[0]=='.git':continue
  need(not q.is_symlink()and(q.is_file()or q.is_dir()),'ordinary diagnostic source')
  if q.is_file():actual[q.relative_to(HERE).as_posix()]=pin(read(q,2*M))
 allowed=set(p['files'])|{'source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/core-systemd-btf-diagnostic.yml'};need(set(actual)==allowed and all(actual[n]==row for n,row in p['files'].items()),'whole closed diagnostic source before host read')
 for n in('.github/workflows/native-arm-build.yml','.github/workflows/core-systemd-btf-diagnostic.yml'):need(read(HERE/n,65536).count(pin(raw)['sha256'].encode())==1,'whole manifest stamp')
 need(read(HERE/'.github/workflows/native-arm-build.yml',65536)==read(HERE/'.github/workflows/core-systemd-btf-diagnostic.yml',65536),'exact diagnostic workflow alias');return actual

def capture(output,source_sha,run,attempt):
 started=time.monotonic();deadline=started+180;output=Path(output).absolute();need(output.parent.is_dir()and not output.exists()and not any(q.is_symlink()for q in(output,*output.parents)),'fresh separate owned output');output.mkdir(mode=0o700);fact=dict(status='INCOMPLETE_READ_ONLY_HOST_BTF_DIAGNOSTIC',actual_authority=False,native_package='NOT_RUN',target_kernel='NOT_SELECTED',hardware='NOT_RUN',release='NOT_ADMITTED',run=run,source=source_sha,attempt=attempt,limit_seconds=180)
 try:
  fact['source_files']=source();env=os.environ;need(re.fullmatch('[a-f0-9]{40}',source_sha)and env.get('GITHUB_SHA')==env.get('SOURCE_SHA')==source_sha and env.get('GITHUB_RUN_ID')==str(run)and env.get('GITHUB_RUN_ATTEMPT')==str(attempt)and attempt==1 and run>0,'exact supplied source/run first attempt');need(os.uname().sysname=='Linux'and os.uname().machine in('aarch64','arm64')and env.get('GITHUB_ACTIONS')=='true'and env.get('RUNNER_ARCH')=='ARM64'and env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and env.get('GITHUB_JOB')=='native','source-owned real ARM64 workflow context')
  fact['host']=dict(uname=list(os.uname()),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),kernel_btf_scope='EXPOSED_RUNNING_HOST_KERNEL_ONLY_NOT_ASAHI_OR_TARGET',wall_time_UTC=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
  for n,p in(('proc-version.txt','/proc/version'),('os-release.txt','/etc/os-release')):
   raw=Path(p).read_bytes();need(len(raw)<=65536,'bounded host description');save(output/n,raw)
  btf=read('/sys/kernel/btf/vmlinux',32*M);need(len(btf)>24 and btf[:2]==b'\x9f\xeb'and btf[2]==1,'actual little endian BTFv1');save(output/'vmlinux.btf',btf);fact['BTF']=dict(path='/sys/kernel/btf/vmlinux',**pin(btf))
  found=shutil.which('bpftool',path='/usr/sbin:/usr/bin:/sbin:/bin');need(found is not None,'native host bpftool missing; raw BTF retained, no install/fallback');candidates=[Path(found).resolve()];kernel=os.uname().release
  candidates += [Path('/usr/lib/linux-tools')/kernel/'bpftool']
  tools=[]
  for p in candidates:
   if p.exists():
    p=p.resolve();raw=read(p,32*M);s=p.stat()
    if raw[:4]==b'\x7fELF'and len(raw)>20 and struct.unpack_from('<H',raw,18)[0]==183 and s.st_uid==0 and not(s.st_mode&0o022):tools.append((p,raw))
  need(tools,'root-owned native AArch64 ELF bpftool required; host wrapper not substituted');tool,tool_raw=tools[0];fact['tool']=dict(path=str(tool),**pin(tool_raw));streams,version=command([str(tool),'version'],deadline,65536)
  for n,b in streams.items():save(output/('bpftool-version.'+n),b)
  fact['version_command']=version;need(version['returncode']==0,'bpftool version failed');streams,role=command([str(tool),'btf','dump','file',str(output/'vmlinux.btf'),'format','c'],deadline,16*M);save(output/'bpftool-dump.stderr',streams['stderr']);need(role['returncode']==0 and not streams['stderr']and streams['stdout'].startswith(b'#ifndef __VMLINUX_H__')and b'preserve_access_index'in streams['stdout'],'complete generated original bpftool C header');save(output/'vmlinux.h',streams['stdout']);fact['header_command']=role;fact['header']=pin(streams['stdout']);need(pin(read(tool,32*M))==pin(tool_raw),'whole tool identity/bytes unchanged')
  dpkg=Path('/usr/bin/dpkg-query');need(dpkg.is_file(),'native host package provenance query required');queries=[('tool-package-owner',['-S',str(tool)]),('kernel-package',['-W','-f=${binary:Package}\t${Version}\t${Architecture}\n','linux-image-'+kernel])]
  for label,args in queries:
   try:
    streams,role=command([str(dpkg),*args],deadline,65536);fact[label]=role
    for stream,body in streams.items():save(output/(label+'.'+stream),body)
   except Exception as e:fact[label]=dict(status='NOT_ESTABLISHED',error=str(e))
  copyrights=[]
  for p in(Path('/usr/share/doc/linux-tools-common/copyright'),Path('/usr/share/doc')/('linux-image-'+kernel)/'copyright'):
   if p.exists():
    real=p.resolve();raw=read(real,M);n='copyright-'+str(len(copyrights))+'.txt';save(output/n,raw);copyrights.append(dict(requested=str(p),resolved=str(real),file=n,**pin(raw)))
  fact['license']=dict(classification='GENERATED_KERNEL_TYPE_DECLARATIONS_INPUT_DATA_ONLY_REQUIRES_ORIGINAL_KERNEL_SOURCE_LICENSE_JOIN_BEFORE_REUSE',source='RUNNING_HOST_BTF_NOT_PINNED_UPSTREAM_KERNEL_SOURCE',host_copyrights=copyrights,wrapper_license='MIT_ONLY_WRAPPER_NOT_KERNEL_DATA')
  fact['status']='PASS_READ_ONLY_NATIVE_HOST_BTF_AND_FULL_HEADER_DATA_NO_TARGET_AUTHORITY'
 except Exception as e:fact['error']=dict(type=type(e).__name__,message=str(e))
 fact['elapsed_seconds']=time.monotonic()-started;fact['files']={p.name:pin(read(p,32*M))for p in output.iterdir()if p.is_file()};save(output/'receipt.json',enc(fact));return fact
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--run',type=int,required=True);p.add_argument('--attempt',type=int,required=True);a=p.parse_args();fact=capture(a.output,a.source,a.run,a.attempt);print(json.dumps(fact,sort_keys=True));raise SystemExit(0 if fact['status'].startswith('PASS_')else 1)
