# SPDX-License-Identifier: MIT
"""One explicit Ubuntu24/arm64 CI prerequisite; caller owns all supervision.

No action on import. This does not install project packages or target-system tools.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import time

KIND='UBUNTU24_ARM64_LIBARCHIVE_TOOLS_CI_PREREQUISITE_V1'
PACKAGE='libarchive-tools'
CI_TOOLS=('apt-get','apt-cache','dpkg','dpkg-query')
DECLARATION=dict(kind=KIND,package=PACKAGE,distribution='ubuntu',version='24.04',architecture='arm64',
 seconds=450,commands=9,address_space_bytes=512*1024**2,cache_bytes=512*1024**2,cache_nodes=4096,file_bytes=128*1024**2,
 command_output_bytes=1024**2,update_seconds=120,query_seconds=15,simulation_seconds=30,
 download_seconds=90,install_seconds=120,retries=0,normal_repository_signatures=True,
 repository_key_trust_changes=False,normal_dependencies_and_hooks=True)
CACHE='ci-prerequisite-cache'
FORMAT='${binary:Package}\t${Status}\t${Version}\t${Architecture}\n'
APT_FIXED=['-o','Acquire::Retries=0','-o','Acquire::http::Timeout=15','-o','Acquire::https::Timeout=15',
 '-o','APT::Update::Error-Mode=any','-o','Acquire::AllowInsecureRepositories=false',
 '-o','Acquire::AllowDowngradeToInsecureRepositories=false','-o','APT::Get::AllowUnauthenticated=false',
 '-o','APT::Get::allow-Downgrades=false','-o','APT::Get::allow-Change-Held-Packages=false',
 '-o','Acquire::Check-Valid-Until=true']

def need(ok,message):
 if not ok:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def context(env,machine,release,uid):
 need(uid==0 and machine in('aarch64','arm64')and env.get('GITHUB_ACTIONS')=='true'and env.get('RUNNER_OS')=='Linux'and
  env.get('RUNNER_ARCH')=='ARM64'and env.get('ImageOS')=='ubuntu24'and env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and
  env.get('GITHUB_EVENT_NAME')=='workflow_dispatch','explicit native Ubuntu24 GitHub CI controller only')
 values={}
 for line in release.decode().splitlines():
  if '='in line:
   key,value=line.split('=',1);values[key]=value.strip('"')
 need(values.get('ID')=='ubuntu'and values.get('VERSION_ID')=='24.04','literal Ubuntu24.04 prerequisite; no host/Asahi fallback')
def public_file(path,root,uid):
 path=path.resolve(strict=True);need(path==root or root in path.parents,'public configuration stays within selected root')
 before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_uid==uid and not before.st_mode&0o022 and before.st_nlink==1 and 0<=before.st_size<=2*1024**2,'ordinary root-owned bounded public configuration')

 for parent in (path.parent,*path.parent.parents):
  if parent!=root and root not in parent.parents:continue
  info=parent.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==uid and not info.st_mode&0o022,'root-owned non-writable public configuration ancestors')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
  need(identity(before)==identity(os.fstat(fd)),'same public configuration descriptor')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(2*1024**2+1)
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'public configuration stable');return raw
 finally:os.close(fd)


def trust_snapshot(root=Path('/'),uid=0):
 root=Path(root);names=('etc/apt/sources.list','etc/apt/sources.list.d','etc/apt/trusted.gpg','etc/apt/trusted.gpg.d','etc/apt/apt.conf','etc/apt/apt.conf.d','usr/share/keyrings')
 rows={};total=0
 for name in names:
  path=root/name
  if not path.exists():continue
  pending=[path];visited=0
  while pending:
   leaf=pending.pop();visited+=1;need(visited<=1024,'bounded public APT configuration nodes')
   if leaf.is_dir()and not leaf.is_symlink():
    with os.scandir(leaf)as entries:
     for entry in entries:
      need(visited+len(pending)<1024,'bounded pending public configuration nodes');pending.append(Path(entry.path))
    continue
   need(not leaf.is_symlink(),'no public APT configuration alias')
   raw=public_file(leaf,root,uid);relative=leaf.relative_to(root).as_posix();rows[relative]=pin(raw);total+=len(raw)
   need(len(rows)<=1024 and total<=16*1024**2,'bounded public repository/key/trust configuration')
   if relative.startswith('etc/apt/'):
    need(not re.search(rb'(?im)(?:(?:trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*=\s*(?:yes|true|1)|^\s*(?:Trusted|Allow-Insecure|Allow-Weak|Allow-Downgrade-To-Insecure)\s*:\s*(?:yes|true|1)\b|AllowUnauthenticated\s+["\']?(?:true|1)|AllowInsecureRepositories\s+["\']?(?:true|1)|AllowDowngradeToInsecureRepositories\s+["\']?(?:true|1))',raw),'normal APT signature policy; insecure source/config refused')
 need(any(n.startswith('etc/apt/sources.list')for n in rows)and any(n.startswith(('usr/share/keyrings/','etc/apt/trusted.gpg'))for n in rows),'existing normal repository and public key configuration required')
 return rows

def cache_census(path,deadline,limits,retiring=False):
 need(time.monotonic()<deadline,'finite prerequisite wall budget')
 path=Path(path);need(path.name==CACHE and path.is_absolute()and path==path.resolve()and not path.is_symlink(),'fixed owned prerequisite cache')
 count=0;size=0
 if not path.exists():return dict(nodes=0,allocated_bytes=0)
 pending=[path]
 while pending:
  leaf=pending.pop();need(time.monotonic()<deadline,'finite prerequisite census/cleanup')
  info=leaf.lstat();count+=1;size+=info.st_blocks*512
  need(not leaf.is_symlink()and(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode)and info.st_nlink==1),'ordinary owned APT cache nodes only')
  need(count<=limits['cache_nodes']and(retiring or size<=limits['cache_bytes']),'bounded prerequisite cache allocation/nodes')
  if stat.S_ISDIR(info.st_mode):
   with os.scandir(leaf)as entries:
    for entry in entries:
     need(len(pending)+count<limits['cache_nodes'],'bounded pending prerequisite cache nodes');pending.append(Path(entry.path))

 return dict(nodes=count,allocated_bytes=size)

def candidate(raw):
 rows=re.findall(rb'^\s*Candidate:\s*(\S+)\s*$',raw,re.M);need(len(rows)==1,'one actual libarchive-tools candidate before install')
 value=rows[0].decode('ascii');need(re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}',value)and value!='(none)','literal selected libarchive-tools version')
 return value

def installed(raw,version):
 rows=raw.decode('ascii').splitlines();need(len(rows)==1,'one actual selected package state')
 fields=rows[0].split('\t');need(fields==[PACKAGE,'install ok installed',version,'arm64'],'exact installed libarchive-tools version/architecture/state')
 return dict(package=PACKAGE,state=fields[1],version=version,architecture='arm64')

def cleanup(out,deadline,limits):
 path=Path(out)/CACHE
 if not path.exists()and not path.is_symlink():return True
 cache_census(path,deadline,limits,retiring=True)
 # No links/special nodes were admitted, and this is the one new fixed cache.
 shutil.rmtree(path);need(not path.exists(),'owned prerequisite cache absent');return True


def prepare(owner,env,machine,root=Path('/'),uid=0):
 """Reusable literal-package API: bounded run_prerequisite + fresh tool observer.

 root/uid are inert test seams; operational caller supplies no overrides.
 """
 limits=owner.policy['host_prerequisites'];need(limits==DECLARATION,'separately Root-admitted exact CI prerequisite proposal')
 root=Path(root);release=public_file(root/'etc/os-release',root,uid);context(env,machine,release,uid)
 trust=trust_snapshot(root,uid);end=min(owner.end,time.monotonic()+limits['seconds']);calls=0
 report=dict(kind=KIND,status='STARTED_NO_NATIVE_ACCEPTANCE',package=PACKAGE,Root_acceptance=None,selected_version=None,
  installed=None,repository_key_trust_before=trust,commands=[],cache_absent=False)
 owner.prerequisite=report
 before=owner.H.probe_all();need(set(before['missing_or_invalid'])<={'bsdtar'},'other host prerequisites must already be valid; no generalized installer')
 report['tools_before']=before
 prior={n:row['selected']for n,row in before['tools'].items()if row['selected']is not None}
 def refresh():
  facts=owner.H.probe_all();tools={n:row['selected']for n,row in facts['tools'].items()if row['selected']is not None}
  for name in CI_TOOLS:tools[name]=owner.H.inspect('/usr/bin/'+name)
  owner.tools=tools;return facts
 refresh();ci_before={n:dict(bytes=owner.tools[n]['bytes'],sha256=owner.tools[n]['sha256'])for n in CI_TOOLS}
 cache=owner.out/CACHE;need(not cache.exists(),'fresh fixed APT cache');cache.mkdir(mode=0o755)
 for name in('lists','archives'):(cache/name).mkdir(mode=0o755)
 opts=['-o','Dir::State::lists='+str(cache/'lists'),'-o','Dir::Cache::archives='+str(cache/'archives'),
  '-o','Dir::Cache::pkgcache='+str(cache/'pkgcache.bin'),'-o','Dir::Cache::srcpkgcache='+str(cache/'srcpkgcache.bin')]
 def run(name,args,seconds,check=True):
  nonlocal calls
  calls+=1;need(calls<=limits['commands'],'finite prerequisite command count');cache_census(cache,end,limits)
  code,raw=owner.run_prerequisite([owner.tool(name),*args],seconds,check,end,cache,limits)
  report['commands'].append(dict(name=name,argv=[owner.tools[name]['path'],*args],exit=code,output=pin(raw)))
  need(trust_snapshot(root,uid)==trust,'repository/key/trust configuration unchanged')
  return code,raw
 _,raw=run('dpkg',['--print-architecture'],15);need(raw.strip()==b'arm64','actual dpkg arm64 host architecture')
 code,raw=run('dpkg-query',['-W','--showformat='+FORMAT,PACKAGE],15,False);need(code in(0,1),'normal initial package query only');report['initial_package_query']=dict(exit=code,output=pin(raw))
 run('apt-get',[*APT_FIXED,*opts,'update'],120)
 _,raw=run('apt-cache',[*opts,'policy',PACKAGE],15);version=candidate(raw);report['selected_version']=version
 owner.record_prerequisite(report) # Exact selected candidate is durable BEFORE download/install.
 install=['--yes','--no-remove','--no-install-recommends','install',PACKAGE+'='+version]
 run('apt-get',[*APT_FIXED,*opts,'--simulate',*install],30)
 run('apt-get',[*APT_FIXED,*opts,'--download-only',*install],90)
 run('apt-get',[*APT_FIXED,*opts,'--no-download',*install],120)
 # Installation changes /usr directory metadata; every subsequent executable is
 # freshly observed, never repaired by changing an old observation in place.
 after=refresh()
 for name,pin_before in ci_before.items():need({k:owner.tools[name][k]for k in('bytes','sha256')}==pin_before,'APT/dpkg executable body unchanged by the one prerequisite')
 for name,row in prior.items():
  if name!='bsdtar':need(after['tools'][name]['selected']is not None and all(after['tools'][name]['selected'][k]==row[k]for k in('path','bytes','sha256')),'preexisting host executable body unchanged')
 _,raw=run('dpkg-query',['-W','--showformat='+FORMAT,PACKAGE],15);report['installed']=installed(raw,version)
 need(not after['missing_or_invalid'],'all13 host tools freshly present after explicit setup')
 _,raw=run('bsdtar',['--version'],15);need(raw.startswith(b'bsdtar '),'actual libarchive bsdtar program, no tar substitute')
 report.update(tools_after=after,bsdtar_version_output=pin(raw),
  repository_key_trust_after=trust_snapshot(root,uid))
 report['cache_absent']=cleanup(owner.out,end,limits);report['status']='PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY';owner.record_prerequisite(report)
 return report
