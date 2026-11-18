# SPDX-License-Identifier: MIT
"""Preserved public native CI/platform context; no package manager or key census."""
import hashlib,json,os,re,stat
from pathlib import Path

def need(ok,message):
 if not ok:raise ValueError(message)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def context(env,machine,release,uid,record=None):
 # Only fixed public fields; invalid/unknown text is omitted, never truncated.
 def safe(value,pattern):
  return value if type(value)is str and len(value)<=160 and re.fullmatch(pattern,value)else None
 patterns=dict(GITHUB_ACTIONS='true|false',RUNNER_OS='Linux|Windows|macOS',RUNNER_ARCH='ARM64|X64|ARM',
  ImageOS='[A-Za-z0-9._-]{1,64}',ImageVersion='[0-9][A-Za-z0-9._-]{0,63}',
  GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',
  GITHUB_RUN_ATTEMPT='[1-9][0-9]{0,2}',GITHUB_RUN_ID='[1-9][0-9]{1,19}',GITHUB_SHA='[0-9a-f]{40}',
  GITHUB_REF='refs/heads/codex/fish02-no-host-apt-v4-source-[A-Za-z0-9._-]{1,80}',GITHUB_JOB='pair')
 public={name:safe(env.get(name),pattern)for name,pattern in patterns.items()}
 values={};valid=type(release)is bytes and 0<len(release)<=16384
 if valid:
  try:
   for line in release.decode('utf-8').splitlines():
    key=line.split('=',1)[0]
    if key not in('ID','VERSION_ID'):continue
    match=re.fullmatch(r'(ID|VERSION_ID)=(?:"([A-Za-z0-9._-]{1,32})"|([A-Za-z0-9._-]{1,32}))',line)
    if not match or key in values:valid=False;continue
    values[key]=match[2]or match[3]
  except UnicodeDecodeError:valid=False
 valid=valid and set(values)=={'ID','VERSION_ID'}
 checks=dict(ROOT_UID=type(uid)is int and uid==0,MACHINE_ARM64=machine in('aarch64','arm64'),
  CI_ACTIONS=public['GITHUB_ACTIONS']=='true',CI_RUNNER_OS=public['RUNNER_OS']=='Linux',CI_RUNNER_ARCH=public['RUNNER_ARCH']=='ARM64',
  CI_REPOSITORY=public['GITHUB_REPOSITORY']is not None,CI_DISPATCH=public['GITHUB_EVENT_NAME']is not None,
  CI_FIRST_ATTEMPT=public['GITHUB_RUN_ATTEMPT']=='1',CI_RUN_ID=public['GITHUB_RUN_ID']is not None,
  CI_SOURCE_SHA=public['GITHUB_SHA']is not None,CI_SOURCE_REF=public['GITHUB_REF']is not None,CI_JOB_PAIR=public['GITHUB_JOB']=='pair',
  OS_RELEASE_FORMAT=bool(valid),OS_UBUNTU=valid and values.get('ID')=='ubuntu',OS_VERSION24_04=valid and values.get('VERSION_ID')=='24.04')
 facts=dict(kind='PUBLIC_UBUNTU24_ARM_CI_CONTEXT_V1',uid=uid if type(uid)is int and 0<=uid<2**32 else None,
  machine=safe(machine,'[A-Za-z0-9_-]{1,32}'),os_release={k:safe(values.get(k),'[A-Za-z0-9._-]{1,32}')for k in('ID','VERSION_ID')},
  environment=public,checks=checks,reason_codes=[name for name,passed in checks.items()if not passed],
  provider_labels_informational=True,Root_authority=None)
 need(len(json.dumps(facts))<=8192,'finite public context receipt')
 if record is not None:record(facts) # Durable BEFORE any context refusal or APT action.
 need(not facts['reason_codes'],'CI prerequisite context refused: '+','.join(facts['reason_codes']))
 return facts


def public_file(path,root,uid):
 path=path.resolve(strict=True);need(path==root or root in path.parents,'public configuration stays within selected root')
 before=path.lstat()
 need(stat.S_ISREG(before.st_mode)and before.st_uid==uid and not before.st_mode&0o022 and before.st_nlink==1 and 0<=before.st_size<=2*1024**2,'ordinary root-owned bounded public configuration')

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
