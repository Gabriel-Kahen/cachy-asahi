#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy the exact seven retained audio objects; no download, extraction or execution."""
import argparse,hashlib,json,os,shutil,stat,time
from pathlib import Path
POLICY='5dae018a1357708e85393048728a6fb44cd9c9eb02a78ab19e60435d370ffdf2'
CARRIER='405761af52cdfa92b97bbf5b0519f32230d9a254'
NAMES={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}
MAX_TOTAL=8*1024**2;SECONDS=600

def need(ok,reason):
 if not ok:raise ValueError(reason)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap,deadline):
 path=Path(path);need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary retained input path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and stat.S_IMODE(before.st_mode)in(0o600,0o644)and 0<=before.st_size<=cap,'owned nonexecuting retained input shape');parts=[];left=before.st_size+1
  while left:
   need(time.monotonic()<deadline,'audio seed deadline');chunk=os.read(fd,min(left,1024**2))
   if not chunk:break
   parts.append(chunk);left-=len(chunk)
  raw=b''.join(parts);need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'retained input changed');return raw
 finally:os.close(fd)
def seed(policy,carrier,output):
 deadline=time.monotonic()+SECONDS;raw=read(policy,1024**2,deadline);need(pin(raw)['sha256']==POLICY,'frozen audio policy pin');rows=json.loads(raw)
 need(type(rows)is list and len(rows)==6 and {r['name']for r in rows}==NAMES,'six frozen audio policy rows');wanted={}
 for row in rows:
  name=row['filename'];need(type(name)is str and Path(name).name==name and name not in wanted,'unique ordinary audio filename');wanted[name]=(carrier/'packages'/name,dict(bytes=row['size'],sha256=row['sha256']))
  if row['origin']=='ALARM':
   need(row['name']=='lsp-plugins-lv2','only fixed LSP official signature');wanted[name+'.sig']=(carrier/'upstream-signatures'/(name+'.sig'),dict(bytes=row['signature_size'],sha256=row['signature_sha256']))
 need(len(wanted)==7 and all(type(r['bytes'])is int and 0<r['bytes']<=MAX_TOTAL for _,r in wanted.values())and sum(r['bytes']for _,r in wanted.values())<=MAX_TOTAL,'seven bounded original objects')
 output=Path(output);parent=output.parent;need(output.is_absolute()and output.name=='audio-archives'and parent==parent.resolve()and not any(p.is_symlink()for p in(parent,*parent.parents))and parent.is_dir()and parent.stat().st_uid==os.geteuid()and not parent.stat().st_mode&0o022 and not os.path.lexists(output),'fresh private runner audio output')
 output.mkdir(mode=0o700);owned=output.stat();made=[]
 try:
  for name,(source,expected)in wanted.items():
   body=read(source,expected['bytes'],deadline);need(pin(body)==expected,'retained original audio byte pin: '+name)
   fd=os.open(output/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
   with os.fdopen(fd,'wb')as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
   made.append(name)
  need(set(p.name for p in output.iterdir())==set(wanted)and(output.stat().st_dev,output.stat().st_ino)==(owned.st_dev,owned.st_ino)and time.monotonic()<deadline,'closed exact owned audio output')
  return dict(status='AUDIO_INPUT_SEED_PASS_EXACT_RETAINED_SEVEN',files={n:r for n,(_,r)in wanted.items()},carrier_source_expected=CARRIER,carrier_revision_verification='CALLER_ENFORCED',policy_sha256=POLICY,network_requests=0,package_or_signature_execution=False,cold_retriever='SKIPPED_EXISTING_OUTPUT_WOULD_REFUSE',later_frozen_audit='REQUIRED_UNCHANGED',deadline_seconds=SECONDS)
 except BaseException:
  if output.is_dir()and not output.is_symlink()and(output.stat().st_dev,output.stat().st_ino)==(owned.st_dev,owned.st_ino):shutil.rmtree(output)
  raise

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--policy',required=True,type=Path);parser.add_argument('--carrier',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);a=parser.parse_args();print(json.dumps(seed(a.policy,a.carrier,a.output),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
