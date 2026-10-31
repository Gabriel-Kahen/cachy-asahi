#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite offline Debian archive chain; independent key authority is a separate gate."""
import datetime,email.utils,hashlib,io,json,lzma,os,stat,subprocess,tempfile,time
from pathlib import Path
KEYS={'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8':'4CB50190207B4758A3F73A796ED0E7B82643E131','04B54C3CDCA79751B16BC6B5225629DF75B188BD':'B8E5F13176D2A7A75220028078DBA3BC47EF2265'}
ARCHIVE='glibc_2.43.orig.tar.xz';ARCHIVE_SHA='b8f0d50a7d4255658efe1f608cacdc4be82bb3c009875626df5968cc64c58880';TREE='1fbcd978e2051d72273231f03b921b1503e0e424'
PUBLIC_PINS={'sid-InRelease': {'bytes': 192842, 'sha256': '7adfcfd12245e14a1198f6340dfb60b19a61d73531ef6cce925a68deb4e06f98'}, 'sid-Sources.xz': {'bytes': 12028604, 'sha256': '781f5a9546d0b41aaa5b4abcf61ba3168fc5dc8c0e74f17d68a2a24670035583'}, 'glibc_2.43.orig.tar.xz': {'bytes': 21553420, 'sha256': 'b8f0d50a7d4255658efe1f608cacdc4be82bb3c009875626df5968cc64c58880'}, 'glibc_2.43-7.dsc': {'bytes': 8571, 'sha256': 'a99e5beb8f568765d191f3d0d074cf6b60d2c89dec84f2f4bb70573e52e0a835'}, 'archive-key-12.asc': {'bytes': 11861, 'sha256': 'c2a9a16fde95e037bafd0fa6b7e31f41b4ff1e85851de5558f19a2a2f0e955e2'}, 'archive-key-13.asc': {'bytes': 11861, 'sha256': '6f1d277429dd7ffedcc6f8688a7ad9a458859b1139ffa026d1eeaadcbffb0da7'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def read(path,cap=96*1024**2):
 path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary source/auth path required');a=path.stat()
 need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=cap,'bounded single-link auth object required');raw=path.read_bytes();b=path.stat();identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns);need(len(raw)==a.st_size and identity(a)==identity(b),'auth object drift');return raw
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def fields(raw):
 out={};key=None
 for line in raw.decode('utf8').splitlines():
  if line.startswith((' ','\t')):need(key is not None,'orphan continuation');out[key]+='\n'+line.strip()
  else:key,sep,text=line.partition(':');need(sep and key not in out,'invalid/duplicate source field');out[key]=text.strip()
 return out
def sums(raw):
 out={}
 for line in raw.splitlines():
  if not line:continue
  digest,size,name=line.split();need(len(digest)==64 and name not in out and all(c in '0123456789abcdef' for c in digest),'closed SHA256 rows');out[name]=dict(bytes=int(size),sha256=digest)
 return out
def authority(policy,inputs):
 value=decode(read(policy,65536))
 need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_INDEPENDENT_DEBIAN_ARCHIVE_AUTHORITY','UNBOUND independent Debian key-bootstrap authority; no build bundle or native actors')
 need(value.get('key_pairs')==KEYS and value.get('candidate')==dict(name='cachy-asahi-glibc-gnu-provider',version='2.43.caa2-1',archive_sha256=ARCHIVE_SHA,payload_tree=TREE),'new candidate/key authority selection differs')
 row=value.get('decision');need(type(row) is dict and set(row)=={'path','bytes','sha256'} and Path(row['path']).name==row['path'] and row['path'] not in ('.','..'),'Root independent authority decision reference required')
 raw=read(Path(inputs)/row['path'],65536);need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'Root key authority decision pin differs');decision=decode(raw)
 need(decision.get('status')=='ROOT_ACCEPTED_INDEPENDENT_DEBIAN_ARCHIVE_KEY_BOOTSTRAP' and decision.get('key_pairs')==KEYS and decision.get('candidate')==value['candidate'] and decision.get('independent_evidence') and decision.get('not_just_publisher_https') is True,'Root independent key bootstrap decision missing')
 return dict(status='PASS_ROOT_BOUND_NEW_SOURCE_KEY_AUTHORITY',decision_sha256=pin(raw)['sha256'],candidate=value['candidate'],native='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED')
def key_status(text,now):
 last=None;primary=None;seen=set();keyfacts=[]
 for line in text.splitlines():
  row=line.split(':')
  if row[0] in ('pub','sub'):last=row
  elif row[0]=='fpr' and last is not None:
   fpr=row[9]
   if last[0]=='pub':primary=fpr;need(primary in KEYS,'unselected archive primary')
   else:need(KEYS.get(primary)==fpr,'unselected archive subkey')
   need(fpr not in seen and 's' in last[11].lower() and last[1] not in ('r','e','d','i') and int(last[5])<=now and last[6] and now<int(last[6]),'revoked/expired/disabled/invalid/future archive key')
   seen.add(fpr);keyfacts.append(dict(kind=last[0],fingerprint=fpr,primary=primary,created=int(last[5]),expires=int(last[6])));last=None
 need(seen==set(KEYS)|set(KEYS.values()),'both exact archive key pairs required')
 return keyfacts
def signature_status(text,returncode,now):
 statuses=[line[9:].split() for line in text.splitlines() if line.startswith('[GNUPG:] ')]
 need(returncode==0 and all(row and row[0] in {'PLAINTEXT','NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG'} for row in statuses),'unknown/error/expired/revoked signature status')
 valid=[row for row in statuses if row[0]=='VALIDSIG']
 need(len(valid)==2 and all(len(row)==11 and int(row[3])<=now and (row[4]=='0' or now<int(row[4])) and row[8] in ('8','9','10') for row in valid) and {(row[-1],row[1]) for row in valid}==set(KEYS.items()),'both exact current archive signatures required')
 return statuses
def current_release(raw,now):
 value=fields(raw);need(value.get('Origin')=='Debian' and value.get('Codename')=='sid','exact Debian sid source archive required')
 date=email.utils.parsedate_to_datetime(value['Date']).timestamp();until=email.utils.parsedate_to_datetime(value['Valid-Until']).timestamp();need(date<=now<until,'archive metadata not current')
 return value
def inspect_chain(inputs,transcript=None):
 inputs=Path(inputs).absolute();data={n:read(inputs/n) for n in PUBLIC_PINS}
 for n,row in PUBLIC_PINS.items():need(pin(data[n])==row,'exact Debian chain object differs: '+n)
 now=int(time.time());commands=[];keyfacts=[]
 def run(argv):
  r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=30,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'));need(len(r.stdout)+len(r.stderr)<=512*1024,'crypto output bound')
  commands.append(dict(argv=argv,exit=r.returncode,status=r.stdout.decode('utf8','strict'),stderr=r.stderr.decode('utf8','replace')));need(r.returncode==0,'actual Debian crypto command failed');return r
 with tempfile.TemporaryDirectory(prefix='debian-source-public-',dir=Path(transcript).parent if transcript is not None else None) as temporary:
  home=Path(temporary)
  for name in ('archive-key-12.asc','archive-key-13.asc','sid-InRelease'):(home/name).write_bytes(data[name])
  r=run(['/usr/bin/gpg','--no-options','--homedir',str(home),'--batch','--no-autostart','--with-colons','--with-fingerprint','--with-subkey-fingerprint','--show-keys',str(home/'archive-key-12.asc'),str(home/'archive-key-13.asc')]);last=None;primary=None;seen=set()
  keyfacts=key_status(r.stdout.decode(),now)
  asc=home/'archive.asc';asc.write_bytes(data['archive-key-12.asc']+data['archive-key-13.asc']);ring=home/'archive.gpg'
  run(['/usr/bin/gpg','--no-options','--homedir',str(home),'--batch','--no-autostart','--output',str(ring),'--dearmor',str(asc)])
  release=home/'Release';r=run(['/usr/bin/gpgv','--homedir',str(home),'--keyring',str(ring),'--status-fd','1','--output',str(release),str(home/'sid-InRelease')]);signature_status(r.stdout.decode(),r.returncode,now)
  release_raw=read(release,524288);release_fields=current_release(release_raw,now)
  need(sums(release_fields['SHA256'])['main/source/Sources.xz']==pin(data['sid-Sources.xz']),'signed source index hash differs')
 records=[];paragraph=bytearray();decoded=0
 with lzma.open(io.BytesIO(data['sid-Sources.xz']),'rb') as stream:
  while True:
   line=stream.readline(1024**2+1)
   if not line:break
   decoded+=len(line);need(decoded<=256*1024**2 and len(line)<=1024**2,'source index decoder bound')
   if line==b'\n':
    if paragraph.startswith(b'Package: glibc\n') and fields(paragraph).get('Version')=='2.43-7':records.append(bytes(paragraph))
    paragraph.clear()
   else:paragraph.extend(line);need(len(paragraph)<=2*1024**2,'source paragraph bound')
 need(len(records)==1,'unique exact glibc2.43-7 source required');record=fields(records[0]);need(record['Directory']=='pool/main/g/glibc','exact source directory required');checksums=sums(record['Checksums-Sha256'])
 for n in (ARCHIVE,'glibc_2.43-7.dsc'):need(checksums[n]==pin(data[n]),'signed original source object differs')
 result=dict(status='CRYPTOGRAPHIC_DEBIAN_CHAIN_ONLY_NOT_BOOTSTRAP_AUTHORITY',key_pairs=KEYS,key_material=keyfacts,release=pin(release_raw),date=release_fields['Date'],valid_until=release_fields['Valid-Until'],sources=pin(data['sid-Sources.xz']),source_record=pin(records[0]),archive=pin(data[ARCHIVE]),gpg_status=r.stdout.decode(),diagnostic=r.stderr.decode(),security='NO_CREDIT',release_admission='NOT_GRANTED')
 if transcript is not None:Path(transcript).write_text(json.dumps(dict(checked_epoch=now,commands=commands,result=result),sort_keys=True,indent=2)+'\n')
 return result
