#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Exact old Perl package DATA review; never authenticate or execute its contents."""
import argparse,collections,hashlib,importlib.util,json,os,stat,sys,tarfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ARCHIVE={'bytes':16017184,'sha256':'f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f'}
SIGNATURE={'bytes':566,'sha256':'f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca'}
NAME='perl-5.42.3-1-aarch64.pkg.tar.xz'
TEXT_CAP=65536


def need(ok,label):
 if not ok:raise ValueError(label)
def encode(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def pin_bytes(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def input_pin(path,cap=64*1024**2):
 path=Path(path);need(not any(p.is_symlink() for p in path.parents),'input ancestry alias refused')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=cap,'bounded single-link ordinary input required')
  digest=hashlib.file_digest(f,'sha256').hexdigest();after=os.fstat(f.fileno());current=path.lstat()
  identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
  need(identity(before)==identity(after)==identity(current),'input changed during read')
 return {'bytes':before.st_size,'sha256':digest}
def helper():
 origin=json.loads((HERE/'origin.json').read_text())
 for n,ref in origin['files'].items():need(input_pin(HERE/n)==ref,'frozen DATA helper differs')
 p=HERE/'frozen/archive.py';s=importlib.util.spec_from_file_location('perl_old_archive_data',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def raw_texts(path,rows,A):
 # A first bounded read_rows pass has validated every header/extension/link.
 # This second bounded pass reads only the small explicit review text surface.
 S=A.load('perl_review_stream',HERE/'frozen/archive_stream.py')
 limits=S.Limits(compressed_bytes=64*1024**2,total_compressed_bytes=64*1024**2,decoded_bytes=160*1024**2,members=12000,file_bytes=32*1024**2,window_bytes=128*1024**2,deadline=time.monotonic()+90)
 selected={n for n,r in rows.items() if r['type']=='file' and (n in ('.PKGINFO','.BUILDINFO','.INSTALL','.CHANGELOG') or n.startswith(('etc/','usr/share/libalpm/')))}
 need(all(rows[n]['bytes']<=TEXT_CAP for n in selected) and sum(rows[n]['bytes'] for n in selected)<=512*1024,'bounded review text surface required')
 texts={}
 with path.open('rb') as f:
  decoded=S.Decoded(f,limits,0)
  with tarfile.open(fileobj=decoded,mode='r|',stream=True) as tar:
   for member in tar:
    S.tick(limits);name=member.name.removeprefix('./').rstrip('/')
    if name not in selected:continue
    need(member.isfile() and member.size==rows[name]['bytes'] and name not in texts,'ordinary unique review text required')
    with tar.extractfile(member) as body:raw=body.read(TEXT_CAP+1)
    need(pin_bytes(raw)=={k:rows[name][k] for k in ('bytes','sha256')},'review text differs from payload map')
    need(b'\0' not in raw,'unhandled binary review text');raw.decode('utf-8','strict');texts[name]=raw
   while decoded.read(65536):pass
  need(decoded.done and set(texts)==selected,'complete bounded review text pass required')
 return texts


def analyze(path):
 A=helper();rows=A.read_rows(Path(path));texts=raw_texts(Path(path),rows,A)
 need('.PKGINFO' in texts,'actual PKGINFO required')
 metadata={}
 for line in texts['.PKGINFO'].decode().splitlines():
  if not line or line.startswith('#'):continue
  need(' = ' in line,'unhandled PKGINFO directive');k,v=line.split(' = ',1);metadata.setdefault(k,[]).append(v)
 review={n:r for n,r in rows.items() if n.startswith(('.', 'etc/', 'usr/share/libalpm/'))}
 hardlinks={n:r for n,r in rows.items() if r['type']=='hardlink'}
 for n,r in hardlinks.items():
  target=rows[r['target']];need(target['type']=='file' and all(target[k]==r[k] for k in ('bytes','sha256')),'complete hardlink target binding required')
 backups=metadata.get('backup',[])
 need(all(p in rows and rows[p]['type']=='file' for p in backups),'declared backup path absent from actual regular payload')
 return rows,texts,metadata,review,hardlinks,backups


def write_data(directory,name,raw):
 p=directory/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(raw)
 p.chmod(0o600);return pin_bytes(raw)

def review_exact(archive,signature,output):
 started=time.monotonic();archive=Path(archive);signature=Path(signature);out=Path(output)
 before={'archive':input_pin(archive),'signature':input_pin(signature,2048)}
 need(before=={'archive':ARCHIVE,'signature':SIGNATURE},'exact retained old Perl archive/signature pins required')
 need(out.is_absolute() and not out.exists() and not any(p.is_symlink() for p in (out,*out.parents)) and out.parent.is_dir(),'fresh ordinary output directory required')
 need(not out.is_relative_to(archive.parent) and not out.is_relative_to(signature.parent),'outputs must be disjoint from retained originals')
 rows,texts,metadata,review,hardlinks,backups=analyze(archive)
 need(metadata.get('pkgname')==['perl'] and metadata.get('pkgver')==['5.42.3-1'] and metadata.get('arch')==['aarch64'],'actual old ARM Perl identity required')
 need(rows['usr/bin/perl'].get('ELF_machine')==183 and rows['usr/lib/perl5/5.42/core_perl/CORE/libperl.so'].get('ELF_machine')==183,'actual aarch64 interpreter/libperl declarations required')
 after={'archive':input_pin(archive),'signature':input_pin(signature,2048)};need(before==after,'retained inputs changed during review')
 os.umask(0o077);out.mkdir(mode=0o700);files={}
 files['payload.json']=write_data(out,'payload.json',encode(rows))
 # Exact shape/status/note emitted by core prepare.py:61, never an approval.
 packet=dict(status='ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION',archive=ARCHIVE,signature=SIGNATURE,metadata_config_hook_paths=review,note='Root reviews exact original ALPM metadata/hooks/configuration before normal trusted rollback')
 files['baseline-review.json']=write_data(out,'baseline-review.json',encode(packet))
 text_files={}
 for index,(name,raw) in enumerate(sorted(texts.items())):
  output='texts/'+str(index).zfill(2)+'-'+name.replace('/','_').lstrip('.')+'.data';ref=write_data(out,output,raw);files[output]=ref;text_files[name]={'file':output,**ref,'scope':'RAW_DATA_NOT_EXECUTED'}
 result={'schema_version':1,'status':'DATA_REVIEW_COMPLETE_AUTHENTICATION_AND_ROOT_ADMISSION_PENDING','archive':ARCHIVE,'signature':SIGNATURE,'inputs_before':before,'inputs_after':after,'originals_unchanged':True,'counts':{'nodes':len(rows),'types':dict(sorted(collections.Counter(r['type'] for r in rows.values()).items())),'ELF_headers':sum('ELF_machine' in r for r in rows.values()),'hardlinks':len(hardlinks)},'metadata':metadata,'hardlinks':hardlinks,'backup_paths':backups,'metadata_config_hook_paths':list(review),'INSTALL_present':'.INSTALL' in rows,'raw_texts':text_files,'files':files,'core_interface':'baseline-review.json matches exact prepare.py:61 output shape/status/selection/note; remains ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION','authentication':'NOT RUN; signature pin equality is not signature authentication','package_code':'NOT EXECUTED','Perl_build_install_service_network_GPG':'NOT RUN','Root_authority':None,'elapsed_seconds':round(time.monotonic()-started,3),'native16K_M2_performance_release':'NOT ACCEPTED'}
 write_data(out,'review.json',encode(result));return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--signature',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 need(__debug__ and sys.flags.isolated and sys.version_info>=(3,14),'Python3.14 isolated DATA reader required')
 result=review_exact(a.archive,a.signature,a.output);print(json.dumps({'status':result['status'],'counts':result['counts'],'output':str(a.output)}))
if __name__=='__main__':main()
