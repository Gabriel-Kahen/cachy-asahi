#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only, fixed LLVM22 candidate inventory. No compiler/container execution."""
import argparse,base64,hashlib,json,platform,re,shutil,struct,subprocess,tarfile,tempfile
from pathlib import Path
TOOLS=('make','clang','clang++','ld.lld','llvm-ar','llvm-nm','llvm-strip','llvm-objcopy','llvm-objdump','llvm-readelf','bison','flex','perl','sh','pahole','openssl','pkg-config')


def pin(p):
 with p.open('rb') as f:return {'bytes':p.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}


def fields(raw):
 out={}
 for block in raw.decode().split('\n\n'):
  lines=block.splitlines()
  if lines and lines[0].startswith('%'):out[lines[0].strip('%')]=lines[1:]
 return out


def needed(path):
 with path.open('rb') as f:
  head=f.read(64)
  if head[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',head,18)[0]!=62:raise ValueError('actual x86_64 ELF required')
  off=struct.unpack_from('<Q',head,32)[0];width,count=struct.unpack_from('<HH',head,54)
  if width!=56 or count>128:raise ValueError('ELF table bound')
  f.seek(off);headers=[struct.unpack('<IIQQQQQQ',f.read(56)) for _ in range(count)]
  dynamic=[h for h in headers if h[0]==2];interpreter=[]
  for h in headers:
   if h[0]==3:f.seek(h[2]);interpreter.append(f.read(h[5]).rstrip(b'\0').decode())
  if not dynamic:return interpreter,[]
  h=dynamic[0]
  if h[5]>65536 or h[5]%16:raise ValueError('dynamic table bound')
  f.seek(h[2]);entries=[struct.unpack('<qQ',f.read(16)) for _ in range(h[5]//16)]
  address=next(v for k,v in entries if k==5);load=next(h for h in headers if h[0]==1 and h[3]<=address<h[3]+h[5]);strings=address-load[3]+load[2];names=[]
  for k,v in entries:
   if k==1:f.seek(strings+v);names.append(f.read(256).split(b'\0',1)[0].decode())
  search=[]
  for k,v in entries:
   if k in (15,29):
    f.seek(strings+v);search.extend(f.read(4096).split(b'\0',1)[0].decode().split(':'))
  return interpreter+names,search


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 records={};metadata_paths={}
 for path in Path('/var/lib/pacman/local').glob('*/desc'):
  row=fields(path.read_bytes());records[row['NAME'][0]]=row;metadata_paths[row['NAME'][0]]=path
 providers={};provided_exact={}
 for name,row in records.items():
  for expression in row.get('PROVIDES',[]):
   providers.setdefault(re.split('[<>=]',expression,maxsplit=1)[0],[]).append(name);provided_exact.setdefault(expression,[]).append(name)
 seed={'clang','llvm','llvm-libs','lld','compiler-rt','make','bison','flex','perl','bash','coreutils','findutils','diffutils','gawk','grep','sed','gzip','tar','util-linux','pkgconf','python','openssl','pahole'};selected=set();queue=list(seed);edges=[];unresolved=[]
 while queue:
  name=queue.pop()
  if name in selected:continue
  if name not in records:unresolved.append(name);continue
  selected.add(name)
  for expression in records[name].get('DEPENDS',[]):
   dependency=re.split('[<>=]',expression,maxsplit=1)[0];candidates=[dependency] if dependency in records else sorted(set(provided_exact.get(expression,providers.get(dependency,[]))))
   if len(candidates)!=1:raise ValueError('ambiguous/missing actual installed provider: '+expression)
   provider=candidates[0];edges.append({'package':name,'dependency':expression,'provider':provider,'version':records[provider]['VERSION'][0]});queue.append(provider)
 # The installed ALPM's own comparator verifies every collected version relation.
 check=subprocess.run(['/usr/bin/pacman','-T',*sorted({e['dependency'] for e in edges})],capture_output=True,timeout=20)
 if check.returncode:raise ValueError('actual installed dependency closure differs')
 packages={};cache=Path('/var/cache/pacman/pkg')
 for name in sorted(selected):
  row=records[name];version=row['VERSION'][0];arch=row['ARCH'][0];archive=cache/(name+'-'+version.split(':')[-1]+'-'+arch+'.pkg.tar.zst')
  fact={'version':version,'arch':arch,'licenses':row.get('LICENSE',[]),'local_directory':metadata_paths[name].parent.name,'metadata_files':{n:pin(metadata_paths[name].parent/n) for n in ('desc','files','mtree') if (metadata_paths[name].parent/n).is_file()},'installed_metadata':pin(metadata_paths[name]),'archive':None,'signature':None}
  if archive.is_file():fact['archive']={'path':str(archive),**pin(archive)}
  if Path(str(archive)+'.sig').is_file():fact['signature']={'path':str(archive)+'.sig',**pin(Path(str(archive)+'.sig'))}
  packages[name]=fact
 tools={};queue=[]
 for name in TOOLS:
  found=shutil.which(name,path='/usr/bin:/bin')
  if not found:raise ValueError('missing fixed candidate tool: '+name)
  path=Path(found).resolve();tools[name]={'path':str(path),**pin(path)};queue.append(path)
 runtime={}
 while queue:
  path=queue.pop()
  if str(path) in runtime:continue
  deps,search=needed(path);runtime[str(path)]={**pin(path),'needed':deps,'rpath_runpath':search}
  for dep in deps:
   choices=[Path(dep)] if dep.startswith('/') else [Path(x.replace('${ORIGIN}',str(path.parent)).replace('$ORIGIN',str(path.parent)))/dep for x in search]+[Path('/usr/lib')/dep]
   target=next((p for p in choices if '$' not in str(p) and p.is_file()),None)
   if target is None:raise ValueError('unresolved actual tool library: '+dep)
   queue.append(target.resolve())
 signatures={};key=Path('/usr/share/pacman/keyrings/cachyos.gpg')
 with tempfile.TemporaryDirectory(prefix='rtc-public-math-') as tmp:
  keyring=key
  if key.read_bytes().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
   keyring=Path(tmp)/'public.gpg';dearmor=subprocess.run(['gpg','--no-options','--batch','--homedir',tmp,'--dearmor','--output',str(keyring),str(key)],capture_output=True,timeout=30)
   if dearmor.returncode:raise ValueError('bounded public key dearmor failed')
  for name in ('clang','llvm','llvm-libs','lld','compiler-rt'):
   row=packages[name]
   if row['archive'] is None or row['signature'] is None:raise ValueError('retained LLVM22 archive/signature absent')
   result=subprocess.run(['gpgv','--homedir',tmp,'--keyring',str(keyring),'--status-fd','1',row['signature']['path'],row['archive']['path']],capture_output=True,timeout=30)
   lines=[s for s in result.stdout.decode().splitlines() if s.startswith('[GNUPG:] VALIDSIG ')]
   if result.returncode or len(lines)!=1:raise ValueError('LLVM22 mathematical signature check failed')
   signatures[name]=lines[0]
 bc=None;db=Path('/var/lib/pacman/sync/extra.db')
 with tarfile.open(db,'r:*') as archive:
  for member in archive:
   if member.name.startswith('bc-') and member.name.endswith('/desc'):
    row=fields(archive.extractfile(member).read());packet=base64.b64decode(row['PGPSIG'][0],validate=True)
    bc={'name':row['NAME'][0],'version':row['VERSION'][0],'arch':row['ARCH'][0],'filename':row['FILENAME'][0],'bytes':int(row['CSIZE'][0]),'sha256':row['SHA256SUM'][0],'depends':row['DEPENDS'],'signature_base64':row['PGPSIG'][0],'signature':{'bytes':len(packet),'sha256':hashlib.sha256(packet).hexdigest()},'database':{'path':str(db),**pin(db)},'archive_retained':False,'signature_math':'NOT RUN: archive missing','proposed_exact_url':'https://archive.archlinux.org/packages/b/bc/'+row['FILENAME'][0]};break
 report={'schema_version':1,'operation':'arm16k-rtc-reference-kernel-v1','status':'CANDIDATE_ONLY_IMAGE_NOT_PREPARED','mode':'HOST_CROSS_ARM64','host_architecture':platform.machine(),'target_architecture':'arm64','host_ISA':'x86_64_v3 cached LLVM packages; actual isolated runner must support this ISA','same_toolchain':False,'tools':tools,'runtime_files':runtime,'packages':packages,'dependency_edges':edges,'actual_dependency_check':'PASS installed host ALPM -T','actual_LLVM22_signature_math':signatures,'public_keyring':{'path':str(key),**pin(key)},'bc_missing_provider':bc,'missing_cached_archives':[n for n,r in packages.items() if r['archive'] is None or r['signature'] is None],'image_id':None,'runtime_closure_reviewed':None,'compiler_facts':None,'configured_result_sha256':None,'resource_authority':None,'compiler_execution':'NOT RUN','configure':'NOT RUN','compile':'NOT RUN','guest_boot':'NOT RUN','M2':'NOT RUN','release_accepted':False}
 with a.output.open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
 print(json.dumps({'packages':len(packages),'runtime_files':len(runtime),'LLVM_signature_checks':len(signatures),'missing_cached_archives':report['missing_cached_archives'],'bc':bc['filename'],'status':report['status']}))


if __name__=='__main__':main()
