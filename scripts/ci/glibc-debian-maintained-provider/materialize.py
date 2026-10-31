#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite, inspection-only Debian quilt source preparation. No build or rules execution."""
import argparse,hashlib,importlib.util,io,json,lzma,os,re,stat,subprocess,sys,tarfile,time,types
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
ARCHIVE='glibc_2.43-7.debian.tar.xz';ARCHIVE_SHA='9f62b90fb4c7423ed5023698c9014ad0086d26f9b6f46b2a163afcea7e581a02'
AUTH_SHA='cff55c85bda9d50fe209e93146d26d331bbe98b6f0a453e3e2ec1029fc57e1d1'
ORIG_SHA='b8f0d50a7d4255658efe1f608cacdc4be82bb3c009875626df5968cc64c58880';ORIG_TREE='1fbcd978e2051d72273231f03b921b1503e0e424'

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def safe(name):
 need(type(name) is str and 0<len(name)<=512 and re.fullmatch(r'[A-Za-z0-9_.+/@-]+',name) and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'unsafe relative patch/metadata path: '+repr(name));return name
def series(raw):
 need(len(raw)<=65536,'series byte bound');result=[]
 for line in raw.decode('ascii').splitlines():
  value=line.split('#',1)[0].strip()
  if not value:continue
  need(len(value.split())==1,'unsupported quilt series options');safe(value);need(value not in result and len(result)<256,'duplicate/excess quilt patch');result.append(value)
 need(result,'empty quilt series');return result

def paths(raw):
 need(0<len(raw)<=4*1024**2,'patch byte bound');lines=raw.split(b'\n');result=[];i=0;active=False;hunks=0
 def path(line):
  value=line[4:].split()[0].decode('ascii')
  if value=='/dev/null':return None
  safe(value);need('/' in value,'explicit p1 source path required');return safe(value.split('/',1)[1])
 while i<len(lines):
  line=lines[i]
  need(not line.startswith((b'GIT binary patch',b'Binary files ',b'rename from ',b'rename to ',b'*** ',b'diff -e ')) and not re.fullmatch(rb'\d+(,\d+)?[acd]\d*(,\d+)?',line) and b'file mode 120000' not in line,'unsupported binary/ed/context/rename/symlink patch')
  if line.startswith(b'diff --git '):
   names=line.split();need(len(names)==4,'unquoted closed git header paths required');old,new=path(b'--- '+names[2]),path(b'+++ '+names[3]);need(old is not None and old==new,'same contained git header target required');result.append(dict(path=new,operation='git-header-declared-target'))
  if line.startswith((b'new file mode ',b'deleted file mode ',b'old mode ',b'new mode ')):
   need(line.split()[-1] in (b'100644',b'100755'),'ordinary git file mode required')
  if line.startswith(b'--- '):
   need(i+1<len(lines) and lines[i+1].startswith(b'+++ '),'paired unified headers required');old,new=path(line),path(lines[i+1]);need(old is not None or new is not None,'empty patch target')
   if old is not None and new is not None and old!=new:
    need(old in (new+'.original',new+'.original2'),'unsupported different unified target labels');result.append(dict(path=old,operation='absent-old-backup-label'))
   result.append(dict(path=new or old,operation='create' if old is None else 'delete' if new is None else 'change'));active=True;i+=2;continue
  if line.startswith(b'@@ '):
   need(re.fullmatch(rb'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*',line) is not None and active,'unified hunk/header required');hunks+=1
  i+=1
 # GNU patch remains the authoritative hunk-count/content parser, with fuzz0.
 # This pass validates every potential header/target and refuses other formats.
 need(result and hunks,'nonempty unified patch required');return result

def target(root,name):
 path=root/safe(name)
 for p in (path,*path.parents):
  if p==root.parent:break
  if p.exists() or p.is_symlink():need(not p.is_symlink() and (p.is_dir() if p!=path else p.is_file()),'nonordinary/symlink patch target: '+name)
 return path

def tree(root):
 entries={};count=total=0;started=time.monotonic()
 def visit(path):
  nonlocal count,total
  rows=[]
  for p in path.iterdir():
   count+=1;need(count<=60000 and time.monotonic()-started<180,'source tree count/time bound');s=p.lstat();name=p.relative_to(root).as_posix()
   if stat.S_ISDIR(s.st_mode):mode=b'40000';digest=visit(p);key=p.name+'/';entries[name]=dict(type='directory',mode=stat.S_IMODE(s.st_mode))
   else:
    need(stat.S_ISLNK(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=64*1024**2,'ordinary source member required');raw=os.readlink(p).encode() if stat.S_ISLNK(s.st_mode) else p.read_bytes();mode=b'120000' if p.is_symlink() else b'100755' if s.st_mode&0o111 else b'100644';key=p.name;total+=len(raw);need(total<=512*1024**2,'source tree bytes bound');digest=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest();entries[name]=dict(type='symlink' if p.is_symlink() else 'file',mode=stat.S_IMODE(s.st_mode),**pin(raw))
   rows.append((key.encode(),mode+b' '+p.name.encode()+b'\0'+digest))
  raw=b''.join(v for _,v in sorted(rows));return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
 return dict(tree=visit(root).hex(),files=entries,logical_bytes=total)

def helper(name,path,expected):
 path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary pinned helper path required');info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=65536 and pin(path.read_bytes())['sha256']==expected,'exact original helper source required: '+name)
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def helper_path(name,explicit):
 if explicit is not None:return Path(explicit)
 bundled=HERE/name
 return bundled if bundled.is_file() else HERE.parent/('glibc-debian-provider/auth.py' if name=='auth.py' else 'glibc-gnu-provider/materialize.py')

def lock():
 raw=(HERE/'source-lock.json').read_bytes();need(pin(raw)['sha256']=='9eef1925b041bdf022ae284e15e473ce5b6795976b132d574ad7d56d21e6d12a','exact maintained source lock required');value=json.loads(raw);need(value['schema']==1 and value['series']['count']==84 and len(value['series']['patches'])==84,'exact finite maintained source lock required');return value

def authenticate(chain,patch_tar,output,auth_helper=None):
 a=helper('maintained_original_chain',helper_path('auth.py',auth_helper),AUTH_SHA);result=a.inspect_chain(chain,output/'source-chain.json')
 records=[];paragraph=bytearray();decoded=0
 with lzma.open(chain/'sid-Sources.xz','rb') as f:
  for line in f:
   decoded+=len(line);need(decoded<=256*1024**2 and len(line)<=1024**2,'bounded original source metadata')
   if line==b'\n':
    if paragraph.startswith(b'Package: glibc\n') and a.fields(paragraph).get('Version')=='2.43-7':records.append(bytes(paragraph))
    paragraph.clear()
   else:paragraph.extend(line);need(len(paragraph)<=2*1024**2,'bounded source paragraph')
 need(len(records)==1,'unique authenticated2.43-7 source paragraph');record=a.fields(records[0]);need(record['Directory']=='pool/main/g/glibc','exact source directory')
 expected=dict(bytes=498952,sha256=ARCHIVE_SHA);need(a.sums(record['Checksums-Sha256'])[ARCHIVE]==expected,'signed Sources patch object differs');raw=a.read(patch_tar,1024**2);need(pin(raw)==expected,'exact patch tar bytes differ')
 dsc=a.read(chain/'glibc_2.43-7.dsc',65536);text=dsc.split(b'\n\n',1)[1].split(b'\n-----BEGIN PGP SIGNATURE-----',1)[0];clear=b'\n'.join(l[2:] if l.startswith(b'- ') else l for l in text.split(b'\n'));fields=a.fields(clear.strip());need(fields['Version']=='2.43-7' and a.sums(fields['Checksums-Sha256'])[ARCHIVE]==expected,'authenticated DSC patch object differs')
 value=dict(status='CURRENT_CRYPTOGRAPHIC_CHAIN_TO_EXACT_DEBIAN_PATCH_TAR_NOT_AUTHORITY_ADMISSION',chain=result,signed_source_record=pin(records[0]),dsc=pin(dsc),patch_tar=expected,independent_new_candidate_authority='UNBOUND',uploader_signature='NOT_RELIED_ON_DSC_HASH_IS_SIGNED_BY_ARCHIVE_METADATA')
 (output/'patch-authentication.json').write_bytes(encoded(value));return raw

def materialize(chain,patch_tar,output,auth_helper=None,inspector_helper=None):
 need(not sys.flags.optimize,'ordinary unoptimized Python required');chain=Path(chain).absolute();output=Path(output).absolute();need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output required');output.mkdir(mode=0o700)
 specification=lock();raw=authenticate(chain,Path(patch_tar).absolute(),output,auth_helper);metadata=output/'metadata';metadata.mkdir();archive_files={};records=[]
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:xz') as t:
  members=t.getmembers();need(len(members)<=1024 and sum(m.size for m in members)<=16*1024**2,'finite Debian metadata archive')
  for m in members:
   name=safe(m.name.rstrip('/'));need(name=='debian' or name.startswith('debian/'),'Debian metadata root');need(name not in archive_files and (m.isfile() or m.isdir() or m.issym()) and m.size<=4*1024**2,'ordinary unique Debian metadata');entry=dict(type='file' if m.isfile() else 'directory' if m.isdir() else 'symlink',mode=m.mode,uid=m.uid,gid=m.gid)
   if m.isfile():
    data=t.extractfile(m).read();entry.update(pin(data))
    if name.startswith('debian/patches/') or name in ('debian/copyright','debian/changelog'):
     p=metadata/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
   elif m.issym():entry['target']=m.linkname;need(name=='debian/patches/series.hurd-amd64' and m.linkname=='series.hurd-i386','only exact unused alternate-series metadata alias')
   archive_files[name]=entry
 series_raw=(metadata/'debian/patches/series').read_bytes();need(pin(series_raw)=={k:specification['series'][k] for k in ('bytes','sha256')},'exact authenticated quilt series differs');names=series(series_raw);need(names==[p['name'] for p in specification['series']['patches']],'all84 ordered patch names required');plan=[]
 for name in names:
  p=metadata/'debian/patches'/name;need(p.is_file() and not p.is_symlink(),'regular listed quilt patch required');data=p.read_bytes();plan.append(dict(name=name,**pin(data),targets=paths(data)))
 need([{k:p[k] for k in ('name','bytes','sha256')} for p in plan]==specification['series']['patches'],'all84 exact patch inputs required')
 project=(HERE/'0002-held-builder-test-expectations.patch').read_bytes();need(pin(project)==specification['project_patch']['pin'],'exact held-builder project patch required');project_path=metadata/'debian/patches/project/0002-held-builder-test-expectations.patch';project_path.parent.mkdir();project_path.write_bytes(project);plan.append(dict(name='project/0002-held-builder-test-expectations.patch',**pin(project),targets=paths(project)))
 (output/'metadata-manifest.json').write_bytes(encoded(archive_files));(output/'series-plan.json').write_bytes(encoded(plan))
 source=output/'source';source.mkdir();m=helper('maintained_original_source',helper_path('original_inspector.py',inspector_helper),'70bcde37f56b5a4ea3a44993a6add82ef4627635801c0a7909b14aefbca00d92');inspect=types.FunctionType(m.inspect.__code__,dict(m.__dict__,gzip=types.SimpleNamespace(open=lzma.open)));limits=dict(seconds=180,source_bytes=512*1024**2,source_compressed=96*1024**2,source_file=64*1024**2,source_members=60000);observed=inspect(chain/'glibc_2.43.orig.tar.xz',ORIG_TREE,limits);need(observed['sha256']==ORIG_SHA,'exact orig object')
 with tarfile.open(chain/'glibc_2.43.orig.tar.xz','r:xz') as t:t.extractall(source,filter='data')
 root=source/observed['root'];before=tree(root);need(before['tree']==ORIG_TREE,'complete original tree differs');(output/'before-tree.json').write_bytes(encoded(before));started=time.monotonic();status='PASS_ALL_AUTHENTICATED_DEBIAN_QUILT_PATCHES_FUZZ0_SOURCE_ONLY';failure=None
 for index,row in enumerate(plan):
  need(time.monotonic()-started<300,'finite complete patch session')
  if index==84:
   need(tree(root)['tree']==specification['complete_patched_tree'],'complete Debian quilt tree differs');source_policy(root,specification)
  changed={};patch=metadata/'debian/patches'/row['name']
  for item in row['targets']:
   p=target(root,item['path']);need(item['operation']!='absent-old-backup-label' or not p.exists(),'ambiguous old backup header label exists');changed[item['path']]=pin(p.read_bytes()) if p.exists() else None
  reject=output/('reject-'+str(index)+'.patch');argv=['/usr/bin/patch','--batch','--forward','--fuzz=0','--no-backup-if-mismatch','--reject-file',str(reject),'-Np1','-i',str(patch)];r=subprocess.run(argv,cwd=root,stdin=subprocess.DEVNULL,capture_output=True,timeout=30,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC'));need(len(r.stdout)+len(r.stderr)<=512*1024,'finite patch diagnostics');record=dict(index=index,name=row['name'],patch=dict(bytes=row['bytes'],sha256=row['sha256']),argv=argv,exit=r.returncode,stdout=r.stdout.decode('utf8','replace'),stderr=r.stderr.decode('utf8','replace'),before=changed,after={n:pin(target(root,n).read_bytes()) if target(root,n).exists() else None for n in changed});records.append(record);(output/'patch-commands.json').write_bytes(encoded(records))
  expected=specification['patch_outputs'][index];need(expected['name']==row['name'] and record['stdout']==expected['stdout'] and record['stderr']==expected['stderr'] and record['exit']==expected['exit'],'exact recorded patch output/offsets differ: '+row['name'])
  if r.returncode or re.search(rb'\bfuzz\b',r.stdout+r.stderr,re.I):status='STOPPED_EXACT_QUILT_PATCH_FAILURE_NO_WAIVER';failure=record;break
 after=tree(root);(output/'after-tree.json').write_bytes(encoded(after));changed={n:dict(before=before['files'].get(n),after=after['files'].get(n)) for n in before['files'].keys()|after['files'].keys() if before['files'].get(n)!=after['files'].get(n)};allowed={r['path'] for row in plan[:len(records)] for r in row['targets']};need(all(n in allowed or any(p.startswith(n+'/') for p in allowed) and (after['files'].get(n,{}).get('type')=='directory' or after['files'].get(n) is None and before['files'].get(n,{}).get('type')=='directory') for n in changed),'patch wrote undeclared source path')
 result=dict(status=status,source_version='Debian glibc2.43-7 orig+explicit quilt series',candidate='NEW_CAA3_SOURCE_NOT_CAA2',before_tree=before['tree'],quilt_tree=specification['complete_patched_tree'],after_tree=after['tree'],series_count=84,project_patch_count=1,offset_patches=sum('offset ' in r['stdout'] for r in records[:84]),attempted=len(records),completed=sum(r['exit']==0 for r in records),failed_patch=None if failure is None else failure['name'],delta=changed,patch_tar=pin(raw),independent_authority='NOT_GRANTED_BY_SOURCE_PREPARATION',build='NOT_RUN',native='NOT_RUN',security='NO_CREDIT_APPLICABILITY_NOT_ESTABLISHED',release='NOT_ADMITTED',upstream_code_executed=False,documentation=specification['documentation'],mount_guard_policy=specification['mount_guard_policy'])
 need(failure is not None or after['tree']==specification['prepared_tree'],'complete pinned Debian patched tree differs')
 for name,expected in specification['source_manifest_pins'].items():need(pin((output/name).read_bytes())==expected,'complete source node/metadata manifest differs: '+name)
 (output/'result.json').write_bytes(encoded(result));return result
def source_policy(root,specification):
 for name,row in specification['source_policy_files'].items():
  path=target(root,name);need(path.is_file() and pin(path.read_bytes())==row,'source-specific mount/manual policy differs: '+name)
 need(sorted(p.name for p in (root/'manual').iterdir())==['Makefile'],'no unauthenticated manual files may be reinserted')
 for name in specification['documentation']['omitted_files']:need(not (root/name).exists() and not (root/name).is_symlink(),'omitted GNU manual path reappeared')
 return dict(status='PASS_EXACT_AUTHENTICATED_UPSTREAM_GUARDS_AND_DEBIAN_MANUAL_POLICY',mount_patch='0001_SUPERSEDED_NOT_APPLIED',documentation='MAKEINFO=: REQUIRED; Debian manual-linked test semantics explicitly changed')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('chain-inputs','patch-tar','output'):p.add_argument('--'+name,type=Path,required=True)
 for name in ('auth-helper','inspector-helper'):p.add_argument('--'+name,type=Path)
 p.add_argument('--inspection-only',action='store_true');p.add_argument('--authority',type=Path);a=p.parse_args()
 try:
  need(a.inspection_only != bool(a.authority),'select explicit source inspection or independently bound new-candidate authority')
  if a.authority:
   from authority import check
   check(a.authority,a.chain_inputs,a.auth_helper)
  r=materialize(a.chain_inputs,a.patch_tar,a.output,a.auth_helper,a.inspector_helper);print(json.dumps({k:r[k] for k in ('status','before_tree','quilt_tree','after_tree','series_count','project_patch_count','offset_patches','completed','failed_patch','native','release')},sort_keys=True));raise SystemExit(0 if r['failed_patch'] is None else 1)
 except (ValueError,OSError,KeyError) as error:print(json.dumps(dict(status='REFUSED_MAINTAINED_SOURCE',reason=str(error)[:300],native='NOT_RUN',release='NOT_ADMITTED')));raise SystemExit(1)
