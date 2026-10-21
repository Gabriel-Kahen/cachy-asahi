"""Finite original574 missing-input preparation before the owner log/file cap."""
import hashlib,importlib.util,json,os,resource,stat,time
from pathlib import Path
import common as C

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def tick(deadline):C.need(time.monotonic()<deadline,'original890s prefetch envelope exhausted')
def exact(path,row,deadline):
 path=Path(path);C.need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary baseline input path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  C.need(stat.S_ISREG(a.st_mode)and a.st_uid==os.getuid()and a.st_nlink==1 and a.st_size==row['size'],'owned singlelink exact baseline input')
  h=hashlib.sha256();size=0
  while True:
   tick(deadline);b=os.read(fd,1024**2)
   if not b:break
   size+=len(b);C.need(size<=row['size'],'bounded baseline input');h.update(b)
  C.need(key(a)==key(os.fstat(fd))==key(path.stat(follow_symlinks=False))and size==row['size']and h.hexdigest()==row['sha256'],'whole baseline input hash/identity drift');return list(key(a))
 finally:os.close(fd)

def prepare(out,deadline,opener=None):
 """Only trusted source functions run; opener injection is for offline controls."""
 tick(deadline);out=C.private(out);context=C.private(out/'context');deps=C.private(context/'deps');C.private(context/'keys')
 C.need({p.name for p in context.iterdir()}=={'deps','keys'}and not any((context/'keys').iterdir()),'fresh original context root and empty key slots')
 os.umask(0o077);os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',LANG='C.UTF-8',HOME=str(out/'home'))
 raw=C.read(C.ROOT/'baseline/maintained-desktop574-inputs.json');custody=C.load(C.ROOT/'baseline/public14-custody.json');asset=C.ROOT/'baseline/public14'
 C.need(custody['status']=='ROOT_VERIFIED_ALL18_PUBLISHED_GIT_BLOBS_EXACT14_JOIN_TO_FROZEN574_AND_LOCAL_ROOTFS_PAIR'and custody['source']=='04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd'and custody['ref']=='codex/retained-public-inputs-zlib-v1'and custody['git_joins']==18 and custody['native_acceptance']is False,'whole Root published18 exact input custody')
 C.need(C.pin(raw)==custody['original574_inputs']==dict(bytes=623664,sha256='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9')and C.files(asset)==custody['files'],'whole original574 lock and published18 bodies')
 inputs=json.loads(raw);M=module(C.ROOT/'baseline/maintained_desktop574.py','baseline_original_plan_fetch');items=M.plan(inputs,context);C.need(len(items)==1153,'original complete1153 plan')
 package_rows={r['filename']:r for r in items if r['target'].parent==deps};index=C.load(asset/'index.json');rows=index['files'];names={r['filename']for r in rows}
 C.need(index['desktop574_lock_sha256']==C.pin(raw)['sha256']and len(rows)==len(names)==14 and sum(r['size']for r in rows)==custody['public14_bytes']==4123282,'published14 whole lock/membership/bytes binding')
 for row in rows:C.need(row['filename']in package_rows and {k:package_rows[row['filename']][k]for k in('filename','size','sha256')}==row,'each public14 input is exact original plan row')
 before={}
 for p in deps.iterdir():
  C.need(p.name in package_rows,'foreign original574 cache name');before[p.name]=exact(p,package_rows[p.name],deadline)
 C.need(names.isdisjoint(before),'fresh public14 destination slots required')
 rootfs=[r for r in items if r['target']in(context/'rootfs.tar.gz',context/'rootfs.tar.gz.sig')];C.need(len(rootfs)==2 and {r['filename']for r in rootfs}==set(custody['rootfs_local']),'two exact original rootfs plan rows')
 for row in rootfs:
  C.need(dict(bytes=row['size'],sha256=row['sha256'])==custody['rootfs_local'][row['filename']]['pin'],'exact originally frozen rootfs/signature pins')
  C.need(not os.path.lexists(row['target'])and not os.path.lexists(row['target'].with_name(row['target'].name+'.partial')),'fresh rootfs slots only, no previous/foreign cache adoption')
 limit=resource.getrlimit(resource.RLIMIT_FSIZE);C.need(all(v==resource.RLIM_INFINITY or v>=max(r['size']for r in rootfs)for v in limit),'rootfs prefetch must precede owner128MiB file cap; no limit is raised')
 S=module(asset/'seed.py','baseline_held_public14_seed');seed=S.seed(asset,deps);tick(deadline)
 C.need(set(p.name for p in deps.iterdir())==set(before)|names,'only exact14 package/signature cache additions')
 for n,key in before.items():C.need(exact(deps/n,package_rows[n],deadline)==key,'all previous source-owned cache inode/metadata/bytes held')
 for n in names:exact(deps/n,package_rows[n],deadline)
 fetched=[]
 for row in rootfs:
  tick(deadline)
  if opener is None:result=M.fetch(row)
  else:result=M.fetch(row,opener=opener)
  exact(row['target'],row,deadline);fetched.append(dict(filename=row['filename'],target=row['target'].name,url=row['url'],pin=dict(bytes=row['size'],sha256=row['sha256']),fetch=result))
 for n,key in before.items():C.need(exact(deps/n,package_rows[n],deadline)==key,'previous cache unchanged after rootfs acquisition')
 C.need({p.name for p in deps.iterdir()}==set(before)|names and {p.name for p in context.iterdir()}=={'deps','keys','rootfs.tar.gz','rootfs.tar.gz.sig'}and not any((context/'keys').iterdir()),'only exact companion additions after fetch')
 for n in names:exact(deps/n,package_rows[n],deadline)
 C.private(out);C.private(context);C.private(deps);C.private(context/'keys');tick(deadline)
 return dict(schema=1,status='EXACT_ORIGINAL574_PUBLIC14_AND_ROOTFS_PAIR_PREPARED_NOT_NATIVE_AUTHORITY',original_inputs=C.pin(raw),published18=dict(source=custody['source'],ref=custody['ref'],files=custody['files']),public14=seed,rootfs=fetched,previous_cache=dict(files=len(before),files_map={n:dict(bytes=package_rows[n]['size'],sha256=package_rows[n]['sha256'])for n in before},unchanged_inodes_metadata_bytes=True),prefetch_envelope_seconds=890,allowance='NONRESERVED_WITHIN_UNCHANGED_PREFETCH_SHELL',observed_fsize_limit=list(limit),owner_fsize_limit=128*1024**2,signature_authentication='UNCHANGED_NATIVE_GATE_STILL_REQUIRED',native_acceptance=False)
