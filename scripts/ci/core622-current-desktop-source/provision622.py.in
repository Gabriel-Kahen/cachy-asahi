# SPDX-License-Identifier: MIT
"""Five-cap copied574→607 provisioner and exact owned-root retirement."""
import gzip,hashlib,json,os,stat,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,desktop622 as X,formation622 as F,media
ROLES={'current607-inputs','fresh607-source','current607-code','baseline-cache'}
ROOT=Path('/measurement/current607')

def profile():return C.decode(C.read(Path(__file__).with_name('composition.json'),4*1024**2))
def private_scope(original):return X.clone(original,INFRASTRUCTURE=original.INFRASTRUCTURE|ROLES)
def capabilities(helper,raw,omitted):
 import inspect
 body=inspect.getsource(helper.derive);old="'etc/hosts','etc/hostname','etc/resolv.conf'}";new="'etc/hosts','etc/hostname','etc/resolv.conf','current607-inputs','fresh607-source','current607-code','baseline-cache'}"
 C.need(body.count(old)==1,'finite exact original capability boundary allowlist');changed=body.replace(old,new);C.need(changed.replace(new,old)==body,'whole original capability derivation inverse')
 namespace=dict(vars(helper));exec(compile(changed,'core622-fixed-infrastructure-caps','exec'),namespace);return namespace['derive'](raw,omitted)

def readonly(root,identity=None):
 root=Path(root);C.need(root.is_absolute()and not any(p.is_symlink()for p in(root,*root.parents)),'literal ordinary read-only bind role');fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);C.need(stat.S_ISDIR(st.st_mode)and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'fresh actual read-only bind readback');C.need(identity is None or [st.st_dev,st.st_ino]==identity,'exact actual provisioned root inode');C.need(C.identity(st)==C.identity(os.fstat(fd))==C.identity(root.stat()),'stable actual root descriptor/path')
 finally:os.close(fd)

def owned(selected):
 C.selection(selected);C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CAA_CORE7_PREPARE')==selected['nonce']and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline original five-cap ARM PID1 preparer')
 fields=dict(v.split(':',1)for v in Path('/proc/self/status').read_text().splitlines()if ':'in v);C.need(all(int(fields[k],16)==0x8000001b for k in('CapEff','CapPrm','CapBnd'))and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0 and fields['NoNewPrivs'].strip()=='1','exact original five caps and NNP')
 return selected

def write(name,value,uid,gid,compressed=False):
 raw=C.encoded(value);C.need(len(raw)<=256*1024**2,'original full graph raw cap');raw=gzip.compress(raw,mtime=0)if compressed else raw;C.need(len(raw)<=64*1024**2 and sum(p.stat().st_size for p in Path('/out').iterdir()if p.is_file())+len(raw)<=512*1024**2,'original aggregate export cap');path=Path('/out')/name;C.need(not path.exists(),'fresh fixed complete proof leaf');path.write_bytes(raw);os.chown(path,uid,gid);return C.pin(raw)

def payload(P,ready,rows,code,end):
 """Keep original archive parser limits; clamp its clock to this same phase."""
 old_load=P.load
 def load(name,path):
  module=old_load(name,path)
  if str(path).endswith('/scripts/update/archive_stream.py'):
   original=module.Limits;module=X.clone(module)
   def limits(*args,**kw):
    values=list(args);C.need(len(values)==7 and not kw,'held seven-field payload parser limits');values[-1]=min(values[-1],end);return original(*values)
   module.Limits=limits
  return module
 out=X.clone(P,load=load);result=out.payload(ready,rows,code);C.need(time.monotonic()<end,'whole payload before original phase expiry');return result

def keys(api,record,end):
 path=Path('/tmp/current607-public-gpg');C.need(not path.exists(),'fresh public-only provisioning key home');path.mkdir(mode=0o700);(path/'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n');argv=['/usr/bin/gpg','--batch','--no-options','--homedir',str(path),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
 def command(args,seconds=30):
  remaining=end-time.monotonic();C.need(remaining>0,'same provisioning phase clock');row,out,err,error=api['runtime'].run_command(args,Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),min(seconds,remaining),1024**2);C.need(error is None and row['exit_code']==0 and row['group_absence_verified'],'original public-key command exit/group absence');return out
 for k in record['keyrings']:
  C.need(k['path'].startswith('keys/')and '/'not in k['path'][5:],'flat exact fresh public key role');C.need(C.pin(C.read(Path('/current607-inputs')/k['path']))==dict(bytes=k['size'],sha256=k['sha256']),'every fresh public key byte')
 command(argv+['--import',*[str(Path('/current607-inputs')/k['path'])for k in record['keyrings']]]);C.need(not command(argv+['--with-colons','--list-secret-keys']),'no secret key mounted into provisioner')
 trust=path/'ownertrust';trust.write_text(''.join(s+':6:\n'for s in sorted(record['preparation']['signer_roles'].values())));command(argv+['--import-ownertrust',str(trust)]);return path,command

def prepare():
 selected=owned(C.decode(C.read('/workspace/selection.json')));ms=C.decode(C.read('/workspace/media-selection.json'));value=profile();end=float(os.environ['CAA_CORE622_PHASE_END']);C.need(0<end-time.monotonic()<=1900 and not ROOT.exists(),'fresh owned607 root inside unchanged1900 media phase')
 for role in ROLES:readonly(Path('/')/role)
 out=Path('/measurement');st=out.stat();lease=dict(schema=1,nonce=selected['nonce'],parent=[st.st_dev,st.st_ino],root=None,status='INTENT_FRESH_OWNED607_PROVISION',phase_deadline=end);(out/'current607-lease.json').write_bytes(C.encoded(lease));os.chown(out/'current607-lease.json',ms['uid'],ms['gid'])
 D=media.module('/source');scope,roots,copier,_=D.apis();scope=private_scope(scope);limits=roots.Limits(deadline=end,max_packages=622,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 policy=scope.mount_policy(Path('/'),ROOT,scope.mounts(scope._mount_table()));before,_=scope.source_manifest(Path('/'),limits,roots,policy);caps=capabilities(D.cap_scope,C.read('/source/media-source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|scope.RUNTIME);mapping=caps.observe(Path('/'),D.cap_scope.nodes(before),limits)
 copy=copier.copy_data(Path('/'),ROOT,limits=limits,excluded=scope.RUNTIME|(scope.INFRASTRUCTURE&set(policy['observed_mounts']))|scope.MOUNT_FILES,absolute_paths=True);C.need(not copy['unsupported_counts'],'whole original five-cap copy without omissions');scope._restore_boundaries(Path('/'),ROOT,before,roots,copier,limits)
 measured=roots.observe(ROOT,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);C.need(measured['complete']and measured['nodes']==before,'complete actual574 copied nodes/hardlinks');caps.restore(ROOT,D.cap_scope.nodes(measured['nodes']),mapping,limits)
 st=ROOT.stat();lease.update(root=[st.st_dev,st.st_ino],status='OWNED_CURRENT607_ROOT_LIVE');(out/'current607-lease.json').write_bytes(C.encoded(lease));os.chown(out/'current607-lease.json',ms['uid'],ms['gid'])
 import adapter
 core=adapter.core(Path('/workspace/core-source'));api=core.api;initial=api['db'].database(ROOT,max_packages=622,max_files=100000,max_nodes=500000,observed=measured['nodes']);C.need({r['name']:r['version']for r in initial}==value['before574'],'actual574 copied database')
 ready=Path('/current607-inputs');record=C.decode(C.read(ready/'manifest.json',4*1024**2));rows=X.manifest(value,record);P=C.load('_core622_original_full607_archive_parser',Path('/fresh607-source/parent604/profile.py'))
 for r in rows:
  for rel,pin in((r['archive'],dict(bytes=r['size'],sha256=r['sha256'])),(r['signature'],dict(bytes=r['signature_size'],sha256=r['signature_sha256']))):P.checked(ready,rel,pin,maximum=256*1024**2)
 signed=payload(P,ready,rows,Path('/current607-code'),end);C.need(signed['packages']==value['before607'],'complete authenticated607 payload projection')
 rawlock=C.decode(C.read('/workspace/core-source/scripts/ci/core-native-lifecycle/retained/desktop574-inputs.lock.json',4*1024**2));retired=next(r for r in rawlock['packages']if r['name']=='libfdk-aac');oldpath=Path('/baseline-cache')/retired['filename'];C.need(C.pin(C.read(oldpath,128*1024**2))==dict(bytes=retired['size'],sha256=retired['sha256']),'exact original upstream codec archive');removed=core.C.P.archive(oldpath)
 keyhome,command=keys(api,record,end)
 try:
  operands=[dict(r,archive=ready/r['archive'],signature=ready/r['signature'])for r in rows];transaction=X.provision(api,ROOT,keyhome,Path('/out/current607-provision.log'),operands,value,end)
  graph=roots.observe(ROOT,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);actual_caps=caps.observe(ROOT,D.cap_scope.nodes(graph['nodes']),limits);final=api['db'].database(ROOT,max_packages=622,max_files=100000,max_nodes=500000,observed=graph['nodes'])
  sys.path.insert(0,str(core.root/'runtime/runtime-vm/scripts/update'));import aux_checkpoint,root_link_selection
  root_link_selection.check(graph,limits);checkpoint=aux_checkpoint.checkpoint(ROOT,graph,limits);aux=core.F.capture(api,ROOT,graph,limits,core.F.read_aux(ROOT));core.F.check_record(aux,graph['nodes']);auxiliary=dict(status='FULL_FD_CHECKPOINT_AND_LIVE_AUXILIARY_LIBRARY_KEYS',checkpoint=api['capabilities'].digest({k:v for k,v in checkpoint.items()if k not in('main_bytes','aux_bytes')}),live_auxiliary=aux)
  validation=F.check(value,measured,graph,mapping,actual_caps,signed,removed,initial,final,auxiliary);source_after,_=scope.source_manifest(Path('/'),limits,roots,policy);C.need(source_after==before and caps.observe(Path('/'),D.cap_scope.nodes(source_after),limits)==mapping,'complete original image source nodes/caps unchanged')
  files={};files['current607-root.json.gz']=write('current607-root.json.gz',graph,ms['uid'],ms['gid'],True);files['current607-capabilities.json']=write('current607-capabilities.json',actual_caps,ms['uid'],ms['gid']);files['current607-database.json']=write('current607-database.json',final,ms['uid'],ms['gid']);files['current607-auxiliary.json']=write('current607-auxiliary.json',auxiliary,ms['uid'],ms['gid'])
  report=dict(schema=1,status=validation['status'],nonce=selected['nonce'],scope=X.PROVISIONING,normal_hook_installation=False,root_identity=lease['root'],parent_identity=lease['parent'],copy=copy,transaction=transaction,validation=validation,files=files,graph_nodes_sha256=hashlib.sha256(json.dumps(graph['nodes'],sort_keys=True).encode()).hexdigest(),capabilities_sha256=api['capabilities'].digest(actual_caps),database_sha256=value['fresh607']['sha256'],packages=607,phase_deadline=end,fit='NOT_ESTABLISHED',hardware='NOT_RUN');write('current607-formation.json',report,ms['uid'],ms['gid']);return report
 finally:command(['/usr/bin/gpgconf','--homedir',str(keyhome),'--kill','all'],15)

def retire():
 selected=owned(C.decode(C.read('/workspace/selection.json')));lease=C.decode(C.read('/measurement/current607-lease.json'));C.need(lease['nonce']==selected['nonce']and lease['root']is not None and [ROOT.parent.stat().st_dev,ROOT.parent.stat().st_ino]==lease['parent'],'exact owned parent/nonce before retirement')
 import adapter
 api=adapter.core('/workspace/core-source').api;limits=api['roots'].Limits(deadline=float(os.environ['CAA_CORE622_PHASE_END']),max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3);limits.tick();sys.path.insert(0,str(Path('/workspace/core-source/runtime/runtime-vm/scripts/update')));import disposable_copy
 parent=api['roots']._open_root(ROOT.parent);fd=None
 try:
  fd=os.open(ROOT.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);mount=api['roots']._mount_id(fd,limits);C.need([os.fstat(fd).st_dev,os.fstat(fd).st_ino]==lease['root'],'same actual provisioned607 root identity');disposable_copy._same(parent,ROOT.name,fd,tuple(lease['root']),mount,limits);disposable_copy._empty(fd,mount,limits,[0]);disposable_copy._same(parent,ROOT.name,fd,tuple(lease['root']),mount,limits);os.rmdir(ROOT.name,dir_fd=parent);C.need(not ROOT.exists(),'actual owned607 root removed before original cleanup')
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)
 ms=C.decode(C.read('/workspace/media-selection.json'));return write('current607-retirement.json',dict(status='PASS_EXACT607_ROOT_REMOVED_BEFORE_ORIGINAL_CLEANUP',nonce=selected['nonce'],root=lease['root'],parent=lease['parent']),ms['uid'],ms['gid'])

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('role',choices=('provision607','retire607'));a=p.parse_args();prepare()if a.role=='provision607'else retire()
