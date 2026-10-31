#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit finite kit77 VM media roles; no actors without owned ARM context."""
import argparse,ast,base64,hashlib,importlib.util,json,os,re,shlex,shutil,stat,subprocess,sys,time,types
from pathlib import Path
HERE=Path(__file__).absolute().parent;PROVIDERS=HERE/'providers'
PROVIDER_SHA='a8b4c69c18ad48f44b7871e1f2099e30f2559e8fb71bfc3327e7f2ed5447a957'
FULL_PROVIDER_SHA='e9d91f48abbad36b10f57f6949a00ef8044bf58967f8831dbe4c297a0dcb8e6e'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
PURPOSE='KIT138_FRESH_ROOT_TEST_SOFTWARE_ARM_GUEST_FULL_LIFECYCLE_V1'
BUDGETS=dict(overall=15840,prepare=2400,qemu=10380,export=1200,cleanup=300,kit=4500,produce=300,receive=300,candidate=1500)
RUNTIME=frozenset(('proc','sys','dev','run','tmp'));INFRA=frozenset(('source','workspace','measurement'));MOUNT_FILES=frozenset(('etc/hosts','etc/hostname','etc/resolv.conf'))
MAX_FILE=16*1024**2;MAX_PUBLIC=126*1024**2;MAX_ROWS=2048

def need(v,s):
 if not v:raise ValueError(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return(json.dumps(v,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate media JSON key');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def relative(n):
 need(type(n)is str and 0<len(n)<=4096 and not n.startswith('/')and all(p not in('','.','..')and re.fullmatch('[A-Za-z0-9_.+-]+',p)for p in n.split('/')),'finite portable relative media path');return n
def read(p,cap=MAX_FILE):
 p=Path(p);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary media ancestry');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink media DATA');b=p.read_bytes();z=p.lstat();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(b)==a.st_size and key(a)==key(z),'whole stable media DATA');return b
def save(p,v):
 p=Path(p)
 with p.open('xb')as f:f.write(encoded(v))
 p.chmod(0o600)
def row(p):return pin(read(p))
def serial(nonce,role):
 need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and role in('boot','data'),'explicit serial nonce/role');v=base64.b85encode(hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode()+b'\0'+bytes.fromhex(nonce)).digest()[:16]).decode();need(len(v)==20 and ','not in v,'literal virtio serial');return v

def selection(v,role):
 need(type(v)is dict and set(v)=={'schema','purpose','identity','nonce','image','kernel','source_map_sha256','uid','gid','source_manifest','accepted_manifest','runtime_manifest','budgets','launcher_epoch_s'}and type(v['schema'])is int and v['schema']==1 and v['purpose']==PURPOSE,'closed explicit kit77 media selection')
 i=v['identity'];need(type(i)is dict and set(i)=={'source_sha','feature_code_sha','run_id','token','consumer'}and type(i['source_sha'])is str and re.fullmatch('[a-f0-9]{40}',i['source_sha'])and i['source_sha']==i['feature_code_sha']and type(i['run_id'])is str and re.fullmatch('[1-9][0-9]*',i['run_id'])and type(i['token'])is str and re.fullmatch('[a-f0-9]{16}',i['token'])and i['consumer']=='offline-kit-accepted-'+i['token'],'finite same-source owner identity')
 need(type(v['nonce'])is str and re.fullmatch('[a-f0-9]{32}',v['nonce'])and type(v['image'])is str and re.fullmatch('sha256:[a-f0-9]{64}',v['image']),'explicit nonce/immutable image')
 need(all(type(v[k])is int and v[k]==1001 for k in('uid','gid'))and v['budgets']==BUDGETS and all(type(x)is int for x in v['budgets'].values()),'fixed ordinary guest uid/gid/budgets')
 need(type(v['kernel'])is dict and type(v['kernel'].get('profile'))is dict and v['kernel']['profile']['release']=='7.1.13-generic16k-managed-gui','selected Core generic16K kernel')
 if role=='prepare':need(v['launcher_epoch_s']is None,'prepare must not invent launch UTC time')
 else:need(v['launcher_epoch_s']is None or(type(v['launcher_epoch_s'])is int and 1700000000<=v['launcher_epoch_s']<2**32),'finite actual launcher time')
 for key,maximum in [('source_manifest',256),('accepted_manifest',47),('runtime_manifest',32)]:
  d=v[key];need(type(d)is dict and 0<len(d)<=maximum and(key!='accepted_manifest'or len(d)==47),'finite complete input manifest');total=0
  for n,w in d.items():
   relative(n);need(key!='runtime_manifest'or'/'not in n,'runtime basenames only');need(type(w)is dict and set(w)=={'bytes','sha256','mode'}and type(w['bytes'])is int and 0<=w['bytes']<=MAX_FILE and type(w['mode'])is int and w['mode']in(0o644,0o755)and type(w['sha256'])is str and re.fullmatch('[a-f0-9]{64}',w['sha256']),'exact bounded input pin');total+=w['bytes']
  need(total<=64*1024**2,'finite input aggregate')
 need('guest_entry.py'in v['runtime_manifest'],'real guest PID1 entry required');need(type(v['source_map_sha256'])is str and re.fullmatch('[a-f0-9]{64}',v['source_map_sha256'])and v['source_manifest'].get('scripts/ci/offline-kit-accepted-native/source-map.json',{}).get('sha256')==v['source_map_sha256'],'exact source map selection join');return v

def guard(s):
 need(os.getpid()==1 and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('KIT77_VM_MEDIA_NONCE')==s['nonce']and os.environ.get('KIT77_VM_MEDIA_IMAGE')==s['image'],'owned explicit ARM media actor')
 need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'offline media actor')
 with Path('/proc/self/status').open()as stream:raw=stream.read(65537)
 need(len(raw)<=65536,'bounded own capability status');f=dict(x.split(':',1)for x in raw.splitlines()if':'in x);mask=0x8000001b
 need(all(int(f[k],16)==mask for k in('CapEff','CapPrm','CapBnd'))and int(f['CapInh'],16)==int(f['CapAmb'],16)==0 and f['NoNewPrivs'].strip()=='1','exact fivecap no-new-privileges media actor')

def provider_rows():
 whole_raw=read(HERE/'provider-pins.json');need(pin(whole_raw)['sha256']==FULL_PROVIDER_SHA,'pinned complete45 provider namespace');whole=decode(whole_raw);need(type(whole)is dict and len(whole)==45 and all(n.startswith('providers/')for n in whole),'closed complete provider roles');full={}
 for name,w in whole.items():
  relative(name);p=HERE/name;b=read(p);need(dict(pin(b),mode=stat.S_IMODE(p.stat().st_mode))==w,'exact complete provider '+name);full[name]=b
 paths=list(PROVIDERS.rglob('*'));expected_dirs={p.as_posix()for n in whole for p in Path(n).parents if p!=Path('providers')and p!=Path('.')};seen_dirs={'providers/'+p.relative_to(PROVIDERS).as_posix()for p in paths if p.is_dir()}
 need(not any(p.is_symlink()or not(p.is_file()or p.is_dir())for p in paths)and {'providers/'+p.relative_to(PROVIDERS).as_posix()for p in paths if p.is_file()}==set(whole)and seen_dirs==expected_dirs,'exact ordinary45 provider namespace')
 raw=read(HERE/'provider-manifest.json');need(pin(raw)['sha256']==PROVIDER_SHA,'pinned14 media provider manifest');v=decode(raw);need(v['schema']==1 and len(v['files'])==14,'closed14 selected media provider rows');result={}
 for name,w in v['files'].items():
  relative(name);need('providers/'+name in full and whole['providers/'+name]==w,'media subset joins complete provider pin');result[name]=full['providers/'+name]
 return result

def module(n,p):
 spec=importlib.util.spec_from_file_location(n,p);v=importlib.util.module_from_spec(spec);sys.modules[n]=v;spec.loader.exec_module(v);return v

def apis():
 rows=provider_rows();base=PROVIDERS/'media-source';update=base/'scripts/update';c=types.ModuleType('contract');c.__dict__.update(need=need,read=lambda p,cap=MAX_FILE:read(p,cap),decode=decode,encoded=encoded,pin=pin,sha=lambda b:pin(b)['sha256'],row=row,relative=relative,save=save);sys.modules['contract']=c
 for n in('capacity','supervision','full_root','measure_copy','root_path'):module(n,update/(n+'.py'))
 scope=module('_kit77_scope',base/'scripts/ci/full-root-upgrade-caller/persistent_scope.py')
 # Explicit new finite boundary policy; old adapter guards are never called or weakened.
 scope.RUNTIME=RUNTIME;scope.INFRASTRUCTURE=INFRA;scope.MOUNT_FILES=MOUNT_FILES
 caps=module('_kit77_caps',base/'scripts/ci/current604-public-pair-updater16k/cap_scope.py');audit=module('_kit77_elf',base/'scripts/ci/managed-gui-generic16k/elf_audit.py');reader=module('_kit77_reader',base/'scripts/virtual/generic16k/fixture.py')
 t=ast.parse(rows['media-source/scripts/ci/current604-public-pair-updater16k/disk.py']);functions=[n for n in t.body if isinstance(n,ast.FunctionDef)and n.name in('image_directory','formatter_recovery_directory')];need(len(functions)==2,'whole original two formatter functions');ns=dict(C=c,Path=Path,stat=stat,os=os,command=command);exec(compile(ast.Module(body=functions,type_ignores=[]),'pinned-original-formatter-functions','exec'),ns)
 return types.SimpleNamespace(scope=scope,roots=sys.modules['full_root'],copier=sys.modules['measure_copy'],caps=caps,audit=audit,reader=reader,formatter=ns['formatter_recovery_directory'],image_directory=ns['image_directory'])

def command(argv,seconds=600):
 need(type(seconds)is int and 0<seconds<=1200,'finite media command');p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds);need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=2*1024**2,'owned finite media command failure');return p.stdout

def mount_policy(rows):
 need(type(rows)is list and rows and len(rows)<=4096,'bounded mount rows');d={r['path']:r for r in rows};need(len(d)==len(rows)and'/'in d and all('/'+n in d for n in INFRA),'literal three media mounts');root=d['/']['id'];out=d['/measurement'];need(out['id']!=root and out['fs']not in {'tmpfs','ramfs','proc','sysfs','devtmpfs','overlay'},'separate persistent disk-backed measurement');observed=[]
 for r in rows:
  n=r['path'].lstrip('/')
  if not n:continue
  need(n.split('/')[0]in RUNTIME or n in INFRA or n in MOUNT_FILES,'unlisted persistent mount refused');observed.append(n)
 need(all(d['/'+n]['id']!=root for n in INFRA),'separate explicit source/workspace/measurement mounts');return dict(source_mount=root,target_mount=out['id'],observed_mounts=sorted(observed))

def role_copy(source,target,rows,*,source_checkout=False):
 need(type(source_checkout)is bool,'literal source checkout role')
 actual=set();directories=set();expected_dirs={p.as_posix()for n in rows for p in Path(n).parents if p!=Path('.')};count=0
 for folder,children,files in os.walk(source,followlinks=False):
  for name in tuple(children):
   path=Path(folder)/name
   if Path(folder)==source and(name=='.git'or source_checkout and name in('retained-native-tools','retained-public-inputs')):need(not path.is_symlink()and stat.S_ISDIR(path.lstat().st_mode),'ordinary checkout DATA directory');children.remove(name);continue
   count+=1;need(count<=4096 and not path.is_symlink(),'bounded ordinary input directory');directories.add(path.relative_to(source).as_posix())
  for name in files:
   count+=1;need(count<=4096,'bounded input role count');path=Path(folder)/name;need(not path.is_symlink()and path.is_file(),'ordinary input role file');actual.add(path.relative_to(source).as_posix())
 need(actual==set(rows)and directories==expected_dirs,'whole selected role namespace')
 for n,w in rows.items():
  p=source/n;b=read(p);need(dict(pin(b),mode=stat.S_IMODE(p.stat().st_mode))==w,'exact input role body');q=target/n;q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb')as stream:stream.write(b)
  q.chmod(w['mode'])

def bootstrap(s):
 nonce=s['nonce'];lines=['#!/usr/bin/bash','set -euo pipefail','export PATH=/usr/bin:/bin LC_ALL=C LANG=C','test "$(id -u)" = 0','mount -t proc -o nosuid,nodev,noexec proc /proc','grep -qw "kit77_vm='+nonce+'" /proc/cmdline','mount -t sysfs -o nosuid,nodev,noexec sysfs /sys','test "$(cat /sys/class/block/vda/serial)" = '+shlex.quote(serial(nonce,'boot')),'test "$(cat /sys/class/block/vdb/serial)" = '+shlex.quote(serial(nonce,'data')),'mount -o remount,nosuid /dev','mkdir -p /dev/pts','mount -t devpts -o nosuid,noexec,gid=5,mode=620 devpts /dev/pts','mount -t tmpfs -o nosuid,nodev,size=512m,mode=1777 tmpfs /tmp','mount -t tmpfs -o nosuid,nodev,size=128m,mode=755 tmpfs /run','mkdir -p /sys/fs/cgroup','mount -t cgroup2 -o nosuid,nodev,noexec cgroup2 /sys/fs/cgroup','mkdir /volume','mount -t ext4 -o rw,nosuid,nodev /dev/vdb /volume','mount --bind /volume/kit77 /kit77','umount /volume','rmdir /volume']
 for n in('source','accepted','runtime'):lines+=['mount --bind /kit77/'+n+' /kit77/'+n,'mount -o remount,bind,ro /kit77/'+n]
 return ('\n'.join(lines+['exec /usr/bin/python3 -I -B /kit77/runtime/guest_entry.py'])+'\n').encode()


def inventory(root,nodes):
 rows=[]
 for name,node in nodes.items():
  if not re.fullmatch(r'var/lib/pacman/local/[^/]+/desc',name):continue
  need(node['type']=='file','ordinary installed DB descriptor');raw=read(Path(root)/name,65536);need(pin(raw)=={k:node[k]for k in('bytes','sha256')},'installed DB descriptor pin');fields=raw.decode().splitlines();values={}
  for key in('NAME','VERSION'):
   matches=[i for i,x in enumerate(fields)if x=='%'+key+'%'];need(len(matches)==1 and matches[0]+1<len(fields),'unique installed DB identity');values[key]=fields[matches[0]+1];need(values[key]and not any(c.isspace()for c in values[key]),'finite installed identity value')
  rows.append(values['NAME']+' '+values['VERSION'])
 need(len(rows)==574 and len({r.split(' ',1)[0]for r in rows})==574,'complete574 installed inventory');return ('\n'.join(sorted(rows))+'\n').encode()


def overlay_model(before,overlay):
 expected={'init-kit77','kit77','etc/machine-id'}|({'.dockerenv'}if'.dockerenv'in before else set());need(type(overlay)is dict and set(overlay)==expected,'literal complete VM-only overlay');result=dict(before)
 for name,value in overlay.items():
  need(type(value)is dict and set(value)=={'before','after'}and value['before']==before.get(name),'exact overlay original node join')
  if value['after']is None:need(name=='.dockerenv','only inherited Docker marker removal');result.pop(name)
  else:result[name]=value['after']
 return result

def prepare(s,out=Path('/measurement')):
 need(not any(out.iterdir())and shutil.disk_usage(out).free>=48*1024**3,'fresh48GiB owned media stage');a=apis();stage=out/'stage';stage.mkdir(mode=0o700);info=stage.lstat();save(out/'stage-owner.json',dict(nonce=s['nonce'],device=info.st_dev,inode=info.st_ino));boot=stage/'boot';data=stage/'data';data.mkdir(mode=0o700)
 def limits():return a.roots.Limits(deadline=time.monotonic()+900,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3,max_package_files=100000)
 policy=mount_policy(a.scope.mounts(a.scope._mount_table()));before,_=a.scope.source_manifest(Path('/'),limits(),a.roots,policy)
 capability=a.caps.derive(read(PROVIDERS/'media-source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|RUNTIME);mapping=capability.observe(Path('/'),a.caps.nodes(before),limits())
 copied=a.copier.copy_data(Path('/'),boot,limits=limits(),excluded=RUNTIME|(INFRA&set(policy['observed_mounts']))|MOUNT_FILES,absolute_paths=True);need(not copied['unsupported_counts'],'complete original574 copy');a.scope._restore_boundaries(Path('/'),boot,before,a.roots,a.copier,limits())
 measured=a.roots.observe(boot,limits=limits(),hardlinks='generic-development-internal',absolute_paths=True);need(measured['complete']is True and measured['nodes']==before,'whole original574 node/content/hardlink equality');capability.restore(boot,a.caps.nodes(before),mapping,limits());after,_=a.scope.source_manifest(Path('/'),limits(),a.roots,policy);need(before==after and capability.observe(Path('/'),a.caps.nodes(after),limits())==mapping,'original inventory/capability preservation')
 lock='scripts/ci/offline-kit-accepted-native/expected-packages.lock';expected=read(Path('/source')/lock);need(pin(expected)['sha256']==LOCK and inventory(Path('/'),before)==inventory(boot,before)==expected,'complete original574 installed inventory preserved');need(not any(os.path.lexists(boot/n)for n in('kit77','init-kit77','volume')),'fresh reserved bootstrap paths')
 kit=data/'kit77';kit.mkdir(mode=0o700)
 for role,source,key in [('source',Path('/source'),'source_manifest'),('accepted',Path('/workspace/accepted'),'accepted_manifest'),('runtime',Path('/workspace/runtime'),'runtime_manifest')]:
  target=kit/role;target.mkdir();role_copy(source,target,s[key],source_checkout=role=='source')
 for role in('work','public'):(kit/role).mkdir(mode=0o700)
 save(kit/'selection.json',s);(boot/'kit77').mkdir(mode=0o700);init=bootstrap(s);(boot/'init-kit77').write_bytes(init);(boot/'init-kit77').chmod(0o755)
 overlay={'init-kit77':dict(before=None,after=dict(type='file',uid=0,gid=0,mode=0o755,**pin(init))),'kit77':dict(before=None,after=dict(type='directory',uid=0,gid=0,mode=0o700))}
 marker=boot/'.dockerenv'
 if os.path.lexists(marker):need(marker.is_file()and not marker.is_symlink()and marker.stat().st_nlink==1 and marker.stat().st_size==0,'ordinary empty inherited Docker marker');overlay['.dockerenv']=dict(before=before['.dockerenv'],after=None);marker.unlink()
 machine=boot/'etc/machine-id';need(machine.is_file()and not machine.is_symlink()and machine.stat().st_nlink==1,'ordinary original machine-id');old=read(machine,128);need(pin(old)=={k:before['etc/machine-id'][k]for k in('bytes','sha256')},'original machine-id baseline');overlay['etc/machine-id']=dict(before=before['etc/machine-id'],after=dict(before['etc/machine-id'],**pin((s['nonce']+'\n').encode())));machine.write_text(s['nonce']+'\n')
 overlay_model(before,overlay)
 save(kit/'baseline-nodes.json',before);save(kit/'capabilities.json',mapping);save(kit/'overlay.json',overlay)
 audit=a.audit.audit(boot,a.reader);save(out/'source-nodes.json',before);save(out/'source-capabilities.json',mapping);save(out/'boot-overlay.json',overlay);save(out/'elf16k.json',audit)
 for name,size in [('boot',16*1024**3),('data',24*1024**3)]:
  root=stage/name;allocated=sum(p.lstat().st_blocks*512 for p in root.rglob('*'));need(allocated<=10*1024**3 and shutil.disk_usage(out).free>=allocated+8*1024**3,'bounded source/disk allocation');image=out/(name+'.raw')
  with image.open('xb')as stream:stream.truncate(size)
  command(['/usr/bin/mkfs.ext4','-F','-b','4096','-m','0','-L','KIT77_'+name.upper(),'-d',root,image])
  if name=='boot':a.formatter(image,before,out)
 current=stage.lstat();need((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino)and not stage.is_mount()and shutil.rmtree.avoids_symlink_attacks,'exact original stage inode');shutil.rmtree(stage)
 save(out/'prepared.json',dict(status='PREPARED_KIT77_MEDIA_NOT_BOOTED',nonce=s['nonce'],image=s['image'],source_inventory_sha256=pin(encoded(before))['sha256'],capabilities_sha256=pin(encoded(mapping))['sha256'],boot_bytes=16*1024**3,data_bytes=24*1024**3,serials={n:serial(s['nonce'],n)for n in('boot','data')},launcher_epoch_s=None,acceptance=False))
 for p in out.iterdir():os.chown(p,s['uid'],s['gid'])


PUBLIC_BODY_PINS={'public_names':'670c5fb9aa59f04a7db19359f4dda08aa9a9e7cdf467c491e1aeb324e182189f','portable_public':'13f3a20d76851807b63f60cc39aab6af3a8dee2da154d6e1c8e6c2fd4508bd63','private_retention':'a515b2ddd891b345180e76321959873bfffebe42c58725c3559e67c7e4e386e3'}
VM_PUBLIC={'vm/'+n+'.json'for n in ('result','root','clock','source-proof')}|{'vm-actors/actors.json'}|{'vm-actors/%04d.log'%i for i in range(6)}|{'vm/phases/'+short+'-'+phase+suffix for short in('maintenance','diagnostics')for phase in('produce','receive','candidate')for suffix in('.json','-boundary.json','.descriptor.json')}
def fresh_public(s,allowed):
 allowed=set(allowed);native='scripts/ci/offline-kit-accepted-native/accepted/'
 allowed-={'accepted-carrier/'+n[len(native):]for n in s['source_manifest']if n.startswith(native)}
 need(len(s['accepted_manifest'])==47,'complete fresh TEST carrier for public mapping');allowed|={'accepted-carrier/'+n for n in s['accepted_manifest']}
 for short,package,version in(('maintenance','cachy-asahi-maintenance','0.1.0-2'),('diagnostics','cachy-asahi-session-diagnostics','0.1.0-3')):
  public=short+'/trial/public/';archive=package+'-'+version+'-any.pkg.tar.xz.sig'
  allowed-={public+'producer-logs/'+n+'.json'for n in('original-key-dearmor','original-signature')};allowed|={public+'producer-logs/'+n+'.json'for n in('root-test-key-dearmor','root-test-signature')}
  old=('original-signature-verification.json','original-'+archive,'original-'+short+'.TEST-public.asc','original-'+short+'.TEST-original-status.txt','original-'+short+'.provenance.json')
  new=('fresh-root-test-signature-verification.json','root-test-profile.json','root-test-'+archive,'root-test-'+short+'.TEST-public.asc','root-test-'+short+'.TEST-original-status.txt','historical-'+archive,'historical-'+short+'.TEST-public.asc','historical-'+short+'.TEST-original-status.txt','historical-'+short+'.provenance.json')
  for label in('good','expired','tampered','wrong-key','bootstrap-tampered'):
   root=public+'transport/'+label+'/release/evidence/';allowed-={root+n for n in old};allowed|={root+n for n in new}
 return allowed


def public_allowlist(s,source=Path('/source')):
 name='scripts/ci/offline-kit-accepted-native/owner.py';raw=read(source/name);need(dict(pin(raw),mode=stat.S_IMODE((source/name).stat().st_mode))==s['source_manifest'][name],'whole sealed source owner before pure public helpers');text=raw.decode();nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name in PUBLIC_BODY_PINS];need(len(nodes)==3 and all(pin(ast.get_source_segment(text,n).encode())['sha256']==PUBLIC_BODY_PINS[n.name]for n in nodes),'byte-held finite public helper functions');ns=dict(re=re,LANE='scripts/ci/offline-kit-accepted-native',RETENTION_STEPS=('install','reinstall','remove','reinstall-after-remove','final-remove'));exec(compile(ast.Module(body=nodes,type_ignores=[]),'three-pinned-pure-public-helpers','exec'),ns);allowed=fresh_public(s,ns['public_names']({'files':s['source_manifest']}))|{'source/'+n for n in s['source_manifest']}|VM_PUBLIC
 return allowed,ns['portable_public'],ns['private_retention']

def export(s,out=Path('/measurement')):
 a=apis();allowed,portable,private=public_allowlist(s);image=out/'data.raw';target=out/'guest-export';need(not target.exists(),'fresh guest export');held=image.lstat();need(stat.S_ISREG(held.st_mode)and held.st_nlink==1 and held.st_size==24*1024**3 and held.st_uid==s['uid']and not any(p.is_symlink()for p in(image,*image.parents)),'exact owned data disk');cache={};seen_inodes={}
 def listing(parent):
  if parent not in cache:cache[parent]=a.image_directory(command(['/usr/bin/debugfs','-R','ls -p /kit77/public'+('/'+parent if parent else ''),image],60))
  return cache[parent]
 def entry(name):
  parts=name.split('/');parent=''
  for component in parts[:-1]:
   value=listing(parent).get(component);need(value is not None and stat.S_ISDIR(value['mode'])and value['uid']==value['gid']==0,'ordinary root-owned indexed parent');parent=parent+'/'+component if parent else component
  value=listing(parent).get(parts[-1]);need(value is not None and stat.S_ISREG(value['mode'])and value['uid']==value['gid']==0 and type(value['size'])is int and 0<=value['size']<=MAX_FILE,'ordinary bounded indexed public file');need(value['inode']not in seen_inodes or seen_inodes[value['inode']]==name,'public hardlink aliases refused');seen_inodes[value['inode']]=name;return value
 index_entry=entry('index.json');need(index_entry['size']<=2*1024**2,'bounded public index');target.mkdir(mode=0o700)
 def get(name):
  value=entry(name);path=target/name;path.parent.mkdir(parents=True,exist_ok=True);command(['/usr/bin/debugfs','-R','dump /kit77/public/'+name+' '+str(path),image],120);raw=read(path);need(len(raw)==value['size'],'complete original indexed bytes');return raw
 raw=get('index.json');index=decode(raw);need(type(index)is dict and set(index)=={'schema','purpose','identity','nonce','status','result_status','files','bytes','acceptance'}and type(index['schema'])is int and index['schema']==1 and index['purpose']=='KIT138_FRESH_ROOT_TEST_GUEST_PUBLIC_INDEX_V1'and index['identity']==s['identity']and index['nonce']==s['nonce']and index['status']=='KIT138_FRESH_ROOT_TEST_GUEST_PUBLIC_DATA_ONLY'and type(index['result_status'])is str and index['acceptance']is False and type(index['files'])is dict and 0<len(index['files'])<=MAX_ROWS-1,'closed nonadmitting public index');files={'index.json':pin(raw)};total=len(raw);advertised=0
 for name,w in index['files'].items():
  need(name!='index.json'and name in allowed and portable(name)and not private(tuple(name.split('/'))),'exact old public/source/fixedVM filename only');need(type(w)is dict and set(w)=={'bytes','sha256'}and type(w['bytes'])is int and 0<=w['bytes']<=MAX_FILE and type(w['sha256'])is str and re.fullmatch('[a-f0-9]{64}',w['sha256']),'exact public file pin');advertised+=w['bytes'];need(len(raw)+advertised<=MAX_PUBLIC,'aggregate public bytes before export');need(entry(name)['size']==w['bytes'],'indexed original leaf size')
 need(type(index['bytes'])is int and index['bytes']==advertised,'exact public index aggregate')
 for name,w in sorted(index['files'].items()):
  payload=get(name);need(pin(payload)==w,'public original byte pin');files[name]=pin(payload);total+=len(payload)
 # Only explicitly indexed paths are looked up/dumped; unrelated roots are never scanned.
 after=image.lstat();key=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns);need(key(after)==key(held),'unchanged owned data disk through export')
 for p in sorted(target.rglob('*'),reverse=True):os.chown(p,s['uid'],s['gid'])
 os.chown(target,s['uid'],s['gid']);save(out/'guest-export.json',dict(status='EXACT_KIT77_PUBLIC_FILES_DATA_ONLY',nonce=s['nonce'],files=files,bytes=total,acceptance=False));os.chown(out/'guest-export.json',s['uid'],s['gid'])


def scrub(s,out=Path('/measurement')):
 owner=decode(read(out/'stage-owner.json'));stage=out/'stage';i=stage.lstat();need(owner==dict(nonce=s['nonce'],device=i.st_dev,inode=i.st_ino)and stat.S_ISDIR(i.st_mode)and not stage.is_symlink()and not stage.is_mount()and shutil.rmtree.avoids_symlink_attacks,'exact owned stage inode/nonce only');shutil.rmtree(stage)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=('prepare','export','scrub'));role=p.parse_args().role;s=selection(decode(read(Path('/workspace/selection.json'))),role);guard(s);globals()[role](s)
if __name__=='__main__':main()

