#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit-input, render-only native Linux Sway/Done developer counterfactual."""
import argparse,hashlib,json,os,platform,re,shutil,signal,stat,struct,subprocess,sys,tarfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SYSTEM={'fish':'/usr/bin/fish','grim':'/usr/bin/grim','busctl':'/usr/bin/busctl','dbus_daemon':'/usr/bin/dbus-daemon','notify_send':'/usr/bin/notify-send','timeout':'/usr/bin/timeout','bwrap':'/usr/bin/bwrap','sleep':'/usr/bin/sleep','shell':'/usr/bin/bash','python':str(Path(sys.executable).resolve())}
TOOLS=set(SYSTEM)|{'sway','swaymsg','mako','makoctl'}
STYLE='c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504'

SOURCE_PINS={'controller.py': '487d16718115d25bb94f2d82885690e4f4a64e38a12559d820fd9a31b2209996', 'observation.py': '153fad25f0b5f58730cd077bdf414ed2b30ae6d7c780aa4f8f99484b7348d057', 'monitor.py': '7704da1b060e739f63e4d7062a02938e64bcfbe1c10b4d6581532ded2f194de0', 'capture.py': '283160761381a55b441396b4c3aa8049ee240f5c78656c26165d62c2efc56cbc', 'fish_terminal.py': 'fb6ec2870544fccfd3aeb005657709093f9da7dfe7650c06eb901526faba4734', 'done-lock.json': 'e7de2d6d72e4f6f3882c5b5c5c0c65c71a89146e629ceb17004a45013f607026'}

def need(ok,why):
 if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def path(value):
 need(type(value) is str and value.startswith('/') and str(Path(value))==value and '..' not in Path(value).parts,'absolute normalized path required')
 p=Path(value)
 for q in [*reversed(p.parents),p]:
  need(not q.is_symlink(),'symlink path component refused')
 return p

def native_architecture():
 name=platform.machine();machines={'x86_64':62,'aarch64':183}
 need(sys.platform=='linux' and name in machines,'native Linux x86_64 or aarch64 required')
 return {'name':name,'elf_machine':machines[name]}

def native_elf(raw,architecture):
 need(raw[:6]==b'\x7fELF\x02\x01' and len(raw)>=64 and struct.unpack_from('<H',raw,18)[0]==architecture['elf_machine'],'native '+architecture['name']+' ELF required')


def ordinary(value,expected,limit=32*1024**2,executable=False,known_links=(),architecture=None):
 p=path(value);before=p.lstat()
 if before.st_nlink!=1:
  need(len(known_links)==before.st_nlink==3 and str(p) in known_links,'ordinary single-link input required')
  for alias in known_links:
   other=path(alias).lstat();need(stat.S_ISREG(other.st_mode) and (other.st_dev,other.st_ino,other.st_nlink)==(before.st_dev,before.st_ino,3),'complete known Fish multicall alias group required')
 need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,os.getuid()) and not before.st_mode&0o6022,'ordinary single-link input required')
 need(0<=before.st_size<=limit and re.fullmatch('[0-9a-f]{64}',expected or '') is not None,'bounded input/hash required')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  held=os.fstat(stream.fileno());need((held.st_dev,held.st_ino)==(before.st_dev,before.st_ino),'input identity changed');raw=stream.read(limit+1)
 after=p.lstat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==before.st_size and sha(raw)==expected,'input hash/drift refused')
 if executable:
  need(before.st_mode&0o111,'executable input required');native_elf(raw,native_architecture() if architecture is None else architecture)
 return p,raw,(before.st_dev,before.st_ino)

def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs)

def host(render):
 need(Path(SYSTEM['python']).is_relative_to('/usr'),'native Python runtime must be under readonly /usr')
 need(sys.platform=='linux' and platform.machine() in ('x86_64','aarch64') and os.getuid()!=0,'ordinary native Linux x86_64 or aarch64 caller required')
 p=path(render);s=p.lstat();need(re.fullmatch('/dev/dri/renderD[0-9]+',render) is not None and stat.S_ISCHR(s.st_mode) and os.major(s.st_rdev)==226 and os.minor(s.st_rdev)>=128 and os.access(p,os.R_OK|os.W_OK),'accessible actual DRM render node required')

def archive(raw,lock):
 import io
 result={};seen=set();total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:xz') as stream:
  for m in stream:
   name=m.name;need(name not in seen and not name.startswith('/') and '..' not in Path(name).parts and not name.startswith('./'),'unsafe/duplicate package member')
   seen.add(name);need(len(seen)<=128 and (m.isdir() or m.isfile()) and not m.pax_headers and not m.mode&0o7022,'plain bounded package metadata required')
   if m.isdir():continue
   need(name in lock['payload'] or name in {'.PKGINFO','.BUILDINFO','.MTREE'},'undeclared package member')
   total+=m.size;need(m.size<=131072 and total<=262144,'package decoded cap')
   data=stream.extractfile(m).read(m.size+1);need(len(data)==m.size,'package length differs')
   if name in lock['payload']:
    row=lock['payload'][name];need(m.mode==row['mode'] and len(data)==row['size'] and sha(data)==row['sha256'],'original Done payload differs');result[name]=data
 need(set(result)==set(lock['payload']),'incomplete Done payload');return result

def system_aliases():
 need(Path('/usr/bin/sh').resolve()==Path(SYSTEM['shell']),'fixed sh→bash runtime alias required')

def preflight(inputs,input_sha,work):
 architecture=native_architecture()
 sources_code={name:ordinary(str(HERE/name),expected,131072)[1] for name,expected in SOURCE_PINS.items()}
 p,raw,_=ordinary(inputs,input_sha,32768);v=decode(raw)
 need(type(v) is dict and set(v)=={'schema_version','tools','libraries','mako_config','done_archive','render_node','source_metadata'} and type(v['schema_version']) is int and v['schema_version']==1,'exact input schema1 required')
 need(type(v['source_metadata']) is dict and len(encoded(v['source_metadata']))<=8192,'bounded caller-declared source metadata required')
 need(type(v['tools']) is dict and set(v['tools'])==TOOLS and type(v['libraries']) is list and len(v['libraries'])<=16,'finite exact tool/library inputs required')
 w=path(work);need(not w.exists() and not w.is_symlink() and w.parent.is_dir(),'fresh work directory required')
 need(w.parent.stat().st_uid==os.getuid() and not w.parent.stat().st_mode&0o022,'owned non-public work parent required')
 binaries={};libraries={};identities=set();sources=[];total=[0]
 def take(row,executable=False,limit=32*1024**2,known_links=()):
  need(type(row) is dict and set(row)=={'path','sha256'},'exact path/hash row required')
  q,data,identity=ordinary(row['path'],row['sha256'],limit,executable,known_links,architecture)
  total[0]+=len(data);need(total[0]<=128*1024**2,'total input byte cap128MiB')
  need(identity not in identities,'aliased input refused');identities.add(identity);sources.append(q)
  need(w not in q.parents and q not in w.parents,'work/input overlap refused');return q,data
 for name,row in v['tools'].items():
  q,data=take(row,True,known_links=('/usr/bin/fish','/usr/bin/fish_indent','/usr/bin/fish_key_reader') if name=='fish' else ())
  if name in SYSTEM:need(str(q)==SYSTEM[name],'fixed native system tool path required: '+name)
  binaries[name]=(q,data)
 for row in v['libraries']:
  q,data=take(row);need(re.fullmatch('lib[A-Za-z0-9_.+-]+\\.so(?:\\.[0-9]+)*',q.name) is not None and q.name not in libraries,'ordinary uniquely named shared library required');native_elf(data,architecture);libraries[q.name]=(q,data)
 config,data=take(v['mako_config'],limit=4096);need(sha(data)==STYLE,'unchanged shipped Mako style required')
 lock=decode((HERE/'done-lock.json').read_bytes());q,done=take(v['done_archive'],limit=65536);need(len(done)==lock['bytes'] and sha(done)==lock['sha256'],'exact retained Done0.1.0-2 archive required');payload=archive(done,lock)
 system_aliases()
 host(v['render_node'])
 return {'native_arch':architecture,'inputs':v,'inputs_sha256':input_sha,'work':w,'binaries':binaries,'libraries':libraries,'config':data,'payload':payload,'sources':sources_code}

def stage(plan):
 w=plan['work'];w.mkdir(mode=0o700)
 for name in ('home','runtime','tools','libs','diagnostic'):(w/name).mkdir(mode=0o700)
 inside={}
 for name,(q,raw) in plan['binaries'].items():
  target=Path(SYSTEM[name]) if name in SYSTEM else Path('/work/tools')/name
  if name not in SYSTEM:(w/'tools'/name).write_bytes(raw);(w/'tools'/name).chmod(0o555)
  inside[name]={'path':str(target),'sha256':sha(raw)}
 for name,(q,raw) in plan['libraries'].items():(w/'libs'/name).write_bytes(raw);(w/'libs'/name).chmod(0o444)
 for name,raw in plan['payload'].items():
  dest=w/'done'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(0o444)
 (w/'mako.conf').write_bytes(plan['config']);(w/'sway.conf').write_text('output * resolution 1024x768 position 0 0\nseat seat0 fallback true\nfocus_follows_mouse no\ndefault_border none\n')
 for name,raw in plan['sources'].items():(w/'diagnostic'/name).write_bytes(raw);(w/'diagnostic'/name).chmod(0o444)
 label='X86' if plan['native_arch']['name']=='x86_64' else 'AARCH64'
 scope='NATIVE_'+label+'_SWAY_NOTIFICATION_COUNTERFACTUAL_ONLY_NOT_HYPRLAND_ALPM_'+('ARM_' if label=='X86' else '')+'M2'
 bindings={'native_arch':plan['native_arch'],'scope':scope,'inputs':plan['inputs'],'inputs_sha256':plan['inputs_sha256'],'source_metadata_qualification':'CALLER_DECLARED_NOT_INDEPENDENT_SOURCE_TO_BINARY_ATTESTATION','inside_tools':inside,'fish_aliases':['/usr/bin/fish','/usr/bin/fish_indent','/usr/bin/fish_key_reader'] if plan['binaries']['fish'][0].stat().st_nlink==3 else [],'libraries':{n:{'sha256':sha(x[1])} for n,x in plan['libraries'].items()},'diagnostic_sources':{q.name:sha(q.read_bytes()) for q in (w/'diagnostic').glob('*.py')}}
 (w/'bindings.json').write_bytes(encoded(bindings));return bindings

def argv(plan):
 a=[str(plan['binaries']['bwrap'][0]),'--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--ro-bind','/etc','/etc','--ro-bind','/sys','/sys','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64','--proc','/proc','--dev','/dev','--dev-bind',plan['inputs']['render_node'],plan['inputs']['render_node'],'--tmpfs','/tmp','--tmpfs','/run','--bind',str(plan['work']),'/work','--ro-bind',str(plan['work']/'diagnostic'),'/inputs','--chdir','/work']
 env={'PATH':'/usr/bin','HOME':'/work/home','XDG_RUNTIME_DIR':'/work/runtime','XDG_CONFIG_HOME':'/work/home/config','XDG_CACHE_HOME':'/work/home/cache','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','CACHY_NATIVE_UID':str(os.getuid()),'CACHY_RENDER_NODE':plan['inputs']['render_node']}
 for k,v in env.items():a+=['--setenv',k,v]
 return a+['--',str(plan['binaries']['python'][0]),'-I','-B','/inputs/controller.py']

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inputs',required=True);parser.add_argument('--inputs-sha256',required=True);parser.add_argument('--work-dir',required=True);parser.add_argument('--validate-only',action='store_true');args=parser.parse_args()
 plan=preflight(args.inputs,args.inputs_sha256,args.work_dir)
 if args.validate_only:print('VALIDATED_INPUTS_NO_ACTORS_NO_WORK_CREATED');return 0
 stage(plan);a=argv(plan);started=time.monotonic();process=None
 try:
  process=subprocess.Popen(a,env={'PATH':'/usr/bin'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:out,err=process.communicate(timeout=120)
  except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);out,err=process.communicate(timeout=5);raise ValueError('whole owned fixture120s timeout; no pass')
  need(len(out)+len(err)<=65536,'bounded wrapper output')
  (plan['work']/'launch.json').write_bytes(encoded({'argv':a,'pid':process.pid,'exit':process.returncode,'seconds':time.monotonic()-started,'stdout':out.decode('utf8','replace'),'stderr':err.decode('utf8','replace')}))
  result=decode((plan['work']/'result.json').read_bytes());need(process.returncode==0 and result['native_arch']==plan['native_arch'] and result['status']=='PASS_NATIVE_'+('X86' if plan['native_arch']['name']=='x86_64' else 'AARCH64')+'_GPU_DONE_FUNCTIONAL_PENDING_VISUAL_REVIEW','fixture failed; retain original output, never retry captures');print(result['status']);return 0
 except BaseException as error:
  (plan['work']/'outer-failure.json').write_bytes(encoded({'status':'FAIL_NOT_ACCEPTANCE','error_type':type(error).__name__,'error':str(error)[:512],'seconds':time.monotonic()-started,'child_exit':None if process is None else process.poll(),'cleanup_qualification':'bwrap namespace lifetime owns remaining actors; no fresh live absence attestation'}));raise

if __name__=='__main__':
 try:raise SystemExit(main())
 except (ValueError,OSError,tarfile.TarError,json.JSONDecodeError) as error:print('REFUSED: '+str(error),file=sys.stderr);raise SystemExit(1)
