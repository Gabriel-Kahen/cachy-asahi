# SPDX-License-Identifier: MIT
"""One ordinary bounded journey, safe complete evidence, later private-home custody."""
import hashlib,io,json,os,stat,time,zipfile
from pathlib import Path
import receipt as R

def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def key(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def registry(root):
 root=Path(root);R.need(not any(p.is_symlink()for p in(root,*root.parents)),'no private workspace aliases');out={};spent=0
 for path in(root,*sorted(root.rglob('*'))):
  a=path.lstat();R.need(not path.is_symlink()and(stat.S_ISDIR(a.st_mode)or stat.S_ISREG(a.st_mode))and len(out)<R.BOUNDS['max_nodes'],'closed finite ordinary workspace nodes');raw=None
  if stat.S_ISREG(a.st_mode):
   R.need(a.st_nlink==1 and a.st_size<=R.BOUNDS['max_file'],'bounded singlelink workspace file');raw=path.read_bytes();spent+=len(raw);R.need(spent<=R.BOUNDS['max_bytes']and len(raw)==a.st_size,'finite complete workspace bytes')
  attrs={n:os.getxattr(path,n,follow_symlinks=False).hex()for n in os.listxattr(path,follow_symlinks=False)};R.need('security.capability'not in attrs and key(path.lstat())==key(a),'stable private workspace identity/capabilities');out[path.relative_to(root).as_posix()]=dict(identity=key(a),file=None if raw is None else pin(raw),xattrs=attrs)
 return out

def archive(root,records):
 R.need(registry(root)==records,'whole workspace closure before export');stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED)as z:
  for name,row in records.items():
   if row['file']is None:continue
   R.need(name and all(32<=ord(c)<127 and c not in ':\\<>|?*"'for c in name)and not set(name.split('/'))&{'','..','.'},'safe closed evidence member');raw=(root/name).read_bytes();R.need(pin(raw)==row['file'],'whole evidence file identity');info=zipfile.ZipInfo(name,(2026,10,22,0,0,0));info.external_attr=(stat.S_IFREG|stat.S_IMODE(row['identity'][2]))<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,raw)
  info=zipfile.ZipInfo('workspace-custody.json',(2026,10,22,0,0,0));info.external_attr=(stat.S_IFREG|0o600)<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,enc(records))
 raw=stream.getvalue();R.need(0<len(raw)<=R.BOUNDS['max_bytes']and registry(root)==records,'closed bounded evidence and post-export registry');return raw

def run(g,context,supervised,account,nonce,deadline,absent):
 C=g['C'];work=Path('/tmp/onboarding-full606');R.need(not work.exists(),'fresh normal native user journey');work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid);started=time.monotonic();absent(account.pw_uid);result=None
 try:
  result=supervised.run(['/usr/bin/python3','-I','-B','/runner/developer/ordinary_entry.py',str(context['home']),str(work),nonce],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(R.BOUNDS['fixture'],max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1,signal_uid=account.pw_uid)
 finally:
  if result is not None:
   (g['OUT']/'onboarding-process.stdout').write_bytes(result['stdout']);(g['OUT']/'onboarding-process.stderr').write_bytes(result['stderr']);(g['OUT']/'onboarding-process.json').write_bytes(enc({k:v for k,v in result.items()if k not in('stdout','stderr')}))
  absent(account.pw_uid);records=registry(work);raw=archive(work,records);(g['OUT']/'onboarding-evidence.zip').write_bytes(raw)
 R.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']is result['group_retired']is True,'real journey foreground actor/group retired');value=json.loads(result['stdout']);R.need(json.loads((work/'evidence/ordinary-result.json').read_bytes())==value and value['nonce']==nonce,'ordinary stdout/file/nonce join')
 value.update(status='PASS_FULL606_APPS7_SETUP6_SOFTWARE_ONBOARDING_REQUIRES_REPLAY',phase='install-setup6',package_count=606,versions={'cachy-asahi-apps':'0.1.0-7','cachy-asahi-setup':'0.1.0-6','cachy-asahi-repository-runtime':'0.1.0-1'},clock=dict(started=started,seconds=time.monotonic()-started),direct_child_reaped=True,group_retired=True,ordinary_uid_absent=True,evidence=pin(raw),evidence_path='container/onboarding-evidence.zip',native_acceptance='REQUIRES_FULL_REPLAY_AND_ROOT_DECISION',graphical_terminal='NOT_RUN',GUI='NOT_RUN',audio='NOT_RUN',hardware='NOT_RUN',independent_new_user_install='NOT_RUN',performance='NOT_CLAIMED',release='NOT_ADMITTED');R.validate(value,nonce);R.replay(raw,value,(Path(__file__).resolve().parent/'held/hello.c').read_bytes());(g['OUT']/'onboarding-result.json').write_bytes(enc(value));return value,work,records
