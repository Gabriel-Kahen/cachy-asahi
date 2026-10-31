# SPDX-License-Identifier: MIT
"""Source-owned readonly BuildKit proof; never a Docker-runtime marker surrogate."""
import hashlib,json,os,re,stat,sys
from pathlib import Path
SECRET=Path('/run/secrets/caa-gui-build')
ROLES={'runtime606':('/tmp/managed604','install606.py','bundle/expected-installed.lock',606),'controller590':('/tmp/tooling606','install_tooling.py','expected590.lock',590)}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap):
 need(not any(q.is_symlink()for q in(path,*path.parents)),'ordinary build proof input');a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'singlelink bounded build proof input');raw=path.read_bytes()
 key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(len(raw)==a.st_size and key(a)==key(path.lstat()),'build proof input drift');return raw
def readonly_secret(mounts):
 rows=[]
 for line in mounts.splitlines():
  fields=line.split();split=fields.index('-')if'-'in fields else -1
  if split>=6 and fields[4]==str(SECRET):rows.append(fields)
 return len(rows)==1 and 'ro'in rows[0][5].split(',')and rows[0][rows[0].index('-')+1]=='tmpfs'
def check(expected,role):
 need(re.fullmatch('[a-f0-9]{64}',expected or'')and role in ROLES,'exact caller proof digest and fixed build role')
 mounts=Path('/proc/self/mountinfo').read_text();interfaces=sorted(p.name for p in Path('/sys/class/net').iterdir())
 facts=dict(euid=os.geteuid(),architecture=os.uname().machine,live_systemd=Path('/run/systemd/system').exists(),network_interfaces=interfaces,readonly_secret_mount=readonly_secret(mounts))
 print('CAA_GUI_BUILD_BOUNDARY '+json.dumps(facts,sort_keys=True),flush=True)
 need(facts['euid']==0 and facts['architecture']=='aarch64'and facts['live_systemd']is False and interfaces==['lo']and facts['readonly_secret_mount'],'owned native offline BuildKit secret-mount boundary required')
 s=SECRET.lstat();need(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o400,'root-only readonly BuildKit proof mode')
 raw=read(SECRET,2*1024**2);need(pin(raw)['sha256']==expected,'exact caller source-owned proof bytes');proof=json.loads(raw)
 need(set(proof)=={'schema','purpose','role','nonce','base_image','files','lock'}and proof['schema']==1 and proof['purpose']=='SOURCE_OWNED_OFFLINE_GUI_IMAGE_BUILD'and proof['role']==role and re.fullmatch('[a-f0-9]{32}',proof['nonce'])and re.fullmatch('sha256:[a-f0-9]{64}',proof['base_image']),'closed source-owned build proof')
 directory,installer,lock,count=ROLES[role];root=Path(directory);names=set()
 for p in root.rglob('*'):
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary whole build context')
  if p.is_file():
   n=p.relative_to(root).as_posix();names.add(n);need(n in proof['files']and pin(read(p,256*1024**2))==proof['files'][n],'whole source-owned build context '+n)
 need(names==set(proof['files'])and {'Dockerfile','build_scope.py',installer,lock}<=names,'closed whole source-owned build context')
 need(proof['lock']==dict(path=lock,packages=count,**pin(read(root/lock,65536)))and len((root/lock).read_bytes().splitlines())==count,'exact complete build inventory lock')
 value=dict(status='PASS_SOURCE_OWNED_NATIVE_OFFLINE_BUILDKIT_BOUNDARY',role=role,nonce=proof['nonce'],base_image=proof['base_image'],proof=pin(raw),context_files=len(names),lock=proof['lock'])
 print('CAA_GUI_BUILD_SCOPE '+json.dumps(value,sort_keys=True),flush=True);return value

def dockerfile(base_reference,role):
    need(role in ROLES and re.fullmatch('cachy-asahi-desktop574-base:[a-f0-9]{32}',base_reference),'fixed owned build template')
    directory,installer,_,_=ROLES[role]
    return 'FROM '+base_reference+'\nARG CAA_GUI_BUILD_PROOF_SHA\nCOPY . '+directory+'/\nRUN --mount=type=secret,id=caa-gui-build,required=true,mode=0400 python3 -I -B '+directory+'/'+installer+' "$CAA_GUI_BUILD_PROOF_SHA" && rm -rf '+directory+'\n'

def prepare(context,role,base_image,base_reference,output):
    """Called only by the already-authorized source controller, before docker build."""
    need(role in ROLES and re.fullmatch('sha256:[a-f0-9]{64}',base_image)and re.fullmatch('cachy-asahi-desktop574-base:[a-f0-9]{32}',base_reference),'exact selected base image and owned alias')
    need(context.is_dir()and not any(p.is_symlink()for p in(context,*context.parents))and not output.exists()and output.parent.is_dir()and all(c not in str(output)for c in(',','\n','\r')),'fresh contained source proof')
    directory,installer,lock,count=ROLES[role]
    recipe=dockerfile(base_reference,role)
    need(not(context/'Dockerfile').exists(),'fresh source-owned Dockerfile');(context/'Dockerfile').write_text(recipe)
    files={}
    for p in sorted(context.rglob('*')):
        need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary source-owned build context')
        if p.is_file():files[p.relative_to(context).as_posix()]=pin(read(p,256*1024**2))
    need({'Dockerfile','build_scope.py',installer,lock}<=set(files),'complete fixed build source roles')
    raw_lock=read(context/lock,65536);need(len(raw_lock.splitlines())==count,'complete fixed build inventory')
    proof=dict(schema=1,purpose='SOURCE_OWNED_OFFLINE_GUI_IMAGE_BUILD',role=role,nonce=os.urandom(16).hex(),base_image=base_image,files=files,lock=dict(path=lock,packages=count,**pin(raw_lock)))
    raw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode()
    with output.open('xb')as out:out.write(raw)
    output.chmod(0o600)
    return ['--secret','id=caa-gui-build,src='+str(output),'--build-arg','CAA_GUI_BUILD_PROOF_SHA='+pin(raw)['sha256']],dict(role=role,proof=pin(raw),nonce=proof['nonce'],base_image=base_image,context_files=len(files),lock=proof['lock'])
