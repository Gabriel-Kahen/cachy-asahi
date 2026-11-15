#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare pinned reference-VM inputs only. Never launch a VM."""
import argparse,base64,hashlib,json,os,re,secrets,shutil,subprocess,tarfile,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE='docker.io/library/archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
LIMIT=3*1024**3
TARGETS=['qemu-system-x86=11.1.3-1','qemu-img=11.1.3-1','linux=7.2.14.arch1-1','mkinitcpio=42.2-1','fakeroot=1:2.1.4-1','python=3.14.9-1','e2fsprogs=1.47.4-1']


def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def catalogs(directory):
 spec=json.loads((HERE/'selected-inputs.json').read_text());rows={}
 for name,pin in spec['catalogs'].items():
  p=directory/name;assert p.is_file()and not p.is_symlink()and sha(p)==pin
  with tarfile.open(p)as t:
   for m in t:
    if m.name.endswith('/desc'):
     assert m.size<131072
     text=t.extractfile(m).read().decode();parts=text.split('\n\n');d={part.splitlines()[0].strip('%'):part.splitlines()[1:]for part in parts if part.startswith('%')}
     n=d['NAME'][0];assert n not in rows
     d['repository']=[Path(name).stem];rows[n]=d
 return spec,rows


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-prepare-x86-reference',action='store_true');p.add_argument('--catalogs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_prepare_x86_reference and __debug__ and os.geteuid()!=0):p.error('ordinary host user/explicit preparation opt-in required')
 security=json.loads(subprocess.check_output(['docker','info','--format','{{json .SecurityOptions}}'],text=True));assert 'name=rootless'in security,'rootless Docker required'
 spec,rows=catalogs(a.catalogs.resolve(strict=True));out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 baseline=shutil.disk_usage(out).free;assert baseline>LIMIT+512*1024**2,'insufficient bounded preparation reserve'
 token=secrets.token_hex(8);resolver='cachy-tcg-resolver:'+token;tools='cachy-tcg-tools:'+token;container='cachy-tcg-assemble-'+token
 report={'schema_version':1,'status':'HOLD','purpose':'x86_64 reference VM input preparation only','VM_boot':'NOT RUN','base':BASE,'targets':TARGETS,'source_pins':{f.name:sha(f)for f in HERE.glob('*.py')},'additional_disk_limit':LIMIT,'memory_limit':LIMIT}
 def cmd(label,argv,timeout=90):
  path=out/(label+'.log')
  with path.open('wb')as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
  assert r.returncode==0,(label,r.returncode)
  return path
 try:
  with tempfile.TemporaryDirectory(prefix='.tcg-ref-context-',dir=out)as tmp:
   context=Path(tmp);(context/'db').mkdir()
   for name in spec['catalogs']:shutil.copyfile(a.catalogs/name,context/'db'/name)
   resolveconf='[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseOptional TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n'
   for repo in ['core','extra']:resolveconf+='['+repo+']\nServer = https://archive.archlinux.org/repos/2026/11/09/$repo/os/$arch\n'
   (context/'resolve.conf').write_text(resolveconf)
   (context/'Dockerfile.resolve').write_text('FROM '+BASE+'\nCOPY db/ /var/lib/pacman/sync/\nCOPY resolve.conf /opt/resolve.conf\n')
   cmd('resolver-image',['docker','build','--network=none','--pull=false','-f',str(context/'Dockerfile.resolve'),'-t',resolver,str(context)],120)
   path=cmd('resolve-exact-transaction',['docker','run','--rm','--init','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=1','--memory=512m','--pids-limit=64','--entrypoint','/usr/bin/pacman',resolver,'--config','/opt/resolve.conf','-Sp','--noconfirm','--print-format','PKG|%n|%v|%l|%s',*TARGETS])
   selected=[]
   for line in path.read_text().splitlines():
    if line.startswith('PKG|'):
     _,name,version,url,size=line.split('|');row=rows[name]
     assert version==row['VERSION'][0]and url.endswith('/'+row['FILENAME'][0])and url.startswith('https://archive.archlinux.org/repos/2026/11/09/')
     assert int(size)==int(row['CSIZE'][0]);selected.append(row)
   assert len(selected)>=len(TARGETS)and len({r['NAME'][0]for r in selected})==len(selected)
   assert sum(int(r['CSIZE'][0])for r in selected)<=512*1024**2
   assert sum(int(r['ISIZE'][0])for r in selected)<=1024**3
   cache=out/'packages';cache.mkdir(mode=0o700);(context/'packages').mkdir()
   package_refs=[];fetch_deadline=time.monotonic()+360
   for row in selected:
    name=row['FILENAME'][0];assert re.fullmatch(r'[A-Za-z0-9@._+:-]+\.pkg\.tar\.zst',name)
    url='https://archive.archlinux.org/repos/2026/11/09/'+row['repository'][0]+'/os/x86_64/'+name
    dst=cache/name
    assert time.monotonic()<fetch_deadline,'whole acquisition deadline'
    cmd('fetch-'+row['NAME'][0],['curl','--fail','--location','--silent','--show-error','--proto','=https','--max-time',str(min(180,max(1,int(fetch_deadline-time.monotonic())))),'--max-filesize',str(int(row['CSIZE'][0])),'--output',str(dst),url],190)
    assert dst.stat().st_size==int(row['CSIZE'][0])and sha(dst)==row['SHA256SUM'][0]
    signature=base64.b64decode(row['PGPSIG'][0],validate=True);assert 32<len(signature)<16384
    sig=Path(str(dst)+'.sig');sig.write_bytes(signature)
    for f in [dst,sig]:os.link(f,context/'packages'/f.name)
    package_refs.append({'name':row['NAME'][0],'version':row['VERSION'][0],'filename':name,'bytes':dst.stat().st_size,'sha256':sha(dst),'signature_sha256':sha(sig),'signature_origin':'exact frozen official repository PGPSIG','url':url,'upstream_url':row.get('URL',[]),'license':row.get('LICENSE',[])})
   report['packages']=package_refs
   for source in [HERE/'assemble.py',HERE/'record_inputs.py',HERE/'vm_actor.py',HERE/'guest-proof.sh']:
    shutil.copyfile(source,context/source.name)
   shutil.copyfile(HERE.parents[2]/'scripts/virtual/owned_process.py',context/'owned_process.py')
   (context/'package-refs.json').write_text(json.dumps(package_refs,indent=2)+'\n')
   (context/'install.conf').write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
   shutil.copyfile(HERE/'Dockerfile',context/'Dockerfile')
   cmd('tool-image',['docker','build','--network=none','--pull=false','-t',tools,str(context)],300)
  image=json.loads(subprocess.check_output(['docker','image','inspect',tools],text=True))[0];report['tool_image']=tools;report['tool_image_id']=image['Id'];report['tool_image_bytes']=image['Size']
  # Explicit preparation metadata query only; no kernel/guest VM is launched.
  cmd('qemu-version-only',['docker','run','--rm','--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--entrypoint','/usr/bin/qemu-system-x86_64',tools,'--version'])
  assembly=out/'assembly';assembly.mkdir(mode=0o700)
  cmd('assemble',['docker','run','--name',container,'--init','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=2','--memory=3g','--pids-limit=256','--tmpfs','/tmp:rw,nodev,nosuid,size=1g','--mount','type=bind,source='+str(assembly)+',target=/work','--entrypoint','/usr/bin/fakeroot',tools,'--','/usr/bin/python3','-I','/opt/assemble.py'],240)
  prepared=json.loads((assembly/'prepared.json').read_text());report['prepared']=prepared
  allocated=sum(p.stat().st_blocks*512 for p in out.rglob('*')if p.is_file())
  report['allocated_output_bytes']=allocated;report['free_delta_bytes']=baseline-shutil.disk_usage(out).free
  assert report['free_delta_bytes']<=LIMIT,'additional actual filesystem use exceeds3GiB; no boot allowed'
  report['status']='PREPARED_NOT_BOOTED'
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  subprocess.run(['docker','rm','--force',container],capture_output=True,timeout=30)
  subprocess.run(['docker','image','rm',resolver],capture_output=True,timeout=30)
  (out/'preparation.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'failure':report.get('failure'),'report':str(out/'preparation.json'),'VM_boot':'NOT RUN'}))
 return 0 if report['status']=='PREPARED_NOT_BOOTED'else 1


if __name__=='__main__':raise SystemExit(main())
