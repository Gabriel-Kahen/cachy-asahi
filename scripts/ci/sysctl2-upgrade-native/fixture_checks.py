#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Installed commands/private model only; fixed /proc/sys is never opened for writes."""
import hashlib,importlib.machinery,importlib.util,json,os,stat,subprocess,sys
from pathlib import Path
PACKAGE='cachy-asahi-sysctl';BASE=PACKAGE;NEW=PACKAGE+'2'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def command(argv):
 p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=25,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
 need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=128*1024,'installed private fixture failed: '+p.stderr.decode(errors='replace')[-512:]);return p

def snapshot(root):
 result={};spent=0
 for path in (root,*sorted(root.rglob('*'))):
  s=path.lstat();need(len(result)<64 and not path.is_symlink()and (stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)),'ordinary bounded fixture state')
  raw=path.read_bytes()if stat.S_ISREG(s.st_mode)else b'';spent+=len(raw);need(spent<=128*1024,'fixture state byte cap')
  result[path.relative_to(root).as_posix()]=dict(dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,links=s.st_nlink,mtime_ns=s.st_mtime_ns,bytes=len(raw),sha256=digest(raw))
 return result

def seed(program,work):
 need(not(work/'legacy').exists(),'one-time v1 records required');legacy=work/'legacy';legacy.mkdir(mode=0o700);tree=legacy/'tree';tree.mkdir(mode=0o700);(tree/'vm').mkdir(mode=0o700);leaf=tree/'vm/swappiness';leaf.write_bytes(b'60\n');leaf.chmod(0o600);random=tree/'kernel/random';random.mkdir(parents=True,mode=0o700);(random/'boot_id').write_bytes(b'12345678-1234-1234-1234-123456789abc\n');state=legacy/'state';state.mkdir(mode=0o700)
 loader=importlib.machinery.SourceFileLoader('exact_installed_sysctl_v1',str(program));spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);model=m.Tree(tree,model=True)
 m.plan(model,state,'planned',m.KEY,20);m.plan(model,state,'applied',m.KEY,30);need(m.operate(model,state,'applied','apply')['status']=='APPLIED'and leaf.read_bytes()==b'30\n','real installed v1 private apply required')
 expected=dict(nodes=snapshot(legacy),phases={'applied':'APPLIED','planned':'PLANNED'},scope='PRIVATE_MODEL_NOT_KERNEL')
 (work/'legacy-receipt.json').write_bytes(encoded(expected));return expected

def preserved(work):
 expected=json.loads((work/'legacy-receipt.json').read_bytes());need(snapshot(work/'legacy')==expected['nodes'],'v1 model/journal/baseline altered across ALPM transition');return expected

def discover(program,work):
 expected=preserved(work);p=command([program,'experiments','--state',work/'legacy/state']);v=json.loads(p.stdout)
 need(v['status']=='SAVED_EXPERIMENTS'and v['live_state']=='NOT_READ'and v['mutation']=='NONE'and {r['name']:r['phase']for r in v['experiments']}==expected['phases']and len(v['experiments'])==2 and all(r['status']=='SAVED'and r['baseline']==60 and r['key']=='vm.swappiness'and r['target']==(30 if r['name']=='applied'else 20)for r in v['experiments']),'exact original v1 planned/applied records must be discovered without live claims');preserved(work);return dict(status='PASS_V1_RECORDS_DISCOVERED_READONLY',records=2,phases=expected['phases'],stdout_bytes=len(p.stdout),stdout_sha256=digest(p.stdout),live_state='NOT_READ',kernel_mutation='NOT_RUN')

def main(role,work,phase):
 need(os.getuid()==os.geteuid()>0 and role in(BASE,NEW)and work.is_absolute()and work.is_dir()and not work.is_symlink()and work.stat().st_uid==os.getuid(),'ordinary user owned fixture required')
 policy=json.loads(Path('/runner/input-policy.json').read_bytes());row=policy['products'][role];program=Path('/usr/bin')/PACKAGE;s=program.lstat();raw=program.read_bytes();need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755 and dict(bytes=len(raw),sha256=digest(raw))==row['source_files'][PACKAGE],'exact installed program owner/mode/source required')
 command([program,'--help']);source=Path('/inputs/sources')/role
 suite=command(['/usr/bin/python3','-I','-B','-Werror::ResourceWarning',source/'test_sysctl.py','--command-source',program]);text=(suite.stdout+suite.stderr).decode(errors='replace');need(all(m in text for m in row['check_markers'])and 'skipped='not in text and 'OK (skipped='not in text,'installed private test count/no-skips required')
 if role==BASE:seed(program,work);discovery=None
 else:discovery=discover(program,work)
 receipt=dict(status='PASS_INSTALLED_SYSCTL_PRIVATE_UPGRADE_FIXTURES',role=role,version=row['version'],phase=phase,controls=19 if role==BASE else 28,source_sha256=digest(raw),suite=dict(exit_code=0,stdout_bytes=len(suite.stdout),stdout_sha256=digest(suite.stdout),stderr_bytes=len(suite.stderr),stderr_sha256=digest(suite.stderr)),legacy_preserved=True,discovery=discovery,kernel_mutation='NOT_RUN',hardware='NOT_RUN')
 p=work/(phase+'-receipt.json');need(not p.exists(),'fresh phase receipt');p.write_bytes(encoded(receipt));print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main(sys.argv[1],Path(sys.argv[2]),sys.argv[3])
