#!/usr/bin/env -S python3 -I -B
"""Bind only explicit Root-selected recovery operands; default performs no action."""
import argparse,hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
B=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(p):
 with Path(p).open('rb')as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
 return dict(bytes=Path(p).stat().st_size,sha256=digest)
def read(p):return json.loads(Path(p).read_bytes())
def put(p,v):
 with Path(p).open('x')as f:os.fchmod(f.fileno(),0o600);json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def parameters(path,sha):
 need(pin(path)['sha256']==sha,'whole external Root parameter pin');v=read(path)
 need(set(v)==set(read(HERE/'Root-parameters.TEMPLATE.json'))and v['issued_by']=='Root'and v['accepted']is True and all(x is not None for x in v.values()),'complete explicit Root selections; no default grant')
 need(re.fullmatch('[0-9a-f]{32}',v['nonce'])and re.fullmatch('[0-9a-f]{40}',v['Main']),'Root selected nonce/Main')
 seal=HERE/'packet-seal.DATA.json';need(pin(seal)['sha256']==v['packet_seal_sha256'],'whole preparation seal')
 closure=read(seal);need(not any(p.is_symlink()for p in HERE.rglob('*')),'unaliasable complete preparation');found={p.relative_to(HERE).as_posix()for p in HERE.rglob('*')if p.is_file()and p.relative_to(HERE).as_posix()!='packet-seal.DATA.json'}
 need(found==set(closure['files']),'complete sealed preparation membership')
 for name,row in closure['files'].items():
  p=HERE/name;need(not p.is_symlink()and dict(**pin(p),mode=stat.S_IMODE(p.lstat().st_mode))==row,'whole preparation bytes/modes')
 R=module('Root_fixed_ldcache_outer',HERE/'capsule/run_metadata.py');f=R.fixed();R.check_prior_packet(f)
 for name in('runtime_profile','request'):R.check_ref(v[name])
 Q=module('Root_pure_recovery_request',HERE/'operation/recovery.py');request=read(v['request']['path']);Q.require_issued(request)
 need(v['resources']==f['resources']and type(v['resource_review'])is str and v['resource_review']and type(v['serialization_review'])is str and v['serialization_review'],'Root exact new policy/serialization review')
 need(type(v['transport'])is dict and set(v['transport'])=={'docker_cli','docker_endpoint'}and v['transport']['docker_endpoint']=='unix:///run/user/1000/docker.sock','Root selected exact ordinary rootless transport')
 need(set(v['transport']['docker_cli'])=={'path','bytes','sha256','device','inode','uid','gid','mode','nlink'},'whole Root-qualified CLI identity')
 f=dict(f,input_raw=dict(path=request['backing']['path'],**request['backing']['pin']),input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),docker_cli=v['transport']['docker_cli'],docker_endpoint=v['transport']['docker_endpoint'])
 T=R.ordinary(v['trial_directory']);need(T.is_relative_to(B)and T!=B and T.parent.is_dir()and T.parent.stat().st_uid==1000 and not T.parent.stat().st_mode&0o022,'Root selected private trial parent')
 need(request['output']==str(T/'actor-output/decoder-output'),'same Root request/output mount')
 need(request['overlay']['path']==R.fixed()['input_prepared']['path']and request['backing']['path']==R.fixed()['input_raw']['path'],'exact r86 public recovery input paths')
 runtime=R.ordinary(v['runtime_profile']['path']);need(re.fullmatch(r'Root-runtime54-profile.ACTUAL-r[0-9]+\.json',runtime.name),'explicit already Root-issued runtime; never select/attest one here')
 return v,R,f,T,runtime

def entry_argv(c,authority,authority_sha):
 return ['/usr/bin/systemd-run','--user','--scope','--collect','--quiet','--unit='+c['controller_scope']['unit'],'-p','MemoryMax=536870912','-p','MemorySwapMax=0','-p','CPUQuota=100%','-p','TasksMax=64','/usr/bin/python3','-I','-B',str(HERE/'capsule/run_metadata.py'),'--execute-root-issued-outer','--authority',str(authority),'--authority-sha256',authority_sha]

def issue(path,sha):
 v,R,f,T,runtime=parameters(path,sha);need(not T.exists(),'fresh explicit Root trial')
 c=read(HERE/'capsule/outer-input.UNISSUED.json')
 c.update(issued_by='Root',accepted=True,allow_outer=True,nonce=v['nonce'],Main=v['Main'],issued_at=v['issued_at'],expires_at=v['expires_at'],outer_capsule=dict(path=str(HERE/'capsule/seal.json'),**pin(HERE/'capsule/seal.json')),qualification_authority=v['request'],runtime_profile=v['runtime_profile'],transport=v['transport'],outer_output=str(T/'actor-output'),controller_scope=v['controller_scope'])
 R.require_issued(c,f)
 T.mkdir(mode=0o700);issued=T/'issued';issued.mkdir(mode=0o700)
 authority=issued/'Root-outer-authority.ACTUAL.json';put(authority,c);ref=dict(path=str(authority),**pin(authority))
 command=dict(argv=entry_argv(c,authority,ref['sha256']),authority=ref,entry='UNENTERED',runtime=runtime.stem.split('-')[-1],once=True,retry=False,external_seconds=485,cleanup_seconds=90)
 put(issued/'Root-entry-command.ACTUAL.json',command);put(issued/'Root-review.ACTUAL.json',dict(issuer='Root',parameters=dict(path=str(path),**pin(path)),resource_review=v['resource_review'],serialization_review=v['serialization_review'],runtime_profile=v['runtime_profile'],request=v['request'],Root_acceptance=None,VM=None,lifecycle=None))
 return command
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parameters',type=Path,required=True);p.add_argument('--parameters-sha256',required=True);a=p.parse_args();need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid()==os.geteuid()==1000,'ordinary isolated explicit Root invocation');print(json.dumps(issue(a.parameters,a.parameters_sha256),sort_keys=True))
