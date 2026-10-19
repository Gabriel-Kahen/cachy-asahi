#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned606 source/copy slice; no Docker, live '/', acceptance or actor creation."""
import argparse,contextlib,hashlib,json,os,re,stat,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path[:0]=[str(HERE),str(ROOT/'held-copy/scripts/update'),str(ROOT/'held-copy/scripts/apps')]
import contract as C
with C.phase('startup'):
 import guard as G
 import full_root as roots
 import aux_copy,aux_checkpoint,root_link_selection
 import full574_copy as scope
 import file_capabilities as caps

def limits(seconds=C.WORKER_SECONDS):return roots.Limits(deadline=time.monotonic()+seconds,**C.BOUNDS)
def observe(path,budget):
 value=roots.observe(path,limits=budget,hardlinks='generic-development-internal',absolute_paths=True)
 root_link_selection.check(value,budget);aux_checkpoint.checkpoint(path,value,budget)
 return value

def process_status():
 raw=Path('/proc/self/status').read_bytes()
 C.need(len(raw)<=65536,'bounded process status')
 fields={line.split(':',1)[0]:line.split(':',1)[1].strip()for line in raw.decode().splitlines()if ':'in line}
 result={k:int(fields[k],16)for k in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')}
 result.update(NoNewPrivs=int(fields['NoNewPrivs']),uid=os.geteuid(),gid=os.getegid())
 return result

def handoff(value,nonce,context):
 C.need(type(value)is dict and value.get('schema_version')==1 and value.get('purpose')==C.PURPOSE,'bridge handoff schema/purpose')
 C.need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)and value.get('nonce')==nonce,'exact owner nonce')
 C.need(value.get('source_native')==context['source_native'] and value.get('source_run')==context['source_run'] and value.get('expected606_sha256')==C.LOCK,'known606 source/run/lock')
 C.need(value.get('source_root')==str(C.SOURCE_ROOT)and value.get('work_root')==str(C.WORK_ROOT),'fixed source/work roots')
 return G.fixed_maprefs(value.get('maps'))

def maps(value,budget,context):
 refs=handoff(value,value['nonce'],context);proof=C.PROOF_ROOT
 fd=roots._open_root(proof)
 try:
  C.need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'proof mount must actually be readonly')
  mount=roots._mount_id(fd,budget);raw=scope._mountinfo(budget);lines=raw.splitlines()
  C.need(len(lines)<=32768,'proof mount inventory bound')
  rows=[x.split()for x in lines if len(x.split())>5 and x.split()[4]==bytes(proof)]
  C.need(len(rows)==1 and int(rows[0][0])==mount and b'ro'in rows[0][5].split(b',')and b'rw'not in rows[0][5].split(b','),'exact readonly proof mount')
  C.need(not any(len(x.split())>4 and x.split()[4].startswith(bytes(proof)+b'/')for x in lines),'proof shadow mount refused')
  result={}
  for name,row in refs.items():
   budget.tick();raw=C.ordinary(Path(row['path']));C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')},'private map pin differs');result[name]=C.decode(raw)
  C.need(roots._mount_id(fd,budget)==mount,'proof mount drift')
  bridge=result['bridge_proof'];C.need(bridge.get('nonce')==value['nonce']and bridge.get('source_native')==context['source_native']and bridge.get('source_run')==context['source_run'],'bridge private proof owner/source/run differs')
  return result
 finally:os.close(fd)

def mount_guard(proof,budget):
 """No workspace mkdir or chown occurs before this actual mount/lease proof."""
 raw=scope._mountinfo(budget);lines=raw.splitlines();C.need(len(lines)<=32768,'worker mount table bound')
 paths={'/runner':True,'/seed':True,'/bridge-proof':True,'/work':False,'/out':False};fds={}
 try:
  for name,readonly in paths.items():
   fd=roots._open_root(Path(name));fds[name]=fd;mount=roots._mount_id(fd,budget)
   C.need(bool(os.fstatvfs(fd).f_flag&os.ST_RDONLY)==readonly,'actual worker bind access differs')
   rows=[r.split()for r in lines if len(r.split())>5 and r.split()[4]==name.encode()]
   C.need(len(rows)==1 and int(rows[0][0])==mount,'one exact unshadowed worker bind')
   C.need(not any(len(r.split())>4 and r.split()[4].startswith(name.encode()+b'/')for r in lines),'worker nested bind refused')
  source,work=(os.fstat(fds[n])for n in('/seed','/work'))
  C.need(source.st_dev==work.st_dev and source.st_uid==work.st_uid==os.geteuid()and stat.S_IMODE(work.st_mode)==0o700,'owned private disk-backed work lease')
  C.need(proof.get('work_root')=='/work'and proof.get('work_staging_root')=='/measurement/work'and list(roots._identity(work))==proof.get('work_identity'),'exact finalized work backing identity')
  scope._rows(raw,roots._mount_id(fds['/seed'],budget),roots._mount_id(fds['/work'],budget),(os.major(source.st_dev),os.minor(source.st_dev)))
 finally:
  for fd in fds.values():os.close(fd)
 return True

def copy_context(*,source=C.SOURCE_ROOT,workspace=C.WORK_ROOT/'main',budget):
 """Exact lifetime, with its copier bound to the existing exact /seed/work guard."""
 lifetime=aux_copy._isolated(aux_copy.disposable_copy.__file__,aux_copy.LIFETIME_SHA256)
 lifetime.measure_copy=types.SimpleNamespace(copy_data=scope.copy_data)
 return lifetime.copied_root(source,workspace,limits=budget,cleanup_seconds=C.CLEANUP_SECONDS,cleanup_extra_nodes=10000)

def copy_verified(data,budget,*,copier=copy_context):
 """Caller must pass only maps already authenticated by maps()/closed owner."""
 with C.phase('source-observe'):
  before=observe(C.SOURCE_ROOT,budget);G.same_source(data['ordinary_observation'],before)
 expected=G.package_inventory(data['packages']);G.inventory(expected,expected)
 import importlib.util
 spec=importlib.util.spec_from_file_location('_copy606_raw_database',ROOT/'held-copy/scripts/ci/full-root-upgrade/root_upgrade.py');driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
 with C.phase('source-database'):
  C.need(driver.database(C.SOURCE_ROOT,max_packages=606,max_files=budget.max_package_files,max_nodes=budget.max_nodes,observed=before['nodes'])==data['packages'],'independent complete raw DB/ownership/dependency rows differ')
 C.need(hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(expected.items())).encode()).hexdigest()==C.LOCK,'exact606 complete package lock')
 with C.phase('source-capabilities'):
  actual_caps=caps.observe(C.SOURCE_ROOT,before['nodes'],budget);C.need(actual_caps==data['capabilities'],'source complete capability map')
 proof=data['bridge_proof'];C.need(proof.get('status')=='READY_FOR_READONLY_BIND_NOT_WORKER_AUTHORITY','bridge source proof grants no worker authority')
 held=roots._open_root(C.SOURCE_ROOT)
 try:
  C.need(list(roots._identity(os.fstat(held)))==proof.get('source_identity'),'bridge/seed backing identity differs')
  C.need(os.fstatvfs(held).f_flag&os.ST_RDONLY,'source must actually be readonly')
  source_id=roots._identity(os.fstat(held))
  copy_budget=roots.Limits(deadline=min(budget.deadline,time.monotonic()+C.COPY_SECONDS),**C.BOUNDS)
  with C.phase('copy-context'):
   with copier(budget=copy_budget)as(target,report):
    with C.phase('copy-observe'):
     copied=observe(target,budget)
     C.need(copied['nodes']==before['nodes'],'complete copied graph differs')
    with C.phase('copy-hardlinks-root'):
     roots.check_hardlink_preservation(root_link_selection.view(before,budget),root_link_selection.view(copied,budget),protected_paths=(),limits=budget)
     targetfd=roots._open_root(target)
     try:
      original=os.fstat(held);os.fchown(targetfd,original.st_uid,original.st_gid);os.fchmod(targetfd,stat.S_IMODE(original.st_mode))
      C.need((os.fstat(targetfd).st_uid,os.fstat(targetfd).st_gid,stat.S_IMODE(os.fstat(targetfd).st_mode))==(original.st_uid,original.st_gid,stat.S_IMODE(original.st_mode)),'new target root metadata restoration')
     finally:os.close(targetfd)
    report['root_initialization']='EXACT_SOURCE_ROOT_MODE_UID_GID_NEW_INODE'
    with C.phase('copy-capabilities'):
     caps.restore(target,copied['nodes'],actual_caps,budget)
     C.need(caps.observe(target,copied['nodes'],budget)==actual_caps,'copied capability restoration differs')
    try:
     with C.phase('lifecycle'):yield target,report,before,actual_caps
    finally:C.phase_marker('BEGIN','copy-retire')
  C.phase_marker('END','copy-retire')
  with C.phase('source-proof'):G.same_source(before,observe(C.SOURCE_ROOT,budget))
  with C.phase('source-proof-capabilities'):
   C.need(caps.observe(C.SOURCE_ROOT,before['nodes'],budget)==actual_caps and roots._identity(os.fstat(held))==source_id,'source capability/root identity changed')
 finally:os.close(held)
copy_verified=contextlib.contextmanager(copy_verified)

def main():
 p=argparse.ArgumentParser();p.add_argument('--selection',type=Path,required=True);p.add_argument('--handoff',type=Path,required=True);p.add_argument('--nonce',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 # All absent inputs refuse before process inspection, map reads or any copy.
 with C.phase('authority'):
  context=C.authority(C.decode(C.ordinary(a.selection,4*1024**2)),'copy-worker8',a.nonce)
  C.actor_guard(a.nonce);value=C.decode(C.ordinary(a.handoff,1024**2));handoff(value,a.nonce,context)
 budget=limits()
 with C.phase('sealed-maps'):data=maps(value,budget,context)
 with C.phase('mount-proof'):mount_guard(data['bridge_proof'],budget)
 import driver
 with C.phase('plan-load'):
  plan=C.decode(C.ordinary(Path('/runner/inputs/lifecycle-plan.json'),4*1024**2))
 with copy_verified(data,budget)as(target,report,before,capmap):
  result=driver.run(target,data=data,plan=plan,budget=budget,worker=sys.modules[__name__])
  result.update(purpose=C.PURPOSE,nonce=a.nonce,source_native=context['source_native'],source_run=context['source_run'],expected606_sha256=C.LOCK,copy=report,capability_count=len(capmap),whole_worker_seconds=C.WORKER_SECONDS,copy_seconds=C.COPY_SECONDS,cleanup_seconds=C.CLEANUP_SECONDS)
 with C.phase('result-publish'):
  C.need(report['cleanup']=='PASS-owned-workspace-removed','copy cleanup must complete')
  # The closed owner supplies an independently owned output bind, never /seed.
  C.need(a.output.parent==Path('/out')and not a.output.exists()and not a.output.is_symlink(),'new fixed owned output')
  fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
  with os.fdopen(fd,'wb')as stream:stream.write(C.encoded(result))
if __name__=='__main__':main()
