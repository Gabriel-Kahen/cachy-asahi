# SPDX-License-Identifier: MIT
"""GNU-only source-pinned Apps proof derivative for /held -> /work/{two cases}."""
import hashlib,os,stat,sys,types
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/update'))
import aux_copy
import full_root as roots
PROOF='scripts/apps/full574_copy.py'
PROOF_SHA256='33d49316c28dee344e78e17d7e7ffa409c9d7ad09bb48a82651f7d44f1cb61a0'
ANCHORS=((b"SOURCE=Path('/seed');WORK=Path('/work')",b"SOURCE=Path('/held');WORK=Path('/work')"),
 (b"destination in (WORK/'main',WORK/'interrupted')",b"destination in (WORK/'pristine',WORK/'modified')"))
ADAPTED_COPIER_SHA256='289522a9be37ed907bbee1bf46a4967f3eda89460dcd44757254b15ac821d5af'
need=aux_copy.aux.need

def qualified():
 path=ROOT/PROOF
 with aux_copy.measure_copy._descriptors() as held:
  parent=roots._open_root(path.parent);held.append(parent)
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);held.append(fd);info=os.fstat(fd)
  need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=128*1024,'GNU copy proof source shape')
  raw=os.read(fd,info.st_size+1)
  need(len(raw)==info.st_size and roots._identity(info)==roots._identity(os.fstat(fd))==roots._identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) and hashlib.sha256(raw).hexdigest()==PROOF_SHA256,'GNU exact Apps copy proof source')
 need(all(raw.count(before)==1 for before,_ in ANCHORS),'GNU exact two copy proof anchors')
 changed=raw
 for before,after in ANCHORS:changed=changed.replace(before,after)
 module=types.ModuleType('_gnu574_scoped_copy');module.__file__=str(path);exec(compile(changed,str(path),'exec'),module.__dict__)
 original=module.copy_data
 def copy_data(*args,**kwargs):
  report=original(*args,**kwargs);proof=report.pop('apps_bind_scope')
  proof.update(apps_proof_sha256=PROOF_SHA256,gnu_proof_sha256=hashlib.sha256(changed).hexdigest(),lifetime_sha256=aux_copy.LIFETIME_SHA256)
  report['gnu_bind_scope']=proof;return report
 module.copy_data=copy_data;module.gnu_proof_sha256=hashlib.sha256(changed).hexdigest()
 return module

def copied_root(source,workspace,*,limits,cleanup_seconds=60,cleanup_extra_nodes=10000):
 module=aux_copy._isolated(aux_copy.disposable_copy.__file__,aux_copy.LIFETIME_SHA256)
 module.measure_copy=types.SimpleNamespace(copy_data=qualified().copy_data)
 return module.copied_root(source,workspace,limits=limits,cleanup_seconds=cleanup_seconds,cleanup_extra_nodes=cleanup_extra_nodes)

def receipt(value,case):
 need(case in ('pristine','modified') and type(value) is dict and set(value)=={'proof','checkpoints','apps_proof_sha256','gnu_proof_sha256','lifetime_sha256','original_copier_sha256','adapted_copier_sha256'},'GNU exact copy scope case/receipt')
 proof=value['proof'];module=qualified()
 need(proof['status']=='PROVED_DISJOINT_READONLY_SOURCE_AND_OWNED_WORK_BIND_ROOTS' and proof['source']=='/held' and proof['destination_parent']=='/work/'+case and
      type(value['checkpoints']) is int and value['checkpoints']==7 and value['apps_proof_sha256']==PROOF_SHA256 and value['gnu_proof_sha256']==module.gnu_proof_sha256 and value['lifetime_sha256']==aux_copy.LIFETIME_SHA256 and value['original_copier_sha256']==aux_copy.COPY_SHA256,'GNU complete pinned copy scope proof')
 need(value['adapted_copier_sha256']==ADAPTED_COPIER_SHA256,'GNU adapted copier receipt source')
 return value
