#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact75 default/known-published source factory. No actor, Git or network."""
import argparse,hashlib,json,re,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/gnu-verity-mapping-smoke'
WF='.github/workflows/native-arm-gnu-verity-mapping-smoke.yml'
GENERIC='.github/workflows/native-arm-build.yml'

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p):
 p=Path(p);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=4*1024**2,'bounded ordinary source');raw=p.read_bytes();z=p.lstat();need(len(raw)==s.st_size and(s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_mtime_ns,z.st_ctime_ns),'source lifetime drift');return raw

def emit(own,output,selected=False):
 own=own.absolute();output=output.absolute();need(type(selected)is bool and output.parent.is_dir()and not output.exists()and not any(q.is_symlink()for q in(output,*output.parents)),'fresh ordinary output; finite explicit selection')
 a=json.loads(read(HERE/'default-role.json'));b=json.loads(read(HERE/'selected-role.json'));selection=json.loads(read(HERE/'selection.json'));need(a['purpose']==b['purpose']==selection['purpose']=='GNU_VERITY_STANDALONE_MAPPING_INTEGRITY_SMOKE_V1'and a['scope']==b['scope']==selection['scope']=='STANDALONE_DM_VERITY_MAPPING_AND_INTEGRITY_SMOKE_ONLY'and len(a['files'])==len(b['files'])==75 and set(a['files'])==set(b['files']),'whole exact75 roles/purpose')
 need(selection['published_source']=='5eb899f1d42526820f0f9556439a0fa918e31a14'and selection['published_ref']=='codex/gnu-verity-mapping-smoke-v1'and all(selection[k]is None for k in('actual_source','actual_ref','actual_run')),'known genuine source is not mapping actual authority')
 raw={}
 for n,v in a['files'].items():
  need(type(n)is str and re.fullmatch('[A-Za-z0-9_./-]+',n)and all(q not in('','.','..')for q in n.split('/'))and(n==GENERIC or n==WF or n.startswith(LANE+'/')),'finite own namespace only');body=read(own/(WF if n==GENERIC else n));need(pin(body)==v,'whole NULL-default body: '+n);raw[n]=body
 need(all(json.loads(raw[LANE+'/'+n])is None for n in('kernel-descriptor.json','Root-build-decision.json','kernel-build-result.json')),'default authority NULL');policy=json.loads(raw[LANE+'/input-policy.json']);need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run')),'all default mapping actual selectors NULL')
 diff=sorted(n for n in raw if a['files'][n]!=b['files'][n]);need(diff==selection['changed_leaves']and len(diff)==6 and set(diff)=={GENERIC,WF,LANE+'/source-manifest.json',LANE+'/kernel-descriptor.json',LANE+'/Root-build-decision.json',LANE+'/kernel-build-result.json'},'exact six-leaf source selection inverse')
 overlay=HERE/'selected-overlay';need({q.relative_to(overlay).as_posix()for q in overlay.rglob('*')if q.is_file()}==set(diff),'closed six-leaf selected overlay')
 for n in diff:
  body=read(overlay/n);need(pin(body)==b['files'][n],'whole known genuine selected overlay: '+n)
  if selected:raw[n]=body
 target=b if selected else a;need({n:pin(body)for n,body in raw.items()}==target['files']and raw[WF]==raw[GENERIC],'whole source factory equality; same registered workflow')
 # Entire source and selection authenticated before creating any output.
 output.mkdir(mode=0o700)
 for n,body in raw.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body)
 return dict(status='EMITTED_EXACT75_SOURCE_ONLY_NO_MAPPING_ACTUAL_AUTHORITY',files=75,published_source=selection['published_source']if selected else None,published_ref=selection['published_ref']if selected else None,kernel_input='ROOT_ACCEPTED_BUILD_ONLY'if selected else'NULL_REFUSE_BEFORE_ACTORS',actual_source=None,actual_ref=None,actual_run=None,scope=selection['scope'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--own',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--selected',action='store_true');a=p.parse_args();print(json.dumps(emit(a.own,a.output,a.selected),sort_keys=True))
