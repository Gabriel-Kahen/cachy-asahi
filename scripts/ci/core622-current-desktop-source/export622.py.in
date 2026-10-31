# SPDX-License-Identifier: MIT
"""Preserve current public DATA and invoke the entire original opaque transport."""
import argparse,hashlib,importlib.util,json,os,stat,sys,types
from pathlib import Path

def need(v,s):
 if not v:raise ValueError(s)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def copy(output,public):
 source=output/'core622-public';need(output.parent==Path('/tmp')and output.is_absolute()and public.is_absolute()and not public.exists()and not any(x.is_symlink()for x in(output,public,*output.parents,*public.parents)),'fresh explicit current output/public paths');rows={};total=0
 if source.exists():
  for f in source.rglob('*'):
   st=f.lstat();need(st.st_uid==os.getuid()and not f.is_symlink()and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'only current caller-owned ordinary public evidence')
   if f.is_file():
    n=f.relative_to(source).as_posix();need(st.st_size<=128*1024**2 and len(rows)<4096,'original individual public caps');raw=f.read_bytes();need(len(raw)==st.st_size,'whole current public bytes');rows[n]=pin(raw);total+=len(raw);need(total<=768*1024**2,'original768MiB aggregate');target=public/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  need((public/'export.json').is_file(),'source-owned full Core retainer required');record=json.loads((public/'export.json').read_bytes());need(set(rows)==set(record['files'])|{'export.json'}and all(rows[n]==v for n,v in record['files'].items()),'unchanged complete current Core public closure');return
 public.mkdir(mode=0o700)
 # An original producer failure can precede every Core consumer. Preserve only
 # the fixed outer current result; no invented Core owner or cleanup receipt.
 result=output/'result.json'
 if result.is_file():
  st=result.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and st.st_size<=4*1024**2,'ordinary bounded current outer result');raw=result.read_bytes();need(len(raw)==st.st_size,'whole current result');(public/'fresh607-caller-result.json').write_bytes(raw);rows['fresh607-caller-result.json']=pin(raw)
 raw=(json.dumps(dict(status='CORE622_PRE_PROVISION_FAILURE_DATA_ONLY',scope='COPIED_ROOT_PROVISIONING_NOT_NORMAL_HOOK_INSTALLATION_THEN_NORMAL_CORE_VM',Core_runtime='NOT_ESTABLISHED',acceptance=False,hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n').encode();(public/'current622-context.json').write_bytes(raw);rows['current622-context.json']=pin(raw);(public/'export.json').write_text(json.dumps(dict(schema=1,status='FAIL_OR_INCOMPLETE',files=rows,bytes=sum(r['bytes']for r in rows.values()),errors=[dict(file='Core622',error='PRE_PROVISION_FAILURE_DATA_ONLY')],hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n')

def transport(core,public,target):
 path=core/'scripts/ci/core-native-lifecycle/owner.py';sys.path.insert(0,str(path.parent));spec=importlib.util.spec_from_file_location('_core622_whole_original_transport',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.transport(types.SimpleNamespace(public=public,output=target))

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--transport-only',action='store_true');p.add_argument('--core-source',type=Path);p.add_argument('--transport',type=Path);a=p.parse_args()
 if a.transport_only:need(a.core_source is not None and a.transport is not None,'explicit original transport source/output');return transport(a.core_source,a.public,a.transport)
 return copy(a.output,a.public)
if __name__=='__main__':raise SystemExit(main())
