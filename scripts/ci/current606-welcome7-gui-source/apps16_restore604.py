# SPDX-License-Identifier: MIT
"""Explicit whole561→562 restore precondition correction; source only."""
import ast,base64,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':5290,'sha256':'70541c5bf40b7d79bcbbe299f76430568ba847ed0cd75501b76ce91b8890977c'}

def canonical(api,path):
 path=Path(path).absolute();api['need'](path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary input/output');return path

def inputs(api):
 read,pin,need,files=(api[k]for k in('ordinary','pin','need','files'));raw=read(HERE/'apps16-restore604-profile.json');need(pin(raw)==PROFILE,'whole restore604 profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_GUI562_RESTORE604'and p['actual']is None and p['before_source']=='d34854151f578547c2f64f46d14f5d9129bf2d66'and p['after_source']=='37bee5c50f8808b618b90ab0a559d7fa88a8a4ab','exact restore604 identities');raw=read(HERE/'apps16-restore604-maps.json');need(pin(raw)==p['maps'],'whole restore604 maps');maps=json.loads(raw);need({n:len(v)for n,v in maps.items()}==dict(before=561,null_before=561,selected=562,unbound=562),'whole561/562 variants');payload=files(canonical(api,HERE/'apps16-restore604-payload'));need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable restore604 operands');return p,maps,payload

def emit(api,predecessor,output,unbound=False):
 need,pin,files,enc=(api[k]for k in('need','pin','files','encoded'));need(type(unbound)is bool,'literal NULL choice');predecessor=canonical(api,predecessor);output=canonical(api,output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh source/factory disjoint output');p,maps,payload=inputs(api);mapping=maps['null_before'if unbound else'before'];expected=maps['unbound'if unbound else'selected'];before=files(predecessor);need({n:pin(b)for n,b in before.items()}==mapping,'whole original561 variant');text=before['factory/factory.py'].decode();need(text.count(p['before_seam'])==1 and text.replace(p['before_seam'],p['proposed_seam'],1).encode()==payload['factory.py'],'sole counted593 to604 restore precondition seam')
 out=dict(before);out['factory/factory.py']=payload['factory.py'];out['admission.py']+=payload['admission.fragment'];out['management-restore-parent.json']=enc(dict(variant='unbound'if unbound else'selected',source=None if unbound else p['before_source'],ref=None if unbound else p['before_ref'],actual=None,files=mapping,before_bodies={n:base64.b64encode(before[n]).decode()for n in('admission.py','factory/factory.py','source-manifest.json')}));out['source-manifest.json']=enc(dict(status='SOURCE_ONLY_APPS16_GUI_RESTORE604_NO_GUI_ACCEPTANCE',files={n:pin(b)for n,b in sorted(out.items())if n!='source-manifest.json'},actual_source=None,actual_ref=None,actual_run=None));need({n:pin(b)for n,b in out.items()}==expected,'whole exact562 before writes')
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 need({n:pin(b)for n,b in files(predecessor).items()}==mapping,'fresh whole561 revalidation before writes');p2,m2,b2=inputs(api);need((p2,m2,b2)==(p,maps,payload),'fresh source operands before writes');output.mkdir(mode=0o700)
 for n,b in sorted(out.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb')as stream:stream.write(b)
 need({n:pin(b)for n,b in files(output).items()}==expected,'whole emitted562');return dict(status='SOURCE_ONLY_APPS16_GUI_RESTORE604_NO_GUI_ACCEPTANCE',files=562,source=None if unbound else p['after_source'],ref=None if unbound else p['after_ref'],actual_source=None,actual_ref=None,actual_run=None)
