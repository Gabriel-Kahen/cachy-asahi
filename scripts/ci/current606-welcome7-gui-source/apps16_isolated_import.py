# SPDX-License-Identifier: MIT
"""Explicit exact562→564→565 isolated post-session startup source factory."""
import ast,base64,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 5253, 'sha256': '10dd1a0e3b14c39809592bc94db887e9767f10e5266ea7005794690f230c3c65'}

def canonical(api,path):
 path=Path(path).absolute();api['need'](path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary input/output');return path

def inputs(api):
 read,pin,need,files=(api[k]for k in('ordinary','pin','need','files'));raw=read(HERE/'apps16-isolated-import-profile.json');need(pin(raw)==PROFILE,'whole isolated-import profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_GUI565_ISOLATED_IMPORT'and p['actual']is None and p['before_source']=='37bee5c50f8808b618b90ab0a559d7fa88a8a4ab'and p['stage_source']=='a1a0dea6fc4d3cf15fb82c72c52385c277eae0cc'and p['after_source']=='b9a1195e5f5c5e439db791383e18e56511de2f5a','exact published562/564/565 source identities');raw=read(HERE/'apps16-isolated-import-maps.json');need(pin(raw)==p['maps'],'complete isolated before/stage/after maps');maps=json.loads(raw);need({n:len(v)for n,v in maps.items()}==dict(before=562,null_before=562,stage=564,null_stage=564,selected=565,unbound=565),'entire selected/NULL source namespaces');payload=files(canonical(api,HERE/'apps16-isolated-import-payload'));need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole five readable source operands');return p,maps,payload

def manifest(api,values,status):
 return api['encoded'](dict(status=status,files={n:api['pin'](b)for n,b in sorted(values.items())if n!='source-manifest.json'},actual_source=None,actual_ref=None,actual_run=None))

def compose(api,before,unbound,p,maps,payload):
 need,pin,enc=(api[k]for k in('need','pin','encoded'));mapping=maps['null_before'if unbound else'before'];stage_map=maps['null_stage'if unbound else'stage'];wanted=maps['unbound'if unbound else'selected'];need({n:pin(b)for n,b in before.items()}==mapping,'whole exact562 source variant');anchor='    return changes\n';marker=payload['post-session-factory.fragment'].decode();loader=payload['isolated-factory.fragment'].decode();old=before['factory/factory.py'].decode();need(old.count(anchor)==1,'one marker factory seam');out=dict(before);out['factory/factory.py']=old.replace(anchor,marker+anchor,1).encode();out['factory/post_session.py']=payload['post_session.py'];out['admission.py']+=payload['post-session-admission.fragment'];out['post-session-parent.json']=enc(dict(variant='unbound'if unbound else'selected',source=None if unbound else p['before_source'],ref=None if unbound else p['before_ref'],actual=None,files=mapping,before_bodies={n:base64.b64encode(before[n]).decode()for n in('admission.py','factory/factory.py','source-manifest.json')}));out['source-manifest.json']=manifest(api,out,'SOURCE_ONLY_GUI_POST_SESSION_STAGE_DATA_NO_GUI_ACCEPTANCE');need({n:pin(b)for n,b in out.items()}==stage_map,'entire exact564 stage before startup child');stage=dict(out)
 text=out['factory/factory.py'].decode();need(text.count(anchor)==1,'one isolated factory seam');out['factory/factory.py']=text.replace(anchor,loader+anchor,1).encode();out['admission.py']+=payload['isolated-admission.fragment'];out['isolated-import-parent.json']=enc(dict(variant='unbound'if unbound else'selected',source=None if unbound else p['stage_source'],ref=None if unbound else p['stage_ref'],actual=None,files=stage_map,before_bodies={n:base64.b64encode(stage[n]).decode()for n in('admission.py','source-manifest.json')}));out['source-manifest.json']=manifest(api,out,'SOURCE_ONLY_GUI_POST_SESSION_ISOLATED_IMPORT_NO_GUI_ACCEPTANCE');need({n:pin(b)for n,b in out.items()}==wanted,'entire exact565 output before writes')
 restored=dict(out);restored.pop('isolated-import-parent.json');need(restored['factory/factory.py'].decode().count(loader)==1,'one complete loader block inverse');restored['factory/factory.py']=restored['factory/factory.py'].decode().replace(loader,'',1).encode()
 for n in('admission.py','source-manifest.json'):restored[n]=stage[n]
 need(restored==stage,'complete565 to564 byte inverse');restored.pop('post-session-parent.json');restored.pop('factory/post_session.py');need(restored['factory/factory.py'].decode().count(marker)==1,'one complete marker block inverse');restored['factory/factory.py']=restored['factory/factory.py'].decode().replace(marker,'',1).encode()
 for n in('admission.py','source-manifest.json'):restored[n]=before[n]
 need(restored==before,'complete564 to562 byte inverse');return out

def emit(api,predecessor,output,unbound=False):
 need,pin,files=(api[k]for k in('need','pin','files'));need(type(unbound)is bool,'literal NULL choice');predecessor=canonical(api,predecessor);output=canonical(api,output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh source/factory disjoint output');p,maps,payload=inputs(api);before=files(predecessor);out=compose(api,before,unbound,p,maps,payload)
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 need(files(predecessor)==before,'fresh whole562 revalidation before writes');need(inputs(api)==(p,maps,payload),'fresh exact source operands before writes');output.mkdir(mode=0o700)
 for n,b in sorted(out.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(b)
 need(files(output)==out,'whole exact565 emitted source');return dict(status='SOURCE_ONLY_GUI_POST_SESSION_ISOLATED_IMPORT_NO_GUI_ACCEPTANCE',files=565,source=None if unbound else p['after_source'],ref=None if unbound else p['after_ref'],actual_source=None,actual_ref=None,actual_run=None,native_GUI='NOT_RUN',native_fit='UNKNOWN')
