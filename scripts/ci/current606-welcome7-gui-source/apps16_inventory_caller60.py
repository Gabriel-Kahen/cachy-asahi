# SPDX-License-Identifier: MIT
"""Explicit public562→565→568→570 TCG caller60 source; old35/product30 stay held."""
import ast,base64,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 32826, 'sha256': '48f8b312994806010501d4fd14abbeaa25f41a8053062c6e28bb5f73b13cc2d6'}
DELEGATE="""def prepare_apps16_inventory_caller60(predecessor,output,unbound=False):
 import importlib.util
 spec=importlib.util.spec_from_file_location('_maintained_GUI_inventory_caller60',HERE/'apps16_inventory_caller60.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.emit(globals(),predecessor,output,unbound)

"""
CLI_BEFORE='a=p.parse_args();emit='
CLI_AFTER="group.add_argument('--apps16-inventory-caller60',action='store_true',help='explicit TCG caller60 source570 from public restore562; product30/default35 held');group.add_argument('--apps16-inventory-caller60-unbound',action='store_true',help='strict NULL570 derived from public restore562; refuses actors');a=p.parse_args();emit=(lambda parent,out:prepare_apps16_inventory_caller60(parent,out,a.apps16_inventory_caller60_unbound)) if a.apps16_inventory_caller60 or a.apps16_inventory_caller60_unbound else "
def once(api,text,before,after):
 api['need'](text.count(before)==1,'one counted caller60 source seam');return text.replace(before,after,1)
def main_inverse(api,text):return once(api,once(api,text,DELEGATE,''),CLI_AFTER,CLI_BEFORE)
def canonical(api,path):
 path=Path(path).absolute();api['need'](path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary source path');return path

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def inputs(api):
 read,pin,need,files=(api[k]for k in('ordinary','pin','need','files'));raw=read(HERE/'apps16-inventory-caller60-profile.json');need(pin(raw)==PROFILE,'whole fixed caller60 source profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_GUI570_EXPLICIT_CALLER60_AND_PRESECRET_CONTROLS'and p['actual']is p['current_source']is p['current_ref']is p['current_run']is None and p['before_source']=='37bee5c50f8808b618b90ab0a559d7fa88a8a4ab'and p['via_source']=='b9a1195e5f5c5e439db791383e18e56511de2f5a'and p['after_source']=='04db51b4932bb3af6fb6dc36ea2f533996de814c'and p['presecret_before_source']=='b693a4c5a791f71fc3b91d109cbf9e49a14e424a','public exact562/565/568/570 and no current actual authority');raw=read(HERE/'apps16-inventory-caller60-maps.json');need(pin(raw)==p['maps'],'whole caller60 closed maps');maps=json.loads(raw);need(set(maps)=={'selected','unbound','before568'}and all(len(maps[k])==570 for k in('selected','unbound'))and set(maps['before568'])=={'selected','unbound'}and all(len(m)==568 for m in maps['before568'].values()),'both complete568 variants');payload=files(canonical(api,HERE/'apps16-inventory-caller60-payload'));need({n:pin(b)for n,b in payload.items()}==p['payload'],'whole readable helper/profile/finite fragments')
 for n,w in p['canonical_before'].items():
  raw=read(HERE/n)
  if n=='prepare.py':raw=main_inverse(api,raw.decode()).encode()
  elif n=='README.md':raw=raw[:w['bytes']]
  need(pin(raw)==w,'every old canonical function/module/default/operand held '+n)
 I=load('_held_isolated_source_compose',HERE/'apps16_isolated_import.py');ip,im,ib=I.inputs(api);need(ip['before_source']==p['before_source']and ip['after_source']==p['via_source'],'existing maintained public562→565 identity');return p,maps,payload,I,(ip,im,ib)

def original(api,values,layer_name,expected):
 need,pin=(api[k]for k in('need','pin'));layer=json.loads(values[layer_name]);need(layer['files']==expected,'whole exact source-owned before namespace');restored={n:base64.b64decode(layer['before_bodies'][n],validate=True)if n in layer['before_bodies']else values[n]for n in expected};need({n:pin(b)for n,b in restored.items()}==expected,'every source-owned original byte inverse');return restored

def null_restore562(api,before,predecessor,I):
 # Public562 carries whole selected561, which carries whole cleanup561 before bodies.
 # Reuse existing maintained NULL rendering; no opaque NULL payload or disk staging.
 need,pin,enc=(api[k]for k in('need','pin','encoded'));A=load('_held_apps16_null_renderer',HERE/'apps16.py');ap,am,ab=A.inputs(api);R=load('_held_restore604_operands',HERE/'apps16_restore604.py');rp,rm,rb=R.inputs(api);selected=original(api,before,'management-restore-parent.json',rm['before']);cleanup=original(api,selected,'apps16-parent.json',am['before']);virtual=dict(api)
 virtual['files']=lambda path:dict(cleanup)if Path(path)==predecessor else api['files'](path)
 null=A.render(virtual,predecessor,True);need({n:pin(b)for n,b in null.items()}==rm['null_before'],'existing exact NULL561 feeds restore604')
 out=dict(null);out['factory/factory.py']=rb['factory.py'];out['admission.py']+=rb['admission.fragment'];out['management-restore-parent.json']=enc(dict(variant='unbound',source=None,ref=None,actual=None,files=rm['null_before'],before_bodies={n:base64.b64encode(null[n]).decode()for n in('admission.py','factory/factory.py','source-manifest.json')}));out['source-manifest.json']=I.manifest(api,out,'SOURCE_ONLY_APPS16_GUI_RESTORE604_NO_GUI_ACCEPTANCE');need({n:pin(b)for n,b in out.items()}==rm['unbound'],'whole exact NULL562 derived only from public562');return out

def compose(api,before,unbound,p,maps,payload,I,isolated,predecessor):
 need,pin,enc=(api[k]for k in('need','pin','encoded'));ip,im,ib=isolated;need({n:pin(b)for n,b in before.items()}==im['before'],'whole genuine public562 input for both routes');base=null_restore562(api,before,predecessor,I)if unbound else before;stage=I.compose(api,base,unbound,ip,im,ib);mapping=im['unbound'if unbound else'selected'];need({n:pin(b)for n,b in stage.items()}==mapping,'existing exact565 intermediate')
 out=dict(stage);text=stage['factory/factory.py'].decode()
 for row in p['copy_seams']:text=once(api,text,row['before'],row['after'])
 out['factory/factory.py']=text.encode();out['factory/current_products.py']+=payload['current-products.fragment'];out['factory/inventory_capacity.py']=payload['inventory_capacity.py'];out['factory/inventory-vm-profile.json']=payload['inventory-vm-profile.json'];out['admission.py']+=payload['admission.fragment'];pub=p['parent565_publication'];context=None if unbound else dict(publication=pub,git=dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['via_source'],ref=p['via_ref'],files=mapping),authorization=mapping);out['inventory-vm-parent.json']=enc(dict(variant='null'if unbound else'known',source=None if unbound else p['via_source'],ref=None if unbound else p['via_ref'],actual=None,files=mapping,context=context,before_bodies={n:base64.b64encode(stage[n]).decode()for n in p['before_body_roles']}));out['source-manifest.json']=I.manifest(api,out,'SOURCE_ONLY_GUI_TCG_INVENTORY_CALLER60_NO_GUI_ACCEPTANCE');wanted=maps['before568']['unbound'if unbound else'selected'];need({n:pin(b)for n,b in out.items()}==wanted,'entire exact568 before presecret extension')
 restored={n:out[n]for n in stage}
 for n in p['before_body_roles']:restored[n]=stage[n]
 need(restored==stage and set(out)-set(stage)=={'factory/inventory_capacity.py','factory/inventory-vm-profile.json','inventory-vm-parent.json'}and {n for n in stage if stage[n]!=out[n]}==set(p['before_body_roles']),'whole565 inverse; exactly3added/4changed all others byteheld');return presecret(api,out,unbound,p,maps,payload,I)

def presecret(api,before,unbound,p,maps,payload,I):
 need,pin,enc=(api[k]for k in('need','pin','encoded'));out=dict(before);out['apps16_common.py']=once(api,before['apps16_common.py'].decode(),p['presecret_old'],p['presecret_call']).encode();out['inventory_presecret_controls.py']=payload['inventory_presecret_controls.py'];out['admission.py']+=payload['presecret-admission.fragment'];mapping=maps['before568']['unbound'if unbound else'selected'];pub=p['parent568_publication'];context=None if unbound else dict(publication=pub,git=dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['presecret_before_source'],ref=p['presecret_before_ref'],files=mapping),authorization=mapping);out['caller60-presecret-parent.json']=enc(dict(variant='null'if unbound else'known',source=None if unbound else p['presecret_before_source'],ref=None if unbound else p['presecret_before_ref'],actual=None,files=mapping,context=context,before_bodies={n:base64.b64encode(before[n]).decode()for n in p['presecret_before_roles']}));out['source-manifest.json']=I.manifest(api,out,'SOURCE_ONLY_GUI_CALLER60_PRESECRET_CONTROLS_NO_RUNTIME_CHANGE');need({n:pin(b)for n,b in out.items()}==maps['unbound'if unbound else'selected'],'entire exact570 before output');need(set(out)-set(before)=={'inventory_presecret_controls.py','caller60-presecret-parent.json'}and {n for n in before if out[n]!=before[n]}==set(p['presecret_before_roles']),'whole568 inverse; exactly2added/3host-only changes');need(out['apps16_common.py'].replace(p['presecret_call'].encode(),p['presecret_old'].encode(),1)==before['apps16_common.py'],'entire original source controls except one main delegation');return out

def emit(api,predecessor,output,unbound=False):
 need,files,pin=(api[k]for k in('need','files','pin'));need(type(unbound)is bool,'literal NULL route');predecessor=canonical(api,predecessor);output=canonical(api,output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output)and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh disjoint ordinary public-input/factory output');p,maps,payload,I,isolated=inputs(api);before=files(predecessor);out=compose(api,before,unbound,p,maps,payload,I,isolated,predecessor)
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 need(files(predecessor)==before,'fresh whole public562 revalidation before writes');p2,m2,b2,_,i2=inputs(api);need((p2,m2,b2,i2)==(p,maps,payload,isolated),'fresh whole fixed caller60/old operands before writes');output.mkdir(mode=0o700)
 for n,b in sorted(out.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(b)
 need({n:pin(b)for n,b in files(output).items()}==maps['unbound'if unbound else'selected'],'whole emitted570 equality');return dict(status='SOURCE_ONLY_EXPLICIT_TCG_INVENTORY_CALLER60',files=570,source_authority=None if unbound else p['after_source'],ref_authority=None if unbound else p['after_ref'],current_source=None,current_ref=None,current_run=None,actual=None,actual_source=None,actual_ref=None,actual_run=None,profile='GUI_TCG_INVENTORY_CALLER_60_V1',product_scan_seconds=30,default_caller_seconds=35,old35_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN',native_hotspot='UNKNOWN',native_GUI='NOT_RUN',acceptance='NOT_GRANTED')
