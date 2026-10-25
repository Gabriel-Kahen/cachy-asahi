# SPDX-License-Identifier: MIT
"""Exact source derivation for the Apps7 lane; original callers are untouched."""
import ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps7-full574-repair-native'
OLD='scripts/ci/apps-full574-repair-native'

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def derive(root,name):
 row=json.loads((HERE/'derivation-pins.json').read_bytes())['files'][name]
 raw=(root/row['path']).read_bytes();need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'whole original source differs: '+name)
 text=raw.decode();ledger=[]
 def replace(old,new,count=1):
  nonlocal text
  need(text.count(old)==count,'exact source seam: '+name+': '+old);text=text.replace(old,new);ledger.append(dict(before=old,after=new,count=count))
 if name=='contract':
  replace("LANE='"+OLD+"'","LANE='"+LANE+"'")
  replace("'cachy-asahi-apps':'0.1.0-6'","'cachy-asahi-apps':'0.1.0-7'")
  replace("'ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS'","'ROOT_BOUND_APPS7_NATIVE574_SIGNED_REPAIR_INPUTS'")
  replace("'FROZEN_NATIVE574_SIGNED_REPAIR_CASE_SOURCE'","'FROZEN_APPS7_NATIVE574_SIGNED_REPAIR_CASE_SOURCE'")
  replace("STATUS='PASS_NATIVE574_SIGNED_REPAIR_CASE_AND_ORDERED_TEARDOWN'","STATUS='PASS_APPS7_NATIVE574_SIGNED_REPAIR_CASE_AND_ORDERED_TEARDOWN'")
  replace("value['adapter'].get('path')=='scripts/apps/full574_closure.py'","value['adapter'].get('path')==LANE+'/closure.py'")
 elif name=='closure':
  replace("'cachy-asahi-apps':'0.1.0-6'","'cachy-asahi-apps':'0.1.0-7'")
  replace("recipe=ROOT/'packages/tools'/package","recipe=ROOT/'packages/tools'/('cachy-asahi-apps7' if package=='cachy-asahi-apps' else package)")
  replace("scoped=fast.bind(ROOT,roots,caps,copy_scope,aux_copy,source_bytes)","_native_spec=importlib.util.spec_from_file_location('_apps7_native_path_view',ROOT/'"+LANE+"/path_view.py')\n_native_view=importlib.util.module_from_spec(_native_spec);sys.modules[_native_spec.name]=_native_view;_native_spec.loader.exec_module(_native_view)\nscoped=_native_view.bind(fast,ROOT,roots,caps,copy_scope,aux_copy,source_bytes)")
 elif name=='transaction':
  replace("Path(__file__).with_name('full574_closure.py')","ROOT/'"+LANE+"/closure.py'",2)
  replace("str(Path(__file__).resolve())","str(ROOT/'"+LANE+"/transaction.py')")
 elif name=='inspection':
  replace("HERE/'transaction.py'","HERE.parent/'ci/apps7-full574-repair-native/transaction.py'")
  replace("str(Path(__file__).resolve())","str(HERE.parent/'ci/apps7-full574-repair-native/inspection.py')")
 elif name=='base_lifecycle':
  replace("'/source/scripts/apps/transaction.py'","'/source/"+LANE+"/transaction.py'")
  replace("SOURCE/'scripts/apps/transaction.py'","SOURCE/'"+LANE+"/transaction.py'")
 elif name=='lifecycle':
  replace("SOURCE/'scripts/ci/apps-full574-native/lifecycle.py'","SOURCE/'"+LANE+"/base_lifecycle.py'",3)
  replace("SOURCE/'scripts/apps/repair_inspection.py'","SOURCE/'"+LANE+"/inspection.py'")
  replace("SOURCE/'scripts/apps/transaction.py'","SOURCE/'"+LANE+"/transaction.py'")
  replace("{'cachy-asahi-apps':'0.1.0-6'}","{'cachy-asahi-apps':'0.1.0-7'}")
 elif name=='checks':replace("{'cachy-asahi-apps':'0.1.0-6'}","{'cachy-asahi-apps':'0.1.0-7'}")
 else:raise ValueError('undeclared source derivative')
 ast.parse(text)
 # Inverse every declared replacement: no other source byte may change.
 restored=text
 for row in reversed(ledger):restored=restored.replace(row['after'],row['before'],row['count'])
 need(restored.encode()==raw,'all other original source bytes must remain held')
 if name in ('contract','closure','lifecycle','checks'):
  count=text.count('0.1.0-7')
  if count:replace('0.1.0-7','0.1.0-16',count)
  if name=='closure':replace("('cachy-asahi-apps7' if package==","('cachy-asahi-apps16' if package==")
 ast.parse(text)
 return text.encode(),ledger

def run(name,namespace):
 root=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
 row=json.loads((HERE/'derivation-pins.json').read_bytes())['files'][name]
 raw,ledger=derive(root,name)
 namespace['__file__']=str(root/row['path'])
 exec(compile(raw,str(root/row['path'])+':apps7-exact-derivative','exec'),namespace)
