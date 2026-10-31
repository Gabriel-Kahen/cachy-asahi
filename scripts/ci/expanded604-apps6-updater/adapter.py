# SPDX-License-Identifier: MIT
"""Derive selected Apps5→6 constants after the original full604/copy/progress guards."""
import ast,hashlib
from pathlib import Path
import contract as C
OLD='scripts/ci/expanded604-current-management-updater'
PREFIX='scripts/ci/expanded604-apps6-updater/'
SELECTED={'scripts/ci/full-root-upgrade/root_upgrade.py','scripts/ci/full-root-upgrade/construct_repository.py',
 'scripts/update/scale_update.py','scripts/ci/full-root-upgrade-caller/upgrade_hook.py',
 'scripts/ci/full-root-failed-update/run.py','scripts/ci/full-root-failed-update/caller.py',
 'scripts/ci/full-root-postcommit-failure/run.py','scripts/ci/full-root-postcommit-failure/caller.py'}
priorC=C.load('_apps6_exact_prior_contract',C.HERE.parent/'expanded604-current-management-updater/contract.py')
prior=C.scoped('_apps6_exact_prior_adapter',C.HERE.parent/'expanded604-current-management-updater/adapter.py',{'contract':priorC})

def value(v):
 if type(v) is not str:return v
 exact={priorC.BEFORE:C.BEFORE,priorC.AFTER:C.AFTER,priorC.PACKAGE:C.PACKAGE,
 '4cf9884dacb2816532b07c8107982d7157656046':C.NATIVE,
 'd31e4bdfb5c0c38e0128bbcb5127926414628f2d8d047f9eb0a2da0142848519':C.RECIPE,
 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac':'66c46d4645fa443d23df0e97765905555fe5bc2607787dca3f30ee2084cf597f',
 'build574.lock':'build575.lock','cachy-asahi-setup':'cachy-asahi-apps','0.1.0-3':'0.1.0-5','0.1.0-5':'0.1.0-6',
 '-0.1.0-3':'-0.1.0-5','-0.1.0-5':'-0.1.0-6'}
 if v in exact:return exact[v]
 # Exact selected archive/DB/source paths, not a global product version rewrite.
 v=v.replace('cachy-asahi-setup-0.1.0-3','cachy-asahi-apps-0.1.0-5').replace('cachy-asahi-setup-0.1.0-5','cachy-asahi-apps-0.1.0-6')
 for before,after in (('packages/cachy-asahi-setup-', 'public/packages/cachy-asahi-apps-'),('runtime/cachy-asahi-setup-','public/runtime/cachy-asahi-apps-'),('source/cachy-asahi-setup/','public/source/cachy-asahi-apps/')):v=v.replace(before,after)
 return v.replace('actual-current604-persistent-root-setup5-test','actual-apps6-current604-persistent-root-test').replace('actual-current604-precommit-failure-disposal-test','actual-apps6-current604-precommit-failure-disposal-test').replace('actual-current604-postcommit-failure-disposal-test','actual-apps6-current604-postcommit-failure-disposal-test')

def transform(raw,name):
 """Only declared constants; complete AST equality after those exact substitutions."""
 C.need(name in SELECTED,'finite selected module set');text=raw.decode();tree=ast.parse(text);lines=text.splitlines(keepends=True);offset=[0]
 for line in lines:offset.append(offset[-1]+len(line))
 edits=[];expected=ast.parse(raw)
 for node in ast.walk(expected):
  if isinstance(node,ast.Constant):node.value=value(node.value)
 for node in ast.walk(tree):
  if isinstance(node,ast.Constant) and value(node.value)!=node.value:edits.append((offset[node.lineno-1]+node.col_offset,offset[node.end_lineno-1]+node.end_col_offset,repr(value(node.value))))
 for a,b,v in sorted(edits,reverse=True):text=text[:a]+v+text[b:]
 C.need(ast.dump(ast.parse(text),include_attributes=False)==ast.dump(expected,include_attributes=False),'undeclared Apps6 AST mutation');return text.encode(),len(edits)

def constructor(raw):
 text=raw.decode();tree=ast.parse(text);lines=text.splitlines(keepends=True);edits=[]
 for node in tree.body:
  if isinstance(node,ast.FunctionDef) and node.name in ('locks','inspect_package'):
   if node.name=='locks':body="def locks(root, setup):\n    helper=load_module(root,'apps6_selected','"+PREFIX+"selected_package.py')\n    return helper.locks(root)\n"
   else:body="def inspect_package(args, api=None):\n    api=api or apis(ordinary(args.source_root,directory=True))\n    helper=load_module(Path(args.source_root),'apps6_selected','"+PREFIX+"selected_package.py')\n    return helper.inspect_package(args,api)\n"
   edits.append((node.lineno-1,node.end_lineno,body))
 C.need(len(edits)==2,'two exact constructor inspector/lock seams')
 for a,b,v in sorted(edits,reverse=True):lines[a:b]=[v]
 text=''.join(lines);C.need(text.count("source['project_url']")==1,'original source URL association seam');text=text.replace("source['project_url']","pkg['url'][0]");return text.encode()

def prepare(source,target,case,*,git=True,implementation=None):
 # Original adapter uses its own Setup3→5 locks solely as its source-derivation basis.
 config,caller=prior.prepare(source,target,case,git=git,implementation=implementation or C.SOURCE)
 changes={}
 for name in sorted(SELECTED):
  p=target/name
  if not p.exists():continue
  raw=p.read_bytes();new,count=transform(raw,name)
  if name.endswith('/construct_repository.py'):
   new=constructor(new)
   text=new.decode();C.need(text.count("'inventory_count': 574")==1 and text.count("['inventory_count'] == 574")==1,'two exact native build metadata count operands');new=text.replace("'inventory_count': 574","'inventory_count': 575").replace("['inventory_count'] == 574","['inventory_count'] == 575").encode()
  p.write_bytes(new);changes[name]=dict(before=hashlib.sha256(raw).hexdigest(),after=C.sha(p),constant_edits=count)
 for name in ('selected_package.py','apps6-product.json'):
  p=target/PREFIX/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((C.HERE/name).read_bytes())
 for name,lock in (('expected-updater-v2.lock','before604.lock'),('expected-setup4-v2.lock','after604.lock')):(target/'scripts/ci/full-development-composition'/name).write_bytes((C.HERE/lock).read_bytes())
 binding=target/PREFIX/'apps6-binding.json';binding.write_bytes(C.encoded(C.policy(bound=False)['apps6']))
 v=C.read(config);v['purpose']=value(v['purpose']);v['scale'].update(before_lock_sha256=C.BEFORE,after_lock_sha256=C.AFTER);v['release'].update(release_id='apps6-current604-'+case+'-20261017',namespace='cachy-asahi-apps6-current604-'+case)
 for n in ('selected_package.py','apps6-product.json','apps6-binding.json'):v['code_pins'][PREFIX+n]=C.sha(target/PREFIX/n)
 v['code_pins']={n:C.sha(target/n) for n in v['code_pins']};v['external_pins']['/persistent_scope.py']=C.sha(caller/'persistent_scope.py');config.write_bytes(C.encoded(v))
 row=C.read(target/'adapter.json');row.update(status='PRIVATE_APPS5_TO6_CURRENT604_SELECTION_ONLY',before_sha256=C.BEFORE,after_sha256=C.AFTER,selected='cachy-asahi-apps',package_sha256=C.PACKAGE,other603='UNCHANGED',selection=changes,config_sha256=C.sha(config),native='NOT_RUN');(target/'adapter.json').write_bytes(C.encoded(row));return config,caller
