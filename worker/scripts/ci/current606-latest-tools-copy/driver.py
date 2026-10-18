# SPDX-License-Identifier: MIT
"""Actual two-tool worker; no live-root qualification or host actor creation."""
import copy,hashlib,os,pwd,time
from pathlib import Path
import contract as C,guard as G,lifecycle,physical,roles,supervised,rooted_cli
ROOT=Path(__file__).resolve().parents[3]

def without_context(value,contexts):
 result=copy.deepcopy(value);nodes=result['nodes'];private={n for n in nodes if any(n==p or n.startswith(p+'/')for p in contexts)}
 C.need(len(private)<=512 and sum(nodes[n].get('bytes',0)for n in private)<=32*1024**2,'SAME aggregate fixture512/32MiB bounds')
 for g in result.get('hardlink_groups',{}).values():C.need(not any(n in private for n in g['members']),'fixture external hardlink')
 result['nodes']={n:r for n,r in nodes.items()if n not in private};return result

def run(target,*,data,plan,budget,worker):
 C.need(Path(target)==Path('/work/main/root')and type(plan)is dict and set(plan)=={'apps','welcome'},'finite two-selected copied-root plan')
 api={k:roles.load(k)for k in G.BASE};db=api['apps']['driver'].database_api();expected=G.package_inventory(data['packages']);G.inventory(expected,expected)
 plans={}
 for k,version in G.BASE.items():
  path='var/lib/pacman/local/'+G.NAMES[k]+'-'+version
  with db.directory(C.SOURCE_ROOT,path)as fd:fields=db.fields(db.read_record(fd,'desc',expected=data['ordinary_observation']['nodes'][path+'/desc']))
  plans[k]=api[k]['plan'].complete(plan[k],fields)
 products=lifecycle.operands(plans,api);seed=worker.observe(target,budget);contexts={k:api[k]['rooted_fixture'].CONTEXT.lstrip('/')for k in api};contexts['apps605']=rooted_cli.CONTEXT.lstrip('/')
 C.need(not any(p in seed['nodes']for p in contexts.values()),'both private fixture contexts absent in original606')
 selected_dirs=set(C.APPS_DIRS)|set(C.WELCOME_DIRS);selected_files=set(C.APPS_FILES)|set(C.WELCOME_FILES)
 for directory in selected_dirs:C.need({n for n in seed['nodes']if n.startswith(directory+'/')}=={n for n in selected_files if n.startswith(directory+'/')},'complete exclusive selected directory, no unowned descendants')
 for package in data['packages']:
  path='var/lib/pacman/local/'+package['name']+'-'+package['version']
  with db.directory(target,path)as fd:owned=db.fields(db.read_record(fd,'files',expected=seed['nodes'][path+'/files'])).get('FILES',[])
  ownrole=next((k for k,n in G.NAMES.items()if n==package['name']),None);own=set(C.APPS_DIRS if ownrole=='apps'else C.WELCOME_DIRS if ownrole=='welcome'else())
  C.need(not any((d in owned or d+'/'in owned)and d not in own for d in selected_dirs),'protected604/other selected package owns exclusive directory')
 runtime=plans['apps']['runtime'];C.need(expected.get('cachy-asahi-repository-runtime')==runtime['version']=='0.1.0-1','Runtime1 already among protected604')
 for n,w in runtime['payload'].items():
  r=seed['nodes'].get(n);C.need(r and r['type']=='file'and r['uid']==r['gid']==0 and r['mode']==w['mode']and r['bytes']==w['size']and r['sha256']==w['sha256'],'all existing Runtime1 source-bound payload')
 # Original Apps keyring implementation already accepts exactly these two
 # original-producer/new-native TEST keys. Welcome5 uses the same producer key.
 verification=__import__('importlib').util.spec_from_file_location('_joint_verification',ROOT/'held-apps-worker/scripts/ci/current606-apps7-copy/verification.py');V=__import__('importlib').util.module_from_spec(verification)
 with roles.aliases({'contract':api['apps']['contract'],'supervised':api['apps']['supervised']}):verification.loader.exec_module(V)
 keyring=V.prepare(plans['apps']['verification_keys'],signers={p['signer']for group in products.values()for p in group.values()},budget=budget);runtime_receipt=V.verify_product(runtime,budget=budget)
 stages={};stages['apps']=api['apps']['rooted_fixture'].stage(target);stages['welcome']=api['welcome']['rooted_fixture'].stage(target,plans['welcome']['fixture_policy'],plans['welcome']['fixture_products'],Path('/runner/inputs/sources'));stages['apps605']=rooted_cli.stage(target)
 account=pwd.getpwnam('alarm');C.need(account.pw_uid>0 and account.pw_gid>0,'original ordinary account');homes={};preserved={};home_graph={};output_pins={};windows={};last_lock=[None];counter=[0]
 for role,prefix in contexts.items():
  context=Path(target)/prefix;homes[role]={}
  for kind in('fresh','existing'):
   home=context/'homes'/kind;home.mkdir(mode=0o700)
   if kind=='existing':
    for relative in('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
     p=home/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('preserve '+relative+'\n');p.chmod(0o600)
    (home/'.config/alias').symlink_to('cachy-asahi/preferences')
   (home/'runtime').mkdir(mode=0o700)
   for p in(home,*home.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
   homes[role][kind]='/'+home.relative_to(target).as_posix()
   for p in home.rglob('*'):
    if p.is_file()and not p.is_symlink():preserved[p]=C.pin(C.ordinary(p))
 for n in('fixture-plans','transaction-plans'):
  p=Path('/work')/n;C.need(not p.exists(),'fresh owned private plan dir');p.mkdir(mode=0o700)
 def observe(versions):
  budget.tick();full=worker.observe(target,budget)
  for p,row in(*preserved.items(),*output_pins.items()):C.need(C.pin(C.ordinary(p,16*1024**2))==row,'private existing home/earlier fixture output changed')
  for role,stage in stages.items():
   for n,row in stage['files'].items():C.need(C.pin(C.ordinary(Path(target)/contexts[role]/n,1024**2))==row,'exact staged source fixture bytes changed')
  rows=db.database(target,max_packages=606,max_files=budget.max_package_files,max_nodes=budget.max_nodes,observed=full['nodes']);inventory={r['name']:r['version']for r in rows};ids=physical.capture(target,full['nodes'],budget)
  for role,values in homes.items():
   for kind,home in values.items():
    prefix=home.lstrip('/');graph={n:dict(node=r,identity=ids[n])for n,r in full['nodes'].items()if n==prefix or n.startswith(prefix+'/')};key=(role,kind)
    if key not in home_graph:home_graph[key]=graph
    else:C.need(home_graph[key]==graph,'full both-tool fresh/existing home graph/inodes changed')
  ids={n:r for n,r in ids.items()if not any(n==p or n.startswith(p+'/')for p in contexts.values())}
  valid={k:(v is None or api[k]['driver'].selected_database(target,rows,full['nodes'],products[k][v],window=windows.get((k,v))))for k,v in versions.items()}
  return dict(observation=without_context(full,contexts.values()),inventory=inventory,physical=ids,capabilities=worker.caps.observe(target,full['nodes'],budget),selected_database_validated=valid,lock_parent=last_lock[0])
 def transact(phase,role,before,product):
  budget.tick();after=dict(before)
  if product is None:after.pop(G.NAMES[role])
  else:after[G.NAMES[role]]=product['version']
  archive=None if product is None else{k:product[k]for k in('path','bytes','sha256','signature','signer','version')};counter[0]+=1;p=Path('/work/transaction-plans')/(str(counter[0])+'.json')
  with p.open('xb')as out:out.write(C.encoded(dict(selected=role,root=str(target),before=before,after=after,archive=archive,keys='/work/test-verification',log='/out/'+phase+'-alpm.log')))
  p.chmod(0o600);start=int(time.time());r=supervised.run([os.sys.executable,'-I','-B',str(Path(__file__).with_name('step_entry.py')),str(p)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},cwd='/',timeout=min(90,budget.deadline-time.monotonic()),output_limit=128*1024,grace=1)
  C.need(r['returncode']==0 and r['termination']is None and r['direct_child_reaped']and r['group_retired'],'actual signed selected child retirement');receipt=C.decode(r['stdout']);C.need(receipt.pop('selected')==role and receipt['status']==('COMMITTED_SELECTED_APPS_REQUIRES_FULL_READBACK'if role=='apps'else'COMMITTED_SELECTED_WELCOME_REQUIRES_FULL_READBACK'),'exact original primitive and role');last_lock[0]=receipt['lock_parent']
  if product is not None:windows[(role,product['version'])]=(start,int(time.time()))
  return dict(returncode=r['returncode'],direct_child_reaped=r['direct_child_reaped'],group_retired=r['group_retired'],termination=r['termination'],descendants_reaped=r['descendants_reaped'],receipt=receipt,stdout=C.pin(r['stdout']),stderr=C.pin(r['stderr']))
 def fixtures(phase,versions,products):
  result={};inventory=dict(expected)
  for k,v in versions.items():
   if v is None:inventory.pop(G.NAMES[k])
   else:inventory[G.NAMES[k]]=v
  for role,version in versions.items():
   if version is None:continue
   stage_role='apps605'if role=='apps'and len(inventory)==605 else role;F=rooted_cli if stage_role=='apps605'else api[role]['rooted_fixture'];context=Path(target)/contexts[stage_role];records=[]
   for kind in(('fresh','existing')if role=='apps'else('root-guard','fresh','existing')):
    budget.tick();work=context/'outputs'/(phase+'-'+kind);work.mkdir(mode=0o700);ordinary=kind!='root-guard';uid=account.pw_uid if ordinary else 0;gid=account.pw_gid if ordinary else 0;os.chown(work,uid,gid);home=homes[stage_role][kind if ordinary else'fresh']
    env=dict(HOME=home,PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',XDG_CONFIG_HOME=home+'/.config',XDG_CACHE_HOME=home+'/.cache',XDG_DATA_HOME=home+'/.local/share',XDG_STATE_HOME=home+'/.local/state',XDG_RUNTIME_DIR=home+'/runtime',TMPDIR='/'+work.relative_to(target).as_posix())
    fixture_role=('apps6'if version=='0.1.0-6'else'apps7')if role=='apps'else('cachy-asahi-welcome'if version=='0.1.0-4'else'cachy-asahi-welcome5');spec=dict(root=str(target),script='/'+contexts[stage_role]+('/fixture_entry.py'if role=='apps'else'/fixture_checks.py'),work='/'+work.relative_to(target).as_posix(),role=fixture_role,kind='ordinary'if ordinary else'root-guard',uid=uid,gid=gid,environment=env,derived_fixture_sha256=stages[stage_role]['derived_fixture_sha256']);counter[0]+=1
    record=F.run(spec,spec_path=Path('/work/fixture-plans')/(str(counter[0])+'.json'),timeout=min(70,budget.deadline-time.monotonic()));r=record['receipt']
    if role=='apps':
     wanted_controls='NOT_RUN_ORIGINAL15_REQUIRES606_DOMAIN'if len(inventory)==605 else 15 if version=='0.1.0-7'else 0
     C.need(r['status']==('PASS_ACTUAL_APPS605_READONLY_CLI_ONLY'if len(inventory)==605 else'PASS_ACTUAL_INSTALLED_APPS_READONLY')and r['CLI']==2 and r['inventory_count']==len(inventory)and r['installed_controls']==wanted_controls,'actual Apps605 CLI or full606 CLI/Apps15')
     digest=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest();C.need(r['inventory_versions_sha256']==digest,'actual CLI exact joint606 inventory')
    elif not ordinary:C.need(r['status']=='PASS_ORIGINAL_ROOT_REFUSAL_ASSERTION','actual original Welcome root assertion')
    else:C.need(r['status']=='PASS_INSTALLED_WELCOME_DISPLAYLESS_AND_NATIVE_SCHEMA_FIXTURES'and r['version']==version and r['cli_controls']==5 and r['report_controls']==(8 if version=='0.1.0-4'else 12),'full actual Welcome5 CLI/schema assertions')
    for p in work.rglob('*'):
     C.need(p.is_dir()or p.is_file()and not p.is_symlink(),'ordinary fixture output shape')
     if p.is_file():output_pins[p]=C.pin(C.ordinary(p,16*1024**2))
    records.append(record)
   wanted=dict(CLI=2,inventory_count=len(inventory),installed_controls='NOT_RUN_ORIGINAL15_REQUIRES606_DOMAIN'if len(inventory)==605 else 15 if version=='0.1.0-7'else 0)if role=='apps'else dict(CLI=5,report=8 if version=='0.1.0-4'else 12)
   result[role]=dict(homes={h:wanted for h in('fresh','existing')},zero_capabilities=True,NNP=1,receipts=records)
  return result
 def source_unchanged():
  G.same_source(data['ordinary_observation'],worker.observe(C.SOURCE_ROOT,budget));return worker.caps.observe(C.SOURCE_ROOT,data['ordinary_observation']['nodes'],budget)==data['capabilities']
 result=lifecycle.exercise(expected=expected,plans=plans,apis=api,observe=observe,transact=transact,fixtures=fixtures,source_unchanged=source_unchanged);result.update(verification_keyring=keyring,protected_Runtime1=runtime_receipt,fixture_sources={k:{n:v for n,v in stage.items()if n in('original_fixture_sha256','derived_fixture_sha256','routing')}for k,stage in stages.items()});return result
