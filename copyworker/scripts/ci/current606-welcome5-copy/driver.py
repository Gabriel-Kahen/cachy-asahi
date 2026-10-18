# SPDX-License-Identifier: MIT
"""Concrete copied-root readback, finite signed steps and original rooted fixtures."""
import importlib.util,os,pwd,time
from pathlib import Path
import contract as C,guard as G,lifecycle,physical,rooted_fixture as F,supervised
ROOT=Path(__file__).resolve().parents[3];CONTEXT=F.CONTEXT.lstrip('/')

def database_api():
 p=ROOT/'held-copy/scripts/ci/full-root-upgrade/root_upgrade.py';s=importlib.util.spec_from_file_location('_welcome606_complete_db',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def without_context(value):
 """Only the fresh, source-owned fixture context is outside target preservation."""
 import copy
 result=copy.deepcopy(value);nodes=result['nodes'];private={n:r for n,r in nodes.items()if n==CONTEXT or n.startswith(CONTEXT+'/')}
 C.need(len(private)<=512 and sum(r.get('bytes',0)for r in private.values())<=32*1024**2,'rooted fixture private node/byte bounds')
 result['nodes']={n:r for n,r in nodes.items()if n not in private}
 for group in result.get('hardlink_groups',{}).values():C.need(not any(n in private for n in group['members']),'rooted fixture external hardlinks refused')
 return result

def selected_database(root,rows,nodes,product,*,window):
 db=database_api();version=product['version'];name='var/lib/pacman/local/cachy-asahi-welcome-'+version
 selected=[r for r in rows if r['name']==lifecycle.NAME];C.need(len(selected)==1 and selected[0]['version']==version and set(selected[0]['files'])==set(product['payload']),'complete selected current ownership/version')
 C.need(nodes.get(name)==dict(type='directory',mode=0o755,uid=0,gid=0),'selected DB directory metadata')
 actual={n for n in nodes if n.startswith(name+'/')};C.need(actual=={name+'/desc',name+'/files',name+'/mtree'},'exact selected current DB record closure')
 for entry in actual:
  C.need(nodes[entry]['type']=='file'and nodes[entry]['mode']==0o644 and nodes[entry]['uid']==nodes[entry]['gid']==0,'selected DB regular record mode/owner')
 with db.directory(root,name)as fd:fields=db.fields(db.read_record(fd,'desc',expected=nodes[name+'/desc']))
 validate_fields(fields,product.get('database_fields'),window)
 mtree=C.ordinary(Path(root)/name/'mtree',16*1024**2);C.need(C.pin(mtree)==product.get('mtree'),'complete selected raw mtree must match exact original/candidate archive')
 return True

def validate_fields(fields,wanted,window):
 C.need(type(wanted)is dict and set(fields)==set(wanted)and 'INSTALLDATE'in fields,'all selected DB fields must be archive-derived and declared')
 C.need(all(fields[k]==v for k,v in wanted.items()if k!='INSTALLDATE'),'selected current DB metadata differs from exact archive')
 if window is None:C.need(fields['INSTALLDATE']==wanted['INSTALLDATE'],'initial selected source DB installation date')
 else:
  C.need(len(fields['INSTALLDATE'])==1 and fields['INSTALLDATE'][0].isdigit()and window[0]<=int(fields['INSTALLDATE'][0])<=window[1],'normal transaction INSTALLDATE outside actual commit window')
 return True

def run(target,*,data,plan,budget,worker):
 C.need(Path(target)==Path('/work/main/root')and type(plan)is dict and set(plan)=={'original4','new5','original604_manifest','fixture_policy','fixture_products','verification_keys'},'finite copied-root lifecycle inputs')
 import plan as plan_api
 db=database_api();name='var/lib/pacman/local/cachy-asahi-welcome-0.1.0-4'
 with db.directory(C.SOURCE_ROOT,name)as fd:source_fields=db.fields(db.read_record(fd,'desc',expected=data['ordinary_observation']['nodes'][name+'/desc']))
 plan=plan_api.complete(plan,source_fields)
 products=lifecycle.operands(plan['original4'],plan['new5'],original604_manifest=plan['original604_manifest']);expected=G.package_inventory(data['packages']);G.inventory(expected,expected)
 C.need(plan['fixture_products']['cachy-asahi-welcome']==products['0.1.0-4']and plan['fixture_products']['cachy-asahi-welcome5']==products['0.1.0-5'],'fixtures use original4, never a newly built4 substitute')
 seed=worker.observe(target,budget);C.need(CONTEXT not in seed['nodes'],'fixture context absent in complete original606 graph')
 for directory in C.WELCOME_DIRS:
  actual={n for n in seed['nodes']if n.startswith(directory+'/')};wanted={n for n in C.WELCOME_FILES if n.startswith(directory+'/')};C.need(actual==wanted,'no unowned/foreign descendants in selected exclusive directory')
 for package in data['packages']:
  if package['name']==lifecycle.NAME:continue
  name='var/lib/pacman/local/'+package['name']+'-'+package['version'];db=database_api()
  with db.directory(target,name)as fd:owned=db.fields(db.read_record(fd,'files',expected=seed['nodes'][name+'/files'])).get('FILES',[])
  C.need(not any(d+'/'in owned or d in owned for d in C.WELCOME_DIRS),'another605 package owns selected directory')
 import verification
 keyring=verification.prepare(plan['verification_keys'],signers={products[v]['signer']for v in products},budget=budget)
 stage=F.stage(target,plan['fixture_policy'],plan['fixture_products'],Path('/runner/inputs/sources'))
 account=pwd.getpwnam('alarm');C.need(account.pw_uid>0 and account.pw_gid>0,'same original574 ordinary account')
 context=Path(target)/CONTEXT;homes={};preserved={};home_graph={};output_pins={};windows={};current_version='0.1.0-4';counter=[0];last_lock=[None]
 for kind in('fresh','existing'):
  home=context/'homes'/kind;home.mkdir(mode=0o700)
  if kind=='existing':
   for relative in('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
    f=home/relative;f.parent.mkdir(parents=True,exist_ok=True);f.write_text('preserve '+relative+'\n');f.chmod(0o600)
   (home/'.config/alias').symlink_to('cachy-asahi/preferences')
  runtime=home/'runtime';runtime.mkdir(mode=0o700)
  for f in(home,*home.rglob('*')):os.chown(f,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes[kind]='/'+home.relative_to(target).as_posix()
  for f in home.rglob('*'):
   if f.is_file()and not f.is_symlink():preserved[f]=C.pin(C.ordinary(f))
 for name in('fixture-plans','transaction-plans'):
  p=Path('/work')/name;C.need(not p.exists(),'fresh worker plan directory');p.mkdir(mode=0o700)
 def observe():
  budget.tick();full=worker.observe(target,budget)
  for p,row in output_pins.items():C.need(C.pin(C.ordinary(p,16*1024**2))==row,'earlier rooted fixture output changed')
  for name,row in stage['files'].items():C.need(C.pin(C.ordinary(context/name,1024**2))==row,'source-owned fixture input changed')
  for p,row in preserved.items():C.need(C.pin(C.ordinary(p))==row,'private existing ordinary home changed')
  rows=database_api().database(target,max_packages=606,max_files=budget.max_package_files,max_nodes=budget.max_nodes,observed=full['nodes']);inventory={r['name']:r['version']for r in rows}
  capmap=worker.caps.observe(target,full['nodes'],budget);observed=without_context(full);ids=physical.capture(target,full['nodes'],budget)
  for kind,home in homes.items():
   prefix=home.lstrip('/');values={n:dict(node=r,identity=ids[n])for n,r in full['nodes'].items()if n==prefix or n.startswith(prefix+'/')}
   if kind not in home_graph:home_graph[kind]=values
   else:C.need(values==home_graph[kind],'complete fresh/existing private home graph/inodes changed')
  ids={n:r for n,r in ids.items()if n!=CONTEXT and not n.startswith(CONTEXT+'/')}
  valid=current_version is None or selected_database(target,rows,full['nodes'],products[current_version],window=windows.get(current_version))
  return dict(observation=observed,inventory=inventory,physical=ids,capabilities=capmap,selected_database_validated=valid,lock_parent=last_lock[0])
 def transact(phase,before,product):
  nonlocal current_version
  budget.tick();after=dict(before)
  if product is None:after.pop(lifecycle.NAME)
  else:after[lifecycle.NAME]=product['version']
  archive=None if product is None else{k:product[k]for k in('path','bytes','sha256','signature','signer','version')}
  spec=dict(root=str(target),before=before,after=after,archive=archive,keys='/work/test-verification',log='/out/'+phase+'-alpm.log');counter[0]+=1;p=Path('/work/transaction-plans')/(str(counter[0])+'.json')
  with p.open('xb')as out:out.write(C.encoded(spec))
  p.chmod(0o600);start=int(time.time());result=supervised.run([os.sys.executable,'-I','-B',str(Path(__file__).with_name('step_entry.py')),str(p)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},cwd='/',timeout=min(90,budget.deadline-time.monotonic()),output_limit=128*1024,grace=1)
  C.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired'],'signed transaction child failed or group not retired')
  receipt=C.decode(result['stdout']);C.need(receipt['status']=='COMMITTED_SELECTED_WELCOME_REQUIRES_FULL_READBACK','signed transaction typed receipt');last_lock[0]=receipt['lock_parent']
  current_version=None if product is None else product['version']
  if current_version is not None:windows[current_version]=(start,int(time.time()))
  return dict(returncode=result['returncode'],direct_child_reaped=result['direct_child_reaped'],group_retired=result['group_retired'],termination=result['termination'],descendants_reaped=result['descendants_reaped'],receipt=receipt,stdout=C.pin(result['stdout']),stderr=C.pin(result['stderr']))
 def fixtures(phase,version,product):
  role='cachy-asahi-welcome'if version=='0.1.0-4'else'cachy-asahi-welcome5';observations=[]
  for kind in('root-guard','fresh','existing'):
   budget.tick();work=context/'outputs'/(phase+'-'+kind);work.mkdir(mode=0o700);ordinary=kind!='root-guard';uid=account.pw_uid if ordinary else 0;gid=account.pw_gid if ordinary else 0;os.chown(work,uid,gid)
   home=homes[kind]if ordinary else F.CONTEXT+'/homes/fresh';env=dict(HOME=home,PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',XDG_CONFIG_HOME=home+'/.config',XDG_CACHE_HOME=home+'/.cache',XDG_DATA_HOME=home+'/.local/share',XDG_STATE_HOME=home+'/.local/state',XDG_RUNTIME_DIR=home+'/runtime',TMPDIR='/'+work.relative_to(target).as_posix())
   spec=dict(root=str(target),script=F.CONTEXT+'/fixture_checks.py',work='/'+work.relative_to(target).as_posix(),role=role,kind='ordinary'if ordinary else'root-guard',uid=uid,gid=gid,environment=env,derived_fixture_sha256=stage['derived_fixture_sha256']);counter[0]+=1
   result=F.run(spec,spec_path=Path('/work/fixture-plans')/(str(counter[0])+'.json'),timeout=min(70,budget.deadline-time.monotonic()));receipt=result['receipt'];C.need(receipt['status']==('PASS_INSTALLED_WELCOME_DISPLAYLESS_AND_NATIVE_SCHEMA_FIXTURES'if ordinary else'PASS_ORIGINAL_ROOT_REFUSAL_ASSERTION'),'exact real fixture assertion result')
   if ordinary:C.need(receipt['cli_controls']==5 and receipt['report_controls']==(8 if version=='0.1.0-4'else 12)and receipt['program_sha256']==product['payload']['usr/bin/cachy-asahi-welcome']['sha256'],'real source-pinned fixture control totals')
   for path in work.rglob('*'):
    C.need(path.is_dir()or path.is_file()and not path.is_symlink(),'ordinary fixture output shape')
    if path.is_file():output_pins[path]=C.pin(C.ordinary(path,16*1024**2))
   observations.append(result)
  return dict(root_guard='PASS',homes={k:dict(CLI=5,report=8 if version=='0.1.0-4'else 12)for k in('fresh','existing')},zero_capabilities=True,NNP=1,receipts=observations)
 def source_unchanged():
  G.same_source(data['ordinary_observation'],worker.observe(C.SOURCE_ROOT,budget));return worker.caps.observe(C.SOURCE_ROOT,data['ordinary_observation']['nodes'],budget)==data['capabilities']
 result=lifecycle.exercise(expected=expected,original4=products['0.1.0-4'],new5=products['0.1.0-5'],original604_manifest=plan['original604_manifest'],observe=observe,transact=transact,fixtures=fixtures,source_unchanged=source_unchanged)
 result['verification_keyring']=keyring
 result['fixture_derivative']={k:stage[k]for k in('original_fixture_sha256','derived_fixture_sha256','routing')};return result
