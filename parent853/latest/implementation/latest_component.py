# SPDX-License-Identifier: MIT
"""One six-tool native composition; full fresh graph on every fixed action."""
import base64,hashlib,json,os,pwd,stat,sys,time
from pathlib import Path
import latest_plan as P
import latest_graph_scope as G
import latest_record_capture as R
import latest_restoration as LR
import latest_domain as D
import latest_graph_timing as graph_timing
HERE=Path(__file__).resolve().parent

def selected_paths(products):
 result={}
 for role,name,old,new in P.PRODUCTS:
  rows=products[role];P.need(set(rows)==({'latest'}if old is None else{'original','latest'}),'complete fixed original/latest archive roles');files=set().union(*(set(r['payload'])for r in rows.values()));private=('usr/lib/'+name,'usr/share/'+name,'usr/share/doc/'+name,'usr/share/licenses/'+name);directories=set()
  for file in files:
   parent=file.rpartition('/')[0]
   while parent:
    if any(parent==prefix or parent.startswith(prefix+'/')for prefix in private):directories.add(parent)
    parent=parent.rpartition('/')[0]
  result[role]=dict(files=sorted(files),directories=sorted(directories))
 G.paths(result);return result

def physical_domain(graph):return P.physical_domain(graph)

def exercise(g,context):
 C=g['C'];need=C.need;home=context['home'];base=P.baseline(context['expected']);A=C.load('_latest_exact_boot_inputs',HERE.parent/'boot607/accepted_inputs.py');N=C.scoped_load('_latest_exact_native_contract',HERE.parent/'boot607/native_contract.py',{'accepted_inputs':A})
 C.scoped_load('_latest_existing_sixcap_signal_api',Path('/runner/real606/native_api.py'),{'native_contract':N});N.native_scope('/',home,'/out/latest607-native.log');need(g['inventory']()==base and P.inventory_bytes(base)==Path('/runner/expected606.lock').read_bytes(),'genuine complete606 before composition');context['preservation'](base)
 plan=C.read(Path('/tools606/latest/input-plan.json'));need(plan['status']=='READY_SIX_EXACT_TOOL_ARCHIVES_FRESH_ORIGINAL_TEST_SIGNATURES'and plan['scope']=='HISTORICAL_ACCEPTED_INPUTS_NO_COMBINED_CREDIT'and plan['signer_roles']==context['s']['original']['preparation']['signer_roles']and plan['nonce_authority']=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION','same nativeproducer freshTEST/source-ownednonce plan');need(all(plan[k]is None for k in('actual_source','actual_ref','actual_run')),'inputplan grants no newactualcredit')
 import apps8_inputs as A8,next_inputs as NEXT
 A8.validate_custody(plan['apps8_input']);NEXT.validate_custody(plan['next_inputs']);paths=selected_paths(plan['products']);raw=(HERE/'held/package_graph.py').read_bytes();capture_scope=G.bind(raw,paths);scopes={role:G.bind(raw,paths,role)for role,_,_,_ in P.PRODUCTS}
 account=pwd.getpwnam('alarm');homes=[];receipts={};events=[];aux=[];transactions={};setup_state=[];phase='baseline606';deadline=time.monotonic()+P.BOUNDS['component']
 timings=graph_timing.GraphTiming(g['OUT']/'latest607-graph-timing.json',plan['nonce'],deadline,lambda:phase)
 capture_scope.capture=timings.wrap(capture_scope.capture)
 def snapshot(root):
  out={}
  for p in(root,*sorted(root.rglob('*'))):
   s=p.lstat();need(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode)or stat.S_ISLNK(s.st_mode),'ordinary owned private user/report nodes');out[p.relative_to(root).as_posix()]=dict(identity=capture_scope.key(s),value=os.readlink(p)if stat.S_ISLNK(s.st_mode)else hashlib.sha256(p.read_bytes()).hexdigest()if stat.S_ISREG(s.st_mode)else None)
  return out
 for kind in('fresh','existing'):
  h=Path('/tmp')/('latest607-home-'+kind);h.mkdir(mode=0o700)
  if kind=='existing':
   (h/'.config').mkdir();(h/'.config/retained').write_text('preserve latest-tools user configuration\n');(h/'.config/alias').symlink_to('retained')
  for p in(h,*h.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
  homes.append((h,snapshot(h)))
 def users():
  for h,before in homes:need(snapshot(h)==before,'private original userhome changed')
  if setup_state:setup_state[0].users()
  for work,before in receipts.items():need(snapshot(work)==before,'previous private fixture/report nodes changed')
 def mark(operation):
  (g['OUT']/'latest607-progress.json').write_bytes(C.encoded(dict(status='LATEST607_PROGRESS_DATA_ONLY',phase=phase,operation=operation,nonce=plan['nonce'],acceptance='NOT_GRANTED')))
 def capture(want):
  mark('complete-fresh-native-graph');need(time.monotonic()<deadline and g['inventory']()==want,'layered4200 deadline and complete actualinventory');rows=context['driver'].database(Path('/'),max_packages=607);need({r['name']:r['version']for r in rows}==want,'complete independent fullrawDB inventory');users();return capture_scope.capture(Path('/'),rows,deadline=deadline)
 previous=capture(base);baseline=previous;physical=physical_domain(previous);before_records=R.capture('/',previous,N.ordinary);(g['OUT']/'latest607-selected-before.json').write_bytes(C.encoded(before_records));previous_ld,previous_aux=context['previous_ld'],context['previous_aux']
 def auxiliary(label):
  nonlocal previous_ld,previous_aux
  mark('complete-fresh-rawauxiliary');state=context['audio'].ld_state(context['adapter'],context['audio_rows']);data,_,_=context['audio'].ld_aux_read(state);transition=context['audio'].aux_order.compare(previous_aux,data);need(data==previous_aux and state==previous_ld,'whole original ldconfig/helper/config/alias/scan/target/cache/rawaux unchanged');raw=C.encoded(state);state_ref=dict(path='container/latest607-ld-baseline606.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());aux_ref=dict(path='container/latest607-aux-baseline606.bin',bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
  if label=='baseline606':(g['OUT']/'latest607-ld-baseline606.json').write_bytes(raw);(g['OUT']/'latest607-aux-baseline606.bin').write_bytes(data)
  else:need(state_ref==aux[0]['state_reference']and aux_ref==aux[0]['auxiliary_reference'],'full freshly observed bytes equal the explicitly shared retained blob')
  aux.append(dict(phase=label,source_owned_nonce=plan['nonce'],state_sha256=state_ref['sha256'],aux_sha256=aux_ref['sha256'],state_reference=state_ref,auxiliary_reference=aux_ref,retention='EXACT_EQUAL_BLOB_SHARED_AFTER_FRESH_COMPLETE_OBSERVATION',transition=transition,helper_exit='NOT_OBSERVED'));previous_ld,previous_aux=state,data
 auxiliary('baseline606')
 supervised=C.scoped_load('_latest_original_supervised',Path('/runner/boot607/copyworker/scripts/ci/current606-apps7-copy/supervised.py'),{'contract':N});B=C.load('_latest_original_boot79_command',Path('/runner/boot607/accepted-lifecycle.py'))
 import latest_setup
 setup_suites=latest_setup.Suites(g,context,N,supervised,deadline,plan['nonce'],capture_scope);setup_state.append(setup_suites)
 def installed(current,want):
  # All currently installed selected tools must match the exact immutable
  # original/latest archive payload, not only the acted-on package.
  for role,name,old,new in P.PRODUCTS:
   scope=scopes[role];version=want.get(name)
   if version is None:need(all(not os.path.lexists('/'+p)for p in scope.SELECTED_FILES|scope.SELECTED_DIRS),'removed selected payload/private directories remain');continue
   row=plan['products'][role]['original'if version==old else'latest'];db=[r for r in current['packages']if r['name']==name];meta=row['metadata']['.PKGINFO'];need(len(db)==1 and db[0]['version']==version and db[0]['arch']==meta['arch'][0]and set(db[0]['files'])==set(row['payload'])and db[0]['depend']==meta.get('depend',[])and db[0]['provides']==meta.get('provides',[])and db[0]['conflict']==meta.get('conflict',[]),'allselected complete actual ALPM metadata/source ownership')
   record=current['nodes']['var/lib/pacman/local/'+name+'-'+version];identity=record['identity'];need(record['kind']=='directory'and dict(mode=stat.S_IMODE(identity[2]),uid=identity[3],gid=identity[4],capability=record['capability'],children=record['children'])==LR.DIRECTORY,'complete selected raw DB directory mode/owner/capability/children')
   for p,expected in row['payload'].items():
    n=current['nodes'][p];i=n['identity'];need(n['kind']=='file'and i[3]==i[4]==0 and i[5]==1 and stat.S_IMODE(i[2])==expected['mode']and n['sha256']==expected['sha256']and n['capability']is None,'allselected exact installed source/license bytes/mode/owner/singlelink/capabilities')
   for directory in scope.SELECTED_DIRS:
    children=sorted({p[len(directory)+1:].split('/')[0]for p in row['payload']if p.startswith(directory+'/')})
    if not children:need(not os.path.lexists('/'+directory),'obsolete selected private directory remains');continue
    node=current['nodes'][directory];identity=node['identity'];need(node['kind']=='directory'and identity[3]==identity[4]==0 and stat.S_IMODE(identity[2])==0o755 and node['capability']is None and node['children']==children,'exact complete selected private-directory children/modes/ownership/capability')
   context['I'].payloads(context['L'],{name:row})
   absent=scope.SELECTED_FILES-set(row['payload']);need(all(not os.path.lexists('/'+p)for p in absent),'obsolete original/latest selected payload remains')
 def step(e):
  nonlocal previous,phase
  phase=e['phase'];role=e['role'];name=e['name'];want=e['after'];need({r['name']:r['version']for r in previous['packages']}==e['before'],'exact preceding fullinventory')
  operand=None
  if e['archive_role']is not None:
   row=plan['products'][role][e['archive_role']];archive=Path('/tools606/latest/archives')/row['archive'];signature=archive.with_name(archive.name+'.sig');need(N.pin(N.ordinary(archive))=={k:row[k]for k in('bytes','sha256')}and N.pin(N.ordinary(signature,65536))=={k:row['signature'][k]for k in('bytes','sha256')}and row['signer']==plan['signer_roles']['ephemeral_TEST'],'whole exact fresh signed original/latest archive');g['verify_signature'](['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'],archive,signature,row['signer']);operand=dict(path=str(archive),**{k:row[k]for k in('bytes','sha256')},signature=dict(path=str(signature),**{k:row['signature'][k]for k in('bytes','sha256')}),signer=row['signer'],version=e['version'])
  mark('isolated-original-signed-noexec-transaction');value=dict(role=role,root='/',before=e['before'],after=want,archive=operand,keys=str(home),log='/out/latest607-alpm.log');path=g['OUT']/('latest607-step-'+phase+'.json');need(not path.exists(),'fresh transactionplan');path.write_bytes(C.encoded(value));path.chmod(0o644)  # Explicit public transaction DATA; trust/fixture outputs remain private.
  result=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'step_entry.py'),str(path)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(90,max(0.001,deadline-time.monotonic())),output_limit=128*1024,grace=1);need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']is True and result['group_retired']is True,'original signed transaction/group retirement');transaction=N.decode(result['stdout']);need(transaction['status']=='COMMITTED_SELECTED_LATEST_TOOL_REQUIRES_FULL_NATIVE_READBACK'and transaction['role']==role and transaction['product']==name,'exact selected transactionreceipt');current=capture(want);proof=G.protected(scopes[role],previous,current,transaction['lock_parent']);previous=current;need({r['name']:r for r in current['packages']if r['name']in physical}==physical,'originalother601 complete DB rows physically protected');installed(current,want)
  if e['action']=='restore-original'and e['version']is not None:transactions[role]=transaction['transaction_clock']
  observations=[]
  if name in want:
   for h,_ in homes:
    mark('ordinary-installed-private-fixture-'+role);work=Path('/tmp')/('latest607-'+h.name+'-'+phase);work.mkdir(mode=0o700);(work/'plan.json').write_bytes(C.encoded(dict(inventory=want,phase=phase)));(work/'plan.json').chmod(0o400)
    for p in(work,*work.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid,follow_symlinks=False)
    B.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','HOME='+str(h),'TMPDIR='+str(work),'/usr/bin/python3','-I','-B',str(HERE/'latest_fixture.py'),str(work),role],timeout=min(100,max(0.001,deadline-time.monotonic())));observed=json.loads((work/'receipt.json').read_bytes());need(observed['status']=='PASS_ACTUAL_LATEST_TOOL_PRIVATE_FIXTURE'and(observed['role'],observed['version'],observed['phase'],observed['home'])==(role,want[name],phase,h.name)and observed['inventory_sha256']==hashlib.sha256(P.inventory_bytes(want)).hexdigest(),'exact ordinary installedfixture result');receipts[work]=snapshot(work);observations.append(observed)
  real_modules=setup_suites.run(phase)if phase in P.REAL_PHASES else None
  users();after_fixture=capture(want);need(after_fixture==current,'installed fixture changed complete package/rawDB/user/config graph');auxiliary(phase);g['run'](context['pacman']+['-Dk']);deps=sorted({d for r in current['packages']for d in r['depend']});g['run'](context['pacman']+['-T',*deps]);events.append(dict(real_modules=real_modules,phase=phase,role=role,count=len(want),unaffected_count=e['unaffected_count'],all_nonacted=proof,other601_physical_preservation=True,selected_five_inode_restoration='NOT_CLAIMED',signature='REQUIRED_ORIGINAL_EPHEMERAL_TEST',transaction=transaction,transaction_process=dict(**{k:v for k,v in result.items()if k not in('stdout','stderr')},stdout=N.pin(result['stdout']),stderr=N.pin(result['stderr'])),observations=observations,graph_sha256=hashlib.sha256(C.encoded(current)).hexdigest(),fixture_graph_unchanged=True,user_config_preserved=True,prior_reports_preserved=True))
 for event in P.transitions(base):step(event)
 after_records=R.capture('/',previous,N.ordinary);restoration=D.bind_restoration(before_records,after_records,transactions);(g['OUT']/'latest607-selected-after.json').write_bytes(C.encoded(after_records));context['preservation'](base);mark('restored606-before-original-native-continuation');result=dict(status='PASS_NATIVE607_LATEST_SIX_TOOL_COMPONENT_REQUIRES_FULL_REPLAY',scope=previous['scope'],source_owned_nonce=plan['nonce'],nonce_authority=plan['nonce_authority'],base_count=606,peak_count=607,restored_count=606,events=events,ldconfig=aux,apps8_input=plan['apps8_input'],next_inputs=plan['next_inputs'],setup_real_modules=setup_suites.summary(),baseline_graph_sha256=hashlib.sha256(C.encoded(baseline)).hexdigest(),other601_physical_preservation=dict(original604_unselected=599,original606_additions=2,total=601,domain='COMPLETE_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPABILITY_WITH_PROVEN_SELECTED_PARENT_TRANSITIONS'),selected_five_logical_restoration=restoration,selected_five_inode_restoration='NOT_CLAIMED',new_tool_builds='NOT_RUN_ACCEPTED_NATIVE_ARCHIVES_REUSED',hardware='NOT_RUN',GUI='NOT_RUN',live_audio='NOT_RUN',live_KSM='NOT_RUN',real_journal='NOT_READ',live_pstore='NOT_READ',performance='NOT_CLAIMED',release='NOT_ADMITTED');(g['OUT']/'latest607.json').write_bytes(C.encoded(result));context['s']['report']['latest607']=result;return previous_ld,previous_aux
