# SPDX-License-Identifier: MIT
"""Real Setup240 bodies on full606, with fifteen fresh native preservation graphs."""
import base64,hashlib,json,os,pwd,stat,sys,time
from pathlib import Path
import latest_plan as P,latest_graph_scope as G,latest_restoration as R,latest_record_capture as RECORD
from native_api import C as N
HERE=Path(__file__).resolve().parent

def ordinary_absent(uid):
 entries=list(Path('/proc').iterdir());P.need(len(entries)<=512,'bounded actual process namespace')
 for p in entries:
  if not p.name.isdigit():continue
  try:raw=(p/'status').read_text()
  except FileNotFoundError:continue
  fields=[line.split()[1:]for line in raw.splitlines()if line.startswith('Uid:')];P.need(len(fields)==1 and len(fields[0])==4 and str(uid)not in fields[0],'ordinary fixture process remains')

def selected_paths(products):
 files=set(products['original1']['payload'])|set(products['new2']['payload']);dirs={'usr/share/doc/cachy-asahi-setup','usr/share/licenses/cachy-asahi-setup'}
 P.need(files=={'usr/bin/cachy-asahi-setup','usr/bin/cachy-asahi-repository',*(d+'/'+n for d,n in [('usr/share/doc/cachy-asahi-setup','README.md'),('usr/share/doc/cachy-asahi-setup','repository-enrollment.md'),('usr/share/licenses/cachy-asahi-setup','LICENSE'),('usr/share/licenses/cachy-asahi-setup','NOTICE')])},'fixed six selected Setup source/license paths')
 return {'setup':dict(files=sorted(files),directories=sorted(dirs))}

def exercise(g,context):
 C=g['C'];base=P.baseline(context['expected']);keys=context['home'];N.native_scope('/',keys,'/out/setup6-native.log');context['preservation'](base)
 plan=C.read(Path('/tools606/setup6/native-plan.json'));P.need(plan['purpose']=='FULL606_SETUP6_REAL_MODULES_NATIVE_CORRECTNESS'and plan['nonce_authority']=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION'and all(plan[k]is None for k in('actual_source','actual_ref','actual_run')),'source-owned exact native plan only');nonce=plan['nonce'];products=plan['products'];P.need(products['original1']['signer']==products['new2']['signer']==context['s']['original']['preparation']['signer_roles']['ephemeral_TEST'],'same original ephemeral TEST signer')
 P.need(products['original1']['sha256']=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'and products['new2']['sha256']=='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8','exact accepted old/new Setup archive bodies');scope=G.bind((HERE/'held/package_graph.py').read_bytes(),selected_paths(products),'setup');deadline=time.monotonic()+P.BOUNDS['component'];phase='baseline5';graphs=[];events=[];retained={};transactions={}
 account=pwd.getpwnam('alarm');P.need(account.pw_uid>0,'same ordinary account');source=Path('/runner/setup240');SC=C.load('_whole_original_setup240_contract',source/'scripts/ci/setup6-real-modules/contract.py');SC.verify_source(source);H=C.load('_whole_original_setup_homes',source/'scripts/ci/setup5-real-modules/run.py');LC=C.scoped_load('_whole_original_setup_registry',source/'scripts/ci/setup6-real-modules/lifecycle.py',{'contract':SC})
 P.need({n:v for n,v in SC.VERSIONS.items()if n!=P.NAME}=={n:base[n]for n in SC.VERSIONS if n!=P.NAME},'all six exact installed module package versions')
 supervised=C.scoped_load('_whole_original_setup_supervisor',Path('/runner/copyworker/scripts/ci/current606-doctor2-copy/supervised.py'),{'contract':N})
 previous_ld,previous_aux=context['previous_ld'],context['previous_aux'];aux=[];clock=None
 def progress(operation):
  (g['OUT']/'setup6-progress.json').write_bytes(C.encoded(dict(status='SETUP6_NATIVE_PROGRESS_DATA_ONLY',phase=phase,operation=operation,nonce=nonce,acceptance=False)))
 def registry(parent,report):
  accepted=LC.workspace_snapshot(parent,report,context['L'],H);identities={}
  for relative in accepted:
   p=parent/relative;s=p.lstat();identities[relative]=dict(identity=scope.key(s),capability=os.getxattr(p,'security.capability',follow_symlinks=False).hex()if'security.capability'in os.listxattr(p,follow_symlinks=False)else None)
  return dict(accepted=accepted,identities=identities)
 def users():
  ordinary_absent(account.pw_uid)
  for parent,(report,before)in retained.items():P.need(registry(parent,report)==before,'every prior fifteen-home source-owned registry/identity preserved')
 def capture(want):
  progress('complete-fresh-package-rawDB-ancestry-config-user-graph');P.need(time.monotonic()<deadline and g['inventory']()==want,'component3000 deadline/exact606 or605 inventory');users();packages=context['driver'].database(Path('/'),max_packages=606);P.need({r['name']:r['version']for r in packages}==want,'whole independent ALPM database');started=time.monotonic();row=dict(sequence=len(graphs),phase=phase,state='BEGIN',started=started);graphs.append(row)
  try:
   value=scope.capture(Path('/'),packages,deadline=deadline);row.update(state='COMPLETE',nodes=len(value['nodes']),bytes_read=value['bytes_read'],graph_sha256=hashlib.sha256(C.encoded(value)).hexdigest());return value
  except BaseException:row['state']='FAILED';raise
  finally:
   row['seconds']=time.monotonic()-started;P.need(len(graphs)<=15,'fixed fifteen fresh graphs');(g['OUT']/'setup6-graph-timing.json').write_bytes(C.encoded(dict(profile='FULL606_SETUP6_REAL_MODULES_GRAPH_DATA_V1',nonce=nonce,component_seconds=3000,consumer_seconds=4800,owner_seconds=9600,observations=graphs,actual_authority=False)))
 def installed(graph,want,window=None):
  version=want.get(P.NAME)
  if version is None:P.need(all(not os.path.lexists('/'+p)for p in scope.SELECTED_FILES|scope.SELECTED_DIRS),'selected removal complete');return
  product=products['original1'if version=='0.1.0-5'else'new2'];actual=[r for r in graph['packages']if r['name']==P.NAME];meta=product['pkginfo'];P.need(len(actual)==1 and actual[0]['version']==version and actual[0]['arch']==meta['arch'][0]and set(actual[0]['files'])==set(product['payload'])and actual[0]['depend']==meta.get('depend',[])and actual[0]['provides']==meta.get('provides',[])and actual[0]['conflict']==meta.get('conflict',[]),'complete selected ALPM identity/ownership/dependencies')
  for name,expected in product['payload'].items():
   node=graph['nodes'][name];identity=node['identity'];P.need(node['kind']=='file'and identity[3]==identity[4]==0 and identity[5]==1 and stat.S_IMODE(identity[2])==expected['mode']and node['sha256']==expected['sha256']and node['capability']is None,'whole installed selected source/license bytes/owner/mode/singlelink/caps')
  record='var/lib/pacman/local/'+P.NAME+'-'+version;dbdir=graph['nodes'][record];P.need(dbdir['kind']=='directory'and dict(mode=stat.S_IMODE(dbdir['identity'][2]),uid=dbdir['identity'][3],gid=dbdir['identity'][4],capability=dbdir['capability'],children=dbdir['children'])==R.DIRECTORY,'whole selected DB directory shape')
  for leaf in('desc','files','mtree'):
   node=graph['nodes'][record+'/'+leaf];i=node['identity'];P.need(node['kind']=='file'and i[3]==i[4]==0 and i[5]==1 and stat.S_IMODE(i[2])==0o644 and node['capability']is None,'selected DB leaf metadata')
  P.need(N.pin(N.ordinary(Path('/')/record/'mtree'))==product['mtree'],'full raw selected archive mtree');fields=context['driver'].fields(N.ordinary(Path('/')/record/'desc'));wanted=product['database_fields'];P.need(set(fields)==set(wanted)and all(fields[k]==v for k,v in wanted.items()if k!='INSTALLDATE'),'all selected DB fields match exact archive/source schema')
  if window is None:P.need(fields['INSTALLDATE']==wanted['INSTALLDATE'],'original selected initial installation date')
  else:P.need(len(fields['INSTALLDATE'])==1 and fields['INSTALLDATE'][0].isdigit()and window['start_seconds']<=int(fields['INSTALLDATE'][0])<=window['end_seconds'],'selected installation date actual transaction')
 def auxiliary():
  nonlocal previous_ld,previous_aux
  progress('complete-fresh-raw-auxiliary');state=context['audio'].ld_state(context['adapter'],context['audio_rows']);data,_,_=context['audio'].ld_aux_read(state);transition=context['audio'].aux_order.compare(previous_aux,data);P.need(state==previous_ld and data==previous_aux,'full original helper/config/alias/scan/cache/rawaux unchanged');raw=C.encoded(state)
  if not aux:(g['OUT']/'setup6-ld-baseline5.json').write_bytes(raw);(g['OUT']/'setup6-aux-baseline5.bin').write_bytes(data)
  aux.append(dict(phase=phase,nonce=nonce,state=N.pin(raw),auxiliary=N.pin(data),state_path='container/setup6-ld-baseline5.json',auxiliary_path='container/setup6-aux-baseline5.bin',transition=transition,freshness='COMPLETE_FRESH_OBSERVATION_EQUAL_BLOB_SHARED',helper_exit='NOT_OBSERVED'));previous_ld,previous_aux=state,data
 baseline=capture(base);previous=baseline;physical={r['name']:r for r in baseline['packages']if r['name']!=P.NAME};P.need(len(physical)==605,'exact other605 physical domain');record='var/lib/pacman/local/'+P.NAME+'-0.1.0-5';source_fields=context['driver'].fields(N.ordinary(Path('/')/record/'desc'));plan_api=C.scoped_load('_whole_setup_archive_DB_fields',Path('/runner/copyworker/scripts/ci/current606-doctor2-copy/plan.py'),{'contract':N})
 for product in products.values():product['database_fields']=plan_api.fields(product['pkginfo'],source_fields)
 P.need(products['original1']['database_fields']==source_fields,'whole original Setup5 DB/archive calibration');installed(baseline,base);before_records=RECORD.capture('/',baseline,N.ordinary);(g['OUT']/'setup6-selected-before.json').write_bytes(C.encoded(before_records));auxiliary()
 for event in P.transitions(base):
  phase=event['phase'];want=event['after'];P.need({r['name']:r['version']for r in previous['packages']}==event['before'],'exact prior fullinventory');product=None if event['archive_role']is None else products[event['archive_role']];operand=None
  if product:
   archive=Path(product['path']);sig=product['signature'];P.need(archive.parent==Path('/tools606/setup6/archives')and N.pin(N.ordinary(archive))=={k:product[k]for k in('bytes','sha256')}and N.pin(N.ordinary(Path(sig['path']),65536))=={k:sig[k]for k in('bytes','sha256')},'whole exact freshly signed operand');g['verify_signature'](['gpg','--batch','--no-options','--homedir',str(keys),'--no-auto-key-retrieve'],archive,Path(sig['path']),product['signer']);operand={k:product[k]for k in('path','bytes','sha256','signature','signer','version')}
  progress('signed-noexec-transaction');value=dict(root='/',before=event['before'],after=want,archive=operand,keys=str(keys),log='/out/setup6-native.log');path=g['OUT']/('setup6-step-'+phase+'.json');P.need(not path.exists(),'fresh native transaction operands');path.write_bytes(C.encoded(value));path.chmod(0o644)
  result=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'step_entry.py'),str(path)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(90,max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1);P.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired'],'real signed transaction and group retirement');transaction=N.decode(result['stdout']);P.need(transaction['status']=='COMMITTED_NATIVE_SETUP6_REQUIRES_FULL_READBACK','typed signed native transaction');clock=transaction['transaction_clock'];R.interval(clock);current=capture(want);proof=G.protected(scope,previous,current,transaction['lock_parent']);P.need({r['name']:r for r in current['packages']if r['name']in physical}==physical,'all other605 complete ALPM rows');installed(current,want,clock);real=None
  if event['version']=='0.1.0-6':
   progress('whole-actual-setup240-real-modules');parent=Path('/tmp')/('setup6-real-'+phase);P.need(not parent.exists(),'fresh owned real-module workspace');parent.mkdir(mode=0o700);os.chown(parent,account.pw_uid,account.pw_gid);ordinary_absent(account.pw_uid)
   observed=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'ordinary_entry.py'),str(keys),str(parent)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(240,max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1,signal_uid=account.pw_uid);P.need(observed['returncode']==0 and observed['termination']is None and observed['direct_child_reaped']and observed['group_retired'],'whole original240 fixture and owned group retirement');ordinary_absent(account.pw_uid);real=N.decode(observed['stdout']);SC.validate_real(real);P.need(C.read(parent/'work/receipt.json')==real,'whole actual fixture file/stdout join');retained[parent]=(real,registry(parent,real));(g['OUT']/('setup6-real-'+phase+'.json')).write_bytes(C.encoded(real))
  users();after_fixture=capture(want);P.need(after_fixture==current,'real modules changed complete package/rawDB/user/config graph');installed(after_fixture,want,clock);auxiliary();g['run'](context['pacman']+['-Dk']);deps=sorted({d for r in current['packages']for d in r['depend']});g['run'](context['pacman']+['-T',*deps]);events.append(dict(phase=phase,count=len(want),version=event['version'],other605_physical_preservation=proof,transaction=transaction,process={k:v for k,v in result.items()if k not in('stdout','stderr')},stdout=N.pin(result['stdout']),stderr=N.pin(result['stderr']),real_modules=real,private_registries_preserved=True,fixture_graph_unchanged=True));previous=after_fixture
  if phase=='restore-original5':transactions['setup']=clock
 after_records=RECORD.capture('/',previous,N.ordinary);restoration=R.records(before_records,after_records,transactions);(g['OUT']/'setup6-selected-after.json').write_bytes(C.encoded(after_records));context['preservation'](base);P.need(len(graphs)==15 and len(retained)==4 and len(events)==7,'all captures/real suites/transactions mandatory');result=dict(status='PASS_NATIVE_FULL606_SETUP6_REAL_MODULES_REQUIRES_REPLAY',nonce=nonce,base_count=606,counts=[606,606,606,606,606,605,606,606],events=events,graphs=graphs,ldconfig=aux,selected_logical_restoration=restoration,selected_inode_restoration='NOT_CLAIMED',other605_physical_preservation=True,real_modules_suites=4,Apps7_coexistence='NOT_RUN_BASELINE_APPS6',notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',audio='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',performance='NOT_CLAIMED');(g['OUT']/'setup6-full606.json').write_bytes(C.encoded(result));context['s']['report']['setup6_full606']=result;return previous_ld,previous_aux

_complete_source_owned_exercise=exercise
def exercise(g,context):
 try:return _complete_source_owned_exercise(g,context)
 except BaseException as error:
  try:
   progress=g['C'].read(g['OUT']/'setup6-progress.json');value=dict(status='SETUP6_NATIVE_FAILURE_DATA_NOT_ACCEPTANCE',phase=progress['phase'],operation=progress['operation'],nonce=progress['nonce'],error_type=type(error).__name__,error=str(error)[:1024],acceptance=False);(g['OUT']/'setup6-error.json').write_bytes(g['C'].encoded(value))
  except Exception:pass
  raise
