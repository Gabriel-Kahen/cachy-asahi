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
 out={}
 for role,name,_,_ in P.PRODUCTS:
  files=set(products[role]['original']['payload'])|set(products[role]['new']['payload']);dirs={n.rpartition('/')[0]for n in files if n.startswith(('usr/share/doc/','usr/share/licenses/','usr/lib/'))}
  P.need(files and len(files)==(8 if role=='apps'else 6),'exact source-bound selected payload count');out[role]=dict(files=sorted(files),directories=sorted(dirs))
 return out

def exercise(g,context):
 C=g['C'];base=P.baseline(context['expected']);keys=context['home'];N.native_scope('/',keys,'/out/setup6-native.log');context['preservation'](base)
 plan=C.read(Path('/tools606/setup6/native-plan.json'));P.need(plan['purpose']=='FULL606_APPS7_SETUP6_COEXISTENCE_NATIVE_CORRECTNESS'and plan['nonce_authority']=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION'and all(plan[k]is None for k in('actual_source','actual_ref','actual_run')),'source-owned exact native plan only');nonce=plan['nonce'];products=plan['products'];P.need(all(p['signer']==context['s']['original']['preparation']['signer_roles']['ephemeral_TEST']for pair in products.values()for p in pair.values()),'same original ephemeral TEST signer for all four operands')
 P.need(products['setup']['original']['sha256']=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'and products['setup']['new']['sha256']=='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8'and products['apps']['original']['sha256']=='1ce4a540a5ec2fa26353847b93fed953e084cf65e872836f670ac721446cd3d7'and products['apps']['new']['sha256']=='23fc2fe5707606b0f3bd8c6322b9e7ae0c47a6ff1024cd239f4486679638be39','all four exact archive identities');paths=selected_paths(products);scope=G.bind((HERE/'held/package_graph.py').read_bytes(),paths);scopes={role:G.bind((HERE/'held/package_graph.py').read_bytes(),paths,role)for role,_,_,_ in P.PRODUCTS};deadline=time.monotonic()+P.BOUNDS['component'];phase='baseline-original606';graphs=[];events=[];retained={};apps_retained={};transactions={}
 account=pwd.getpwnam('alarm');P.need(account.pw_uid>0,'same ordinary account');source=Path('/runner/setup240');SC=C.load('_whole_original_setup240_contract',source/'scripts/ci/setup6-real-modules/contract.py');SC.verify_source(source);H=C.load('_whole_original_setup_homes',source/'scripts/ci/setup5-real-modules/run.py');LC=C.scoped_load('_whole_original_setup_registry',source/'scripts/ci/setup6-real-modules/lifecycle.py',{'contract':SC})
 P.need({n:v for n,v in SC.VERSIONS.items()if n not in{r[1]for r in P.PRODUCTS}}=={n:base[n]for n in SC.VERSIONS if n not in{r[1]for r in P.PRODUCTS}},'all six exact installed module package versions')
 supervised=C.scoped_load('_whole_original_setup_supervisor',Path('/runner/copyworker/scripts/ci/current606-doctor2-copy/supervised.py'),{'contract':N})
 previous_ld,previous_aux=context['previous_ld'],context['previous_aux'];aux=[];clock=None
 def progress(operation):
  (g['OUT']/'setup6-progress.json').write_bytes(C.encoded(dict(status='SETUP6_NATIVE_PROGRESS_DATA_ONLY',phase=phase,operation=operation,nonce=nonce,acceptance=False)))
 def registry(parent,report):
  accepted=LC.workspace_snapshot(parent,report,context['L'],H);identities={}
  for relative in accepted:
   p=parent/relative;s=p.lstat();identities[relative]=dict(identity=scope.key(s),capability=os.getxattr(p,'security.capability',follow_symlinks=False).hex()if'security.capability'in os.listxattr(p,follow_symlinks=False)else None)
  return dict(accepted=accepted,identities=identities)
 def plain_registry(parent):
  out={}
  for path in(parent,*sorted(parent.rglob('*'))):
   P.need(not path.is_symlink()and(path.is_dir()or path.is_file()),'ordinary Apps owned home namespace');st=path.lstat();out[path.relative_to(parent).as_posix()]=dict(identity=scope.key(st),sha256=N.pin(N.ordinary(path))['sha256']if path.is_file()else None)
  return out
 def users():
  ordinary_absent(account.pw_uid)
  for parent,before in apps_retained.items():P.need(plain_registry(parent)==before,'all prior Apps7 fresh/existing homes preserved')
  for parent,(report,before)in retained.items():P.need(registry(parent,report)==before,'every prior fifteen-home source-owned registry/identity preserved')
 def capture(want):
  progress('complete-fresh-package-rawDB-ancestry-config-user-graph');P.need(time.monotonic()<deadline and g['inventory']()==want,'component7200 deadline/exact606 or605 inventory');users();packages=context['driver'].database(Path('/'),max_packages=606);P.need({r['name']:r['version']for r in packages}==want,'whole independent ALPM database');started=time.monotonic();row=dict(sequence=len(graphs),phase=phase,state='BEGIN',started=started);graphs.append(row)
  try:
   value=scope.capture(Path('/'),packages,deadline=deadline);row.update(state='COMPLETE',nodes=len(value['nodes']),bytes_read=value['bytes_read'],graph_sha256=hashlib.sha256(C.encoded(value)).hexdigest());return value
  except BaseException:row['state']='FAILED';raise
  finally:
   row['seconds']=time.monotonic()-started;P.need(len(graphs)<=29,'fixed29 fresh graphs');(g['OUT']/'setup6-graph-timing.json').write_bytes(C.encoded(dict(profile='FULL606_APPS7_SETUP6_COEXISTENCE_GRAPH_DATA_V1',nonce=nonce,component_seconds=7200,consumer_seconds=9000,owner_seconds=13800,observations=graphs,actual_authority=False)))
 def installed_one(graph,want,role,window=None):
  _,name,old,new=P.product(role);active=scopes[role];version=want.get(name)
  if version is None:P.need(all(not os.path.lexists('/'+p)for p in active.SELECTED_FILES|active.SELECTED_DIRS),'selected removal complete');return
  product=products[role]['original'if version==old else'new'];actual=[r for r in graph['packages']if r['name']==name];meta=product['pkginfo'];P.need(len(actual)==1 and actual[0]['version']==version and actual[0]['arch']==meta['arch'][0]and set(actual[0]['files'])==set(product['payload'])and actual[0]['depend']==meta.get('depend',[])and actual[0]['provides']==meta.get('provides',[])and actual[0]['conflict']==meta.get('conflict',[]),'complete selected ALPM identity/ownership/dependencies')
  for relative,expected in product['payload'].items():
   node=graph['nodes'][relative];identity=node['identity'];P.need(node['kind']=='file'and identity[3]==identity[4]==0 and identity[5]==1 and stat.S_IMODE(identity[2])==expected['mode']and node['sha256']==expected['sha256']and node['capability']is None,'whole installed selected source/license bytes/owner/mode/singlelink/caps')
  record='var/lib/pacman/local/'+name+'-'+version;dbdir=graph['nodes'][record];P.need(dbdir['kind']=='directory'and dict(mode=stat.S_IMODE(dbdir['identity'][2]),uid=dbdir['identity'][3],gid=dbdir['identity'][4],capability=dbdir['capability'],children=dbdir['children'])==R.DIRECTORY,'whole selected DB directory shape')
  for leaf in('desc','files','mtree'):
   node=graph['nodes'][record+'/'+leaf];i=node['identity'];P.need(node['kind']=='file'and i[3]==i[4]==0 and i[5]==1 and stat.S_IMODE(i[2])==0o644 and node['capability']is None,'selected DB leaf metadata')
  P.need(N.pin(N.ordinary(Path('/')/record/'mtree'))==product['mtree'],'full raw selected archive mtree');fields=context['driver'].fields(N.ordinary(Path('/')/record/'desc'));wanted=product['database_fields'];P.need(set(fields)==set(wanted)and all(fields[k]==v for k,v in wanted.items()if k!='INSTALLDATE'),'all selected DB fields match exact archive/source schema')
  if window is None:P.need(fields['INSTALLDATE']==wanted['INSTALLDATE'],'original selected initial installation date')
  else:P.need(len(fields['INSTALLDATE'])==1 and fields['INSTALLDATE'][0].isdigit()and window['start_seconds']<=int(fields['INSTALLDATE'][0])<=window['end_seconds'],'selected installation date actual transaction')
 def installed(graph,want,windows=None):
  for role,_,_,_ in P.PRODUCTS:installed_one(graph,want,role,(windows or{}).get(role))
 def auxiliary():
  nonlocal previous_ld,previous_aux
  progress('complete-fresh-raw-auxiliary');state=context['audio'].ld_state(context['adapter'],context['audio_rows']);data,_,_=context['audio'].ld_aux_read(state);transition=context['audio'].aux_order.compare(previous_aux,data);P.need(state==previous_ld and data==previous_aux,'full original helper/config/alias/scan/cache/rawaux unchanged');raw=C.encoded(state)
  if not aux:(g['OUT']/'setup6-ld-baseline5.json').write_bytes(raw);(g['OUT']/'setup6-aux-baseline5.bin').write_bytes(data)
  aux.append(dict(phase=phase,nonce=nonce,state=N.pin(raw),auxiliary=N.pin(data),state_path='container/setup6-ld-baseline5.json',auxiliary_path='container/setup6-aux-baseline5.bin',transition=transition,freshness='COMPLETE_FRESH_OBSERVATION_EQUAL_BLOB_SHARED',helper_exit='NOT_OBSERVED'));previous_ld,previous_aux=state,data
 baseline=capture(base);previous=baseline;physical={r['name']:r for r in baseline['packages']if r['name']not in{r[1]for r in P.PRODUCTS}};P.need(len(physical)==604,'exact other604 physical domain');windows={}
 for role,name,old,_ in P.PRODUCTS:
  record='var/lib/pacman/local/'+name+'-'+old;source_fields=context['driver'].fields(N.ordinary(Path('/')/record/'desc'));path=HERE/'held/apps_plan.py'if role=='apps'else Path('/runner/copyworker/scripts/ci/current606-doctor2-copy/plan.py');api=C.scoped_load('_whole_'+role+'_archive_DB_fields',path,{'contract':N})
  for product in products[role].values():product['database_fields']=api.fields(product['pkginfo'],source_fields)
  P.need(products[role]['original']['database_fields']==source_fields,'whole original selected DB/archive calibration')
 installed(baseline,base);before_records=RECORD.capture('/',baseline,N.ordinary);(g['OUT']/'setup6-selected-before.json').write_bytes(C.encoded(before_records));auxiliary()
 for event in P.transitions(base):
  phase=event['phase'];want=event['after'];P.need({r['name']:r['version']for r in previous['packages']}==event['before'],'exact prior fullinventory');role=event['role'];product=None if event['archive_role']is None else products[role][event['archive_role']];operand=None
  if product:
   archive=Path(product['path']);sig=product['signature'];P.need(archive.parent==Path('/tools606/'+('apps7'if role=='apps'else'setup6')+'/archives')and N.pin(N.ordinary(archive))=={k:product[k]for k in('bytes','sha256')}and N.pin(N.ordinary(Path(sig['path']),65536))=={k:sig[k]for k in('bytes','sha256')},'whole exact freshly signed operand');g['verify_signature'](['gpg','--batch','--no-options','--homedir',str(keys),'--no-auto-key-retrieve'],archive,Path(sig['path']),product['signer']);operand={k:product[k]for k in('path','bytes','sha256','signature','signer','version')}
  progress('signed-noexec-transaction');value=dict(root='/',before=event['before'],after=want,archive=operand,keys=str(keys),log='/out/setup6-native.log',role=role);path=g['OUT']/('setup6-step-'+phase+'.json');P.need(not path.exists(),'fresh native transaction operands');path.write_bytes(C.encoded(value));path.chmod(0o644)
  result=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'step_entry.py'),str(path)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(90,max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1);P.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired'],'real signed transaction and group retirement');transaction=N.decode(result['stdout']);P.need(transaction['status']=='COMMITTED_NATIVE_APPS7_SETUP6_REQUIRES_FULL_READBACK','typed signed native transaction');clock=transaction['transaction_clock'];R.interval(clock);current=capture(want);proof=G.protected(scopes[role],previous,current,transaction['lock_parent']);P.need({r['name']:r for r in current['packages']if r['name']in physical}==physical,'all other604 complete ALPM rows');windows[role]=clock;installed(current,want,windows);real=None;apps_real=None;apps_process=None
  if event['real_setup']:
   progress('whole-actual-setup240-real-modules');parent=Path('/tmp')/('coexist-setup-'+phase);P.need(not parent.exists(),'fresh owned real-module workspace');parent.mkdir(mode=0o700);os.chown(parent,account.pw_uid,account.pw_gid);ordinary_absent(account.pw_uid)
   observed=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'ordinary_entry.py'),str(keys),str(parent)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(240,max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1,signal_uid=account.pw_uid);P.need(observed['returncode']==0 and observed['termination']is None and observed['direct_child_reaped']and observed['group_retired'],'whole original240 fixture and owned group retirement');ordinary_absent(account.pw_uid);real=N.decode(observed['stdout']);SC.validate_real(real);P.need(C.read(parent/'work/receipt.json')==real,'whole actual fixture file/stdout join');retained[parent]=(real,registry(parent,real));(g['OUT']/('setup6-real-'+phase+'.json')).write_bytes(C.encoded(real))
  if want.get('cachy-asahi-apps')=='0.1.0-7':
   progress('actual-installed-apps7-two-homes');parent=Path('/tmp')/('coexist-apps-'+phase);P.need(not parent.exists(),'fresh Apps7 home parent');parent.mkdir(mode=0o700);os.chown(parent,account.pw_uid,account.pw_gid);expected=g['OUT']/('coexist-expected-'+phase+'.json');expected.write_bytes(C.encoded(want));expected.chmod(0o644);ordinary_absent(account.pw_uid)
   observed=supervised.run(['/usr/bin/python3','-I','-B',str(HERE/'apps_entry.py'),str(keys),str(parent),str(expected)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(P.BOUNDS['apps_fixture'],max(.001,deadline-time.monotonic())),output_limit=128*1024,grace=1,signal_uid=account.pw_uid);P.need(observed['returncode']==0 and observed['termination']is None and observed['direct_child_reaped']and observed['group_retired'],'actual Apps7 both homes/group retirement');ordinary_absent(account.pw_uid);apps_real=N.decode(observed['stdout']);apps_process={k:v for k,v in observed.items()if k not in('stdout','stderr')};apps_retained[parent]=plain_registry(parent);(g['OUT']/('coexist-apps-'+phase+'.json')).write_bytes(C.encoded(apps_real))
  users();after_fixture=capture(want);P.need(after_fixture==current,'real modules changed complete package/rawDB/user/config graph');installed(after_fixture,want,windows);auxiliary();g['run'](context['pacman']+['-Dk']);deps=sorted({d for r in current['packages']for d in r['depend']});g['run'](context['pacman']+['-T',*deps]);events.append(dict(phase=phase,count=len(want),version=event['version'],other604_physical_preservation=proof,acted_role=role,transaction=transaction,process={k:v for k,v in result.items()if k not in('stdout','stderr')},stdout=N.pin(result['stdout']),stderr=N.pin(result['stderr']),real_modules=real,Apps7=apps_real,Apps7_process=apps_process,private_registries_preserved=True,fixture_graph_unchanged=True));previous=after_fixture
  if phase.startswith('restore-'):transactions[role]=clock
 after_records=RECORD.capture('/',previous,N.ordinary);restoration=R.records(before_records,after_records,transactions);(g['OUT']/'setup6-selected-after.json').write_bytes(C.encoded(after_records));context['preservation'](base);P.need(len(graphs)==29 and len(retained)==4 and len(events)==14,'all captures/real suites/transactions mandatory');result=dict(status='PASS_NATIVE_FULL606_APPS7_SETUP6_COEXISTENCE_REQUIRES_REPLAY',nonce=nonce,base_count=606,counts=[606,*[len(e['after'])for e in P.transitions(base)]],events=events,graphs=graphs,ldconfig=aux,selected_logical_restoration=restoration,selected_inode_restoration='NOT_CLAIMED',other604_physical_preservation=True,real_modules_suites=4,Apps7_coexistence='ACTUAL_INSTALLED_CLI_AND15_CONTROLS_BOTH_HOMES_REQUIRES_REPLAY',notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',audio='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',performance='NOT_CLAIMED');(g['OUT']/'setup6-full606.json').write_bytes(C.encoded(result));context['s']['report']['setup6_full606']=result;return previous_ld,previous_aux

_complete_source_owned_exercise=exercise
def exercise(g,context):
 try:return _complete_source_owned_exercise(g,context)
 except BaseException as error:
  try:
   progress=g['C'].read(g['OUT']/'setup6-progress.json');value=dict(status='SETUP6_NATIVE_FAILURE_DATA_NOT_ACCEPTANCE',phase=progress['phase'],operation=progress['operation'],nonce=progress['nonce'],error_type=type(error).__name__,error=str(error)[:1024],acceptance=False);(g['OUT']/'setup6-error.json').write_bytes(g['C'].encoded(value))
  except Exception:pass
  raise
