"""Four exact HTTPS reads, private accepted-certificate GPGv, metadata-only child."""
import ast,datetime,hashlib,json,math,os,re,resource,selectors,signal,ssl,stat,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
BASE=Path(__file__).absolute().parent;MIB=1024**2;SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6';START=time.monotonic();END=START+1200;PLAN=json.loads((BASE/'execution-plan.json').read_bytes());COMMANDS=[]
def need(v,code):
 if not v:raise ValueError(code)
def live():need(time.monotonic()<END,'absolute1200-deadline')
def save(name,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=2*MIB,'receipt bound');p=BASE/name;t=p.with_suffix('.new');t.write_bytes(raw);t.chmod(0o600);os.replace(t,p)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
for p,w in PLAN['execution_sources'].items():need(sha(Path(p))==w['sha256'],'source-drift')
for p,w in PLAN['tools'].items():need(sha(Path(p))==w['sha256'],'tool-drift')
# Reuse only the inspected source-issued process/signature functions, rawcompiled.
env=dict(subprocess=subprocess,selectors=selectors,signal=signal,os=os,time=time,tempfile=tempfile,require=need)
tree=ast.parse((BASE/'capture/lifecycle.py').read_bytes());nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('bounded_process','cleanup_group')];need(len(nodes)==2,'process-source');exec(compile(ast.Module(body=nodes,type_ignores=[]),str(BASE/'capture/lifecycle.py'),'exec'),env)
tree=ast.parse((BASE/'capture/authenticate_missing.py').read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='signature_status');sig_env={'need':need};exec(compile(ast.Module(body=[node],type_ignores=[]),str(BASE/'capture/authenticate_missing.py'),'exec'),sig_env)
HOME=BASE/'keys/private-home';HOME.mkdir(mode=0o700);CERT=BASE/'keys/certificate.gpg';PUBLIC=HOME/'accepted-public.gpg';CLI=PLAN['tools_by_name'];ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','HOME':str(HOME),'GNUPGHOME':str(HOME),'TMPDIR':str(BASE/'keys')}
def limits():
 resource.setrlimit(resource.RLIMIT_AS,(384*MIB,384*MIB));resource.setrlimit(resource.RLIMIT_CPU,(110,110));resource.setrlimit(resource.RLIMIT_FSIZE,(2*MIB,2*MIB));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
gpg=[CLI['gpg'],'--no-options','--batch','--homedir',str(HOME),'--no-auto-key-retrieve','--no-autostart']
allowed=[gpg+['--with-colons','--show-keys',str(CERT)],gpg+['--import',str(CERT)],gpg+['--export',SIGNER]]
for e in PLAN['entries']:
 if e['kind']=='archive':
  name=Path(urllib.parse.urlsplit(e['url']).path).name
  allowed.append([CLI['gpgv'],'--homedir',str(HOME),'--keyring',str(PUBLIC),'--status-fd','1',str(BASE/'cache'/(name+'.sig')),str(BASE/'cache'/name)])
def command(argv,timeout=90):
 live();need(argv in allowed or argv[:4]==[CLI['python'],'-I','-B',str(BASE/'metadata_child.py')],'closed-command')
 result=env['bounded_process'](argv,timeout=min(timeout,END-time.monotonic()-2),stdout_limit=MIB,stderr_limit=MIB,env=ENV,preexec_fn=limits)
 observed={k:v.decode('utf-8',errors='backslashreplace') if isinstance(v,bytes) else v for k,v in result.items()};observed['argv']=argv;COMMANDS.append(observed);save('process-observations.json',COMMANDS)
 need(result['reason']=='exit' and result['returncode']==0 and result['cleanup'].get('reaped') is True and not result['cleanup'].get('errors'),'bounded process failed');live();return result
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise ValueError('redirect refused')
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
def download(e):
 live();url=e['url'];need(url in {v['url'] for v in PLAN['entries']},'fixed URL only');p=urllib.parse.urlsplit(url);need(p.scheme=='https' and p.hostname=='pkgmirror.sametimetomorrow.net' and not(p.query or p.fragment or p.username or p.password),'HTTPS URL scope');target=BASE/'cache'/Path(p.path).name;partial=target.with_suffix(target.suffix+'.partial');maximum=e['operator_declared_bytes'] if e['kind']=='archive' else 4*MIB;size=0;h=hashlib.sha256();before=time.monotonic()
 with OPENER.open(urllib.request.Request(url,headers={'User-Agent':'cachy-asahi-bounded-source-audit/1'}),timeout=min(30,END-time.monotonic())) as response:
  need(response.status==200 and response.url==url,'HTTP response/url refused');length=response.headers.get('Content-Length');need(length is None or length.isdigit() and int(length)<=maximum,'advertised size refused')
  with partial.open('xb') as out:
   partial.chmod(0o600)
   while True:
    live();need(time.monotonic()-before<300,'per-read deadline');block=response.read1(min(MIB,maximum-size+1))
    if not block:break
    size+=len(block);need(size<=maximum,'download cap');out.write(block);h.update(block)
  need(size==e['operator_declared_bytes'] and (length is None or size==int(length)),'exact declared byte mismatch')
 partial.rename(target);return {'identity':e['identity'],'kind':e['kind'],'url':url,'path':str(target),'bytes':size,'sha256':h.hexdigest(),'predeclared_sha256':None,'hash_provenance':'observed post-download','redirects':False}
receipt={'schema_version':1,'status':'IN_PROGRESS','plan_sha256':sha(BASE/'execution-plan.json'),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'downloads':[],'packages':[],'failures':[],'acceptance':{'all261_accepted':False,'installation_accepted':False,'hardware_accepted':False,'signed_database_association_accepted':False,'independent_key_owner_trust_accepted':False,'image_correspondence_accepted':False},'old_missing_contract_or_references_modified':False}
def expired(*a):raise TimeoutError('absolute1200-deadline')
previous=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,1200)
try:
 save('actual-receipt.json',receipt)
 show=command(allowed[0]);publics=[];expect_fpr=False
 for line in show['stdout'].decode('utf-8').splitlines():
  fields=line.split(':');need(fields[0] not in ('sec','ssb'),'private certificate refused')
  if fields[0]=='pub':expect_fpr=True
  elif fields[0]=='fpr' and expect_fpr:publics.append(fields[9]);expect_fpr=False
 need(publics==[SIGNER],'accepted certificate exact primary');command(allowed[1]);exported=command(allowed[2])['stdout'];need(exported and len(exported)<MIB,'accepted public export');PUBLIC.write_bytes(exported);PUBLIC.chmod(0o600);receipt['public_certificate']={'source_sha256':sha(CERT),'primary_fingerprint':SIGNER,'private_home':str(HOME),'user_global_keyring_modified':False,'no_autostart':True}
 for e in PLAN['entries']:
  result=download(e);receipt['downloads'].append(result);save('actual-receipt.json',receipt);print(json.dumps({'downloaded':Path(result['path']).name,'bytes':result['bytes'],'sha256':result['sha256']}),flush=True)
 for e in PLAN['entries']:
  if e['kind']!='archive':continue
  path=BASE/'cache'/Path(urllib.parse.urlsplit(e['url']).path).name;verified=command([CLI['gpgv'],'--homedir',str(HOME),'--keyring',str(PUBLIC),'--status-fd','1',str(path)+'.sig',str(path)]);signature=sig_env['signature_status'](verified['stdout'],SIGNER)
  metadata=command([CLI['python'],'-I','-B',str(BASE/'metadata_child.py'),str(path),json.dumps(e['identity'],sort_keys=True),sha(path)],timeout=110);observed=json.loads(metadata['stdout']);need(observed['identity']==e['identity'] and observed['status']=='PASS_SIGNED_METADATA_EXACT_TUPLE','metadata tuple');save('observations/'+e['identity']['name']+'.json',observed)
  receipt['packages'].append({'identity':e['identity'],'status':'PASS_EXACT_SIGNED_ARCHIVE_METADATA_DATA','signature_verification':signature,'archive':next(d for d in receipt['downloads'] if d['path']==str(path)),'signature':next(d for d in receipt['downloads'] if d['path']==str(path)+'.sig'),'metadata_reference':{'path':str(BASE/'observations'/ (e['identity']['name']+'.json')),'sha256':sha(BASE/'observations'/(e['identity']['name']+'.json'))}});save('actual-receipt.json',receipt);print(json.dumps({'verified':e['identity'],'status':'PASS_EXACT_SIGNED_DATA'}),flush=True)
 need(len(receipt['downloads'])==4 and len(receipt['packages'])==2,'complete two-pair only');receipt['status']='PASS_TWO_EXACT_SIGNED_ARCHIVE_DATA_ONLY'
except BaseException as error:
 receipt['status']='FAIL_NO_COMPLETE_TWO_PAIR';receipt['failures'].append({'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error)[:1500]});print(json.dumps({'status':'FAIL','type':type(error).__name__,'message':str(error)[:300]}),flush=True)
finally:
 signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();receipt['elapsed_seconds']=time.monotonic()-START;receipt['owned_gpg_socket_paths_remaining']=[str(p) for p in HOME.glob('S.gpg-agent*') if os.path.lexists(p)];receipt['process_observation_count']=len(COMMANDS);receipt['storage_bytes']=sum(p.stat().st_size for p in BASE.rglob('*') if p.is_file());need(receipt['storage_bytes']<128*MIB,'storage cap');save('actual-receipt.json',receipt)
raise SystemExit(receipt['status']!='PASS_TWO_EXACT_SIGNED_ARCHIVE_DATA_ONLY')
