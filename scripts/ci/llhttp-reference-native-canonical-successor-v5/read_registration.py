#!/usr/bin/python3 -I -B
"""Fresh read-only Source93 workflow and secret-NAMES worker DATA; no Root authority."""
import base64,datetime,hashlib,importlib.util,json,os,re,resource,stat,subprocess,sys,time
from pathlib import Path
MAIN=Path('/home/gabe/Documents/ChatGPT/cachy-asahi')
BASE=MAIN/'artifacts/development/orchestrator-resume-20261114'
OUT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v5-20261117/artifacts/development/llhttp93-canonical-v5-20261117-r1/registration-DATA')
HEAD='620b5b28c4e07cfd23e753bde3de51695a7a7ef8'
CID='8f6370a35215496c0e6c10922929028f5146644b'
REF='refs/heads/codex/llhttp-reference-native-source-20261117-r5'
REPO='Gabriel-Kahen/cachy-asahi'
URL='https://github.com/'+REPO+'.git'
WF='.github/workflows/native-arm-llhttp-reference-source.yml'
WFPIN=dict(bytes=6201,sha256='2ba05dea048406382cf0285c1a73f56b8671c8a322ffd2636ae41ddc64d82c99')
def need(ok,why):
    if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def put(name,value):
    path=OUT/name;raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    with path.open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())

def rawput(name,raw):
    with (OUT/name).open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

# Do not inspect any credential/key/secret value. Child programs inherit the
# authorized existing credential route; only known trace/resource settings change.
for key in tuple(os.environ):
    if key.startswith('GIT_TRACE')or key in ('GIT_CURL_VERBOSE','GH_DEBUG'):os.environ.pop(key,None)
os.environ['GIT_OPTIONAL_LOCKS']='0';os.environ['GOMAXPROCS']='2';os.environ['GOMEMLIMIT']='128MiB'
O=module(MAIN/'scripts/virtual/owned_process.py','delegated_publication_owned_children')
O.prepare();START=time.monotonic();COMMANDS=[];PUSH_SUBMITTED=False

def run(argv,cwd=None,seconds=45,allow_nonzero=False):
    need(len(COMMANDS)+0<80 and time.monotonic()-START<720,'finite metadata continuation')
    cap=min(seconds,45,720-(time.monotonic()-START));need(cap>2,'remaining operation budget')
    index=len(COMMANDS)+0+1;prefix=f'command-{index:03d}'
    def limits():
        resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024**2,4*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with (OUT/(prefix+'.stdout')).open('xb')as stdout,(OUT/(prefix+'.stderr')).open('xb')as stderr:
        os.fchmod(stdout.fileno(),0o600);os.fchmod(stderr.fileno(),0o600)
        child=subprocess.Popen(argv,cwd=cwd,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=limits)
        retirement=O.supervise(child,cap=cap,retirement=1,grace=.1,streams=(),max_output=0)
    retirement.pop('output',None);output=(OUT/(prefix+'.stdout')).read_bytes();diagnostic=(OUT/(prefix+'.stderr')).read_bytes();need(len(output)+len(diagnostic)<=4*1024**2,'complete bounded separate output')
    row=dict(argv=argv,cwd=str(cwd)if cwd else None,retirement=retirement,stdout=pin(output),stderr=pin(diagnostic));COMMANDS.append(row);put(prefix+'.json',row)
    natural=retirement['reaped']is True and retirement['ownership']=='REAPED'and retirement['group_census']=='EMPTY_TWICE'and retirement['output_complete']is True and not retirement['signals']and not retirement['timeout']and retirement['error']is None and type(retirement['exit'])is int
    need(natural,'complete natural child retirement; uncertain publication never retried');need(allow_nonzero or retirement['exit']==0,'nonzero metadata command; no publication retry')
    return output,retirement['exit']

GIT=['/usr/bin/git','--no-replace-objects','-c','core.hooksPath=/dev/null','-c','maintenance.auto=false','-c','gc.auto=0','-c','core.preloadIndex=false','-c','index.threads=1','-c','core.attributesFile=/dev/null','-c','core.autocrlf=false','-c','commit.gpgSign=false']
def git(args,cwd=None,**kw):return run(GIT+args,cwd,**kw)[0]


def get(endpoint,name,jq=None):
    need((endpoint=='repos/'+REPO or endpoint.startswith('repos/'+REPO+'/'))and not any(x in endpoint for x in('/logs','/artifacts')),'read-only metadata or exact workflow source endpoint')
    argv=['gh','api','--method','GET',endpoint]
    if jq:argv+=['--jq',jq]
    raw,_=run(argv,MAIN);rawput(name,raw);return json.loads(raw)

def main_cas(label):
    remote=get('repos/'+REPO+'/git/ref/heads/main',label+'-Main-ref.raw.json')
    local=git(['rev-parse','HEAD','refs/remotes/origin/main'],MAIN).decode().splitlines()
    branch=git(['symbolic-ref','--short','HEAD'],MAIN).decode().strip()
    public=git(['ls-remote','--heads',URL,'refs/heads/main'],MAIN).decode().split()
    need(remote['ref']=='refs/heads/main'and remote['object']['sha']==HEAD and local==[HEAD,HEAD]and branch=='main'and public==[HEAD,'refs/heads/main'],'fresh same initial/final API/local/tracking/public Main CAS')
    return dict(API=remote['object']['sha'],local_HEAD=local[0],tracking=local[1],branch=branch,public_remote=public[0])

result=dict(status='HOLD_WORKER_DATA',issuer='workerDATA',Root_adoption=None,Root_native_authority=None,secret_values_read=False)
try:
    need(sys.flags.isolated and sys.flags.dont_write_bytecode,'isolated bytecode-free execution')
    adopted=BASE/'Root-llhttp93-publication-r1/Root-publication.ACTUAL.json';raw=adopted.read_bytes()
    need(pin(raw)==dict(bytes=1532,sha256='dfab228173747346422a809872ae41885918099de17e9ecf114d9ca519d6afef'),'Root-adopted exact Source93 receipt')
    initial=main_cas('initial')
    repo=get('repos/'+REPO,'repository.raw.json');need(repo['full_name']==REPO and repo['default_branch']=='main','same default Main repository')
    workflow=get('repos/'+REPO+'/actions/workflows/420972285','workflow.raw.json')
    need(workflow['id']==420972285 and workflow['path']==WF and workflow['state']=='active','active exact workflow id/path')
    expected=(Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-native-canonical-successor-v5-20261117/artifacts/development/llhttp93-canonical-v5-20261117-r1/Source93-DATA')/WF).read_bytes();need(pin(expected)==WFPIN,'whole Source93 workflow fixed pin')
    decoded={}
    for label,ref in [('Main',HEAD),('Source93',CID)]:
        body=get('repos/'+REPO+'/contents/'+WF+'?ref='+ref,label+'-workflow.raw.json')
        need(body['encoding']=='base64'and body['path']==WF and body['type']=='file','ordinary exact contents response')
        raw=base64.b64decode(''.join(body['content'].split()),validate=True)
        need(raw==expected and len(raw)==body['size']and body['sha']==hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'API whole workflow body/blob ID join')
        rawput(label+'-workflow.yml',raw);decoded[label]=pin(raw)
    local_body=git(['show',HEAD+':'+WF],MAIN);need(local_body==expected,'local Git immutable Main workflow whole body API join')
    source_store=BASE/'Root-llhttp93-publication-r1/public-readback'
    source_body=git(['show',CID+':'+WF],source_store);need(source_body==expected,'independent public Git Source93 workflow whole body join')
    source_ref=get('repos/'+REPO+'/git/ref/'+REF.removeprefix('refs/'),'Source93-ref.raw.json');need(source_ref['ref']==REF and source_ref['object']['sha']==CID,'fresh Source93 immutable ref/CID join')
    names=sorted(set(re.findall(r'\bsecrets\.([A-Z][A-Z0-9_]*)',expected.decode())))
    need(len(names)==22 and len(re.findall(r'\bsecrets\b',expected.decode()))==22 and not re.search(r'\bsecrets\s*\[',expected.decode()),'all22 literal referenced secret names; no dynamic references')
    catalog=[];total=None
    for page in range(1,6):
        data=get('repos/'+REPO+'/actions/secrets?per_page=100&page='+str(page),'secret-NAMES-page-'+str(page)+'.raw.json','{total_count,names:[.secrets[].name]}')
        need(set(data)=={'total_count','names'}and type(data['total_count'])is int and data['total_count']<=500 and len(data['names'])<=100 and all(isinstance(n,str)and re.fullmatch('[A-Z_][A-Z0-9_]*',n)for n in data['names']),'bounded names-only catalog')
        if total is None:total=data['total_count']
        need(data['total_count']==total,'stable secret catalog count');catalog+=data['names']
        if len(catalog)>=total:break
    need(len(catalog)==len(set(catalog))==total and set(names)<=set(catalog),'complete names-only catalog; all22 required present')
    final=main_cas('final');need(initial==final,'same stable initial/final Main CAS')
    observed=int(time.time())
    put('registration-readback.DATA.json',dict(kind='CALLER_WORKFLOW_REGISTRATION_READBACK_DATA_V1',issuer='workerDATA',Root_adoption=None,observed_utc=observed,repository=REPO,registered_on_default_branch=True,registration_commit=HEAD,state='active',workflow_id=420972285,workflow_path=WF,workflow_sha256=WFPIN['sha256']))
    result.update(status='PASS_SOURCE93_REGISTRATION_SECRET_NAMES_WORKER_DATA',observed_utc=observed,Main=HEAD,source=CID,source_ref=REF,workflow_id=420972285,workflow_path=WF,workflow=WFPIN,workflow_API_Main_Source=decoded,local_Git_whole_body_join=True,source_public_Git_whole_body_join=True,initial_Main_CAS=initial,final_Main_CAS=final,required_secret_names=names,required_secret_name_count=22,all_required_secret_names_present=True,catalog_count=total,Root_publication_receipt=pin(adopted.read_bytes()),native_cache_crypto_verification='NOT RUN',native_POST=False,Original_GET=False,lease=False)
except BaseException as error:
    result['failure']=dict(type=type(error).__name__,message=str(error)[:600])
finally:
    result['commands']=len(COMMANDS);put('registration-review.DATA.json',result)
    print(json.dumps({k:result.get(k)for k in('status','issuer','Root_adoption','Main','source','commands','required_secret_name_count','catalog_count','failure')},sort_keys=True),flush=True)
    if not result['status'].startswith('PASS_'):raise SystemExit(2)
