# SPDX-License-Identifier: MIT
"""Source-owned live607 recovery; requires a genuine independently admitted /seed.

All normal transaction/commit, authentication, lock and kernel retirement bodies
are held. This private derivation omits the ancestor's install578 stage. Import
and DATA validation launch no actors and do not manufacture a native provider.
"""
import ast,contextlib,hashlib,importlib.util,os,re,sys,types
from pathlib import Path
SOURCE=Path('/source');INPUTS=Path('/inputs');WORK=Path('/work');OUT=Path('/out')
OPERATION='recover-apps16-reinstall607';PROFILE_ENV='APPS16_INTERRUPTION_PROFILE_SHA256'
TRANSACTION='/operation/transaction607.py';INSPECTION='/operation/inspection607.py';WRAPPER='/operation/boundary607.py'
PINS={'lifecycle.py':(58307,'daa0b85b6dbbc932461b0314df89de8299bccda6a04a610dd2238947a6179e69'),'boundary.py':(23903,'edecc31c9850166269adafaeb2e9583cc4de90f41550ed77247e0670ad596cb5'),'recovery.py':(23075,'41f4fade35b83fa6de40af3b8f29234130213d037597601d5150804721f598ba')}
def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def _source(module,name):
    raw=Path(module.__file__).read_bytes();need((len(raw),pin(raw)['sha256'])==PINS[name],'complete immutable ancestor: '+name);return raw.decode()
def _body(text,name):
    rows=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name];need(len(rows)==1,'one source-owned function: '+name);return ast.get_source_segment(text,rows[0])+'\n'
def _replace(text,seams):
    result=text
    for old,new in seams:
        need(old!=new and result.count(old)==1,'one exact607 seam: '+old[:80]);result=result.replace(old,new,1)
    inverse=result
    for old,new in reversed(seams):
        need(inverse.count(new)==1,'one inverse607 seam');inverse=inverse.replace(new,old,1)
    need(inverse==text,'whole source607 inverse');return result,dict(before=pin(text.encode()),after=pin(result.encode()),seams=[dict(before=a,after=b)for a,b in seams])
def _clone(module,name):
    result=types.ModuleType(name);result.__dict__.update(vars(module));result.__name__=name
    for key,value in list(vars(result).items()):
        if isinstance(value,types.FunctionType)and value.__globals__ is vars(module):
            f=types.FunctionType(value.__code__,vars(result),value.__name__,value.__defaults__,value.__closure__);f.__kwdefaults__=value.__kwdefaults__;result.__dict__[key]=f
    return result

def derive(L,B,N):
    """Pure complete-function inverses, never collected code or live execution."""
    text=_source(L,'lifecycle.py');_source(B,'boundary.py');nt=_source(N,'recovery.py')
    l=_clone(L,'_live607_lifecycle');b=_clone(B,'_live607_boundary');n=_clone(N,'_live607_recovery');b.NORMAL=TRANSACTION;b.WRAPPER=WRAPPER
    admitted,al=_replace(_body(nt,'admit'),[("need(len(inventory['packages'])==578,'exact retained component578 inventory')","need(len(inventory['packages'])==607,'exact retained current607 inventory')")]);exec(compile(admitted,'<whole-normal-admission607>','exec'),vars(n))
    interrupt,il=_replace(_body(text,'interrupted_recovery'),[("'/source/'+X.LANE+'/transaction.py'",repr(TRANSACTION)),("wrapped[3]='/operation/boundary.py'","wrapped[3]="+repr(WRAPPER))])
    execute,el=_replace(_body(text,'execute'),[
        ("import boundary,recovery,route607","import boundary,recovery"),
        ("baseline=adapter.measure(seed,T.limits());source_sha=adapter.digest(baseline['nodes'])","provider=provider_gate(C,T,R,adapter)\n    baseline=adapter.measure(seed,T.limits());source_sha=adapter.digest(baseline['nodes'])"),
        ("'original owned full574 copy'","'original owned current607 copy'"),
        ("    path,plan=R.planned(calls,workspace,'install','install',['apps','cache','orphans'])\n    installed=calls.call(H.apply_args(calls,workspace,owner,path,plan))\n    C.need(installed['prepared_add']==C.VERSIONS and not installed['prepared_remove']and len(H.count(workspace))==578,'actual signed component install578')\n    C.load('operation_install_checks',C.HERE/'checks.py').preserved(C,installed,caps_sha)\n","    inventory_gate(C,T,R,workspace)\n"),
        ("inspection=R.inspected(T,calls,workspace,owner,path,plan,'repair-bytes')","inspection=initial_inspection(C,R,calls,workspace,owner,path,plan)\n    inventory_gate(C,T,R,workspace)"),
        ("base_count=574,installed_count=578,full_current607='PENDING_SEPARATE_EXACT_ROUTE'","base_count=607,installed_count=607,full_current607='EXACT_CURRENT607_NATIVE_PROVIDER_REQUIRED',provider=provider"),
        ("str(SOURCE/X.LANE/'inspection.py')","INSPECTION"),
        ("status=X.LIFECYCLE,install=installed,plan=plan","status=X.LIFECYCLE,plan=plan")])
    valid,vl=_replace(_body(text,'validate'),[
        ("value['base_count']==574 and value['installed_count']==578 and value['full_current607']=='PENDING_SEPARATE_EXACT_ROUTE'","value['base_count']==607 and value['installed_count']==607 and value['full_current607']=='EXACT_CURRENT607_NATIVE_PROVIDER_REQUIRED'"),
        ("    C.load('recovery_install_checks',C.HERE/'checks.py').preserved(C,value['install'],value['source_capabilities_sha256'])\n    C.need(value['install']['prepared_add']==C.VERSIONS and not value['install']['prepared_remove'],'signed installed578')\n","    provider_data(C,value['provider'])\n    C.need('install'not in value,'607 root already contains current candidates; no install578 stage')\n")])
    retain,rl=_replace(_body(text,'retained'),[
        ("for field in('install','inspection_refusal','retry_refusal','recovery_inspection','normal_repair'):","for field in('inspection_refusal','retry_refusal','recovery_inspection','normal_repair'):"),
        ("'RETAINED_COMPLETE_COMPONENT578_RECOVERY_DATA_NOT_ROOT_ACCEPTANCE'","'RETAINED_COMPLETE_CURRENT607_RECOVERY_DATA_NOT_ROOT_ACCEPTANCE'"),
        ("'unchanged578 normalized metadata across exact raw DB restoration'","'unchanged607 normalized metadata across exact raw DB restoration'"),
        ("    selected={n for n,r in payload.items()if r['type']=='file'}","    inventory_data(C,C.decode(inventory_raw))\n    selected={n for n,r in payload.items()if r['type']=='file'}")])
    vars(l).update(provider_gate=provider_gate,provider_data=provider_data,inventory_gate=inventory_gate,inventory_data=inventory_data,initial_inspection=initial_inspection,INSPECTION=INSPECTION);sys.modules[l.__name__]=l
    exec(compile(interrupt+'\n'+execute+'\n'+valid+'\n'+retain,'<whole-live607-lifecycle>','exec'),vars(l))
    return l,b,n,dict(schema_version=1,status='COMPLETE_ANCESTOR_FUNCTION_INVERSES',ancestors={k:dict(bytes=v[0],sha256=v[1])for k,v in PINS.items()},admission=al,interruption=il,execute=el,validate=vl,retained=rl,normal_commit_apply='UNCHANGED',worker_seconds=600,reap_seconds=5,worker_output_bytes=1024**2)

def _backend():
    path=Path(__file__).with_name('backend607.py');spec=importlib.util.spec_from_file_location('_lifecycle607_backend',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def inventory_data(C,value):
    _backend().inventory_check(value)
    source=C.HERE.parents[2]
    reader=C.load('live607_retained_inventory',source/'packages/tools/cachy-asahi-apps16/inventory.py');app=C.load('live607_retained_app',source/'packages/tools/cachy-asahi-apps16/apps.py')
    unused,r,unused_pins=app.helpers(source)
    reader.validate(value,lambda row:app.package(row,r));return value

def inspection_argv(C,R,workspace,owner,path,sha):
    return ['/usr/bin/python3','-I','-B',INSPECTION,'inspect-reinstall',*R.H.common(workspace,owner),*R.H.credentials(),'--applications','apps','--plan',str(path),'--plan-sha256',sha]

def inventory_gate(C,T,R,workspace):
    P=C.load('live607_inventory_arguments',SOURCE/'scripts/ci/apps7-full574-repair-native/inspection.py')
    args=P.parser().parse_args(inspection_argv(C,R,workspace,C.sha(C.read(workspace/'apps-copy.json',65536)),OUT/'unused-plan.json','0'*64)[4:]);app,c,r=T.app_source(args)
    value=app.inventory_reader().collect(workspace/'root'/T.DB,c,lambda row:app.package(row,r));inventory_data(C,value);return value

def provider_data(C,value):
    K=_backend();C.need(type(value)is dict and set(value)=={'admission','policy','lease','files'},'closed native607 provider')
    admission=K.admission_check(value['admission']);policy=value['policy'];lease=value['lease']
    C.need(policy['purpose']==lease['purpose']==K.PURPOSE and lease['source']=='/seed'and policy['admission']==admission and policy['admission_sha256']==K.digest(admission),'genuine607 provider/policy/seed joined')
    C.need(policy['inventory_domain']==lease['inventory_domain']==K.DOMAIN and policy['execution_budget']==lease['execution_budget']==K.BUDGET,'exact607 domain; all other budgets held')
    for name in('admission','policy','lease'):C.need(value['files'][name]==K.pin(K.encoded(value[name])),'canonical raw provider pin')
    raw={Path('/policy'):K.encoded(policy),Path('/lease'):K.encoded(lease)}
    args=types.SimpleNamespace(full574_policy='/policy',full574_policy_sha256=K.pin(raw[Path('/policy')])['sha256'],full574_lease='/lease',full574_lease_sha256=K.pin(raw[Path('/lease')])['sha256'])
    K.policy_pair(args,types.SimpleNamespace(B=types.SimpleNamespace(client=types.SimpleNamespace(read_path=lambda path,limit:raw[path]))))
    return value

def provider_gate(C,T,R,adapter):
    K=_backend();raw={name:C.read(INPUTS/('current607-'+name+'.json'),1024**2)for name in('admission','policy','lease')}
    values={name:C.decode(body)for name,body in raw.items()};C.need(all(K.encoded(values[n])==raw[n]for n in raw),'canonical complete provider DATA')
    args=types.SimpleNamespace(full574_policy=str(INPUTS/'current607-policy.json'),full574_policy_sha256=C.sha(raw['policy']),full574_lease=str(INPUTS/'current607-lease.json'),full574_lease_sha256=C.sha(raw['lease']))
    p,l=K.policy_pair(args,T);C.need(p==values['policy']and l==values['lease']and p['admission']==values['admission'],'independent provider document joins')
    value=dict(values,files={n:K.pin(b)for n,b in raw.items()});provider_data(C,value)
    admission=value['admission']
    C.need(admission['source']==os.environ.get('SOURCE_SHA')and str(admission['run_id'])==os.environ.get('GITHUB_RUN_ID')and str(admission['attempt'])==os.environ.get('GITHUB_RUN_ATTEMPT')and admission['token']==os.environ.get('OWNER_TOKEN')==os.environ.get('CACHY_ASAHI_APPS_TRANSACTION'),'independent actual source/run/attempt/owner admission before copy or export')
    for name,body in raw.items():(OUT/('current607-'+name+'.json')).write_bytes(body)
    C.save(OUT/'native607-provider.json',value);return value

def initial_inspection(C,R,calls,workspace,owner,path,plan):
    sha=C.sha(C.read(path));row=calls.call(inspection_argv(C,R,workspace,owner,path,sha));C.load('live607_initial_checks',C.HERE/'checks.py').inspection(C,row,sha);C.save(OUT/'repair-bytes-inspection.json',row);return row

@contextlib.contextmanager
def _aliases(B,N):
    saved={name:sys.modules.get(name)for name in('boundary','recovery')};sys.modules.update(boundary=B,recovery=N)
    try:yield
    finally:
        for name,value in saved.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value

def _scope(C,L,B,N):
    l,b,n,ledger=derive(L,B,N);l.SOURCE=SOURCE;l.WORK=WORK;l.OUT=OUT;l.INPUTS=INPUTS;return l,b,n,ledger

def run(C,R,T,normal,L,B,N,calls):
    """Executable607 path, conditional on actual independently admitted native /seed.

    /seed is the unchanged copier mount name. Its new lease must be live607;
    missing provider DATA refuses before copy. No native readiness is inferred.
    """
    profile=os.environ.get(PROFILE_ENV);need(type(profile)is str and re.fullmatch('[0-9a-f]{64}',profile),'independent current607 operation profile');need(L.X.OPERATION==OPERATION,'explicit separately selected607 operation')
    l,b,n,ledger=_scope(C,L,B,N);K=_backend();adapter=K.bind(T,normal)
    h=R.H;original={key:getattr(h,key)for key in('C','common','backend')};old_rc=getattr(R,'C',None);proxy=types.SimpleNamespace(**vars(C));proxy.ENV=dict(C.ENV,**{PROFILE_ENV:profile})
    scope,cl,bl=command_scope(proxy,h);h.C=proxy;h.common=scope['common'];h.backend=scope['backend'];R.C=proxy
    ledger.update(common=cl,backend=bl)
    def admitted_provider(*args):
        value=provider_gate(*args);C.save(OUT/'lifecycle607-derivation.json',ledger);return value
    l.provider_gate=admitted_provider
    try:
        with _aliases(b,n):return l.execute(proxy,R,T,adapter,calls)
    finally:
        for key,value in original.items():setattr(h,key,value)
        if old_rc is None:delattr(R,'C')
        else:R.C=old_rc


def command_scope(C,H):
    raw=Path(H.__file__).read_text()
    common,cl=_replace(_body(raw,'common'),[("'/inputs/full574-'","'/inputs/current607-'"),("('full574-'+key+'.json')","('current607-'+key+'.json')")])
    backend,bl=_replace(_body(raw,'backend'),[("'/source/scripts/ci/apps7-full574-repair-native/transaction.py'",repr(TRANSACTION))])
    scope=dict(vars(H),C=C,INPUTS=INPUTS)
    exec(compile(common+'\n'+backend,'<held-native607-command-slots>','exec'),scope)
    return scope,cl,bl

def _components(C):
    return[C.load('live607_ancestor_'+name,Path(__file__).with_name(name+'.py'))for name in('lifecycle','boundary','recovery')]

def validate(C,value):
    l,b,n,ledger=_scope(C,*_components(C))
    with _aliases(b,n):return l.validate(C,value)

def retained(C,value,directory,files):
    l,b,n,ledger=_scope(C,*_components(C));directory=Path(directory)
    for name in('admission','policy','lease'):
        raw=C.read(directory/('current607-'+name+'.json'),1024**2);C.need(C.decode(raw)==value['provider'][name]and pin(raw)==value['provider']['files'][name]==files['lifecycle-public/current607-'+name+'.json'],'physical retained genuine607 provider')
    raw=C.read(directory/'native607-provider.json',4*1024**2);C.need(C.decode(raw)==value['provider']and pin(raw)==files['lifecycle-public/native607-provider.json'],'physical607 provider summary')
    raw=C.read(directory/'lifecycle607-derivation.json',1024**2);derived=C.decode(raw);C.need(pin(raw)==files['lifecycle-public/lifecycle607-derivation.json']and all(derived[k]==v for k,v in ledger.items()),'complete retained finite607 derivation')
    with _aliases(b,n):return l.retained(C,value,directory,files)
